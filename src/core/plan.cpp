#include "core/plan.hpp"

#include <algorithm>
#include <set>

#include "core/gpu.hpp"
#include "core/launch.hpp"
#include "core/seccomp.hpp"
#include "util/log.hpp"
#include "util/sys.hpp"

namespace hf {

// ---------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------

std::vector<fs::path> find_git_entries(const fs::path& root, size_t cap) {
    std::vector<fs::path> out;
    std::error_code ec;
    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
    for (; !ec && it != end; it.increment(ec)) {
        const fs::directory_entry& e = *it;
        if (e.path().filename() != ".git") continue;
        std::error_code e2;
        // bwrap resolves a bind *source* through symlinks, so `.git -> ~/.ssh` would mount the target
        // without ever passing Policy. A symlinked .git is never legitimate: refuse the tree.
        if (e.is_symlink(e2))
            throw PolicyError(cat("'", e.path().string(), "' is a symlink; refusing to mount a working tree with a symlinked .git"));
        // Fail closed: a truncated scan would leave later repos writable.
        if (out.size() >= cap)
            throw Error(cat("more than ", cap, " .git entries under ", root.string(), "; mount a smaller subdirectory"));
        out.push_back(e.path());
        if (e.is_directory(e2)) it.disable_recursion_pending();   // never descend into a .git directory
    }
    if (ec) throw Error(cat("cannot scan ", root.string(), " for .git entries (", ec.message(), "); refusing to mount it"));
    return out;
}

Strings match_font_files(const fs::path& root, const Strings& families, size_t cap) {
    static const std::set<std::string> exts = {".ttf", ".otf", ".ttc", ".woff", ".woff2", ".pcf", ".gz"};
    Strings out;
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return out;
    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
    while (!ec && it != end) {
        std::error_code e2;
        if (it->is_regular_file(e2) && exts.count(lower(it->path().extension().string()))) {
            std::string lp = lower(it->path().string());
            for (auto& f : families) {
                if (lp.find(lower(f)) != std::string::npos) { out.push_back(it->path().string()); break; }
            }
            if (out.size() >= cap) break;
        }
        it.increment(ec);
    }
    std::sort(out.begin(), out.end());
    return out;
}

namespace {

const char* kXdgSub[] = {".config", ".cache", ".local/share", ".local/state", ".local/bin"};

// Identity files are generated, never the host's. There is deliberately NO /etc/machine-id: it is a stable per-install
// identifier (a fingerprinting handle, and it names the journal and the DBus machine). The cost: GLib/DBus cannot start a
// session bus or the accessibility bus ("Cannot spawn a message bus without a machine-id", org.a11y.Bus), so screen-reader
// support is off in sandboxed GUI apps. If an app genuinely needs one, bind a RANDOM file: [fs] ro = /path/to/fake => /etc/machine-id
void mount_identity(ArgBuilder& b, const Profile& p, const PlanCtx& c) {
    const std::string U = p.fake_user;
    const std::string uid = std::to_string(c.user.uid), gid = std::to_string(c.user.gid);
    write_file(c.session / "passwd",
               "root:x:0:0:root:/root:/bin/sh\n" + U + ":x:" + uid + ":" + gid + ":" + U + ":/home/" + U + ":/bin/sh\n"
               "nobody:x:65534:65534:nobody:/:/sbin/nologin\n", 0644);
    write_file(c.session / "group", "root:x:0:\n" + U + ":x:" + gid + ":\nnogroup:x:65534:\n", 0644);
    write_file(c.session / "nsswitch.conf", "passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n", 0644);
    write_file(c.session / "hosts", "127.0.0.1 localhost " + p.hostname + "\n::1 localhost\n", 0644);
    b.ro_bind(c.session / "passwd", "/etc/passwd");
    b.ro_bind(c.session / "group", "/etc/group");
    b.ro_bind(c.session / "nsswitch.conf", "/etc/nsswitch.conf");
    b.ro_bind(c.session / "hosts", "/etc/hosts");
}

// resolv.conf is never the host's unless the profile says `dns = host` (mode host). pasta: pasta's forwarder (a host
// stub on 127.0.0.x is unreachable from the private namespace). host: the profile's resolver. ivpn: `ip netns exec`
// overlays /etc/resolv.conf with /etc/netns/<ns>/resolv.conf, written from the WireGuard config's DNS.
void bind_resolv_conf(ArgBuilder& b, const Profile& p, const PlanCtx& c) {
    if (c.pasta) {
        write_file(c.session / "resolv.conf", pasta_resolv_conf(), 0644);
        b.ro_bind(c.session / "resolv.conf", "/etc/resolv.conf");
    } else if (p.net == NetMode::Host && p.dns != "host") {
        if (!is_ipv4_unicast(p.dns)) throw ProfileError(cat("profile '", p.name, "': network mode host needs dns = <IPv4> or dns = host"));
        write_file(c.session / "resolv.conf", cat("nameserver ", p.dns, "\n"), 0644);
        b.ro_bind(c.session / "resolv.conf", "/etc/resolv.conf");
    } else if ((p.net == NetMode::Host || p.net == NetMode::Ivpn) && fs::exists("/etc/resolv.conf")) {   // dns = host, or the ivpn overlay
        b.ro_bind("/etc/resolv.conf", "/etc/resolv.conf");
    }
}

// `libs = minimal`: bind exactly the files resolve_profile_data() took from the OS's saved file list for the
// libs this profile `use`s. Nothing is analysed at run time; the list is created once per OS by
// `holdfast libs --refresh` and committed under data/os/.
void mount_listed_libs(ArgBuilder& b, const Profile& p, const PlanCtx& c) {
    if (p.lib_binds.empty()) {
        if (!p.bins.empty())
            throw ProfileError(cat("libs = minimal resolved no library files for '", p.name, "': list the libs you need under [libs] use = ..., "
                                   "or set `libs = full` in [fs]"));
        return;
    }
    Strings sorted = p.lib_binds;
    std::sort(sorted.begin(), sorted.end());                  // parents before children
    for (const std::string& l : sorted) {
        std::error_code ec;
        if (!fs::exists(l, ec))
            throw Error(cat("library file listed for this OS no longer exists on this host: ", l, " (the saved file list is out of date, e.g. after an upgrade): "
                            "run `holdfast libs --check` to see what changed, `holdfast libs --refresh` to update it, or set `libs = full`"));
        c.policy->check_bind(l, false);
        b.ro_bind(canon(l), l);
    }
}

// [gpu] mode = render: bind only DRM render nodes, which expose the kernel driver's GPU ioctl surface but not KMS.
// The default (none) binds nothing; [display] never implies this. No Mesa variables are set: the userland's driver chooses.
void mount_gpu(ArgBuilder& b, const Profile& p, const PlanCtx& c, const VarCtx& vc) {
    if (p.gpu != GpuMode::Render) return;
    Strings nodes;
    if (!p.gpu_devices.empty()) {
        for (const std::string& d : p.gpu_devices) {
            const fs::path node = expand(d, vc);
            c.policy->check_bind(node, true, true);           // explicit allowance: exactly this render-node key
            nodes.push_back(canon(node).string());
        }
    } else {
        nodes = find_render_nodes();
        if (nodes.empty())
            throw Error("gpu mode = render: no DRM render node found under /dev/dri (check that the GPU driver is loaded, "
                        "or name one with [gpu] device = /dev/dri/renderD<number>)");
        for (const std::string& n : nodes) c.policy->check_bind(n, true, true);
    }
    std::sort(nodes.begin(), nodes.end());
    nodes.erase(std::unique(nodes.begin(), nodes.end()), nodes.end());
    for (const std::string& n : nodes) {
        std::string why;
        if (!render_node_openable(n, &why))
            throw Error(cat("gpu mode = render: cannot open render node '", n, "' read-write: ", why,
                            " (add the invoking user to the 'render' or 'video' group, or check that the GPU driver is loaded)"));
        b.dev_bind(n, n);
    }
    // A render node alone is not enough: Mesa maps the DRM fd through sysfs to pick the driver, and host profiles need the
    // EGL/Vulkan manifests (they live in /usr/share, which libs = full does not bind). Fixed read-only paths, so they are
    // outside Policy's user-mount blacklist on purpose; never add anything here that is profile-controlled.
    for (const std::string& s : gpu_support_binds(p.root == RootMode::Host)) b.ro_bind(s, s);
}

void mount_host_rootfs(ArgBuilder& b, const Profile& p, const PlanCtx& c, const VarCtx& vc) {
    b.dir("/usr/bin");
    b.symlink("usr/bin", "/bin").symlink("usr/bin", "/sbin").symlink("usr/bin", "/usr/sbin");

    // usr-merge symlinks are needed in both modes (the dynamic loader path in every ELF goes through them);
    // whole library directories only in `libs = full`.
    bind_host_library_dirs(b, p.libs == LibsMode::Full);

    std::set<std::string> seen;
    for (const std::string& tok : p.bins) {
        std::string name = tok;
        std::optional<fs::path> host;
        if (auto eq = tok.find('='); eq != std::string::npos) {
            name = tok.substr(0, eq);
            host = fs::path(expand(tok.substr(eq + 1), vc));
            if (!fs::exists(*host)) host.reset();
        } else {
            host = which(name);
        }
        if (name.empty() || name.find('/') != std::string::npos) throw ProfileError("[bin] invalid name: " + tok);
        if (!seen.insert(name).second) continue;
        if (!host) { log::warn("allowed binary not found on host, skipped: " + name); continue; }
        std::error_code ec;
        fs::path real = fs::canonical(*host, ec);
        if (ec) { log::warn("cannot resolve " + host->string()); continue; }
        try { c.policy->check_bind(real, false); }
        catch (const PolicyError& e) { log::warn(std::string("binary skipped: ") + e.what()); continue; }
        b.ro_bind(real, fs::path("/usr/bin") / name);
        // Multi-call/alternatives targets sometimes locate resources relative to their real path.
        if (real != *host && !path_under(real, c.user.home) && real != fs::path("/usr/bin") / name)
            b.ro_bind_try(real, real);
    }

    if (p.libs == LibsMode::Minimal) mount_listed_libs(b, p, c);

    if (p.fs_defaults) {
        // CA trust: /etc/ssl and /etc/ca-certificates are often only pointers. The roots themselves live under
        // /usr/share/ca-certificates (Debian, Arch trust-source), /etc/pki (Fedora/RHEL) or via p11-kit's module config;
        // without them a browser or curl using the system store trusts nothing and every HTTPS site fails.
        for (const char* d : {"/etc/ld.so.cache", "/usr/share/terminfo", "/usr/share/zoneinfo", "/etc/ssl",
                              "/etc/ca-certificates", "/usr/share/ca-certificates", "/etc/pki", "/usr/share/p11-kit",
                              "/etc/os-release", "/usr/lib/os-release"})
            if (fs::exists(d)) b.ro_bind_try(d, d);
        if (c.network) bind_resolv_conf(b, p, c);
    }
}

void mount_bundle_rootfs(ArgBuilder& b, const Profile& p, const PlanCtx& c, std::set<std::string>& etc_skip) {
    const fs::path R = c.paths.rootfs;
    if (!fs::is_directory(R / "usr"))
        throw Error(cat("the Alpine userland for profile '", p.name, "' is not set up yet; run the profile once (holdfast run ", p.name, ") and it is created"));
    for (const char* t : {"bin", "sbin", "lib", "lib64", "usr"}) {
        fs::path s = R / t;
        std::error_code ec;
        if (fs::is_symlink(s, ec)) b.symlink(fs::read_symlink(s).string(), fs::path("/") / t);
        else if (fs::is_directory(s, ec)) b.ro_bind(s, fs::path("/") / t);
    }
    // /etc is rebuilt on a tmpfs: bundle files minus anything identity/network related.
    static const std::set<std::string> skip = {"passwd", "group", "shadow", "gshadow", "nsswitch.conf", "resolv.conf",
                                               "hosts", "hostname", "machine-id" /* see mount_identity: no stable host id */, "mtab", "passwd-", "group-", "shadow-"};
    etc_skip.insert(skip.begin(), skip.end());
    b.tmpfs("/etc");
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(R / "etc", ec)) {
        std::string n = e.path().filename().string();
        if (etc_skip.count(n)) continue;
        if (e.is_symlink()) b.symlink(fs::read_symlink(e.path()).string(), fs::path("/etc") / n);
        else b.ro_bind(e.path(), fs::path("/etc") / n);
    }
    if (c.network) {
        // resolv.conf from host (or from the ip-netns overlay when running under ivpn).
        bind_resolv_conf(b, p, c);
    }
}

void mount_fonts(ArgBuilder& b, const Profile& p, const PlanCtx& c, const fs::path& fonts_root) {
    Strings files = match_font_files(fonts_root, p.font_families);
    if (files.empty()) throw Error(cat("[fonts] no font files matching '", join(p.font_families, ","), "' under ", fonts_root.string()));
    b.tmpfs("/usr/share/fonts");
    for (auto& f : files) {
        fs::path rel = fs::relative(f, fonts_root);
        b.ro_bind(canon(f), fs::path("/usr/share/fonts") / rel);
    }
    std::string conf = "<?xml version=\"1.0\"?>\n<!DOCTYPE fontconfig SYSTEM \"fonts.dtd\">\n<fontconfig>\n"
                       "  <dir>/usr/share/fonts</dir>\n  <cachedir>/tmp/fontcache</cachedir>\n";
    const std::string first = lower(p.font_families.front());
    auto alias = [&](const char* generic, const char* fam) {
        conf += cat("  <alias><family>", generic, "</family><prefer><family>", fam, "</family></prefer></alias>\n");
    };
    if (first.find("liberation") != std::string::npos) { alias("sans-serif", "Liberation Sans"); alias("serif", "Liberation Serif"); alias("monospace", "Liberation Mono"); }
    else { alias("sans-serif", "DejaVu Sans"); alias("serif", "DejaVu Serif"); alias("monospace", "DejaVu Sans Mono"); }
    conf += "</fontconfig>\n";
    write_file(c.session / "fonts.conf", conf, 0644);
    b.ro_bind(c.session / "fonts.conf", "/etc/fonts/fonts.conf");
}

}  // namespace

// ---------------------------------------------------------------------------------
// the plan
// ---------------------------------------------------------------------------------

void bind_host_library_dirs(ArgBuilder& b, bool whole) {
    for (const char* l : {"/lib", "/lib64"}) {
        std::error_code ec;
        if (fs::is_symlink(l, ec)) { if (fs::exists(l, ec)) b.symlink(fs::read_symlink(l).string(), l); }
        else if (fs::is_directory(l, ec) && whole) b.ro_bind_try(l, l);
    }
    if (whole)
        for (const char* d : {"/usr/lib", "/usr/lib64"})
            if (fs::is_directory(d)) b.ro_bind(d, d);
}

Plan build_plan(const Profile& p, const PlanCtx& c) {
    if (!c.policy) throw Error("internal: policy missing");
    Plan plan;
    ArgBuilder& b = plan.b;
    VarCtx vc;
    vc.user = &c.user; vc.paths = &c.paths; vc.cwd = c.cwd;
    const std::string U = p.fake_user;
    const fs::path fhome = fs::path("/home") / U;
    const std::string uid = std::to_string(c.user.uid);

    // -- isolation core ---------------------------------------------------------
    b.flag("--unshare-all").flag("--unshare-user").flag("--unshare-ipc").flag("--unshare-pid")
     .flag("--unshare-uts").flag("--unshare-cgroup");
    if (c.network) b.flag("--share-net");          // else --unshare-all already isolates it
    if (p.net == NetMode::Host)
        log::warn("net=host shares the host network namespace, which also exposes host *abstract* unix sockets "
                  "(e.g. the X11 server's @/tmp/.X11-unix/X0, some D-Bus) regardless of display=none. "
                  "Use net=ivpn for a private namespace.");
    b.flag("--die-with-parent");
    if (p.new_session && !c.pty_proxy) b.flag("--new-session");   // blocks TIOCSTI keystroke injection; with a pty proxy the sandbox's tty IS the proxy
    b.raw({"--cap-drop", "ALL"});
    // bwrap applies --clearenv/--setenv strictly in order: --clearenv must come BEFORE every --setenv (DISPLAY, XAUTHORITY,
    // PULSE_SERVER, HOME, ...) or it wipes them. Keep it here, ahead of the display/audio/environment sections below.
    b.flag("--clearenv");
    // Inside pasta's user namespace we may be mapped to uid 0; pin the identity the fake passwd describes.
    if (c.pasta) b.raw({"--uid", uid, "--gid", std::to_string(c.user.gid)});
    if (p.disable_userns && c.userns_disable_supported) b.flag("--disable-userns");
    b.raw({"--hostname", p.hostname});
    b.raw({"--proc", "/proc"}).raw({"--dev", "/dev"});
    mount_gpu(b, p, c, vc);
    b.tmpfs("/tmp").tmpfs("/run").dir(fs::path("/run/user") / uid).dir("/var/tmp");
    b.raw({"--chmod", "0700", (fs::path("/run/user") / uid).string()});

    // -- userland ---------------------------------------------------------------
    std::set<std::string> etc_skip;
    fs::path fonts_root;
    if (p.root == RootMode::Host) {
        mount_host_rootfs(b, p, c, vc);
        fonts_root = "/usr/share/fonts";
    } else {
        mount_bundle_rootfs(b, p, c, etc_skip);
        fonts_root = c.paths.rootfs / "usr/share/fonts";
    }
    mount_identity(b, p, c);
    if (c.display && !p.font_families.empty()) mount_fonts(b, p, c, fonts_root);

    for (const auto& t : p.tmpfs) b.tmpfs(expand(t, vc));

    // -- persistent fake $HOME --------------------------------------------------
    make_private_dir(c.paths.home);
    for (auto s : kXdgSub) make_private_dir(c.paths.home / s);
    for (auto& d : p.home_dirs) make_private_dir(c.paths.home / d);
    b.bind(c.paths.home, fhome);

    for (const auto& m : p.home_binds) {
        fs::path src = c.user.home / expand(m.src, vc);
        if (!fs::exists(src)) {
            if (m.optional) continue;
            throw Error("[home] bind source does not exist: " + src.string());
        }
        fs::path dst = fhome / (m.dst.empty() ? expand(m.src, vc) : expand(m.dst, vc));
        c.policy->check_bind(src, m.rw);
        if (m.rw) b.bind(canon(src), dst); else b.ro_bind(canon(src), dst);
    }

    // -- user-declared mounts (whitelist) --------------------------------------
    for (const auto& m : p.mounts) {
        Strings srcs = expand_glob(m.src, vc);
        if (srcs.size() > 1 && !m.dst.empty()) throw ProfileError("glob with explicit destination is ambiguous: " + m.src);
        bool any = false;
        for (const auto& s : srcs) {
            if (!fs::exists(s)) continue;
            any = true;
            fs::path dst = m.dst.empty() ? fs::path(s) : fs::path(expand(m.dst, vc));
            c.policy->check_bind(s, m.rw);
            if (m.rw) b.bind(canon(s), dst); else b.ro_bind(canon(s), dst);
        }
        if (!any && !m.optional) throw Error("[fs] source does not exist: " + m.src);
    }

    // -- working tree + .git guard ---------------------------------------------
    if (c.mount_cwd) {
        c.policy->check_cwd(c.cwd);
        b.bind(c.cwd, p.cwd_dest);
        if (p.git_protect) {
            size_t n = 0;
            for (const auto& g : find_git_entries(c.cwd)) {
                // `--ro-bind` over a bind: the mountpoint cannot be renamed/unlinked from inside.
                b.ro_bind(g, fs::path(p.cwd_dest) / fs::relative(g, c.cwd));
                ++n;
            }
            log::info(cat("working tree mounted at ", p.cwd_dest, " (", n, " .git entr", n == 1 ? "y" : "ies", " read-only)"));
        }
    }

    // -- display / audio / clipboard -------------------------------------------
    if (c.display) {                                   // protocol-neutral: binds and variables, whatever X11 or Wayland needs
        for (const auto& d : c.display->binds) {
            if (d.rw) b.bind(d.host, d.sandbox); else b.ro_bind(d.host, d.sandbox);
        }
        for (const auto& [k, v] : c.display->env) b.setenv(k, v);
    }
    if (p.audio) {
        fs::path sock = c.user.runtime_dir / "pulse/native";
        if (fs::exists(sock)) {
            fs::path in_box = fs::path("/run/user") / uid / "pulse/native";
            b.ro_bind(sock, in_box);
            b.setenv("PULSE_SERVER", "unix:" + in_box.string());
            log::warn("audio=pulse also grants MICROPHONE access to every process in the sandbox "
                      "(the browser's permission prompt does not protect you from a compromised process).");
        } else {
            log::warn("audio=pulse requested but " + sock.string() + " does not exist");
        }
    }
    if (p.clipboard_out) {
        write_file(c.session / "clip", "", 0600);
        b.bind(c.session / "clip", p.clipboard_path);
    }

    // -- environment (--clearenv was emitted at the top: see the comment there) ----------------
    b.setenv("HOME", fhome.string()).setenv("USER", U).setenv("LOGNAME", U).setenv("SHELL", "/bin/sh");
    b.setenv("XDG_RUNTIME_DIR", (fs::path("/run/user") / uid).string());
    if (p.root == RootMode::Host) b.setenv("PATH", "/usr/bin:" + (fhome / ".local/bin").string());
    else b.setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:" + (fhome / ".local/bin").string() + ":" +
                          (fhome / ".cargo/bin").string() + ":" + (fhome / "go/bin").string());
    Strings pass = {"TERM", "LANG", "COLORTERM"};
    pass.insert(pass.end(), p.env_pass.begin(), p.env_pass.end());
    for (auto& k : pass) if (const char* v = std::getenv(k.c_str())) b.setenv(k, v);
    for (auto& [k, v] : p.env_set) b.setenv(k, expand(v, vc));
    for (auto& k : p.env_unset) b.raw({"--unsetenv", k});

    // -- command ----------------------------------------------------------------
    fs::path wd = c.mount_cwd ? fs::path(p.cwd_dest) : fhome;
    b.chdir(wd);
    Strings cmd = c.command_override.empty() ? p.command : c.command_override;
    if (cmd.empty()) throw ProfileError("no command: set [profile] command or pass one after --");
    if (c.expand_command) for (auto& w : cmd) w = expand(w, vc);
    if (c.display && !c.display->background.empty()) {   // X11: the window manager; nothing for Wayland
        Strings wrapped = {"/bin/sh", "-c", c.display->background + " & exec \"$@\"", "holdfast"};
        wrapped.insert(wrapped.end(), cmd.begin(), cmd.end());
        cmd = wrapped;
    }
    b.command(cmd);
    if (p.seccomp == "none") {
        log::warn("seccomp = none: no syscall filter; the sandbox can reach the full kernel syscall surface");
    } else if (p.seccomp == "default") {
        plan.seccomp = c.session / "seccomp.bpf";
        write_default_seccomp(plan.seccomp);
    } else {
        plan.seccomp = expand(p.seccomp, vc);
    }
    return plan;
}

}  // namespace hf
