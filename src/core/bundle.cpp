#include "core/bundle.hpp"

#include <algorithm>
#include <cstdio>

#include "core/datadefs.hpp"
#include "core/plan.hpp"
#include "core/seccomp.hpp"
#include "core/session.hpp"
#include "util/log.hpp"

namespace hf {

std::string alpine_arch() {
    std::string a = host_arch();
    if (a == "x86_64" || a == "aarch64") return a;
    throw Error("unsupported architecture for the Alpine bundle: " + a);
}

// A dep is installed into the profile's persistent $HOME, so its stamp depends on the recipe and on that home's path.
std::string dep_stamp(const Profile& p, const DepRecipe& d) { return sha256_str(cat(d.digest, "|", p.fake_user)); }

// Everything the OS file declares (version, mirror, pinned hash, packages). Deps are per profile and are not part of
// it. All profiles naming the same os read the same file, so a mismatch means the file changed after the bundle was
// built (or two data directories define the same os name differently).
std::string bundle_spec(const Profile& p) {
    return sha256_str(cat(p.alpine_version, "|", p.alpine_mirror, "|", p.alpine_sha256, "|", join(p.apk_packages, " ")));
}

void bundle_verify(const Profile& p, const Paths& paths) {
    std::string have, tar;
    try { have = trim(read_file(paths.bundle / "spec.stamp")); } catch (...) {}
    try { tar = trim(read_file(paths.bundle / "tarball.sha256")); } catch (...) {}
    const std::string id = paths.bundle.filename().string();
    const std::string fix = cat("re-run with --refresh to rebuild it (holdfast run --refresh ", p.name, "); changes made inside it are discarded");
    if (have.empty())
        throw Error(cat("the userland '", id, "' has no spec.stamp (not built by this holdfast?); ", fix));
    if (have != bundle_spec(p))
        throw Error(cat("the userland '", id, "' was built from a different data/os/", id, ".profile (version, mirror, sha256 or packages) "
                        "than the one now in use; ", fix));
    if (!p.alpine_sha256.empty() && tar != p.alpine_sha256)
        throw Error(cat("the userland '", id, "' was built from tarball ", tar, " but data/os/", id, ".profile pins ", p.alpine_sha256, "; ", fix));
}

bool bundle_installed(const Paths& paths) { return fs::exists(paths.rootfs / "bin/busybox") || fs::exists(paths.rootfs / "bin/sh"); }

namespace {

std::string read_stamp(const fs::path& f) {
    try { return trim(read_file(f)); } catch (...) { return ""; }
}
fs::path dep_stamp_path(const Paths& paths, const DepRecipe& d) { return paths.state / "deps" / (d.name + ".stamp"); }

// The network of the two install sandboxes comes from the os file's [install]: pasta's private namespace, or none
// (bwrap's --unshare-all then keeps the network namespace unshared).
void install_network(ArgBuilder& b, const Profile& p) {
    b.flag("--unshare-all").flag("--unshare-user");
    if (p.install_net == NetMode::Pasta) b.flag("--share-net");
}

// Separate from install_network: in the apk sandbox it must come after the rootfs is bound at / (parents before children).
void install_resolv(ArgBuilder& b, const Profile& p, const fs::path& session) {
    if (p.install_net != NetMode::Pasta) return;
    write_file(session / "resolv.conf", pasta_resolv_conf(), 0644);   // network is pasta's private namespace; see launch.hpp
    b.ro_bind(session / "resolv.conf", "/etc/resolv.conf");
}

Strings install_launch(const Profile& p, const User& u, const fs::path& session, const ArgBuilder& b, const fs::path& seccomp) {
    Strings v = launcher_argv(find_bwrap(), session, b, seccomp);
    if (p.install_net == NetMode::Pasta) v = pasta_argv(find_pasta(), v, p.install_dns);
    return as_user(u, v);
}

std::string install_net_desc(const Profile& p) {
    if (p.install_net != NetMode::Pasta) return "no network";
    return cat("network via pasta, DNS ", p.install_dns);
}

// Checked before anything is created, so a missing setting is one sentence instead of a half-built userland.
void require_install_dns(const Profile& p, const std::string& what) {
    if (p.install_net == NetMode::Pasta && p.install_dns.empty())
        throw ProfileError(cat(what, " needs the network, and holdfast does not fall back to the host's /etc/resolv.conf: set the resolver "
                               "in data/os/", p.os, ".profile:\n  [install]\n  dns = 1.1.1.1"));
}

// The bootstrap runs HOST binaries (sh, tar, sha256sum, curl, ...). What it may mount from the host is exactly what the os
// file's `[install] use` lists, resolved like a `libs = minimal` profile: those libs' saved files on this OS, never whole
// library directories, never /etc/ld.so.cache. Resolved before anything is created.
Strings bootstrap_tools(const Profile& p) {
    Strings t = {"sh", "tar", "gzip", "sha256sum", "cut", "chmod", "rm", "mkdir", "mv"};
    if (p.install_net == NetMode::Pasta) t.push_back("curl");    // offline uses the cached tarball only
    return t;
}

HostLibs require_host_tools(const Profile& p, const User& u) {
    const std::string fix = cat("data/os/", p.os, ".profile");
    if (p.install_use.empty())
        throw ProfileError(cat("setting up the Alpine userland runs host tools (", join(bootstrap_tools(p), " "), ") in a sandbox, and nothing from "
                               "the host is mounted unless you list it. Declare the libs that provide them in ", fix, ":\n  [install]\n"
                               "  use = shell archive coreutils", p.install_net == NetMode::Pasta ? " net certs" : "",
                               "\n(data/lib/*.profile; their files on this host come from `holdfast libs --refresh`)"));
    HostLibs h = resolve_host_libs(p.install_use, p.roots.empty() ? data_roots(u.home.string()) : p.roots, "");
    Strings missing;
    for (const std::string& t : bootstrap_tools(p)) if (!h.commands.count(t)) missing.push_back(t);
    if (!missing.empty())
        throw ProfileError(cat("[install] use = ", join(p.install_use, " "), " in ", fix, " does not provide: ", join(missing, " "),
                               "; add the data/lib that lists them"));
    return h;
}

// The install sandboxes get the default filter unless the profile turned seccomp off (a custom BPF file is written for
// the profile's own programs, not for curl/tar/apk).
fs::path install_seccomp(const Profile& p, const fs::path& session) {
    if (p.seccomp == "none") return {};
    fs::path f = session / "seccomp.bpf";
    write_default_seccomp(f);
    return f;
}

// Runs in the bootstrap sandbox. Constant text: all data arrives through HF_* environment variables, never by
// interpolation. /cache holds downloaded tarballs, /work is the bundle directory.
const char* kBootstrapScript = R"SH(
set -eu
umask 077
cd /cache
if [ -f "$HF_NAME" ] && [ -n "$HF_SHA" ] && echo "$HF_SHA  $HF_NAME" | sha256sum -c - >/dev/null 2>&1; then
  echo "using cached $HF_NAME" >&2
else
  rm -f "$HF_NAME"
  echo "downloading $HF_NAME" >&2
  curl -fsSL --proto =https --tlsv1.2 --retry 2 -o "$HF_NAME" "$HF_BASE/$HF_NAME"
fi
want="$HF_SHA"
if [ -z "$want" ]; then
  echo "warning: no alpine_sha256 pinned; trusting the mirror's .sha256 (integrity only, not authenticity)" >&2
  want=$(curl -fsSL --proto =https --tlsv1.2 --retry 2 "$HF_BASE/$HF_NAME.sha256" | cut -d' ' -f1)
fi
if ! echo "$want  $HF_NAME" | sha256sum -c - >&2; then
  rm -f "$HF_NAME"
  echo "sha256 mismatch for $HF_NAME" >&2
  exit 3
fi
cd /work
chmod -R u+rwX rootfs rootfs.tmp 2>/dev/null || true
rm -rf rootfs rootfs.tmp spec.stamp tarball.sha256
mkdir rootfs.tmp
tar -C rootfs.tmp --no-same-owner --exclude='./dev/*' -xzf "/cache/$HF_NAME"
[ -d rootfs.tmp/bin ] || { echo "tarball does not look like a rootfs" >&2; exit 4; }
mv rootfs.tmp rootfs
printf '%s\n' "$want" > tarball.sha256
echo "userland ready" >&2
)SH";

// Download, verify and extract the Alpine minirootfs INSIDE a throwaway sandbox: the host only supplies the
// curl/tar/sha256sum binaries, and the sandbox sees nothing of your files, only the two folders it writes.
void fetch_and_extract(const Profile& p, const User& u, const Paths& paths, const fs::path& session, const HostLibs& host) {
    std::string branch;
    if (!is_exact_alpine_release(p.alpine_version, &branch))
        throw ProfileError(cat("alpine_version '", p.alpine_version, "' must be an exact release such as 3.24.3 (data/os/", p.os, ".profile)"));
    if (p.alpine_mirror.rfind("https://", 0) != 0) throw ProfileError("alpine_mirror must be an https:// URL: " + p.alpine_mirror);
    const std::string arch = alpine_arch();
    const std::string ver = p.alpine_version.front() == 'v' ? p.alpine_version.substr(1) : p.alpine_version;
    const std::string name = cat("alpine-minirootfs-", ver, "-", arch, ".tar.gz");

    ArgBuilder b;
    install_network(b, p);
    b.flag("--die-with-parent");
    b.raw({"--cap-drop", "ALL"}).raw({"--hostname", "holdfast-bootstrap"});
    b.raw({"--proc", "/proc"}).raw({"--dev", "/dev"}).tmpfs("/tmp");
    b.dir("/usr/bin");
    b.symlink("usr/bin", "/bin").symlink("usr/bin", "/sbin").symlink("usr/bin", "/usr/sbin");
    bind_host_library_dirs(b, false);                              // only the usr-merge symlinks, no directories
    const Policy pol(u, {});
    for (const std::string& f : host.files) {                      // the [install] use libs' saved files, sorted: parents first
        std::error_code ec;
        if (!fs::exists(f, ec))
            throw Error(cat("library file listed for os '", host.os, "' no longer exists on this host: ", f,
                            " (run `holdfast libs --check`, then `holdfast libs --refresh`)"));
        pol.check_bind(f, false);
        b.ro_bind(canon(f), f);
    }
    for (const std::string& tool : bootstrap_tools(p)) {
        auto hp = which(tool);
        std::error_code ec;
        const fs::path real = hp ? fs::canonical(*hp, ec) : fs::path();
        if (!hp || ec)
            throw Error(cat("fetching the userland needs '", tool, "' installed on the host (it runs inside a sandbox, but the binary comes from the host)"));
        pol.check_bind(real, false);
        b.ro_bind(real, fs::path("/usr/bin") / tool);
        if (real != *hp) b.ro_bind_try(real, real);              // multi-call/alternatives targets that look for themselves
    }
    install_resolv(b, p, session);
    const fs::path cache = paths.cache / "alpine" / arch;
    make_private_dir(cache);
    make_private_dir(paths.bundle);
    b.bind(cache, "/cache").bind(paths.bundle, "/work");
    b.flag("--clearenv").setenv("HOME", "/tmp").setenv("PATH", "/usr/bin");
    b.setenv("HF_BASE", cat(p.alpine_mirror, "/", branch, "/releases/", arch)).setenv("HF_NAME", name).setenv("HF_SHA", p.alpine_sha256);
    b.command({"/bin/sh", "-c", kBootstrapScript});

    log::info(cat("fetching ", name, " into ", cache.string(), " inside a sandbox (", install_net_desc(p), ")"));
    const int rc = run_sandbox(install_launch(p, u, session, b, install_seccomp(p, session)), p.terminal == TermMode::Filter);
    if (rc == 3) throw Error(cat("sha256 mismatch for ", name, ": the download does not match the hash in data/os/", p.os, ".profile; nothing was installed"));
    if (rc == 6)
        throw Error(cat("fetching the Alpine userland failed: the mirror's name did not resolve via ", install_net_desc(p),
                        ". Check that this resolver answers, or set another with [install] dns in data/os/", p.os, ".profile"));
    if (rc != 0) throw Error(cat("fetching the Alpine userland failed (exit ", rc, "); see the messages above"));
}

ArgBuilder writable_args(const Profile& p, const Paths& paths, const fs::path& session) {
    ArgBuilder b;
    install_network(b, p);
    b.flag("--die-with-parent");
    b.raw({"--uid", "0", "--gid", "0"});                          // apk needs to chown as "root" (userns-mapped to you)
    b.raw({"--hostname", "holdfast-provision"});
    b.bind(paths.rootfs, "/");
    b.raw({"--proc", "/proc"}).raw({"--dev", "/dev"}).tmpfs("/tmp");
    install_resolv(b, p, session);
    make_private_dir(paths.home);
    const fs::path fh = fs::path("/home") / p.fake_user;
    b.bind(paths.home, fh);
    b.flag("--clearenv");
    b.setenv("HOME", fh.string()).setenv("USER", p.fake_user);
    b.setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:" + (fh / ".cargo/bin").string() + ":" + (fh / "go/bin").string());
    if (const char* t = std::getenv("TERM")) b.setenv("TERM", t);
    return b;
}

// The ONE step that is not an ordinary profile run: `apk add` for the os packages. A package manager must own the whole
// userland, so this sandbox is deliberately different and says so: the rootfs is bound WRITABLE at /, `--uid 0` makes it
// userns-root (your uid mapped to 0, no real privilege), and the network is pasta's private namespace. Deps do not
// use this; they run as the profile itself (see dep_profile).
void install_os_packages(const Profile& p, const User& u, const Paths& paths, const fs::path& session) {
    log::info(cat("installing the os packages with apk: writable rootfs, userns-root, ", install_net_desc(p), " (data/os/", p.os, ".profile)"));
    ArgBuilder b = writable_args(p, paths, session);
    b.command({"/bin/sh", "-c", apk_script(p.apk_packages)});
    const int rc = run_sandbox(install_launch(p, u, session, b, install_seccomp(p, session)), p.terminal == TermMode::Filter);
    if (rc != 0)
        throw Error(cat("installing the os packages failed (exit ", rc, "); the end of apk's output is above, all of it is in ",
                        (paths.rootfs / kApkLog).string(), ". Check data/os/", p.os, ".profile; `holdfast os-shell ", p.name,
                        "` opens a shell in this exact sandbox to try it by hand"));
}

// Defines hf_fetch for the recipe's `fetch` steps. Constant text: URL, hash and destination arrive as positional
// parameters (each step is `hf_fetch "$1" "$2" "$3"; shift 3`), never interpolated. Same checks as the rootfs download:
// https only, the pinned sha256 decides, a mismatch removes the file and fails the recipe.
const char* kFetchHelper = R"SH(hf_fetch() {
  hf_d="$HOME/$3"
  if [ -f "$hf_d" ] && echo "$2  $hf_d" | sha256sum -c - >/dev/null 2>&1; then echo "fetch: ~/$3 is up to date" >&2; return 0; fi
  mkdir -p "$(dirname "$hf_d")"
  rm -f "$hf_d.part"
  echo "fetch: $1 -> ~/$3" >&2
  curl -fsSL --proto =https --tlsv1.2 --retry 2 -o "$hf_d.part" "$1"
  if ! echo "$2  $hf_d.part" | sha256sum -c - >/dev/null 2>&1; then rm -f "$hf_d.part"; echo "fetch: sha256 mismatch for $1" >&2; exit 3; fi
  mv -f "$hf_d.part" "$hf_d"
}
)SH";

void install_dep(const Profile& p, const Paths& paths, const DepRecipe& d) {
    // The recipe's own tools are checked first, so a missing `go` is one clear sentence instead of a half-run build.
    std::string script = "set -e\n";
    Strings needs = d.needs;
    if (!d.fetch.empty()) { needs.push_back("curl"); needs.push_back("sha256sum"); }
    for (const auto& n : needs)
        script += cat("command -v ", shell_quote(n), " >/dev/null 2>&1 || { echo ",
                      shell_quote(cat("dep '", d.name, "' needs '", n, "' in the userland: add its package to data/os/", p.os, ".profile")),
                      " >&2; exit 5; }\n");
    if (!d.fetch.empty()) script += kFetchHelper;
    for (const auto& l : d.run) script += l + "\n";

    RunOptions ro;
    ro.no_cwd = true;
    ro.yes = true;
    ro.userland_ready = true;                                      // the userland and its packages are already in place
    ro.raw_command = true;                                         // recipe lines are the shell's: $PWD, $HOME, ... are not holdfast's
    ro.command = {"/bin/sh", "-c", script, cat("dep-", d.name)};
    ro.command.insert(ro.command.end(), d.fetch.begin(), d.fetch.end());
    log::info(cat("dep '", d.name, "': an ordinary run of '", p.name, "' with network=", d.net == NetMode::Pasta ? cat("pasta (DNS ", p.install_dns, ")") : "none",
                  " and this recipe as the command"));
    const int rc = run_profile(dep_profile(p, d), ro);
    if (rc == 3) throw Error(cat("dep '", d.name, "': a download did not match its sha256 in data/dep/", d.name, ".profile; nothing was kept"));
    if (rc != 0) throw Error(cat("dep '", d.name, "' failed (exit ", rc, "); see the messages above, fix data/dep/", d.name, ".profile and run again"));
    for (const auto& f : d.provides) {
        std::error_code ec;
        if (!fs::exists(fs::symlink_status(paths.home / f, ec)))
            throw Error(cat("dep '", d.name, "' finished but did not create ~/", f, " (listed in `provides`); fix data/dep/", d.name, ".profile"));
    }
}

}  // namespace

Strings deps_missing_files(const Profile& p, const Paths& paths) {
    Strings out;
    for (const auto& d : p.deps)
        for (const auto& f : d.provides) {
            std::error_code ec;
            if (!fs::exists(fs::symlink_status(paths.home / f, ec))) { out.push_back(d.name); break; }
        }
    return out;
}

std::string apk_script(const Strings& packages) {
    // --no-progress: the progress bar redraws one line, which hides the per-package lines (and a terminal filter may drop it).
    // pipefail so the `tee` copy does not hide apk's exit status; busybox ash has it.
    std::string add = "apk add --no-cache --no-progress";
    for (auto& pk : packages) add += " " + shell_quote(pk);
    return cat("set -eu\nset -o pipefail\nlog=/", kApkLog, "\nmkdir -p \"$(dirname \"$log\")\"\n",
               "if ! { apk update --no-progress && ", add, "; } 2>&1 | tee \"$log\"; then\n",
               "  echo '---- apk failed; the last 60 lines of its output follow (all of it: <bundle>/rootfs/", kApkLog, ") ----' >&2\n",
               "  tail -n 60 \"$log\" >&2\n  exit 1\nfi\n");
}

int bundle_shell(const Profile& p, const User& u, const Paths& paths, bool dry) {
    if (p.root != RootMode::Bundle) throw Error(cat("os-shell needs a bundle profile; '", p.name, "' is mode = host"));
    if (!bundle_installed(paths))
        throw Error(cat("the userland for '", p.name, "' is not set up yet; run the profile once (holdfast run ", p.name, ")"));
    bundle_verify(p, paths);
    require_install_dns(p, "the os shell");
    struct Scratch { fs::path d; ~Scratch() { std::error_code ec; fs::remove_all(d, ec); } } sc{make_session_dir(u, paths, p.name + "-osshell")};
    ArgBuilder b = writable_args(p, paths, sc.d);
    b.setenv("PS1", cat("(holdfast-os:", p.os, ") # "));
    b.command(debug_shell(p));
    if (dry) { std::printf("%s\n", b.pretty().c_str()); return 0; }
    log::warn(cat("os shell for '", p.os, "': writable userland, userns-root, ", install_net_desc(p), ". Changes here are not tracked and apply to "
                  "every profile with os = ", p.os, " until `holdfast run --refresh` rebuilds it"));
    return run_sandbox(install_launch(p, u, sc.d, b, install_seccomp(p, sc.d)), p.terminal == TermMode::Filter);
}

Profile dep_profile(const Profile& p, const DepRecipe& d) {
    Profile r = p;
    r.net = d.net;
    r.dns = d.net == NetMode::Pasta ? p.install_dns : "";      // a dep is an install step: the os file's resolver
    r.cwd = CwdMode::None;
    r.display.reset();
    r.display_use.clear();
    r.allow_host_display = false;
    r.audio = false;
    r.clipboard_out = false;
    r.dep_use.clear();
    r.deps.clear();
    return r;
}

void bundle_ensure(const Profile& p, const User& u, const Paths& paths, bool refresh, bool dry, const Strings& refresh_deps) {
    const bool installed = bundle_installed(paths);
    if (dry) {                                                     // print / check never download or install anything
        if (!installed)
            throw Error(cat("the Alpine userland for '", p.name, "' is not set up yet; run the profile once (holdfast run ", p.name, ") and it is created"));
        bundle_verify(p, paths);
        for (const auto& n : deps_missing_files(p, paths))
            log::warn(cat("dep '", n, "': something it provides is missing; the next run installs it again"));
        return;
    }

    // Decide what is out of date before creating anything. A changed definition is an error unless --refresh.
    bool rebuild = !installed;
    if (installed) {
        try { bundle_verify(p, paths); }
        catch (const Error&) { if (!refresh) throw; rebuild = true; }
    }
    const bool packages_due = rebuild || read_stamp(paths.bundle / "packages.stamp") != bundle_spec(p);
    for (const auto& n : refresh_deps) {
        const bool known = std::any_of(p.deps.begin(), p.deps.end(), [&](const DepRecipe& d) { return d.name == n; });
        if (!known) throw Error(cat("--refresh-dep=", n, ": profile '", p.name, "' has no such dep ([deps] use = ", join(p.dep_use, " "), ")"));
    }
    const Strings gone = deps_missing_files(p, paths);
    std::vector<const DepRecipe*> due;
    for (const auto& d : p.deps) {
        const std::string have = read_stamp(dep_stamp_path(paths, d));
        const bool named = std::find(refresh_deps.begin(), refresh_deps.end(), d.name) != refresh_deps.end();
        if (refresh || named || have.empty()) { due.push_back(&d); continue; }
        if (have != dep_stamp(p, d))
            throw Error(cat("dep '", d.name, "' changed since it was installed into '", p.name, "'; reinstall it with: holdfast run --refresh-dep=",
                            d.name, " ", p.name, " (its commands run again)"));
        if (std::find(gone.begin(), gone.end(), d.name) != gone.end()) {
            log::info(cat("dep '", d.name, "' was installed, but something it provides is gone from ", paths.home.string(), "; running it again"));
            due.push_back(&d);
        }
    }
    if (!rebuild && !packages_due && due.empty()) return;          // the common case: nothing to do

    HostLibs host;
    if (rebuild) { require_install_dns(p, "fetching the Alpine userland"); host = require_host_tools(p, u); }
    if (packages_due && !p.apk_packages.empty()) require_install_dns(p, "installing the os packages (apk)");
    for (const DepRecipe* d : due)
        if (d->net == NetMode::Pasta) require_install_dns(p, cat("dep '", d->name, "'"));

    make_private_dir(paths.state);
    struct Scratch { fs::path d; ~Scratch() { std::error_code ec; fs::remove_all(d, ec); } } sc{make_session_dir(u, paths, p.name + "-setup")};
    if (rebuild) {
        log::info(installed ? "rebuilding the Alpine userland (its definition changed)" : "first run: setting up the Alpine userland");
        fetch_and_extract(p, u, paths, sc.d, host);
        write_file(paths.bundle / "spec.stamp", bundle_spec(p) + "\n", 0600);
        std::error_code ec;
        fs::remove(paths.bundle / "packages.stamp", ec);           // a fresh rootfs has none of the packages
    }
    if (packages_due) {
        if (!p.apk_packages.empty()) install_os_packages(p, u, paths, sc.d);
        write_file(paths.bundle / "packages.stamp", bundle_spec(p) + "\n", 0600);
    }
    for (const DepRecipe* d : due) {
        install_dep(p, paths, *d);
        make_private_dir(paths.state / "deps");
        write_file(dep_stamp_path(paths, *d), dep_stamp(p, *d) + "\n", 0600);
    }
    log::info("userland ready: " + paths.rootfs.string());
}

}  // namespace hf
