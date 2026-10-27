#include "core/session.hpp"

#include <set>
#include <unistd.h>

#include <cstdio>
#include <regex>

#include "core/bundle.hpp"
#include "core/launch.hpp"
#include "core/seccomp.hpp"
#include "net/netns.hpp"
#include "ui/display.hpp"
#include "util/log.hpp"

namespace hf {

namespace {

struct SessionDir {
    fs::path path;
    ~SessionDir() { std::error_code ec; if (!path.empty()) fs::remove_all(path, ec); }
};

bool confirm_tty(const std::string& q) {
    FILE* tty = std::fopen("/dev/tty", "r+");
    if (!tty) return false;
    std::fprintf(tty, "%s [y/N] ", q.c_str());
    std::fflush(tty);
    char buf[16] = {0};
    bool yes = std::fgets(buf, sizeof buf, tty) && (buf[0] == 'y' || buf[0] == 'Y');
    std::fclose(tty);
    return yes;
}

Strings expanded_denies(const Profile& p) { return p.extra_deny; }

struct Prepared {
    User user;
    Paths paths;
    std::unique_ptr<Policy> policy;
    fs::path bwrap;
    BwrapVersion ver;
};

Prepared prepare(const Profile& p) {
    Prepared r;
    r.user = resolve_user();
    r.paths = make_paths(r.user, p.name, p.bundle_id);
    r.policy = std::make_unique<Policy>(r.user, expanded_denies(p));
    r.bwrap = find_bwrap();
    r.ver = bwrap_version(r.bwrap);
    return r;
}

NetnsConfig netns_cfg(const Profile& p, const Prepared& pr, const fs::path& session, const VarCtx& vc) {
    NetnsConfig c;
    c.ns_name = p.ns_name.empty() ? derive_ns_name(p.name) : p.ns_name;
    c.wg_conf = expand(p.wg_conf, vc);
    c.session_dir = session;
    c.lock_dir = pr.paths.run_root;
    c.octet = p.subnet_octet;
    c.verify = p.net_verify;
    return c;
}

}  // namespace

void validate_profile(const Profile& p, bool has_cmd) {
    static const std::regex user_ok("^[a-z_][a-z0-9_-]{0,31}$"), host_ok("^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$");
    if (!std::regex_match(p.fake_user, user_ok)) throw ProfileError("[home] user is not a valid unix name: " + p.fake_user);
    if (!std::regex_match(p.hostname, host_ok)) throw ProfileError("[profile] hostname invalid: " + p.hostname);
    if (p.command.empty() && !has_cmd) throw ProfileError("[profile] command is empty (or pass one after --)");
    fs::path cd = p.cwd_dest;
    if (!cd.is_absolute() || cd == "/" ) throw ProfileError("[profile] cwd_dest must be an absolute, non-root path");
    for (const char* sys : {"/usr", "/etc", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/dev", "/sys", "/run", "/var"})
        if (path_under(cd, sys)) throw ProfileError("[profile] cwd_dest must not live under " + std::string(sys));
    if (p.clipboard_out && !fs::path(p.clipboard_path).is_absolute()) throw ProfileError("[clipboard] path must be absolute");
    if (p.root == RootMode::Host) {
        if (p.bins.empty()) log::warn("host mode with an empty [bin] allow list: nothing will be runnable");
        if (!p.wm.empty()) {
            bool sh = false;
            for (auto& b : p.bins) if (b == "sh" || b.rfind("sh=", 0) == 0) sh = true;
            if (!sh) throw ProfileError("[display] wm needs 'sh' in [bin] allow");
        }
    } else {
        if (!p.bins.empty()) log::warn("[bin] is ignored in bundle mode (the bundle is the whole userland)");
        if (p.bundle_id.empty()) throw ProfileError("bundle profile without a resolved os: set [profile] os = NAME (data/os/NAME.os, kind = bundle)");
    }
    if (p.net == NetMode::Ivpn && p.wg_conf.empty()) throw ProfileError("[network] mode=ivpn needs wg_conf = /path/to/wireguard.conf");
    if (p.display == DisplayMode::None && !p.wm.empty())
        log::warn("[display] wm is set but display mode is none; it will be ignored by the X server (none)");
    if (p.display == DisplayMode::None && p.audio) log::warn("audio without display: allowed, but unusual");
}

int run_profile(Profile p, const RunOptions& o) {
    if (o.net) p.net = *o.net;
    if (o.wg_conf) p.wg_conf = *o.wg_conf;
    validate_profile(p, !o.command.empty());
    Prepared pr = prepare(p);

    if (p.root == RootMode::Bundle) {
        if (!bundle_installed(pr.paths)) throw Error("bundle not installed; run: holdfast bundle setup " + p.name);
        bundle_verify(p, pr.paths);
        if (!bundle_provisioned(p, pr.paths)) log::warn("profile changed since the bundle was provisioned; run: holdfast bundle setup " + p.name);
    }

    // -- working tree ------------------------------------------------------------
    CwdMode cm = o.no_cwd ? CwdMode::None : (o.yes || o.cwd ? CwdMode::Yes : p.cwd);
    fs::path cwd = o.cwd ? canon(*o.cwd) : canon(fs::current_path());
    bool mount_cwd = false;
    if (cm != CwdMode::None) {
        pr.policy->check_cwd(cwd);   // throws PolicyError for $HOME, /, media roots, denied trees...
        if (cm == CwdMode::Yes || o.dry) mount_cwd = true;
        else if (confirm_tty(cat("Mount '", cwd.string(), "' read-write at ", p.cwd_dest, "?"))) mount_cwd = true;
        else log::info("working tree not mounted");
    }

    SessionDir sd;
    sd.path = make_session_dir(pr.user, pr.paths, p.name);
    VarCtx vc; vc.user = &pr.user; vc.paths = &pr.paths; vc.cwd = cwd;

    PlanCtx c;
    c.user = pr.user; c.paths = pr.paths; c.policy = pr.policy.get(); c.session = sd.path;
    c.cwd = cwd; c.mount_cwd = mount_cwd; c.command_override = o.command;
    c.userns_disable_supported = pr.ver.at_least(0, 8, 0);
    c.network = p.net != NetMode::None;
    c.pasta = p.net == NetMode::Pasta;
    c.pty_proxy = p.terminal == TermMode::Filter && terminal_proxy_possible();
    fs::path pasta;
    if (c.pasta && !o.dry) pasta = find_pasta();

    std::unique_ptr<NetNs> ns;
    std::unique_ptr<XephyrServer> xs;
    std::unique_ptr<ClipboardBridge> cb;

    if (p.net == NetMode::Ivpn) {
        NetnsConfig nc = netns_cfg(p, pr, sd.path, vc);
        if (o.dry) {
            WgInfo w = parse_wg_conf(read_file(nc.wg_conf));
            log::info(cat("[dry-run] ivpn: ns=", nc.ns_name, " endpoint=", w.endpoint_ip, ":", w.endpoint_port,
                          " dns=", join(w.dns, ",")));
        } else {
            ns = std::make_unique<NetNs>(pr.user, nc);
            ns->up();
        }
    }
    if (p.display == DisplayMode::Xephyr) {
        if (o.dry) { DisplayInfo d; d.display = ":90"; d.socket = "/tmp/.X11-unix/X90"; c.display = d; }
        else { xs = XephyrServer::start(pr.user, p, sd.path); c.display = xs->info(); }
    } else if (p.display == DisplayMode::Host) {
        c.display = o.dry ? DisplayInfo{":0", "/tmp/.X11-unix/X0", "", true} : host_x11(pr.user, p);
    }

    Plan plan = build_plan(p, c);

    if (o.dry) {
        std::printf("%s\n", plan.b.pretty().c_str());
        return 0;
    }
    if (p.clipboard_out) cb = std::make_unique<ClipboardBridge>(pr.user, sd.path / "clip", p.clipboard_sanitize);

    Strings launch = launcher_argv(pr.bwrap, sd.path, plan.b, plan.seccomp);
    if (c.pasta) launch = pasta_argv(pasta, launch);
    Strings full = ns ? ns->wrap(launch) : as_user(pr.user, launch);
    log::info(cat("starting '", p.name, "' (", p.root == RootMode::Host ? "host-whitelist" : "bundle", " userland, net=",
                  p.net == NetMode::None ? "none" : p.net == NetMode::Host ? "host" : p.net == NetMode::Pasta ? "pasta" : "ivpn", ")"));
    int rc = run_sandbox(full, p.terminal == TermMode::Filter);
    log::info(cat("sandbox exited with code ", rc));
    return rc;    // destructors: clipboard -> Xephyr -> netns (rules, veth, namespace) -> session dir
}

int net_test(Profile p, const RunOptions& o) {
    p.net = NetMode::Ivpn;
    if (o.wg_conf) p.wg_conf = *o.wg_conf;
    Prepared pr = prepare(p);
    SessionDir sd; sd.path = make_session_dir(pr.user, pr.paths, p.name);
    VarCtx vc; vc.user = &pr.user; vc.paths = &pr.paths;
    NetNs ns(pr.user, netns_cfg(p, pr, sd.path, vc));
    ns.up();
    std::fprintf(stderr, "kill-switch self-test:\n");
    bool ok = ns.selftest();
    std::fprintf(stderr, ok ? "ALL CHECKS PASSED\n" : "SOME CHECKS FAILED\n");
    return ok ? 0 : 1;
}

void net_cleanup(const std::string& ns_name) {
    User u = resolve_user();
    Paths p = make_paths(u, "x");
    NetNs::cleanup_stale(u, ns_name, p.run_root);
}

int doctor() {
    int bad = 0;
    auto row = [&](const std::string& what, bool ok, const std::string& hint, bool required) {
        std::fprintf(stderr, "  [%s] %-28s %s\n", ok ? " ok " : (required ? "FAIL" : "warn"), what.c_str(), ok ? "" : hint.c_str());
        if (!ok && required) ++bad;
    };
    std::fprintf(stderr, "core:\n");
    auto bw = which("bwrap");
    row("bwrap", bw.has_value(), "apt install bubblewrap", true);
    if (bw) {
        auto v = bwrap_version(*bw);
        row("bwrap >= 0.8 (--disable-userns)", v.at_least(0, 8, 0), "older bwrap works; nested userns not blocked", false);
        auto r = run({bw->string(), "--unshare-user", "--ro-bind", "/", "/", "true"}, true);
        row("unprivileged user namespaces", r.ok(),
            "kernel/AppArmor blocks them (Ubuntu 24.04: kernel.apparmor_restrict_unprivileged_userns=0 or an AppArmor profile for bwrap)", true);
    }
    row("setpriv", which("setpriv").has_value(), "util-linux", false);
    row("seccomp filter (built in)", seccomp_available(), "rebuilt without libseccomp: profiles must set `seccomp = none` or a custom .bpf", false);
    row("pasta", which("pasta").has_value(), "package passt; required for [network] mode=pasta and `bundle setup`", false);
    std::fprintf(stderr, "bundle mode:\n");
    for (auto t : {"curl", "tar", "sha256sum"}) row(t, which(t).has_value(), "required for `bundle setup`", false);
    std::fprintf(stderr, "ivpn mode:\n");
    for (auto t : {"ip", "iptables", "wg-quick", "wg", "ping", "sudo"}) row(t, which(t).has_value(), "required for [network] mode=ivpn", false);
    row("ip6tables", which("ip6tables").has_value(), "recommended (IPv6 defence in depth)", false);
    std::fprintf(stderr, "display / extras:\n");
    row("Xephyr", which("Xephyr").has_value(), "xserver-xephyr, for [display] mode=xephyr", false);
    row("xclip or wl-copy", which("xclip").has_value() || which("wl-copy").has_value(), "for [clipboard] mode=out", false);
    return bad ? 1 : 0;
}

}  // namespace hf
