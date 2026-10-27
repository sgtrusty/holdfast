#include "core/session.hpp"

#include <set>
#include <unistd.h>

#include <cstdio>
#include <regex>

#include "core/bundle.hpp"
#include "core/datadefs.hpp"
#include "core/launch.hpp"
#include "core/seccomp.hpp"
#include "net/netns.hpp"
#include "protocol/display/display.hpp"
#include "ui/clipboard.hpp"
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
    const std::string conf = expand(p.wg_conf, vc);
    std::error_code ec;
    if (!fs::is_regular_file(conf, ec))
        throw Error(cat("WireGuard config not found: ", conf, "\n  Download one from your VPN provider (IVPN: https://www.ivpn.net/setup/wireguard/) and save it there, "
                        "or point at it with --wg=FILE (or [network] wg_conf).\n  It needs exactly one Endpoint, as an IPv4 literal, and no PostUp/PreUp hooks."));
    c.wg_conf = conf;
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
    } else {
        if (!p.bins.empty()) log::warn("[bin] is ignored in bundle mode (the bundle is the whole userland)");
        if (p.bundle_id.empty()) throw ProfileError("bundle profile without a resolved os: set [profile] os = NAME (data/os/NAME.os, kind = bundle)");
    }
    if (p.net == NetMode::Ivpn && p.wg_conf.empty()) throw ProfileError("[network] mode=ivpn needs wg_conf = /path/to/wireguard.conf");
    display::validate(p);                              // consent for host displays, X11-only keys, unimplemented combinations
    if (!p.display && p.audio) log::warn("audio without display: allowed, but unusual");
}

Strings debug_shell(const Profile& p) {
    if (p.root == RootMode::Bundle)   // constant script, nothing interpolated
        return {"/bin/sh", "-c", "if command -v bash >/dev/null 2>&1; then exec bash; else exec sh; fi"};
    auto allowed = [&](const std::string& n) {
        for (const auto& t : p.bins) if (t.substr(0, t.find('=')) == n) return true;
        return false;
    };
    if (allowed("bash")) return {"bash"};
    if (allowed("sh")) return {"sh"};
    throw Error(cat("--debug needs a shell inside the sandbox: add 'bash' (or 'sh') to [bin] allow of profile '", p.name,
                    "' (and, with libs = minimal, a [libs] use that provides it)"));
}

int run_profile(Profile p, RunOptions o) {
    if (o.net) p.net = *o.net;
    if (o.wg_conf) p.wg_conf = *o.wg_conf;
    if (o.debug) {
        if (!o.command.empty()) throw Error("--debug replaces the command with a shell; drop the words after `--`");
        o.command = debug_shell(p);
        p.env_set.emplace_back("PS1", cat("(holdfast:", p.name, ") \\w\\$ "));   // so you can tell which sandbox you are in
        log::info(cat("debug: running ", o.command[0] == "/bin/sh" ? "bash (or sh)" : o.command[0], " in the sandbox of '", p.name,
                      "' instead of its command; everything else is exactly what the profile gets"));
    }
    validate_profile(p, !o.command.empty());
    Prepared pr = prepare(p);

    if (p.root == RootMode::Bundle && !o.userland_ready)
        bundle_ensure(p, pr.user, pr.paths, o.refresh, o.dry);   // first run builds it, in sandboxes

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
    std::unique_ptr<display::Backend> disp;
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
    disp = display::open(p, pr.user, sd.path, o.dry);   // nullptr without a display; X11 and Wayland differ only inside protocol/display
    if (disp) c.display = disp->setup();

    Plan plan = build_plan(p, c);

    if (o.dry) {
        std::printf("%s\n", plan.b.pretty().c_str());
        return 0;
    }
    if (p.clipboard_out) cb = std::make_unique<ClipboardBridge>(pr.user, sd.path / "clip", p.clipboard_sanitize);

    Strings launch = launcher_argv(pr.bwrap, sd.path, plan.b, plan.seccomp);
    if (c.pasta) launch = pasta_argv(pasta, launch);
    Strings full = ns ? ns->wrap(launch, c.pty_proxy) : as_user(pr.user, launch);
    log::info(cat("starting '", p.name, "' (", p.root == RootMode::Host ? "host-whitelist" : "bundle", " userland, net=",
                  p.net == NetMode::None ? "none" : p.net == NetMode::Host ? "host" : p.net == NetMode::Pasta ? "pasta" : "ivpn", ")"));
    int rc = run_sandbox(full, p.terminal == TermMode::Filter, ns && c.pty_proxy);
    if (rc != 0) log::info(cat("sandbox exited with code ", rc));
    return rc;    // destructors: clipboard -> display backend (e.g. Xephyr) -> netns (rules, veth, namespace) -> session dir
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

}  // namespace hf
