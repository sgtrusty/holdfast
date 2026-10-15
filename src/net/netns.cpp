#include "net/netns.hpp"

#include <unistd.h>

#include <chrono>
#include <regex>
#include <thread>

#include "util/log.hpp"

namespace hf {

// ---------------------------------------------------------------------------------
// config parsing
// ---------------------------------------------------------------------------------

WgInfo parse_wg_conf(const std::string& text) {
    static const std::regex ipv4(R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)");
    static const std::regex hook(R"(^\s*(PreUp|PostUp|PreDown|PostDown|SaveConfig|Table)\s*=)", std::regex::icase);
    static const std::regex dns(R"(^\s*DNS\s*=\s*(.*)$)", std::regex::icase);
    static const std::regex ep(R"(^\s*Endpoint\s*=\s*(.*)$)", std::regex::icase);
    WgInfo w;
    int endpoints = 0;
    std::stringstream ss(text);
    std::string line;
    while (std::getline(ss, line)) {
        std::smatch m;
        if (std::regex_search(line, m, hook))
            throw ProfileError("WireGuard config uses '" + trim(m[1].str()) +
                               "': wg-quick would execute it as root / alter routing; remove it");
        if (std::regex_match(line, m, dns)) {
            for (auto& d : split_ws([&] { std::string s = m[1].str(); for (auto& c : s) if (c == ',') c = ' '; return s; }()))
                w.dns.push_back(d);
            continue;  // stripped from the sanitised copy (keeps wg-quick away from host resolvconf)
        }
        if (std::regex_match(line, m, ep)) {
            ++endpoints;
            std::string v = trim(m[1].str());
            auto colon = v.rfind(':');
            std::string host = colon == std::string::npos ? v : v.substr(0, colon);
            std::string port = colon == std::string::npos ? "" : v.substr(colon + 1);
            if (!std::regex_match(host, ipv4))
                throw ProfileError("Endpoint must be an IPv4 literal (got '" + v +
                                   "'); resolve hostnames yourself so no DNS query ever leaves outside the tunnel");
            int p = 0;
            try { p = std::stoi(port); } catch (...) {}
            if (p < 1 || p > 65535) throw ProfileError("Endpoint port invalid: " + v);
            w.endpoint_ip = host; w.endpoint_port = p;
        }
        w.sanitized += line + "\n";
    }
    if (endpoints != 1) throw ProfileError("WireGuard config must contain exactly one Endpoint (found " + std::to_string(endpoints) + ")");
    return w;
}

bool valid_ns_name(const std::string& n) {
    static const std::regex ok("^hf-[a-z0-9_-]{1,40}$");
    return std::regex_match(n, ok);
}
std::string derive_ns_name(const std::string& profile) { return "hf-" + profile; }

int derive_octet(const std::string& n) {
    uint32_t h = 2166136261u;
    for (unsigned char c : n) { h ^= c; h *= 16777619u; }
    return static_cast<int>(h % 254) + 1;
}

// ---------------------------------------------------------------------------------
// NetNs
// ---------------------------------------------------------------------------------

NetNs::NetNs(const User& u, NetnsConfig cfg) : user_(u), cfg_(std::move(cfg)) {
    if (!valid_ns_name(cfg_.ns_name)) throw ProfileError("namespace name must match hf-[a-z0-9_-]{1,40}: " + cfg_.ns_name);
    int o = cfg_.octet ? cfg_.octet : derive_octet(cfg_.ns_name);
    vh_ = cat("hfh", o); vn_ = cat("hfn", o); wgif_ = cat("hfwg", o);
    host_ip_ = cat("10.200.", o, ".1"); ns_ip_ = cat("10.200.", o, ".2");
}

NetNs::~NetNs() { down(); }

Strings NetNs::in_ns(Strings cmd) const {
    Strings v = {"ip", "netns", "exec", cfg_.ns_name};
    v.insert(v.end(), cmd.begin(), cmd.end());
    return as_root(v);
}

void NetNs::must(const Strings& argv, const std::string& what) {
    auto r = run(argv);
    if (!r.ok()) throw Error(cat("network setup failed (", what, "): ", join(argv, " ")));
}

void NetNs::add_host_rule(Rule r) {
    Strings a = {r.tool};
    if (!r.table.empty()) { a.push_back("-t"); a.push_back(r.table); }
    a.push_back(r.insert ? "-I" : "-A");
    a.push_back(r.chain);
    if (r.insert) a.push_back("1");
    for (auto& w : split_ws(r.spec)) a.push_back(w);
    must(as_root(a), "host firewall rule");
    r.added = true;
    rules_.push_back(std::move(r));
}

bool NetNs::ping(const Strings& extra, int wait_s) {
    Strings c = {"ping", "-c1", cat("-W", wait_s)};
    c.insert(c.end(), extra.begin(), extra.end());
    return run(in_ns(c), true).ok();
}

void NetNs::up() {
    fs::create_directories(cfg_.lock_dir);
    if (!lock_.try_acquire(cfg_.lock_dir / ("netns-" + cfg_.ns_name + ".lock")))
        throw Error("namespace '" + cfg_.ns_name + "' is in use by another holdfast session");

    wg_ = parse_wg_conf(read_file(cfg_.wg_conf));
    const std::string ep = wg_.endpoint_ip, port = std::to_string(wg_.endpoint_port);
    const std::string tag = "holdfast:" + cfg_.ns_name;
    have_ip6_ = which("ip6tables").has_value();
    if (!which("wg-quick") || !which("ip") || !which("iptables")) throw Error("need ip, iptables and wg-quick (wireguard-tools) installed");

    if (!is_root()) { log::info("requesting sudo for network setup (one prompt; ticket is kept alive until cleanup)"); if (!run({"sudo", "-v"}).ok()) throw Error("sudo authentication failed"); sudo_keepalive_start(); }

    // We hold the lock => anything with our name is a stale leftover from a crashed run.
    teardown(true);

    std::string wgfile = (cfg_.session_dir / (wgif_ + ".conf")).string();
    write_file(wgfile, wg_.sanitized, 0600);

    try {
        created_ = true;
        must(as_root({"ip", "netns", "add", cfg_.ns_name}), "ip netns add");
        must(in_ns({"ip", "link", "set", "lo", "up"}), "lo up");

        must(as_root({"ip", "link", "add", vh_, "type", "veth", "peer", "name", vn_}), "veth create");
        must(as_root({"ip", "link", "set", vn_, "netns", cfg_.ns_name}), "veth move");
        must(as_root({"ip", "addr", "add", host_ip_ + "/30", "dev", vh_}), "host addr");
        must(as_root({"ip", "link", "set", vh_, "up"}), "host link up");
        must(in_ns({"ip", "addr", "add", ns_ip_ + "/30", "dev", vn_}), "ns addr");
        must(in_ns({"ip", "link", "set", vn_, "up"}), "ns link up");
        run(in_ns({"sysctl", "-qw", "net.ipv6.conf." + vn_ + ".disable_ipv6=1"}), true);
        must(in_ns({"ip", "route", "add", ep + "/32", "via", host_ip_, "dev", vn_}), "endpoint route");

        // Host side: the namespace may reach *only* endpoint:port/udp, nothing else, ever.
        if (read_file("/proc/sys/net/ipv4/ip_forward").rfind("1", 0) != 0) {
            must(as_root({"sysctl", "-qw", "net.ipv4.ip_forward=1"}), "ip_forward");
            fwd_changed_ = true;
        }
        const std::string cm = " -m comment --comment " + tag;
        add_host_rule({"iptables", "nat", "POSTROUTING", "-s " + ns_ip_ + "/32 -d " + ep + "/32 -p udp --dport " + port + cm + " -j MASQUERADE", false, false});
        add_host_rule({"iptables", "", "FORWARD", "-o " + vh_ + cm + " -j DROP", true, false});
        add_host_rule({"iptables", "", "FORWARD", "-i " + vh_ + cm + " -j DROP", true, false});
        add_host_rule({"iptables", "", "FORWARD", "-o " + vh_ + " -s " + ep + "/32 -d " + ns_ip_ + "/32 -p udp --sport " + port +
                       " -m conntrack --ctstate ESTABLISHED,RELATED" + cm + " -j ACCEPT", true, false});
        add_host_rule({"iptables", "", "FORWARD", "-i " + vh_ + " -s " + ns_ip_ + "/32 -d " + ep + "/32 -p udp --dport " + port + cm + " -j ACCEPT", true, false});
        add_host_rule({"iptables", "", "INPUT", "-i " + vh_ + cm + " -j DROP", true, false});

        // Kill switch FIRST (default-deny), tunnel second: no window where traffic can leak.
        log::info("arming kill switch (default DROP) before bringing the tunnel up");
        for (const char* t : {"iptables", "ip6tables"}) {
            if (std::string(t) == "ip6tables" && !have_ip6_) continue;
            for (const char* ch : {"INPUT", "OUTPUT", "FORWARD"}) must(in_ns({t, "-P", ch, "DROP"}), "default policy");
            must(in_ns({t, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"}), "ks lo out");
            must(in_ns({t, "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"}), "ks lo in");
        }
        must(in_ns({"iptables", "-A", "OUTPUT", "-o", vn_, "-d", ep, "-p", "udp", "--dport", port, "-j", "ACCEPT"}), "ks endpoint out");
        must(in_ns({"iptables", "-A", "INPUT", "-i", vn_, "-s", ep, "-p", "udp", "--sport", port, "-j", "ACCEPT"}), "ks endpoint in");
        if (!have_ip6_) log::warn("ip6tables not found: IPv6 is only constrained by routing (no v6 route exists outside the tunnel)");

        if (!wg_.dns.empty()) {
            fs::path rc = cfg_.session_dir / "resolv.conf";
            std::string body;
            for (auto& d : wg_.dns) body += "nameserver " + d + "\n";
            write_file(rc, body, 0644);
            must(as_root({"install", "-D", "-m", "0644", rc.string(), "/etc/netns/" + cfg_.ns_name + "/resolv.conf"}), "netns resolv.conf");
        }

        log::info("bringing up WireGuard inside " + cfg_.ns_name);
        must(in_ns({"wg-quick", "up", wgfile}), "wg-quick up");
        up_ = true;
        for (const char* t : {"iptables", "ip6tables"}) {
            if (std::string(t) == "ip6tables" && !have_ip6_) continue;
            must(in_ns({t, "-A", "OUTPUT", "-o", wgif_, "-j", "ACCEPT"}), "ks wg out");
            must(in_ns({t, "-A", "INPUT", "-i", wgif_, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"}), "ks wg in");
        }
        if (cfg_.verify) verify_tunnel();
    } catch (...) {
        down();
        throw;
    }
}

void NetNs::verify_tunnel() {
    const std::string target = wg_.dns.empty() ? "1.1.1.1" : wg_.dns.front();
    log::info("verifying tunnel (ping " + target + " through " + wgif_ + ")");
    ping({target}, 3);  // first packet triggers the handshake
    for (int i = 0; i < 10; ++i) {
        auto r = capture(in_ns({"wg", "show", wgif_, "latest-handshakes"}));
        // "<pubkey>\t<unix-ts>"; ts==0 => no handshake yet
        auto tab = r.out.find('\t');
        if (tab != std::string::npos && trim(r.out.substr(tab + 1)) != "0") { log::info("WireGuard handshake OK"); return; }
        std::this_thread::sleep_for(std::chrono::milliseconds(700));
    }
    throw Error("no WireGuard handshake after ~7s (wrong endpoint/keys, or UDP blocked); aborting");
}

bool NetNs::selftest() {
    bool ok = true;
    auto check = [&](const char* what, bool pass) { std::fprintf(stderr, "  [%s] %s\n", pass ? "PASS" : "FAIL", what); ok &= pass; };
    check("tunnel carries traffic (ping 1.1.1.1 via wg)", ping({"1.1.1.1"}, 3));
    check("direct path via veth is blocked (ping -I veth 1.1.1.1)", !ping({"-I", vn_, "1.1.1.1"}, 2));
    run(in_ns({"ip", "link", "set", wgif_, "down"}), true);
    check("kill switch: traffic dies when wg interface is down", !ping({"1.1.1.1"}, 2));
    auto r = capture(in_ns({"iptables", "-L", "OUTPUT", "-v", "-n", "-x"}));
    check("default OUTPUT policy is DROP", r.out.find("policy DROP") != std::string::npos);
    return ok;
}

Strings NetNs::wrap(Strings inner) const {
    Strings w = in_ns({"setpriv", cat("--reuid=", user_.uid), cat("--regid=", user_.gid), "--init-groups", "--"});
    w.insert(w.end(), inner.begin(), inner.end());
    return w;
}

void NetNs::teardown(bool quiet) noexcept {
    try {
        for (auto it = rules_.rbegin(); it != rules_.rend(); ++it) {
            if (!it->added) continue;
            Strings a = {it->tool};
            if (!it->table.empty()) { a.push_back("-t"); a.push_back(it->table); }
            a.push_back("-D"); a.push_back(it->chain);
            for (auto& w : split_ws(it->spec)) a.push_back(w);
            run(as_root(a), true);
        }
        rules_.clear();
        // Stale rules from a crashed predecessor are matched by tag and removed too.
        const std::string tag = "holdfast:" + cfg_.ns_name;
        for (const char* tool : {"iptables"}) {
            for (auto [table, chain] : {std::pair<const char*, const char*>{"", "FORWARD"}, {"", "INPUT"}, {"nat", "POSTROUTING"}}) {
                for (int guard = 0; guard < 16; ++guard) {
                    Strings s = {tool};
                    if (*table) { s.push_back("-t"); s.push_back(table); }
                    s.push_back("-S"); s.push_back(chain);
                    auto r = capture(as_root(s));
                    std::stringstream ss(r.out); std::string line, hit;
                    while (std::getline(ss, line)) if (line.find(tag) != std::string::npos && line.rfind("-A ", 0) == 0) { hit = line; break; }
                    if (hit.empty()) break;
                    hit.replace(0, 2, "-D");
                    Strings d = {tool};
                    if (*table) { d.push_back("-t"); d.push_back(table); }
                    for (auto& w : split_words(hit)) d.push_back(w);
                    if (!run(as_root(d), true).ok()) break;
                }
            }
        }
        run(as_root({"ip", "netns", "delete", cfg_.ns_name}), true);
        run(as_root({"ip", "link", "del", vh_}), true);
        if (valid_ns_name(cfg_.ns_name)) run(as_root({"rm", "-rf", "--", "/etc/netns/" + cfg_.ns_name}), true);
        if (fwd_changed_) {
            auto r = capture(as_root({"ip", "netns", "list"}));
            if (r.out.find("hf-") == std::string::npos) run(as_root({"sysctl", "-qw", "net.ipv4.ip_forward=0"}), true);
            fwd_changed_ = false;
        }
        (void)quiet;
    } catch (...) {}
}

void NetNs::down() noexcept {
    if (!created_) return;
    log::info("tearing down network namespace " + cfg_.ns_name);
    teardown(true);
    created_ = false; up_ = false;
    sudo_keepalive_stop();
}

void NetNs::cleanup_stale(const User& u, const std::string& ns, const fs::path& lock_dir) {
    NetnsConfig c; c.ns_name = ns; c.lock_dir = lock_dir;
    NetNs n(u, c);
    fs::create_directories(lock_dir);
    if (!n.lock_.try_acquire(lock_dir / ("netns-" + ns + ".lock"))) throw Error("namespace '" + ns + "' belongs to a live session");
    if (!is_root()) { if (!run({"sudo", "-v"}).ok()) throw Error("sudo authentication failed"); }
    n.teardown(false);
    log::info("cleaned " + ns);
}

}  // namespace hf
