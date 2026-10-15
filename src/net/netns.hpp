// holdfast - WireGuard-in-netns with a fail-closed kill switch.
//
//   host                         netns "hf-<profile>"
//   ┌──────────────┐  veth /30  ┌──────────────────────────────────────┐
//   │ hfhN 10.200.N.1├──────────┤ hfnN 10.200.N.2      hfwgN (wireguard)│
//   └──────┬───────┘            │  OUTPUT policy DROP; only                │
//          │ NAT + FORWARD      │   lo, veth->endpoint:port/udp, wg iface  │
//          ▼ (endpoint:port only)└──────────────────────────────────────┘
#pragma once
#include "util/sys.hpp"

namespace hf {

struct WgInfo {
    std::string endpoint_ip;
    int endpoint_port = 0;
    Strings dns;
    std::string sanitized;   // config without DNS, safe to hand to wg-quick
};
// Throws ProfileError for: hooks (PreUp/PostUp/...), Table=, non-IPv4-literal or
// multiple Endpoints.
WgInfo parse_wg_conf(const std::string& text);

std::string derive_ns_name(const std::string& profile);   // "hf-<profile>"
int derive_octet(const std::string& ns_name);              // 1..254
bool valid_ns_name(const std::string& n);

struct NetnsConfig {
    std::string ns_name;
    fs::path wg_conf;       // user's WireGuard config (never modified)
    fs::path session_dir;   // private dir for the sanitised copy
    fs::path lock_dir;
    int octet = 0;          // 0 => derived
    bool verify = true;
};

class NetNs {
public:
    NetNs(const User& u, NetnsConfig cfg);
    NetNs(const NetNs&) = delete;
    NetNs& operator=(const NetNs&) = delete;
    ~NetNs();

    void up();                          // throws Error; leaves nothing behind on failure
    void down() noexcept;               // idempotent
    bool selftest();                    // destructive kill-switch test (net-test)
    Strings wrap(Strings inner) const;  // ip netns exec NS setpriv ... inner
    const std::string& name() const { return cfg_.ns_name; }

    static void cleanup_stale(const User& u, const std::string& ns_name, const fs::path& lock_dir);

private:
    struct Rule { std::string tool, table, chain, spec; bool insert; bool added; };
    Strings in_ns(Strings cmd) const;
    void must(const Strings& argv, const std::string& what);
    void add_host_rule(Rule r);
    void teardown(bool quiet) noexcept;
    void verify_tunnel();
    bool ping(const Strings& extra, int wait_s);

    User user_;
    NetnsConfig cfg_;
    FileLock lock_;
    WgInfo wg_;
    std::string vh_, vn_, wgif_, host_ip_, ns_ip_;
    std::vector<Rule> rules_;
    bool created_ = false, up_ = false, fwd_changed_ = false, have_ip6_ = false;
};

}  // namespace hf
