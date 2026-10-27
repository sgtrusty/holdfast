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

// ---- why a handshake did not complete (pure, unit-tested; the NetNs methods only gather the inputs) -------------------
// Packet counters of the four rules one handshake crosses: namespace OUTPUT -> host FORWARD -> (internet) -> host FORWARD
// back -> namespace INPUT. -1 = could not be read.
struct HandshakeTrail {
    long sent = -1;        // left the namespace towards the endpoint (namespace OUTPUT accept, out = the veth)
    long forwarded = -1;   // reached the host and was forwarded (host FORWARD accept, in = the host veth)
    long replies = -1;     // an answer from the endpoint came back to the host (host FORWARD accept, out = the host veth)
    long delivered = -1;   // that answer entered the namespace (namespace INPUT accept, in = the veth)
    bool nft_forward_drop = false;   // some nftables table has a forward chain with `policy drop`
    long wg_rx_bytes = -1;           // bytes WireGuard itself ACCEPTED from the peer (`wg show <if> transfer`); 0 = it discarded everything
    int config_has_psk = -1;         // 1/0: does the WireGuard config have a PresharedKey line (the key is never printed); -1 unknown
};
// Pure: bytes received from `wg show <if> transfer` output ("<pubkey>\t<rx>\t<tx>"); -1 if it cannot be parsed.
long wg_transfer_rx(const std::string& transfer_output);
// Pure: true when the config text has a `PresharedKey =` line.
bool config_has_preshared_key(const std::string& wg_conf_text);
// Packets counted by the first rule of `iptables -L CHAIN -v -n -x --line-numbers` output matching target/in/out ("*" =
// any interface); -1 when no rule matches.
long iptables_hits(const std::string& listing, const std::string& target, const std::string& in, const std::string& out);
// True when `nft list ruleset` shows a chain hooked at forward with `policy drop`.
bool has_nft_forward_drop(const std::string& ruleset);
// One actionable paragraph: the four counters, where they stop, the likely cause and the fix.
std::string explain_handshake_failure(const HandshakeTrail& t, const std::string& host_veth, const std::string& endpoint_ip, int endpoint_port);

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
    // ip netns exec NS setpriv ... [setsid -w -c --] inner     (new_ctty: the pty proxy's terminal becomes inner's controlling tty)
    Strings wrap(Strings inner, bool new_ctty = false) const;
    const std::string& name() const { return cfg_.ns_name; }

    static void cleanup_stale(const User& u, const std::string& ns_name, const fs::path& lock_dir);

private:
    struct Rule { std::string tool, table, chain, spec; bool insert; bool added; };
    Strings in_ns(Strings cmd) const;
    void must(const Strings& argv, const std::string& what);
    void add_host_rule(Rule r);
    void teardown(bool quiet) noexcept;
    void verify_tunnel();
    std::string diagnose_handshake() noexcept;   // reads counters while the rules still exist; never throws
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
