# IVPN / WireGuard namespace

```
host                           netns hf-<profile>
hfhN 10.200.N.1/30 ──veth── hfnN 10.200.N.2/30     hfwgN (wireguard)
  NAT+FORWARD only for                 INPUT/OUTPUT/FORWARD policy DROP;
  endpoint:port/udp                    allowed: lo, veth→endpoint:port, wg iface
```

`[network] mode = ivpn` needs root for the namespace, veth and firewall rules. holdfast itself always runs as you: it prefixes
only those commands with `sudo`, and the sandboxed program is started through `setpriv --reuid=<you>`, so it never has root.
It asks for your password at most once. If it had to ask, it **revokes the sudo ticket again (`sudo -k`) when it is done**, so
nothing else of yours can ride on it afterwards; a ticket you already had before running holdfast is left alone. While the
sandbox is running the ticket stays alive, because tearing the namespace down at exit needs it. During that time any other
process of yours in the same terminal session can use it too (the sandboxed program cannot: no sudo, no setuid, no privileges).
You can also run `sudo -E holdfast ...` instead.
`holdfast net-test PROFILE` brings the namespace up and checks that the tunnel carries traffic, the direct veth path is
blocked, traffic dies when the wg interface is down, and the policy is DROP.
`holdfast net-cleanup NAME` removes a stale namespace left behind by a crash.

For plain internet access without a VPN use `mode = pasta` (see `docs/CONCEPTS.md`); it needs no root.

## No handshake

`no WireGuard handshake after ~7s: the WireGuard config is probably wrong or stale` is the usual outcome of an old or mis-generated
config: the server answers, WireGuard cannot validate the answer, nothing flows. Download a fresh config from your provider (and
make sure it includes the `PresharedKey` if your account uses one), put it where `wg_conf` points, and run again. Nothing leaked:
the kill switch was armed first and the namespace is torn down.

Everything else is only shown with `-v`: wg-quick's own command log, and on a failed handshake the packet counters of the four
rules one handshake crosses plus the kernel's view of the interface. They tell a bad config apart from a blocked path:

| counter | stops here means |
|---|---|
| sent from the namespace = 0 | wg-quick did not configure the interface or the Endpoint route; check `sudo ip netns exec <ns> wg show` |
| forwarded by this host = 0 | **another firewall on the host drops forwarded traffic before holdfast's rule.** The common case is nftables with `policy drop` on its forward chain (the stock Arch `/etc/nftables.conf`): an `iptables` ACCEPT cannot override another table's DROP at the same hook |
| answers back = 0 | the handshake left your machine and nothing returned: wrong Endpoint IP/port, UDP blocked by the network, or the provider does not know this key |
| answers delivered = 0 | answers reach the host but not the namespace: reverse-path filtering or the NAT rule |
| all non-zero, `transfer` shows `0` received | the path and your firewall are fine and WireGuard discarded every answer: a stale key/config or a PresharedKey mismatch (the usual case). holdfast says whether your config has a `PresharedKey` line; the key itself is never printed |

The tunnel counts as verified as soon as a ping to the tunnel's DNS address (or `1.1.1.1`) is answered, since the kill switch lets
nothing else out. `[network] verify = no` skips the check (the kill switch still applies).

If your counters stop at "forwarded by this host = 0" and the host's nftables has a forward chain with `policy drop`, allow
holdfast's veth in that chain once (adjust the table and chain names to your ruleset; these are the common ones). The rules are scoped to the endpoint:

```sh
sudo nft insert rule inet filter forward iifname "hfh*" ip daddr <endpoint-ip> udp dport <port> accept
sudo nft insert rule inet filter forward oifname "hfh*" ct state established,related accept
```

To make that permanent, put the same two rules in your `/etc/nftables.conf` forward chain. holdfast does not edit your firewall
rules for you.

## What changed vs. the original scripts

- The kill switch is armed **before** `wg-quick up` (default-DROP policy, not appended rules): no leak window; IPv6 gets the same treatment.
- Host NAT/FORWARD/INPUT rules are scoped to **endpoint:port/udp only**, tagged with a comment, and the veth is otherwise dropped on the host (the old rules MASQUERADE-d and forwarded the whole subnet).
- A per-namespace **flock**: a second session of the same profile is refused instead of tearing down the first one's network (the old script ran `cleanup` unconditionally at start). Crashed leftovers are found by tag and removed.
- WireGuard configs containing `PreUp/PostUp/PreDown/PostDown/SaveConfig/Table` are **rejected** (wg-quick would execute them as root). The endpoint must be an IPv4 literal (no DNS query outside the tunnel). The config is copied to a private dir under a safe interface name; your file is never modified.
- `ip_forward` is restored on exit if holdfast changed it.
