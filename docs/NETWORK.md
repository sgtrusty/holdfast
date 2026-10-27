# IVPN / WireGuard namespace

```
host                           netns hf-<profile>
hfhN 10.200.N.1/30 ──veth── hfnN 10.200.N.2/30     hfwgN (wireguard)
  NAT+FORWARD only for                 INPUT/OUTPUT/FORWARD policy DROP;
  endpoint:port/udp                    allowed: lo, veth→endpoint:port, wg iface
```

`[network] mode = ivpn` needs `sudo` (one prompt, kept alive until cleanup) or run as `sudo -E holdfast ...`.
`holdfast net-test PROFILE` brings the namespace up and checks that the tunnel carries traffic, the direct veth path is
blocked, traffic dies when the wg interface is down, and the policy is DROP.
`holdfast net-cleanup NAME` removes a stale namespace left behind by a crash.

For plain internet access without a VPN use `mode = pasta` (see `docs/CONCEPTS.md`); it needs no root.

## What changed vs. the original scripts

- The kill switch is armed **before** `wg-quick up` (default-DROP policy, not appended rules): no leak window; IPv6 gets the same treatment.
- Host NAT/FORWARD/INPUT rules are scoped to **endpoint:port/udp only**, tagged with a comment, and the veth is otherwise dropped on the host (the old rules MASQUERADE-d and forwarded the whole subnet).
- A per-namespace **flock**: a second session of the same profile is refused instead of tearing down the first one's network (the old script ran `cleanup` unconditionally at start). Crashed leftovers are found by tag and removed.
- WireGuard configs containing `PreUp/PostUp/PreDown/PostDown/SaveConfig/Table` are **rejected** (wg-quick would execute them as root). The endpoint must be an IPv4 literal (no DNS query outside the tunnel). The config is copied to a private dir under a safe interface name; your file is never modified.
- `ip_forward` is restored on exit if holdfast changed it.
