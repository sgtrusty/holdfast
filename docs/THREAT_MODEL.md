# Threat model

**Protected asset:** your user's files, credentials, session (X/Wayland/D-Bus/keyring), network position and
clipboard — from the program inside the sandbox.

**Adversary:** the sandboxed program (supply-chain-compromised tool, hostile web page, LLM agent, curious
plugin) running as your uid, able to execute arbitrary code *inside* the sandbox.

| Threat | Mitigation | Residual risk |
|---|---|---|
| Read `~/.ssh`, tokens, browser profiles | Host mode: nothing is mounted unless listed; bundle: private fs. Policy deny-list on every user mount, symlink-resolved | A path you explicitly allow is readable |
| Mount `$HOME`, `/`, media roots by accident/trick | Sensitive-root + ancestor-exposure rules, exit 3 | |
| Run host binaries / find setuid helpers | Only whitelisted binaries exist; `--cap-drop ALL`; nested userns disabled (bwrap ≥ 0.8) | Allowed binaries and libs are real host code |
| Tamper with git history/hooks | `.git` entries re-bound read-only, un-renameable | Repos created *after* launch; hostile build files you later execute |
| Keystroke injection to the launching tty (TIOCSTI) | `--new-session` | Disabled by `new_session = no` |
| Network exfiltration | Default fresh empty netns | `host`/`ivpn` give network by design |
| IP / DNS leak when VPN drops | Default-DROP firewall armed before tunnel, endpoint-only host NAT, tunnel DNS, IPv6 policy DROP | Needs correct host `iptables`; nft-only hosts rely on the iptables-nft shim; Docker's FORWARD chain ordering is handled by inserting at position 1 |
| Privilege escalation via VPN config | `PostUp`/hooks rejected; config copied; names validated before `rm -rf` | You still run wg-quick as root on a config you chose |
| Snoop/inject via X11 | Private Xephyr + random cookie (no host X) | `mode=host` is full exposure (needs explicit flag) |
| Steal microphone | Off by default | `audio=pulse` exposes it to all processes |
| Clipboard sniffing | One-way bridge only | Sandbox can overwrite your clipboard |
| Fingerprinting | Fake identity/hostname, no machine-id, restricted fonts | Browser-level fingerprints remain |
| Tampered bundle download | HTTPS-only, sha256 verify, optional pin | Unpinned hash is same-origin; no GPG yet |
| Stale network state / leaked rules | Lock + tag sweep + RAII teardown + `net-cleanup` | `SIGKILL` of holdfast leaves state until next run/`net-cleanup` |
| Kernel / syscall-surface exploits | userns + caps dropped + pid/ipc/uts/cgroup ns | No built-in seccomp yet |

**Out of scope:** a compromised host, malicious root, kernel 0-days, hardware attacks, covert timing channels.
