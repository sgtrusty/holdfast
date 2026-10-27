# Origins

holdfast merges four earlier approaches.

| Origin | What it contributed |
|---|---|
| `develbox.sh` | **Bundle mode**: the sandbox's whole userland is a private, hash-verified Alpine minirootfs, so your host's `/usr`, `/etc`, `/bin` are never visible. Per-arch. |
| `lvim` | **Host-whitelist mode**: expose only named binaries + libs from the host; fake `passwd`/`group`/`nsswitch`; persistent fake `$HOME`; `.git` re-bound read-only inside the mounted working tree; refusal to mount `$HOME`/`/`; one-way clipboard bridge; offline by default with an online "sync" switch. |
| `run-ivpn-librewolf.sh` | **IVPN/WireGuard in a network namespace** with a kill switch, nested **Xephyr** display (only its socket is shared), minimal font set, mic warning. |
| `wssch` bwrap helper | **Structure**: allowlist → argv builder → `--args` fd, `findGitDirs` pruning, `--clearenv`-style hygiene. |

On top of that it adds a central **deny-list policy** (symlink-safe), strict profile parsing that fails closed, a hardened
network setup (`docs/NETWORK.md`), a default seccomp filter, and a filtered terminal.

## What changed vs. the scripts

- No `--ro-bind / /` of the whole host; no host `/etc/group` leak (lvim bound it); fresh `/dev`; `--clearenv`; fake `/etc/hosts`; no `machine-id`.
- Downloads are HTTPS-only and **hash-verified** (develbox fetched Go/Rust unverified).
- The shell is never used to run a command: everything is an argv vector; the only `sh` is a constant 3-line trampoline that opens the args file.
- Libraries are bound per file from a saved per-OS list instead of mounting `/usr/lib` whole (`libs = minimal`).
- Network access can go through `pasta` (private namespace) instead of sharing the host namespace.
