# holdfast

A small C++20 tool that launches programs inside a **bubblewrap** sandbox whose
contents are *declared*, not inherited. It merges four earlier approaches:

| Origin | What it contributed |
|---|---|
| `develbox.sh` | **Bundle mode**: the sandbox's whole userland is a private, hash-verified Alpine minirootfs, so your host's `/usr`, `/etc`, `/bin` are never visible. Per-arch, per-profile. |
| `lvim` | **Host-whitelist mode**: expose only named binaries + libs from the host; fake `passwd`/`group`/`nsswitch`; persistent fake `$HOME`; `.git` re-bound read-only inside the mounted working tree; refusal to mount `$HOME`/`/`; one-way clipboard bridge; offline by default with an online "sync" switch. |
| `run-ivpn-librewolf.sh` | **IVPN/WireGuard in a network namespace** with a kill switch, nested **Xephyr** display (only its socket is shared), minimal font set, mic warning. |
| `wssch` bwrap helper | **Structure**: allowlist → argv builder → `--args` fd, `findGitDirs` pruning, `--clearenv`-style hygiene. |

On top of that it adds a central **deny-list policy** (symlink-safe), strict
profile parsing that fails closed, and a considerably hardened network setup
(see *What changed vs. the scripts* below).

```
holdfast run lazyvim              # offline editor, current dir mounted at /shared, .git read-only
holdfast run --net=pasta lazyvim  # same, online ("sync" mode) through a private pasta netns
holdfast run librewolf-ivpn       # amnesic browser, nested X, all traffic via WireGuard netns
holdfast bundle setup lazygit-dev # one-time: fetch+verify Alpine, apk add, build tools
holdfast run lazygit-dev          # run inside the private Alpine userland
holdfast print lazyvim            # show the exact bwrap command line, change nothing
```

## Build

holdfast builds with [predep](https://github.com/10per5/predep) driving
[premake5](https://premake.github.io/) (no CMake). Install both, then:

```sh
# one-time: put premake5 + predep on PATH (Linux x86_64)
curl -fsSL "https://github.com/premake/premake-core/releases/download/v5.0.0/premake-5.0.0-linux.tar.gz" \
  | tar -xz && install -m 0755 premake5 /usr/local/bin/
curl -fsSL "https://github.com/10per5/predep/releases/latest/download/predep-linux-x86_64.tar.gz" \
  | tar -xz && install -m 0755 predep /usr/local/bin/
premake5 --version && predep --version

predep                # build the holdfast binary            -> bin/holdfast
predep check          # build + unit tests                   (zero warnings is the bar)
predep e2e            # real-bwrap smoke test (non-root, needs userns)
sudo predep install   # optional; installs binary + example profiles + docs
```

Or invoke premake5 directly:

```
premake5 gmake && make config=release -j$(nproc)     # -> bin/holdfast
./bin/holdfast_tests                                 # unit checks
```

Requirements: Linux, C++20 compiler, `premake5` (any recent 5.x), `make`,
`predep`, and `bwrap` (tested with 0.9.0; ≥ 0.8 needed for `--disable-userns`).
Build dependency: `libseccomp` headers (`libseccomp-dev`/`libseccomp-devel`) for the default seccomp filter;
`HOLDFAST_SECCOMP=OFF` builds without it (profiles must then say `seccomp = none`). Run `holdfast doctor` to see which optional
features your host supports.

> **Warnings are errors.** The build enables `-Werror` by default to keep the
> "zero warnings" bar. To relax it for a local build: `HOLDFAST_WERROR=OFF predep`.

Optional runtime tools: `pasta` from `passt` (`[network] mode=pasta`, and `bundle setup`), `curl tar sha256sum` (bundle), `ip iptables wg-quick wg ping sudo setpriv`
(ivpn), `Xephyr` (nested display), `xclip` or `wl-copy` (clipboard).

> **Ubuntu 24.04+**: AppArmor blocks unprivileged user namespaces for bwrap by
> default. Either install a bwrap AppArmor profile or set
> `kernel.apparmor_restrict_unprivileged_userns=0`. `holdfast doctor` detects this.

## Concepts

**Profile** – an INI file describing one sandbox (see `docs/PROFILE_REFERENCE.md`).
Looked up by name in `$HOLDFAST_PROFILES`, `~/.config/holdfast/profiles/`,
`/etc/holdfast/profiles/`, or passed as a path. Unknown sections/keys are errors.
Examples live in `profiles/`; `holdfast init NAME > ~/.config/holdfast/profiles/NAME.profile`.

**Userland modes**
- `mode = host` – a tmpfs root is assembled from: the library files listed in the profile's `[libs]` section (`libs = minimal`, default; generate the list with `holdfast libs PROFILE`; `libs = full` binds `/usr/lib*` read-only instead), each binary in `[bin] allow` bound individually at `/usr/bin/<name>`, plus the files you list in `[fs]`. Anything not listed does not exist.
- `mode = bundle` – the userland is `~/.local/share/holdfast/profiles/<name>/rootfs`, an Alpine minirootfs downloaded over HTTPS, sha256-verified (optionally pinned), extracted unprivileged, then provisioned (`apk add`, your `provision` lines) in a network-enabled, writable stage. Day-to-day runs mount it read-only.

**Network** – `none` (default, fresh empty netns), `pasta` (private netns with outbound internet; host loopback and abstract sockets unreachable), `host` (shares the host netns, **including abstract unix sockets such as X11**; avoid), or `ivpn` (WireGuard inside `hf-<profile>`, see below).

**Display** – `none`, `xephyr` (private nested X server with a random cookie; only its socket enters the sandbox), or `host` (requires `allow_host_x11 = yes`, because it hands over your keyboard and screen).

**Working tree** – `cwd = ask|yes|none`: the current directory is bound read-write at `/shared`; every `.git` (directory *or* worktree/submodule file) inside is re-bound read-only.

**Policy** – before any host path is bound it is canonicalised (symlinks resolved) and checked against a deny-list (`~/.ssh`, `~/.gnupg`, cloud/browser credentials, `/etc/shadow`, docker/libvirt sockets, session bus, …) and a sensitive-root list (`/`, `$HOME`, `/home`, removable-media roots, `/usr`, `/etc`, …). A mount is refused if it *is*, is *inside*, or would *contain* a denied path. Extend with `[fs] deny = …`.

## IVPN / WireGuard namespace

```
host                           netns hf-<profile>
hfhN 10.200.N.1/30 ──veth── hfnN 10.200.N.2/30     hfwgN (wireguard)
  NAT+FORWARD only for                 INPUT/OUTPUT/FORWARD policy DROP;
  endpoint:port/udp                    allowed: lo, veth→endpoint:port, wg iface
```
Needs `sudo` (one prompt, kept alive until cleanup) or run as `sudo -E holdfast …`.
`holdfast net-test PROFILE` brings it up and checks: tunnel carries traffic, the
direct veth path is blocked, traffic dies when the wg interface is down, policy is DROP.

### What changed vs. the scripts

- Kill switch is armed **before** `wg-quick up` (default-DROP policy, not appended rules) – no leak window; IPv6 gets the same treatment.
- Host NAT/FORWARD/INPUT rules are scoped to **endpoint:port/udp only**, tagged with a comment, and the veth is otherwise dropped on the host (the old rules MASQUERADE-d and forwarded the whole subnet).
- A per-namespace **flock**: a second session of the same profile is refused instead of tearing down the first one's network (the old script ran `cleanup` unconditionally at start). Crashed leftovers are found by tag and removed (`holdfast net-cleanup NAME`).
- WireGuard configs containing `PreUp/PostUp/PreDown/PostDown/SaveConfig/Table` are **rejected** (wg-quick would execute them as root). Endpoint must be an IPv4 literal (no DNS query outside the tunnel). The config is copied to a private dir under a safe interface name; your file is never modified.
- `ip_forward` is restored on exit if holdfast changed it.
- No `--ro-bind / /` of the whole host; no host `/etc/group` leak (lvim bound it); fresh `/dev`; `--clearenv`; fake `/etc/hosts`; no `machine-id`.
- Downloads are HTTPS-only and **hash-verified** (develbox fetched Go/Rust unverified).
- The shell is never used to run a command: everything is argv; the only `sh` is a constant 3-line trampoline that opens the args file.

## Safety notes (read these)

- `audio = pulse` exposes the **microphone** to every process in the sandbox.
- `terminal = filter` (default): the sandbox runs on its own pty and its output is filtered, so it cannot write your clipboard (OSC 52), forge titles/hyperlinks, or make your terminal type replies into your shell. TTY programs get a real controlling terminal and Ctrl-C works. `terminal = passthrough` falls back to `new_session` (blocks TIOCSTI, but Ctrl-C then reaches holdfast, not the program).
- `[clipboard] mode = out` lets the sandbox *set* your host clipboard (not read it).
- The `.git` guard protects history/hooks of repos that exist at launch. It does not stop the sandbox from writing a hostile `Makefile`/`.envrc`/IDE task that *you* later run outside.
- Bundle provisioning runs **with network** and trusts the packages/commands in your profile.
- The Alpine hash comes from the same mirror as the tarball (integrity, not authenticity). Pin `alpine_sha256` for real supply-chain assurance.
- bwrap is not a VM: kernel bugs reachable through the syscall surface apply. A default seccomp denylist (`bpf`, `io_uring`, `mount`, `keyctl`, `userfaultfd`, `TIOCSTI`, ...) is on unless the profile says `seccomp = none` or supplies its own `.bpf`; it is a denylist, not a full syscall allowlist.

See `docs/THREAT_MODEL.md` for scope, `docs/SPEC.md` for the technical design and `docs/DEFERRED.md` for known limitations and untested areas.

## Exit codes
`0` ok · `1` error · `2` usage · `3` refused by policy · `70` internal · otherwise the sandboxed command's exit code (`128+n` if killed by signal `n`).

## Roadmap
Built-in libseccomp filter · minimal-library mode (resolve `DT_NEEDED` per allowed binary instead of binding `/usr/lib`) · nftables-native backend · Wayland socket passthrough with security-context · `alpine` signature (GPG) verification · TOML profiles · overlayfs bundles (bwrap ≥ 0.11) · per-profile resource limits (cgroups).
