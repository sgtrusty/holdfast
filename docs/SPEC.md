# holdfast – technical specification (v0.1)

## 1. Goals / non-goals

**Goals.** (G1) Run an untrusted or semi-trusted program with only the filesystem, binaries, network
and display it was explicitly granted. (G2) Declarative, reviewable profiles; `print` shows the exact
bwrap argv. (G3) Fail closed: unknown keys, unknown variables, missing bundles, policy violations,
unsafe WireGuard configs are errors, never warnings. (G4) Leave no host state behind (netns, veth,
iptables rules, `ip_forward`, X servers, temp files). (G5) No third-party C++ dependencies; no
shell-string execution.

**Non-goals.** Defence against kernel exploits, a malicious *host* user, or hardware side channels;
multi-user daemon; container image management; Windows/macOS.

## 2. Source layout

```
src/
  main.cpp                CLI grammar, command dispatch, exit codes
  util/common.{hpp,cpp}   Error types, trim/split_words/shell_quote, path_under/norm/canon
  util/log.{hpp,cpp}      leveled stderr logger
  util/sys.{hpp,cpp}      User resolution, argv-only exec (run/capture/spawn/wait), sudo wrapping +
                          keepalive, which(), file IO (0600, root->user chown), flock, sha256 (via sha256sum)
  core/profile.{hpp,cpp}  Profile struct, strict INI parser, profile lookup
  core/paths.{hpp,cpp}    on-disk layout, $VAR expansion + glob, Policy (deny-list / sensitive roots)
  core/argbuilder.hpp     typed bwrap argv builder (+ separate command vector, pretty printer)
  core/plan.{hpp,cpp}     Profile+PlanCtx -> bwrap argv (rootfs, identity, home, mounts, git guard,
                          fonts, display, audio, clipboard, env); git/font/xauth helpers
  core/launch.{hpp,cpp}   bwrap discovery/version, args-file trampoline, signal-forwarding runner
  core/bundle.{hpp,cpp}   Alpine fetch/verify/extract, provisioning stage, stamp, purge
  core/session.{hpp,cpp}  run_profile orchestration, validate_profile, net_test, doctor
  net/netns.{hpp,cpp}     WireGuard config parsing/sanitising, NetNs lifecycle, kill switch, self-test
  ui/display.{hpp,cpp}    XephyrServer, host X11, ClipboardBridge
tests/test_main.cpp       83 dependency-free unit checks      tests/e2e.sh  real-bwrap smoke test
profiles/*.profile        example profiles                    docs/                this documentation
```

Dependency direction (no cycles): `util` ← `core/{profile,paths,argbuilder}` ← `core/plan` ←
`core/{launch,bundle}` ← `core/session` ; `net` and `ui` depend on `util` (+`core/plan.hpp` types for
`ui`); `session` wires everything.

## 3. CLI

```
holdfast run [opts] PROFILE [-- CMD...]     holdfast libs [--check|--refresh] [OS]
holdfast print|check PROFILE                holdfast net-test PROFILE | net-cleanup NAME
holdfast list [libs|os]                     holdfast doctor | help | version
opts: --net=none|pasta|host|ivpn --wg=FILE --cwd=DIR --no-cwd -y -n/--dry-run --refresh --check -v
```
There is no bundle or purge command: a bundle profile sets its userland up on first `run`, and state is plain folders
under the data dir that you can inspect or delete (`doctor` prints the location). Details: `docs/CONCEPTS.md`, `src/cli/args.cpp`.
`--` ends option parsing; everything after replaces `[profile] command`.

## 4. Profile model
See `PROFILE_REFERENCE.md`. Parsing is two-phase: *parse* (syntax, enums, booleans, name regexes;
no filesystem access) → *plan time* (variable expansion, globbing, policy). Variables available in
paths/commands: `$HOME $USER $UID $GID $XDG_RUNTIME_DIR $STATE $CWD $ARCH` (and `~/`). An unknown variable
is a `ProfileError`. Inline comments: whitespace + `#`.

## 5. Run pipeline (`run_profile`)

1. Apply CLI overrides; `validate_profile` (regexes for user/hostname, `cwd_dest` not under system prefixes, `sh` present when `wm` is used, `wg_conf` present for ivpn, …).
2. `prepare`: resolve target user (`SUDO_USER` if root, refuse plain root), layout paths, build `Policy`, locate bwrap, probe version.
3. Bundle mode: require installed bundle; warn when the provision stamp no longer matches the profile.
4. Working tree: choose cwd; `Policy::check_cwd` (throws → exit 3); confirm on `/dev/tty` for `cwd=ask` (no tty ⇒ not mounted).
5. Create the per-run **session dir** `<XDG_RUNTIME_DIR>/holdfast/<name>.<pid>` (0700; fallback `/tmp/holdfast-UID`).
6. Start network (`NetNs::up`) → display (`XephyrServer::start` / `host_x11`) in that order.
7. `build_plan` (§6) – writes session files, returns the argv.
8. Start `ClipboardBridge` if configured.
9. `launcher_argv` writes `bwrap.args` (NUL-separated, 0600) and returns the trampoline argv; wrap with `NetNs::wrap` (`[sudo] ip netns exec NS setpriv --reuid … --`) or `as_user` (setpriv when root).
10. `run_with_signals`: SIGTERM/SIGHUP forwarded to the child chain; SIGINT swallowed (tty already delivered it to the process group).
11. Teardown by RAII in reverse order: clipboard → Xephyr (TERM, then KILL) → netns (rules, namespace, veth, `/etc/netns/NS`, `ip_forward`, sudo keepalive) → session dir.

`--dry-run` executes 1-7 with *no* network/display side effects (placeholder display `:90`) and prints
`ArgBuilder::pretty()`.

### Why a trampoline and an args file
`bwrap --args FD` avoids argv length limits and keeps mount lists off `ps`. A pipe fd would be closed by
`sudo`/`setpriv`, so the list goes in a 0600 file in the private session dir and a **constant** script
(`a=$1; s=$2; b=$3; shift 3; exec 3<$a; exec $b [--seccomp 4] --args 3 -- "$@"`) opens it. The sandboxed
command is passed on the real argv because bwrap does not accept the command from the args fd (verified
against bwrap 0.9.0). No user data is ever interpolated into script text.

## 6. Plan assembly (order matters: parents before children)

1. **Isolation core**: `--unshare-all --unshare-user --unshare-ipc --unshare-pid --unshare-uts --unshare-cgroup`, `--share-net` only when network ≠ none, `--die-with-parent`, `--new-session` (profile), `--cap-drop ALL`, `--disable-userns` (bwrap ≥ 0.8), `--hostname`, fresh `--proc`, `--dev`, tmpfs `/tmp` `/run`, `/run/user/UID` (0700), `/var/tmp`.
2. **Userland**
   - *host*: `--dir /usr/bin`; `/bin /sbin /usr/sbin → usr/bin`; `/usr/lib /usr/lib64` read-only (when `libs=yes`); `/lib /lib64` symlinked or bound exactly as on the host; each `[bin] allow` entry: `which` → `realpath` → policy check → `--ro-bind real /usr/bin/NAME` (+ the real path itself for alternatives/multicall targets outside `$HOME`); defaults (`ld.so.cache`, terminfo, zoneinfo, `/etc/ssl`, ca-certificates, os-release, and `resolv.conf` only when networked).
   - *bundle*: `bin sbin lib lib64 usr` of the rootfs read-only (symlinks preserved); `/etc` is a tmpfs repopulated entry-by-entry from the bundle except identity/network files (`passwd group shadow nsswitch.conf resolv.conf hosts hostname machine-id …`).
3. **Identity**: generated `passwd` (root, fake user with real uid/gid, nobody), `group`, `nsswitch.conf`, `hosts` bound read-only. Host `/etc/passwd|group|machine-id` are never exposed.
4. **Fonts** (when a display exists and `[fonts] allow` is set): `/usr/share/fonts` becomes a tmpfs holding only matching font *files* (path match, case-insensitive, ≤ 600) + a generated `fonts.conf`.
5. **Home**: persistent `<state>/home` → `/home/<fake_user>` (XDG dirs pre-created); `[home] bind/ro_bind` map `$HOME/<rel>`; `[fs]` mounts (globs allowed). Every user-specified source passes `Policy::check_bind(canonical_path, rw)` and the *canonical* path is what bwrap receives (limits symlink-swap races).
6. **Working tree**: `--bind CWD /shared`, then one `--ro-bind` per `.git` entry (dir or file; no descent into matches) *after* the rw bind so it overlays it. A bind-mount point cannot be renamed or removed from inside.
7. **Display/audio/clipboard** binds + `DISPLAY`/`XAUTHORITY`/`PULSE_SERVER`.
8. **Environment**: `--clearenv`; fixed `HOME USER LOGNAME SHELL XDG_RUNTIME_DIR PATH`; pass-through of `TERM LANG COLORTERM` + `[env] pass`; then `[env] set`, `[env] unset`.
9. `--chdir` (`/shared` or fake home), optional `wm` wrapper (`sh -c '<wm> & exec "$@"'`), command.

## 7. Policy

`Policy(user, extra_deny)` builds a canonical deny set: credential/browser dirs under `$HOME`
(`.ssh .gnupg .aws .azure .kube .docker .netrc .git-credentials .password-store .pki .mozilla
.librewolf .thunderbird .config/{gcloud,gh,google-chrome,chromium,BraveSoftware,Signal,Bitwarden,rclone,holdfast}
.local/share/{keyrings,kwalletd} .npmrc .pypirc .cargo/credentials.toml .terraform.d`), system secrets
(`/etc/{shadow,gshadow,sudoers,sudoers.d,ssh} /root /boot /var/lib/docker /sys /proc/kcore`), sockets
(`docker.sock`, libvirt, `$XDG_RUNTIME_DIR/{bus,gnupg,keyring,ssh-agent.socket,gcr,wayland-0}`) and `[fs] deny`.

`check_bind(src, rw)` rejects when, after `weakly_canonical`: `src` is a sensitive root (`/`, `/home`,
`$HOME`, `/home`'s parent, `/run/media/USER[/label]`, `/media/USER[/label]`, `/usr /etc /var /run /tmp /opt
/mnt /dev /proc /sys /boot /bin /sbin /lib /lib64`), **or** `src` is inside a denied path, **or** `src`
is an ancestor of an *existing* denied path, **or** (rw) `src` is under a system prefix. Exit code 3.
Binaries and system defaults are bound by holdfast itself and bypass the user-mount sensitive-root rule
but binaries are still checked against the deny set.

## 8. Bundle subsystem

Layout: `<data>/cache/alpine/<arch>/alpine-minirootfs-X.Y.Z-<arch>.tar.gz`,
`<data>/bundles/<os>/{rootfs,spec.stamp,tarball.sha256}`, `<data>/profiles/<name>/{home,provision.stamp}`; `<data>` =
`$HOLDFAST_HOME` or `~/.local/share/holdfast`. Arch ∈ {x86_64, aarch64}. `<os>` is the `data/os` file the profile names.

`bundle_ensure` (called by `run`; `print`/`check` only verify): nothing installed → set it up; installed and
`spec.stamp` equal → done (re-provision only if the provision stamp differs); installed but the definition changed → error
unless `--refresh`. Setting up, with no host process touching the downloaded bytes:
(1) a **bootstrap sandbox** (`--unshare-all`, network through pasta, default seccomp, host `sh curl tar gzip sha256sum …`
bound read-only, only `/cache` and `/work` writable) downloads `<mirror>/v<X.Y>/releases/<arch>/alpine-minirootfs-<X.Y.Z>-<arch>.tar.gz`
(exact releases only; HTTPS, TLS ≥ 1.2) unless a cached file matches the pinned hash; (2) verifies sha256 against
`alpine_sha256` if pinned, else against the mirror's `.sha256`, deleting the file and failing on mismatch; (3) extracts into
`rootfs.tmp` (`--no-same-owner`, no `/dev/*`) and renames it to `rootfs`; the host then writes `spec.stamp =
sha256(version|mirror|pin|packages)`; (4) a **provision sandbox**: the rootfs bound **writable** at `/`, `--uid 0 --gid 0`
(userns-mapped), network through pasta, fake home bound, running `set -e; apk update; apk add --no-cache <packages>;
<provision lines…>`; then `provision.stamp = sha256(version|mirror|pin|packages|provision)` is written.

## 9. Network namespace subsystem (`NetNs`)

State machine: `lock → teardown(stale) → ns add → veth → addresses/route → host rules → kill switch →
dns → wg-quick up → wg-iface rules → verify`. Any exception → `down()` (idempotent).

- Naming: ns `hf-<profile>` (`^hf-[a-z0-9_-]{1,40}$` enforced before any `rm -rf /etc/netns/<ns>`), octet N = FNV-1a(ns)%254+1 or `[network] subnet`; veth `hfhN`/`hfnN`, wg iface `hfwgN`, addresses `10.200.N.1/30` ↔ `.2/30`.
- Locking: `flock(LOCK_EX|LOCK_NB)` on `<run_root>/netns-<ns>.lock` for the session's lifetime.
- Host rules (all tagged `-m comment --comment holdfast:<ns>`): nat POSTROUTING MASQUERADE for `ns_ip → endpoint:port/udp`; FORWARD: accept out (same match), accept return (`conntrack ESTABLISHED,RELATED`, `sport`), DROP `-i/-o veth`; INPUT DROP `-i veth`. Teardown deletes by saved spec, then sweeps by tag.
- Kill switch (inside ns, **before** the tunnel): policies INPUT/OUTPUT/FORWARD = DROP (v4 and, if present, v6); accept lo; accept veth↔endpoint:port/udp only; after `wg-quick up`, accept OUTPUT `-o wg` and INPUT `-i wg` for `ESTABLISHED,RELATED`. Route to the endpoint is a `/32` via the host veth; no default route exists outside the tunnel.
- `wg-quick` input is a sanitised copy (DNS stripped, hooks rejected). DNS from the profile goes to `/etc/netns/<ns>/resolv.conf`; `ip netns exec` overlays it, and bwrap then binds `/etc/resolv.conf` from that view.
- Verify: ping the first DNS server (or 1.1.1.1) to trigger the handshake, then poll `wg show IF latest-handshakes` ≤ ~7 s.
- Privilege: `sudo` (or direct when already root) for `ip/iptables/sysctl/wg-quick/install/rm`; a keepalive thread runs `sudo -n -v` every 45 s so teardown cannot hang on a password prompt. The sandbox itself always runs as the unprivileged user (`setpriv --reuid --regid --init-groups`). bwrap's user namespace cannot modify a netns owned by the initial user namespace, and caps are dropped.

## 10. Display, clipboard, audio

- **Xephyr**: first free display ≥ 90 (checks socket + lock), retry on early death; 16 random bytes cookie written as an X authority file with `FamilyWild` (matches regardless of the sandbox's different hostname), passed via `-auth`, bound at `/tmp/.Xauthority` with `XAUTHORITY`; `-nolisten tcp -terminate`, window title marks it untrusted. Abstract-socket access is per-netns, and the cookie is enforced either way.
- **Host X11**: only with `allow_host_x11 = yes`; shares the real socket (+ your `XAUTHORITY`); warned loudly.
- **Clipboard**: inotify `IN_CLOSE_WRITE` on a session file bound into the sandbox; content ≤ 1 MiB is piped to `xclip -selection clipboard` / `wl-copy` as the user, then the file is truncated. One direction only.
- **Audio**: binds only `$XDG_RUNTIME_DIR/pulse/native` read-only and sets `PULSE_SERVER`; logs the microphone warning.

## 11. Error handling & exit codes
`Error` → 1 · `PolicyError` → 3 · unexpected `std::exception` → 70 · usage → 2 · otherwise child status.
All diagnostics go to stderr with `[hf]`, `[hf:WARN]`, `[hf:ERROR]` prefixes; stdout is reserved for
`print`, `list`, `libs`, `doctor`. Colour (classic SGR, `src/util/style.cpp`) is used only when the stream is a terminal,
`NO_COLOR` is unset and `TERM` is not `dumb`; piped output is always plain.

## 12. Verification status (v0.1)

| Area | Status |
|---|---|
| Parser, policy (incl. symlink bypass, ancestor exposure), WG parsing, git/font/xauth helpers, plan invariants | unit-tested (83 checks) |
| Host-mode sandbox under real bwrap 0.9.0: whitelist, fake identity, no network, `.git` ro + not renamable, `$HOME` refusal | `tests/e2e.sh` |
| netns lifecycle (add/veth/rules/kill-switch/teardown, concurrency lock, stale recovery, `ip_forward` restore, DNS overlay) | exercised for real with a stub `wg-quick`/`wg` |
| Real WireGuard handshake against IVPN, `net-test` check 1 | **not exercised** (no tunnel available) |
| Xephyr startup / cookie auth, clipboard bridge, host-X11, pulse | **not exercised** (no X server in CI image) |
| Bundle setup on first `run` (sandboxed download, verify, extract, apk provisioning) and bundle-mode *run* | spec/stamp logic and plan generation unit-tested; the sandboxed network stages **not exercised** |
| Seccomp, pasta, terminal filter, `libs = minimal` | see `docs/DEFERRED.md` (written and unit-tested; not yet exercised under a real bwrap) |
