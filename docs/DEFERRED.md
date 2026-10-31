# Deferred work and known limitations

Things we know about and chose not to solve yet. Keep this honest: if something here gets fixed, delete it;
if a new gap is found, add it. Nothing here is a secret, and none of it should be claimed as done in the README.

## Not yet run (written and type-checked only)

The pasta mode, default seccomp filter, `libs = minimal` / `holdfast libs`, shared bundles, and the terminal
filter + pty proxy were written in an environment without a linker or `bwrap`. They need a real run:
`make config=release && ./bin/holdfast_tests`, `sh tests/e2e.sh`, `sh tests/e2e_tty.sh`, then interactive
checks (resize, Ctrl-C, mouse, exit) with `lazyvim` and `lazygit-dev`. Specific assumptions to confirm:

- pasta: the option set (`--config-net --no-map-gw -t/-u/-T/-U none --dns-forward`), that DNS works through the
  forwarder address (`192.0.2.53`), and that bwrap's `--unshare-user --uid/--gid` works nested inside pasta's user namespace.
- seccomp: example profiles that use a browser (`librewolf-ivpn`) have not been checked against the default denylist.
- the terminal filter may drop a sequence some program legitimately needs; widen the allowlist in `src/ui/termfilter.cpp`
  only after checking the reply/side effects of that sequence.

## Terminal

- **Hard kill of holdfast.** The pty proxy puts your terminal in raw mode and restores it on every normal and
  SIGTERM/SIGHUP exit. If holdfast itself is killed with `SIGKILL` (or crashes hard) nothing can restore it:
  the terminal stays raw and may keep mouse reporting or the alternate screen on. Fix it with `reset`
  (or `stty sane`). The sandbox dies with holdfast (`--die-with-parent`), so only the terminal state is affected.
- **Bidi controls in terminal output are not stripped.** Unicode has invisible "bidirectional" control characters
  (U+202A..U+202E and U+2066..U+2069, e.g. RIGHT-TO-LEFT OVERRIDE) that change the order in which text is *displayed*
  without changing the bytes. A hostile program could print a file name or command whose bytes are one thing but
  which looks like something else ("Trojan Source"). The clipboard bridge already strips them. The terminal filter does
  not, because most terminal emulators do not implement bidi at all, so the practical risk is low and stripping could
  mangle genuine right-to-left text. Revisit if a bidi-aware terminal is a target.
- **Misleading drawn text.** The filter controls escape sequences, not meaning: a sandboxed program can still print
  "Password:" or fake prompts.
- **Late replies.** The terminal's answers to allowed queries (DA, cursor position, ...) go to the sandboxed program.
  A reply that arrives after the program exited can still land in your shell; pending input is flushed on exit but
  cannot catch what is still in flight.

## Sandbox hardening

- **seccomp is a denylist**, not a syscall allowlist. It removes known-dangerous calls (`bpf`, `io_uring_*`, `mount`, ...)
  but the rest of the syscall surface stays reachable. `clone`, `clone3`, `unshare`, `setns`, `ptrace` are deliberately
  allowed. A real allowlist per profile class would be a separate project.
- **The sudo ticket is live for the whole ivpn session.** holdfast revokes the ticket it created when it exits (`sudo -k`), but
  while the sandbox runs it keeps refreshing it, because teardown needs root. Other processes of yours in the same terminal
  session can use it during that time. Closing that window would need a small privileged helper that holds the rules and
  cleans up by itself, which is a bigger design than this.
- **ivpn on hosts with their own nftables forward policy.** holdfast's host rules are `iptables` (the nft shim on most
  distros). Another table with `policy drop` on the forward hook can win over them; if the packets die on the host, the
  failure prints the exact `nft` rules to add (`docs/NETWORK.md`, "No handshake"), but holdfast does not add them itself. A
  native nftables backend (roadmap) would remove the guesswork. On one real host (Arch, whose stock config has such a chain)
  the packet counters showed the forwarding working anyway, so this is a diagnosis aid, not a known failure.
- **ivpn has only been seen working on one host.** A failed run there turned out to be a stale WireGuard config (the server
  answered, WireGuard discarded the answers); with a fresh config the tunnel came up and the browser started. holdfast now says
  "config probably wrong or stale" and keeps the packet counters and kernel view behind `-v`. The sudo/pty fix and the DISPLAY fix
  that followed have not been re-run end to end.
- **Wayland is host-socket only.** `server = host` connects the sandbox to your real compositor when `WAYLAND_DISPLAY` is set (with consent). Still open: a nested
  private compositor (cage/weston/sway, a new `server =` value, the Xephyr equivalent) and the `wp_security_context_v1` protocol so a compositor can mark the sandbox as
  restricted. The Wayland backend has not been run against a real compositor yet; the X11 one was only moved, not changed.
  GPU access is independent of the protocol: `[gpu] mode = render` binds the DRM render node for both X11 and Wayland.
- **`net=host`** shares the host network namespace, including abstract unix sockets (X11, some D-Bus), whatever
  `display = none` says. Prefer `net=pasta`. pasta (and host) still reach the LAN.
- **Whitelisted binaries are a PATH allowlist, not an exec allowlist.** With `libs = full`, anything executable under
  `/usr/lib` can still be run by absolute path. `libs = minimal` narrows this; it does not prevent running a bound
  library directory's executables.
- **Policy deny-list is a deny-list.** It protects known credential paths and sockets; unknown ones are only protected
  by not being mounted. Extend with `[fs] deny`.
- **Clipboard.** Sanitised text still lands in your clipboard; a harmless-looking multi-line command is still a paste hazard.
- **`.git` guard** only covers repositories present at launch.

## Libraries and bundles

- **No per-OS file lists are shipped.** `data/os` has the Alpine bundle definition but no host file lists: the first
  minimal-libs run on a distro tells you to create one (`holdfast libs --refresh --out=./data`). A list must be
  created on each supported distro/architecture and committed; CI should run `holdfast libs --check` per supported OS.
  Until then the shipped example profiles use `libs = full`.
- **The file list can still go stale, just in one place instead of in every profile.** After an upgrade
  `holdfast libs --check` shows a `+`/`-` diff and a run fails closed on a listed file that no longer exists. Open
  follow-up: a way to mark hand-added entries as intentional (today `libs --refresh` rescans and drops them; add the file
  to a lib's `paths`/`sonames` instead).
- Dependency analysis is `DT_NEEDED` only; anything loaded with `dlopen` must be declared in the lib's `paths`/`sonames`
  (see `data/lib/*.profile`). Toolchains (`gcc`, `rustc`, `cargo`, ...) need `libs = full`.
- The lib/os/profile files use the INI-style syntax; TOML is a later rename, not a redesign.
- Bundles are Alpine only. The shared `os` mechanism is not Alpine-specific, but no other distro is fetched or verified.
- The Alpine tarball hash comes from the same mirror unless you pin `alpine_sha256` in the `data/os` file; GPG verification is not implemented.
- Dep recipes install into `$HOME`: the userland is read-only for them, so a write elsewhere fails (packages go in the
  `data/os` file). A recipe that needs a tool whose cache or output is not under `$HOME` or `/tmp` will fail until it is
  pointed there; this has not been tried with `go`, `cargo` or `git` under a real bwrap yet.
- A dep's stamp covers its recipe (and, with `provides`, that its files still exist), not the userland it was built against: after `--refresh` rebuilds the userland (a new Go,
  say), already-installed deps are kept until their own recipe changes or you delete their stamp. `needs` only checks that
  a command exists, not its version.
- The `apk add` sandbox (writable userland, userns-root, network) runs without the default seccomp filter. Dep recipes do
  get the profile's filter, since they are ordinary runs. Adding it to `apk` needs a real run to see what it needs.
- The fetch/extract sandbox still uses host binaries (`curl tar gzip sha256sum`) with the host's `/usr/lib` mounted read-only.
  It sees none of your files, but it is not a minimal-libs sandbox.
- No bundle or purge command: to remove a userland or a profile's saved `$HOME`, delete its folder (`holdfast doctor`
  prints the data dir). Bundles are shared by `os`, so deleting `bundles/<os>/` affects every profile naming it.
- A changed `data/os` definition makes runs fail until `--refresh`; there is no incremental update (it re-extracts and
  reinstalls everything).
- **One uid in the install sandbox.** bwrap maps a single uid/gid (yours, as 0), so a package that ships files owned by
  another uid or gid (setuid helpers such as `linux-pam`'s `unix_chkpwd`) cannot be installed: `failed to preserve owner`.
  Possible fixes, none done: apk's `--usermode` where the Alpine release has it, or subordinate uid/gid ranges
  (`/etc/subuid`, `newuidmap`) the way rootless podman does. The second would also be needed by dpkg and pacman.
- **Alpine only, so musl only.** Prebuilt Linux release binaries are almost always glibc, and a musl build cannot load the
  host's glibc *userspace* driver (NVIDIA proprietary). Mesa-based GPUs (AMD, Intel, nouveau) talk to the kernel through the
  DRM render node and use the bundle's own Mesa, so `[gpu] mode = render` works in a bundle. The plan is a
  `distro =` key in `kind = bundle` files that selects a backend (`fetch_base`, `install_packages`, `verify`; the apk step is
  already isolated in `install_os_packages()`), with `alpine_*` kept as aliases:

  | | Alpine (today) | Debian | Arch |
  |---|---|---|---|
  | base rootfs | minirootfs tarball + sha256 | official `rootfs.tar.xz` + sha256 | `archlinux-bootstrap-YYYY.MM.01` + sha256/signature |
  | packages | `apk add` | `apt-get install` | `pacman -S` |
  | pinning | exact release; packages float inside it | `snapshot.debian.org` date | Arch Linux Archive date |
  | userns-root gotchas | setuid owners | dpkg `chown`/statoverride, `APT::Sandbox::User "root"`, no systemd triggers | `DisableSandbox`, keyring init or `SigLevel`, mirrors |

  Every backend shares the one-uid problem above. NVIDIA's proprietary driver still needs a glibc userland; Mesa-based
  render-node access is available in the current Alpine bundle.
- **Deps cannot write to the working tree.** A recipe sees only `$HOME`, so files a project build wants under its own tree
  must be copied there by the build step. An opt-in, per-recipe read-write bind of one subdirectory was considered and left
  out for now: it lets an install step (often fetching code from the internet) write into your repository, so it needs the
  same `cwd` consent and `.git` protection as a normal run and a test that the subdirectory cannot escape the tree.
- No `print --install`: `holdfast os-shell -n PROFILE` prints the argv of the install sandbox, but not the apk script
  (it is `apk_script()` in `src/core/bundle.cpp`).
- Bundles installed by the earlier `bundle setup` layout (`profiles/<name>/rootfs`) are not migrated: the next run sets
  up a new one. A bundle profile needs `os = NAME` (the inline `[bundle]` version/packages keys are rejected), and
  `alpine_version` must be an exact release.

## Roadmap items still open

nftables backend, Wayland socket passthrough with security-context, per-profile cgroup limits, TOML profiles,
overlayfs bundles (bwrap >= 0.11), a CI pipeline that runs `predep check` / `predep e2e` (those stages are commented out in `predep.toml` for now).
