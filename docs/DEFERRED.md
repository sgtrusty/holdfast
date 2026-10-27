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

- `[libs]` lists are host-specific (distro, arch, versions). They go stale after upgrades: run
  `holdfast libs --check PROFILE` (planned follow-up: let hand-added entries be marked intentional so they do not fail the check).
- Dependency analysis is `DT_NEEDED` only; libraries loaded with `dlopen` rely on the small built-in map in
  `src/core/libs.cpp` or on explicit `[fs]` entries. Toolchains (`gcc`, `rustc`, `cargo`, ...) need `libs = full`.
- Bundles are Alpine only. The shared-id mechanism is not Alpine-specific, but no other distro is fetched or verified.
- The Alpine tarball hash comes from the same mirror unless you pin `alpine_sha256` in the profile; GPG verification is not implemented.
- `provision` lines run with a shared rootfs writable; keep them to `$HOME` (packages go in `packages`).
- Bundles installed before `bundles/<id>` existed (old `profiles/<name>/rootfs`) must be set up again.

## Roadmap items still open

nftables backend, Wayland socket passthrough with security-context, per-profile cgroup limits, TOML profiles,
overlayfs bundles (bwrap >= 0.11), a CI pipeline that runs `predep check` / `predep e2e` (those stages are commented out in `predep.toml` for now).
