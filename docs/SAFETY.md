# Safety notes (read these)

holdfast narrows what a program can reach; it is not a VM. Scope and assumptions are in `docs/THREAT_MODEL.md`, known
gaps in `docs/DEFERRED.md`. The things most worth knowing before you rely on it:

- `audio = pulse` exposes the **microphone** to every process in the sandbox.
- `terminal = filter` (default): the sandbox runs on its own pty and its output is filtered, so it cannot write your clipboard (OSC 52), forge titles/hyperlinks, or make your terminal type replies into your shell. TTY programs get a real controlling terminal and Ctrl-C works. `terminal = passthrough` falls back to `new_session` (blocks TIOCSTI, but Ctrl-C then reaches holdfast, not the program).
- `[clipboard] mode = out` lets the sandbox *set* your host clipboard (not read it). Control characters are stripped by default (`sanitize = yes`).
- The `.git` guard protects history and hooks of repos that exist at launch. It does not stop the sandbox from writing a hostile `Makefile`/`.envrc`/IDE task that *you* later run outside.
- Installing a bundle's packages (`apk add`, writable userland, userns-root) and its `data/dep` recipes (ordinary runs of the profile, with the network each recipe declares, usually `pasta`) trusts the packages in the `data/os` file and every command in the recipes you `use`.
- The Alpine hash comes from the same mirror as the tarball (integrity, not authenticity). Pin `alpine_sha256` in the `data/os` file for real supply-chain assurance.
- bwrap is not a VM: kernel bugs reachable through the syscall surface apply. A default seccomp denylist (`bpf`, `io_uring`, `mount`, `keyctl`, `userfaultfd`, `TIOCSTI`, ...) is on unless the profile says `seccomp = none` or supplies its own `.bpf`. It is a denylist, not a full syscall allowlist.
- `net = ivpn` uses `sudo` for the network setup only (see `docs/NETWORK.md`): the sandboxed program never has root, and holdfast revokes the sudo ticket it created when it exits. The ticket is live while the sandbox runs, because teardown needs it.
- `net = host` shares the host network namespace, including abstract unix sockets (e.g. X11). Prefer `net = pasta`.
- Profiles and `data/dep` recipes are trusted code: `wm` lines and recipe `run` lines are shell run for you. Never use one you did not read.

## Exit codes

`0` ok · `1` error · `2` usage · `3` refused by policy · `70` internal · otherwise the sandboxed command's exit code (`128+n` if killed by signal `n`).
