# AGENTS.md – guidance for AI coding agents (and humans) working on holdfast

holdfast is a **security tool**. When in doubt, be stricter, not more convenient.

> This file is for changing holdfast. If you only want to *use* it from another project (run a command, an editor or an
> agent inside a sandbox), read `docs/INTEGRATION.md` instead: run the CLI as a subprocess, do not link it.

## Build / test (run all of these before declaring work done)
```
predep check                    # premake5 build + unit tests (warnings are errors)
predep e2e                      # real-bwrap smoke test (as a NON-root user, needs unprivileged userns)
```
Or, calling premake5 directly (predep is just a thin driver over `premake5 gmake && make`):
```
premake5 gmake && make config=release -j$(nproc) && ./bin/holdfast_tests
```
Zero warnings is the bar (`-Wall -Wextra -Wpedantic -Wshadow -Wconversion`). C++20, no new dependencies
without an explicit request. `bwrap` 0.9.0 is the reference version for behavior. `-Werror` is ON by
default; set `HOLDFAST_WERROR=OFF` to build without it.

The build is described in `premake5.lua`; `predep.toml` declares the `build`/`test`/`e2e`/`check`/`install`
/`clean` stages. The output binary lands at `bin/holdfast` (unit-test binary at `bin/holdfast_tests`).

## Invariants — do not break these
1. **No shell strings.** Run programs with `hf::run/capture/spawn` (argv vectors). The only `/bin/sh` use is the constant trampoline in `core/launch.cpp`; never interpolate data into it. (`wm` lines and `data/dep` recipe `run` lines are *profile-author* shell by design.)
2. **Every host path that enters the sandbox from user/profile input goes through `Policy::check_bind`** and is bound by its *canonical* path. Adding a new mount source ⇒ add the policy call and a test in `tests/test_main.cpp`.
3. **Fail closed.** Unknown profile key/section/variable, missing bundle, bad WireGuard directive ⇒ throw (`ProfileError`/`Error`/`PolicyError`). Never downgrade an error to a warning to "make it work".
4. **Defaults are restrictive**: network `none`, display `none`, audio `none`, clipboard `none`, `.git` protected, `--cap-drop ALL`, `--clearenv`. A new capability must be opt-in per profile and carry a warning if it widens exposure.
5. **Kill switch before tunnel.** In `NetNs::up()` the default-DROP policy must be installed before `wg-quick up`. Host rules stay scoped to `endpoint:port/udp`.
6. **Cleanup is RAII and idempotent.** Anything created in `run_profile` (netns, X server, session dir, rules, sysctl) must be undone by a destructor, and by `net-cleanup` if it can outlive the process. Validate names (`valid_ns_name`) before any `rm -rf`.
7. **Bind order**: parents before children; the `.git` read-only binds must come after the rw bind of the tree.
8. **stdout is data** (`print`, `list`, `libs`, `doctor`); logs go to stderr via `hf::log`.
9. Files written for the sandbox use `write_file`/`make_private_dir` (0600/0700 and root→user chown when run via sudo).
10. bwrap takes the **command on the real argv**, not from `--args` (verified); keep `ArgBuilder::cmd()` separate.

## Where things go
| Task | Touch |
|---|---|
| New profile key | `profile.hpp` field → `profile.cpp` parse (strict) → use in `plan.cpp`/`session.cpp` → `docs/PROFILE_REFERENCE.md` → parser test |
| New deny path / sensitive root | `Policy` ctor / `is_sensitive_root` in `core/paths.cpp` → policy test |
| New bwrap flag | `ArgBuilder` (+ `pretty()` arity list) → `plan.cpp` → invariant test in `test_main.cpp` |
| Firewall/netns change | `net/netns.cpp`; extend `NetNs::selftest`; re-run the stub lifecycle (below) |
| New command or CLI option | help text and `parse_args` in `src/cli/args.cpp` (keep the help columns aligned) → dispatch in `src/main.cpp` → case in the `cli: option parsing` test |
| New helper binary | add to `doctor()`; check with `which()` and give an actionable error |
| New tool a minimal-libs profile can use | `data/lib/NAME.profile` (commands, sonames, paths, needs) → `holdfast libs --refresh` on each supported OS → commit the changed `data/os/*.profile`. No C++ change. |
| New install step for a bundle profile (a tool built/fetched into its `$HOME`) | `data/dep/NAME.profile` (`needs` + `run` lines; install into `$HOME`) → list it under the profile's `[deps] use`. No C++ change. |
| New OS setup (bundle packages / pinned release, or a host distro file list) | `data/os/NAME.profile`; never inline version/packages in a profile. See `docs/DATA.md`. |
| New key in a data file | `datadefs.cpp` (strict parse + `render_os` if it is written back) → `docs/DATA.md` → parser test |

## Testing netns changes without a VPN
In a container/VM where you are root: put stub `wg-quick`/`wg` scripts first in `PATH` (the stub
creates a veth pair named after the config file, `wg show … latest-handshakes` prints `KEY<TAB>1700000000`),
then run `SUDO_USER=<unprivileged-user> holdfast run <ivpn profile> -- <cmd>` and afterwards assert:
`ip netns list` empty, no `hfh*/hfn*/hfwg*` links, `iptables -S | grep holdfast` and the nat table empty,
`ip_forward` restored, `/etc/netns/hf-*` gone. A second concurrent run must be refused by the lock.

## Style
Small functions, early validation, `Error` with an actionable message (say what to run/change).
Comments explain *why* (threat/edge case), not what. No global mutable state except the logger, signal
forwarding and sudo keepalive in `util/sys.cpp`/`core/launch.cpp`.

## Known gaps you may be asked to fill (see README roadmap)
seccomp filter (libseccomp, behind a build option) · DT_NEEDED-based minimal libs · nftables backend ·
Alpine GPG verification · Wayland. Do not claim these as done without tests.
