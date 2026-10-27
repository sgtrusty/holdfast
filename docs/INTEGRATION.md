# Using holdfast from another project

**Run the `holdfast` binary as a subprocess. Do not link it.**

The build also produces `bin/holdfast_core.a`, but that exists only so the CLI and the unit tests share code. It exports
C++ types with no stable API or ABI, and no `.so` is built or planned. The things that make the sandbox safe (the
argv-only launcher, signal forwarding, the pty and terminal filter, sudo handling, cleanup) live in the CLI process, and
the process boundary is part of the security design. If your project needs a library API, open an issue first rather than
wrapping the internals.

## The contract

```sh
holdfast run [options] PROFILE [-- COMMAND [ARGS...]]
```

- **argv, never a shell string.** Everything after `--` is the command as separate arguments, exactly as given. holdfast
  never builds a shell command line from your data.
- **stdout is the program's output** (and data for `print`, `list`, `init`, `libs`). holdfast's own logs go to **stderr**.
- **Exit code** is the sandboxed command's (`128+n` if it died of signal `n`); holdfast's own: `1` error, `2` usage,
  `3` refused by policy, `70` internal.
- **Fail closed.** An unknown key, a missing bundle, a denied mount or a missing library list is an error with a message
  that says what to run or change. Fix the profile; do not look for a way around the check.
- Useful options: `-y` (do not ask before mounting the working tree), `--cwd=DIR` (mount DIR, implies yes),
  `--no-cwd`, `--net=none|pasta|host|ivpn`, `--dns=IPV4|host` (required with `--net=pasta`/`host` unless the profile sets `dns`), `-n` (same as `print`), `-v`.
- Dry runs: `holdfast print PROFILE` shows the exact `bwrap` argv and changes nothing; `holdfast check PROFILE` validates.
- Debugging a profile: `holdfast run --debug PROFILE` opens `bash` (else `sh`) in that exact sandbox instead of its command:
  same mounts, network, seccomp and terminal filter, nothing added. A host profile needs `bash` or `sh` in `[bin] allow`.
  `holdfast print --debug PROFILE` shows the argv it would use. Not for scripts: it is an interactive shell.
- State and data locations can be overridden for tests and CI: `HOLDFAST_HOME` (state), `HOLDFAST_DATA` (profiles go in its `profile/`).
- A project can keep its profile and the data it references together: `[profile] data = ./data` in the profile (relative
  to the profile file) makes holdfast search that directory's `os/ dep/ lib/ display/` first, so
  `holdfast run ./tools/dev.profile` works from any directory without setting `HOLDFAST_DATA`. `[profile] include = FILE`
  shares one base between several profiles, and `[commands]` gives named entry points: `holdfast run ./tools/dev.profile build`.

## Calling it

```ts
// Bun / Node
import { spawn } from "node:child_process";
const p = spawn("holdfast", ["run", "-y", "--cwd=" + projectDir, "./agent.profile", "--", "npm", "test"],
                { stdio: ["ignore", "pipe", "pipe"] });
```

```python
# Python
import subprocess
r = subprocess.run(["holdfast", "run", "-y", f"--cwd={project}", "./agent.profile", "--", "pytest", "-q"],
                   capture_output=True, text=True)
# r.returncode: 3 = refused by policy (e.g. you asked to mount $HOME), 1 = error (stderr says what to fix),
# anything else is the sandboxed command's own exit code
```

When stdin and stdout are not terminals (pipes, CI) no pty is used and the output reaches you unfiltered.
When they are terminals, the program runs on its own pty and escape sequences are filtered (`terminal = filter`).

## Writing the profile for your project

A profile is a short INI file kept in your repository and passed by path (anything containing `/` or ending in `.profile`).
Start from an example in `data/profile/` (`holdfast list -v` shows where they live). A small offline host-mode profile:

```ini
[profile]
name    = myproject
command = sh
cwd     = yes                # mounts the working tree read-write at /shared; every .git inside is re-bound read-only

[bin]
allow = sh ls cat make       # only these binaries exist in the sandbox

[fs]
libs = full                  # zero setup. `libs = minimal` (the default) additionally needs [libs] use = ... and a
                             # saved per-OS file list, see docs/DATA.md
[home]
user = agent
```

Network is off unless you ask: `--net=pasta --dns=1.1.1.1` (private namespace, outbound only, an explicit resolver) is the way to give a sandbox internet.
Reference: `docs/PROFILE_REFERENCE.md`. Concepts: `docs/CONCEPTS.md`.

## Rules for agents and automation

- Run holdfast as the normal user, never as plain root (it refuses that). The one exception is `net = ivpn`, which needs
  root for the network namespace and uses `sudo` itself (`docs/NETWORK.md`); do not add `sudo` for anything else.
- Do not weaken a profile to make something work: leave `seccomp`, `terminal`, `[git] protect`, `cwd` and the network at
  their defaults unless the user explicitly asked, and say so when you change one.
- Profiles and `data/dep` recipes are trusted code (`wm` and recipe `run` lines are shell). Read a profile before running it; never generate
  one from untrusted input.
- A denied path (exit `3`) is the policy working. Mount a more specific subdirectory instead of `$HOME` or a credentials
  directory.
- Working *on* holdfast itself (not using it) is covered by `AGENTS.md` at the repository root.

## Replacing a hand-written bwrap wrapper

Map your wrapper's pieces to profile sections instead of building `bwrap` arguments yourself: allowed binaries to
`[bin] allow`, read-only paths to `[fs] ro`/`ro_try`, the project directory to `cwd = yes` (or `--cwd`), persistent
config and cache to `[home] dirs`, network to `--net`, environment to `[env]`. Anything not declared does not exist in
the sandbox.
