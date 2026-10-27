# holdfast

A small C++20 tool that launches programs inside a **bubblewrap** sandbox whose contents are *declared*, not
inherited: only the binaries, libraries and paths a profile lists exist inside. Offline by default, `.git` read-only,
a default seccomp filter, and a filtered terminal. It fails closed: an unknown key or a denied mount is an error, never a
warning.

```
holdfast run lazyvim              # offline editor, current dir mounted at /shared, .git read-only
holdfast run --net=pasta lazyvim  # same, online ("sync" mode) through a private pasta netns
holdfast run librewolf-ivpn       # amnesic browser, nested X, all traffic via a WireGuard netns
holdfast bundle setup lazygit-dev # one-time: fetch + verify Alpine, install packages
holdfast run lazygit-dev          # run inside the private Alpine userland
holdfast print lazyvim            # show the exact bwrap command line, change nothing
```

## Build

```sh
predep                # build -> bin/holdfast       (needs premake5 + predep, bwrap, libseccomp headers)
predep check          # build + unit tests          (zero warnings is the bar)
# or: premake5 gmake && make config=release -j$(nproc) && ./bin/holdfast_tests
holdfast doctor       # which optional features this host supports
```

Install steps, requirements, optional tools and the Ubuntu AppArmor note: `docs/BUILD.md`.

## How it works, in five lines

- A **profile** (`.profile`, INI) declares one sandbox; unknown keys are errors.
- **Host mode** binds only the listed binaries and library files; **bundle mode** uses a private, hash-pinned Alpine userland.
- Reusable pieces live in `data/`: `profile/`, `lib/` (what a tool needs) and `os/` (an OS setup).
- **Network** is `none` by default; `pasta` gives a private namespace with internet; `ivpn` forces a WireGuard tunnel.
- Every host path goes through a symlink-safe **policy** (`~/.ssh`, credentials, sockets, `$HOME`, `/` are refused).

## Documentation

| | |
|---|---|
| `docs/CONCEPTS.md` | profiles, userland modes, network, display, working tree, policy |
| `docs/PROFILE_REFERENCE.md` | every profile key |
| `docs/DATA.md` | `data/lib` and `data/os`, the per-OS library file lists, shared bundles |
| `docs/INTEGRATION.md` | using holdfast from another project or from an agent |
| `docs/SAFETY.md` · `docs/THREAT_MODEL.md` | what it protects, what it does not, exit codes |
| `docs/NETWORK.md` | the IVPN/WireGuard namespace and its kill switch |
| `docs/DEFERRED.md` | known limitations and untested areas |
| `docs/SPEC.md` · `docs/HISTORY.md` | technical design; where it came from |

## AGENTS

You are an AI agent (or a human in a hurry) who just landed on this repository. Two different jobs, two different entry points:

- **Changing holdfast itself** (code, profiles, data files, docs): read **`AGENTS.md`** first. It has the build and test
  commands, the invariants you must not break (no shell strings, fail closed, restrictive defaults, RAII cleanup) and a
  table of which files to touch for each kind of change.
- **Using holdfast from another project** (to sandbox a command, an editor, an AI agent, a build): read
  **`docs/INTEGRATION.md`**. In short:
  - Run the `holdfast` binary as a **subprocess** with an argv vector: `holdfast run -y --cwd=DIR ./your.profile -- cmd args...`.
    **Do not link it** as a library: `bin/holdfast_core.a` is an internal convenience with no stable API or ABI, no `.so`
    exists, and the process boundary is part of the security design.
  - stdout is the program's output and data (`print`, `list`, `init`); logs go to stderr; exit `3` means refused by policy.
  - Keep a small `.profile` in your repository (start from `holdfast init NAME` or `data/profile/`), and `holdfast check`
    it. Do not weaken defaults (network, seccomp, terminal filter, `.git` protection) unless the user asked.
