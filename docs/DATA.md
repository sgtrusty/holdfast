# Data files: `data/profile`, `data/lib`, `data/os`, `data/dep`

Profiles say **what** a sandbox needs. Three other kinds of file say **where** it lives, **what an OS setup is** and **how
an extra tool gets installed**, so that nothing host-specific is copied into profiles and nothing is declared twice.

```
data/
  profile/NAME.profile   intent: mounts, network, display, [bin] allow, [libs] use, [deps] use, [profile] os
  lib/NAME.profile       what one tool/library family needs (hand-written, distro-neutral)
  os/NAME.profile        one OS setup: a bundle's pinned Alpine + packages, or a host distro's resolved library files
  dep/NAME.profile       one install step for a bundle profile (build or fetch a tool into its $HOME)
```

Every file is a `.profile` in the same INI-style syntax (TOML is a roadmap item; the files will be converted, not
redesigned). The **directory** says what a file describes: a sandbox (`profile/`), a tool (`lib/`), an OS setup (`os/`) or
an install step (`dep/`).
Names are `[a-z0-9][a-z0-9._-]{0,63}` and become file names.

## The per-OS file list (plain words)

A minimal sandbox must bind exactly the library files a program needs, and those file names differ per distro
(Debian 12: `/usr/lib/x86_64-linux-gnu/libpython3.11.so.1.0`, Arch: `/usr/lib/libpython3.14.so.1.0`). holdfast does not
work them out while you run a sandbox (no ELF parsing at run time). Instead `holdfast libs` scans your machine **once,
ahead of time** and saves "python3 needs these exact files on this distro" in the `os/` file for that distro, as a
`[files.ARCH.LIB]` section. That saved list is all a sandbox reads at run time. You never edit it by hand:

- `holdfast libs --refresh` scans this machine and creates or updates the list,
- `holdfast libs --check` compares the saved list with this machine and tells you when an OS upgrade made it out of date.

The same word, **refresh**, is used for bundles: `holdfast run --refresh PROFILE` rebuilds the userland from the current
`data/os` file (re-extract, reinstall packages) after you changed it.

## Search order

First match wins: `$HOLDFAST_DATA`, `$HOLDFAST_SHARE/data`, `~/.config/holdfast/data`, `/etc/holdfast/data`,
`<share dir>/data` (installed by `predep install`). A user file therefore overrides a shipped one of the same name.
Profiles are also still found in `$HOLDFAST_PROFILES`, `~/.config/holdfast/profiles`, `/etc/holdfast/profiles`.
`holdfast list`, `holdfast list libs`, `holdfast list os` show what is visible.

## `data/lib/NAME.profile`

```ini
[lib]
description = python3 interpreter with its standard library and extension modules
commands = python3 python pip pip3          # binaries this lib provides (a profile's [bin] allow must be covered)
sonames  = libfoo.so.*                       # shared libraries to bind, globs, searched in the loader's lib dirs
paths    = /usr/lib/python3* /usr/local/lib/python3*   # data/plugin dirs loaded at run time (dlopen, imports); globs
needs    = otherlib                          # other libs, followed transitively
```

`base` (loader, libc, NSS/resolver, iconv, locales) is implicit in every minimal profile. You do not list it.
Toolchain commands (`gcc cc g++ c++ ld lld clang rustc cargo`) are refused: they need crt files and static
archives, which no minimal set provides. Profiles that need them say `libs = full`.

## `data/os/NAME.profile`

**Bundle** (the shared Alpine userland; replaces the old inline `[bundle]` keys):

```ini
[os]
kind = bundle
alpine_version = 3.24.3            # an exact release is required (fetched by name; latest-stable / v3.24 / edge are rejected)
alpine_sha256  = f8e1caf...        # pin the tarball (strongly recommended; without it only the mirror's own .sha256 is checked)
packages = ca-certificates build-base git bash curl go rust cargo
```

Every profile with `[profile] os = NAME` shares `<data>/bundles/NAME/rootfs`; the fake `$HOME` and the deps installed into
it stay per profile. The first `holdfast run` of any of them creates the userland (inside sandboxes), and
each later run verifies it was built from this file's current version/mirror/sha256/packages, refusing otherwise. After
editing the file, `holdfast run --refresh PROFILE` rebuilds it for every profile sharing it (changes made inside are discarded).

**Host** (the saved file list: which concrete files each lib needs on one distro and architecture):

```ini
[os]
kind = host
id = debian                         # /etc/os-release ID
version = 12                        # optional VERSION_ID prefix; the most specific match wins
[files.x86_64.python3]               # one section per architecture and lib
bind = /usr/lib/x86_64-linux-gnu/libpython3.11.so.1.0
...
```

File lists are **generated, never hand-written**:

```sh
HOLDFAST_DATA=./data holdfast libs --refresh          # on a debian 12 box: creates/updates data/os/debian-12.profile
HOLDFAST_DATA=./data holdfast libs --check            # CI / after upgrades: exit 1 and a `+`/`-` diff if this host drifted
holdfast libs                                          # print instead of saving (do not redirect onto the file it reads)
```

`holdfast libs` reads ELF headers of every lib's commands and sonames on THIS host (nothing is executed) and keeps the
`[files.*]` sections of other architectures already in the file.

## `data/dep/NAME.profile`

An install step for a **bundle** profile: a tool you want in its userland that the package list does not give you (a
branch built from source, a single script, a plugin). It replaces the old inline `provision` lines.

```ini
[dep]
description = lazygit (sh-integration branch), built with Go
os = alpine-3.24-dev                # the userland it is built for; the profile using it must name the same os
needs = go                          # commands that must already exist in the userland; add their package to the data/os file
[network]
mode = pasta                        # none (the default) | pasta
[install]
run = go install github.com/jesseduffield/lazygit@sh-integration      # one shell line per `run`, in order
```

A profile opts in with `[deps] use = lazygit delta ...`. A dep is **an ordinary run of that profile**, produced by the same
code that runs it day to day, so nothing about the sandbox is special-cased for installs:

| | where it comes from |
|---|---|
| userland | the profile's `os`, mounted **read-only** like every other run (installs go to `$HOME`, not into the userland) |
| identity, `$HOME` | the profile's: your uid (not root), the fake user's persistent home |
| seccomp, terminal filter, `[home]`, `[env]`, `hostname` | the profile's |
| network | **the recipe**: `[network] mode`, `none` if it says nothing (the profile's own network is not inherited) |
| command | **the recipe**: its `run` lines, after the `needs` check |
| working tree, display, audio, clipboard, `wm`, nested deps | switched off: an install step needs none of them |

The last two rows are the complete list of differences (`dep_profile()` in `src/core/bundle.cpp`, covered by a test).
`[dep] os` is required and must equal the profile's: a tool built on Alpine (musl) will not run on another userland.

What happens, per dep:

- Install into `$HOME` (`go install` already does; `cargo install --root "$HOME/go"`). The userland is read-only for a dep,
  so anything written elsewhere simply fails instead of silently landing in the shared rootfs.
- `needs` is checked first, inside the userland, so a missing `go` is one clear sentence instead of a half-run build.
- Each dep has its own stamp (`<data>/profiles/<name>/deps/<dep>.stamp`, a hash of the recipe, including its os and network, plus the home path). A dep you
  add later installs on the next run; an edited recipe is refused until `holdfast run --refresh PROFILE`, which runs the
  recipes again. Delete a stamp, or the folder, to force one.
- Recipes are trusted shell like any profile's `wm` line: read one before you use it. Deps are only for bundle mode.

`holdfast list deps` shows what is available.

**The one special step is not a dep:** installing the `data/os` file's `packages` with `apk add`. A package manager must own
the whole userland, so that sandbox is deliberately different: the rootfs is writable, `--uid 0` makes it userns-root (your
uid mapped to 0, no real privilege), and the network is pasta's. holdfast says so when it runs; it lives in
`install_os_packages()` in `src/core/bundle.cpp`.

## How a minimal profile resolves (run time, no ELF parsing)

1. `[libs] use = ...` plus implicit `base`, expanded through `needs`.
2. Every `[bin] allow` command must appear in some used lib's `commands`, else the profile is rejected.
3. The OS file is `[profile] os` if set, else the host's `/etc/os-release` ID/VERSION_ID is matched against `data/os`.
4. For each lib the saved file list for this architecture is read; a missing one is an error naming `holdfast libs --refresh`.
5. The files are bound read-only through `Policy::check_bind`. A listed file that no longer exists is an error
   (the list is out of date after an upgrade) telling you to run `holdfast libs --check`.

Why this cannot go stale per profile: profiles contain no paths at all. The only host-specific data is the saved file
list, one file per OS, refreshed with one command and verified in CI.
