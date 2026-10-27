# Data files: `data/profile`, `data/lib`, `data/os`, `data/dep`, `data/display`

Profiles say **what** a sandbox needs. Three other kinds of file say **where** it lives, **what an OS setup is** and **how
an extra tool gets installed**, so that nothing host-specific is copied into profiles and nothing is declared twice.

```
data/
  profile/NAME.profile   intent: mounts, network, display, [bin] allow, [libs] use, [deps] use, [profile] os
  lib/NAME.profile       what one tool/library family needs (hand-written, distro-neutral)
  os/NAME.profile        one OS setup: a bundle's pinned Alpine + packages, or a host distro's resolved library files
  dep/NAME.profile       one install step for a bundle profile (build or fetch a tool into its $HOME)
  display/NAME.profile   one kind of display: a private Xephyr (+ window manager) or your real session
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

First match wins: `--data=DIR` (repeatable, command line), `$HOLDFAST_DATA`, `<profile dir>/data` (only for a profile given by path, so a project can keep `os/` and `dep/` files next to its profile and run it from anywhere; refused if group/world-writable or a symlink leaving the profile's directory),
`$HOLDFAST_SHARE/data`, `~/.config/holdfast/data`, `/etc/holdfast/data`, then ONE
shipped root: `data/` next to the binary (a checkout, or `/opt/holdfast` after `predep install`), else `/opt/holdfast/data`.
A user file therefore overrides a shipped one of the same name. Profiles follow the same layout (`<root>/profile/`).
The old `$HOLDFAST_PROFILES`, `~/.config/holdfast/profiles` and `/etc/holdfast/profiles` are not searched; a profile left
there is an error that says where to move it.
`holdfast list`, `holdfast list libs`, `holdfast list os` show what is visible; add `--data=DIR` to include a project's data.

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
# Downloaded tarballs are kept in <data>/cache/alpine/<arch>/ (<data> = $HOLDFAST_HOME or ~/.local/share/holdfast)
# and reused while they match alpine_sha256.

[install]                          # how the install steps (fetch, apk, pasta deps) reach the network
net = pasta                        # pasta (default) | none
dns = 1.1.1.1                      # IPv4 resolver for pasta; required once an install step uses the network
use = shell archive coreutils net certs   # data/lib names: the ONLY host files the download sandbox mounts
```

`[install]` only changes how the userland is fetched, not what it contains, so it is not part of the bundle's stamp.
- `net = none` builds offline: it needs a pinned `alpine_sha256` and the tarball already in the cache, and no `packages`
  (apk needs the network). `host` is refused: these sandboxes are writable and userns-root.
- `dns` is the resolver for the fetch, `apk add` and every dep with `[network] mode = pasta`. There is no fallback, neither to
  a profile's `[network] dns` nor to the host's `/etc/resolv.conf`: a step that needs the network without it is refused
  before anything is created.
- `use` (required to build the userland): the download runs the host's `sh tar gzip sha256sum cut chmod rm mkdir mv` (and
  `curl` with `net = pasta`). Only the files the listed libs (plus `base`) have in this host's `kind = host` os file are
  mounted, read-only, exactly like a `libs = minimal` profile: no library directories, no `/etc/ld.so.cache`. Create that
  file once with `holdfast libs --refresh`. A tool no listed lib provides is an error that names it.
- Both install sandboxes run under the default seccomp filter unless the profile says `seccomp = none`.

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
holdfast libs --refresh --out=./data                  # on a debian 12 box: creates/updates ./data/os/debian-12.profile
holdfast libs --data=./data --check                   # CI / after upgrades: exit 1 and a `+`/`-` diff if this host drifted
holdfast libs                                          # print instead of saving (do not redirect onto the file it reads)
```

`--refresh` writes to `~/.config/holdfast/data/os/NAME.profile`, or to `DIR/os/` with `--out=DIR`; never back into the
shipped data (`/opt/holdfast/data`, a checkout) and never into `$HOLDFAST_DATA` or a project's data dir unless you pass
`--out`. The list describes one machine, so it only lands somewhere shared or committed when you say so. The user copy is
searched first, so it shadows a shipped file.
A lib that cannot be analysed on this host (e.g. a python with more than 50000 files) is reported and gets no file list;
the others are still written, and the command exits 1.

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
provides = ~/go/bin/lazygit         # optional: what the recipe leaves in $HOME; if one is gone, the dep runs again
[network]
mode = pasta                        # none (the default) | pasta
[install]
run = go install github.com/jesseduffield/lazygit@sh-integration      # one shell line per `run`, in order
```

`[install]` takes three kinds of steps, run in the order written:

| key | what it does |
|---|---|
| `run = LINE` | one shell line |
| `run_file = PATH` | a script kept next to the recipe (relative to its directory, may not lead outside it, also not via a symlink); its text is run as part of the recipe by `/bin/sh` and is part of the recipe's hash, so editing it counts as editing the recipe |
| `fetch = https://URL SHA256 ~/DEST` | download to `$HOME/DEST` and check the sha256; a mismatch deletes the file and fails the recipe, a file already there with the right hash is kept. Needs `[network] mode = pasta` and `curl` in the userland. The URL, hash and path reach the shell as parameters, not as text |

**Variables:** holdfast does not expand anything in a recipe. `$HOME`, `$PWD`, `$(…)` are the shell's, exactly as you
would expect from a shell line (profile keys such as `[fs]` and `command` use holdfast's own variables; recipes do not).
Recipes get no positional parameters of their own (`$1`… are taken by `fetch`).

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
  add later installs on the next run; an edited recipe is refused until `holdfast run --refresh-dep=NAME PROFILE`, which runs
  that recipe again (`--refresh` runs all of them). A stamp only says the recipe ran: list what it installs under `provides`
  and a dep whose files were deleted from `$HOME` runs again by itself (`check`/`print` warn about it). After it runs, every
  `provides` path must exist, or the run fails.
- Recipes are trusted shell like any profile's `wm` line: read one before you use it. Deps are only for bundle mode.

`holdfast list deps` shows what is available.

**The one special step is not a dep:** installing the `data/os` file's `packages` with `apk add`. A package manager must own
the whole userland, so that sandbox is deliberately different: the rootfs is writable, `--uid 0` makes it userns-root (your
uid mapped to 0, no real privilege), and the network is pasta's (or none, see `[install]`). holdfast says so when it runs; it lives in
`install_os_packages()` in `src/core/bundle.cpp`.

When it fails: apk runs with `--no-progress`, so every package line is printed; its whole output is also kept in
`<data>/bundles/<os>/rootfs/var/log/holdfast-apk.log`, and the last 60 lines are repeated after a failure.
`holdfast os-shell PROFILE` opens a shell in exactly that sandbox (writable userland, userns-root, the `[install]`
network) to try `apk add` by hand; `-n` prints its bwrap argv instead. What you change there is not tracked and affects every
profile with the same `os` until `holdfast run --refresh` rebuilds the userland.

The sandbox maps exactly one uid (yours, as 0). A package that ships files owned by another uid or gid (setuid helpers such
as `linux-pam`'s `unix_chkpwd`) fails with `failed to preserve owner`; leave such packages out of `packages`. See
`docs/DEFERRED.md`.

## `data/display/NAME.profile`

A sandbox profile says `[display] use = NAME`; this file says what that display is.

```ini
[display]
description = private X11 server (Xephyr) with the i3 window manager
server = xephyr          # xephyr | host   (required)
size   = 1920x1280       # xephyr only, default 1280x800
xauth  = yes             # xephyr only, default yes: private cookie file
wm     = i3              # xephyr only: shell snippet started in the sandbox; needs `sh` in [bin] allow on host-root profiles
```

- `server = xephyr` is a private X11 server. X needs a separate window manager, hence `wm`.
- `server = host` is your real session: Wayland when `WAYLAND_DISPLAY` is set, otherwise X11. It takes no other keys (Wayland
  needs no window manager, cookie or size). The sandbox profile must also say `[display] allow_host = yes`; consent is never in the shared file.
- Keys that do not apply are errors. Shipped: `x11-xephyr`, `x11-xephyr-i3`, `host`. `holdfast list displays` shows what is visible.

## How a minimal profile resolves (run time, no ELF parsing)

1. `[libs] use = ...` plus implicit `base`, expanded through `needs`.
2. Every `[bin] allow` command must appear in some used lib's `commands`, else the profile is rejected.
3. The OS file is `[profile] os` if set, else the host's `/etc/os-release` ID/VERSION_ID is matched against `data/os`.
4. For each lib the saved file list for this architecture is read; a missing one is an error naming `holdfast libs --refresh`.
5. The files are bound read-only through `Policy::check_bind`. A listed file that no longer exists is an error
   (the list is out of date after an upgrade) telling you to run `holdfast libs --check`.

Why this cannot go stale per profile: profiles contain no paths at all. The only host-specific data is the saved file
list, one file per OS, refreshed with one command and verified in CI.
