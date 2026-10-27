# Data files: `data/profile`, `data/lib`, `data/os`

Profiles say **what** a sandbox needs. Two other kinds of file say **where** it lives and **what an OS setup is**,
so that nothing host-specific is copied into profiles and nothing is declared twice.

```
data/
  profile/NAME.profile   intent: mounts, network, display, [bin] allow, [libs] use, [profile] os
  lib/NAME.profile       what one tool/library family needs (hand-written, distro-neutral)
  os/NAME.profile        one OS setup: a bundle's pinned Alpine + packages, or a host distro's resolved library files
```

Every file is a `.profile` in the same INI-style syntax (TOML is a roadmap item; the files will be converted, not
redesigned). The **directory** says what a file describes: a sandbox (`profile/`), a tool (`lib/`) or an OS setup (`os/`).
Names are `[a-z0-9][a-z0-9._-]{0,63}` and become file names.

## The per-OS file list (plain words)

A minimal sandbox must bind exactly the library files a program needs, and those file names differ per distro
(Debian 12: `/usr/lib/x86_64-linux-gnu/libpython3.11.so.1.0`, Arch: `/usr/lib/libpython3.14.so.1.0`). holdfast does not
work them out while you run a sandbox (no ELF parsing at run time). Instead `holdfast libs` scans your machine **once,
ahead of time** and saves "python3 needs these exact files on this distro" in the `os/` file for that distro, as a
`[files.ARCH.LIB]` section. That saved list is all a sandbox reads at run time. You never edit it by hand:

- `holdfast libs --refresh` scans this machine and creates or updates the list,
- `holdfast libs --check` compares the saved list with this machine and tells you when an OS upgrade made it out of date.

The same word, **refresh**, is used for bundles: `holdfast bundle setup PROFILE --refresh` redoes the userland from the
current `data/os` file (re-download, re-extract, reinstall packages) after you changed it.

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
alpine_version = 3.24.3            # exact release: fetched by name, nothing moves under you
alpine_sha256  = f8e1caf...        # pin the tarball
packages = ca-certificates build-base git bash curl go rust cargo
```

Every profile with `[profile] os = NAME` shares `<data>/bundles/NAME/rootfs`; the fake `$HOME` stays per profile and
`provision` lines stay in the profile. `setup` and `run` verify the installed bundle was built from this file's current
version/mirror/sha256/packages and refuse otherwise. After editing the file: `holdfast bundle setup PROFILE --refresh`
(rebuilds the userland for every profile sharing it).

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

## How a minimal profile resolves (run time, no ELF parsing)

1. `[libs] use = ...` plus implicit `base`, expanded through `needs`.
2. Every `[bin] allow` command must appear in some used lib's `commands`, else the profile is rejected.
3. The OS file is `[profile] os` if set, else the host's `/etc/os-release` ID/VERSION_ID is matched against `data/os`.
4. For each lib the saved file list for this architecture is read; a missing one is an error naming `holdfast libs --refresh`.
5. The files are bound read-only through `Policy::check_bind`. A listed file that no longer exists is an error
   (the list is out of date after an upgrade) telling you to run `holdfast libs --check`.

Why this cannot go stale per profile: profiles contain no paths at all. The only host-specific data is the saved file
list, one file per OS, refreshed with one command and verified in CI.
