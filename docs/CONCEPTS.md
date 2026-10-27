# Concepts

**Profile**: an INI file describing one sandbox (`docs/PROFILE_REFERENCE.md`). It is found by name in
`$HOLDFAST_PROFILES`, `~/.config/holdfast/profiles/`, `/etc/holdfast/profiles/`, then the `profile/` directory of each
data dir (`docs/DATA.md`), or passed as a path. Unknown sections and keys are errors. Examples ship in `data/profile/`;
copy one with `holdfast init NAME > ~/.config/holdfast/profiles/NAME.profile`.

## Userland modes

- **`mode = host`**: a tmpfs root is assembled from
  - the library files of the profile's `[libs] use` set, taken from the saved per-OS file list in `data/os`
    (`libs = minimal`, the default; create/verify the lists with `holdfast libs`), or `/usr/lib*` read-only with `libs = full`,
  - each binary in `[bin] allow`, bound individually at `/usr/bin/<name>`,
  - the files you list in `[fs]`.

  Anything not listed does not exist.
- **`mode = bundle`**: the userland is a private Alpine minirootfs, `~/.local/share/holdfast/bundles/<os>/rootfs`,
  shared by every profile that names the same `os`. It is downloaded over HTTPS, sha256-verified (pin it in the `data/os`
  file), extracted unprivileged, then provisioned (`apk add`, your `provision` lines) in a network-enabled writable stage.
  Day-to-day runs mount it read-only.

## Network

| mode | what the sandbox gets |
|---|---|
| `none` (default) | a fresh empty network namespace |
| `pasta` | a private namespace with outbound internet via `pasta`; host loopback services, inbound ports and host abstract sockets are unreachable |
| `host` | the host's network namespace, **including abstract unix sockets such as the X11 server's**: avoid |
| `ivpn` | WireGuard inside `hf-<profile>` with a kill switch, see `docs/NETWORK.md` |

## Display

`none`; `xephyr` (a private nested X server with a random cookie; only its socket enters the sandbox); or `host`
(requires `allow_host_x11 = yes`, because it hands over your keyboard and screen).

## Working tree

`cwd = ask|yes|none`: the current directory is bound read-write at `/shared`; every `.git` (directory *or*
worktree/submodule file) inside is re-bound read-only. A symlinked `.git` is refused.

## Policy

Before any host path is bound it is canonicalised (symlinks resolved) and checked against a deny-list (`~/.ssh`,
`~/.gnupg`, cloud/browser credentials, `/etc/shadow`, docker/libvirt sockets, session bus, ...) and a sensitive-root list
(`/`, `$HOME`, `/home`, removable-media roots, `/usr`, `/etc`, ...). A mount is refused if it *is*, is *inside*, or would
*contain* a denied path. Extend with `[fs] deny = ...`.

## Terminal and syscalls

The sandbox runs on its own pty with its output filtered (`terminal = filter`), and a default seccomp denylist is applied
(`seccomp = default`). Details: `docs/PROFILE_REFERENCE.md` ("Terminal filter", "Default seccomp filter").
