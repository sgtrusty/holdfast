# Concepts

**Profile**: an INI file describing one sandbox (`docs/PROFILE_REFERENCE.md`). It is found by name in
`$HOLDFAST_PROFILES`, `~/.config/holdfast/profiles/`, `/etc/holdfast/profiles/`, then the `profile/` directory of each
data dir (`docs/DATA.md`), or passed as a path. Unknown sections and keys are errors. The data that ships with holdfast
(`data/profile`, `data/lib`, `data/os`) is found next to the binary: in a checkout, or under `/opt/holdfast` after
`predep install`, so the example profiles run by name with nothing to copy. `holdfast list -v` shows what is visible and
where it came from; to customise one, copy its file into `~/.config/holdfast/profiles/` and edit it.

## Userland modes

- **`mode = host`**: a tmpfs root is assembled from
  - the library files of the profile's `[libs] use` set, taken from the saved per-OS file list in `data/os`
    (`libs = minimal`, the default; create/verify the lists with `holdfast libs`), or `/usr/lib*` read-only with `libs = full`,
  - each binary in `[bin] allow`, bound individually at `/usr/bin/<name>`,
  - the files you list in `[fs]`.

  Anything not listed does not exist.
- **`mode = bundle`**: the userland is a private Alpine minirootfs, `~/.local/share/holdfast/bundles/<os>/rootfs`,
  shared by every profile that names the same `os`. There is no setup command: the first `holdfast run` creates it.
  Everything that touches the downloaded bytes runs inside sandboxes (no host process handles the tarball): a throwaway
  network-restricted sandbox downloads it over HTTPS, checks the sha256 (pin it in the `data/os` file) and extracts it,
  then a second one runs `apk add` and your `provision` lines. Day-to-day runs mount it read-only.
  Changing the `data/os` file makes the next run refuse until you `holdfast run --refresh PROFILE` (rebuild; changes made
  inside the userland are discarded). It is all plain folders: `holdfast doctor` prints the data directory; to remove a
  userland or a profile's saved `$HOME`, delete its folder (`bundles/<os>/`, `profiles/<name>/`).

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
