# Concepts

**Profile**: an INI file describing one sandbox (`docs/PROFILE_REFERENCE.md`). It is found by name in the
`profile/` directory of each data dir (`~/.config/holdfast/data`, `/etc/holdfast/data`, the shipped data; `docs/DATA.md`),
or passed as a path. Unknown sections and keys are errors. The data that ships with holdfast
(`data/profile`, `data/lib`, `data/os`) is found next to the binary: in a checkout, or under `/opt/holdfast` after
`predep install`, so the example profiles run by name with nothing to copy. `holdfast list -v` shows what is visible and
where it came from; to customise one, copy its file into `~/.config/holdfast/data/profile/` and edit it.

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
  then another runs `apk add` for the os packages (the one step that needs a writable userland and userns-root), and each
  `[deps] use` recipe (`data/dep`) runs as an ordinary run of the profile itself, with the recipe's own network, to install
  extra tools into its persistent `$HOME`. Day-to-day runs mount the userland read-only.
  Changing the `data/os` file makes the next run refuse until you `holdfast run --refresh PROFILE` (rebuild; changes made
  inside the userland are discarded); an edited dep recipe is refused the same way and re-run by `--refresh`. It is all plain folders: `holdfast doctor` prints the data directory; to remove a
  userland or a profile's saved `$HOME`, delete its folder (`bundles/<os>/`, `profiles/<name>/`).

## Network

| mode | what the sandbox gets |
|---|---|
| `none` (default) | a fresh empty network namespace |
| `pasta` | a private namespace with outbound internet via `pasta`; host loopback services, inbound ports and host abstract sockets are unreachable |
| `host` | the host's network namespace, **including abstract unix sockets such as the X11 server's**: avoid |
| `ivpn` | WireGuard inside `hf-<profile>` with a kill switch, see `docs/NETWORK.md` |

## Display

A profile only names one: `[display] use = x11-xephyr-i3`. The file in `data/display/` says what it is, with one choice, `server`:

| `server` | what happens |
|---|---|
| `xephyr` | X11. A private X server (Xephyr) with a random cookie; only its socket enters the sandbox. X needs a separate window manager, so the file can set `wm` (e.g. `i3`), plus `size` and `xauth` |
| `host` | your real session: the Wayland compositor socket if `WAYLAND_DISPLAY` is set, otherwise your X server. Nothing else to configure (Wayland has no window-manager/server split). The sandbox profile must say `allow_host = yes`, because it hands over your screen and input |

Each protocol is a backend in `src/protocol/display/` that turns the choice into plain data (files to bind, environment variables,
an optional background command), so the rest of holdfast does not know which protocol is in use. A private Wayland compositor
(cage, weston) would be a new `server` value; it is not implemented yet.

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
