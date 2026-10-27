# Profile reference

INI syntax: `[section]`, `key = value`, `#`/`;` full-line comments, inline comments start with
whitespace + `#`. Repeatable keys append. Section/key names are case-insensitive. Unknown names are errors.
Booleans: `yes/no/true/false/on/off/1/0`. Variables: `$HOME $USER $UID $GID $XDG_RUNTIME_DIR $STATE $CWD $ARCH`, `~/`.
Mount syntax: `SRC` or `SRC => DEST` (DEST defaults to SRC). Globs (`* ? [..]`) are allowed in `[fs]` sources.

## [profile]
| key | default | meaning |
|---|---|---|
| name | file stem | `[a-z0-9][a-z0-9_-]{0,31}`; names state dirs and the netns |
| description | | shown by `list` |
| mode | `host` | `host` (whitelist host binaries/libs) or `bundle` (private Alpine) |
| command | | argv, shell-style quoting; replaced by `-- CMD…` on the CLI |
| hostname | `holdfast` | UTS hostname inside |
| new_session | `yes` | `bwrap --new-session` (blocks TIOCSTI; Ctrl-C then hits holdfast, not the inner program) |
| disable_userns | `yes` | `--disable-userns` when bwrap ≥ 0.8 |
| seccomp | `default` | `default` (built-in libseccomp filter, see below) · `none` (no filter, warns) · path to a compiled BPF file. A build without libseccomp refuses `default`. |
| cwd | `ask` | `none` / `ask` (tty prompt) / `yes`; mounts the current dir at `cwd_dest` |
| cwd_dest | `/shared` | absolute, not under `/usr /etc /bin /lib /proc /dev /sys /run /var` |

## [bin]  (host mode)
`allow = name [name=/abs/path …]` – each is bound at `/usr/bin/<name>`. Missing binaries are skipped with a warning.

## [fs]
| key | meaning |
|---|---|
| ro / ro_try | read-only bind (`_try`: skip if absent) |
| rw / rw_try | read-write bind (refused under system prefixes) |
| tmpfs | extra tmpfs mount |
| deny | extra deny-list path (globs ok) |
| defaults | `yes`: bind ld.so.cache, terminfo, zoneinfo, ssl, ca-certificates, os-release (+resolv.conf if networked) |
| libs | `minimal` (default): bind only the shared libraries the allowed binaries need (ELF `DT_NEEDED`, resolved transitively, nothing executed) plus a built-in map of runtime data dirs (python stdlib, `git-core`, nvim runtime, NSS modules). Unresolvable libs or toolchain commands (`gcc cc g++ ld lld clang rustc cargo`) are an error that tells you to use `full`; there is no automatic fallback. `full`: bind `/usr/lib /usr/lib64` (and `/lib*`) read-only. Anything `dlopen`ed that is not in the map needs an `[fs] ro_try` entry, or `libs = full`. |

## [home]
`user` (fake login name, default `sandbox`) · `dirs` (create in fake home) · `bind = REL [=> REL]` (rw, from real `$HOME`) · `ro_bind` (same, read-only).
The fake home is persistent at `<data>/profiles/<name>/home`.

## [env]
`set = NAME=VALUE` · `pass = NAME …` (copy from host; `TERM LANG COLORTERM` always) · `unset = NAME …`.
The environment is otherwise cleared.

## [network]
`mode = none|pasta|host|ivpn` · `wg_conf` (ivpn) · `ns_name` (default `hf-<name>`) · `subnet` (1-254, default derived) · `verify = yes|no`.

`pasta`: private network namespace with outbound internet via `pasta` (package `passt`). Host loopback services and
inbound ports are unreachable, and host *abstract* unix sockets (X11, D-Bus) are not shared. `host` shares the host
network namespace and therefore those sockets: prefer `pasta`. The LAN is reachable in both.

### Default seccomp filter
`seccomp = default` returns EPERM for: kexec/module/reboot, `bpf`, `perf_event_open`, `userfaultfd`, `io_uring_*`,
`keyctl`/`add_key`/`request_key`, `mount` and the new-mount API, `pivot_root`, `open_by_handle_at`, clock setting,
legacy x86 calls (`modify_ldt`, `iopl`, ...), plus the `TIOCSTI`/`TIOCLINUX` ioctls. `clone`, `clone3`, `unshare`,
`setns` and `ptrace` stay allowed (browsers, nested sandboxes, debuggers). Foreign-ABI syscalls are killed.

## [display]
`mode = none|xephyr|host` · `size = WxH` · `wm = <shell snippet started in background before the command>` ·
`xauth = yes|no` (xephyr cookie) · `allow_host_x11 = yes` (required for `mode=host`).

## [audio]  `mode = none|pulse` – pulse also grants microphone access.
## [clipboard]  `mode = none|out` · `path` (in-sandbox file, default `/tmp/clip_pipe`) · `sanitize = yes|no` (default `yes`: strip control characters, incl. ESC/CR/DEL/C1 and bidi overrides; `\n` and `\t` are kept).
## [git]  `protect = yes|no` – re-bind every `.git` read-only under the mounted tree.
## [fonts]  `allow = family …` – substring match on font file paths; only these are visible.

## [bundle]
| key | default | |
|---|---|---|
| alpine_version | `latest-stable` | e.g. `v3.21` |
| alpine_mirror | `https://dl-cdn.alpinelinux.org/alpine` | HTTPS only |
| alpine_sha256 | | pin the tarball hash (also enables offline reuse of the cache) |
| packages | | `apk add` list (repeatable) |
| provision | | one shell line per key, run once in the writable stage with network; do not use ` #` inside |
