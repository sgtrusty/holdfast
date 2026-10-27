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
| terminal | `filter` | `filter`: when stdin/stdout are terminals the program runs on a fresh pty (its own controlling tty) and everything it prints is filtered, see "Terminal filter" below. `passthrough`: the sandbox writes straight to your terminal (not recommended). |
| new_session | `yes` | `bwrap --new-session`. Only used when the terminal is NOT proxied (`terminal = passthrough`, or stdio is not a tty). It blocks TIOCSTI, but Ctrl-C then hits holdfast and `/dev/tty` is unavailable. With `terminal = filter` it is unnecessary. |
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
| libs | `minimal` (default): bind exactly the files listed in `[libs]` (below); nothing is analysed at run time. An empty `[libs]` with a non-empty `[bin]` is an error. `full`: bind `/usr/lib /usr/lib64` (and `/lib*`) read-only. |

## [libs]  (host mode, `libs = minimal`)
`bind = /absolute/path` (repeatable) – read-only, bound at that path. A missing entry is an error (stale list: regenerate or use `libs = full`).
Generate the list once with `holdfast libs PROFILE` (reads ELF `DT_NEEDED` headers of your `[bin] allow` binaries plus a built-in map of
runtime data dirs such as the python stdlib or `git-core`; executes nothing), review it and paste it into the profile.
Toolchain commands (`gcc cc g++ ld lld clang rustc cargo`) are refused by the generator: use `libs = full`.
Entries are host-specific (distro, arch, versions). `holdfast libs --check PROFILE` re-runs the analysis and prints a diff (`+` missing from the profile, `-` no longer produced); exit 1 if they differ, handy for CI.

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

### Terminal filter
A terminal is programmable: bytes a program prints can set your clipboard (OSC 52), forge titles and hyperlinks, make the
terminal type replies into your shell (title/answerback reports) and leave mouse reporting on after a crash.
With `terminal = filter` the sandbox runs on a pty and its output goes through an allowlist parser. Passed: text, UTF-8,
colours (SGR), cursor movement, erase/scroll, alternate screen, mouse/focus/bracketed-paste/sync modes, safe queries
(DA, cursor position, XTVERSION, DECRQM, kitty keyboard, fg/bg colour query), charset designation, window titles
(sanitised and prefixed `[sandbox]`). Dropped: all other OSC (52 clipboard, 8 hyperlinks, 7, 9, 99, 777, 1337, colour
setting, ...), DCS/APC/PM/SOS (sixel, kitty graphics, tmux passthrough), XTWINOPS (`CSI t`: title reports, resize, move),
RIS, keyboard lock, media copy, 8-bit/C1 controls, ENQ and other C0 controls. When the sandbox ends, modes it left on are reset.
Not covered: what the program *draws* (it can still print misleading text), and bidi overrides in terminal output.
Input is relayed byte for byte. If the terminal ever stays raw after a hard kill of holdfast itself, run `reset`.

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
| id | profile name | shared userland identity (`[a-z0-9._-]`, ≤ 64). Profiles with the same id use one rootfs under `<data>/bundles/<id>`; the fake `$HOME` stays per profile. Setup and `run` verify that the installed bundle was built from this profile's `alpine_version`+`alpine_mirror`+`alpine_sha256` (and the pinned tarball) and fail otherwise. `packages` are additive across profiles; `provision` lines run with the shared rootfs writable, so keep them to `$HOME`. |
| alpine_version | `latest-stable` | exact release (`3.24.3`: fetched by name, reproducible) or a moving alias (`v3.24`, `latest-stable`, `edge`: warns). Pin an exact release plus `alpine_sha256`. |
| alpine_mirror | `https://dl-cdn.alpinelinux.org/alpine` | HTTPS only |
| alpine_sha256 | | pin the tarball hash (also enables offline reuse of the cache) |
| packages | | `apk add` list (repeatable) |
| provision | | one shell line per key, run once in the writable stage with network; do not use ` #` inside |
