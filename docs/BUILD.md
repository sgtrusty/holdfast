# Building and host requirements

holdfast builds with [predep](https://github.com/10per5/predep) driving [premake5](https://premake.github.io/) (no CMake).

```sh
# one-time: put premake5 + predep on PATH (Linux x86_64)
curl -fsSL "https://github.com/premake/premake-core/releases/download/v5.0.0/premake-5.0.0-linux.tar.gz" \
  | tar -xz && install -m 0755 premake5 /usr/local/bin/
curl -fsSL "https://github.com/10per5/predep/releases/latest/download/predep-linux-x86_64.tar.gz" \
  | tar -xz && install -m 0755 predep /usr/local/bin/

predep                # build the holdfast binary            -> bin/holdfast
predep check          # build + unit tests                   (zero warnings is the bar)
predep e2e            # real-bwrap smoke test (non-root, needs userns)
sudo predep install   # optional; installs the binary, data/ (profiles, libs, os) and docs
```

Or directly: `premake5 gmake && make config=release -j$(nproc) && ./bin/holdfast_tests`.
Terminal and end-to-end checks: `sh tests/e2e.sh ./bin/holdfast`, `sh tests/e2e_tty.sh ./bin/holdfast`.

## Requirements

- Linux, a C++20 compiler, `premake5` (any recent 5.x), `make`, `predep`.
- `bwrap` (tested with 0.9.0; 0.8 or newer is needed for `--disable-userns`).
- `libseccomp` headers (`libseccomp-dev` / `libseccomp-devel`) for the default seccomp filter. `HOLDFAST_SECCOMP=OFF`
  builds without it; profiles must then say `seccomp = none`.
- No other third-party C++ libraries.

**Warnings are errors.** The build enables `-Werror` by default to keep the "zero warnings" bar. To relax it for a local
build: `HOLDFAST_WERROR=OFF predep`.

Run `holdfast doctor` to see which optional features your host supports.

## Optional runtime tools

| for | tools |
|---|---|
| `mode = pasta`, and setting up a bundle profile | `pasta` (package `passt`) |
| bundle mode (first run) | `curl tar gzip sha256sum` (they run inside a sandbox, the binaries come from the host) |
| `mode = ivpn` | `ip iptables wg-quick wg ping sudo setpriv` |
| nested display | `Xephyr` |
| clipboard bridge | `xclip` or `wl-copy` |

## Ubuntu 24.04+

AppArmor blocks unprivileged user namespaces for bwrap by default. Either install a bwrap AppArmor profile or set
`kernel.apparmor_restrict_unprivileged_userns=0`. `holdfast doctor` detects this.
