# Neovim/LazyVim with a whitelisted toolchain, fake identity, offline by default.
# Replaces: lvim
#
#   cd ~/Projects/foo && holdfast run lazyvim          # offline editing
#   holdfast run --net=pasta lazyvim                    # "sync" mode: plugins/LSP downloads (private netns via pasta)
#
# The working tree is mounted read-write at /shared, but every .git inside it is
# re-bound READ-ONLY: the editor (or an agent inside it) can change files, not history/hooks.

[profile]
name        = lazyvim
description = Neovim + toolchain, offline, .git read-only
mode        = host
command     = nvim
hostname    = virtual-home-lazyvim
cwd         = ask             # confirm before mounting the current directory
new_session = yes

[bin]
allow = nvim vim git bash sh env id uname arch readlink realpath setsid sha256sum
allow = unzip wget curl tar gzip make which sleep tr tail cut whoami expr chmod awk
allow = basename dirname tee sed grep ls cat mkdir rm mv cp stty
allow = rg fd lua-language-server node npm python3 pip python
allow = gcc cc g++ ld as ar pkg-config lld rustc cargo
# Pin an exact host binary with name=/absolute/path
# allow = steam=/usr/bin/steam

[fs]
# gcc/rustc/cargo link against the host's crt files, libc.so and static archives, which `libs = minimal`
# (the default) does not mount. Treesitter/Mason builds need them, so this profile opts out.
libs = full
# Read-only runtime bits. ro_try silently skips what your distro doesn't have.
ro_try = /usr/share/nvim
ro_try = /usr/include
ro_try = /usr/local/include
ro_try = /usr/lib/gcc
ro_try = /usr/lib/node_modules
ro_try = /etc/inputrc
ro_try = /etc/bash.bashrc
ro_try = /etc/lsb-release
tmpfs  = /tmp/scratch

[home]
user = lazyvim
dirs = .config .local/share .local/state .cache .local/bin .cargo/bin
# Extra host directories shown inside the fake home (read-write). Use sparingly;
# the policy refuses anything containing ~/.ssh, ~/.gnupg, browser profiles, ...
# bind = Projects

[env]
set  = EDITOR=nvim
set  = LANG=en_US.UTF-8
set  = RUSTFLAGS=-C linker=/usr/bin/gcc
pass = EDITOR_MODE
unset = DBUS_SESSION_BUS_ADDRESS

[network]
mode = none                   # override per run with --net=pasta (preferred over host)

[display]
mode = none

[clipboard]
# Inside the sandbox:  printf '%s' "$TEXT" > /tmp/clip_pipe   -> lands in the HOST clipboard.
# One-way only; the sandbox can never read your clipboard.
mode = out
path = /tmp/clip_pipe

[git]
protect = yes
