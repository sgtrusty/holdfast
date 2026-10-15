# Self-contained Alpine userland (NOT your host's /usr, /etc, /bin) with Go + Rust,
# used to build and run the lazygit "stage hunks" test build.
# Replaces: develbox.sh
#
#   holdfast bundle setup lazygit-dev       # one-time: download+verify Alpine, apk add, build tools
#   cd ~/some/repo && holdfast run lazygit-dev

[profile]
name        = lazygit-dev
description = lazygit test build in a private Alpine bundle
mode        = bundle
command     = lazygit
cwd         = ask
new_session = no              # lazygit is a full-screen TUI that wants a controlling tty

[bundle]
alpine_version = latest-stable
# Optional: pin the minirootfs tarball's sha256 for reproducible/offline reuse.
# alpine_sha256 = <64 hex>
packages = ca-certificates build-base git bash curl go rust cargo
# Run once, with network, as userns-root inside the bundle. HOME=/home/sandbox is persistent.
provision = go install github.com/jesseduffield/lazygit@sh-integration
provision = cargo install --git https://github.com/stefanhaller/delta.git --branch osc-1717-metadata --root /home/sandbox/go
provision = git clone --depth 1 --branch osc-1717-metadata https://github.com/stefanhaller/difftastic.git /tmp/difft && cargo install --path /tmp/difft --root /home/sandbox/go
provision = curl -fsSL https://raw.githubusercontent.com/stefanhaller/diff-so-fancy/refs/heads/osc-1717-metadata/diff-so-fancy -o /home/sandbox/go/bin/diff-so-fancy && chmod +x /home/sandbox/go/bin/diff-so-fancy

[home]
user = sandbox

[network]
mode = none                   # provisioning has network; day-to-day running does not

[git]
protect = no                  # lazygit has to write .git (stage/commit); you opted into that
