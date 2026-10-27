# Self-contained Alpine userland (NOT your host's /usr, /etc, /bin) with Go + Rust,
# used to build and run the lazygit "stage hunks" test build.
# Replaces: develbox.sh
#
#   cd ~/some/repo && holdfast run lazygit-dev    # first run downloads + verifies Alpine and installs the tools (in sandboxes)
#   holdfast run --refresh lazygit-dev            # rebuild the userland after editing data/os/alpine-3.24-dev.profile

[profile]
name        = lazygit-dev
description = lazygit test build in a private Alpine bundle
mode        = bundle
# The userland (Alpine release, pinned hash, package list) is declared once in data/os/alpine-3.24-dev.profile and
# shared by every profile that names it; holdfast refuses to run a bundle built from a different version of that file.
os          = alpine-3.24-dev
command     = lazygit
cwd         = ask
new_session = no

[bundle]
# Per-profile only. Run once, with network, as userns-root inside the bundle. HOME=/home/sandbox is persistent.
provision = go install github.com/jesseduffield/lazygit@sh-integration
provision = cargo install --git https://github.com/stefanhaller/delta.git --branch osc-1717-metadata --root /home/sandbox/go
provision = git clone --depth 1 --branch osc-1717-metadata https://github.com/stefanhaller/difftastic.git /tmp/difft && cargo install --path /tmp/difft --root /home/sandbox/go
provision = curl -fsSL https://raw.githubusercontent.com/stefanhaller/diff-so-fancy/refs/heads/osc-1717-metadata/diff-so-fancy -o /home/sandbox/go/bin/diff-so-fancy && chmod +x /home/sandbox/go/bin/diff-so-fancy

[home]
user = sandbox

[network]
mode = none                   # provisioning has network; day-to-day running does not

[git]
protect = yes                 # lazygit has to write .git (stage/commit); you opted into that
