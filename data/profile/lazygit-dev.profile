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

[deps]
# Install steps (data/dep/NAME.profile), run once into this profile's persistent $HOME; those with network use pasta
# and the resolver from data/os/alpine-3.24-dev.profile [install] dns. Each
# recipe is stamped on its own: a new dep installs on the next run, an edited recipe asks for --refresh.
use = lazygit delta difftastic diff-so-fancy

[home]
user = sandbox

[network]
mode = none                   # installing deps has network; day-to-day running does not

[git]
protect = yes                 # lazygit has to write .git (stage/commit); you opted into that
