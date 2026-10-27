# An install step for bundle profiles. It runs as an ORDINARY run of the profile that lists it under [deps] use: same
# userland (read-only), same persistent $HOME, same identity (your uid, not root), same seccomp and terminal filter.
# Only what is written below differs from that profile. Trusted shell: read it before you use it.
[dep]
description = lazygit (sh-integration branch), built with Go
os = alpine-3.24-dev        # the userland this is built for; the profile using it must name the same os
needs = go                  # must already exist in that userland (add its package to data/os/<os>.profile)

[network]
mode = pasta                # downloading sources needs the internet; leave this out and the recipe runs offline

[install]
run = go install github.com/jesseduffield/lazygit@sh-integration
