# One Alpine userland, shared by every profile with `os = alpine-3.24-dev` (<data>/bundles/alpine-3.24-dev/rootfs).
# Everything that defines the userland lives here and nowhere else: change a package or the pinned release
# once, then `holdfast run --refresh PROFILE` rebuilds it. Profiles keep only their own `provision` lines.
[os]
kind = bundle
description = Alpine 3.24 with Go and Rust toolchains
# Exact release + pinned hash: nothing moves under you (latest-stable and branch names are moving targets).
alpine_version = 3.24.3
alpine_sha256 = f8e1cafba9b1b283b5d30d06f9885c8d2bc161ffe9083ade8e2e157813a53407
packages = ca-certificates build-base git bash curl go rust cargo
