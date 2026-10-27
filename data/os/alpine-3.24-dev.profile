# One Alpine userland, shared by every profile with `os = alpine-3.24-dev` (<data>/bundles/alpine-3.24-dev/rootfs).
# Everything that defines the userland lives here and nowhere else: change a package or the pinned release
# once, then `holdfast run --refresh PROFILE` rebuilds it. Profiles keep only their own install steps (data/dep).
# `packages` are installed with apk in the one special sandbox: writable rootfs, userns-root, network via pasta.
# [install] says how the install steps (download, apk, deps with network) reach the network and what they may use
# from the host. Nothing else from the host is mounted, and the host's /etc/resolv.conf is never read.
[os]
kind = bundle
description = Alpine 3.24 with Go and Rust toolchains
# Exact release + pinned hash: nothing moves under you (latest-stable and branch names are moving targets).
alpine_version = 3.24.3
alpine_sha256 = f8e1cafba9b1b283b5d30d06f9885c8d2bc161ffe9083ade8e2e157813a53407
packages = ca-certificates build-base git bash curl go rust cargo

[install]
net = pasta
dns = 1.1.1.1                 # resolver for the download, apk and every dep with [network] mode = pasta
# The download runs the HOST's sh/tar/gzip/sha256sum/curl: only these libs' files (data/lib/*.profile, as saved
# for your distro by `holdfast libs --refresh`) are mounted, read-only. Not needed once the userland exists.
use = shell archive coreutils net certs
