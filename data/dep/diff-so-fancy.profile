[dep]
description = diff-so-fancy (upstream master), a single script
os = alpine-3.24-dev
needs = curl

[network]
mode = pasta

[install]
run = mkdir -p "$HOME/go/bin"
run = curl -fsSL https://raw.githubusercontent.com/so-fancy/diff-so-fancy/refs/heads/master/diff-so-fancy -o "$HOME/go/bin/diff-so-fancy" && chmod +x "$HOME/go/bin/diff-so-fancy"
# Proof of concept for fetching a fork's feature branch instead (that branch no longer exists upstream):
# run = curl -fsSL https://raw.githubusercontent.com/stefanhaller/diff-so-fancy/refs/heads/osc-1717-metadata/diff-so-fancy -o "$HOME/go/bin/diff-so-fancy" && chmod +x "$HOME/go/bin/diff-so-fancy"
