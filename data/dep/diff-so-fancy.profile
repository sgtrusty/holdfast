[dep]
description = diff-so-fancy (osc-1717-metadata branch), a single script
os = alpine-3.24-dev
needs = curl

[network]
mode = pasta

[install]
run = mkdir -p "$HOME/go/bin"
run = curl -fsSL https://raw.githubusercontent.com/stefanhaller/diff-so-fancy/refs/heads/osc-1717-metadata/diff-so-fancy -o "$HOME/go/bin/diff-so-fancy" && chmod +x "$HOME/go/bin/diff-so-fancy"
