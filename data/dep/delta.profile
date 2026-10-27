[dep]
description = delta (upstream main), built with cargo
os = alpine-3.24-dev
needs = cargo

[network]
mode = pasta

[install]
run = cargo install --git https://github.com/dandavison/delta.git --branch main --root "$HOME/go"
# Proof of concept for building a fork's feature branch instead (that branch no longer exists upstream):
# run = cargo install --git https://github.com/stefanhaller/delta.git --branch osc-1717-metadata --root "$HOME/go"
