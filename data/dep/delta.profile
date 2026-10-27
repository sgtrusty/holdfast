[dep]
description = delta (osc-1717-metadata branch), built with cargo
os = alpine-3.24-dev
needs = cargo

[network]
mode = pasta

[install]
run = cargo install --git https://github.com/stefanhaller/delta.git --branch osc-1717-metadata --root "$HOME/go"
