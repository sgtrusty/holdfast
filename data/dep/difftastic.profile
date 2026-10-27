[dep]
description = difftastic (upstream master), built with cargo
os = alpine-3.24-dev
needs = git cargo

[network]
mode = pasta

[install]
run = git clone --depth 1 --branch master https://github.com/Wilfred/difftastic.git /tmp/difft && cargo install --path /tmp/difft --root "$HOME/go"
# Proof of concept for building a fork's feature branch instead:
# run = git clone --depth 1 --branch osc-1717-metadata https://github.com/stefanhaller/difftastic.git /tmp/difft && cargo install --path /tmp/difft --root "$HOME/go"
