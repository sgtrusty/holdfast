[dep]
description = difftastic (osc-1717-metadata branch), built with cargo
os = alpine-3.24-dev
needs = git cargo

[network]
mode = pasta

[install]
run = git clone --depth 1 --branch osc-1717-metadata https://github.com/stefanhaller/difftastic.git /tmp/difft && cargo install --path /tmp/difft --root "$HOME/go"
