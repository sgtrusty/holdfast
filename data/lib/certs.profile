[lib]
description = the host's CA trust store (for https from host tools, e.g. the Alpine bootstrap's curl)
# Directories, bound whole and read-only: certificate bundles and the hashed links that point into them.
paths = /etc/ssl /etc/ca-certificates /usr/share/ca-certificates /etc/pki /usr/share/p11-kit
