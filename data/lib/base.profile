# The C runtime every dynamically linked program needs. Always part of a profile's lib set (no `use` needed).
# Globs are searched in the loader's library directories (ld.so.conf + the usual lib dirs).
[lib]
description = dynamic loader, libc, NSS/resolver modules, iconv and locale data
sonames = libc.so.* libc.musl-*.so.* ld-linux*.so.* ld-musl-*.so.* libm.so.* libresolv.so.* libnss_files.so.* libnss_dns.so.* libgcc_s.so.*
paths = /usr/lib/locale /usr/lib/gconv /usr/lib/*/gconv
