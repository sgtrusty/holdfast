# LibreWolf, amnesic, on its own nested X server, ALL traffic forced through an IVPN
# WireGuard tunnel inside a network namespace with a fail-closed kill switch.
# Replaces: run-ivpn-librewolf.sh
#
#   holdfast run librewolf-ivpn
#   holdfast net-test librewolf-ivpn      # verify the kill switch once after setup

[profile]
name        = librewolf-ivpn
description = Amnesic LibreWolf behind IVPN (netns + kill switch + Xephyr)
mode        = host
command     = librewolf --no-remote --profile /tmp/lw
hostname    = localhost
cwd         = none            # a browser needs no project directory
# Browsers are GUI apps with no tty: new-session is harmless and keeps TIOCSTI closed.
new_session = yes

[bin]
# Host binaries that exist inside the sandbox. Nothing else is executable.
allow = librewolf i3 sh

[fs]
# A browser dlopens graphics/audio/GTK plugins that cannot be derived from ELF headers.
libs = full
# Browser runtime data. Missing paths are skipped silently (ro_try).
ro_try = /usr/lib/librewolf
ro_try = /usr/share/librewolf
ro_try = /usr/share/glib-2.0
ro_try = /usr/share/icons/hicolor
ro_try = /usr/share/icons/Adwaita
ro_try = /usr/share/mime
ro_try = /etc/fonts
tmpfs  = /tmp/lw              # ephemeral profile: gone when the sandbox exits

[home]
user = browser

[env]
set  = MOZ_ENABLE_WAYLAND=0
pass = LANG

[network]
mode      = ivpn
# Download from https://www.ivpn.net/setup/wireguard/ . Must contain exactly one
# Endpoint, as an IPv4 literal, and no PostUp/PreUp hooks (holdfast rejects those).
wg_conf   = $HOME/.config/holdfast/ivpn.conf
verify    = yes

[display]
mode = xephyr
size = 1920x1280
wm   = i3

[fonts]
# Only these families are visible (reduces font fingerprinting).
allow = liberation dejavu

[audio]
# WARNING: pulse also exposes your microphone to everything in the sandbox.
mode = none
