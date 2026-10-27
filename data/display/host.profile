# Your REAL session: Wayland compositor socket if WAYLAND_DISPLAY is set, otherwise your X server (keylogging and
# screen capture possible). Nothing else to configure. The sandbox profile must say `allow_host = yes`.
[display]
description = your real desktop session (Wayland if available, else X11)
server = host
