# Xephyr plus the i3 window manager, with the X server itself rendering through the GPU (glamor).
# A profile using this still needs `[gpu] mode = render` for sandboxed clients to get a DRM render node,
# and its host Xephyr must advertise -glamor (see `holdfast doctor`).
[display]
description = private X11 server (Xephyr) with the i3 window manager and glamor (GPU-backed)
server = xephyr
size = 1920x1280
xauth = yes
glamor = yes
wm = i3
