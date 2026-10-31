# A private X server (Xephyr) in a window whose own rendering is GPU-backed through glamor.
# Mesa clients also need the sandbox profile's `[gpu] mode = render` to get a DRM render node.
[display]
description = private X11 server (Xephyr) with glamor (GPU-backed), no window manager
server = xephyr
size = 1280x800
xauth = yes
glamor = yes
