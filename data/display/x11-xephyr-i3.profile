# Xephyr plus the i3 window manager, started inside the sandbox (the profile needs `sh` and `i3` in [bin] allow).
[display]
description = private X11 server (Xephyr) with the i3 window manager
server = xephyr
size = 1920x1280
xauth = yes
wm = i3
