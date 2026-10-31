# Xephyr plus the i3 window manager, with the X server's own 2D drawing accelerated through glamor.
# This does NOT accelerate GL clients: Xephyr's GLX is software, so programs inside still get llvmpipe.
# For GPU-rendered clients use a `server = host` display (see data/profile/gpu-host.profile).
[display]
description = private X11 server (Xephyr) with i3 and glamor (2D only; client GL is software)
server = xephyr
size = 1920x1280
xauth = yes
glamor = yes
wm = i3
