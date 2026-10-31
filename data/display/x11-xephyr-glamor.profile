# A private X server (Xephyr) in a window whose own 2D drawing is GPU-backed through glamor.
# This does NOT accelerate GL clients: Xephyr's GLX is software, so programs inside still get llvmpipe.
# For GPU-rendered clients use a `server = host` display (see data/profile/gpu-host.profile).
[display]
description = private X11 server (Xephyr) with glamor (2D only; client GL is software)
server = xephyr
size = 1280x800
xauth = yes
glamor = yes
