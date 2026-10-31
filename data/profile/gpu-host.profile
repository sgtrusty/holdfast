# GPU demo on your real X11 session: the sandbox gets DRM render nodes and uses the host X server, so
# DRI3 hands it a real GPU file descriptor and glxinfo should report your driver, not llvmpipe.
#
#   holdfast run gpu-host                 # glxinfo -B: "Accelerated: yes" and your GPU
#   holdfast run gpu-host -- glxgears     # animated gears, rendered on the GPU
#   holdfast run gpu-host -- vulkaninfo --summary
#
# This is the counterpart to gpu-xephyr: Xephyr is a nested X server whose GLX is software, so clients
# there render with llvmpipe even when -glamor is on (glamor only accelerates Xephyr's own 2D drawing).
#
# Requirements:
#   - an X11 session (DISPLAY=:N). `server = host` follows WAYLAND_DISPLAY, and a native Wayland
#     session does not run X11 clients; glxinfo needs X11. On Wayland, use a native EGL/Vulkan client.
#   - a DRM render node your user may open read-write (render/video group or a logind ACL)
#   - mesa-utils (glxinfo, glxgears); vulkan-tools for vulkaninfo
#
# WARNING: this shares your real X11 session. The sandbox can observe and inject input for every
# window; `allow_host = yes` is the consent for that. Use gpu-xephyr if you need an isolated display.
[profile]
name        = gpu-host
description = GPU demo: real X11 session + DRM render nodes (glxinfo sees the GPU)
mode        = host
command     = glxinfo -B
hostname    = gpu
cwd         = none            # no project directory is needed to ask the GPU who it is

[bin]
# Missing ones are skipped with a warning; install what you want to run.
allow = glxinfo glxgears eglinfo vulkaninfo

[fs]
# Mesa's GL/EGL/gallium drivers are dlopen()ed and cannot be derived from ELF headers. A real profile
# can use a data/lib definition instead; this demo opts out.
libs = full

[display]
use = host                    # your real X11 session (DRI3 is what turns the render node into GPU GL)
allow_host = yes              # required: the sandbox can see and drive all your X11 windows

[gpu]
mode = render                 # the opt-in: bind /dev/dri/renderD* (never card*/nvidia*)
# device = /dev/dri/renderD128  # optional: pin one node; for host X11 it must be the server's GPU
