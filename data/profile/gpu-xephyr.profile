# GPU plumbing demo behind a private Xephyr window: Xephyr itself renders through the GPU (glamor) and
# the sandbox gets DRM render nodes, but **client GL inside Xephyr is software (llvmpipe)**. Xephyr is a
# nested X server with its own software GLX; -glamor only accelerates its 2D drawing on the host. Use
# `gpu-host` if you want glxinfo to report the real GPU.
#
#   holdfast run gpu-xephyr                 # glxinfo -B: llvmpipe is the expected result here
#   holdfast run gpu-xephyr -- glxgears     # works, but on the CPU
#   holdfast run gpu-xephyr -- eglinfo      # same: software rendering
#
# This profile is still useful: it proves the render node is bound and openable (the same plumbing the
# host demo needs), and that the Xephyr window itself is GPU-composited when -glamor is available.
#
# Requirements:
#   - an Xephyr build that advertises -glamor (`holdfast doctor` says whether yours does)
#   - a DRM render node your user may open read-write (usually the render/video group or a logind ACL)
#   - mesa-utils (glxinfo, glxgears) and, for eglinfo, mesa-utils-extra (package names vary by distro)
#
# Set [gpu] mode = none (or delete the section) to compare: the profile still starts, but Mesa clients
# inside have no render node. Xephyr's own glamor runs on the host and is unaffected.
[profile]
name        = gpu-xephyr
description = GPU plumbing demo: Xephyr glamor + render nodes (client GL is llvmpipe)
mode        = host
command     = glxinfo -B
hostname    = gpu
cwd         = none            # no project directory is needed to ask the GPU who it is

[bin]
# Missing ones are skipped with a warning; install what you want to run.
allow = glxinfo glxgears eglinfo

[fs]
# Mesa drivers and the GL/EGL/gallium files are dlopen()ed and cannot be derived from ELF
# headers. A real profile can use a data/lib definition instead; this demo opts out.
libs = full

[display]
use = x11-xephyr-glamor       # data/display/: Xephyr started with -glamor (2D acceleration only)

[gpu]
mode = render                 # the opt-in: bind /dev/dri/renderD* (never card*/nvidia*)
# device = /dev/dri/renderD128  # optional: pin one node instead of binding every render node
