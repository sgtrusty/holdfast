# GPU demo: a private Xephyr window whose X server renders through the GPU (glamor), plus
# DRM render nodes so Mesa clients in the sandbox can use the GPU directly.
#
#   holdfast run gpu-xephyr                 # glxinfo -B: which renderer did we get?
#   holdfast run gpu-xephyr -- glxgears     # animated gears, rendered by the GPU if all is well
#   holdfast run gpu-xephyr -- eglinfo      # EGL/GLES information
#
# Requirements:
#   - an Xephyr build that advertises -glamor (`holdfast doctor` says whether yours does)
#   - a DRM render node your user may open read-write (usually the render/video group or a logind ACL)
#   - mesa-utils (glxinfo, glxgears) and, for eglinfo, mesa-utils-extra (package names vary by distro)
#
# Set [gpu] mode = none (or delete the section) to compare: the same profile still starts, but
# Mesa clients inside have no render node and fall back to software. Xephyr's own glamor runs on
# the host and is unaffected. holdfast deliberately sets no Mesa variables, so the difference is
# the GPU access itself, not LIBGL_ALWAYS_SOFTWARE.
[profile]
name        = gpu-xephyr
description = GPU demo: Xephyr with glamor + DRM render nodes (glxinfo/glxgears)
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
use = x11-xephyr-glamor       # data/display/: Xephyr started with -glamor

[gpu]
mode = render                 # the opt-in: bind /dev/dri/renderD* (never card*/nvidia*)
# device = /dev/dri/renderD128  # optional: pin one node instead of binding every render node
