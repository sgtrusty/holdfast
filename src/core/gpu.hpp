// holdfast - DRM render-node discovery (the [gpu] mode = render surface)
#pragma once

#include "core/paths.hpp"

namespace hf {

// Canonical, sorted /dev/dri/renderD<digits> nodes present on the host. Empty when /dev/dri does not exist.
Strings find_render_nodes();

// Kernel driver name for a render node (e.g. "amdgpu", "i915", "nouveau"), from
// /sys/class/drm/renderD<N>/device/driver. Empty when it cannot be read.
std::string render_node_driver(const fs::path& node);

// Whether the invoking user can open the node O_RDWR (the sandbox submits GPU work through it). `why` gets strerror().
bool render_node_openable(const fs::path& node, std::string* why = nullptr);

// Host paths (all read-only) that must accompany a render node for Mesa/libdrm to use it instead of falling back to
// llvmpipe: sysfs is how libdrm maps a passed DRM fd back to a node/driver, and host profiles also need the EGL/Vulkan
// manifest directories and Mesa's drirc.d. `host_root` adds the userland files (a bundle already has them in its /usr).
// These are fixed paths, not profile input; callers bind exactly this list.
Strings gpu_support_binds(bool host_root);

}  // namespace hf
