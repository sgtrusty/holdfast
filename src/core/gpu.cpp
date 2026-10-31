#include "core/gpu.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <set>

namespace hf {

namespace {

bool render_name(const std::string& n) {
    if (n.rfind("renderD", 0) != 0 || n.size() == 7) return false;
    for (size_t i = 7; i < n.size(); ++i)
        if (n[i] < '0' || n[i] > '9') return false;
    return true;
}

}  // namespace

Strings find_render_nodes() {
    std::set<std::string> found;
    std::error_code ec;
    for (fs::directory_iterator it("/dev/dri", fs::directory_options::skip_permission_denied, ec), end; !ec && it != end; it.increment(ec)) {
        if (!render_name(it->path().filename().string())) continue;
        // Canonicalise first: a symlinked path that leaves /dev/dri is not a render node the sandbox may see.
        if (is_render_node(it->path())) found.insert(canon(it->path()).string());
    }
    return Strings(found.begin(), found.end());
}

std::string render_node_driver(const fs::path& node) {
    const fs::path link = fs::path("/sys/class/drm") / node.filename() / "device/driver";
    std::error_code ec;
    const fs::path target = fs::read_symlink(link, ec);
    if (ec) return "";
    return target.filename().string();
}

bool render_node_openable(const fs::path& node, std::string* why) {
    const int fd = open(node.c_str(), O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
        close(fd);
        return true;
    }
    if (why) *why = std::strerror(errno);
    return false;
}

Strings gpu_support_binds(bool host_root) {
    // libdrm's drmGetDevice2()/Mesa's loader resolve a DRM fd through /sys/dev/char/<maj>:<min>, its /sys/devices target and
    // /sys/bus/pci (PCI revision/workarounds). Without these Mesa cannot name the driver and quietly selects llvmpipe even
    // though the render node is bound. /sys/class/drm is deliberately not mounted: it exposes connector/monitor state.
    Strings out;
    for (const char* p : {"/sys/dev/char", "/sys/devices", "/sys/bus/pci/devices"})
        if (fs::exists(p)) out.emplace_back(p);
    if (!host_root) return out;             // a bundle's own /usr already carries these
    // Manifests and Mesa's per-application workarounds live in /usr/share, which `libs = full` does not mount (it only
    // binds /usr/lib*). Missing paths are simply skipped: a distro without Vulkan still gets working GL/EGL.
    for (const char* p : {"/usr/share/drirc.d", "/usr/share/glvnd/egl_vendor.d", "/usr/share/vulkan/icd.d", "/etc/vulkan/icd.d"})
        if (fs::exists(p)) out.emplace_back(p);
    return out;
}

}  // namespace hf
