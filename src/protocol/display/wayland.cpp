#include "protocol/display/wayland.hpp"

#include <sys/stat.h>

#include <regex>

#include "util/log.hpp"

namespace hf::display {

namespace {

class WaylandHost final : public Backend {
public:
    WaylandHost(const User& u, bool dry) {
        // WAYLAND_DISPLAY is a socket name inside $XDG_RUNTIME_DIR, or an absolute path.
        std::string name = "wayland-0";
        if (const char* w = std::getenv("WAYLAND_DISPLAY"); w && *w) name = w;
        fs::path host;
        if (name.find('/') != std::string::npos) {
            host = name;
            name = host.filename().string();
        } else {
            const char* xr = std::getenv("XDG_RUNTIME_DIR");
            host = fs::path(xr && *xr ? std::string(xr) : u.runtime_dir.string()) / name;
        }
        static const std::regex name_ok("^[A-Za-z0-9._-]{1,64}$");       // becomes a path component and an environment value
        if (!std::regex_match(name, name_ok)) throw Error("unusable WAYLAND_DISPLAY: " + name);
        if (!dry) {
            struct stat st{};
            if (stat(host.c_str(), &st) != 0 || !S_ISSOCK(st.st_mode))
                throw Error(cat("no Wayland socket at ", host.string(), "; is a Wayland session running? (WAYLAND_DISPLAY=", name, ")"));
        }
        setup_.backend = "wayland-host";
        // rw: connecting to a socket needs write access to its node; there is no file content to protect
        setup_.binds.push_back({host, fs::path("/run/user") / std::to_string(u.uid) / name, true});
        setup_.env.emplace_back("WAYLAND_DISPLAY", name);               // XDG_RUNTIME_DIR inside is already /run/user/<uid>
        log::warn("host Wayland session shared with the sandbox: your compositor may offer it privileged extensions (screen capture, "
                  "virtual input); holdfast does not restrict that yet");
    }
    const Setup& setup() const override { return setup_; }

private:
    Setup setup_;
};

}  // namespace

void validate_wayland(const Profile& p) {
    (void)p;                                            // host only; a private compositor (cage/weston) would be a new `server =` value
}

std::unique_ptr<Backend> open_wayland(const Profile& p, const User& u, bool dry) {
    (void)p;
    return std::make_unique<WaylandHost>(u, dry);
}

}  // namespace hf::display
