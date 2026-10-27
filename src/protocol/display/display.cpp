#include "protocol/display/display.hpp"

#include <cstdlib>

#include "protocol/display/wayland.hpp"
#include "protocol/display/x11.hpp"

namespace hf::display {

DisplayProtocol effective_protocol(const DisplayDef& d) {
    if (d.mode == DisplayMode::Nested) return d.protocol;
    const char* w = std::getenv("WAYLAND_DISPLAY");      // prefer Wayland: it isolates clients from each other, X11 does not
    return (w && *w) ? DisplayProtocol::Wayland : DisplayProtocol::X11;
}

void validate(const Profile& p) {
    if (!p.display) {
        if (p.allow_host_display) throw ProfileError("[display] allow_host is set but there is no `use = NAME`: there is no display for it to apply to");
        return;
    }
    const DisplayDef& d = *p.display;
    // Consent lives in the sandbox profile, not the display file: a shared data file must not be able to hand over your session.
    if (d.mode == DisplayMode::Host && !p.allow_host_display)
        throw ProfileError(cat("display '", d.name, "' shares your real ", effective_protocol(d) == DisplayProtocol::X11 ? "X11 session" : "Wayland compositor",
                               " (keylogging, screen capture); set `allow_host = yes` under [display] to accept that, or use a nested display"));
    if (d.mode == DisplayMode::Nested && p.allow_host_display)
        throw ProfileError(cat("[display] allow_host = yes but display '", d.name, "' is nested: remove it (it only applies to mode = host)"));
    if (effective_protocol(d) == DisplayProtocol::X11) validate_x11(p);
    else validate_wayland(p);
}

std::unique_ptr<Backend> open(const Profile& p, const User& u, const fs::path& session, bool dry) {
    if (!p.display) return nullptr;
    validate(p);                                        // open() is also reachable without validate_profile(); never skip the consent checks
    return effective_protocol(*p.display) == DisplayProtocol::X11 ? open_x11(p, u, session, dry) : open_wayland(p, u, dry);
}

}  // namespace hf::display
