// holdfast - Wayland display backend
#pragma once
#include "protocol/display/display.hpp"

namespace hf::display {

// Wayland has no X-style split between a display server and a window manager: the compositor IS the window manager, so there is no
// `wm`, no cookie file and nothing to start for a program that talks to an existing compositor.
//
// mode = host:   the sandbox gets a client connection to YOUR compositor (its socket is bound in). Clients cannot read each other's
//                windows or keystrokes by protocol design, but a compositor may offer privileged extensions (screen capture, virtual
//                input) to any client unless it restricts sandboxed ones (wp_security_context_v1, which holdfast does not use yet).
//                Needs allow_host_wayland = yes.
// mode = nested: a private compositor in a window (cage/weston/sway): the Wayland equivalent of Xephyr. Not implemented yet.
void validate_wayland(const Profile& p);
std::unique_ptr<Backend> open_wayland(const Profile& p, const User& u, bool dry);

}  // namespace hf::display
