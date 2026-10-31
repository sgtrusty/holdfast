// holdfast - X11 display backends
#pragma once
#include "protocol/display/display.hpp"

namespace hf::display {

// mode = nested: a private X server (Xephyr) with a random cookie; only its socket and cookie enter the sandbox. X11 clients can
//                read each other's windows and keystrokes, so the sandbox must be the only client: hence a server of its own,
//                and a separate window manager (`wm`) if you want movable/resizable windows.
// mode = host:   the real X server. Hands over your keyboard and screen; needs allow_host_x11 = yes.
void validate_x11(const Profile& p);
std::unique_ptr<Backend> open_x11(const Profile& p, const User& u, const fs::path& session, bool dry);

// MIT-MAGIC-COOKIE-1 authority file with a FamilyWild entry, so it matches regardless of the sandbox's (unshared) hostname.
void write_xauth(const fs::path& file, const std::string& display_num, const std::string& cookie16);

// Whether this Xephyr build advertises -glamor (from `Xephyr -help`). It is optional and build-dependent; `doctor` reports it.
bool xephyr_advertises_glamor(const fs::path& xephyr);

}  // namespace hf::display
