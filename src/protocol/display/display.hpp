// holdfast - display protocols behind one small interface
//
// build_plan() knows nothing about X11 or Wayland. A display backend turns a profile's [display] section into plain data:
// files/sockets to bind into the sandbox, environment variables, and (only if the protocol needs it) a command to run in the
// background before the program. Adding a protocol means adding a file in this directory and one line in open().
//
//   x11.cpp      a private nested X server (Xephyr) or the host's X server; X needs a separate window manager (`wm`)
//   wayland.cpp  the host's Wayland socket; the compositor is the window manager, so there is nothing like `wm` here
#pragma once
#include <memory>
#include <utility>

#include "core/profile.hpp"
#include "util/sys.hpp"

namespace hf::display {

struct Bind {
    fs::path host, sandbox;
    bool rw = false;               // sockets need rw to connect; regular files (cookies) are read-only
};

// Everything the sandbox gets from a display, as data.
struct Setup {
    std::string backend;                                          // "x11-nested", "x11-host", "wayland-host": for messages and tests
    std::vector<Bind> binds;
    std::vector<std::pair<std::string, std::string>> env;         // DISPLAY, XAUTHORITY / WAYLAND_DISPLAY, ...
    std::string background;                                       // shell snippet started in the sandbox before the program; "" = none
};

// A running backend (e.g. the Xephyr process). Destroying it stops whatever it started.
class Backend {
public:
    virtual ~Backend() = default;
    virtual const Setup& setup() const = 0;
};

// Fail-closed checks of the [display] section, no side effects: host access needs explicit consent, X11-only keys (size, xauth, wm)
// are errors under any other protocol or mode, unimplemented combinations say so. Throws ProfileError.
// What `server = host` means right now: Wayland when WAYLAND_DISPLAY is set, else X11. Nested displays carry their own.
DisplayProtocol effective_protocol(const DisplayDef& d);
void validate(const Profile& p);

// nullptr when the profile has no display. dry = describe only (print/check): nothing is started or required to exist.
std::unique_ptr<Backend> open(const Profile& p, const User& u, const fs::path& session, bool dry);

}  // namespace hf::display
