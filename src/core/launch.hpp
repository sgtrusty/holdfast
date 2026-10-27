// holdfast - bwrap discovery and launching
#pragma once
#include "core/argbuilder.hpp"
#include "util/sys.hpp"

namespace hf {

fs::path find_bwrap();                       // throws if missing
struct BwrapVersion { int major = 0, minor = 0, patch = 0; bool at_least(int a, int b, int c) const; };
BwrapVersion bwrap_version(const fs::path& bwrap);

// Writes the NUL-separated args file (0600, in the private session dir) and returns the
// argv of a tiny fixed trampoline that opens it as fd 3 (and seccomp as fd 4) and execs
// bwrap. A file is used instead of an inherited pipe because sudo/setpriv close
// unknown file descriptors. The trampoline script is constant: no user data is ever
// interpolated into shell text.
Strings launcher_argv(const fs::path& bwrap, const fs::path& session, const ArgBuilder& b, const fs::path& seccomp);

// pasta (from the passt package) gives the sandbox a *private* network namespace with outbound
// connectivity. Unlike net=host this does not share the host's abstract unix sockets (X11, D-Bus), and
// with the options below the sandbox cannot reach host loopback services or forward ports in either direction.
fs::path find_pasta();                       // throws if missing
inline constexpr const char* kPastaDns = "192.0.2.53";   // RFC 5737 TEST-NET-1: intercepted by pasta --dns-forward
std::string pasta_resolv_conf();             // /etc/resolv.conf for the sandbox
Strings pasta_argv(const fs::path& pasta, const Strings& inner);

// Runs argv in the foreground, forwarding SIGTERM/SIGHUP, returns the exit code.
int run_with_signals(const Strings& argv);

}  // namespace hf
