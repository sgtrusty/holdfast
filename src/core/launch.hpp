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

// Runs argv in the foreground, forwarding SIGTERM/SIGHUP, returns the exit code.
int run_with_signals(const Strings& argv);

}  // namespace hf
