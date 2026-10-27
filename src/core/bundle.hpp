// holdfast - "bundle" userland: a private Alpine minirootfs, shared by every profile that names the same `os`
//
// There is no bundle command. Running a bundle profile sets the userland up on first use, and everything that
// touches the downloaded bytes (fetch, hash check, extraction, cleanup, `apk add`, your data/dep recipes) runs
// inside sandboxes. The result is plain folders under the data dir (<data>/bundles/<os>/, <data>/profiles/<name>/)
// that you can open, edit or delete yourself.
#pragma once
#include "core/launch.hpp"
#include "core/paths.hpp"

namespace hf {

std::string alpine_arch();
std::string bundle_spec(const Profile& p);   // what must match for profiles that share an os: version, mirror, sha256, packages
std::string dep_stamp(const Profile& p, const DepRecipe& d);   // recorded per profile and dep once the recipe ran

// A dep is an ordinary run of the profile that uses it: same userland (read-only), same persistent $HOME, same fake
// identity (your uid, not root), same seccomp filter and terminal filter, all produced by the normal profile code.
// What differs is exactly this, and nothing is added behind your back:
//   network = the recipe's [network] mode (none if it says nothing), not the profile's own
//   command = the recipe's script (passed through RunOptions by bundle_ensure)
//   no working tree, display, audio, clipboard, wm or nested deps: an install step needs none of them
Profile dep_profile(const Profile& p, const DepRecipe& d);
bool bundle_installed(const Paths& paths);
// Fail closed: the installed userland must have been built from exactly this profile's data/os definition (and the
// tarball it pins, if any). Throws Error telling you to re-run with --refresh otherwise.
void bundle_verify(const Profile& p, const Paths& paths);

// Makes the userland and the profile's deps ready for `run`, doing only what is out of date:
//   userland missing          -> download, verify, extract (sandboxed), then `apk add` the os packages (sandboxed)
//   definition changed        -> error; `refresh` (holdfast run --refresh) rebuilds it, discarding changes made inside
//   dep never installed       -> run its recipe (sandboxed, writable userland, persistent $HOME, network via pasta)
//   dep recipe changed        -> error; `refresh` runs every dep recipe again
// dry = true (print/check) never downloads or installs: it only verifies what exists.
void bundle_ensure(const Profile& p, const User& u, const Paths& paths, bool refresh, bool dry);

}  // namespace hf
