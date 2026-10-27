// holdfast - "bundle" userland: a private Alpine minirootfs, shared by every profile that names the same `os`
//
// There is no bundle command. Running a bundle profile sets the userland up on first use, and everything that
// touches the downloaded bytes (fetch, hash check, extraction, cleanup, `apk add`, your provision lines) runs
// inside sandboxes. The result is plain folders under the data dir (<data>/bundles/<os>/, <data>/profiles/<name>/)
// that you can open, edit or delete yourself.
#pragma once
#include "core/launch.hpp"
#include "core/paths.hpp"

namespace hf {

std::string alpine_arch();
std::string provision_stamp(const Profile& p);
std::string bundle_spec(const Profile& p);   // what must match for profiles that share an os: version, mirror, sha256, packages
bool bundle_installed(const Paths& paths);
// Fail closed: the installed userland must have been built from exactly this profile's data/os definition (and the
// tarball it pins, if any). Throws Error telling you to re-run with --refresh otherwise.
void bundle_verify(const Profile& p, const Paths& paths);
bool bundle_provisioned(const Profile& p, const Paths& paths);

// Makes the userland ready for `run`:
//   not there yet            -> download, verify, extract (sandboxed), then apk add + provision lines (sandboxed)
//   there, definition equal  -> nothing (or only re-provision when the profile's provision lines changed)
//   there, definition differs-> error; `refresh` (holdfast run --refresh) rebuilds it, discarding changes made inside
// dry = true (print/check) never downloads: it only verifies what exists.
void bundle_ensure(const Profile& p, const User& u, const Paths& paths, bool refresh, bool dry);

}  // namespace hf
