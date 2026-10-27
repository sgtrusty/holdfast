// holdfast - "bundle" userland: a private Alpine minirootfs per profile
#pragma once
#include "core/launch.hpp"
#include "core/paths.hpp"

namespace hf {

std::string alpine_arch();
std::string provision_stamp(const Profile& p);
std::string bundle_spec(const Profile& p);   // what must be identical for profiles that share a bundle id
bool bundle_installed(const Paths& paths);
// Fail closed: the installed bundle must have been built from exactly this profile's version/mirror/sha256
// (and the tarball it pins, if any). Throws Error naming the bundle id otherwise.
void bundle_verify(const Profile& p, const Paths& paths);
bool bundle_provisioned(const Profile& p, const Paths& paths);

// Download (cached, sha256-verified) + extract + provision (apk + profile lines).
void bundle_setup(const Profile& p, const User& u, const Paths& paths, const fs::path& session, bool force);
// Writable root shell inside the bundle, with network, for manual maintenance.
int bundle_shell(const Profile& p, const User& u, const Paths& paths, const fs::path& session);
// everything=false: remove only the userland (keeps your persistent fake $HOME).
void bundle_purge(const Paths& paths, bool everything);

}  // namespace hf
