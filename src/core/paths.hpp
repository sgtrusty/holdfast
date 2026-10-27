// holdfast - on-disk layout, variable expansion, policy
#pragma once
#include <map>

#include "core/profile.hpp"
#include "util/sys.hpp"

namespace hf {

// Persistent layout (all under the target user's data dir, never system-wide):
//   <data>/cache/alpine/<arch>/...      downloaded minirootfs tarballs
//   <data>/bundles/<id>/rootfs          bundle userland, shared by every profile with `[profile] os = <id>`
//   <data>/bundles/<id>/spec.stamp      hash of version|mirror|sha256 the rootfs was built from
//   <data>/bundles/<id>/tarball.sha256  sha256 of the verified minirootfs tarball
//   <data>/profiles/<name>/home         persistent fake $HOME (never shared)
//   <data>/profiles/<name>/provision.stamp
// Ephemeral per-run:
//   <runtime>/holdfast/<name>.<pid>/    passwd, group, hosts, fonts.conf, args, xauth, clip
struct Paths {
    fs::path data, cache, state, bundle, rootfs, home, run_root;
};
// bundle_id empty => the profile name (an unshared bundle).
Paths make_paths(const User& u, const std::string& profile_name, const std::string& bundle_id = "");
fs::path make_session_dir(const User& u, const Paths& p, const std::string& profile_name);

// $VAR expansion. Unknown variables are an error (fail closed).
struct VarCtx {
    const User* user = nullptr;
    const Paths* paths = nullptr;
    fs::path cwd;
    std::map<std::string, std::string> extra;
};
std::string expand(const std::string& s, const VarCtx& c);
// Expand and glob (*, ?, [..]). Returns the pattern itself (expanded) if no glob chars.
Strings expand_glob(const std::string& s, const VarCtx& c);

// ---- policy: blacklist / sensitive-root guard ---------------------------------
class Policy {
public:
    Policy(const User& u, const Strings& extra_deny);
    // Throws PolicyError when binding `src` (read-only or read-write) is forbidden.
    void check_bind(const fs::path& src, bool rw) const;
    // Throws PolicyError when `dir` must never be mounted as the working tree.
    void check_cwd(const fs::path& dir) const;
    const std::vector<fs::path>& deny() const { return deny_; }
    bool is_sensitive_root(const fs::path& p) const;
private:
    User user_;
    std::vector<fs::path> deny_;
};

}  // namespace hf
