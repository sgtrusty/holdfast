// holdfast - turns (Profile + runtime Context) into a bwrap argument vector
#pragma once
#include "core/argbuilder.hpp"
#include "core/paths.hpp"
#include "core/profile.hpp"

namespace hf {

struct DisplayInfo {
    std::string display;   // ":90"
    fs::path socket;       // /tmp/.X11-unix/X90
    fs::path authfile;     // MIT-MAGIC-COOKIE file (may be empty)
    bool host = false;
};

struct PlanCtx {
    User user;
    Paths paths;
    const Policy* policy = nullptr;
    fs::path session;                 // per-run private dir (0700)
    fs::path cwd;                     // resolved working tree
    bool mount_cwd = false;
    std::optional<DisplayInfo> display;
    Strings command_override;
    bool userns_disable_supported = false;
    bool network = false;             // sandbox shares a (possibly netns-restricted) network
};

struct Plan {
    ArgBuilder b;
    fs::path seccomp;                 // optional BPF file for the launcher
};

Plan build_plan(const Profile& p, const PlanCtx& c);

// Every `.git` (directory OR file, as in worktrees/submodules) below root.
// Does not descend into matches.
std::vector<fs::path> find_git_entries(const fs::path& root, size_t cap = 100000);

// DejaVu/Liberation-style font subsetting: returns matching font files.
Strings match_font_files(const fs::path& fonts_root, const Strings& families, size_t cap = 600);

// X11 MIT-MAGIC-COOKIE-1 authority file with a FamilyWild entry, so it matches
// regardless of the sandbox's (unshared) hostname.
void write_xauth(const fs::path& file, const std::string& display_num, const std::string& cookie16);

}  // namespace hf
