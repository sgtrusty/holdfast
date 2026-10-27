// holdfast - turns (Profile + runtime Context) into a bwrap argument vector
#pragma once
#include "core/argbuilder.hpp"
#include "core/paths.hpp"
#include "core/profile.hpp"
#include "protocol/display/display.hpp"

namespace hf {

struct PlanCtx {
    User user;
    Paths paths;
    const Policy* policy = nullptr;
    fs::path session;                 // per-run private dir (0700)
    fs::path cwd;                     // resolved working tree
    bool mount_cwd = false;
    std::optional<hf::display::Setup> display;   // what the display backend gives the sandbox (X11, Wayland, ...); none = no display
    Strings command_override;
    bool userns_disable_supported = false;
    bool network = false;             // sandbox shares a (possibly netns-restricted) network
    bool pty_proxy = false;           // the terminal is proxied through a pty: bwrap must NOT also setsid (--new-session)
    bool pasta = false;               // that network is a pasta namespace (own resolv.conf, uid mapping)
};

struct Plan {
    ArgBuilder b;
    fs::path seccomp;                 // optional BPF file for the launcher
};

Plan build_plan(const Profile& p, const PlanCtx& c);

// The usr-merge symlinks (/lib, /lib64) every ELF's loader path goes through, and with `whole` also the host's
// /usr/lib, /usr/lib64 (and real /lib dirs) read-only. Shared by `libs = full` profiles and the bundle bootstrap sandbox.
void bind_host_library_dirs(ArgBuilder& b, bool whole);

// Every `.git` (directory OR file, as in worktrees/submodules) below root.
// Does not descend into matches.
std::vector<fs::path> find_git_entries(const fs::path& root, size_t cap = 100000);

// DejaVu/Liberation-style font subsetting: returns matching font files.
Strings match_font_files(const fs::path& fonts_root, const Strings& families, size_t cap = 600);


}  // namespace hf
