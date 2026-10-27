// holdfast - declarative sandbox profile (INI-style, strict: unknown keys fail)
#pragma once
#include <utility>

#include "util/common.hpp"

namespace hf {

enum class RootMode { Host, Bundle };
enum class NetMode { None, Host, Pasta, Ivpn };
enum class LibsMode { Minimal, Full };
enum class TermMode { Filter, Passthrough };
enum class DisplayMode { None, Host, Xephyr };
enum class CwdMode { None, Ask, Yes };

struct MountSpec {
    std::string src;       // may contain $VARS / globs, expanded at plan time
    std::string dst;       // empty => same as (expanded) src
    bool rw = false;
    bool optional = false; // skip silently when src is missing
};

struct Profile {
    // [profile]
    std::string name, description;
    RootMode root = RootMode::Host;
    Strings command;
    std::string hostname = "holdfast";
    bool new_session = true;       // only used when the terminal is not proxied (see `terminal`)
    TermMode terminal = TermMode::Filter;   // pty proxy that strips dangerous escape sequences
    bool disable_userns = true;
    std::string os;                // data/os/NAME.os: bundle profiles (required) name their shared userland; host profiles may pin a lock
    std::string seccomp = "default";   // "default" (built-in filter) | "none" | path to a compiled BPF file
    CwdMode cwd = CwdMode::Ask;
    std::string cwd_dest = "/shared";

    // [bin] (host mode)
    Strings bins;                  // "name" or "name=/abs/path"

    // [fs]
    bool fs_defaults = true;
    LibsMode libs = LibsMode::Minimal;
    std::vector<MountSpec> mounts;
    Strings lib_use;               // [libs] use: data/lib/*.lib names this profile needs (libs = minimal)
    Strings lib_binds;             // NOT parsed: filled by resolve_profile_data() from lib_use + the OS lock
    Strings tmpfs;
    Strings extra_deny;

    // [home]
    std::string fake_user = "sandbox";
    Strings home_dirs;
    std::vector<MountSpec> home_binds; // src relative to real $HOME, dst relative to fake home

    // [env]
    std::vector<std::pair<std::string, std::string>> env_set;
    Strings env_pass, env_unset;

    // [network]
    NetMode net = NetMode::None;
    std::string wg_conf, ns_name;
    bool net_verify = true;
    int subnet_octet = 0;          // 0 => derived from ns name

    // [display]
    DisplayMode display = DisplayMode::None;
    std::string display_size = "1280x800";
    std::string wm;                // shell snippet started before the command
    bool allow_host_x11 = false;
    bool xauth = true;

    // [audio] [clipboard] [git] [fonts]
    bool audio = false;
    bool clipboard_out = false;
    bool clipboard_sanitize = true;   // strip control chars before the text reaches the host clipboard
    std::string clipboard_path = "/tmp/clip_pipe";
    bool git_protect = true;
    Strings font_families;

    // [bundle] provision is per profile. Everything else below is NOT parsed from the profile: it comes from
    // the profile's data/os file (bundle kind) via resolve_profile_data(), so one OS setup is declared once.
    std::string bundle_id;         // = the os name; every profile naming the same os shares one userland
    std::string alpine_version;
    std::string alpine_mirror = "https://dl-cdn.alpinelinux.org/alpine";
    std::string alpine_sha256;     // optional pin of the minirootfs tarball
    Strings apk_packages;
    Strings provision;             // shell lines run once inside the bundle (with network)
};

Profile parse_profile(const std::string& text, const std::string& origin);
Profile load_profile_file(const fs::path& p);
// Resolve "name" or a path to a profile file.
fs::path find_profile(const std::string& name_or_path, const std::string& home);

}  // namespace hf
