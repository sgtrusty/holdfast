// holdfast - declarative sandbox profile (INI-style, strict: unknown keys fail)
#pragma once
#include <map>
#include <utility>

#include "util/common.hpp"

namespace hf {

enum class RootMode { Host, Bundle };
enum class NetMode { None, Host, Pasta, Ivpn };
enum class LibsMode { Minimal, Full };
enum class TermMode { Filter, Passthrough };
enum class DisplayProtocol { X11, Wayland };       // which display protocol the sandboxed program speaks
enum class DisplayMode { Host, Nested };           // the host's display server (explicit opt-in) | a private one (X11: Xephyr)
enum class CwdMode { None, Ask, Yes };

struct MountSpec {
    std::string src;       // may contain $VARS / globs, expanded at plan time
    std::string dst;       // empty => same as (expanded) src
    bool rw = false;
    bool optional = false; // skip silently when src is missing
};

// data/dep/NAME.profile: one install step for a bundle profile (a tool built or fetched into the profile's $HOME).
// It runs as an ordinary run of the profile that uses it; everything it needs differently is declared here.
struct DepRecipe {
    std::string name, description;
    std::string os;                // the userland it is built for; the using profile must name the same os
    NetMode net = NetMode::None;   // [network] mode: none (default) or pasta
    Strings needs;                 // commands that must already exist in the userland (its packages come from data/os)
    Strings run;                   // shell lines (and run_file contents), in order; holdfast does not expand variables in them
    Strings fetch;                 // URL SHA256 DEST triples, flattened; each `fetch` step in `run` consumes one triple
    Strings provides;              // paths relative to $HOME that must exist once installed (missing => the dep is due again)
    std::string digest;            // hash of os+net+needs+run+fetch: a changed recipe is detected, never silently re-run
};

// data/display/NAME.profile: what a display IS. A sandbox profile only says `[display] use = NAME`; X11 specifics (Xephyr, its
// size and cookie, the window manager) and Wayland specifics live here, so the sandbox profile does not care which protocol it gets.
struct DisplayDef {
    std::string name, description;
    DisplayProtocol protocol = DisplayProtocol::X11;
    DisplayMode mode = DisplayMode::Nested;
    // x11 + nested only (the parser rejects them elsewhere): Wayland has no server/window-manager split and no cookie file.
    std::string size = "1280x800";
    bool xauth = true;
    std::string wm;                // shell snippet started in the sandbox before the program; X needs a separate window manager
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
    std::string dns;               // [network] dns: IPv4 resolver (pasta: forwarded to; host: written to resolv.conf) or "host" (mode host)
    std::string wg_conf, ns_name;
    bool net_verify = true;
    int subnet_octet = 0;          // 0 => derived from ns name

    // [display]
    std::string display_use;       // [display] use = NAME: a data/display profile; empty = no display
    bool allow_host_display = false;   // [display] allow_host: consent when that display is mode = host (it hands over your real session)
    std::optional<DisplayDef> display;   // NOT parsed: resolve_profile_data() fills it from display_use

    // [audio] [clipboard] [git] [fonts]
    bool audio = false;
    bool clipboard_out = false;
    bool clipboard_sanitize = true;   // strip control chars before the text reaches the host clipboard
    std::string clipboard_path = "/tmp/clip_pipe";
    bool git_protect = true;
    Strings font_families;

    // [deps] use: the data/dep recipes installed into this profile's persistent $HOME (bundle mode only).
    Strings dep_use;


    // Everything below is NOT parsed from the profile: resolve_profile_data() fills it from the profile's data/os file
    // (bundle kind) and its data/dep recipes, so one OS setup and each install step are declared exactly once.
    std::string bundle_id;         // = the os name; every profile naming the same os shares one userland
    std::string alpine_version;
    std::string alpine_mirror = "https://dl-cdn.alpinelinux.org/alpine";
    std::string alpine_sha256;     // optional pin of the minirootfs tarball
    Strings apk_packages;
    NetMode install_net = NetMode::Pasta;   // the os file's [install]: network of the fetch and apk sandboxes
    std::string install_dns;       // its dns: required when an install step (fetch, apk, a pasta dep) uses the network
    Strings install_use;           // its use: the data/lib names the bootstrap may mount from the host
    std::vector<DepRecipe> deps;   // in `use` order
    Strings roots;                 // NOT parsed: the data roots resolve_profile_data() used (the bootstrap resolves [install] use with them)
};

Profile parse_profile(const std::string& text, const std::string& origin);
// pasta needs an IPv4 dns; host needs an IPv4 dns or `host`; none/ivpn take none. Re-checked after --net/--dns overrides.
void check_dns(const Profile& p, const std::string& origin);
// Reads a profile file. Fails closed on unknown keys and sections.
Profile load_profile_file(const fs::path& p);
// Resolve "name" or a path to a profile file.
// A path (contains '/' or ends in .profile) is used as is; a name is <data root>/profile/NAME.profile, first root wins.
// `extra` roots (--data, searched first) come before data_roots(home).
fs::path find_profile(const std::string& name_or_path, const std::string& home, const Strings& extra = {});
// Folders older versions searched ($HOLDFAST_PROFILES, ~/.config/holdfast/profiles, /etc/holdfast/profiles): only checked
// so a profile left there is an error that says where to move it, never silently ignored.
Strings legacy_profile_dirs(const std::string& home);

}  // namespace hf
