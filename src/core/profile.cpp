#include "core/profile.hpp"

#include <regex>

#include "core/datadefs.hpp"
#include "core/ini.hpp"
#include "util/sys.hpp"

namespace hf {

namespace {

using Line = IniLine;

bool as_bool(const Line& l, const std::string& origin) {
    std::string v = lower(l.value);
    if (v == "true" || v == "yes" || v == "1" || v == "on") return true;
    if (v == "false" || v == "no" || v == "0" || v == "off") return false;
    throw ProfileError(cat(origin, ":", l.no, ": '", l.key, "' expects a boolean"));
}

[[noreturn]] void bad(const Line& l, const std::string& origin, const std::string& why) {
    throw ProfileError(cat(origin, ":", l.no, ": [", l.section, "] ", l.key, ": ", why));
}

MountSpec parse_mount(const Line& l, bool rw, bool optional) {
    MountSpec m;
    m.rw = rw; m.optional = optional;
    auto pos = l.value.find("=>");
    if (pos == std::string::npos) {
        m.src = trim(l.value);
    } else {
        m.src = trim(l.value.substr(0, pos));
        m.dst = trim(l.value.substr(pos + 2));
    }
    if (m.src.empty()) throw ProfileError(cat("line ", l.no, ": empty mount source"));
    return m;
}

void append_words(Strings& dst, const std::string& v) { for (auto& w : split_ws(v)) dst.push_back(w); }

}  // namespace

Profile parse_profile(const std::string& text, const std::string& o) {
    Profile p;
    for (const Line& l : parse_ini(text, o)) {
        const std::string &s = l.section, &k = l.key, &v = l.value;
        if (s == "profile") {
            if (k == "name") p.name = v;
            else if (k == "description") p.description = v;
            else if (k == "mode") {
                if (lower(v) == "host") p.root = RootMode::Host;
                else if (lower(v) == "bundle") p.root = RootMode::Bundle;
                else bad(l, o, "expected host|bundle");
            }
            else if (k == "command") p.command = split_words(v);
            else if (k == "hostname") p.hostname = v;
            else if (k == "os") {
                if (!valid_data_name(v)) bad(l, o, "expected an os name (data/os/NAME.os)");
                p.os = v;
            }
            else if (k == "new_session") p.new_session = as_bool(l, o);
            else if (k == "disable_userns") p.disable_userns = as_bool(l, o);
            else if (k == "terminal") {
                std::string x = lower(v);
                if (x == "filter") p.terminal = TermMode::Filter;
                else if (x == "passthrough") p.terminal = TermMode::Passthrough;
                else bad(l, o, "expected filter|passthrough");
            }
            else if (k == "seccomp") {
                if (v.empty()) bad(l, o, "expected default|none|/path/to/filter.bpf");
                p.seccomp = v;
            }
            else if (k == "cwd") {
                std::string x = lower(v);
                if (x == "none") p.cwd = CwdMode::None;
                else if (x == "ask") p.cwd = CwdMode::Ask;
                else if (x == "yes") p.cwd = CwdMode::Yes;
                else bad(l, o, "expected none|ask|yes");
            }
            else if (k == "cwd_dest") p.cwd_dest = v;
            else bad(l, o, "unknown key");
        } else if (s == "bin") {
            if (k == "allow") append_words(p.bins, v); else bad(l, o, "unknown key");
        } else if (s == "fs") {
            if (k == "ro") p.mounts.push_back(parse_mount(l, false, false));
            else if (k == "ro_try") p.mounts.push_back(parse_mount(l, false, true));
            else if (k == "rw") p.mounts.push_back(parse_mount(l, true, false));
            else if (k == "rw_try") p.mounts.push_back(parse_mount(l, true, true));
            else if (k == "tmpfs") p.tmpfs.push_back(v);
            else if (k == "deny") p.extra_deny.push_back(v);
            else if (k == "defaults") p.fs_defaults = as_bool(l, o);
            else if (k == "libs") {
                std::string x = lower(v);
                if (x == "minimal") p.libs = LibsMode::Minimal;
                else if (x == "full") p.libs = LibsMode::Full;
                else bad(l, o, "expected minimal|full (the old yes|no is gone)");
            }
            else bad(l, o, "unknown key");
        } else if (s == "libs") {
            if (k == "use") {
                Strings names;
                append_words(names, v);
                for (auto& n : names) if (!valid_data_name(n)) bad(l, o, "invalid lib name: " + n);
                p.lib_use.insert(p.lib_use.end(), names.begin(), names.end());
            }
            else if (k == "bind") bad(l, o, "concrete paths no longer live in profiles: name the libs you need with `use = ...`; "
                                            "the per-OS paths are generated into data/os/*.os by `holdfast libs`");
            else bad(l, o, "unknown key");
        } else if (s == "home") {
            if (k == "user") p.fake_user = v;
            else if (k == "dirs") append_words(p.home_dirs, v);
            else if (k == "bind") p.home_binds.push_back(parse_mount(l, true, false));
            else if (k == "ro_bind") p.home_binds.push_back(parse_mount(l, false, false));
            else bad(l, o, "unknown key");
        } else if (s == "env") {
            if (k == "set") {
                auto eq = v.find('=');
                if (eq == std::string::npos || eq == 0) bad(l, o, "expected NAME=VALUE");
                p.env_set.emplace_back(trim(v.substr(0, eq)), v.substr(eq + 1));
            }
            else if (k == "pass") append_words(p.env_pass, v);
            else if (k == "unset") append_words(p.env_unset, v);
            else bad(l, o, "unknown key");
        } else if (s == "network") {
            if (k == "mode") {
                std::string x = lower(v);
                if (x == "none") p.net = NetMode::None;
                else if (x == "host") p.net = NetMode::Host;
                else if (x == "pasta") p.net = NetMode::Pasta;
                else if (x == "ivpn" || x == "wireguard") p.net = NetMode::Ivpn;
                else bad(l, o, "expected none|pasta|host|ivpn");
            }
            else if (k == "wg_conf") p.wg_conf = v;
            else if (k == "ns_name") p.ns_name = v;
            else if (k == "verify") p.net_verify = as_bool(l, o);
            else if (k == "subnet") {
                try { p.subnet_octet = std::stoi(v); } catch (...) { bad(l, o, "expected 1..254"); }
                if (p.subnet_octet < 1 || p.subnet_octet > 254) bad(l, o, "expected 1..254");
            }
            else bad(l, o, "unknown key");
        } else if (s == "display") {
            if (k == "mode") {
                std::string x = lower(v);
                if (x == "none") p.display = DisplayMode::None;
                else if (x == "host") p.display = DisplayMode::Host;
                else if (x == "xephyr") p.display = DisplayMode::Xephyr;
                else bad(l, o, "expected none|host|xephyr");
            }
            else if (k == "size") p.display_size = v;
            else if (k == "wm") p.wm = v;
            else if (k == "allow_host_x11") p.allow_host_x11 = as_bool(l, o);
            else if (k == "xauth") p.xauth = as_bool(l, o);
            else bad(l, o, "unknown key");
        } else if (s == "audio") {
            if (k == "mode") {
                std::string x = lower(v);
                if (x == "none") p.audio = false;
                else if (x == "pulse") p.audio = true;
                else bad(l, o, "expected none|pulse");
            } else bad(l, o, "unknown key");
        } else if (s == "clipboard") {
            if (k == "mode") {
                std::string x = lower(v);
                if (x == "none") p.clipboard_out = false;
                else if (x == "out") p.clipboard_out = true;
                else bad(l, o, "expected none|out");
            }
            else if (k == "path") p.clipboard_path = v;
            else if (k == "sanitize") p.clipboard_sanitize = as_bool(l, o);
            else bad(l, o, "unknown key");
        } else if (s == "git") {
            if (k == "protect") p.git_protect = as_bool(l, o); else bad(l, o, "unknown key");
        } else if (s == "fonts") {
            if (k == "allow") append_words(p.font_families, v); else bad(l, o, "unknown key");
        } else if (s == "bundle") {
            if (k == "provision") p.provision.push_back(v);
            else if (k == "id" || k == "alpine_version" || k == "alpine_mirror" || k == "alpine_sha256" || k == "packages")
                bad(l, o, "moved out of profiles: declare the OS setup once in data/os/NAME.os (kind = bundle) and set [profile] os = NAME");
            else bad(l, o, "unknown key");
        } else {
            throw ProfileError(cat(o, ":", l.no, ": unknown section [", s, "]"));
        }
    }
    return p;
}

Profile load_profile_file(const fs::path& path) {
    Profile p = parse_profile(read_file(path), path.string());
    if (p.name.empty()) p.name = path.stem().string();
    static const std::regex ok("^[a-z0-9][a-z0-9_-]{0,31}$");
    if (!std::regex_match(p.name, ok))
        throw ProfileError(path.string() + ": profile name must match [a-z0-9][a-z0-9_-]{0,31}");
    return p;
}

fs::path find_profile(const std::string& n, const std::string& home) {
    if (n.find('/') != std::string::npos || (n.size() > 8 && n.substr(n.size() - 8) == ".profile")) {
        if (!fs::is_regular_file(n)) throw Error("profile not found: " + n);
        return n;
    }
    Strings cands;
    if (const char* e = std::getenv("HOLDFAST_PROFILES")) cands.push_back(cat(e, "/", n, ".profile"));
    cands.push_back(cat(home, "/.config/holdfast/profiles/", n, ".profile"));
    cands.push_back(cat("/etc/holdfast/profiles/", n, ".profile"));
    for (const auto& r : data_roots(home)) cands.push_back(cat(r, "/profile/", n, ".profile"));   // shipped/shared data dirs
    for (auto& c : cands) if (fs::is_regular_file(c)) return c;
    throw Error(cat("profile '", n, "' not found; searched:\n  ", join(cands, "\n  ")));
}

}  // namespace hf
