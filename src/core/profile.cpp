#include "core/profile.hpp"

#include <regex>

#include "util/sys.hpp"

namespace hf {

namespace {

struct Line { std::string section, key, value; int no; };

std::vector<Line> parse_ini(const std::string& text, const std::string& origin) {
    std::vector<Line> out;
    std::stringstream ss(text);
    std::string raw, section;
    int no = 0;
    while (std::getline(ss, raw)) {
        ++no;
        std::string l = trim(raw);
        if (l.empty() || l[0] == '#' || l[0] == ';') continue;
        if (l.front() == '[') {
            if (l.back() != ']') throw ProfileError(cat(origin, ":", no, ": malformed section header"));
            section = lower(trim(l.substr(1, l.size() - 2)));
            continue;
        }
        auto eq = l.find('=');
        if (eq == std::string::npos) throw ProfileError(cat(origin, ":", no, ": expected key = value"));
        if (section.empty()) throw ProfileError(cat(origin, ":", no, ": key outside any section"));
        std::string val = l.substr(eq + 1);
        // Inline comment: whitespace followed by '#'. (A '#' glued to text is data.)
        for (size_t i = 0; i + 1 < val.size(); ++i)
            if (std::isspace(static_cast<unsigned char>(val[i])) && val[i + 1] == '#') { val.erase(i); break; }
        out.push_back({section, lower(trim(l.substr(0, eq))), trim(val), no});
    }
    return out;
}

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
            else if (k == "new_session") p.new_session = as_bool(l, o);
            else if (k == "disable_userns") p.disable_userns = as_bool(l, o);
            else if (k == "seccomp") p.seccomp = v;
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
            else if (k == "libs") p.libs = as_bool(l, o);
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
                else if (x == "ivpn" || x == "wireguard") p.net = NetMode::Ivpn;
                else bad(l, o, "expected none|host|ivpn");
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
            if (k == "alpine_version") p.alpine_version = v;
            else if (k == "alpine_mirror") p.alpine_mirror = v;
            else if (k == "alpine_sha256") p.alpine_sha256 = lower(v);
            else if (k == "packages") append_words(p.apk_packages, v);
            else if (k == "provision") p.provision.push_back(v);
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
    if (!p.alpine_sha256.empty() && !is_hex(p.alpine_sha256, 64))
        throw ProfileError(path.string() + ": [bundle] alpine_sha256 must be 64 hex chars");
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
    for (auto& c : cands) if (fs::is_regular_file(c)) return c;
    throw Error(cat("profile '", n, "' not found; searched:\n  ", join(cands, "\n  ")));
}

}  // namespace hf
