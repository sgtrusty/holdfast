#include "core/datadefs.hpp"

#include <algorithm>
#include <functional>
#include <regex>
#include <set>

#include "core/ini.hpp"
#include "util/log.hpp"
#include "util/sys.hpp"

#ifndef HOLDFAST_SHARE_DIR
#define HOLDFAST_SHARE_DIR "/opt/holdfast"
#endif

namespace hf {

namespace {

[[noreturn]] void bad(const IniLine& l, const std::string& o, const std::string& why) {
    throw ProfileError(cat(o, ":", l.no, ": [", l.section, "] ", l.key, ": ", why));
}

void words(Strings& dst, const std::string& v) { for (auto& w : split_ws(v)) dst.push_back(w); }

}  // namespace

bool valid_data_name(const std::string& n) {
    static const std::regex ok("^[a-z0-9][a-z0-9._-]{0,63}$");
    return std::regex_match(n, ok);
}

bool is_exact_alpine_release(const std::string& v, std::string* branch) {
    static const std::regex re(R"(v?([0-9]+\.[0-9]+)\.[0-9]+)");
    std::smatch m;
    if (!std::regex_match(v, m, re)) return false;
    if (branch) *branch = "v" + m[1].str();
    return true;
}

Strings data_roots(const std::string& home) {
    Strings r;
    if (const char* e = std::getenv("HOLDFAST_DATA"); e && *e) r.push_back(e);
    if (const char* e = std::getenv("HOLDFAST_SHARE"); e && *e) r.push_back(std::string(e) + "/data");
    if (!home.empty()) r.push_back(home + "/.config/holdfast/data");
    r.push_back("/etc/holdfast/data");
    // The data that ships with holdfast sits next to the binary: <prefix>/bin/holdfast -> <prefix>/data. That is
    // /opt/holdfast after `predep install`, and the checkout itself when you run ./bin/holdfast from a clone. The path
    // comes from /proc/self/exe, so a symlink on PATH (e.g. /usr/local/bin/holdfast) still finds it.
    std::error_code ec;
    const fs::path exe = fs::read_symlink("/proc/self/exe", ec);
    if (!ec) {
        const fs::path shipped = exe.parent_path().parent_path() / "data";
        if (fs::is_directory(shipped, ec)) r.push_back(shipped.string());
    }
    const std::string installed = std::string(HOLDFAST_SHARE_DIR) + "/data";
    if (std::find(r.begin(), r.end(), installed) == r.end()) r.push_back(installed);
    return r;
}

LibDef parse_lib(const std::string& text, const std::string& origin, const std::string& name) {
    LibDef d;
    d.name = name;
    for (const IniLine& l : parse_ini(text, origin)) {
        if (l.section != "lib") throw ProfileError(cat(origin, ":", l.no, ": unknown section [", l.section, "]"));
        if (l.key == "name") {
            if (l.value != name) bad(l, origin, "must match the file name (" + name + ")");
        } else if (l.key == "description") {
            d.description = l.value;
        } else if (l.key == "commands") {
            Strings v; words(v, l.value);
            for (auto& c : v) if (c.find('/') != std::string::npos) bad(l, origin, "command names have no '/': " + c);
            d.commands.insert(d.commands.end(), v.begin(), v.end());
        } else if (l.key == "sonames") {
            Strings v; words(v, l.value);
            for (auto& c : v) if (c.find('/') != std::string::npos) bad(l, origin, "sonames have no '/': " + c);
            d.sonames.insert(d.sonames.end(), v.begin(), v.end());
        } else if (l.key == "paths") {
            Strings v; words(v, l.value);
            for (auto& c : v) if (!fs::path(c).is_absolute()) bad(l, origin, "paths must be absolute: " + c);
            d.paths.insert(d.paths.end(), v.begin(), v.end());
        } else if (l.key == "needs") {
            Strings v; words(v, l.value);
            for (auto& c : v) if (!valid_data_name(c)) bad(l, origin, "invalid lib name: " + c);
            d.needs.insert(d.needs.end(), v.begin(), v.end());
        } else {
            bad(l, origin, "unknown key");
        }
    }
    return d;
}

OsDef parse_os(const std::string& text, const std::string& origin, const std::string& name) {
    OsDef o;
    o.name = name;
    bool kind_seen = false;
    const std::vector<IniLine> lines = parse_ini(text, origin);
    for (const IniLine& l : lines)                                  // kind first: it decides which keys are legal
        if (l.section == "os" && l.key == "kind") {
            if (lower(l.value) == "host") o.kind = OsKind::Host;
            else if (lower(l.value) == "bundle") o.kind = OsKind::Bundle;
            else bad(l, origin, "expected host|bundle");
            kind_seen = true;
        }
    if (!kind_seen) throw ProfileError(origin + ": [os] kind = host|bundle is required");
    for (const IniLine& l : lines) {
        if (l.section == "os") {
            if (l.key == "kind") continue;
            if (l.key == "name") {
                if (l.value != name) bad(l, origin, "must match the file name (" + name + ")");
            } else if (l.key == "description") {
                o.description = l.value;
            } else if (o.kind == OsKind::Host && l.key == "id") {
                o.id = lower(l.value);
            } else if (o.kind == OsKind::Host && l.key == "version") {
                o.version = l.value;
            } else if (o.kind == OsKind::Bundle && l.key == "alpine_version") {
                o.alpine_version = l.value;
            } else if (o.kind == OsKind::Bundle && l.key == "alpine_mirror") {
                o.alpine_mirror = l.value;
            } else if (o.kind == OsKind::Bundle && l.key == "alpine_sha256") {
                o.alpine_sha256 = lower(l.value);
                if (!is_hex(o.alpine_sha256, 64)) bad(l, origin, "must be 64 hex chars");
            } else if (o.kind == OsKind::Bundle && l.key == "packages") {
                words(o.packages, l.value);
            } else {
                bad(l, origin, o.kind == OsKind::Host ? "unknown key for kind = host" : "unknown key for kind = bundle");
            }
        } else if (l.section.rfind("files.", 0) == 0) {
            if (o.kind != OsKind::Host) bad(l, origin, "[files.ARCH.LIB] sections belong to kind = host");
            const std::string rest = l.section.substr(6);
            const auto dot = rest.find('.');
            const std::string arch = rest.substr(0, dot), lib = dot == std::string::npos ? "" : rest.substr(dot + 1);
            static const std::regex arch_ok("^[a-z0-9_]{1,16}$");
            if (!std::regex_match(arch, arch_ok) || !valid_data_name(lib))
                throw ProfileError(cat(origin, ":", l.no, ": section must be [files.ARCH.LIB]"));
            if (l.key != "bind") bad(l, origin, "unknown key (expected bind)");
            if (!fs::path(l.value).is_absolute()) bad(l, origin, "bind must be an absolute path");
            o.files[arch][lib].push_back(l.value);
        } else {
            throw ProfileError(cat(origin, ":", l.no, ": unknown section [", l.section, "]"));
        }
    }
    if (o.kind == OsKind::Host && o.id.empty())
        throw ProfileError(origin + ": [os] id (the /etc/os-release ID) is required for kind = host");
    if (o.kind == OsKind::Bundle) {
        if (!is_exact_alpine_release(o.alpine_version))
            throw ProfileError(origin + ": [os] alpine_version must be an exact release such as 3.24.3 "
                                        "(moving aliases like latest-stable cannot be pinned or shared)");
        if (o.alpine_mirror.rfind("https://", 0) != 0) throw ProfileError(origin + ": [os] alpine_mirror must be an https:// URL");
    }
    return o;
}

DepRecipe parse_dep(const std::string& text, const std::string& origin, const std::string& name) {
    DepRecipe d;
    d.name = name;
    for (const IniLine& l : parse_ini(text, origin)) {
        if (l.section == "dep") {
            if (l.key == "name") {
                if (l.value != name) bad(l, origin, "must match the file name (" + name + ")");
            } else if (l.key == "description") {
                d.description = l.value;
            } else if (l.key == "os") {
                if (!valid_data_name(l.value)) bad(l, origin, "expected an os name (data/os/NAME.profile)");
                d.os = l.value;
            } else if (l.key == "needs") {
                Strings v; words(v, l.value);
                for (auto& c : v) if (c.find('/') != std::string::npos || c.empty()) bad(l, origin, "command names have no '/': " + c);
                d.needs.insert(d.needs.end(), v.begin(), v.end());
            } else {
                bad(l, origin, "unknown key");
            }
        } else if (l.section == "network") {
            if (l.key != "mode") bad(l, origin, "unknown key (expected mode)");
            const std::string m = lower(l.value);
            if (m == "none") d.net = NetMode::None;
            else if (m == "pasta") d.net = NetMode::Pasta;
            else bad(l, origin, "a dep may use none or pasta (host would share abstract sockets, ivpn needs root)");
        } else if (l.section == "install") {
            if (l.key != "run") bad(l, origin, "unknown key (expected run)");
            if (l.value.empty()) bad(l, origin, "empty command");
            d.run.push_back(l.value);
        } else {
            throw ProfileError(cat(origin, ":", l.no, ": unknown section [", l.section, "]"));
        }
    }
    if (d.os.empty()) throw ProfileError(origin + ": [dep] os = NAME is required: a tool is built for one userland (musl vs glibc), so say which");
    if (d.run.empty()) throw ProfileError(origin + ": [install] needs at least one `run = ...` line");
    d.digest = sha256_str(cat(d.os, "|", d.net == NetMode::Pasta ? "pasta" : "none", "|", join(d.needs, " "), "|", join(d.run, "\n")));
    return d;
}

DisplayDef parse_display(const std::string& text, const std::string& origin, const std::string& name) {
    DisplayDef d;
    d.name = name;
    bool have_server = false, size_set = false, xauth_set = false;
    for (const IniLine& l : parse_ini(text, origin)) {
        if (l.section != "display") throw ProfileError(cat(origin, ":", l.no, ": unknown section [", l.section, "]"));
        if (l.key == "name") {
            if (l.value != name) bad(l, origin, "must match the file name (" + name + ")");
        } else if (l.key == "description") {
            d.description = l.value;
        } else if (l.key == "server") {
            const std::string x = lower(l.value);
            if (x == "xephyr") { d.protocol = DisplayProtocol::X11; d.mode = DisplayMode::Nested; }
            else if (x == "host") d.mode = DisplayMode::Host;      // protocol follows your session: see display::effective_protocol
            else bad(l, origin, "expected xephyr|host (no display at all = leave `use` out of the profile)");
            have_server = true;
        } else if (l.key == "protocol" || l.key == "mode") {
            bad(l, origin, "replaced by `server = xephyr|host`: Xephyr is X11, and host uses whatever your session runs");
        } else if (l.key == "size") {
            d.size = l.value;
            size_set = true;
        } else if (l.key == "xauth") {
            const std::string x = lower(l.value);
            if (x == "yes" || x == "true" || x == "on" || x == "1") d.xauth = true;
            else if (x == "no" || x == "false" || x == "off" || x == "0") d.xauth = false;
            else bad(l, origin, "expected yes|no");
            xauth_set = true;
        } else if (l.key == "wm") {
            d.wm = l.value;
        } else {
            bad(l, origin, "unknown key");
        }
    }
    if (!have_server) throw ProfileError(origin + ": [display] server = xephyr|host is required");
    const bool x11_nested = d.mode == DisplayMode::Nested;
    if (!x11_nested && (size_set || xauth_set || !d.wm.empty()))
        throw ProfileError(origin + ": size, xauth and wm configure Xephyr (server = xephyr); your host session has its own, and Wayland has no window manager to start");
    static const std::regex size_ok(R"(^\d{3,5}x\d{3,5}$)");
    if (x11_nested && !std::regex_match(d.size, size_ok)) throw ProfileError(origin + ": size must look like 1280x800");
    return d;
}

std::optional<fs::path> find_data(const Strings& roots, const std::string& kind, const std::string& name) {
    if (!valid_data_name(name)) return std::nullopt;
    for (const auto& r : roots) {                       // the directory (profile/ lib/ os/) says what a file is; the extension is always .profile
        fs::path f = fs::path(r) / kind / (name + ".profile");
        std::error_code ec;
        if (fs::is_regular_file(f, ec)) return f;
    }
    return std::nullopt;
}

LibDef load_lib(const std::string& name, const Strings& roots) {
    auto f = find_data(roots, "lib", name);
    if (!f) throw ProfileError(cat("lib '", name, "' not found; create data/lib/", name, ".profile (searched: ", join(roots, ", "), ")"));
    LibDef d = parse_lib(read_file(*f), f->string(), name);
    d.file = *f;
    return d;
}

DepRecipe load_dep(const std::string& name, const Strings& roots) {
    auto f = find_data(roots, "dep", name);
    if (!f) throw ProfileError(cat("dep '", name, "' not found; create data/dep/", name, ".profile (searched: ", join(roots, ", "), ")"));
    return parse_dep(read_file(*f), f->string(), name);
}

DisplayDef load_display(const std::string& name, const Strings& roots) {
    auto f = find_data(roots, "display", name);
    if (!f) throw ProfileError(cat("display '", name, "' not found; create data/display/", name, ".profile (searched: ", join(roots, ", "), ")"));
    return parse_display(read_file(*f), f->string(), name);
}

OsDef load_os(const std::string& name, const Strings& roots) {
    auto f = find_data(roots, "os", name);
    if (!f) throw ProfileError(cat("os '", name, "' not found; create data/os/", name, ".profile (searched: ", join(roots, ", "), ")"));
    OsDef o = parse_os(read_file(*f, 16u << 20), f->string(), name);
    o.file = *f;
    return o;
}

Strings list_data(const Strings& roots, const std::string& kind) {
    std::set<std::string> names;
    for (const auto& r : roots) {
        std::error_code ec;
        for (fs::directory_iterator it(fs::path(r) / kind, ec), end; !ec && it != end; it.increment(ec))
            if (it->path().extension() == ".profile" && valid_data_name(it->path().stem().string())) names.insert(it->path().stem().string());
    }
    return Strings(names.begin(), names.end());
}

HostId read_host_id(const fs::path& path) {
    HostId h;
    std::string text;
    try { text = read_file(path); } catch (const Error&) { return h; }
    std::istringstream in(text);
    for (std::string raw; std::getline(in, raw);) {
        const auto eq = raw.find('=');
        if (eq == std::string::npos) continue;
        std::string k = trim(raw.substr(0, eq)), v = trim(raw.substr(eq + 1));
        if (v.size() >= 2 && (v.front() == '"' || v.front() == '\'') && v.back() == v.front()) v = v.substr(1, v.size() - 2);
        if (k == "ID") h.id = lower(v);
        else if (k == "VERSION_ID") h.version = v;
    }
    return h;
}

std::string suggest_os_name(const HostId& h) {
    std::string n = h.id.empty() ? "linux" : h.id;
    if (!h.version.empty()) n += "-" + h.version;
    for (char& c : n) if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_')) c = '-';
    return lower(n);
}

std::optional<OsDef> match_host_os(const Strings& roots, const HostId& h) {
    std::optional<OsDef> best;
    for (const std::string& n : list_data(roots, "os")) {
        OsDef o;
        try { o = load_os(n, roots); } catch (const Error& e) { log::warn(cat("skipping os '", n, "': ", e.what())); continue; }
        if (o.kind != OsKind::Host || o.id != h.id) continue;
        const bool version_ok = o.version.empty() || h.version == o.version || h.version.rfind(o.version + ".", 0) == 0;
        if (!version_ok) continue;
        if (!best || o.version.size() > best->version.size()) best = o;     // most specific version wins
    }
    return best;
}

std::string render_os(const OsDef& o) {
    std::string s = "# Generated by `holdfast libs`; review before committing. Sections are per architecture and per lib;\n"
                    "# regenerate (or verify with `holdfast libs --check`) after OS upgrades.\n"
                    "[os]\nname = " + o.name + "\nkind = host\nid = " + o.id + "\n";
    if (!o.version.empty()) s += "version = " + o.version + "\n";
    if (!o.description.empty()) s += "description = " + o.description + "\n";
    for (const auto& [arch, libs] : o.files)
        for (const auto& [lib, files] : libs) {
            s += "\n[files." + arch + "." + lib + "]\n";
            for (const auto& f : files) s += "bind = " + f + "\n";
        }
    return s;
}

void resolve_profile_data(Profile& p, const Strings& roots) {
    // The display first: every profile has one (or none), and the paths below return early.
    if (p.display_use.empty()) p.display.reset();
    else p.display = load_display(p.display_use, roots);
    if (p.root == RootMode::Bundle) {
        if (p.os.empty())
            throw ProfileError(cat("bundle profile '", p.name, "' needs [profile] os = NAME (a kind = bundle file in data/os/)"));
        OsDef o = load_os(p.os, roots);
        if (o.kind != OsKind::Bundle) throw ProfileError(cat("os '", p.os, "' is a host OS definition; a bundle profile needs kind = bundle"));
        p.alpine_version = o.alpine_version;
        p.alpine_mirror = o.alpine_mirror;
        p.alpine_sha256 = o.alpine_sha256;
        p.apk_packages = o.packages;
        p.bundle_id = o.name;                       // every profile naming this os shares one userland
        std::set<std::string> seen_dep;
        p.deps.clear();
        for (const auto& n : p.dep_use) {
            if (!seen_dep.insert(n).second) continue;
            p.deps.push_back(load_dep(n, roots));
            if (p.deps.back().os != p.os)                       // binaries built for another userland would not run here
                throw ProfileError(cat("dep '", n, "' is built for os '", p.deps.back().os, "' but profile '", p.name, "' uses os '", p.os,
                                       "'; use a dep for '", p.os, "' or change the profile's os"));
        }
        return;
    }
    if (!p.dep_use.empty())
        throw ProfileError(cat("[deps] use needs mode = bundle: a host-mode profile has no writable userland to install into (profile '", p.name, "')"));
    if (p.libs == LibsMode::Full) {
        if (!p.lib_use.empty()) log::warn("[libs] use is ignored with libs = full");
        return;
    }
    if (p.bins.empty()) return;

    // closure of [libs] use over `needs`; `base` (loader, libc, NSS, locales) is always part of it
    std::vector<LibDef> libs;
    std::set<std::string> seen;
    std::function<void(const std::string&)> add = [&](const std::string& n) {
        if (!seen.insert(n).second) return;
        libs.push_back(load_lib(n, roots));
        const Strings deps = libs.back().needs;     // copy: `libs` may reallocate during the recursion
        for (const auto& dep : deps) add(dep);
    };
    add("base");
    for (const auto& n : p.lib_use) add(n);

    std::set<std::string> provided;
    for (const auto& l : libs) provided.insert(l.commands.begin(), l.commands.end());
    for (const std::string& tok : p.bins) {
        const std::string name = tok.substr(0, tok.find('='));
        if (!provided.count(name))
            throw ProfileError(cat("[bin] allow '", name, "' is not provided by any lib in [libs] use (", join(p.lib_use, " "),
                                   "); add the lib that lists it (data/lib/*.profile), define one, or set `libs = full` in [fs]"));
    }

    OsDef os;
    if (!p.os.empty()) {
        os = load_os(p.os, roots);
        if (os.kind != OsKind::Host) throw ProfileError(cat("os '", p.os, "' is a bundle definition; host profiles need kind = host"));
    } else {
        const HostId h = read_host_id();
        auto m = match_host_os(roots, h);
        if (!m)
            throw ProfileError(cat("no data/os definition matches this host (", h.id, " ", h.version,
                                   "); create one with: HOLDFAST_DATA=<your data dir> holdfast libs --refresh ", suggest_os_name(h),
                                   "   (or set `libs = full` in [fs])"));
        os = *m;
    }
    const std::string arch = host_arch();
    auto by_arch = os.files.find(arch);
    Strings all;
    for (const auto& l : libs) {
        if (by_arch == os.files.end() || !by_arch->second.count(l.name))
            throw ProfileError(cat("os '", os.name, "' has no file list for lib '", l.name, "' on ", arch,
                                   "; scan this system and save it: holdfast libs --refresh ", os.name));
        const Strings& v = by_arch->second.at(l.name);
        all.insert(all.end(), v.begin(), v.end());
    }
    std::sort(all.begin(), all.end());
    all.erase(std::unique(all.begin(), all.end()), all.end());
    p.lib_binds = all;
}

}  // namespace hf
