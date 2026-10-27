#include "core/libs_cmd.hpp"

#include <algorithm>
#include <cstdio>
#include <set>

#include "core/datadefs.hpp"
#include "core/libs.hpp"
#include "util/log.hpp"
#include "util/style.hpp"
#include "util/sys.hpp"

namespace hf {

namespace {

// Where `--refresh` writes, always: $HOLDFAST_DATA if set (the repo's data/ while developing), else the user's own data dir.
// Never the file it was read from: that may be the shipped data (/opt/holdfast, a checkout), which is not the user's to
// rewrite. The user copy comes first in data_roots(), so it shadows a shipped file of the same name.
fs::path user_os_path(const std::string& home, const std::string& name) {
    fs::path root = (std::getenv("HOLDFAST_DATA") && *std::getenv("HOLDFAST_DATA")) ? fs::path(std::getenv("HOLDFAST_DATA"))
                                                                                     : fs::path(home) / ".config/holdfast/data";
    return root / "os" / (name + ".profile");                       // find_data() only looks for .profile
}

}  // namespace

int cmd_libs(const std::string& name_arg, bool check, bool refresh) {
    const User u = resolve_user();
    const Strings roots = data_roots(u.home.string());
    const HostId host = read_host_id();
    const std::string name = name_arg.empty() ? suggest_os_name(host) : name_arg;
    if (!valid_data_name(name)) throw Error("invalid os name: " + name);
    const std::string arch = host_arch();

    std::optional<OsDef> old;
    if (find_data(roots, "os", name)) old = load_os(name, roots);
    if (old && old->kind != OsKind::Host) throw Error(cat("os '", name, "' is a bundle definition; `holdfast libs` only writes kind = host files"));
    if (check && !old) throw Error(cat("os '", name, "' does not exist yet; create it with: holdfast libs --refresh ", name));

    const Strings libs = list_data(roots, "lib");
    if (libs.empty()) throw Error("no data/lib/*.lib found (searched: " + join(roots, ", ") + ")");
    Policy pol(u, {});
    std::map<std::string, Strings> fresh;                            // lib -> sandbox paths on this host
    std::map<std::string, std::string> failed;                       // lib -> why it cannot be listed on this host
    for (const std::string& ln : libs) {
        // One lib that cannot be analysed here (e.g. a python with 50k+ files) must not take the others down. It gets
        // NO file list, so every profile or [install] use naming it fails with "no file list for lib" (fail closed).
        try {
            Strings v;
            for (const auto& [src, dst] : resolve_lib(load_lib(ln, roots), pol)) v.push_back(dst.string());
            std::sort(v.begin(), v.end());
            fresh[ln] = v;
            // Libs list alternative names across distros (dash, mawk, fdfind, vi): a missing one is normal, all missing is not.
            const LibDef def = load_lib(ln, roots);
            Strings absent, present;
            for (const auto& c : def.commands) (which(c) ? present : absent).push_back(c);
            std::string note = absent.empty() ? "" : cat(" (not on this host: ", join(absent, " "), ")");
            if (!def.commands.empty() && present.empty()) log::warn(cat("lib ", ln, ": none of its commands is installed here", note));
            else log::info(cat("lib ", ln, ": ", v.size(), " files", note));
        } catch (const Error& e) {
            failed[ln] = e.what();
            log::error(cat("lib ", ln, ": not listed for this host: ", e.what()));
        }
    }
    const auto report_failed = [&] {
        if (failed.empty()) return;
        Strings names;
        for (const auto& [n, why] : failed) names.push_back(n);
        log::error(cat(failed.size(), " lib(s) have no file list for this host and cannot be used by `libs = minimal` profiles or [install] use: ",
                       join(names, " "), " (see the errors above; fix the data/lib file or use `libs = full` where you need it)"));
    };

    if (check) {
        const auto it = old->files.find(arch);
        const std::map<std::string, Strings> empty;
        const auto& have = it == old->files.end() ? empty : it->second;
        size_t diff = 0;
        const Style st = style_for(stdout);                          // + green, - red on a terminal; plain when piped
        auto emit = [&](const char* sign, const std::string& lib, const std::string& path) {
            std::printf("%s%s%s %s: %s\n", sign[0] == '+' ? st.g : st.x, sign, st.r, lib.c_str(), path.c_str());
            ++diff;
        };
        for (const auto& [lib, want] : fresh) {
            const auto h = have.find(lib);
            if (h == have.end()) { emit("+", lib, "(no file list saved yet)"); continue; }
            const std::set<std::string> a(want.begin(), want.end()), b(h->second.begin(), h->second.end());
            for (const auto& f : a) if (!b.count(f)) emit("+", lib, f);
            for (const auto& f : b) if (!a.count(f)) emit("-", lib, f);
        }
        for (const auto& [lib, files] : have)
            if (!fresh.count(lib)) emit("-", lib, failed.count(lib) ? "(cannot be analysed on this host)" : "(no such data/lib file)");
        report_failed();
        if (diff) log::error(cat("os '", name, "': saved file list for ", arch, " differs from this host (", diff, " differences); update it with: holdfast libs --refresh ", name));
        else log::info(cat("os '", name, "': saved file list for ", arch, " is up to date"));
        return diff || !failed.empty() ? 1 : 0;
    }

    OsDef out;
    out.name = name;
    out.kind = OsKind::Host;
    out.id = old ? old->id : host.id;
    out.version = old ? old->version : host.version;
    out.description = old ? old->description : "";
    if (out.id.empty())
        throw Error("cannot determine the OS id: neither /etc/os-release nor /usr/lib/os-release could be read or has an ID= line; "
                    "create the file by hand with [os] id = ...");
    if (old) out.files = old->files;                                  // keep other architectures
    out.files[arch] = fresh;
    const std::string text = render_os(out);

    if (!refresh) { std::fputs(text.c_str(), stdout); report_failed(); return failed.empty() ? 0 : 1; }
    const fs::path target = user_os_path(u.home.string(), name);
    if (old && fs::path(old->file) != target)
        log::info(cat("based on ", old->file.string(), " (left untouched; its other architectures are kept in the new file)"));
    std::error_code ec;
    fs::create_directories(target.parent_path(), ec);
    const fs::path tmp = target.string() + ".tmp";
    write_file(tmp, text, 0644);
    fs::rename(tmp, target, ec);
    if (ec) throw Error(cat("cannot write ", target.string(), ": ", ec.message()));
    log::info("wrote " + target.string());
    report_failed();
    return failed.empty() ? 0 : 1;
}

}  // namespace hf
