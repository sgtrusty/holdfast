#include "core/libs_cmd.hpp"

#include <algorithm>
#include <cstdio>
#include <set>

#include "core/datadefs.hpp"
#include "core/libs.hpp"
#include "util/log.hpp"
#include "util/sys.hpp"

namespace hf {

namespace {

// Where a NEW os file goes: $HOLDFAST_DATA if set (the repo's data/ while developing), else the user's config.
fs::path new_os_path(const std::string& home, const std::string& name) {
    fs::path root = (std::getenv("HOLDFAST_DATA") && *std::getenv("HOLDFAST_DATA")) ? fs::path(std::getenv("HOLDFAST_DATA"))
                                                                                     : fs::path(home) / ".config/holdfast/data";
    return root / "os" / (name + ".os");
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
    for (const std::string& ln : libs) {
        Strings v;
        for (const auto& [src, dst] : resolve_lib(load_lib(ln, roots), pol)) v.push_back(dst.string());
        std::sort(v.begin(), v.end());
        fresh[ln] = v;
        log::info(cat("lib ", ln, ": ", v.size(), " files"));
    }

    if (check) {
        const auto it = old->files.find(arch);
        const std::map<std::string, Strings> empty;
        const auto& have = it == old->files.end() ? empty : it->second;
        size_t diff = 0;
        auto emit = [&](const char* sign, const std::string& lib, const std::string& path) { std::printf("%s %s: %s\n", sign, lib.c_str(), path.c_str()); ++diff; };
        for (const auto& [lib, want] : fresh) {
            const auto h = have.find(lib);
            if (h == have.end()) { emit("+", lib, "(no file list saved yet)"); continue; }
            const std::set<std::string> a(want.begin(), want.end()), b(h->second.begin(), h->second.end());
            for (const auto& f : a) if (!b.count(f)) emit("+", lib, f);
            for (const auto& f : b) if (!a.count(f)) emit("-", lib, f);
        }
        for (const auto& [lib, files] : have) if (!fresh.count(lib)) emit("-", lib, "(no such data/lib file)");
        if (diff) log::error(cat("os '", name, "': saved file list for ", arch, " differs from this host (", diff, " differences); update it with: holdfast libs --refresh ", name));
        else log::info(cat("os '", name, "': saved file list for ", arch, " is up to date"));
        return diff ? 1 : 0;
    }

    OsDef out;
    out.name = name;
    out.kind = OsKind::Host;
    out.id = old ? old->id : host.id;
    out.version = old ? old->version : host.version;
    out.description = old ? old->description : "";
    if (out.id.empty()) throw Error("cannot determine the OS id (/etc/os-release has no ID=); create the file by hand with [os] id = ...");
    if (old) out.files = old->files;                                  // keep other architectures
    out.files[arch] = fresh;
    const std::string text = render_os(out);

    if (!refresh) { std::fputs(text.c_str(), stdout); return 0; }
    const fs::path target = old ? old->file : new_os_path(u.home.string(), name);
    std::error_code ec;
    fs::create_directories(target.parent_path(), ec);
    const fs::path tmp = target.string() + ".tmp";
    write_file(tmp, text, 0644);
    fs::rename(tmp, target, ec);
    if (ec) throw Error(cat("cannot write ", target.string(), ": ", ec.message()));
    log::info("wrote " + target.string());
    return 0;
}

}  // namespace hf
