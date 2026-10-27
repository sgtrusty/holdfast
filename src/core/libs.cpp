#include "core/libs.hpp"

#include <glob.h>
#include <sys/utsname.h>

#include <deque>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

#include "core/elf.hpp"
#include "util/log.hpp"
#include "util/sys.hpp"

namespace hf {

namespace {

// Commands whose job is linking/compiling need crt files, libc.so linker scripts and static archives,
// none of which are DT_NEEDED. Refuse early with a clear message instead of failing inside the sandbox.
const std::set<std::string> kNeedsFull = {"gcc", "cc", "g++", "c++", "ld", "lld", "ld.lld", "clang", "clang++", "rustc", "cargo"};

std::string triplet() {
    utsname u{};
    if (uname(&u) != 0) return "";
    const std::string m = u.machine;
    if (m == "x86_64" || m == "aarch64" || m == "riscv64" || m == "s390x") return m + "-linux-gnu";
    if (m == "ppc64le") return "powerpc64le-linux-gnu";
    return "";
}

void read_ld_conf(const fs::path& f, Strings& out, int depth) {
    if (depth > 3) return;
    std::string text;
    try { text = read_file(f); } catch (const Error&) { return; }   // only affects search order; a missing lib is reported later
    std::istringstream in(text);
    for (std::string line; std::getline(in, line);) {
        if (auto h = line.find('#'); h != std::string::npos) line.resize(h);
        line = trim(line);
        if (line.empty()) continue;
        if (line.rfind("include", 0) == 0 && line.size() > 7 && (line[7] == ' ' || line[7] == '\t')) {
            std::string pat = trim(line.substr(7));
            if (!fs::path(pat).is_absolute()) pat = (f.parent_path() / pat).string();
            glob_t g{};
            if (glob(pat.c_str(), 0, nullptr, &g) == 0)
                for (size_t i = 0; i < g.gl_pathc; ++i) read_ld_conf(g.gl_pathv[i], out, depth + 1);
            globfree(&g);
        } else if (line[0] == '/') {
            out.push_back(line);
        }
    }
}

const Strings& lib_dirs() {
    static const Strings v = [] {
        Strings d;
        read_ld_conf("/etc/ld.so.conf", d, 0);
        const std::string t = triplet();
        if (!t.empty()) { d.push_back("/lib/" + t); d.push_back("/usr/lib/" + t); }
        for (const char* x : {"/lib64", "/usr/lib64", "/lib", "/usr/lib", "/usr/local/lib"}) d.push_back(x);
        return d;
    }();
    return v;
}

// The ABI of holdfast itself: libraries of another one (lib32 next to lib64) are never candidates.
std::optional<unsigned> native_abi() {
    static const std::optional<unsigned> v = elf_abi("/proc/self/exe");
    return v;
}
bool abi_matches(const fs::path& p, const std::optional<unsigned>& want) {
    if (!want) return true;
    const auto got = elf_abi(p);
    return got && *got == *want;
}

std::string replace_all(std::string s, const std::string& from, const std::string& to) {
    for (size_t p = 0; (p = s.find(from, p)) != std::string::npos; p += to.size()) s.replace(p, from.size(), to);
    return s;
}

struct Collector {
    const Policy& pol;
    std::vector<fs::path> roots;              // directories bound whole (their contents need no extra binds)
    std::map<std::string, fs::path> binds;    // destination -> host source; std::map order puts parents first
    std::set<std::string> seen;               // host paths already analysed
    std::deque<fs::path> todo;

    explicit Collector(const Policy& p) : pol(p) {}

    bool covered(const fs::path& p) const {
        for (const auto& r : roots) if (path_under(p, r)) return true;
        return false;
    }
    void enqueue(const fs::path& real) { if (seen.insert(real.string()).second) todo.push_back(real); }

    // `logical` is where the dynamic loader will look; `real` the file behind any symlink chain.
    void add(const fs::path& logical, const fs::path& real) {
        if (!covered(logical) && binds.emplace(logical.string(), real).second) pol.check_bind(real, false);
        enqueue(real);
    }
    void add_found(const fs::path& p) {
        std::error_code ec;
        fs::path parent = fs::canonical(p.parent_path(), ec);
        fs::path real = ec ? fs::path() : fs::canonical(p, ec);
        if (ec) throw Error(cat("cannot resolve library ", p.string(), ": ", ec.message()));
        add(parent / p.filename(), real);
    }
    void add_root(const fs::path& dir) {
        pol.check_bind(dir, false);
        roots.push_back(dir);
        binds[dir.string()] = dir;
    }
    // ELF objects inside a bound directory: not bound again, but what they link against is.
    void scan(const fs::path& root) {
        std::error_code ec;
        if (!fs::is_directory(root, ec)) return;
        size_t n = 0;
        fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
        for (; !ec && it != end; it.increment(ec)) {
            if (++n > 50000) throw Error(cat("too many files under ", root.string(), " to analyse; use `libs = full` in [fs]"));
            std::error_code e2;
            if (it->is_symlink(e2) || !it->is_regular_file(e2)) continue;
            const bool exec = (it->status(e2).permissions() & fs::perms::owner_exec) != fs::perms::none;
            if ((exec || it->path().filename().string().find(".so") != std::string::npos) && abi_matches(it->path(), native_abi()))
                enqueue(it->path());
        }
        if (ec) throw Error(cat("cannot scan ", root.string(), ": ", ec.message()));
    }

    void resolve(const fs::path& obj, const ElfDeps& e) {
        Strings dirs;
        for (std::string s : e.search) {
            s = replace_all(replace_all(s, "${ORIGIN}", obj.parent_path().string()), "$ORIGIN", obj.parent_path().string());
            if (s.find('$') == std::string::npos) dirs.push_back(s);       // $LIB/$PLATFORM: fall through to defaults
        }
        dirs.insert(dirs.end(), lib_dirs().begin(), lib_dirs().end());
        const std::optional<unsigned> want = elf_abi(obj).has_value() ? elf_abi(obj) : native_abi();   // same ABI as the requester
        for (const std::string& name : e.needed) {
            std::optional<fs::path> found;
            if (name.find('/') != std::string::npos) found = fs::path(name);
            for (const std::string& d : dirs) {
                if (found) break;
                std::error_code ec;
                fs::path c = fs::path(d) / name;
                if (fs::is_regular_file(c, ec) && abi_matches(c, want)) found = c;     // like ld.so: skip wrong-ABI candidates, keep looking
            }
            if (!found)
                throw Error(cat("cannot find ", name, " (needed by ", obj.string(), ") in the library search path; "
                                "set `libs = full` in [fs] to mount the host library directories instead"));
            add_found(*found);
        }
        if (!e.interp.empty()) add_found(e.interp);
    }

    void run() {
        while (!todo.empty()) {
            fs::path f = todo.front();
            todo.pop_front();
            if (auto e = read_elf_deps(f)) resolve(f, *e);
        }
    }
};

}  // namespace

std::vector<std::pair<fs::path, fs::path>> resolve_lib(const LibDef& d, const Policy& pol) {
    for (const std::string& cmd : d.commands)
        if (kNeedsFull.count(cmd))
            throw Error(cat("lib '", d.name, "': '", cmd, "' needs the host's development libraries (crt files, libc.so, static archives), "
                            "which a minimal lib set does not provide; remove it from the lib and use `libs = full` in profiles that need it"));

    Collector c(pol);
    VarCtx vc;
    std::vector<fs::path> support;
    for (const std::string& pattern : d.paths)
        for (const std::string& s : expand_glob(pattern, vc)) {
            std::error_code ec;
            if (fs::exists(s, ec)) support.push_back(canon(s));
        }
    for (const auto& s : support) {          // roots first so `covered()` is complete before any lib is added
        std::error_code ec;
        if (fs::is_directory(s, ec)) c.add_root(s);
        else { pol.check_bind(s, false); c.binds[s.string()] = s; }
    }
    for (const auto& s : support) c.scan(s);

    for (const std::string& cmd : d.commands) {
        auto host = which(cmd);
        if (!host) { log::warn(cat("lib '", d.name, "': command not found on this host, skipped: ", cmd)); continue; }
        c.enqueue(canon(*host));
    }
    for (const std::string& pat : d.sonames)
        for (const std::string& dir : lib_dirs())
            for (const std::string& m : expand_glob(dir + "/" + pat, vc)) {
                std::error_code ec;
                if (fs::is_regular_file(m, ec) && abi_matches(m, native_abi())) c.add_found(m);
            }

    c.run();
    std::vector<std::pair<fs::path, fs::path>> out;
    for (const auto& [dst, src] : c.binds) out.emplace_back(src, dst);
    return out;
}

}  // namespace hf
