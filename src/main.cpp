// holdfast - sandbox launcher built on bubblewrap
#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <set>

#include "cli/args.hpp"
#include "cli/doctor.hpp"
#include "core/bundle.hpp"
#include "core/datadefs.hpp"
#include "core/libs_cmd.hpp"
#include "core/session.hpp"
#include "util/log.hpp"
#include "util/style.hpp"

using namespace hf;

// Data roots, first match wins: --data dirs, then the usual search order (with <profile dir>/data for a profile given by path).
static Profile load(const std::string& name, const Strings& extra) {
    std::string home;
    try { home = resolve_user().home.string(); } catch (...) { if (const char* h = std::getenv("HOME")) home = h; }
    const fs::path file = find_profile(name, home, extra);
    Profile p = load_profile_file(file);
    const bool by_path = name.find('/') != std::string::npos || (name.size() > 8 && name.substr(name.size() - 8) == ".profile");
    Strings roots = extra;
    for (const auto& d : data_roots(home, by_path ? profile_local_root(file) : "")) if (std::find(roots.begin(), roots.end(), d) == roots.end()) roots.push_back(d);
    resolve_profile_data(p, roots);                  // os file / library file lists the profile refers to (fails closed)
    return p;
}

// `list` shows what `run NAME` / profiles' `use` and `os` would find, in the same search order (first match wins, so a
// user copy hides a shipped one). -v adds the file each entry came from.
static int cmd_list(const Strings& a, bool verbose, const Strings& extra) {
    namespace fs = std::filesystem;
    std::string home;
    try { home = resolve_user().home.string(); } catch (...) {}
    Strings roots = extra;
    for (const auto& r : data_roots(home)) roots.push_back(r);
    if (a.size() > 1 || (!a.empty() && a[0] != "libs" && a[0] != "os" && a[0] != "deps" && a[0] != "displays"))
        throw Error("usage: holdfast list [libs|os|deps|displays] [--data=DIR] [-v]");
    // Piped output stays plain, headerless and one entry per line; on a terminal there is a header and colour.
    const Style st = style_for(stdout);
    bool header_done = false;
    auto line = [&](const std::string& name, const char* kind, const std::string& desc, const fs::path& file) {
        if (st.tty && !header_done) {
            header_done = true;
            std::printf("%s%-20s %-7s %s%s\n", st.b, "NAME", "KIND", "DESCRIPTION", st.r);
        }
        const bool invalid = std::string(kind) == "INVALID";
        std::printf("%-20s %s%-7s%s %s", name.c_str(), invalid ? st.x : "", kind, invalid ? st.r : "", desc.c_str());
        if (verbose) std::printf("  %s[%s]%s", st.c, file.c_str(), st.r);
        std::printf("\n");
    };
    if (!a.empty()) {
        const std::string which = a[0];
        for (const auto& n : list_data(roots, which == "libs" ? "lib" : which == "deps" ? "dep" : which == "displays" ? "display" : "os")) {
            try {
                if (which == "libs") { LibDef d = load_lib(n, roots); line(n, "lib", d.description, d.file); }
                else if (which == "deps") { DepRecipe d = load_dep(n, roots); line(n, "dep", d.description, find_data(roots, "dep", n).value_or("")); }
                else if (which == "displays") { DisplayDef d = load_display(n, roots); line(n, d.mode == DisplayMode::Nested ? "xephyr" : "host", d.description, find_data(roots, "display", n).value_or("")); }
                else { OsDef o = load_os(n, roots); line(n, o.kind == OsKind::Host ? "host" : "bundle", o.description, o.file); }
            } catch (const Error& ex) { line(n, "INVALID", ex.what(), ""); }
        }
        return 0;
    }
    for (const std::string& d : legacy_profile_dirs(home)) {
        std::error_code ec;
        for (fs::directory_iterator it(d, ec), end; !ec && it != end; it.increment(ec))
            if (it->path().extension() == ".profile")
                log::warn(cat("not searched any more: ", it->path().string(), "; move it to ", home, "/.config/holdfast/data/profile/"));
    }
    Strings dirs;
    for (const auto& r : roots) dirs.push_back(r + "/profile");
    std::set<std::string> seen;
    for (auto& d : dirs) {
        std::error_code ec;
        if (!fs::is_directory(d, ec)) continue;
        std::vector<fs::path> files;
        for (auto& e : fs::directory_iterator(d, ec)) if (e.path().extension() == ".profile") files.push_back(e.path());
        std::sort(files.begin(), files.end());
        for (const auto& f : files) {
            if (!seen.insert(f.stem().string()).second) continue;          // shadowed by an earlier directory
            try {
                Profile p = load_profile_file(f);
                line(p.name, p.root == RootMode::Host ? "host" : "bundle", p.description, f);
            } catch (const Error& ex) { line(f.stem().string(), "INVALID", ex.what(), f); }
        }
    }
    return 0;
}

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    Strings args(argv + 1, argv + argc);
    if (auto rc = handle_meta(args)) return *rc;       // no arguments, help, version (src/cli/args.cpp)

    const std::string cmd = args[0];
    args.erase(args.begin());

    try {
        if (cmd == "doctor") return doctor();

        Cli cli = parse_args(cmd, args);                // options, positionals, and everything after `--`
        if (cli.verbose) log::set_verbose(true);
        RunOptions& o = cli.run;
        const Strings& pos = cli.pos;

        if (o.debug && cmd != "run" && cmd != "print") throw Error("--debug applies to `run` (open a shell in the sandbox) and `print` (show how)");

        if (!o.refresh_deps.empty() && cmd != "run") throw Error("--refresh-dep applies to `run`");
        if (!cli.out.empty() && cmd != "libs") throw Error("--out applies to `libs --refresh`");
        if (cmd == "list") return cmd_list(pos, cli.verbose, cli.data);

        if (cmd == "libs") {
            if (pos.size() > 1 || (cli.check && cli.refresh)) throw Error("usage: holdfast libs [--check|--refresh [--out=DIR]] [OS]");
            return cmd_libs(pos.empty() ? "" : pos[0], cli.check, cli.refresh, cli.data, cli.out);
        }
        if (cmd == "net-cleanup") {
            if (pos.size() != 1) throw Error("usage: holdfast net-cleanup NAME");
            net_cleanup(pos[0]);
            return 0;
        }
        if (pos.size() != 1) throw Error("expected exactly one PROFILE (see --help)");
        Profile p = load(pos[0], cli.data);

        if (cmd == "os-shell") {
            const User u = resolve_user();
            return bundle_shell(p, u, make_paths(u, p.name, p.bundle_id), o.dry);
        }

        if (cmd == "run") return run_profile(p, o);
        if (cmd == "print") { o.dry = true; return run_profile(p, o); }
        if (cmd == "check") {
            validate_profile(p, true);
            o.dry = true; o.yes = true; o.command = o.command.empty() ? Strings{} : o.command;
            if (p.command.empty() && o.command.empty()) o.command = {"true"};
            if (p.root == RootMode::Bundle && !fs::exists(make_paths(resolve_user(), p.name, p.bundle_id).rootfs))
                std::fprintf(stderr, "note: the Alpine userland is not set up yet; it is created the first time you run this profile\n");
            else
                run_profile(p, o);
            const Style st = style_for(stderr);
            std::fprintf(stderr, "profile '%s' %sOK%s\n", p.name.c_str(), st.g, st.r);
            return 0;
        }
        if (cmd == "net-test") return net_test(p, o);
        throw Error("unknown command: " + cmd + " (see holdfast help)");
    } catch (const PolicyError& e) {
        log::error(std::string("policy: ") + e.what());
        return 3;
    } catch (const Error& e) {
        log::error(e.what());
        return 1;
    } catch (const std::exception& e) {
        log::error(std::string("internal error: ") + e.what());
        return 70;
    }
}
