// holdfast - sandbox launcher built on bubblewrap
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "core/bundle.hpp"
#include "core/datadefs.hpp"
#include "core/libs_cmd.hpp"
#include "core/session.hpp"
#include "util/log.hpp"

#ifndef HOLDFAST_SHARE_DIR
#define HOLDFAST_SHARE_DIR "/usr/local/share/holdfast"
#endif
#ifndef HOLDFAST_VERSION
#define HOLDFAST_VERSION "0.1.0"
#endif

using namespace hf;

namespace {

// Classic SGR only (bold, cyan, reset), and only when the stream is a terminal that wants colour.
struct Ansi { const char *b = "", *c = "", *r = ""; };
Ansi ansi_for(FILE* f) {
    const char* term = std::getenv("TERM");
    if (!isatty(fileno(f)) || std::getenv("NO_COLOR") || (term && std::strcmp(term, "dumb") == 0)) return {};
    return {"\033[1m", "\033[36m", "\033[0m"};
}

}  // namespace

// Explicit `help` goes to stdout (pipe it into a pager); a bare `holdfast` goes to stderr with exit code 2.
static void usage(FILE* f) {
    const Ansi a = ansi_for(f);
    auto head = [&](const char* t) { std::fprintf(f, "\n%s%s%s\n", a.b, t, a.r); };
    // %-*s pads the visible text only: the escape codes are separate arguments outside the padded field.
    auto row = [&](const char* name, const char* desc) { std::fprintf(f, "  %s%-34s%s %s\n", a.c, name, a.r, desc); };

    std::fprintf(f, "%sholdfast%s %s: declarative bubblewrap sandboxes\n", a.b, a.r, HOLDFAST_VERSION);
    head("USAGE");
    std::fprintf(f, "  holdfast %s<command>%s [options] [PROFILE] [-- CMD...]\n", a.c, a.r);

    head("RUN");
    row("run PROFILE [-- CMD...]", "run a sandbox (CMD overrides the profile)");
    row("print PROFILE", "show the exact bwrap argv, change nothing");
    row("check PROFILE", "validate a profile");

    head("PROFILES AND DATA");
    row("list [libs|os]", "list profiles, or lib/os definitions");
    row("init [NAME]", "list or print the example profiles");
    row("libs [OS]", "scan this host, print its library file list");

    head("BUNDLES");
    row("bundle setup PROFILE", "fetch, verify and provision the userland");
    row("bundle shell|info|purge PROFILE", "root shell / status / remove the userland");
    row("purge PROFILE", "delete all state, incl. the fake $HOME");

    head("NETWORK (ivpn)");
    row("net-test PROFILE", "test the kill switch");
    row("net-cleanup NAME", "remove a stale namespace");

    head("OTHER");
    row("doctor", "check host prerequisites");
    row("help, version", "this text / the version");

    head("OPTIONS");
    row("-y, --yes", "don't ask before mounting the working tree");
    row("--cwd=DIR, --no-cwd", "mount DIR / mount no working tree");
    row("--net=none|pasta|host|ivpn", "override the profile's network mode");
    row("--wg=FILE", "WireGuard config (ivpn)");
    row("-n, --dry-run", "same as print");
    row("--refresh", "rebuild a bundle / rewrite the libs list");
    row("--check", "libs: exit 1 if the saved list is stale");
    row("-v, --verbose", "debug output");

    std::fprintf(f, "\n%sPROFILE%s is a name (profile and data dirs are searched) or a path to a .profile file.\n"
                    "Docs: README.md and docs/. Colour: off when not a terminal, NO_COLOR is set, or TERM=dumb.\n", a.b, a.r);
}

static Profile load(const std::string& name) {
    std::string home;
    try { home = resolve_user().home.string(); } catch (...) { if (const char* h = std::getenv("HOME")) home = h; }
    Profile p = load_profile_file(find_profile(name, home));
    resolve_profile_data(p, data_roots(home));       // os file / library file lists the profile refers to (fails closed)
    return p;
}

static bool confirm(const std::string& q, bool yes) {
    if (yes) return true;
    std::fprintf(stderr, "%s [y/N] ", q.c_str());
    char b[8] = {0};
    return std::fgets(b, sizeof b, stdin) && (b[0] == 'y' || b[0] == 'Y');
}

static int cmd_init(const Strings& a) {
    namespace fs = std::filesystem;
    Strings dirs;
    if (const char* e = std::getenv("HOLDFAST_SHARE")) dirs.push_back(std::string(e) + "/data/profile");
    dirs.push_back(std::string(HOLDFAST_SHARE_DIR) + "/data/profile");
    for (auto& d : dirs) {
        if (!fs::is_directory(d)) continue;
        if (a.empty()) {
            for (auto& e : fs::directory_iterator(d)) if (e.path().extension() == ".profile") std::printf("%s\n", e.path().stem().string().c_str());
            return 0;
        }
        fs::path f = fs::path(d) / (a[0] + ".profile");
        if (fs::is_regular_file(f)) { std::fputs(read_file(f).c_str(), stdout); return 0; }
    }
    log::error("example profiles not found (set HOLDFAST_SHARE or install the share/ directory)");
    return 1;
}

static int cmd_list(const Strings& a) {
    namespace fs = std::filesystem;
    std::string home;
    try { home = resolve_user().home.string(); } catch (...) {}
    const Strings roots = data_roots(home);
    if (!a.empty() && a[0] == "libs") {
        for (const auto& n : list_data(roots, "lib")) {
            try { LibDef d = load_lib(n, roots); std::printf("%-20s %s\n", n.c_str(), d.description.c_str()); }
            catch (const Error& ex) { std::printf("%-20s INVALID  %s\n", n.c_str(), ex.what()); }
        }
        return 0;
    }
    if (!a.empty() && a[0] == "os") {
        for (const auto& n : list_data(roots, "os")) {
            try {
                OsDef o = load_os(n, roots);
                std::printf("%-20s %-7s %s\n", n.c_str(), o.kind == OsKind::Host ? "host" : "bundle", o.description.c_str());
            } catch (const Error& ex) { std::printf("%-20s INVALID  %s\n", n.c_str(), ex.what()); }
        }
        return 0;
    }
    if (!a.empty()) throw Error("usage: holdfast list [libs|os]");
    Strings dirs;
    if (const char* e = std::getenv("HOLDFAST_PROFILES")) dirs.push_back(e);
    if (!home.empty()) dirs.push_back(home + "/.config/holdfast/profiles");
    dirs.push_back("/etc/holdfast/profiles");
    for (const auto& r : roots) dirs.push_back(r + "/profile");
    for (auto& d : dirs) {
        if (!fs::is_directory(d)) continue;
        for (auto& e : fs::directory_iterator(d)) {
            if (e.path().extension() != ".profile") continue;
            try {
                Profile p = load_profile_file(e.path());
                std::printf("%-20s %-7s %s\n", p.name.c_str(), p.root == RootMode::Host ? "host" : "bundle", p.description.c_str());
            } catch (const Error& ex) { std::printf("%-20s INVALID  %s\n", e.path().stem().string().c_str(), ex.what()); }
        }
    }
    return 0;
}

int main(int argc, char** argv) {
    std::signal(SIGPIPE, SIG_IGN);
    Strings args(argv + 1, argv + argc);
    if (args.empty()) { usage(stderr); return 2; }
    if (args[0] == "-h" || args[0] == "--help" || args[0] == "help") { usage(stdout); return 0; }
    if (args[0] == "--version" || args[0] == "version") { std::printf("holdfast %s\n", HOLDFAST_VERSION); return 0; }

    const std::string cmd = args[0];
    args.erase(args.begin());

    try {
        if (cmd == "doctor") return doctor();
        if (cmd == "init") return cmd_init(args);
        if (cmd == "list") return cmd_list(args);

        // generic option scan (stops at `--`)
        RunOptions o;
        std::string sub;
        bool refresh = false, yes = false, check_libs = false;   // --refresh: rebuild a bundle / rewrite an OS file list from the current definitions
        Strings pos;
        size_t i = 0;
        for (; i < args.size(); ++i) {
            const std::string& a = args[i];
            if (a == "--") { ++i; break; }
            if (a == "-v" || a == "--verbose") log::set_verbose(true);
            else if (a == "-y" || a == "--yes") { o.yes = true; yes = true; }
            else if (a == "-n" || a == "--dry-run") o.dry = true;
            else if (a == "--no-cwd") o.no_cwd = true;
            else if (a == "--refresh") refresh = true;
            else if (a == "--check") check_libs = true;
            else if (a.rfind("--net=", 0) == 0) {
                std::string m = a.substr(6);
                if (m == "none") o.net = NetMode::None; else if (m == "host") o.net = NetMode::Host; else if (m == "ivpn") o.net = NetMode::Ivpn;
                else if (m == "pasta") o.net = NetMode::Pasta;
                else throw Error("--net expects none|pasta|host|ivpn");
            }
            else if (a.rfind("--wg=", 0) == 0) o.wg_conf = a.substr(5);
            else if (a.rfind("--cwd=", 0) == 0) o.cwd = a.substr(6);
            else if (!a.empty() && a[0] == '-') throw Error("unknown option: " + a);
            else pos.push_back(a);
        }
        for (; i < args.size(); ++i) o.command.push_back(args[i]);

        if (cmd == "libs") {
            if (pos.size() > 1 || (check_libs && refresh)) throw Error("usage: holdfast libs [--check|--refresh] [OS]");
            return cmd_libs(pos.empty() ? "" : pos[0], check_libs, refresh);
        }
        if (cmd == "net-cleanup") {
            if (pos.size() != 1) throw Error("usage: holdfast net-cleanup NAME");
            net_cleanup(pos[0]);
            return 0;
        }
        if (cmd == "bundle") {
            if (pos.size() != 2) throw Error("usage: holdfast bundle setup|shell|info|purge PROFILE");
            sub = pos[0];
            Profile p = load(pos[1]);
            User u = resolve_user();
            Paths paths = make_paths(u, p.name, p.bundle_id);
            if (p.root != RootMode::Bundle) throw Error("profile '" + p.name + "' is not a bundle profile ([profile] mode = bundle)");
            if (sub == "info") {
                std::string verdict = "n/a";
                if (bundle_installed(paths)) { try { bundle_verify(p, paths); verdict = "matches this profile"; } catch (const Error& e) { verdict = e.what(); } }
                std::printf("profile:     %s\nbundle id:   %s\nrootfs:      %s\ninstalled:   %s\nspec check:  %s\nprovisioned: %s\nhome:        %s\n", p.name.c_str(),
                            paths.bundle.filename().c_str(), paths.rootfs.c_str(), bundle_installed(paths) ? "yes" : "no", verdict.c_str(),
                            bundle_provisioned(p, paths) ? "yes" : "no", paths.home.c_str());
                return 0;
            }
            if (sub == "purge") {
                if (!confirm("Remove bundle '" + paths.bundle.filename().string() + "' (shared by every profile with this id; fake $HOMEs are kept)?", yes)) return 1;
                bundle_purge(paths, false);
                return 0;
            }
            struct Tmp { fs::path d; ~Tmp() { std::error_code ec; fs::remove_all(d, ec); } } t{make_session_dir(u, paths, p.name)};
            if (sub == "setup") { bundle_setup(p, u, paths, t.d, refresh); return 0; }
            if (sub == "shell") return bundle_shell(p, u, paths, t.d);
            throw Error("unknown bundle subcommand: " + sub);
        }

        if (pos.size() != 1) throw Error("expected exactly one PROFILE (see --help)");
        Profile p = load(pos[0]);

        if (cmd == "run") return run_profile(p, o);
        if (cmd == "print") { o.dry = true; return run_profile(p, o); }
        if (cmd == "check") {
            validate_profile(p, true);
            o.dry = true; o.yes = true; o.command = o.command.empty() ? Strings{} : o.command;
            if (p.command.empty()) o.command = {"true"};
            if (p.root == RootMode::Bundle) std::fprintf(stderr, "bundle: %s\n", "not inspected by check (see `bundle info`)");
            if (p.root == RootMode::Host || fs::exists(make_paths(resolve_user(), p.name, p.bundle_id).rootfs)) {
                run_profile(p, o);
            }
            std::fprintf(stderr, "profile '%s' OK\n", p.name.c_str());
            return 0;
        }
        if (cmd == "net-test") return net_test(p, o);
        if (cmd == "purge") {
            User u = resolve_user();
            Paths paths = make_paths(u, p.name);
            if (!confirm("DELETE all state of '" + p.name + "' including its persistent fake $HOME at " + paths.state.string() + "? (the bundle userland stays; use `bundle purge`)", yes)) return 1;
            bundle_purge(paths, true);
            return 0;
        }
        throw Error("unknown command: " + cmd + " (see --help)");
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
