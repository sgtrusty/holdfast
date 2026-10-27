// holdfast - sandbox launcher built on bubblewrap
#include <csignal>
#include <cstdio>
#include <cstdlib>

#include "core/bundle.hpp"
#include "core/session.hpp"
#include "util/log.hpp"

#ifndef HOLDFAST_SHARE_DIR
#define HOLDFAST_SHARE_DIR "/usr/local/share/holdfast"
#endif
#ifndef HOLDFAST_VERSION
#define HOLDFAST_VERSION "0.1.0"
#endif

using namespace hf;

static void usage() {
    std::fputs(
R"(holdfast - bubblewrap sandbox launcher: whitelist userland, optional WireGuard netns, nested X

USAGE
  holdfast run [options] PROFILE [-- COMMAND...]   run a sandbox
  holdfast print [options] PROFILE                 show the exact bwrap argv (no side effects)
  holdfast check PROFILE                           validate a profile
  holdfast libs [--check] PROFILE                  print a [libs] block for `libs = minimal` (reads ELF headers; authoring only)
  holdfast bundle setup|shell|info|purge PROFILE   manage the Alpine bundle   [--force]
  holdfast net-test PROFILE                        bring up the netns and test the kill switch
  holdfast net-cleanup NAME                        remove a stale namespace (e.g. hf-librewolf)
  holdfast purge PROFILE [-y]                      delete ALL state of a profile (incl. fake $HOME)
  holdfast init [NAME]                             list/print example profiles
  holdfast list                                    list known profiles
  holdfast doctor                                  check host prerequisites

RUN OPTIONS
  --net=none|pasta|host|ivpn   override [network] mode      --wg=FILE      WireGuard config (ivpn)
  --cwd=DIR              working tree to mount        --no-cwd       never mount a working tree
  -y, --yes              don't ask before mounting    -n, --dry-run  same as `print`
  -v, --verbose          debug output

PROFILE is a name (searched in $HOLDFAST_PROFILES, ~/.config/holdfast/profiles, /etc/holdfast/profiles)
or a path to a .profile file.
)", stderr);
}

static Profile load(const std::string& name) {
    std::string home;
    try { home = resolve_user().home.string(); } catch (...) { if (const char* h = std::getenv("HOME")) home = h; }
    return load_profile_file(find_profile(name, home));
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
    if (const char* e = std::getenv("HOLDFAST_SHARE")) dirs.push_back(std::string(e) + "/profiles");
    dirs.push_back(std::string(HOLDFAST_SHARE_DIR) + "/profiles");
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

static int cmd_list() {
    namespace fs = std::filesystem;
    Strings dirs;
    if (const char* e = std::getenv("HOLDFAST_PROFILES")) dirs.push_back(e);
    try { dirs.push_back((resolve_user().home / ".config/holdfast/profiles").string()); } catch (...) {}
    dirs.push_back("/etc/holdfast/profiles");
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
    if (args.empty() || args[0] == "-h" || args[0] == "--help" || args[0] == "help") { usage(); return args.empty() ? 2 : 0; }
    if (args[0] == "--version" || args[0] == "version") { std::printf("holdfast %s\n", HOLDFAST_VERSION); return 0; }

    const std::string cmd = args[0];
    args.erase(args.begin());

    try {
        if (cmd == "doctor") return doctor();
        if (cmd == "init") return cmd_init(args);
        if (cmd == "list") return cmd_list();

        // generic option scan (stops at `--`)
        RunOptions o;
        std::string sub;
        bool force = false, yes = false, check_libs = false;
        Strings pos;
        size_t i = 0;
        for (; i < args.size(); ++i) {
            const std::string& a = args[i];
            if (a == "--") { ++i; break; }
            if (a == "-v" || a == "--verbose") log::set_verbose(true);
            else if (a == "-y" || a == "--yes") { o.yes = true; yes = true; }
            else if (a == "-n" || a == "--dry-run") o.dry = true;
            else if (a == "--no-cwd") o.no_cwd = true;
            else if (a == "--force") force = true;
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
            Paths paths = make_paths(u, p.name);
            if (p.root != RootMode::Bundle) throw Error("profile '" + p.name + "' is not a bundle profile ([profile] mode = bundle)");
            if (sub == "info") {
                std::printf("profile:     %s\nrootfs:      %s\ninstalled:   %s\nprovisioned: %s\nhome:        %s\n", p.name.c_str(),
                            paths.rootfs.c_str(), bundle_installed(paths) ? "yes" : "no", bundle_provisioned(p, paths) ? "yes" : "no", paths.home.c_str());
                return 0;
            }
            if (sub == "purge") {
                if (!confirm("Remove the bundle userland of '" + p.name + "' (fake $HOME is kept)?", yes)) return 1;
                bundle_purge(paths, false);
                return 0;
            }
            struct Tmp { fs::path d; ~Tmp() { std::error_code ec; fs::remove_all(d, ec); } } t{make_session_dir(u, paths, p.name)};
            if (sub == "setup") { bundle_setup(p, u, paths, t.d, force); return 0; }
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
            if (p.root == RootMode::Host || fs::exists(make_paths(resolve_user(), p.name).rootfs)) {
                run_profile(p, o);
            }
            std::fprintf(stderr, "profile '%s' OK\n", p.name.c_str());
            return 0;
        }
        if (cmd == "libs") return print_libs(p, check_libs);
        if (cmd == "net-test") return net_test(p, o);
        if (cmd == "purge") {
            User u = resolve_user();
            Paths paths = make_paths(u, p.name);
            if (!confirm("DELETE all state of '" + p.name + "' including its persistent fake $HOME at " + paths.state.string() + "?", yes)) return 1;
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
