#include "cli/args.hpp"

#include "util/style.hpp"

namespace hf {

namespace {

NetMode parse_net(const std::string& m) {
    if (m == "none") return NetMode::None;
    if (m == "pasta") return NetMode::Pasta;
    if (m == "host") return NetMode::Host;
    if (m == "ivpn") return NetMode::Ivpn;
    throw Error("--net expects none|pasta|host|ivpn");
}

}  // namespace

void print_usage(FILE* f) {
    const Style a = style_for(f);
    auto head = [&](const char* t) { std::fprintf(f, "\n%s%s%s\n", a.b, t, a.r); };
    // The name column is padded as plain text: the escape codes are separate arguments outside the padded field.
    auto row = [&](const char* name, const char* desc) { std::fprintf(f, "  %s%-34s%s %s\n", a.c, name, a.r, desc); };

    std::fprintf(f, "%sholdfast%s %s: declarative bubblewrap sandboxes\n", a.b, a.r, HOLDFAST_VERSION);
    head("USAGE");
    std::fprintf(f, "  holdfast %s<command>%s [options] [PROFILE] [-- CMD...]\n", a.c, a.r);

    head("RUN");
    row("run PROFILE [-- CMD...]", "run a sandbox (CMD overrides the profile)");
    row("run --refresh PROFILE", "bundle profiles: rebuild the Alpine userland first");
    row("print PROFILE", "show the exact bwrap argv, change nothing");
    row("check PROFILE", "validate a profile");

    head("PROFILES AND DATA");
    row("list [libs|os|deps]", "list profiles (or lib / os / dep files)");
    row("libs [OS]", "scan this host, print its library file list");

    head("NETWORK (ivpn)");
    row("net-test PROFILE", "test the kill switch");
    row("net-cleanup NAME", "remove a stale namespace");

    head("OTHER");
    row("doctor", "check prerequisites; show where state lives");
    row("help, version", "this text / the version");

    head("OPTIONS");
    row("-y, --yes", "don't ask before mounting the working tree");
    row("--cwd=DIR, --no-cwd", "mount DIR / mount no working tree");
    row("--net=none|pasta|host|ivpn", "override the profile's network mode");
    row("--wg=FILE", "WireGuard config (ivpn)");
    row("--debug", "run: open bash (or sh) in the sandbox, not the command");
    row("-n, --dry-run", "same as print");
    row("--refresh", "run: redo changed userland / deps; libs: rewrite list");
    row("--check", "libs: exit 1 if the saved list is stale");
    row("-v, --verbose", "debug output (list: show file paths)");

    std::fprintf(f, "\n%sPROFILE%s is a name or a path to a .profile file. Names are looked up in your own profile dirs, then in the\n"
                    "data that ships with holdfast (next to the binary, e.g. /opt/holdfast/data/profile); `list -v` shows where.\n"
                    "Docs: README.md and docs/. Colour is off when not a terminal, NO_COLOR is set, or TERM=dumb.\n", a.b, a.r);
}

std::optional<int> handle_meta(const Strings& args) {
    if (args.empty()) { print_usage(stderr); return 2; }          // a bare `holdfast` is a usage error
    const std::string& a = args[0];
    if (a == "-h" || a == "--help" || a == "help") { print_usage(stdout); return 0; }   // explicit help: stdout, pipeable
    if (a == "--version" || a == "version") { std::printf("holdfast %s\n", HOLDFAST_VERSION); return 0; }
    return std::nullopt;
}

Cli parse_args(const std::string& cmd, const Strings& rest) {
    Cli c;
    c.cmd = cmd;
    size_t i = 0;
    for (; i < rest.size(); ++i) {
        const std::string& a = rest[i];
        if (a == "--") { ++i; break; }
        if (a == "-v" || a == "--verbose") c.verbose = true;
        else if (a == "-y" || a == "--yes") { c.run.yes = true; c.yes = true; }
        else if (a == "-n" || a == "--dry-run") c.run.dry = true;
        else if (a == "--no-cwd") c.run.no_cwd = true;
        else if (a == "--refresh") { c.refresh = true; c.run.refresh = true; }
        else if (a == "--check") c.check = true;
        else if (a == "--debug") c.run.debug = true;
        else if (a.rfind("--net=", 0) == 0) c.run.net = parse_net(a.substr(6));
        else if (a.rfind("--wg=", 0) == 0) c.run.wg_conf = a.substr(5);
        else if (a.rfind("--cwd=", 0) == 0) c.run.cwd = a.substr(6);
        else if (!a.empty() && a[0] == '-') throw Error("unknown option: " + a + " (see holdfast help)");
        else c.pos.push_back(a);
    }
    for (; i < rest.size(); ++i) c.run.command.push_back(rest[i]);
    return c;
}

}  // namespace hf
