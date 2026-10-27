// Minimal dependency-free test runner.
#include <algorithm>
#include <cstdio>
#include <functional>
#include <set>
#include <unistd.h>

#include "cli/args.hpp"
#include "cli/doctor.hpp"
#include "util/style.hpp"
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
                                  "[env]\nset = K=V=W\n[network]\nmode=ivpn\nsubnet=7\n[deps]\nuse = a b\nuse = c\n", "t");
        CHECK(p.root == RootMode::Bundle);
        CHECK((p.command == Strings{"a", "b c"}));
        CHECK(p.mounts.size() == 2 && p.mounts[0].optional && !p.mounts[0].rw && p.mounts[0].dst == "/b" && p.mounts[1].rw);
        CHECK(p.env_set.at(0).second == "V=W");
        CHECK(p.net == NetMode::Ivpn && p.subnet_octet == 7);
        CHECK((p.dep_use == Strings{"a", "b", "c"}));
        THROWS(ProfileError, parse_profile("[bundle]\nprovision = echo a\n", "t"));        // install steps live in data/dep now
        THROWS(ProfileError, parse_profile("[deps]\nuse = ../evil\n", "t"));
        THROWS(ProfileError, parse_profile("[deps]\nbogus = x\n", "t"));
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

    test("libs analysis: toolchains need libs = full, ELF closure of a real command", [] {
        User u = fake_user();
        Policy pol(u, {});
        LibDef tc;
        tc.name = "toolchain"; tc.commands = {"gcc"};
        THROWS(Error, resolve_lib(tc, pol));                                  // crt files / static archives are not DT_NEEDED
        if (which("sh")) {
            LibDef sh;
            sh.name = "shell"; sh.commands = {"sh"};
            try {
                bool libc = false;
                for (const auto& [src, dst] : resolve_lib(sh, pol)) {
                    if (dst.filename().string().rfind("libc.", 0) == 0 && fs::exists(src)) libc = true;
                    // never a library of another ABI (a 32-bit /usr/lib32/libc.so.6 must not shadow the 64-bit one)
                    CHECK(elf_abi(src) == elf_abi("/proc/self/exe") || !elf_abi(src).has_value());
                }
                const auto e = read_elf_deps(fs::canonical(*which("sh")));
                CHECK(libc || !e.has_value() || e->needed.empty());
            } catch (const Error& ex) {
                CHECK(!"resolve_lib(sh) must not throw on a normal host");
                std::printf("  resolve_lib(sh): %s\n", ex.what());
            }
        }
        CHECK(!elf_abi("/nonexistent").has_value());
        CHECK(elf_abi("/proc/self/exe").has_value());
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

    // ---- data files: data/lib, data/os ------------------------------------------------------------------
    // A throwaway data root with two libs, a host OS (with a lock for THIS architecture) and a bundle OS.
    struct DataRoot {
        std::string d;
        DataRoot() {
            char tmpl[] = "/tmp/hf-data-XXXXXX";
            d = mkdtemp(tmpl);
            fs::create_directories(d + "/lib"); fs::create_directories(d + "/os");
            write_file(d + "/lib/base.profile", "[lib]\nsonames = libc.so.*\n", 0644);
            write_file(d + "/lib/shell.profile", "[lib]\ncommands = sh bash\n", 0644);
            write_file(d + "/os/fakeos-1.profile",
                       "[os]\nkind = host\nid = fakeos\nversion = 1\n"
                       "[files." + host_arch() + ".base]\nbind = /usr/lib/libc.so.6\nbind = /usr/lib/ld.so\n"
                       "[files." + host_arch() + ".shell]\nbind = /usr/lib/libc.so.6\nbind = /usr/lib/libtinfo.so.6\n", 0644);
            write_file(d + "/os/alpine-x.profile",
                       "[os]\nkind = bundle\nalpine_version = 3.24.3\nalpine_sha256 = " + std::string(64, 'a') + "\npackages = git curl\n", 0644);
            write_file(d + "/os/alpine-y.profile", "[os]\nkind = bundle\nalpine_version = 3.23.0\npackages = git curl\n", 0644);
            fs::create_directories(d + "/dep");
            write_file(d + "/dep/hello.profile", "[dep]\ndescription = says hello\nos = alpine-x\nneeds = sh\n[install]\nrun = echo hello > \"$HOME/hello\"\n", 0644);
            write_file(d + "/dep/wrongos.profile", "[dep]\nos = alpine-y\n[install]\nrun = true\n", 0644);
        }
        ~DataRoot() { std::error_code ec; fs::remove_all(d, ec); }
    };

    test("data files: parsing is strict", [] {
        CHECK(parse_lib("[lib]\ncommands = a b\nneeds = base\npaths = /usr/lib/x*\n", "t", "x").commands.size() == 2);
        THROWS(ProfileError, parse_lib("[lib]\nbogus = 1\n", "t", "x"));
        THROWS(ProfileError, parse_lib("[lib]\npaths = relative\n", "t", "x"));
        THROWS(ProfileError, parse_lib("[lib]\ncommands = ../evil\n", "t", "x"));
        THROWS(ProfileError, parse_lib("[lib]\nname = other\n", "t", "x"));            // must match the file name
        THROWS(ProfileError, parse_os("[os]\nid = a\n", "t", "x"));                      // kind is required
        THROWS(ProfileError, parse_os("[os]\nkind = bundle\nid = a\n", "t", "x"));       // host-only key in a bundle
        THROWS(ProfileError, parse_os("[os]\nkind = host\nid = a\nalpine_version = 3\n", "t", "x"));
        THROWS(ProfileError, parse_os("[os]\nkind = host\nid = a\n[files.x86_64.b]\nbind = rel\n", "t", "x"));
        THROWS(ProfileError, parse_os("[os]\nkind = bundle\nalpine_sha256 = zz\n", "t", "x"));
        DepRecipe dr = parse_dep("[dep]\nos = alp\ndescription = d\nneeds = go git\n[install]\nrun = a\nrun = b $HOME\n", "t", "x");
        CHECK((dr.needs == Strings{"go", "git"}) && (dr.run == Strings{"a", "b $HOME"}) && !dr.digest.empty());
        CHECK(dr.os == "alp" && dr.net == NetMode::None);                                  // restrictive default: no network unless declared
        const std::string base = "[dep]\nos = alp\n";
        CHECK(parse_dep(base + "[install]\nrun = a\n", "t", "x").digest != parse_dep(base + "[install]\nrun = b\n", "t", "x").digest);   // edits are detectable
        CHECK(parse_dep(base + "needs = go\n[install]\nrun = a\n", "t", "x").digest != parse_dep(base + "[install]\nrun = a\n", "t", "x").digest);
        CHECK(parse_dep(base + "[network]\nmode = pasta\n[install]\nrun = a\n", "t", "x").net == NetMode::Pasta);
        CHECK(parse_dep(base + "[network]\nmode = pasta\n[install]\nrun = a\n", "t", "x").digest != parse_dep(base + "[install]\nrun = a\n", "t", "x").digest);
        CHECK(parse_dep("[dep]\nos = other\n[install]\nrun = a\n", "t", "x").digest != parse_dep(base + "[install]\nrun = a\n", "t", "x").digest);
        THROWS(ProfileError, parse_dep("[install]\nrun = a\n", "t", "x"));                  // os is required: musl vs glibc matters
        THROWS(ProfileError, parse_dep(base + "description = nothing to run\n", "t", "x"));
        THROWS(ProfileError, parse_dep(base + "[install]\nbogus = a\n", "t", "x"));
        THROWS(ProfileError, parse_dep(base + "needs = ../x\n[install]\nrun = a\n", "t", "x"));
        THROWS(ProfileError, parse_dep(base + "[install]\nrun = a\n[other]\nk = v\n", "t", "x"));
        THROWS(ProfileError, parse_dep(base + "name = other\n[install]\nrun = a\n", "t", "x"));
        THROWS(ProfileError, parse_dep(base + "[network]\nmode = host\n[install]\nrun = a\n", "t", "x"));   // host shares abstract sockets
        THROWS(ProfileError, parse_dep(base + "[network]\nmode = ivpn\n[install]\nrun = a\n", "t", "x"));
        THROWS(ProfileError, parse_dep("[dep]\nos = ../x\n[install]\nrun = a\n", "t", "x"));
        CHECK(is_exact_alpine_release("3.24.3") && is_exact_alpine_release("v3.24.3"));
        CHECK(!is_exact_alpine_release("latest-stable") && !is_exact_alpine_release("v3.24") && !is_exact_alpine_release("edge") && !is_exact_alpine_release(""));
        std::string branch;
        CHECK(is_exact_alpine_release("3.24.3", &branch) && branch == "v3.24");
        THROWS(ProfileError, parse_os("[os]\nkind = bundle\nalpine_version = latest-stable\n", "t", "x"));          // moving alias: cannot be pinned
        THROWS(ProfileError, parse_os("[os]\nkind = bundle\n", "t", "x"));                                         // version is required
        THROWS(ProfileError, parse_os("[os]\nkind = bundle\nalpine_version = 3.24.3\nalpine_mirror = http://x\n", "t", "x"));   // https only
        CHECK(parse_os("[os]\nkind = bundle\nalpine_version = 3.24.3\n", "t", "x").alpine_version == "3.24.3");
        THROWS(ProfileError, parse_profile("[profile]\nos = ../x\n", "t"));                // names become file names
        CHECK((parse_profile("[libs]\nuse = python3 git\nuse = nvim\n", "t").lib_use == Strings{"python3", "git", "nvim"}));
        OsDef o = parse_os("[os]\nkind = host\nid = Debian\nversion = 12\n[files.x86_64.py.thon]\nbind = /a\nbind = /b\n", "t", "debian-12");
        CHECK(o.id == "debian" && o.files["x86_64"]["py.thon"] == (Strings{"/a", "/b"}));
        OsDef rt = parse_os(render_os(o), "t", "debian-12");                              // render_os round-trips
        CHECK(rt.files == o.files && rt.id == o.id && rt.version == o.version);
        CHECK(valid_data_name("python3") && !valid_data_name("../x") && !valid_data_name("A") && !valid_data_name(""));
    });

    test("data files: host detection and OS matching", [] {
        DataRoot r;
        write_file(r.d + "/os-release", "NAME=\"Fake OS\"\nID=fakeos\nVERSION_ID=\"1.2\"\n", 0644);
        HostId h = read_host_id(r.d + "/os-release");
        CHECK(h.id == "fakeos" && h.version == "1.2" && suggest_os_name(h) == "fakeos-1.2");
        auto m = match_host_os({r.d}, h);                                                  // os version "1" matches host "1.2"
        CHECK(m.has_value() && m->name == "fakeos-1");
        CHECK(!match_host_os({r.d}, HostId{"otheros", "1"}).has_value());
    });

    test("data files: bundle profiles take the OS file, sharing and integrity", [] {
        DataRoot r;
        const std::string a = "[profile]\nname=one\nmode=bundle\ncommand=sh\nos=alpine-x\n";
        Profile p = parse_profile(a, "t"), q = parse_profile("[profile]\nname=two\nmode=bundle\ncommand=sh\nos=alpine-x\n[deps]\nuse = hello hello\n", "t");
        Profile y = parse_profile("[profile]\nname=three\nmode=bundle\ncommand=sh\nos=alpine-y\n", "t");
        for (Profile* x : {&p, &q, &y}) resolve_profile_data(*x, {r.d});
        CHECK(p.alpine_version == "3.24.3" && p.alpine_sha256 == std::string(64, 'a') && p.apk_packages == (Strings{"git", "curl"}) && p.bundle_id == "alpine-x");
        User u = fake_user();
        Paths pa = make_paths(u, p.name, p.bundle_id), pb = make_paths(u, q.name, q.bundle_id);
        CHECK(pa.rootfs == pb.rootfs && pa.home != pb.home);                               // userland shared, $HOME never
        CHECK(bundle_spec(p) == bundle_spec(q) && bundle_spec(p) != bundle_spec(y));       // deps are per profile; version/packages are the OS's
        CHECK(p.deps.empty() && q.deps.size() == 1 && q.deps[0].name == "hello");          // duplicates in `use` install once
        CHECK(q.deps[0].needs == Strings{"sh"} && q.deps[0].run.size() == 1 && !q.deps[0].digest.empty());
        CHECK(dep_stamp(q, q.deps[0]) == dep_stamp(q, q.deps[0]));
        Profile other_home = q;
        other_home.fake_user = "someone-else";
        CHECK(dep_stamp(q, q.deps[0]) != dep_stamp(other_home, q.deps[0]));                // installed into $HOME: the path is part of the stamp
        Profile host = parse_profile("[profile]\nname=h\ncommand=sh\n[deps]\nuse = hello\n", "t");   // mode = host
        THROWS(ProfileError, resolve_profile_data(host, {r.d}));                           // nothing writable to install into
        CHECK(q.deps[0].os == "alpine-x" && q.deps[0].net == NetMode::None);              // taken from the recipe, not assumed
        {   // a dep is the using profile with ONLY the documented overrides: identity, seccomp, terminal, os, home stay the profile's
            Profile busy = q;
            busy.net = NetMode::Ivpn; busy.cwd = CwdMode::Yes; busy.display = DisplayMode::Xephyr; busy.wm = "i3"; busy.audio = true;
            busy.clipboard_out = true; busy.seccomp = "none"; busy.terminal = TermMode::Passthrough; busy.dep_use = {"hello"};
            DepRecipe pasta = q.deps[0];
            pasta.net = NetMode::Pasta;
            Profile dp = dep_profile(busy, pasta);
            CHECK(dp.net == NetMode::Pasta && dp.cwd == CwdMode::None && dp.display == DisplayMode::None && dp.wm.empty());
            CHECK(!dp.audio && !dp.clipboard_out && dp.dep_use.empty() && dp.deps.empty());
            CHECK(dp.seccomp == "none" && dp.terminal == TermMode::Passthrough);              // inherited from the profile, not forced
            CHECK(dp.name == busy.name && dp.fake_user == busy.fake_user && dp.os == busy.os && dp.bundle_id == busy.bundle_id && dp.root == RootMode::Bundle);
        }
        Profile wrong = parse_profile("[profile]\nname=w\nmode=bundle\ncommand=sh\nos=alpine-x\n[deps]\nuse = wrongos\n", "t");
        THROWS(ProfileError, resolve_profile_data(wrong, {r.d}));                          // built for another userland: would not run here
        Profile nodep = parse_profile("[profile]\nname=n\nmode=bundle\ncommand=sh\nos=alpine-x\n[deps]\nuse = nosuchdep\n", "t");
        THROWS(ProfileError, resolve_profile_data(nodep, {r.d}));                          // unknown dep: fail closed
        THROWS(Error, make_paths(u, "x", "../escape"));
        THROWS(Error, bundle_ensure(p, u, pa, false, true));                               // print/check never download: nothing set up yet
        THROWS(ProfileError, parse_profile("[bundle]\nalpine_version = 3.24.3\n", "t"));   // moved to data/os
        THROWS(ProfileError, parse_profile("[bundle]\npackages = git\n", "t"));
        Profile no_os = parse_profile("[profile]\nname=n\nmode=bundle\ncommand=sh\n", "t");
        THROWS(ProfileError, resolve_profile_data(no_os, {r.d}));                          // bundle profiles must name their os
        Profile host_os = parse_profile("[profile]\nname=n\nmode=bundle\ncommand=sh\nos=fakeos-1\n", "t");
        THROWS(ProfileError, resolve_profile_data(host_os, {r.d}));                        // wrong kind
        Profile missing = parse_profile("[profile]\nname=n\nmode=bundle\ncommand=sh\nos=nope\n", "t");
        THROWS(ProfileError, resolve_profile_data(missing, {r.d}));
        // integrity of the installed bundle
        char tmpl[] = "/tmp/hf-bun-XXXXXX";
        std::string d = mkdtemp(tmpl);
        Paths bp = pa; bp.bundle = d;
        write_file(d + "/spec.stamp", bundle_spec(p) + "\n", 0600);
        write_file(d + "/tarball.sha256", std::string(64, 'a') + "\n", 0600);
        bundle_verify(p, bp);                                                              // built from this os: fine
        bundle_verify(q, bp);                                                              // ... also for the other profile sharing it
        THROWS(Error, bundle_verify(y, bp));                                               // a different os definition under the same bundle dir
        write_file(d + "/tarball.sha256", std::string(64, 'c') + "\n", 0600);
        THROWS(Error, bundle_verify(p, bp));                                               // installed tarball differs from the pinned hash
        fs::remove_all(d);
    });

    test("data files: host profiles resolve libs through the OS file list", [] {
        DataRoot r;
        const std::string head = "[profile]\nname=t\ncommand=sh\nos=fakeos-1\n[bin]\nallow = sh\n";
        Profile p = parse_profile(head + "[libs]\nuse = shell\n", "t");
        resolve_profile_data(p, {r.d});
        CHECK((p.lib_binds == Strings{"/usr/lib/ld.so", "/usr/lib/libc.so.6", "/usr/lib/libtinfo.so.6"}));   // base + shell, deduplicated, sorted
        Profile full = parse_profile(head + "[fs]\nlibs = full\n", "t");
        resolve_profile_data(full, {r.d});
        CHECK(full.lib_binds.empty());                                                     // full needs no lock
        Profile uncovered = parse_profile("[profile]\nname=t\ncommand=sh\nos=fakeos-1\n[bin]\nallow = sh ls\n[libs]\nuse = shell\n", "t");
        THROWS(ProfileError, resolve_profile_data(uncovered, {r.d}));                      // `ls` is provided by no used lib
        Profile nouse = parse_profile(head, "t");
        THROWS(ProfileError, resolve_profile_data(nouse, {r.d}));                          // sh is not covered without `use`
        Profile unknown = parse_profile(head + "[libs]\nuse = nosuchlib\n", "t");
        THROWS(ProfileError, resolve_profile_data(unknown, {r.d}));
        write_file(r.d + "/lib/extra.profile", "[lib]\ncommands = ls\n", 0644);               // a lib with no lock section in the OS file
        Profile nolock = parse_profile(head + "[libs]\nuse = shell extra\n", "t");
        THROWS(ProfileError, resolve_profile_data(nolock, {r.d}));
        Profile wrong = parse_profile("[profile]\nname=t\ncommand=sh\nos=alpine-x\n[bin]\nallow = sh\n[libs]\nuse = shell\n", "t");
        THROWS(ProfileError, resolve_profile_data(wrong, {r.d}));                          // a bundle os is not a host os
        Profile detect = parse_profile(head + "[libs]\nuse = shell\n", "t");              // no os pin and nothing matches this host
        detect.os.clear();
        THROWS(ProfileError, resolve_profile_data(detect, {r.d + "/nonexistent"}));
    });

    test("cli: option parsing", [] {
        Cli c = parse_args("run", {"-y", "--net=pasta", "--cwd=/proj", "prof", "--", "sh", "-c", "echo --net=host -y"});
        CHECK(c.cmd == "run" && c.yes && c.run.yes);
        CHECK(c.run.net == NetMode::Pasta && c.run.cwd == fs::path("/proj"));
        CHECK((c.pos == Strings{"prof"}));
        CHECK((c.run.command == Strings{"sh", "-c", "echo --net=host -y"}));        // after `--` nothing is interpreted
        Cli b = parse_args("run", {"p", "--refresh", "-v"});
        CHECK(b.refresh && b.run.refresh && b.verbose && (b.pos == Strings{"p"}) && b.run.command.empty());
        CHECK(parse_args("libs", {"--check", "debian-12"}).check);
        Cli n = parse_args("print", {"-n", "--no-cwd", "--wg=/x.conf", "p"});
        CHECK(n.run.dry && n.run.no_cwd && n.run.wg_conf == std::string("/x.conf"));
        for (const char* net : {"none", "pasta", "host", "ivpn"}) CHECK(parse_args("run", {std::string("--net=") + net, "p"}).run.net.has_value());
        THROWS(Error, parse_args("run", {"--bogus", "p"}));
        THROWS(Error, parse_args("run", {"--net=bogus", "p"}));
        CHECK(!handle_meta({"run"}).has_value());                                    // real commands are not meta commands
    });

    test("ivpn: handshake diagnosis", [] {
        const std::string fwd =
            "Chain FORWARD (policy DROP 0 packets, 0 bytes)\n"
            "num      pkts      bytes target     prot opt in     out     source               destination\n"
            "1           3        252 ACCEPT     udp  --  hfh135 *       10.200.135.2         198.51.100.7         udp dpt:2049 /* holdfast:hf-x */\n"
            "2           0          0 ACCEPT     udp  --  *      hfh135  198.51.100.7         10.200.135.2         udp spt:2049 ctstate RELATED,ESTABLISHED /* holdfast:hf-x */\n"
            "3           7          9 DROP       0    --  hfh135 *       0.0.0.0/0            0.0.0.0/0            /* holdfast:hf-x */\n";
        CHECK(iptables_hits(fwd, "ACCEPT", "hfh135", "*") == 3);
        CHECK(iptables_hits(fwd, "ACCEPT", "*", "hfh135") == 0);
        CHECK(iptables_hits(fwd, "DROP", "hfh135", "*") == 7);
        CHECK(iptables_hits(fwd, "ACCEPT", "nope", "*") == -1);                          // no such rule
        CHECK(iptables_hits("", "ACCEPT", "*", "*") == -1);
        CHECK(has_nft_forward_drop("table inet filter {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n\t}\n}\n"));
        CHECK(!has_nft_forward_drop("hook forward priority filter; policy accept;\nhook input priority filter; policy drop;\n"));
        CHECK(wg_transfer_rx("XDU6Syq1DY82IMatsHV0x/TAtbLiRwh/SdFCXlEn40c=\t0\t444\n") == 0);             // the real failing run
        CHECK(wg_transfer_rx("KEY\t1234\t99") == 1234);
        CHECK(wg_transfer_rx("") == -1 && wg_transfer_rx("garbage") == -1 && wg_transfer_rx("KEY\tx\ty") == -1);
        CHECK(config_has_preshared_key("[Peer]\nPublicKey = a\nPresharedKey = b\n") && config_has_preshared_key("  presharedkey=b\n"));
        CHECK(!config_has_preshared_key("[Peer]\nPublicKey = a\n# PresharedKey = b\n"));

        auto why = [](const HandshakeTrail& t) { return explain_handshake_failure(t, "hfh135", "198.51.100.7", 2049); };
        auto has = [](const std::string& s, const char* part) { return s.find(part) != std::string::npos; };
        HandshakeTrail t;
        t.sent = 4; t.forwarded = 0; t.replies = 0; t.delivered = 0;                      // dies at the host's forward hook
        CHECK(has(why(t), "never reach holdfast's FORWARD rule") && !has(why(t), "nft insert rule"));
        t.nft_forward_drop = true;                                                        // ... and an nftables drop chain exists
        CHECK(has(why(t), "nft insert rule inet filter forward iifname \"hfh*\" ip daddr 198.51.100.7 udp dport 2049 accept"));
        CHECK(has(why(t), "oifname \"hfh*\" ct state established,related accept"));
        t.forwarded = 4;                                                                  // left the machine, nothing came back
        CHECK(has(why(t), "nothing came back") && has(why(t), "198.51.100.7:2049"));
        t.replies = 4;                                                                    // came back to the host, not into the namespace
        CHECK(has(why(t), "not the namespace") && has(why(t), "rp_filter"));
        t.delivered = 4;                                                                  // delivered, yet no handshake
        CHECK(has(why(t), "stale") && !has(why(t), "accepted none"));                    // wg's own rx unknown: generic advice
        t.wg_rx_bytes = 0;                                                                // WireGuard itself accepted nothing: the user's real case
        t.config_has_psk = 1;
        CHECK(has(why(t), "accepted none of them") && has(why(t), "has received 0 bytes") && has(why(t), "this config has a PresharedKey line"));
        CHECK(has(why(t), "tcpdump -ni hfn135 -vv udp"));                                 // the exact capture command, interface derived
        t.config_has_psk = 0;
        CHECK(has(why(t), "NO PresharedKey line"));
        t.wg_rx_bytes = 512;                                                              // it did receive data: no "discarded" claim
        CHECK(!has(why(t), "accepted none") && has(why(t), "WireGuard has received data"));
        t.sent = 0;
        CHECK(has(why(t), "never sent a handshake"));
        t.sent = -1;
        CHECK(has(why(t), "could not be read"));
        CHECK(has(why(t), "sent from the namespace") && has(why(t), "?"));                // unreadable counters print as ?
    });

    test("shipped data files all parse", [] {
        if (!fs::is_directory("data/profile")) return;                                    // only when run from the repository root
        auto each = [](const char* dir, const std::function<void(const std::string&, const std::string&, const std::string&)>& parse) {
            for (const auto& e : fs::directory_iterator(dir)) {
                if (e.path().extension() != ".profile") continue;
                try { parse(read_file(e.path()), e.path().string(), e.path().stem().string()); }
                catch (const Error& ex) { CHECK(!"shipped file must parse"); std::printf("  %s: %s\n", e.path().c_str(), ex.what()); }
            }
        };
        each("data/profile", [](const std::string& t, const std::string& o, const std::string&) { parse_profile(t, o); });
        each("data/lib", [](const std::string& t, const std::string& o, const std::string& n) { parse_lib(t, o, n); });
        each("data/os", [](const std::string& t, const std::string& o, const std::string& n) { parse_os(t, o, n); });
        each("data/dep", [](const std::string& t, const std::string& o, const std::string& n) { parse_dep(t, o, n); });
        Profile lw = parse_profile(read_file("data/profile/librewolf-ivpn.profile"), "librewolf-ivpn");
        bool quiet_userns = false;
        for (const auto& [k, v] : lw.env_set) if (k == "MOZ_ASSUME_USER_NS" && v == "0") quiet_userns = true;
        CHECK(quiet_userns && lw.disable_userns);                                         // namespaces stay forbidden AND Firefox is told so
    });

    test("doctor: feature evaluation", [] {
        auto find = [](const std::vector<FeatureStatus>& v, const std::string& name) {
            for (const auto& f : v) if (f.name == name) return f;
            return FeatureStatus{};
        };
        const std::set<std::string> some = {"pasta", "curl", "tar", "gzip", "sha256sum", "wl-copy"};
        auto fs_ = evaluate_features([&](const std::string& t) { return some.count(t) != 0; });
        CHECK(find(fs_, "net = pasta").ready());
        CHECK(find(fs_, "bundle profiles").ready());
        CHECK(find(fs_, "clipboard = out").ready());                                       // "xclip|wl-copy": either one is enough
        FeatureStatus ivpn = find(fs_, "net = ivpn");
        CHECK(!ivpn.ready() && std::find(ivpn.missing.begin(), ivpn.missing.end(), "wg-quick") != ivpn.missing.end());
        CHECK(std::find(ivpn.missing.begin(), ivpn.missing.end(), "ip6tables") == ivpn.missing.end());   // optional tools never block
        CHECK(std::find(ivpn.missing_optional.begin(), ivpn.missing_optional.end(), "ip6tables") != ivpn.missing_optional.end());
        CHECK(!find(fs_, "display = xephyr").ready());
        auto none = evaluate_features([](const std::string&) { return false; });
        CHECK(none.size() == fs_.size());
        FeatureStatus clip = find(none, "clipboard = out");
        CHECK(!clip.ready() && clip.missing == Strings{"xclip|wl-copy"});
        FeatureStatus bundle = find(none, "bundle profiles");
        CHECK(bundle.missing.size() == 5 && bundle.missing[0] == "pasta");                 // pasta is listed once, first
        auto all = evaluate_features([](const std::string&) { return true; });
        for (const auto& f : all) CHECK(f.ready() && f.missing_optional.empty());
    });

    test("--debug: a shell in the exact sandbox", [] {
        CHECK(parse_args("run", {"--debug", "p"}).run.debug);
        CHECK(!parse_args("run", {"p"}).run.debug);
        auto host = [](const std::string& bins) { return parse_profile("[profile]\nname=t\ncommand=nvim\n[bin]\nallow = " + bins + "\n", "t"); };
        CHECK((debug_shell(host("nvim bash sh git")) == Strings{"bash"}));                  // bash preferred
        CHECK((debug_shell(host("nvim sh")) == Strings{"sh"}));                             // else sh
        CHECK((debug_shell(host("nvim sh=/usr/bin/dash")) == Strings{"sh"}));               // name=/path tokens count
        THROWS(Error, debug_shell(host("nvim git")));                                       // never adds a binary to the sandbox
        THROWS(Error, debug_shell(host("bashful")));                                        // exact names only
        Profile b = parse_profile("[profile]\nname=t\nmode=bundle\ncommand=lazygit\n", "t");
        Strings s = debug_shell(b);
        CHECK(s.size() == 3 && s[0] == "/bin/sh" && s[1] == "-c" && s[2].find("exec bash") != std::string::npos && s[2].find("exec sh") != std::string::npos);
    });

    test("style: colour is off on request", [] {
        setenv("NO_COLOR", "1", 1);
        Style off = style_for(stdout);
        CHECK(std::string(off.b).empty() && std::string(off.r).empty() && std::string(off.g).empty() && std::string(off.x).empty());
        unsetenv("NO_COLOR");
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
        for (const char* trust : {"/etc/ssl", "/usr/share/ca-certificates", "/etc/pki"})      // CA roots, not just the pointers to them
            if (fs::exists(trust)) CHECK(has_seq(a, {"--ro-bind-try", trust, trust}));
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
        // libs = minimal: exactly the files resolve_profile_data() took from the OS lock, and none with binaries is an error
        std::string lib = d + "/libfoo.so.1";
        write_file(lib, "x", 0644);
        Profile m = parse_profile("[profile]\nname=t\ncommand=sh\n[bin]\nallow = sh\n[home]\nuser=box\n", "t");
        m.lib_binds = {lib};
        Plan pm = build_plan(m, c);
        CHECK(has_seq(pm.b.args(), {"--ro-bind", fs::canonical(lib).string(), lib}));
        CHECK(!has_seq(pm.b.args(), {"--ro-bind", "/usr/lib", "/usr/lib"}));
        Profile e = parse_profile("[profile]\nname=t\ncommand=sh\n[bin]\nallow = sh\n[home]\nuser=box\n", "t");
        THROWS(ProfileError, build_plan(e, c));
        THROWS(ProfileError, parse_profile("[libs]\nbind = /usr/lib/libc.so.6\n", "t"));   // concrete paths no longer belong in profiles
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

    test("plan: --clearenv comes before every --setenv (DISPLAY must survive)", [] {
        char tmpl[] = "/tmp/hf-plan-env-XXXXXX";
        std::string d = mkdtemp(tmpl);
        User u = fake_user(); u.home = d + "/home"; fs::create_directories(u.home);
        u.runtime_dir = d + "/run";
        Policy pol(u, {});
        Profile p = parse_profile("[profile]\nname=t\ncommand=sh\n[bin]\nallow = sh\n[fs]\nlibs=full\n[home]\nuser=box\n[env]\nset = FOO=bar\n", "t");
        PlanCtx c; c.user = u; c.paths = make_paths(u, "t"); c.paths.data = d + "/data"; c.paths.home = d + "/data/home";
        c.policy = &pol; c.session = d + "/sess"; fs::create_directories(c.session);
        c.display = DisplayInfo{":90", "/tmp/.X11-unix/X90", "", false};                  // what a Xephyr profile gets
        const Strings a = build_plan(p, c).b.args();
        size_t clear = a.size(), first_set = a.size(), display = a.size();
        for (size_t i = 0; i < a.size(); ++i) {
            if (a[i] == "--clearenv" && clear == a.size()) clear = i;
            if (a[i] == "--setenv") { if (first_set == a.size()) first_set = i; if (i + 1 < a.size() && a[i + 1] == "DISPLAY") display = i; }
        }
        CHECK(clear < a.size() && display < a.size() && first_set < a.size());
        CHECK(clear < first_set && clear < display);                                      // bwrap applies these in order: a later --clearenv would wipe DISPLAY
        CHECK(std::count(a.begin(), a.end(), "--clearenv") == 1);
        CHECK(has_seq(a, {"--setenv", "DISPLAY", ":90"}) && has_seq(a, {"--setenv", "FOO", "bar"}));
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
