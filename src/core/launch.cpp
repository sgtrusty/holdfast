#include "core/launch.hpp"

#include <csignal>
#include <regex>

#include "util/log.hpp"

namespace hf {

fs::path find_bwrap() {
    if (auto p = which("bwrap")) return *p;
    throw Error("bubblewrap (bwrap) not found; install it (e.g. apt install bubblewrap)");
}

bool BwrapVersion::at_least(int a, int b, int c) const {
    if (major != a) return major > a;
    if (minor != b) return minor > b;
    return patch >= c;
}

BwrapVersion bwrap_version(const fs::path& bwrap) {
    auto r = capture({bwrap.string(), "--version"});
    std::smatch m;
    BwrapVersion v;
    if (std::regex_search(r.out, m, std::regex(R"((\d+)\.(\d+)\.(\d+))"))) {
        v.major = std::stoi(m[1]); v.minor = std::stoi(m[2]); v.patch = std::stoi(m[3]);
    }
    return v;
}

Strings launcher_argv(const fs::path& bwrap, const fs::path& session, const ArgBuilder& b, const fs::path& seccomp) {
    fs::path args = session / "bwrap.args";
    write_file(args, b.serialize(), 0600);
    static const char* script =
        "a=$1; s=$2; b=$3; shift 3\n"
        "exec 3<\"$a\" || exit 126\n"
        "if [ -n \"$s\" ]; then exec 4<\"$s\" || exit 126; exec \"$b\" --seccomp 4 --args 3 -- \"$@\"; fi\n"
        "exec \"$b\" --args 3 -- \"$@\"\n";
    Strings v = {"/bin/sh", "-c", script, "holdfast", args.string(), seccomp.string(), bwrap.string()};
    v.insert(v.end(), b.cmd().begin(), b.cmd().end());
    return v;
}

static volatile sig_atomic_t g_child = 0;
static void forward(int sig) { if (g_child > 0) kill(static_cast<pid_t>(g_child), sig); }
static void swallow(int) {}

int run_with_signals(const Strings& argv) {
    struct sigaction sa{}, old_t{}, old_h{}, old_i{}, ign{};
    sa.sa_handler = forward;
    sigemptyset(&sa.sa_mask);
    ign.sa_handler = swallow;     // Ctrl-C reaches the foreground process group directly
    sigemptyset(&ign.sa_mask);
    sigaction(SIGTERM, &sa, &old_t);
    sigaction(SIGHUP, &sa, &old_h);
    sigaction(SIGINT, &ign, &old_i);
    pid_t pid = spawn(argv, false);
    g_child = pid;
    int rc = wait_child(pid);
    g_child = 0;
    sigaction(SIGTERM, &old_t, nullptr);
    sigaction(SIGHUP, &old_h, nullptr);
    sigaction(SIGINT, &old_i, nullptr);
    return rc;
}

}  // namespace hf
