#include "core/launch.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <regex>

#include "ui/termfilter.hpp"
#include "util/log.hpp"

namespace hf {

fs::path find_bwrap() {
    if (auto p = which("bwrap")) return *p;
    throw Error("bubblewrap (bwrap) not found; install it (e.g. apt install bubblewrap)");
}

fs::path find_pasta() {
    if (auto p = which("pasta")) return *p;
    throw Error("pasta not found; install passt (apt/dnf/pacman: passt) or choose another [network] mode");
}

std::string pasta_resolv_conf() { return cat("nameserver ", kPastaDns, "\n"); }

Strings pasta_argv(const fs::path& pasta, const Strings& inner) {
    // -t/-u: no inbound port forwarding; -T/-U: sandbox cannot connect to host loopback services;
    // --no-map-gw: the gateway address does not reach the host either.
    Strings v = {pasta.string(), "--config-net", "--no-map-gw", "-t", "none", "-u", "none", "-T", "none", "-U", "none",
                 "--dns-forward", kPastaDns, "--"};
    v.insert(v.end(), inner.begin(), inner.end());
    return v;
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

// ---- filtered terminal ---------------------------------------------------------------------------------

static volatile sig_atomic_t g_winch = 0;
static void on_winch(int) { g_winch = 1; }

namespace {

bool write_all(int fd, const char* p, size_t n) {          // to the real terminal: block until done
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) { pollfd pf{fd, POLLOUT, 0}; poll(&pf, 1, 100); continue; }
            return false;
        }
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

void write_bounded(int fd, const char* p, size_t n) {      // to the pty: never deadlock against a child that stopped reading
    for (int tries = 0; n > 0 && tries < 50;) {
        ssize_t w = write(fd, p, n);
        if (w > 0) { p += w; n -= static_cast<size_t>(w); continue; }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && errno == EAGAIN) { pollfd pf{fd, POLLOUT, 0}; poll(&pf, 1, 20); ++tries; continue; }
        return;
    }
}

struct RawTerm {                                            // restores the user's terminal on every exit path
    termios saved{};
    bool active = false;
    bool enter() {
        if (tcgetattr(STDIN_FILENO, &saved) != 0) return false;
        termios raw = saved;
        cfmakeraw(&raw);
        active = tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0;
        return active;
    }
    ~RawTerm() { if (active) tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved); }   // FLUSH: drop replies still in flight
};

int exit_code(int status) {
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

}  // namespace

bool terminal_proxy_possible() { return isatty(STDIN_FILENO) && isatty(STDOUT_FILENO); }

int run_sandbox(const Strings& argv, bool filter, bool wrapper_makes_ctty) {
    if (!filter || !terminal_proxy_possible()) return run_with_signals(argv);

    termios tio{};
    winsize ws{};
    if (tcgetattr(STDIN_FILENO, &tio) != 0)
        throw Error("cannot read the terminal attributes; set `terminal = passthrough` in [profile] to run without the filter");
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws);

    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    char sname[128];
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0 || ptsname_r(master, sname, sizeof sname) != 0)
        throw Error(cat("cannot allocate a pty: ", std::strerror(errno)));
    int slave = open(sname, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) throw Error(cat("cannot open the pty: ", std::strerror(errno)));
    tcsetattr(slave, TCSANOW, &tio);                          // same line discipline settings the user's terminal has
    ioctl(slave, TIOCSWINSZ, &ws);
    fcntl(master, F_SETFL, fcntl(master, F_GETFL) | O_NONBLOCK);

    std::vector<char*> av;
    for (const auto& s : argv) av.push_back(const_cast<char*>(s.c_str()));
    av.push_back(nullptr);

    struct sigaction sa{}, wa{}, ign{}, old_t{}, old_h{}, old_i{}, old_w{};
    sa.sa_handler = forward;
    sigemptyset(&sa.sa_mask);
    wa.sa_handler = on_winch;                                  // no SA_RESTART: poll() must wake up
    sigemptyset(&wa.sa_mask);
    ign.sa_handler = swallow;
    sigemptyset(&ign.sa_mask);
    sigaction(SIGTERM, &sa, &old_t);
    sigaction(SIGHUP, &sa, &old_h);
    sigaction(SIGINT, &ign, &old_i);
    sigaction(SIGWINCH, &wa, &old_w);

    pid_t pid = fork();
    if (pid < 0) throw Error("fork failed");
    if (pid == 0) {
        if (!wrapper_makes_ctty) {
            setsid();
            ioctl(slave, TIOCSCTTY, 0);                       // the pty slave becomes the sandbox's controlling terminal
        }                                                     // else: argv ends in `setsid -w -c`, which does this AFTER sudo has run
        const bool err_tty = isatty(STDERR_FILENO);
        dup2(slave, STDIN_FILENO);
        dup2(slave, STDOUT_FILENO);
        if (err_tty) dup2(slave, STDERR_FILENO);
        execvp(av[0], av.data());
        _exit(127);
    }
    close(slave);
    g_child = pid;

    int status = 0;
    bool reaped = false;
    {
        RawTerm raw;
        raw.enter();
        TermFilter filt;
        char buf[16384];
        bool in_open = true, master_open = true;
        auto pump = [&]() {                                    // pty -> filter -> terminal
            ssize_t r = read(master, buf, sizeof buf);
            if (r > 0) {
                std::string o = filt.feed(buf, static_cast<size_t>(r));
                if (!write_all(STDOUT_FILENO, o.data(), o.size())) { kill(pid, SIGHUP); master_open = false; }
                return true;
            }
            if (r < 0 && (errno == EINTR || errno == EAGAIN)) return true;
            master_open = false;                               // EIO: every slave fd is closed
            return false;
        };
        while (master_open && !reaped) {
            if (g_winch) {
                g_winch = 0;
                winsize w{};
                if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) ioctl(master, TIOCSWINSZ, &w);   // kernel signals the child
            }
            pollfd fds[2] = {{in_open ? STDIN_FILENO : -1, POLLIN, 0}, {master, POLLIN, 0}};
            int n = poll(fds, 2, 200);
            if (n < 0 && errno != EINTR) break;
            if (n > 0) {
                if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) pump();
                if (in_open && (fds[0].revents & POLLIN)) {
                    ssize_t r = read(STDIN_FILENO, buf, sizeof buf);
                    if (r > 0) write_bounded(master, buf, static_cast<size_t>(r));
                    else if (!(r < 0 && (errno == EINTR || errno == EAGAIN))) in_open = false;
                } else if (in_open && (fds[0].revents & (POLLHUP | POLLERR))) {
                    in_open = false;
                }
            }
            if (waitpid(pid, &status, WNOHANG) == pid) reaped = true;
        }
        while (master_open && pump()) {}                        // what the child printed last (non-blocking)
        const std::string rs = filt.restore();                  // switch off modes a dead sandbox left behind
        write_all(STDOUT_FILENO, rs.data(), rs.size());
    }                                                           // ~RawTerm: cooked mode again, pending input flushed
    if (!reaped)
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    close(master);
    g_child = 0;
    sigaction(SIGTERM, &old_t, nullptr);
    sigaction(SIGHUP, &old_h, nullptr);
    sigaction(SIGINT, &old_i, nullptr);
    sigaction(SIGWINCH, &old_w, nullptr);
    return exit_code(status);
}

}  // namespace hf
