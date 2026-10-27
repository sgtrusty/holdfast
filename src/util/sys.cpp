#include "util/sys.hpp"

#include <fcntl.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>

#include "util/log.hpp"

namespace hf {

bool is_root() { return geteuid() == 0; }

// When running as root on behalf of SUDO_USER, files we create for the sandbox must be
// owned by that user (the launcher runs with dropped privileges and has to read them).
static uid_t g_own_uid = static_cast<uid_t>(-1);
static gid_t g_own_gid = static_cast<gid_t>(-1);
static void own(const fs::path& p) {
    if (geteuid() == 0 && g_own_uid != static_cast<uid_t>(-1)) {
        if (lchown(p.c_str(), g_own_uid, g_own_gid) != 0) {}
    }
}

User resolve_user() {
    const char* su = std::getenv("SUDO_USER");
    passwd* pw = nullptr;
    if (geteuid() == 0) {
        if (su && *su) pw = getpwnam(su);
        if (!pw) throw Error("refusing to run as plain root; run as your normal user (sudo is used only for network helpers)");
    } else {
        pw = getpwuid(getuid());
    }
    if (!pw) throw Error("cannot resolve current user");
    User u;
    u.uid = pw->pw_uid;
    u.gid = pw->pw_gid;
    u.name = pw->pw_name;
    u.home = pw->pw_dir;
    u.runtime_dir = fs::path("/run/user") / std::to_string(u.uid);
    if (geteuid() == 0) { g_own_uid = u.uid; g_own_gid = u.gid; }
    return u;
}

static void fill_argv(const Strings& in, std::vector<char*>& out) {
    out.clear();
    for (const auto& s : in) out.push_back(const_cast<char*>(s.c_str()));
    out.push_back(nullptr);
}

RunResult run(const RunOpts& o) {
    if (o.argv.empty()) throw Error("run(): empty argv");
    log::debug("exec: " + [&] { Strings q; for (auto& a : o.argv) q.push_back(shell_quote(a)); return join(q, " "); }());
    int in[2] = {-1, -1}, out[2] = {-1, -1};
    if (!o.stdin_data.empty() && pipe2(in, O_CLOEXEC) != 0) throw Error("pipe2 failed");
    if (o.capture && pipe2(out, O_CLOEXEC) != 0) throw Error("pipe2 failed");
    std::vector<char*> av;
    fill_argv(o.argv, av);

    pid_t pid = fork();
    if (pid < 0) throw Error("fork failed");
    if (pid == 0) {
        int dn = o.quiet ? open("/dev/null", O_RDWR) : -1;
        if (in[0] >= 0) dup2(in[0], 0); else if (o.quiet) dup2(dn, 0);
        if (out[1] >= 0) dup2(out[1], 1); else if (o.quiet) dup2(dn, 1);
        if (o.merge_stderr && out[1] >= 0) dup2(out[1], 2);
        else if (o.quiet) dup2(dn, 2);
        execvp(av[0], av.data());
        _exit(127);
    }
    if (in[0] >= 0) close(in[0]);
    if (out[1] >= 0) close(out[1]);
    if (in[1] >= 0) {
        size_t off = 0;
        while (off < o.stdin_data.size()) {
            ssize_t n = write(in[1], o.stdin_data.data() + off, o.stdin_data.size() - off);
            if (n < 0) { if (errno == EINTR) continue; break; }
            off += static_cast<size_t>(n);
        }
        close(in[1]);
    }
    RunResult r;
    if (out[0] >= 0) {
        char buf[4096];
        for (;;) {
            ssize_t n = read(out[0], buf, sizeof buf);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            r.out.append(buf, static_cast<size_t>(n));
        }
        close(out[0]);
    }
    r.code = wait_child(pid);
    return r;
}

RunResult run(const Strings& argv, bool quiet) {
    RunOpts o; o.argv = argv; o.quiet = quiet;
    return run(o);
}

RunResult capture_all(const Strings& argv) {
    RunOpts o; o.argv = argv; o.capture = true; o.quiet = true; o.merge_stderr = true;
    return run(o);
}

RunResult capture(const Strings& argv) {
    RunOpts o; o.argv = argv; o.capture = true; o.quiet = true;
    return run(o);
}

pid_t spawn(const Strings& argv, bool quiet) {
    std::vector<char*> av;
    fill_argv(argv, av);
    pid_t pid = fork();
    if (pid < 0) throw Error("fork failed");
    if (pid == 0) {
        if (quiet) {
            int dn = open("/dev/null", O_RDWR);
            dup2(dn, 0); dup2(dn, 1); dup2(dn, 2);
        }
        execvp(av[0], av.data());
        _exit(127);
    }
    return pid;
}

int wait_child(pid_t pid) {
    int st = 0;
    for (;;) {
        pid_t r = waitpid(pid, &st, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) return -1;
        break;
    }
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return -1;
}

bool child_alive(pid_t pid) {
    siginfo_t si{};
    si.si_pid = 0;
    if (waitid(P_PID, static_cast<id_t>(pid), &si, WEXITED | WNOHANG | WNOWAIT) != 0) return false;
    return si.si_pid == 0;
}

Strings as_root(Strings argv) {
    if (is_root()) return argv;
    argv.insert(argv.begin(), "sudo");
    return argv;
}

Strings as_user(const User& u, Strings argv) {
    if (!is_root()) return argv;
    Strings p = {"setpriv", cat("--reuid=", u.uid), cat("--regid=", u.gid), "--init-groups", "--"};
    p.insert(p.end(), argv.begin(), argv.end());
    return p;
}

// ---- sudo keepalive: cleanup at exit needs a valid ticket --------------------
static std::thread g_ka;
static std::mutex g_ka_mu;
static std::condition_variable g_ka_cv;
static bool g_ka_stop = false;

static bool g_ticket_ours = false;   // we asked for the password, so we revoke the ticket when done

void sudo_acquire() {
    if (is_root()) return;
    const bool had_ticket = run({"sudo", "-n", "-v"}, true).ok();      // valid before we started: not ours to revoke
    if (!had_ticket) {
        log::info("sudo is needed for the network setup (asked once, revoked again afterwards)");
        if (!run({"sudo", "-v"}).ok()) throw Error("sudo authentication failed");
    }
    g_ticket_ours = !had_ticket;
    sudo_keepalive_start();
}

void sudo_keepalive_start() {
    if (is_root() || g_ka.joinable()) return;
    g_ka_stop = false;
    g_ka = std::thread([] {
        std::unique_lock<std::mutex> l(g_ka_mu);
        while (!g_ka_cv.wait_for(l, std::chrono::seconds(45), [] { return g_ka_stop; })) {
            l.unlock();
            run({"sudo", "-n", "-v"}, true);
            l.lock();
        }
    });
}
void sudo_keepalive_stop() {
    if (g_ka.joinable()) {
        { std::lock_guard<std::mutex> l(g_ka_mu); g_ka_stop = true; }
        g_ka_cv.notify_all();
        g_ka.join();
    }
    if (g_ticket_ours) {                                                // de-escalate: nothing else may ride on our ticket
        g_ticket_ours = false;
        if (run({"sudo", "-k"}, true).ok()) log::debug("sudo ticket revoked");
    }
}

// ---- files -------------------------------------------------------------------
std::optional<fs::path> which(const std::string& name, const std::string& path_env) {
    if (name.empty() || name.find('/') != std::string::npos) return std::nullopt;
    std::string pe = path_env;
    if (pe.empty()) { const char* e = std::getenv("PATH"); pe = e ? e : "/usr/local/bin:/usr/bin:/bin"; }
    std::stringstream ss(pe);
    std::string dir;
    while (std::getline(ss, dir, ':')) {
        if (dir.empty()) continue;
        fs::path c = fs::path(dir) / name;
        if (access(c.c_str(), X_OK) == 0 && fs::is_regular_file(c)) return c;
    }
    return std::nullopt;
}

std::string read_file(const fs::path& p, size_t max_bytes) {
    int fd = open(p.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) throw Error(cat("cannot open ", p.string(), ": ", std::strerror(errno)));
    std::string out;
    char buf[8192];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
        if (out.size() > max_bytes) { close(fd); throw Error("file too large: " + p.string()); }
    }
    close(fd);
    return out;
}

void write_file(const fs::path& p, const std::string& data, mode_t mode) {
    int fd = open(p.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, mode);
    if (fd < 0) throw Error(cat("cannot write ", p.string(), ": ", std::strerror(errno)));
    size_t off = 0;
    while (off < data.size()) {
        ssize_t n = write(fd, data.data() + off, data.size() - off);
        if (n < 0) { if (errno == EINTR) continue; close(fd); throw Error("write failed: " + p.string()); }
        off += static_cast<size_t>(n);
    }
    fchmod(fd, mode);
    if (geteuid() == 0 && g_own_uid != static_cast<uid_t>(-1) && fchown(fd, g_own_uid, g_own_gid) != 0) {}
    close(fd);
}

void make_private_dir(const fs::path& p) {
    std::error_code ec;
    // chown every newly created component, not only the leaf
    std::vector<fs::path> todo;
    for (fs::path q = p; !q.empty() && q != q.parent_path() && !fs::exists(q); q = q.parent_path()) todo.push_back(q);
    fs::create_directories(p, ec);
    if (ec) throw Error(cat("cannot create ", p.string(), ": ", ec.message()));
    for (auto& q : todo) own(q);
    chmod(p.c_str(), 0700);
}

void make_secure_dir(const fs::path& p) {
    std::error_code ec;
    if (p.has_parent_path()) fs::create_directories(p.parent_path(), ec);
    if (mkdir(p.c_str(), 0700) != 0 && errno != EEXIST) throw Error(cat("cannot create ", p.string(), ": ", std::strerror(errno)));
    own(p);
    struct stat st{};
    // lstat: a pre-planted symlink or a directory owned by someone else must never be trusted.
    if (lstat(p.c_str(), &st) != 0 || !S_ISDIR(st.st_mode))
        throw Error(cat(p.string(), " is not a plain directory; remove it and retry"));
    if (st.st_uid != geteuid() && st.st_uid != g_own_uid)
        throw Error(cat(p.string(), " is owned by another user (uid ", st.st_uid, "); refusing to use it"));
    if (chmod(p.c_str(), 0700) != 0) throw Error(cat("cannot chmod ", p.string(), ": ", std::strerror(errno)));
}

std::string sha256_file(const fs::path& p) {
    auto r = capture({"sha256sum", "--", p.string()});
    if (!r.ok() || r.out.size() < 64) throw Error("sha256sum failed for " + p.string());
    return lower(r.out.substr(0, 64));
}

std::string sha256_str(const std::string& s) {
    RunOpts o; o.argv = {"sha256sum"}; o.stdin_data = s.empty() ? std::string(1, '\n') : s;
    o.capture = true; o.quiet = true;
    auto r = run(o);
    if (!r.ok() || r.out.size() < 64) throw Error("sha256sum failed");
    return lower(r.out.substr(0, 64));
}

FileLock::~FileLock() { if (fd_ >= 0) close(fd_); }

bool FileLock::try_acquire(const fs::path& p) {
    int fd = open(p.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (fd < 0) throw Error(cat("cannot open lock ", p.string(), ": ", std::strerror(errno)));
    if (flock(fd, LOCK_EX | LOCK_NB) != 0) { close(fd); return false; }
    fd_ = fd;
    return true;
}

std::string host_arch() {
    utsname u{};
    uname(&u);
    return u.machine;
}

}  // namespace hf
