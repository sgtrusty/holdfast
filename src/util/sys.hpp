// holdfast - process, user, file and privilege helpers (no shell is ever used
// to run a command; everything is argv-based).
#pragma once
#include <sys/types.h>

#include "util/common.hpp"

namespace hf {

struct User {
    uid_t uid = 0;
    gid_t gid = 0;
    std::string name;
    fs::path home;
    fs::path runtime_dir;  // /run/user/UID
};

// The *target* user: SUDO_USER when running as root through sudo, else the
// invoking user. Refuses plain root (no SUDO_USER).
User resolve_user();

struct RunOpts {
    Strings argv;
    std::string stdin_data;
    bool capture = false;  // capture stdout
    bool quiet = false;    // silence stdin/stdout/stderr (except captured stdout)
    bool merge_stderr = false;   // with capture: stderr goes into the captured text (diagnostics) instead of /dev/null
};
struct RunResult {
    int code = -1;
    std::string out;
    bool ok() const { return code == 0; }
};
RunResult run(const RunOpts& o);
RunResult run(const Strings& argv, bool quiet = false);
RunResult capture_all(const Strings& argv);     // stdout AND stderr, for diagnostics
RunResult capture(const Strings& argv);  // stdout captured, stderr silenced

pid_t spawn(const Strings& argv, bool quiet);  // background; caller must wait_child()
int wait_child(pid_t pid);                      // exit code, or 128+signal
bool child_alive(pid_t pid);                    // non-blocking probe (does not reap)

// Privilege helpers.
bool is_root();
Strings as_root(Strings argv);                  // prefix with sudo unless root
Strings as_user(const User& u, Strings argv);   // setpriv drop when root
// Makes sure sudo works for the rest of this run (one password prompt at most) and keeps the ticket fresh in the
// background, because cleanup at exit needs it. If holdfast had to ask for the password, sudo_keepalive_stop() REVOKES
// the ticket again (`sudo -k`) so nothing else of yours can use it after holdfast is done. A ticket you already had
// before running holdfast is never touched. No-op as root.
void sudo_acquire();
void sudo_keepalive_start();                    // refresh sudo ticket in background
void sudo_keepalive_stop();

// Filesystem helpers.
std::optional<fs::path> which(const std::string& name, const std::string& path_env = "");
std::string read_file(const fs::path& p, size_t max_bytes = 1u << 20);
void write_file(const fs::path& p, const std::string& data, mode_t mode = 0600);
void make_private_dir(const fs::path& p);       // mkdir -p, 0700 on created leaves
// Like make_private_dir, but for dirs holding launcher input (bwrap.args): the leaf must be a real
// directory (not a symlink) owned by us / the sudo user, and is forced to 0700, else throws.
void make_secure_dir(const fs::path& p);
std::string sha256_file(const fs::path& p);     // via sha256sum
std::string sha256_str(const std::string& s);

class FileLock {
public:
    FileLock() = default;
    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;
    ~FileLock();
    bool try_acquire(const fs::path& p);  // non-blocking exclusive
private:
    int fd_ = -1;
};

std::string host_arch();  // uname -m
}  // namespace hf
