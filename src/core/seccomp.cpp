#include "core/seccomp.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "util/sys.hpp"

#ifdef HOLDFAST_HAVE_SECCOMP
#include <seccomp.h>
#include <sys/ioctl.h>
#endif

namespace hf {

bool seccomp_available() {
#ifdef HOLDFAST_HAVE_SECCOMP
    return true;
#else
    return false;
#endif
}

// Deliberately NOT blocked: clone/clone3/unshare/setns (browsers and nested sandboxes need them; bwrap's
// --disable-userns covers user namespaces), ptrace (debuggers; the pid namespace limits it), seccomp/prctl.
// clone3 must never get EPERM: glibc only falls back to clone() on ENOSYS.
const Strings& seccomp_denylist() {
    static const Strings v = {
        // kernel / module / machine control
        "kexec_load", "kexec_file_load", "reboot", "init_module", "finit_module", "delete_module",
        "create_module", "get_kernel_syms", "query_module", "nfsservctl", "lookup_dcookie", "syslog",
        // attack surface with a long CVE history that sandboxed dev tools do not need
        "bpf", "perf_event_open", "userfaultfd", "io_uring_setup", "io_uring_enter", "io_uring_register",
        "keyctl", "add_key", "request_key", "kcmp",
        // filesystem namespace manipulation (the sandbox has no CAP_SYS_ADMIN anyway: defence in depth)
        "mount", "umount", "umount2", "pivot_root", "open_tree", "move_mount", "fsopen", "fsconfig",
        "fsmount", "fspick", "mount_setattr", "name_to_handle_at", "open_by_handle_at",
        "swapon", "swapoff", "acct", "quotactl", "quotactl_fd",
        // clock and legacy x86 oddities
        "settimeofday", "clock_settime", "clock_adjtime", "adjtimex", "stime",
        "modify_ldt", "iopl", "ioperm", "vm86", "vm86old", "uselib", "_sysctl", "sysfs",
    };
    return v;
}

void write_default_seccomp(const fs::path& out) {
#ifdef HOLDFAST_HAVE_SECCOMP
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) throw Error("seccomp_init failed");
    struct Guard { scmp_filter_ctx c; ~Guard() { seccomp_release(c); } } guard{ctx};
    auto fail = [](const char* what, int rc) { throw Error(cat("seccomp: ", what, ": ", std::strerror(-rc))); };

    for (const std::string& name : seccomp_denylist()) {
        int nr = seccomp_syscall_resolve_name(name.c_str());
        if (nr < 0) continue;                                   // unknown or not implemented on this architecture
        if (int rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), nr, 0); rc < 0) fail(name.c_str(), rc);
    }
    // TIOCSTI / TIOCLINUX inject keystrokes into the controlling terminal. --new-session already blocks this,
    // but profiles may set new_session = no (interactive shells), so close it here as well.
    const int ioctl_nr = seccomp_syscall_resolve_name("ioctl");
    if (ioctl_nr >= 0) {
        for (unsigned long cmd : {static_cast<unsigned long>(TIOCSTI), static_cast<unsigned long>(TIOCLINUX)}) {
            struct scmp_arg_cmp c{};
            c.arg = 1;
            c.op = SCMP_CMP_MASKED_EQ;
            c.datum_a = 0xFFFFFFFFu;
            c.datum_b = cmd;
            if (int rc = seccomp_rule_add_array(ctx, SCMP_ACT_ERRNO(EPERM), ioctl_nr, 1, &c); rc < 0) fail("ioctl", rc);
        }
    }

    write_file(out, "", 0600);                                   // creates it with the right owner/mode (sudo-safe)
    int fd = open(out.c_str(), O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) throw Error(cat("cannot open ", out.string(), ": ", std::strerror(errno)));
    int rc = seccomp_export_bpf(ctx, fd);
    close(fd);
    if (rc < 0) fail("export", rc);
#else
    (void)out;
    throw Error("this holdfast was built without libseccomp, so the default seccomp filter is unavailable; "
                "rebuild with libseccomp-dev installed (see README), or set `seccomp = none` in the profile to run without a filter");
#endif
}

}  // namespace hf
