// holdfast - orchestration of one sandbox run
#pragma once
#include "core/plan.hpp"
#include "core/profile.hpp"

namespace hf {

struct RunOptions {
    bool dry = false;                   // print the plan, change nothing
    bool yes = false;                   // answer "yes" to the cwd prompt
    bool no_cwd = false;
    bool refresh = false;               // bundle profiles: redo a changed userland / the dep recipes first
    bool userland_ready = false;        // the caller (bundle_ensure running a dep) already prepared the userland: do not recurse
    bool debug = false;                 // --debug: an interactive shell in this exact sandbox instead of the profile's command
    std::optional<fs::path> cwd;
    std::optional<NetMode> net;
    std::optional<std::string> dns;     // --dns=IPv4|host: overrides [network] dns (validated by check_dns)
    std::optional<std::string> wg_conf;
    Strings command;                    // overrides [profile] command
};

// Profile sanity checks that don't need root or a display. Throws ProfileError.
void validate_profile(const Profile& p, bool has_command_override);

// The command `--debug` runs: bash if the profile can run it, else sh. It never adds a binary to the sandbox, because a
// debug shell that quietly changed what the profile gets would defeat the point. Host mode needs `bash` or `sh` in
// [bin] allow (Error otherwise); a bundle userland brings its own shell (Alpine: busybox sh, bash if installed).
Strings debug_shell(const Profile& p);

int run_profile(Profile p, RunOptions o);
int net_test(Profile p, const RunOptions& o);
void net_cleanup(const std::string& ns_name);

}  // namespace hf
