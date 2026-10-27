// holdfast - orchestration of one sandbox run
#pragma once
#include "core/plan.hpp"
#include "core/profile.hpp"

namespace hf {

struct RunOptions {
    bool dry = false;                   // print the plan, change nothing
    bool yes = false;                   // answer "yes" to the cwd prompt
    bool no_cwd = false;
    std::optional<fs::path> cwd;
    std::optional<NetMode> net;
    std::optional<std::string> wg_conf;
    Strings command;                    // overrides [profile] command
};

// Profile sanity checks that don't need root or a display. Throws ProfileError.
void validate_profile(const Profile& p, bool has_command_override);

int run_profile(Profile p, const RunOptions& o);
int net_test(Profile p, const RunOptions& o);
void net_cleanup(const std::string& ns_name);
int doctor();
// Authoring helper: reads ELF headers of the profile's [bin] allow list and prints a `[libs]` block
// to stdout. Never called by `run`; the result is meant to be reviewed and pasted into the profile.
// With check = true nothing is generated for pasting: the fresh analysis is diffed against the profile's
// [libs] list (`+ path` missing from the profile, `- path` not produced by the analysis; stdout) and the
// result is 0 only if they are identical. Still authoring/CI time, never part of `run`.
int print_libs(const Profile& p, bool check = false);

}  // namespace hf
