// holdfast - `holdfast doctor`: what this host can do, and where holdfast keeps things
#pragma once
#include <functional>

#include "util/common.hpp"

namespace hf {

// One optional capability and what it needs. A tool "a|b" means either one is enough; "?x" is nice to have.
struct FeatureStatus {
    std::string name;
    Strings missing;            // required tools that are not available
    Strings missing_optional;   // "?" tools that are not available
    bool ready() const { return missing.empty(); }
};

// Pure: `have(tool)` says whether a tool exists. Tested without touching the host.
std::vector<FeatureStatus> evaluate_features(const std::function<bool(const std::string&)>& have);

// Prints the report to stdout (it is the command's output, pipeable; colour only on a terminal).
// Exit code: 0, or 1 when something REQUIRED is missing (bwrap, unprivileged user namespaces).
int doctor();

}  // namespace hf
