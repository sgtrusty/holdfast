// holdfast - `libs = minimal`: bind only the shared libraries the allowed binaries actually need
#pragma once
#include <utility>

#include "core/paths.hpp"

namespace hf {

struct MinimalLibs {
    // {host source, sandbox destination}, parents before children. Read-only binds.
    std::vector<std::pair<fs::path, fs::path>> binds;
};

// `bins`: {command name, canonical host path} of every binary the profile allows.
// Resolves DT_NEEDED transitively by reading ELF headers (nothing is executed), then adds a small
// built-in map of data/plugin directories that are loaded without being linked (python stdlib,
// git-core helpers, nvim runtime, NSS modules, ...).
// Fails closed: an unresolvable library or a toolchain command throws an Error that names the
// `libs = full` toggle. There is no silent fallback.
MinimalLibs resolve_minimal_libs(const std::vector<std::pair<std::string, fs::path>>& bins, const Policy& pol);

}  // namespace hf
