// holdfast - authoring-time dependency analysis for data/lib/*.profile (used by `holdfast libs`, never by `run`)
#pragma once
#include <utility>

#include "core/datadefs.hpp"
#include "core/paths.hpp"

namespace hf {

// Resolves ONE lib definition on THIS host to the files that must be bound read-only into a sandbox:
// {host source, sandbox destination}, sorted by destination so parents come before children.
//  - commands: found on PATH; their DT_NEEDED closure and PT_INTERP are read from the ELF headers (nothing is executed)
//  - sonames:  globs searched in the loader's library directories (ld.so.conf + standard dirs), plus their closure
//  - paths:    data/plugin directories (globs) bound whole; ELF files inside are scanned for what THEY link against
// The result is what `holdfast libs` writes into data/os/*.profile. Fails closed: an unresolvable library or a
// toolchain command (gcc, rustc, ... need crt files and static archives) throws an Error naming `libs = full`.
std::vector<std::pair<fs::path, fs::path>> resolve_lib(const LibDef& def, const Policy& pol);

}  // namespace hf
