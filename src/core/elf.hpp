// holdfast - just enough ELF parsing to know which shared libraries a binary needs
#pragma once
#include <optional>

#include "util/common.hpp"

namespace hf {

struct ElfDeps {
    std::string interp;     // PT_INTERP (the dynamic loader), empty for static binaries
    Strings needed;         // DT_NEEDED sonames
    Strings search;         // DT_RPATH + DT_RUNPATH entries, $ORIGIN not yet expanded
};

// nullopt: not an ELF file (script, data). Throws Error for ELF we cannot read safely
// (32-bit / big-endian / truncated) so callers fail closed instead of mounting too little.
// Reads the file only; nothing is executed (unlike ldd).
std::optional<ElfDeps> read_elf_deps(const fs::path& file);

// (ELF class << 16) | e_machine for any ELF file (32/64-bit, either endianness), nullopt for non-ELF or unreadable
// files. The dynamic loader silently skips libraries of another ABI and keeps searching (a 32-bit libc.so.6 in
// /usr/lib32 must not shadow the 64-bit one); the lock analysis has to do the same.
std::optional<unsigned> elf_abi(const fs::path& file);

}  // namespace hf
