// holdfast - `holdfast libs`: scan this machine and save / verify the library file list of every data/lib definition
#pragma once
#include "util/common.hpp"

namespace hf {

// Analyses every data/lib/*.profile on THIS host (ELF headers only, nothing is executed) and produces
// data/os/NAME.profile (kind = host) with a [files.ARCH.LIB] section per lib: the exact files that lib needs on this
// distro. File lists of other architectures in an existing file are kept.
//   refresh = false: print the file to stdout       refresh = true: update the file in place (atomic)
//   check = true:    change nothing; print `+ lib: path` (needed now, missing from the saved list) / `- lib: path`
//                    (saved but no longer needed or gone) and return 1 if they differ. For CI and "did my OS
//                    upgrade invalidate this?".
// name empty => derived from /etc/os-release (debian-12, arch, ...). `extra` data roots (--data) are searched first.
// `out` (--out=DIR) is the data root --refresh writes into (DIR/os/NAME.profile); empty = ~/.config/holdfast/data.
int cmd_libs(const std::string& name, bool check, bool refresh, const Strings& extra = {}, const std::string& out = "");

}  // namespace hf
