// holdfast - default syscall filter (seccomp-bpf, generated with libseccomp)
#pragma once
#include "util/common.hpp"

namespace hf {

// True when this binary was built with libseccomp (HOLDFAST_HAVE_SECCOMP).
bool seccomp_available();

// Syscalls the default filter makes fail with EPERM (a denylist: everything else is allowed).
const Strings& seccomp_denylist();

// Writes the compiled BPF program (raw sock_filter array, what `bwrap --seccomp FD` reads) to `out`.
// Throws Error when libseccomp is not built in: a profile asking for the filter never silently runs without it.
void write_default_seccomp(const fs::path& out);

}  // namespace hf
