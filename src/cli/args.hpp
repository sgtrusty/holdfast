// holdfast - command line: help text, version, option parsing (no side effects, unit-testable)
#pragma once
#include <cstdio>
#include <optional>

#include "core/session.hpp"

#ifndef HOLDFAST_VERSION
#define HOLDFAST_VERSION "0.1.0"
#endif

namespace hf {

// Everything the command line says after the command word.
struct Cli {
    std::string cmd;          // run, print, check, bundle, libs, purge, net-test, net-cleanup, ...
    Strings pos;              // positional words: PROFILE, the bundle subcommand, NAME, OS, ...
    RunOptions run;           // what run/print/check/net-test read; run.command = the words after `--`
    bool verbose = false;     // -v
    bool yes = false;         // -y: also used by purge confirmations
    bool refresh = false;     // --refresh: rebuild a bundle / rewrite an OS file list
    bool check = false;       // --check: libs, compare instead of write
                              // --debug is in run.debug (run/print only; main rejects it elsewhere)
};

// Prints the help text. Colour (classic SGR: bold, cyan) only when `f` is a terminal, NO_COLOR is unset and TERM != dumb.
void print_usage(FILE* f);

// `holdfast` with no arguments (usage on stderr, 2), `help`/`-h`/`--help` (usage on stdout, 0), `version`/`--version` (0).
// Returns the process exit code when args were one of those, nullopt otherwise.
std::optional<int> handle_meta(const Strings& args);

// Parses the words after the command. Options and positionals may be mixed; everything after a bare `--` goes to
// run.command untouched. Throws Error on an unknown option or a bad value (e.g. --net=bogus).
Cli parse_args(const std::string& cmd, const Strings& rest);

}  // namespace hf
