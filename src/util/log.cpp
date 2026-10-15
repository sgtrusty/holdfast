#include "util/log.hpp"

#include <cstdio>
#include <mutex>

namespace hf::log {
static bool g_verbose = false;
static std::mutex g_mu;

void set_verbose(bool v) { g_verbose = v; }
bool verbose() { return g_verbose; }

static void emit(const char* tag, const std::string& m) {
    std::lock_guard<std::mutex> l(g_mu);
    std::fprintf(stderr, "%s%s\n", tag, m.c_str());
}
void debug(const std::string& m) { if (g_verbose) emit("[hf:debug] ", m); }
void info(const std::string& m) { emit("[hf] ", m); }
void warn(const std::string& m) { emit("[hf:WARN] ", m); }
void error(const std::string& m) { emit("[hf:ERROR] ", m); }
}  // namespace hf::log
