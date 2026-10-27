#include "util/log.hpp"

#include <cstdio>
#include <mutex>

#include "util/style.hpp"

namespace hf::log {
static bool g_verbose = false;
static std::mutex g_mu;

void set_verbose(bool v) { g_verbose = v; }
bool verbose() { return g_verbose; }

// The tag is coloured only when stderr is a terminal that wants colour (see util/style.hpp); the text is never touched.
static void emit(const char* tag, const char* colour_of, const std::string& m) {
    static const Style st = style_for(stderr);
    const char* col = colour_of[0] == 'c' ? st.c : colour_of[0] == 'y' ? st.y : colour_of[0] == 'x' ? st.x : "";
    std::lock_guard<std::mutex> l(g_mu);
    std::fprintf(stderr, "%s%s%s%s %s\n", st.b, col, tag, st.r, m.c_str());
}
void debug(const std::string& m) { if (g_verbose) emit("[hf:debug]", "", m); }
void info(const std::string& m) { emit("[hf]", "c", m); }
void warn(const std::string& m) { emit("[hf:WARN]", "y", m); }
void error(const std::string& m) { emit("[hf:ERROR]", "x", m); }
}  // namespace hf::log
