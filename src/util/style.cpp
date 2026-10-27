#include "util/style.hpp"

#include <unistd.h>

#include <cstdlib>
#include <cstring>

namespace hf {

Style style_for(FILE* f) {
    Style s;
    s.tty = isatty(fileno(f)) != 0;
    const char* term = std::getenv("TERM");
    if (!s.tty || std::getenv("NO_COLOR") || (term && std::strcmp(term, "dumb") == 0)) return s;
    s.b = "\033[1m";
    s.c = "\033[36m";
    s.g = "\033[32m";
    s.y = "\033[33m";
    s.x = "\033[31m";
    s.r = "\033[0m";
    return s;
}

}  // namespace hf
