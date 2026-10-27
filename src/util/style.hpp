// holdfast - classic ANSI styling shared by help, doctor, list and the log tags
#pragma once
#include <cstdio>

namespace hf {

// Classic SGR only (bold, cyan, green, yellow, red, reset). Every field is "" when colour is off, so callers just print
// them. Colour is off when the stream is not a terminal, NO_COLOR is set, or TERM=dumb. `tty` is true for any terminal
// (colour or not), for things like a header row that only makes sense when a human is reading.
struct Style {
    const char *b = "", *c = "", *g = "", *y = "", *x = "", *r = "";   // bold, cyan, green, yellow, red, reset
    bool tty = false;
};

Style style_for(FILE* f);

}  // namespace hf
