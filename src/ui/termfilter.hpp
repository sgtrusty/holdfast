// holdfast - sanitises what a sandboxed program writes to the user's terminal
#pragma once
#include <map>
#include <set>

#include "util/common.hpp"

namespace hf {

// A terminal is a programmable device: bytes a sandboxed program prints can set your clipboard (OSC 52),
// forge titles and hyperlinks, make the terminal type replies into the shell's input (title/answerback
// reports), change keyboard modes, or leave mouse reporting on after the program died. TermFilter is a
// streaming ECMA-48/DEC parser that forwards plain text and an ALLOWLIST of sequences full-screen programs
// need (colours, cursor movement, erasing, scrolling, alternate screen, mouse/paste/focus modes, safe
// capability queries) and drops everything else. It also remembers which modes the program switched on so
// restore() can switch them off again if the program exits without cleaning up.
class TermFilter {
public:
    std::string feed(const char* data, size_t n);        // bytes in -> safe bytes out (state kept across calls)
    std::string feed(const std::string& s) { return feed(s.data(), s.size()); }
    std::string restore() const;                         // undo modes the program left enabled

    static constexpr size_t kMaxCsi = 128, kMaxOsc = 4096, kMaxDrop = 65536, kMaxTitle = 200;

private:
    enum class St { Ground, Esc, EscInter, Csi, Osc, OscEsc, Drop, DropEsc };
    St st_ = St::Ground;
    std::string seq_;           // current escape sequence, introducer included
    std::string osc_;           // OSC payload
    size_t drop_len_ = 0;
    bool overflow_ = false;
    int utf8_cont_ = 0;         // continuation bytes still expected
    bool c2_pending_ = false;   // saw 0xC2: the next byte decides whether this is a C1 control (U+0080..9F)

    std::map<int, bool> modes_;     // DEC private mode -> last value set by the program
    int kitty_depth_ = 0;
    bool mok_ = false, cursor_style_ = false, region_ = false;

    void ground(unsigned char b, std::string& out);
    void esc_byte(unsigned char b, std::string& out);
    void csi_byte(unsigned char b, std::string& out);
    void finish_csi(std::string& out);
    void finish_osc(std::string& out);
    void abort_to_ground() { st_ = St::Ground; seq_.clear(); osc_.clear(); overflow_ = false; }
    void track_modes(const std::string& params, bool on);
};

}  // namespace hf
