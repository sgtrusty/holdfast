#include "ui/termfilter.hpp"

namespace hf {

namespace {

// DEC private modes a program may toggle. Everything else (132-column switching, reverse screen,
// highlight mouse tracking that can wedge the terminal, 8-bit meta/bell hooks, ...) is dropped.
const std::set<int> kAllowedModes = {1, 6, 7, 9, 12, 25, 45, 47, 66, 69, 1000, 1002, 1003, 1004, 1005, 1006, 1007,
                                     1015, 1016, 1047, 1048, 1049, 2004, 2026, 2027, 2048};
// Modes whose power-on state is "on": restore() must switch them back ON, not off.
const std::set<int> kDefaultOn = {7, 25};

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> v;
    size_t a = 0;
    for (;;) {
        size_t b = s.find(sep, a);
        v.push_back(s.substr(a, b == std::string::npos ? std::string::npos : b - a));
        if (b == std::string::npos) break;
        a = b + 1;
    }
    return v;
}
bool numeric(const std::string& s, int& out, int max = 1000000) {
    if (s.empty() || s.size() > 7) return false;
    int v = 0;
    for (char c : s) { if (c < '0' || c > '9') return false; v = v * 10 + (c - '0'); }
    if (v > max) return false;
    out = v;
    return true;
}
bool all_numeric(const std::string& params, int max = 1000000) {     // "", "1;2" ok; "1:2", "a" not
    if (params.empty()) return true;
    for (const std::string& p : split(params, ';')) { int v; if (!p.empty() && !numeric(p, v, max)) return false; }
    return true;
}

}  // namespace

std::string TermFilter::feed(const char* data, size_t n) {
    std::string out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        const auto b = static_cast<unsigned char>(data[i]);
        switch (st_) {
            case St::Ground: ground(b, out); break;
            case St::Esc: case St::EscInter: esc_byte(b, out); break;
            case St::Csi: csi_byte(b, out); break;
            case St::Osc:
                if (b == 0x07) finish_osc(out);                       // BEL terminator
                else if (b == 0x1b) st_ = St::OscEsc;
                else if (b == 0x18 || b == 0x1a) abort_to_ground();   // CAN/SUB cancel
                else if (osc_.size() <= kMaxOsc) osc_.push_back(static_cast<char>(b));
                else overflow_ = true;
                break;
            case St::OscEsc:
                if (b == '\\') finish_osc(out);                       // ST
                else { abort_to_ground(); st_ = St::Esc; seq_ = "\x1b"; esc_byte(b, out); }
                break;
            case St::Drop:                                            // DCS / SOS / PM / APC: dropped whole
                if (b == 0x1b) st_ = St::DropEsc;
                else if (b == 0x18 || b == 0x1a || ++drop_len_ > kMaxDrop) abort_to_ground();   // never swallow output forever
                break;
            case St::DropEsc:
                if (b == '\\') abort_to_ground();
                else { abort_to_ground(); st_ = St::Esc; seq_ = "\x1b"; esc_byte(b, out); }
                break;
        }
    }
    return out;
}

void TermFilter::ground(unsigned char b, std::string& out) {
    // UTF-8: pass well-formed text, drop C1 controls (U+0080..U+009F encode as C2 80..9F) and stray bytes.
    if (c2_pending_) {
        c2_pending_ = false;
        if (b >= 0x80 && b <= 0x9f) return;                           // C1 control: CSI/OSC/DCS in disguise
        if (b >= 0xa0 && b <= 0xbf) { out.push_back('\xC2'); out.push_back(static_cast<char>(b)); return; }
        // not a continuation: the 0xC2 was malformed; fall through and handle b normally
    }
    if (utf8_cont_ > 0) {
        if (b >= 0x80 && b <= 0xbf) { --utf8_cont_; out.push_back(static_cast<char>(b)); return; }
        utf8_cont_ = 0;                                               // truncated sequence; reprocess b
    }
    if (b >= 0x80) {
        if (b == 0xC2) { c2_pending_ = true; return; }
        if (b >= 0xC3 && b <= 0xDF) utf8_cont_ = 1;
        else if (b >= 0xE0 && b <= 0xEF) utf8_cont_ = 2;
        else if (b >= 0xF0 && b <= 0xF4) utf8_cont_ = 3;
        else return;                                                  // stray continuation / invalid lead / raw C1
        out.push_back(static_cast<char>(b));
        return;
    }
    if (b == 0x1b) { st_ = St::Esc; seq_ = "\x1b"; return; }
    if (b >= 0x20 && b < 0x7f) { out.push_back(static_cast<char>(b)); return; }
    switch (b) {                                                       // C0: BEL BS HT LF VT FF CR SO SI only
        case 0x07: case 0x08: case 0x09: case 0x0a: case 0x0b: case 0x0c: case 0x0d: case 0x0e: case 0x0f:
            out.push_back(static_cast<char>(b));
            break;
        default: break;                                                // NUL ENQ(answerback) CAN SUB FS GS RS US DEL ... dropped
    }
}

void TermFilter::esc_byte(unsigned char b, std::string& out) {
    if (b == 0x18 || b == 0x1a) { abort_to_ground(); return; }
    if (b == 0x1b) { seq_ = "\x1b"; st_ = St::Esc; return; }
    if (b < 0x20) return;                                              // other C0 inside a sequence: ignored
    if (b >= 0x20 && b <= 0x2f) {
        if (seq_.size() > 4) { abort_to_ground(); return; }
        seq_.push_back(static_cast<char>(b)); st_ = St::EscInter; return;
    }
    if (b > 0x7e) { abort_to_ground(); return; }
    if (seq_.size() == 1) {                                            // ESC <b>
        switch (b) {
            case '[': seq_ = "\x1b["; st_ = St::Csi; overflow_ = false; return;
            case ']': osc_.clear(); overflow_ = false; st_ = St::Osc; return;
            case 'P': case 'X': case '^': case '_': drop_len_ = 0; st_ = St::Drop; return;
            case '7': case '8': case '=': case '>': case 'D': case 'E': case 'H': case 'M':
                out.push_back('\x1b'); out.push_back(static_cast<char>(b)); break;     // save/restore cursor, keypad, index, tab set
            default: break;                                            // RIS (c), DECID (Z), SS2/SS3, locking shifts, ... dropped
        }
    } else if (seq_.size() == 2 && std::string("()*+-./").find(seq_[1]) != std::string::npos &&
               ((b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z'))) {
        out += seq_; out.push_back(static_cast<char>(b));              // charset designation (ESC ( 0 = line drawing)
    }                                                                  // ESC SP F/G (C1 transmission), ESC % (UTF-8 off), ESC # : dropped
    abort_to_ground();
}

void TermFilter::csi_byte(unsigned char b, std::string& out) {
    if (b == 0x18 || b == 0x1a) { abort_to_ground(); return; }
    if (b == 0x1b) { seq_ = "\x1b"; st_ = St::Esc; return; }
    if (b < 0x20) return;
    if (b > 0x7e) { abort_to_ground(); return; }
    if (seq_.size() < kMaxCsi) seq_.push_back(static_cast<char>(b)); else overflow_ = true;
    if (b >= 0x40) finish_csi(out);
}

void TermFilter::track_modes(const std::string& params, bool on) {
    for (const std::string& p : split(params, ';')) { int m; if (numeric(p, m)) modes_[m] = on; }
}

void TermFilter::finish_csi(std::string& out) {
    const std::string seq = seq_;
    const bool ovf = overflow_;
    abort_to_ground();
    if (ovf || seq.size() < 3) return;
    // ESC [ [prefix] params [intermediates] final
    size_t i = 2;
    char prefix = 0;
    if (seq[i] >= '<' && seq[i] <= '?') prefix = seq[i++];
    size_t ps = i;
    while (i < seq.size() && ((seq[i] >= '0' && seq[i] <= '9') || seq[i] == ';' || seq[i] == ':')) ++i;
    const std::string params = seq.substr(ps, i - ps);
    size_t is = i;
    while (i < seq.size() && seq[i] >= 0x20 && seq[i] <= 0x2f) ++i;
    const std::string inter = seq.substr(is, i - is);
    if (i + 1 != seq.size()) return;                                   // junk between parts (e.g. param after intermediate)
    const char fin = seq[i];
    int v = 0;
    const bool num = all_numeric(params);                              // ':' (sub-parameters) only legal for SGR below

    bool ok = false;
    if (prefix == 0 && inter.empty()) {
        switch (fin) {
            case 'm': ok = true; break;                                // SGR incl. 38;2;r;g;b and 4:3 underline styles
            case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G': case 'H': case 'I': case 'J':
            case 'K': case 'L': case 'M': case 'P': case 'X': case 'Z': case '@': case '`': case 'a': case 'd':
            case 'e': case 'f': case 'g': case 'S':
                ok = num; break;
            case 'T': ok = num && split(params, ';').size() <= 1; break;   // 5-parameter form starts mouse highlight tracking
            case 'b': ok = num && (params.empty() || numeric(params, v, 65535)); break;   // REP
            case 'c': ok = params.empty() || params == "0"; break;     // DA1
            case 'n': ok = params == "5" || params == "6"; break;      // status / cursor position report
            case 'r': ok = num; region_ = region_ || ok; break;        // DECSTBM
            case 's': ok = params.empty(); break;                      // save cursor (with params it is DECSLRM: unneeded)
            case 'u': ok = params.empty(); break;                      // restore cursor
            case 'h': case 'l': {                                      // ANSI modes: insert (4), newline (20) only; NOT keyboard lock (2)
                ok = num && !params.empty();
                for (const std::string& p : split(params, ';')) if (p != "4" && p != "20") ok = false;
                break;
            }
            default: break;                                            // t (window ops/title reports), i (print), q, p, x, ~, ...
        }
    } else if (prefix == '?' && inter.empty()) {
        switch (fin) {
            case 'h': case 'l': case 'r': case 's': {
                ok = num && !params.empty();
                for (const std::string& p : split(params, ';')) { int m; if (!numeric(p, m) || !kAllowedModes.count(m)) ok = false; }
                if (ok && (fin == 'h' || fin == 'l')) track_modes(params, fin == 'h');
                break;
            }
            case 'J': case 'K': ok = num; break;                       // selective erase
            case 'n': ok = params == "6" || params == "996"; break;    // DECXCPR, colour-scheme query
            case 'u': ok = params.empty(); break;                      // kitty keyboard query
            default: break;
        }
    } else if (prefix == '>' && inter.empty()) {
        if (fin == 'c') ok = params.empty() || params == "0";         // DA2
        else if (fin == 'q') ok = params.empty() || params == "0";    // XTVERSION
        else if (fin == 'm') { ok = num; mok_ = true; }               // modifyOtherKeys
        else if (fin == 'u') { ok = num; if (ok) ++kitty_depth_; }    // kitty keyboard: push
    } else if (prefix == '<' && inter.empty() && fin == 'u') {
        ok = num; if (ok && kitty_depth_ > 0) --kitty_depth_;         // kitty keyboard: pop
    } else if (prefix == '=' && inter.empty() && (fin == 'c' || fin == 'u')) {
        ok = fin == 'c' ? (params.empty() || params == "0") : num;    // DA3 / kitty set flags
    } else if (inter == " " && fin == 'q' && prefix == 0) {
        ok = num && (params.empty() || numeric(params, v, 6));        // DECSCUSR cursor shape
        cursor_style_ = cursor_style_ || ok;
    } else if (inter == "$" && fin == 'p' && (prefix == 0 || prefix == '?')) {
        ok = num && !params.empty();                                   // DECRQM: ask whether a mode is set
    }
    if (ok) out += seq;
}

void TermFilter::finish_osc(std::string& out) {
    const std::string payload = osc_;
    const bool ovf = overflow_;
    abort_to_ground();
    if (ovf) return;
    const size_t semi = payload.find(';');
    int ps;
    if (semi == std::string::npos || !numeric(payload.substr(0, semi), ps)) return;
    const std::string text = payload.substr(semi + 1);
    if (ps == 0 || ps == 2) {                                          // window title: sanitised, length-capped, visibly tagged
        if (text.size() > kMaxTitle) return;
        std::string clean;
        for (size_t i = 0; i < text.size(); ++i) {
            const auto c = static_cast<unsigned char>(text[i]);
            if (c < 0x20 || c == 0x7f) continue;
            if (c == 0xC2 && i + 1 < text.size() && static_cast<unsigned char>(text[i + 1]) >= 0x80 && static_cast<unsigned char>(text[i + 1]) <= 0x9f) { ++i; continue; }
            clean.push_back(static_cast<char>(c));
        }
        out += "\x1b]2;[sandbox] " + clean + "\x1b\\";
    } else if ((ps == 10 || ps == 11 || ps == 12) && text == "?") {    // colour QUERIES only; setting colours could hide text
        out += "\x1b]" + std::to_string(ps) + ";?\x1b\\";
    }                                                                  // 52 clipboard, 8 hyperlinks, 7, 9, 99, 133, 777, 1337, ... dropped
}

std::string TermFilter::restore() const {
    std::string r;
    for (const auto& [mode, on] : modes_) {
        const bool def_on = kDefaultOn.count(mode) != 0;
        if (mode == 47 || mode == 1047 || mode == 1049) continue;      // alternate screen last, below
        if (on != def_on) r += "\x1b[?" + std::to_string(mode) + (def_on ? "h" : "l");
    }
    for (int m : {1049, 1047, 47}) {
        auto it = modes_.find(m);
        if (it != modes_.end() && it->second) r += "\x1b[?" + std::to_string(m) + "l";
    }
    for (int k = 0; k < kitty_depth_ && k < 16; ++k) r += "\x1b[<u";
    if (mok_) r += "\x1b[>4;0m";
    if (cursor_style_) r += "\x1b[0 q";
    if (region_) r += "\x1b[r";
    r += "\x1b>\x1b[0m";                                               // normal keypad, reset attributes
    return r;
}

}  // namespace hf
