// holdfast - the one-way clipboard bridge (sandbox -> host); independent of the display protocol
#pragma once
#include <atomic>
#include <thread>

#include "util/sys.hpp"

namespace hf {

// Removes what makes pasted text dangerous in a terminal: C0 controls except \n and \t (ESC, CR, ...),
// DEL, C1 controls (UTF-8 U+0080..U+009F) and bidi overrides/isolates (U+202A..202E, U+2066..2069).
std::string sanitize_clipboard(const std::string& s);

// The sandbox writes text to a bound file; we copy it to the host clipboard on close (wl-copy on a Wayland session, else xclip).
// There is no host -> sandbox direction.
class ClipboardBridge {
public:
    ClipboardBridge(const User& u, fs::path file, bool sanitize);
    ~ClipboardBridge();
private:
    void loop();
    User user_;
    fs::path file_;
    bool sanitize_;
    std::atomic<bool> stop_{false};
    std::thread th_;
};

}  // namespace hf
