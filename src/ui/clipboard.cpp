#include "ui/clipboard.hpp"

#include <sys/inotify.h>
#include <sys/poll.h>
#include <unistd.h>

#include "util/log.hpp"

namespace hf {

std::string sanitize_clipboard(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        const auto c = static_cast<unsigned char>(s[i]);
        const auto at = [&](size_t k) { return i + k < s.size() ? static_cast<unsigned char>(s[i + k]) : 0u; };
        if (c < 0x20 && c != '\n' && c != '\t') continue;
        if (c == 0x7f) continue;
        if (c == 0xC2 && at(1) >= 0x80 && at(1) <= 0x9F) { ++i; continue; }
        if (c == 0xE2 && at(1) == 0x80 && at(2) >= 0xAA && at(2) <= 0xAE) { i += 2; continue; }
        if (c == 0xE2 && at(1) == 0x81 && at(2) >= 0xA6 && at(2) <= 0xA9) { i += 2; continue; }
        out.push_back(static_cast<char>(c));
    }
    return out;
}

ClipboardBridge::ClipboardBridge(const User& u, fs::path file, bool sanitize)
    : user_(u), file_(std::move(file)), sanitize_(sanitize) {
    th_ = std::thread([this] { loop(); });
}
ClipboardBridge::~ClipboardBridge() { stop_ = true; if (th_.joinable()) th_.join(); }

void ClipboardBridge::loop() {
    int ifd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    if (ifd < 0) { log::warn("clipboard bridge: inotify unavailable"); return; }
    if (inotify_add_watch(ifd, file_.c_str(), IN_CLOSE_WRITE) < 0) { log::warn("clipboard bridge: cannot watch " + file_.string() + "; copies will be dropped"); close(ifd); return; }
    const bool wl = std::getenv("WAYLAND_DISPLAY") != nullptr && which("wl-copy");
    if (!wl && !which("xclip")) log::warn("clipboard bridge: neither wl-copy nor xclip found; copies will be dropped");
    while (!stop_) {
        pollfd pf{ifd, POLLIN, 0};
        if (poll(&pf, 1, 200) <= 0) continue;
        char buf[4096];
        while (read(ifd, buf, sizeof buf) > 0) {}
        std::string text;
        try { text = read_file(file_, 1u << 20); } catch (...) { continue; }
        if (sanitize_) text = sanitize_clipboard(text);
        if (text.empty()) continue;
        if (truncate(file_.c_str(), 0) != 0) {}
        Strings cmd = wl ? Strings{"wl-copy"} : Strings{"xclip", "-selection", "clipboard"};
        RunOpts o; o.argv = as_user(user_, cmd); o.stdin_data = text; o.quiet = true;
        try { run(o); } catch (...) {}
    }
    close(ifd);
}

}  // namespace hf
