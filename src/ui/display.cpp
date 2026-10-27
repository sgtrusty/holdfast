#include "ui/display.hpp"

#include <sys/inotify.h>
#include <sys/poll.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <regex>

#include "util/log.hpp"

namespace hf {

static bool exists_nofollow(const fs::path& p) {
    std::error_code ec;
    return fs::symlink_status(p, ec).type() != fs::file_type::not_found;
}

std::unique_ptr<XephyrServer> XephyrServer::start(const User& u, const Profile& p, const fs::path& session) {
    if (!which("Xephyr")) throw Error("Xephyr not found (install xserver-xephyr / xorg-server-xephyr)");
    if (!std::getenv("DISPLAY") && !std::getenv("WAYLAND_DISPLAY"))
        throw Error("no host display (DISPLAY/WAYLAND_DISPLAY unset); Xephyr needs one to open its window");
    static const std::regex size_ok(R"(^\d{3,5}x\d{3,5}$)");
    if (!std::regex_match(p.display_size, size_ok)) throw ProfileError("[display] size must look like 1280x800");

    std::string cookie(16, '\0');
    if (getrandom(cookie.data(), cookie.size(), 0) != 16) throw Error("getrandom failed");

    for (int n = 90; n < 190; ++n) {
        fs::path sock = fs::path("/tmp/.X11-unix") / cat("X", n);
        if (exists_nofollow(sock) || exists_nofollow(cat("/tmp/.X", n, "-lock"))) continue;

        std::unique_ptr<XephyrServer> s(new XephyrServer());
        s->info_.display = cat(":", n);
        s->info_.socket = sock;
        Strings argv = {"Xephyr", s->info_.display, "-screen", p.display_size, "-resizeable", "-nolisten", "tcp",
                        "-terminate", "-title", "holdfast: " + p.name + " (untrusted)"};
        if (p.xauth) {
            s->info_.authfile = session / "Xauthority";
            write_xauth(s->info_.authfile, std::to_string(n), cookie);
            argv.push_back("-auth"); argv.push_back(s->info_.authfile.string());
        } else {
            log::warn("[display] xauth=no: any local process of any user can talk to this X server");
        }
        s->pid_ = spawn(as_user(u, argv), true);
        for (int i = 0; i < 60; ++i) {
            if (exists_nofollow(sock)) { log::info(cat("Xephyr up on ", s->info_.display, " (", p.display_size, ")")); return s; }
            if (!child_alive(s->pid_)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        // Died early (display raced / taken): try next number. Destructor reaps.
    }
    throw Error("could not start Xephyr on any display number 90..189");
}

XephyrServer::~XephyrServer() {
    if (pid_ > 0) {
        kill(pid_, SIGTERM);
        for (int i = 0; i < 20 && child_alive(pid_); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (child_alive(pid_)) kill(pid_, SIGKILL);
        wait_child(pid_);
    }
}

DisplayInfo host_x11(const User& u, const Profile& p) {
    if (!p.allow_host_x11)
        throw ProfileError("[display] mode=host shares your real X11 session (keylogging, screen capture); "
                           "set allow_host_x11 = yes to accept that, or use mode=xephyr");
    const char* d = std::getenv("DISPLAY");
    if (!d || d[0] != ':') throw Error("DISPLAY must be a local display like :0");
    std::string num = d + 1;
    num = num.substr(0, num.find('.'));
    DisplayInfo i;
    i.host = true;
    i.display = d;
    i.socket = fs::path("/tmp/.X11-unix") / ("X" + num);
    const char* xa = std::getenv("XAUTHORITY");
    fs::path auth = xa ? fs::path(xa) : u.home / ".Xauthority";
    if (fs::exists(auth)) i.authfile = auth;
    log::warn("host X11 shared with the sandbox: it can observe and inject input for ALL your windows");
    return i;
}

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
