#include "protocol/display/x11.hpp"

#include <signal.h>
#include <sys/random.h>

#include <chrono>
#include <thread>

#include "util/log.hpp"

namespace hf::display {

namespace {

bool exists_nofollow(const fs::path& p) {
    std::error_code ec;
    return fs::symlink_status(p, ec).type() != fs::file_type::not_found;
}

// The one place that knows what an X11 client needs: the server socket, optionally the cookie, DISPLAY (+ XAUTHORITY).
Setup x11_setup(const std::string& backend, const std::string& display, const fs::path& socket, const fs::path& authfile,
                const std::string& wm) {
    Setup s;
    s.backend = backend;
    s.binds.push_back({socket, socket, true});
    s.env.emplace_back("DISPLAY", display);
    if (!authfile.empty()) {
        s.binds.push_back({authfile, "/tmp/.Xauthority", false});
        s.env.emplace_back("XAUTHORITY", "/tmp/.Xauthority");
    }
    s.background = wm;
    return s;
}

class X11Nested final : public Backend {
public:
    X11Nested(const Profile& p, const User& u, const fs::path& session, bool dry) {
        const DisplayDef& d = *p.display;
        if (dry) {                                            // describe what a real run would use; start nothing
            setup_ = x11_setup("x11-nested", ":90", "/tmp/.X11-unix/X90", d.xauth ? session / "Xauthority" : fs::path(), d.wm);
            return;
        }
        if (!which("Xephyr")) throw Error("Xephyr not found (install xserver-xephyr / xorg-server-xephyr)");
        if (!std::getenv("DISPLAY") && !std::getenv("WAYLAND_DISPLAY"))
            throw Error("no host display (DISPLAY/WAYLAND_DISPLAY unset); Xephyr needs one to open its window");
        std::string cookie(16, '\0');
        if (getrandom(cookie.data(), cookie.size(), 0) != 16) throw Error("getrandom failed");

        for (int n = 90; n < 190; ++n) {
            const fs::path sock = fs::path("/tmp/.X11-unix") / cat("X", n);
            if (exists_nofollow(sock) || exists_nofollow(cat("/tmp/.X", n, "-lock"))) continue;
            const std::string disp = cat(":", n);
            fs::path auth;
            Strings argv = {"Xephyr", disp, "-screen", d.size, "-resizeable", "-nolisten", "tcp",
                            "-terminate", "-title", "holdfast: " + p.name + " (untrusted)"};
            if (d.glamor) argv.push_back("-glamor");
            if (d.xauth) {
                auth = session / "Xauthority";
                write_xauth(auth, std::to_string(n), cookie);
                argv.push_back("-auth"); argv.push_back(auth.string());
            } else {
                log::warn("[display] xauth=no: any local process of any user can talk to this X server");
            }
            pid_ = spawn(as_user(u, argv), true);
            for (int i = 0; i < 60; ++i) {
                if (exists_nofollow(sock)) {
                    log::debug(cat("Xephyr up on ", disp, " (", d.size, ")"));
                    setup_ = x11_setup("x11-nested", disp, sock, auth, d.wm);
                    return;
                }
                if (!child_alive(pid_)) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            stop();                                           // died early (display number raced / taken): try the next one
        }
        throw Error("could not start Xephyr on any display number 90..189");
    }
    ~X11Nested() override { stop(); }
    const Setup& setup() const override { return setup_; }

private:
    void stop() {
        if (pid_ <= 0) return;
        kill(pid_, SIGTERM);
        for (int i = 0; i < 20 && child_alive(pid_); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (child_alive(pid_)) kill(pid_, SIGKILL);
        wait_child(pid_);
        pid_ = -1;
    }
    Setup setup_;
    pid_t pid_ = -1;
};

class X11Host final : public Backend {
public:
    X11Host(const Profile& p, const User& u, bool dry) {
        if (dry) {
            setup_ = x11_setup("x11-host", ":0", "/tmp/.X11-unix/X0", fs::path(), "");
            return;
        }
        const char* d = std::getenv("DISPLAY");
        if (!d || d[0] != ':') throw Error("DISPLAY must be a local display like :0");
        std::string num = d + 1;
        num = num.substr(0, num.find('.'));
        const char* xa = std::getenv("XAUTHORITY");
        const fs::path auth = xa ? fs::path(xa) : u.home / ".Xauthority";
        setup_ = x11_setup("x11-host", d, fs::path("/tmp/.X11-unix") / ("X" + num), fs::exists(auth) ? auth : fs::path(), "");
        (void)p;
        log::warn("host X11 shared with the sandbox: it can observe and inject input for ALL your windows");
    }
    const Setup& setup() const override { return setup_; }

private:
    Setup setup_;
};

}  // namespace

void validate_x11(const Profile& p) {
    const DisplayDef& d = *p.display;                    // size/xauth/wm combinations were checked when the display file was parsed
    if (d.mode == DisplayMode::Host) return;             // consent (`allow_host`) is checked in display::validate
    if (!d.wm.empty() && p.root == RootMode::Host) {      // the wm is started through `sh -c` inside the sandbox
        bool sh = false;
        for (const auto& b : p.bins) if (b == "sh" || b.rfind("sh=", 0) == 0) sh = true;
        if (!sh) throw ProfileError(cat("display '", d.name, "' starts a window manager: add 'sh' to [bin] allow"));
    }
}

std::unique_ptr<Backend> open_x11(const Profile& p, const User& u, const fs::path& session, bool dry) {
    if (p.display->mode == DisplayMode::Host) return std::make_unique<X11Host>(p, u, dry);
    return std::make_unique<X11Nested>(p, u, session, dry);
}

void write_xauth(const fs::path& file, const std::string& num, const std::string& cookie) {
    auto be16 = [](std::string& s, uint16_t v) { s.push_back(char(v >> 8)); s.push_back(char(v & 0xff)); };
    static const std::string name = "MIT-MAGIC-COOKIE-1";
    std::string d;
    be16(d, 0xffff);                       // FamilyWild
    be16(d, 0);                            // empty address
    be16(d, static_cast<uint16_t>(num.size())); d += num;
    be16(d, static_cast<uint16_t>(name.size())); d += name;
    be16(d, static_cast<uint16_t>(cookie.size())); d += cookie;
    write_file(file, d, 0600);
}

bool xephyr_advertises_glamor(const fs::path& xephyr) {
    // -help is part of the X server option parser and exits without opening a display. Some builds print it on stderr.
    const RunResult r = capture_all({xephyr.string(), "-help"});
    return lower(r.out).find("glamor") != std::string::npos;
}

}  // namespace hf::display
