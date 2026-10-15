// holdfast - display servers and the one-way clipboard bridge
#pragma once
#include <atomic>
#include <memory>
#include <thread>

#include "core/plan.hpp"

namespace hf {

class XephyrServer {
public:
    // Starts a nested X server on a free display number with a private cookie.
    static std::unique_ptr<XephyrServer> start(const User& u, const Profile& p, const fs::path& session);
    ~XephyrServer();
    const DisplayInfo& info() const { return info_; }
private:
    XephyrServer() = default;
    DisplayInfo info_;
    pid_t pid_ = -1;
};

// Opt-in only (profile must set allow_host_x11 = yes): shares the real X server.
DisplayInfo host_x11(const User& u, const Profile& p);

// Sandbox -> host clipboard. The sandbox writes text to a bound file; we copy it
// to the host clipboard on close. There is no host -> sandbox direction.
class ClipboardBridge {
public:
    ClipboardBridge(const User& u, fs::path file);
    ~ClipboardBridge();
private:
    void loop();
    User user_;
    fs::path file_;
    std::atomic<bool> stop_{false};
    std::thread th_;
};

}  // namespace hf
