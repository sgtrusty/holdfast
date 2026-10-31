// holdfast - typed builder for bubblewrap argument vectors
#pragma once
#include "util/common.hpp"

namespace hf {

class ArgBuilder {
public:
    ArgBuilder& raw(std::initializer_list<std::string> a) { for (auto& s : a) v_.push_back(s); return *this; }
    ArgBuilder& flag(const std::string& f) { v_.push_back(f); return *this; }
    ArgBuilder& ro_bind(const fs::path& s, const fs::path& d) { return raw({"--ro-bind", s.string(), d.string()}); }
    ArgBuilder& ro_bind_try(const fs::path& s, const fs::path& d) { return raw({"--ro-bind-try", s.string(), d.string()}); }
    ArgBuilder& bind(const fs::path& s, const fs::path& d) { return raw({"--bind", s.string(), d.string()}); }
    ArgBuilder& bind_try(const fs::path& s, const fs::path& d) { return raw({"--bind-try", s.string(), d.string()}); }
    ArgBuilder& dev_bind(const fs::path& s, const fs::path& d) { return raw({"--dev-bind", s.string(), d.string()}); }
    ArgBuilder& tmpfs(const fs::path& d) { return raw({"--tmpfs", d.string()}); }
    ArgBuilder& dir(const fs::path& d) { return raw({"--dir", d.string()}); }
    ArgBuilder& symlink(const std::string& target, const fs::path& d) { return raw({"--symlink", target, d.string()}); }
    ArgBuilder& setenv(const std::string& k, const std::string& val) { return raw({"--setenv", k, val}); }
    ArgBuilder& chdir(const fs::path& d) { return raw({"--chdir", d.string()}); }
    ArgBuilder& command(const Strings& argv) { cmd_ = argv; return *this; }  // kept apart: bwrap only accepts it on the real argv

    const Strings& args() const { return v_; }
    const Strings& cmd() const { return cmd_; }

    // NUL-terminated serialisation for `bwrap --args FD`.
    std::string serialize() const { std::string o; for (auto& s : v_) { o += s; o.push_back('\0'); } return o; }

    // Human-readable, one option group per line (for --dry-run / print).
    std::string pretty() const {
        std::string o = "bwrap";
        size_t i = 0;
        while (i < v_.size()) {
            const std::string& a = v_[i];
            size_t n = 0;
            if (a == "--bind" || a == "--ro-bind" || a == "--bind-try" || a == "--ro-bind-try" || a == "--dev-bind" || a == "--symlink" || a == "--setenv" || a == "--chmod") n = 2;
            else if (a == "--tmpfs" || a == "--dir" || a == "--proc" || a == "--dev" || a == "--chdir" || a == "--hostname" || a == "--cap-drop" || a == "--uid" || a == "--gid" || a == "--unsetenv") n = 1;
            o += " \\\n  " + a;
            for (size_t j = 1; j <= n && i + j < v_.size(); ++j) o += " " + shell_quote(v_[i + j]);
            i += 1 + n;
        }
        o += " \\\n  --";
        for (auto& w : cmd_) o += " " + shell_quote(w);
        return o;
    }

private:
    Strings v_, cmd_;
};

}  // namespace hf
