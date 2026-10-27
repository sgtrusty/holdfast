#include "core/paths.hpp"

#include <glob.h>
#include <unistd.h>

#include <cstdlib>

namespace hf {

Paths make_paths(const User& u, const std::string& name) {
    Paths p;
    if (const char* e = std::getenv("HOLDFAST_HOME"); e && *e) p.data = e;
    else p.data = u.home / ".local/share/holdfast";
    p.cache = p.data / "cache";
    p.state = p.data / "profiles" / name;
    p.rootfs = p.state / "rootfs";
    p.home = p.state / "home";
    // Never a shared /tmp path: without a per-user runtime dir, stay inside the user's own data dir.
    p.run_root = fs::exists(u.runtime_dir) ? u.runtime_dir / "holdfast" : p.data / "run";
    return p;
}

fs::path make_session_dir(const User&, const Paths& p, const std::string& name) {
    make_secure_dir(p.run_root);
    fs::path d = p.run_root / cat(name, ".", getpid());
    std::error_code ec;
    fs::remove_all(d, ec);
    make_secure_dir(d);
    return d;
}

std::string expand(const std::string& s, const VarCtx& c) {
    std::string out;
    size_t i = 0;
    if (s.rfind("~/", 0) == 0 || s == "~") {
        if (!c.user) throw Error("internal: no user for ~ expansion");
        out = c.user->home.string();
        i = 1;
    }
    for (; i < s.size(); ++i) {
        if (s[i] != '$') { out.push_back(s[i]); continue; }
        size_t j = i + 1;
        std::string var;
        if (j < s.size() && s[j] == '{') {
            size_t e = s.find('}', j);
            if (e == std::string::npos) throw ProfileError("unterminated ${ in: " + s);
            var = s.substr(j + 1, e - j - 1);
            i = e;
        } else {
            while (j < s.size() && (std::isalnum(static_cast<unsigned char>(s[j])) || s[j] == '_')) var.push_back(s[j++]);
            if (var.empty()) { out.push_back('$'); continue; }
            i = j - 1;
        }
        std::string val;
        if (var == "HOME") val = c.user->home.string();
        else if (var == "USER") val = c.user->name;
        else if (var == "UID") val = std::to_string(c.user->uid);
        else if (var == "GID") val = std::to_string(c.user->gid);
        else if (var == "XDG_RUNTIME_DIR") val = c.user->runtime_dir.string();
        else if (var == "STATE" && c.paths) val = c.paths->state.string();
        else if (var == "CWD") val = c.cwd.string();
        else if (var == "ARCH") val = host_arch();
        else if (auto it = c.extra.find(var); it != c.extra.end()) val = it->second;
        else throw ProfileError("unknown variable $" + var + " in: " + s);
        out += val;
    }
    return out;
}

Strings expand_glob(const std::string& s, const VarCtx& c) {
    std::string e = expand(s, c);
    if (e.find_first_of("*?[") == std::string::npos) return {e};
    glob_t g{};
    Strings out;
    if (glob(e.c_str(), GLOB_NOSORT, nullptr, &g) == 0)
        for (size_t i = 0; i < g.gl_pathc; ++i) out.emplace_back(g.gl_pathv[i]);
    globfree(&g);
    return out;
}

// ---- Policy ---------------------------------------------------------------------

Policy::Policy(const User& u, const Strings& extra) : user_(u) {
    const fs::path h = u.home;
    const char* home_rel[] = {
        ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".netrc", ".git-credentials",
        ".password-store", ".pki", ".mozilla", ".librewolf", ".thunderbird",
        ".config/gcloud", ".config/gh", ".config/google-chrome", ".config/chromium",
        ".config/BraveSoftware", ".config/Signal", ".config/Bitwarden", ".config/rclone",
        ".local/share/keyrings", ".local/share/kwalletd", ".npmrc", ".pypirc",
        ".cargo/credentials.toml", ".terraform.d", ".config/holdfast",
        ".config/wssch", ".local/share/holdfast", ".vault-token", ".oci", ".config/op", ".config/1Password",
        ".config/keepassxc", ".config/doctl", ".bash_history", ".zsh_history",
    };
    for (auto r : home_rel) deny_.push_back(canon(h / r));
    const char* abs[] = {
        "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh",
        "/root", "/boot", "/var/run/docker.sock", "/run/docker.sock",
        "/var/lib/docker", "/var/run/libvirt", "/run/libvirt", "/sys", "/proc/kcore", "/tmp/.X11-unix",
    };
    for (auto a : abs) deny_.push_back(canon(a));
    for (const char* r : {"bus", "gnupg", "keyring", "ssh-agent.socket", "gcr", "wayland-0", "wayland-1", "systemd", "docker.sock",
                           "docker", "podman", "pipewire-0", "pulse"})
        deny_.push_back(canon(u.runtime_dir / r));
    VarCtx vc; vc.user = &u;
    for (auto& e : extra) for (auto& x : expand_glob(e, vc)) deny_.push_back(canon(x));
}

bool Policy::is_sensitive_root(const fs::path& p) const {
    fs::path c = canon(p);
    if (c == "/" || c == "/home" || c == "/root" || c == user_.home.parent_path()) return true;
    if (c == canon(user_.home)) return true;
    // removable-media roots: /run/media/USER/<label>, /media/USER/<label>
    for (const char* base : {"/run/media", "/media"}) {
        fs::path b = fs::path(base) / user_.name;
        if (c == b || (c.parent_path() == b)) return true;
    }
    for (const char* top : {"/usr", "/etc", "/var", "/run", "/tmp", "/opt", "/mnt", "/media", "/srv", "/dev", "/proc", "/sys", "/boot", "/bin", "/sbin", "/lib", "/lib64"})
        if (c == top) return true;
    return false;
}

void Policy::check_bind(const fs::path& src, bool rw) const {
    fs::path c = canon(src);
    if (is_sensitive_root(c))
        throw PolicyError(cat("refusing to mount sensitive root '", c.string(), "' (pick a specific subdirectory)"));
    for (const auto& d : deny_) {
        if (path_under(c, d))
            throw PolicyError(cat("'", c.string(), "' is inside denied path '", d.string(), "'"));
        if (path_under(d, c) && fs::exists(d))
            throw PolicyError(cat("'", c.string(), "' would expose denied path '", d.string(), "'"));
    }
    if (rw) {
        for (const char* sys : {"/usr", "/etc", "/boot", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev", "/run/systemd", "/var/lib"})
            if (path_under(c, sys))
                throw PolicyError(cat("refusing read-write mount of system path '", c.string(), "'"));
    }
}

void Policy::check_cwd(const fs::path& dir) const {
    check_bind(dir, true);
}

}  // namespace hf
