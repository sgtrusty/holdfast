#include "cli/doctor.hpp"

#include <cstdio>

#include "cli/args.hpp"
#include "core/datadefs.hpp"
#include "core/launch.hpp"
#include "core/seccomp.hpp"
#include "util/style.hpp"
#include "util/sys.hpp"

namespace hf {

namespace {

struct FeatureSpec { const char* name; Strings tools; };

// What each optional capability needs from the host. Add a feature here and it shows up in `doctor`.
const std::vector<FeatureSpec>& feature_specs() {
    static const std::vector<FeatureSpec> v = {
        {"net = pasta",       {"pasta"}},
        {"bundle profiles",   {"pasta", "curl", "tar", "gzip", "sha256sum"}},
        {"net = ivpn",        {"ip", "iptables", "wg-quick", "wg", "ping", "sudo", "setpriv", "?ip6tables"}},
        {"display = xephyr",  {"Xephyr"}},
        {"clipboard = out",   {"xclip|wl-copy"}},
    };
    return v;
}

// Distro package names that differ from the tool name, so a missing tool comes with the thing to install.
const char* package_for(const std::string& tool) {
    static const std::vector<std::pair<const char*, const char*>> m = {
        {"bwrap", "bubblewrap"}, {"pasta", "passt"}, {"wg-quick", "wireguard-tools"}, {"wg", "wireguard-tools"},
        {"Xephyr", "xserver-xephyr"}, {"ip", "iproute2"}, {"iptables", "iptables"}, {"setpriv", "util-linux"},
        {"xclip", "xclip"}, {"wl-copy", "wl-clipboard"},
    };
    for (const auto& [t, pkg] : m) if (tool == t) return pkg;
    return nullptr;
}

bool any_of(const std::function<bool(const std::string&)>& have, const std::string& spec) {
    size_t a = 0;
    for (;;) {
        const size_t b = spec.find('|', a);
        if (have(spec.substr(a, b == std::string::npos ? std::string::npos : b - a))) return true;
        if (b == std::string::npos) return false;
        a = b + 1;
    }
}

std::string with_package(const std::string& tool) {
    const char* pkg = package_for(tool);
    return pkg && tool != pkg ? cat(tool, " (package ", pkg, ")") : tool;
}

}  // namespace

std::vector<FeatureStatus> evaluate_features(const std::function<bool(const std::string&)>& have) {
    std::vector<FeatureStatus> out;
    for (const auto& spec : feature_specs()) {
        FeatureStatus s;
        s.name = spec.name;
        for (const std::string& t : spec.tools) {
            const bool optional = !t.empty() && t[0] == '?';
            const std::string tool = optional ? t.substr(1) : t;
            if (any_of(have, tool)) continue;
            (optional ? s.missing_optional : s.missing).push_back(tool);
        }
        out.push_back(s);
    }
    return out;
}

int doctor() {
    const Style st = style_for(stdout);
    int bad = 0;
    auto head = [&](const char* t) { std::printf("\n%s%s%s\n", st.b, t, st.r); };
    auto row = [&](const char* tag, const char* colour, const std::string& what, const std::string& detail) {
        std::printf("  %s[%s]%s %-26s %s\n", colour, tag, st.r, what.c_str(), detail.c_str());
    };

    std::printf("%sholdfast%s %s doctor\n", st.b, st.r, HOLDFAST_VERSION);

    head("WHERE THINGS LIVE");
    try {                                                           // plain folders: open, edit or delete them yourself
        const User u = resolve_user();
        std::printf("  %-24s %s\n", "state, bundles, caches", make_paths(u, "x").data.c_str());
        bool first = true;
        for (const auto& r : data_roots(u.home.string())) {
            std::error_code ec;
            const bool exists = fs::is_directory(r, ec);
            std::printf("  %-24s %s%s%s\n", first ? "data files (first wins)" : "", exists ? "" : st.y, r.c_str(), exists ? "" : st.r);
            first = false;
        }
        std::printf("  %-24s %s(yellow = not there; put your own profile/, lib/, os/, dep/ in any of them)%s\n", "", st.y, st.r);
    } catch (const Error&) {}

    head("REQUIRED");
    const auto bw = which("bwrap");
    if (!bw) {
        row("FAIL", st.x, "bwrap", "not found: install bubblewrap (apt/dnf/pacman: bubblewrap)");
        ++bad;
    } else {
        const BwrapVersion v = bwrap_version(*bw);
        row(" ok ", st.g, "bwrap", cat(v.major, ".", v.minor, ".", v.patch, "  ", bw->string()));
        if (!v.at_least(0, 8, 0)) row("warn", st.y, "bwrap >= 0.8", "older bwrap works, but nested user namespaces are not blocked (--disable-userns)");
        const auto r = run({bw->string(), "--unshare-user", "--ro-bind", "/", "/", "true"}, true);
        if (r.ok()) {
            row(" ok ", st.g, "user namespaces", "unprivileged");
        } else {
            row("FAIL", st.x, "user namespaces", "blocked for unprivileged users (Ubuntu 24.04: kernel.apparmor_restrict_unprivileged_userns=0, or an AppArmor profile for bwrap)");
            ++bad;
        }
    }

    head("FEATURES");
    const auto features = evaluate_features([](const std::string& t) { return which(t).has_value(); });
    const bool seccomp = seccomp_available();
    const size_t width = 26;
    auto feature_row = [&](const std::string& name, bool ready, const std::string& detail, const char* colour) {
        std::printf("  %-*s %s%s%s\n", static_cast<int>(width), name.c_str(), colour, ready ? "ready" : detail.c_str(), st.r);
        if (ready && !detail.empty()) std::printf("  %-*s %s%s%s\n", static_cast<int>(width), "", st.y, detail.c_str(), st.r);
    };
    feature_row("host profiles", true, "", st.g);
    if (seccomp) feature_row("default seccomp filter", true, "", st.g);
    else feature_row("default seccomp filter", false, "not built in: rebuild with libseccomp, or profiles must say `seccomp = none`", st.y);
    for (const auto& f : features) {
        Strings need;
        for (const auto& t : f.missing) need.push_back(with_package(t));
        std::string note;
        if (!f.missing_optional.empty()) note = "also useful: " + join(f.missing_optional, " ");
        if (f.ready()) feature_row(f.name, true, note, st.g);
        else feature_row(f.name, false, "needs " + join(need, ", "), st.y);
    }

    if (bad) std::printf("\n%s%d required item%s missing: holdfast cannot run sandboxes on this host until fixed.%s\n", st.x, bad, bad == 1 ? "" : "s", st.r);
    return bad ? 1 : 0;
}

}  // namespace hf
