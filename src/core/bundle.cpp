#include "core/bundle.hpp"

#include <regex>

#include "util/log.hpp"

namespace hf {

std::string alpine_arch() {
    std::string a = host_arch();
    if (a == "x86_64" || a == "aarch64") return a;
    throw Error("unsupported architecture for the Alpine bundle: " + a);
}

std::string provision_stamp(const Profile& p) {
    return sha256_str(cat(p.alpine_version, "|", p.alpine_mirror, "|", p.alpine_sha256, "|",
                          join(p.apk_packages, " "), "|", join(p.provision, "\n")));
}

bool bundle_installed(const Paths& paths) { return fs::exists(paths.rootfs / "bin/busybox") || fs::exists(paths.rootfs / "bin/sh"); }

bool bundle_provisioned(const Profile& p, const Paths& paths) {
    try { return trim(read_file(paths.state / "provision.stamp")) == provision_stamp(p); }
    catch (...) { return false; }
}

static void download(const std::string& url, const fs::path& out) {
    if (url.rfind("https://", 0) != 0) throw Error("refusing non-HTTPS download: " + url);
    auto r = run({"curl", "-fsSL", "--proto", "=https", "--tlsv1.2", "--retry", "2", "-o", out.string(), url});
    if (!r.ok()) { std::error_code ec; fs::remove(out, ec); throw Error("download failed: " + url); }
}

static std::string download_text(const std::string& url) {
    if (url.rfind("https://", 0) != 0) throw Error("refusing non-HTTPS download: " + url);
    auto r = capture({"curl", "-fsSL", "--proto", "=https", "--tlsv1.2", "--retry", "2", url});
    if (!r.ok()) throw Error("download failed: " + url);
    return r.out;
}

static fs::path fetch_alpine(const Profile& p, const Paths& paths, bool force) {
    const std::string arch = alpine_arch();
    const fs::path dir = paths.cache / "alpine" / arch;
    make_private_dir(dir);

    // A pinned hash lets us reuse a cached tarball without any network access.
    if (!force && !p.alpine_sha256.empty()) {
        for (auto& e : fs::directory_iterator(dir))
            if (e.path().extension() == ".gz" && sha256_file(e.path()) == p.alpine_sha256) return e.path();
    }

    const std::string base = cat(p.alpine_mirror, "/", p.alpine_version, "/releases/", arch, "/");
    log::info("looking up Alpine minirootfs at " + base);
    std::string index = download_text(base);
    std::smatch m;
    std::regex re(cat("alpine-minirootfs-[0-9.]+-", arch, R"(\.tar\.gz)"));
    std::string name;
    for (auto it = std::sregex_iterator(index.begin(), index.end(), re); it != std::sregex_iterator(); ++it)
        name = it->str();   // keep the last (listing is sorted ascending)
    if (name.empty()) throw Error("no alpine-minirootfs tarball for " + arch + " at " + base);

    fs::path tarball = dir / name;
    if (!fs::exists(tarball) || force) {
        log::info("downloading " + name);
        download(base + name, tarball);
    }
    std::string want = p.alpine_sha256;
    if (want.empty()) {
        std::string remote = download_text(base + name + ".sha256");
        want = lower(trim(remote).substr(0, 64));
        if (!is_hex(want, 64)) throw Error("could not parse " + name + ".sha256");
    }
    std::string got = sha256_file(tarball);
    if (got != want) {
        std::error_code ec; fs::remove(tarball, ec);
        throw Error(cat("sha256 mismatch for ", name, "\n  expected ", want, "\n  actual   ", got));
    }
    log::info("sha256 verified: " + got);
    return tarball;
}

static void extract(const fs::path& tarball, const Paths& paths) {
    fs::path tmp = paths.state / "rootfs.tmp";
    std::error_code ec;
    fs::remove_all(tmp, ec);
    make_private_dir(tmp);
    auto r = run({"tar", "-C", tmp.string(), "--no-same-owner", "--exclude=./dev/*", "-xzf", tarball.string()});
    if (!r.ok()) throw Error("failed to extract " + tarball.string());
    if (!fs::exists(tmp / "bin")) throw Error("tarball does not look like a rootfs");
    fs::remove_all(paths.rootfs, ec);
    fs::rename(tmp, paths.rootfs);
}

static ArgBuilder writable_args(const Profile& p, const User& u, const Paths& paths, const fs::path& session, bool root_uid) {
    ArgBuilder b;
    b.flag("--unshare-all").flag("--unshare-user").flag("--share-net").flag("--die-with-parent");
    if (root_uid) b.raw({"--uid", "0", "--gid", "0"});   // apk needs to chown as "root" (userns-mapped to you)
    b.raw({"--hostname", "holdfast-provision"});
    b.bind(paths.rootfs, "/");
    b.raw({"--proc", "/proc"}).raw({"--dev", "/dev"}).tmpfs("/tmp");
    write_file(session / "resolv.conf", pasta_resolv_conf(), 0644);   // runs inside pasta; see launch.hpp
    b.ro_bind(session / "resolv.conf", "/etc/resolv.conf");
    make_private_dir(paths.home);
    const fs::path fh = fs::path("/home") / p.fake_user;
    b.bind(paths.home, fh);
    b.flag("--clearenv");
    b.setenv("HOME", fh.string()).setenv("USER", p.fake_user);
    b.setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:" + (fh / ".cargo/bin").string() + ":" + (fh / "go/bin").string());
    if (const char* t = std::getenv("TERM")) b.setenv("TERM", t);
    (void)u;
    return b;
}

void bundle_setup(const Profile& p, const User& u, const Paths& paths, const fs::path& session, bool force) {
    make_private_dir(paths.state);
    if (force || !bundle_installed(paths)) {
        fs::path tb = fetch_alpine(p, paths, force);
        extract(tb, paths);
        std::error_code ec;
        fs::remove(paths.state / "provision.stamp", ec);
    } else {
        log::info("bundle already extracted (use --force to rebuild)");
    }
    if (!force && bundle_provisioned(p, paths)) { log::info("bundle is up to date"); return; }

    std::string script = "set -e\n";
    if (!p.apk_packages.empty()) {
        script += "apk update\napk add --no-cache";
        for (auto& pk : p.apk_packages) script += " " + shell_quote(pk);
        script += "\n";
    }
    for (auto& l : p.provision) script += l + "\n";

    log::warn("provisioning runs WITH network (via pasta, a private namespace) inside the bundle (as userns-root); only your profile's lines execute");
    ArgBuilder b = writable_args(p, u, paths, session, true);
    b.command({"/bin/sh", "-c", script});
    auto la = pasta_argv(find_pasta(), launcher_argv(find_bwrap(), session, b, ""));
    int rc = run_with_signals(as_user(u, la));
    if (rc != 0) throw Error(cat("provisioning failed (exit ", rc, "); fix the profile and re-run `bundle setup`"));
    write_file(paths.state / "provision.stamp", provision_stamp(p) + "\n", 0600);
    log::info("bundle ready: " + paths.rootfs.string());
}

int bundle_shell(const Profile& p, const User& u, const Paths& paths, const fs::path& session) {
    if (!bundle_installed(paths)) throw Error("bundle not installed; run: holdfast bundle setup " + p.name);
    ArgBuilder b = writable_args(p, u, paths, session, true);
    b.command({"/bin/sh"});
    return run_with_signals(as_user(u, pasta_argv(find_pasta(), launcher_argv(find_bwrap(), session, b, ""))));
}

void bundle_purge(const Paths& paths, bool everything) {
    std::error_code ec;
    const fs::path target = everything ? paths.state : paths.rootfs;
    if (!fs::exists(target)) return;
    // Files extracted from the tarball may be read-only.
    run({"chmod", "-R", "u+rwX", "--", target.string()}, true);
    fs::remove_all(target, ec);
    if (!everything) fs::remove(paths.state / "provision.stamp", ec);
    ec.clear();
}

}  // namespace hf
