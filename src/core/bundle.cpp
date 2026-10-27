#include "core/bundle.hpp"

#include "core/datadefs.hpp"
#include "core/plan.hpp"
#include "core/seccomp.hpp"
#include "core/session.hpp"
#include "util/log.hpp"

namespace hf {

std::string alpine_arch() {
    std::string a = host_arch();
    if (a == "x86_64" || a == "aarch64") return a;
    throw Error("unsupported architecture for the Alpine bundle: " + a);
}

// A dep is installed into the profile's persistent $HOME, so its stamp depends on the recipe and on that home's path.
std::string dep_stamp(const Profile& p, const DepRecipe& d) { return sha256_str(cat(d.digest, "|", p.fake_user)); }

// Everything the OS file declares (version, mirror, pinned hash, packages). Deps are per profile and are not part of
// it. All profiles naming the same os read the same file, so a mismatch means the file changed after the bundle was
// built (or two data directories define the same os name differently).
std::string bundle_spec(const Profile& p) {
    return sha256_str(cat(p.alpine_version, "|", p.alpine_mirror, "|", p.alpine_sha256, "|", join(p.apk_packages, " ")));
}

void bundle_verify(const Profile& p, const Paths& paths) {
    std::string have, tar;
    try { have = trim(read_file(paths.bundle / "spec.stamp")); } catch (...) {}
    try { tar = trim(read_file(paths.bundle / "tarball.sha256")); } catch (...) {}
    const std::string id = paths.bundle.filename().string();
    const std::string fix = cat("re-run with --refresh to rebuild it (holdfast run --refresh ", p.name, "); changes made inside it are discarded");
    if (have.empty())
        throw Error(cat("the userland '", id, "' has no spec.stamp (not built by this holdfast?); ", fix));
    if (have != bundle_spec(p))
        throw Error(cat("the userland '", id, "' was built from a different data/os/", id, ".profile (version, mirror, sha256 or packages) "
                        "than the one now in use; ", fix));
    if (!p.alpine_sha256.empty() && tar != p.alpine_sha256)
        throw Error(cat("the userland '", id, "' was built from tarball ", tar, " but data/os/", id, ".profile pins ", p.alpine_sha256, "; ", fix));
}

bool bundle_installed(const Paths& paths) { return fs::exists(paths.rootfs / "bin/busybox") || fs::exists(paths.rootfs / "bin/sh"); }

namespace {

std::string read_stamp(const fs::path& f) {
    try { return trim(read_file(f)); } catch (...) { return ""; }
}
fs::path dep_stamp_path(const Paths& paths, const DepRecipe& d) { return paths.state / "deps" / (d.name + ".stamp"); }

// Runs in the bootstrap sandbox. Constant text: all data arrives through HF_* environment variables, never by
// interpolation. /cache holds downloaded tarballs, /work is the bundle directory.
const char* kBootstrapScript = R"SH(
set -eu
umask 077
cd /cache
if [ -f "$HF_NAME" ] && [ -n "$HF_SHA" ] && echo "$HF_SHA  $HF_NAME" | sha256sum -c - >/dev/null 2>&1; then
  echo "using cached $HF_NAME" >&2
else
  rm -f "$HF_NAME"
  echo "downloading $HF_NAME" >&2
  curl -fsSL --proto =https --tlsv1.2 --retry 2 -o "$HF_NAME" "$HF_BASE/$HF_NAME"
fi
want="$HF_SHA"
if [ -z "$want" ]; then
  echo "warning: no alpine_sha256 pinned; trusting the mirror's .sha256 (integrity only, not authenticity)" >&2
  want=$(curl -fsSL --proto =https --tlsv1.2 --retry 2 "$HF_BASE/$HF_NAME.sha256" | cut -d' ' -f1)
fi
if ! echo "$want  $HF_NAME" | sha256sum -c - >&2; then
  rm -f "$HF_NAME"
  echo "sha256 mismatch for $HF_NAME" >&2
  exit 3
fi
cd /work
chmod -R u+rwX rootfs rootfs.tmp 2>/dev/null || true
rm -rf rootfs rootfs.tmp spec.stamp tarball.sha256
mkdir rootfs.tmp
tar -C rootfs.tmp --no-same-owner --exclude='./dev/*' -xzf "/cache/$HF_NAME"
[ -d rootfs.tmp/bin ] || { echo "tarball does not look like a rootfs" >&2; exit 4; }
mv rootfs.tmp rootfs
printf '%s\n' "$want" > tarball.sha256
echo "userland ready" >&2
)SH";

// Download, verify and extract the Alpine minirootfs INSIDE a throwaway sandbox: the host only supplies the
// curl/tar/sha256sum binaries, and the sandbox sees nothing of your files, only the two folders it writes.
void fetch_and_extract(const Profile& p, const User& u, const Paths& paths, const fs::path& session) {
    std::string branch;
    if (!is_exact_alpine_release(p.alpine_version, &branch))
        throw ProfileError(cat("alpine_version '", p.alpine_version, "' must be an exact release such as 3.24.3 (data/os/", p.os, ".profile)"));
    if (p.alpine_mirror.rfind("https://", 0) != 0) throw ProfileError("alpine_mirror must be an https:// URL: " + p.alpine_mirror);
    const std::string arch = alpine_arch();
    const std::string ver = p.alpine_version.front() == 'v' ? p.alpine_version.substr(1) : p.alpine_version;
    const std::string name = cat("alpine-minirootfs-", ver, "-", arch, ".tar.gz");

    ArgBuilder b;
    b.flag("--unshare-all").flag("--unshare-user").flag("--share-net").flag("--die-with-parent");
    b.raw({"--cap-drop", "ALL"}).raw({"--hostname", "holdfast-bootstrap"});
    b.raw({"--proc", "/proc"}).raw({"--dev", "/dev"}).tmpfs("/tmp");
    b.dir("/usr/bin");
    b.symlink("usr/bin", "/bin").symlink("usr/bin", "/sbin").symlink("usr/bin", "/usr/sbin");
    bind_host_library_dirs(b, true);
    for (const char* tool : {"sh", "curl", "tar", "gzip", "sha256sum", "cut", "chmod", "rm", "mkdir", "mv"}) {
        auto host = which(tool);
        std::error_code ec;
        const fs::path real = host ? fs::canonical(*host, ec) : fs::path();
        if (!host || ec)
            throw Error(cat("fetching the userland needs '", tool, "' installed on the host (it runs inside a sandbox, but the binary comes from the host)"));
        b.ro_bind(real, fs::path("/usr/bin") / tool);
        if (real != *host) b.ro_bind_try(real, real);              // multi-call/alternatives targets that look for themselves
    }
    for (const char* d : {"/etc/ld.so.cache", "/etc/ssl", "/etc/ca-certificates"})
        if (fs::exists(d)) b.ro_bind_try(d, d);                    // CA certificates for https
    write_file(session / "resolv.conf", pasta_resolv_conf(), 0644);   // network is pasta's private namespace
    b.ro_bind(session / "resolv.conf", "/etc/resolv.conf");
    const fs::path cache = paths.cache / "alpine" / arch;
    make_private_dir(cache);
    make_private_dir(paths.bundle);
    b.bind(cache, "/cache").bind(paths.bundle, "/work");
    b.flag("--clearenv").setenv("HOME", "/tmp").setenv("PATH", "/usr/bin");
    b.setenv("HF_BASE", cat(p.alpine_mirror, "/", branch, "/releases/", arch)).setenv("HF_NAME", name).setenv("HF_SHA", p.alpine_sha256);
    b.command({"/bin/sh", "-c", kBootstrapScript});

    fs::path seccomp;
    if (p.seccomp != "none") { seccomp = session / "seccomp.bpf"; write_default_seccomp(seccomp); }
    log::info(cat("fetching ", name, " inside a sandbox (network via pasta)"));
    const int rc = run_sandbox(as_user(u, pasta_argv(find_pasta(), launcher_argv(find_bwrap(), session, b, seccomp))),
                               p.terminal == TermMode::Filter);
    if (rc == 3) throw Error(cat("sha256 mismatch for ", name, ": the download does not match the hash in data/os/", p.os, ".profile; nothing was installed"));
    if (rc != 0) throw Error(cat("fetching the Alpine userland failed (exit ", rc, "); see the messages above"));
}

ArgBuilder writable_args(const Profile& p, const Paths& paths, const fs::path& session) {
    ArgBuilder b;
    b.flag("--unshare-all").flag("--unshare-user").flag("--share-net").flag("--die-with-parent");
    b.raw({"--uid", "0", "--gid", "0"});                          // apk needs to chown as "root" (userns-mapped to you)
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
    return b;
}

// The ONE step that is not an ordinary profile run: `apk add` for the os packages. A package manager must own the whole
// userland, so this sandbox is deliberately different and says so: the rootfs is bound WRITABLE at /, `--uid 0` makes it
// userns-root (your uid mapped to 0, no real privilege), and the network is pasta's private namespace. Deps do not
// use this; they run as the profile itself (see dep_profile).
void install_os_packages(const Profile& p, const User& u, const Paths& paths, const fs::path& session) {
    std::string script = "set -e\napk update\napk add --no-cache";
    for (auto& pk : p.apk_packages) script += " " + shell_quote(pk);
    log::info(cat("installing the os packages with apk: writable rootfs, userns-root, network via pasta (data/os/", p.os, ".profile)"));
    ArgBuilder b = writable_args(p, paths, session);
    b.command({"/bin/sh", "-c", script + "\n"});
    const int rc = run_sandbox(as_user(u, pasta_argv(find_pasta(), launcher_argv(find_bwrap(), session, b, ""))), p.terminal == TermMode::Filter);
    if (rc != 0) throw Error(cat("installing the os packages failed (exit ", rc, "); see the messages above and check data/os/", p.os, ".profile"));
}

void install_dep(const Profile& p, const DepRecipe& d) {
    // The recipe's own tools are checked first, so a missing `go` is one clear sentence instead of a half-run build.
    std::string script = "set -e\n";
    for (const auto& n : d.needs)
        script += cat("command -v ", shell_quote(n), " >/dev/null 2>&1 || { echo ",
                      shell_quote(cat("dep '", d.name, "' needs '", n, "' in the userland: add its package to data/os/", p.os, ".profile")),
                      " >&2; exit 5; }\n");
    for (const auto& l : d.run) script += l + "\n";

    RunOptions ro;
    ro.no_cwd = true;
    ro.yes = true;
    ro.userland_ready = true;                                      // the userland and its packages are already in place
    ro.command = {"/bin/sh", "-c", script};
    log::info(cat("dep '", d.name, "': an ordinary run of '", p.name, "' with network=", d.net == NetMode::Pasta ? "pasta" : "none",
                  " and this recipe as the command"));
    const int rc = run_profile(dep_profile(p, d), ro);
    if (rc != 0) throw Error(cat("dep '", d.name, "' failed (exit ", rc, "); see the messages above, fix data/dep/", d.name, ".profile and run again"));
}

}  // namespace

Profile dep_profile(const Profile& p, const DepRecipe& d) {
    Profile r = p;
    r.net = d.net;
    r.cwd = CwdMode::None;
    r.display.reset();
    r.display_use.clear();
    r.allow_host_display = false;
    r.audio = false;
    r.clipboard_out = false;
    r.dep_use.clear();
    r.deps.clear();
    return r;
}

void bundle_ensure(const Profile& p, const User& u, const Paths& paths, bool refresh, bool dry) {
    const bool installed = bundle_installed(paths);
    if (dry) {                                                     // print / check never download or install anything
        if (!installed)
            throw Error(cat("the Alpine userland for '", p.name, "' is not set up yet; run the profile once (holdfast run ", p.name, ") and it is created"));
        bundle_verify(p, paths);
        return;
    }

    // Decide what is out of date before creating anything. A changed definition is an error unless --refresh.
    bool rebuild = !installed;
    if (installed) {
        try { bundle_verify(p, paths); }
        catch (const Error&) { if (!refresh) throw; rebuild = true; }
    }
    const bool packages_due = rebuild || read_stamp(paths.bundle / "packages.stamp") != bundle_spec(p);
    std::vector<const DepRecipe*> due;
    for (const auto& d : p.deps) {
        const std::string have = read_stamp(dep_stamp_path(paths, d));
        if (refresh || have.empty()) { due.push_back(&d); continue; }
        if (have != dep_stamp(p, d))
            throw Error(cat("dep '", d.name, "' changed since it was installed into '", p.name, "'; reinstall with: holdfast run --refresh ",
                            p.name, " (its commands run again)"));
    }
    if (!rebuild && !packages_due && due.empty()) return;          // the common case: nothing to do

    make_private_dir(paths.state);
    struct Scratch { fs::path d; ~Scratch() { std::error_code ec; fs::remove_all(d, ec); } } sc{make_session_dir(u, paths, p.name + "-setup")};
    if (rebuild) {
        log::info(installed ? "rebuilding the Alpine userland (its definition changed)" : "first run: setting up the Alpine userland");
        fetch_and_extract(p, u, paths, sc.d);
        write_file(paths.bundle / "spec.stamp", bundle_spec(p) + "\n", 0600);
        std::error_code ec;
        fs::remove(paths.bundle / "packages.stamp", ec);           // a fresh rootfs has none of the packages
    }
    if (packages_due) {
        if (!p.apk_packages.empty()) install_os_packages(p, u, paths, sc.d);
        write_file(paths.bundle / "packages.stamp", bundle_spec(p) + "\n", 0600);
    }
    for (const DepRecipe* d : due) {
        install_dep(p, *d);
        make_private_dir(paths.state / "deps");
        write_file(dep_stamp_path(paths, *d), dep_stamp(p, *d) + "\n", 0600);
    }
    log::info("userland ready: " + paths.rootfs.string());
}

}  // namespace hf
