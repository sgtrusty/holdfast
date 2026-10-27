#include "core/bundle.hpp"

#include "core/datadefs.hpp"
#include "core/plan.hpp"
#include "core/seccomp.hpp"
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

// Everything the OS file declares (version, mirror, pinned hash, packages). Provision lines are per profile
// and are not part of it. All profiles naming the same os read the same file, so a mismatch means the file
// changed after the bundle was built (or two data directories define the same os name differently).
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

bool bundle_provisioned(const Profile& p, const Paths& paths) {
    try { return trim(read_file(paths.state / "provision.stamp")) == provision_stamp(p); }
    catch (...) { return false; }
}

namespace {

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

// apk add + the profile's provision lines, in a writable sandbox with network through pasta.
void provision(const Profile& p, const User& u, const Paths& paths, const fs::path& session) {
    std::string script = "set -e\n";
    if (!p.apk_packages.empty()) {
        script += "apk update\napk add --no-cache";
        for (auto& pk : p.apk_packages) script += " " + shell_quote(pk);
        script += "\n";
    }
    for (auto& l : p.provision) script += l + "\n";

    log::warn("provisioning runs WITH network (via pasta, a private namespace) inside the userland (as userns-root); only your profile's lines execute");
    ArgBuilder b = writable_args(p, paths, session);
    b.command({"/bin/sh", "-c", script});
    const int rc = run_sandbox(as_user(u, pasta_argv(find_pasta(), launcher_argv(find_bwrap(), session, b, ""))), p.terminal == TermMode::Filter);
    if (rc != 0) throw Error(cat("provisioning failed (exit ", rc, "); fix the profile (or data/os/", p.os, ".profile) and run it again"));
    write_file(paths.state / "provision.stamp", provision_stamp(p) + "\n", 0600);
}

}  // namespace

void bundle_ensure(const Profile& p, const User& u, const Paths& paths, bool refresh, bool dry) {
    const bool installed = bundle_installed(paths);
    if (dry) {                                                     // print / check never download anything
        if (!installed)
            throw Error(cat("the Alpine userland for '", p.name, "' is not set up yet; run the profile once (holdfast run ", p.name, ") and it is created"));
        bundle_verify(p, paths);
        return;
    }
    if (installed && !refresh) {
        bundle_verify(p, paths);                                   // a changed definition is an error, never a silent rebuild
        if (bundle_provisioned(p, paths)) return;                  // the common case: nothing to do
    }

    make_private_dir(paths.state);
    struct Scratch { fs::path d; ~Scratch() { std::error_code ec; fs::remove_all(d, ec); } } sc{make_session_dir(u, paths, p.name + "-setup")};
    if (refresh || !installed) {
        log::info(installed ? "rebuilding the Alpine userland (--refresh)" : "first run: setting up the Alpine userland");
        fetch_and_extract(p, u, paths, sc.d);
        write_file(paths.bundle / "spec.stamp", bundle_spec(p) + "\n", 0600);
        std::error_code ec;
        fs::remove(paths.state / "provision.stamp", ec);           // a fresh rootfs has none of the packages or provisioned files
    }
    provision(p, u, paths, sc.d);
    log::info("userland ready: " + paths.rootfs.string());
}

}  // namespace hf
