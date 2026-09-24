#include "sandbox/fs.h"

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <filesystem>
#include <fstream>

#include "sandbox/check.h"

namespace fs = std::filesystem;

namespace zaun {
namespace {

const std::string kOldRoot = "/.oldroot";
const char* const kSystemDirs[] = {"/usr", "/lib", "/lib64", "/bin"};
const char* const kEtcFiles[] = {"/etc/ld.so.cache", "/etc/ssl/certs"};
const char* const kDevices[] = {"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom"};

void do_mount(const char* src, const std::string& dst, const char* type, unsigned long flags,
              const char* data = nullptr) {
    check(mount(src, dst.c_str(), type, flags, data) == 0, "mount " + dst);
}

// Binds host `path` at the same path, then remounts with `flags`. Missing paths are skipped.
void bind(const std::string& path, unsigned long flags) {
    std::string src = kOldRoot + path;
    struct stat st;
    if (lstat(src.c_str(), &st) < 0) {
        check(errno == ENOENT, "stat " + src);
        return;
    }
    fs::create_directories(fs::path(path).parent_path());
    if (S_ISLNK(st.st_mode)) {
        fs::create_symlink(fs::read_symlink(src), path);
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        fs::create_directory(path);
    } else {
        int fd = open(path.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0644);
        check(fd >= 0, "create " + path);
        close(fd);
    }
    do_mount(src.c_str(), path, nullptr, MS_BIND);

    // A userns can't clear the source mount's flags, so carry them over.
    struct statvfs sv;
    check(statvfs(path.c_str(), &sv) == 0, "statvfs " + path);
    unsigned long keep = sv.f_flag & (ST_NOSUID | ST_NODEV | ST_NOEXEC | ST_NOATIME | ST_NODIRATIME);
    if (sv.f_flag & ST_RELATIME) {
        keep |= MS_RELATIME;
    } else if (!(sv.f_flag & ST_NOATIME)) {
        keep |= MS_STRICTATIME;
    }
    do_mount(nullptr, path, nullptr, MS_REMOUNT | MS_BIND | flags | keep);
}

}  // namespace

void setup_fs(const std::string& workdir) {
    do_mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE);

    // pivot_root onto a tmpfs over /tmp; the host /tmp stays reachable under the old root.
    do_mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "size=1m,mode=0755");
    fs::create_directory("/tmp" + kOldRoot);
    check(syscall(SYS_pivot_root, "/tmp", ("/tmp" + kOldRoot).c_str()) == 0, "pivot_root");
    check(chdir("/") == 0, "chdir /");

    for (const char* p : kSystemDirs) bind(p, MS_RDONLY | MS_NOSUID | MS_NODEV);
    for (const char* p : kEtcFiles) bind(p, MS_RDONLY | MS_NOSUID | MS_NODEV);

    fs::create_directory("/tmp");
    // ponytail: /tmp is unsized; week 3 adds limits.
    do_mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777");

    fs::create_directory("/dev");
    do_mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_NOEXEC, "size=64k,mode=0755");
    for (const char* d : kDevices) bind(d, MS_NOSUID | MS_NOEXEC);

    fs::create_directories("/etc");
    std::ofstream passwd("/etc/passwd");
    passwd << "zaun:x:" << getuid() << ':' << getgid() << "::" << workdir << ":/bin/sh\n";
    passwd.close();
    check(passwd.good(), "write /etc/passwd");

    bind(workdir, MS_NOSUID | MS_NODEV);

    // proc must be mounted while the host's /proc is still visible.
    fs::create_directory("/proc");
    do_mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC);

    check(umount2(kOldRoot.c_str(), MNT_DETACH) == 0, "umount " + kOldRoot);
    fs::remove(kOldRoot);
    check(chdir(workdir.c_str()) == 0, "chdir " + workdir);
}

std::vector<PathRule> sandbox_rules(const std::string& workdir) {
    std::vector<PathRule> rules;
    for (const char* p : kSystemDirs) rules.push_back({p, kRead | kExec});
    // The root tmpfs, /etc and /dev are writable at the mount level; Landlock keeps them read-only.
    rules.push_back({"/etc", kRead});
    rules.push_back({"/proc", kRead});
    rules.push_back({"/dev", kRead});
    for (const char* d : kDevices) rules.push_back({d, kRead | kWrite});
    for (const std::string& p : {std::string("/tmp"), workdir}) {
        rules.push_back({p, kRead | kWrite | kExec | kRefer});
    }
    return rules;
}

}  // namespace zaun
