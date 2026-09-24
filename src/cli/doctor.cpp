#include "doctor.h"

#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <set>
#include <sstream>
#include <string>

#include "sandbox/landlock.h"

namespace zaun {
namespace {

enum class Status { ok, warn, fail };

bool g_failed = false;

void report(Status s, const char* check, const std::string& detail) {
    static const char* const labels[] = {"ok  ", "warn", "FAIL"};
    std::printf("%s  %-9s %s\n", labels[static_cast<int>(s)], check, detail.c_str());
    if (s == Status::fail) g_failed = true;
}

std::string read_file(const std::string& path) {
    std::ifstream in(path);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool write_file(const char* path, const std::string& s) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = write(fd, s.data(), s.size()) == static_cast<ssize_t>(s.size());
    close(fd);
    return ok;
}

void check_kernel() {
    utsname u{};
    uname(&u);
    int major = 0, minor = 0;
    std::sscanf(u.release, "%d.%d", &major, &minor);
    bool ok = major > 5 || (major == 5 && minor >= 13);
    report(ok ? Status::ok : Status::fail, "kernel",
           std::string(u.release) + " (need >= 5.13)");
}

void check_landlock() {
    int abi = landlock_abi();
    if (abi < 1) {
        report(Status::fail, "landlock", std::string("unavailable: ") + std::strerror(errno));
    } else {
        report(abi >= 4 ? Status::ok : Status::warn, "landlock",
               "ABI " + std::to_string(abi) + (abi >= 4 ? "" : " (< 4: some rules degrade)"));
    }
}

// AppArmor lets unshare succeed and fails later steps, so probe them all.
void check_userns() {
    static const char* const steps[] = {"", "unshare", "setgroups", "uid_map", "gid_map", "mount"};
    uid_t uid = getuid();
    gid_t gid = getgid();
    pid_t pid = fork();
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) _exit(1);
        if (!write_file("/proc/self/setgroups", "deny")) _exit(2);
        if (!write_file("/proc/self/uid_map", std::to_string(uid) + " " + std::to_string(uid) + " 1")) _exit(3);
        if (!write_file("/proc/self/gid_map", std::to_string(gid) + " " + std::to_string(gid) + " 1")) _exit(4);
        if (mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr) < 0) _exit(5);
        _exit(0);
    }
    int status = 0;
    if (pid < 0 || waitpid(pid, &status, 0) < 0 || !WIFEXITED(status)) {
        report(Status::fail, "userns", "probe did not run");
        return;
    }
    int code = WEXITSTATUS(status);
    if (code == 0) {
        report(Status::ok, "userns", "user+mount namespaces usable");
    } else {
        report(Status::fail, "userns", std::string("failed at ") + steps[code]);
    }
}

void check_apparmor() {
    std::string v = read_file("/proc/sys/kernel/apparmor_restrict_unprivileged_userns");
    if (v.empty()) {
        report(Status::ok, "apparmor", "no userns restriction on this kernel");
    } else if (v[0] == '0') {
        report(Status::ok, "apparmor", "apparmor_restrict_unprivileged_userns=0");
    } else {
        report(Status::warn, "apparmor", "apparmor_restrict_unprivileged_userns=1 (needs zaun AppArmor profile)");
    }
}

void check_cgroup() {
    std::string uid = std::to_string(getuid());
    std::string dir = "/sys/fs/cgroup/user.slice/user-" + uid + ".slice/user@" + uid + ".service";
    std::istringstream words(read_file(dir + "/cgroup.controllers"));
    std::set<std::string> controllers{std::istream_iterator<std::string>(words), {}};
    bool writable = access(dir.c_str(), W_OK) == 0;
    std::string missing;
    for (const char* c : {"cpu", "memory", "pids"}) {
        if (!controllers.count(c)) missing += std::string(" ") + c;
    }
    if (writable && missing.empty()) {
        report(Status::ok, "cgroup", "delegated: " + dir);
    } else if (!writable) {
        report(Status::warn, "cgroup", "no writable " + dir + " (falls back to setrlimit)");
    } else {
        report(Status::warn, "cgroup", "missing controllers:" + missing + " (falls back to setrlimit)");
    }
}

}  // namespace

int doctor() {
    check_kernel();
    check_landlock();
    check_userns();
    check_apparmor();
    check_cgroup();
    return g_failed ? 1 : 0;
}

}  // namespace zaun
