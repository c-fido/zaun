#include "cgroup/cgroup.h"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <fstream>
#include <system_error>

#include "sandbox/check.h"

namespace zaun {
namespace {

constexpr long kCpuPeriodUs = 100000;

std::system_error unsupported(const std::string& what) {
    return std::system_error(ENOTSUP, std::generic_category(), what);
}

// Moving a process needs write access to the common ancestor of its cgroup and
// the target, so the target must sit in the subtree this process already runs in.
std::string delegated_root() {
    std::string line;
    std::getline(std::ifstream("/proc/self/cgroup"), line);
    if (line.rfind("0::/", 0) != 0) throw unsupported("cgroup v2 is not in use");
    std::string path = line.substr(3);
    std::string unit = "/user@" + std::to_string(getuid()) + ".service";
    size_t at = path.find(unit);
    if (at == std::string::npos) throw unsupported("not running under " + unit.substr(1));
    return "/sys/fs/cgroup" + path.substr(0, at + unit.size());
}

}  // namespace

Cgroup::Cgroup(const Limits& limits) : dir_(delegated_root() + "/zaun-" + std::to_string(getpid())) {
    check(mkdir(dir_.c_str(), 0755) == 0, dir_);
    try {
        if (limits.memory) {
            write_file(dir_ + "/memory.max", std::to_string(limits.memory));
            write_file(dir_ + "/memory.swap.max", "0");
            write_file(dir_ + "/memory.oom.group", "1");  // an OOM kill takes the whole sandbox
        }
        if (limits.pids) write_file(dir_ + "/pids.max", std::to_string(limits.pids));
        if (limits.cpu > 0) {
            long quota = std::max(1000L, static_cast<long>(limits.cpu * kCpuPeriodUs));
            write_file(dir_ + "/cpu.max", std::to_string(quota) + " " + std::to_string(kCpuPeriodUs));
        }
    } catch (...) {
        rmdir(dir_.c_str());
        throw;
    }
}

Cgroup::~Cgroup() { rmdir(dir_.c_str()); }

void Cgroup::add(pid_t pid) { write_file(dir_ + "/cgroup.procs", std::to_string(pid)); }

void Cgroup::kill() { write_file(dir_ + "/cgroup.kill", "1"); }

}  // namespace zaun
