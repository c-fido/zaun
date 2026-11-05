#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "sandbox/landlock.h"
#include "sandbox/seccomp.h"

namespace zaun {

// A host path bound into the sandbox at the same path.
struct Bind {
    std::string path;
    bool writable;
};

// Zero means unlimited.
struct Limits {
    uint64_t memory = 0;  // bytes
    uint64_t pids = 0;
    double cpu = 0;  // CPUs
    std::chrono::milliseconds timeout{0};
};

// Everything the launcher needs, compiled from a policy (src/policy/compile.h).
struct SandboxPlan {
    std::string workdir;  // canonical; also in binds
    std::vector<Bind> binds;  // parents before children
    std::vector<PathRule> landlock;  // grants and workdir; fs adds the sandbox's own paths
    std::vector<std::string> env;  // variables kept; HOME is always the workdir
    SeccompPlan seccomp;
    Limits limits;
    // Learn view: the host root read-only except /proc, /sys, /dev, /tmp and /run
    // (host sockets), `hide` covered with empty mounts, no Landlock, and every
    // syscall traced. binds then holds only the workdir.
    bool learn = false;
    std::vector<std::string> hide;
};

// True if the target hands a seccomp listener to the supervisor.
inline bool uses_notify(const SandboxPlan& plan) { return plan.learn || plan.seccomp.allowlist; }

}  // namespace zaun
