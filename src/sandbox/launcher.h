#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "learn/tracer.h"
#include "sandbox/plan.h"

namespace zaun {

struct RunResult {
    int exit_code;  // the target's, or 128+signal
    // "exit", "signal", "seccomp" (killed by SIGSYS), "timeout" or "memory" (OOM kill).
    std::string reason;
    std::chrono::milliseconds duration;
    std::optional<uint64_t> memory_peak;  // bytes; needs a cgroup
    bool pids_limited = false;  // a fork failed at pids.max
    bool cgroup = false;  // limits were enforced by a cgroup, not rlimits
    // Learn mode: everything the sandbox did. Allowlist mode: the denied calls.
    Trace notified;
};

// Runs argv in new user/mount/pid/net/ipc/uts namespaces, confined by `plan`.
// Throws std::system_error if setup fails. Blocks SIGCHLD and the forwarded
// signals in the calling thread while it runs and relays the latter to the
// sandbox, so call it from a single-threaded process.
RunResult launch(const SandboxPlan& plan, const std::vector<std::string>& argv);

}  // namespace zaun
