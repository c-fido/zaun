#pragma once

#include <signal.h>

#include <string>
#include <vector>

#include "sandbox/plan.h"

namespace zaun {

// Signals the supervisor forwards to init, and init forwards to the target.
inline constexpr int kForwardedSignals[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2};

// With uses_notify(plan), init holds the socket to the supervisor here; the
// target sends its seccomp listener over it.
inline constexpr int kNotifyFd = 3;

// Runs as PID 1 of the sandbox: builds the root, forks the target, reaps
// zombies and forwards signals. Exits with the target's exit code, or
// 128+signal if it was killed.
[[noreturn]] void run_init(const SandboxPlan& plan, const std::vector<std::string>& argv);

}  // namespace zaun
