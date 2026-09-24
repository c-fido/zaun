#pragma once

#include <signal.h>

#include <string>
#include <vector>

namespace zaun {

// Signals the supervisor forwards to init, and init forwards to the target.
inline constexpr int kForwardedSignals[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2};

// Runs as PID 1 of the sandbox: builds the root, forks the target, reaps
// zombies and forwards signals. Exits with the target's exit code, or
// 128+signal if it was killed.
[[noreturn]] void run_init(const std::string& workdir, const std::vector<std::string>& argv);

}  // namespace zaun
