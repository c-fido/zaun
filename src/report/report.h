#pragma once

#include <string>

#include "sandbox/launcher.h"

namespace zaun {

// Writes `result` as the JSON report of `zaun run --report`: exit code and
// reason, duration, peak memory, and the syscalls an allowlist denied.
void write_report(const std::string& path, const RunResult& result);

}  // namespace zaun
