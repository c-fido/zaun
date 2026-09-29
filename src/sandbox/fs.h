#pragma once

#include <string>
#include <vector>

#include "sandbox/landlock.h"
#include "sandbox/plan.h"

namespace zaun {

// Paths the sandbox builds itself. A policy can't grant them, anything under
// them, or a directory holding them.
inline const char* const kSandboxPaths[] = {"/tmp", "/proc", "/dev", "/etc/passwd"};

// Builds the sandbox root from `plan` and pivots into it. Runs inside the new namespaces.
void setup_fs(const SandboxPlan& plan);

// Landlock rules for kSandboxPaths and the root; the plan's rules cover the rest.
std::vector<PathRule> sandbox_rules();

}  // namespace zaun
