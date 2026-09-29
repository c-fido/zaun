#pragma once

#include <string>

#include "policy/policy.h"
#include "sandbox/plan.h"

namespace zaun {

// Turns a policy into the launcher's plan, with `workdir` (resolved against the
// current directory) as the writable or read-only work directory. Throws
// PolicyError if a grant overlaps a path the sandbox builds itself (see
// kSandboxPaths), the workdir is missing or unsafe, or a syscall name is
// unknown or always denied.
SandboxPlan compile(const Policy& policy, const std::string& workdir);

}  // namespace zaun
