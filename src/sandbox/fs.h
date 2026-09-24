#pragma once

#include <string>
#include <vector>

#include "sandbox/landlock.h"

namespace zaun {

// Builds the sandbox root and pivots into it. Runs inside the new namespaces.
void setup_fs(const std::string& workdir);

// Landlock rules matching the mounts setup_fs builds.
std::vector<PathRule> sandbox_rules(const std::string& workdir);

}  // namespace zaun
