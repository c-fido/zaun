#pragma once

#include <string>

namespace zaun {

// Builds the sandbox root and pivots into it. Runs inside the new namespaces.
void setup_fs(const std::string& workdir);

}  // namespace zaun
