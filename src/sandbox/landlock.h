#pragma once

#include <string>
#include <vector>

namespace zaun {

// What a path rule grants. kWrite covers creating, removing and truncating;
// kRefer allows renaming or linking across directories.
enum PathAccess : unsigned { kRead = 1u << 0, kWrite = 1u << 1, kExec = 1u << 2, kRefer = 1u << 3 };

struct PathRule {
    std::string path;
    unsigned access;  // PathAccess bits
};

// Returns the kernel's Landlock ABI version, or a value < 1 (errno set) if unavailable.
int landlock_abi();

// Restricts the calling thread and its future children to `rules`; anything
// not granted is denied. Missing paths are skipped, and rules on non-directories
// keep only file rights. Needs PR_SET_NO_NEW_PRIVS. Warns on stderr and degrades
// if the kernel lacks Landlock or some rights.
void landlock_restrict(const std::vector<PathRule>& rules);

}  // namespace zaun
