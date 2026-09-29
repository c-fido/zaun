#pragma once

#include <string>
#include <vector>

namespace zaun {

struct SeccompPlan {
    // Baseline allows everything but the always-deny list. Allowlist mode also
    // fails every syscall outside `allow` and the base set with EPERM.
    bool allowlist = false;
    std::vector<std::string> allow;  // syscall names
};

// True if `name` is a syscall on the native architecture.
bool syscall_known(const std::string& name);

// True if `name` is on the always-deny list, which no policy can allow.
bool always_denied(const std::string& name);

// Installs the filter for the calling thread and its future children. Always-deny
// syscalls and clone with namespace flags kill the process, as does any foreign
// architecture; clone3 fails with ENOSYS and the TIOCSTI/TIOCLINUX ioctls with
// EPERM. Throws std::system_error on failure. Install it last: it can block setup.
void seccomp_install(const SeccompPlan& plan);

}  // namespace zaun
