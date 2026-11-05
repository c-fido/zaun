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
//
// Given a Unix socket `sock`, calls an allowlist denies are sent to a supervisor
// as seccomp notifications instead (it replies EPERM and logs them); with
// `trace`, every call is. The listener fd goes over `sock`, then both are closed.
void seccomp_install(const SeccompPlan& plan, bool trace = false, int sock = -1);

}  // namespace zaun
