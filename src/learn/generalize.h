#pragma once

#include <map>
#include <string>
#include <vector>

#include "learn/tracer.h"
#include "policy/policy.h"

namespace zaun {

struct Learned {
    Policy policy;
    int runs = 0;
    // Runs each rule was seen in, keyed "read /usr/lib", "exec /usr/bin/dash", "syscall openat".
    std::map<std::string, int> support;
    std::vector<std::string> warnings;
};

// Turns traces of learn-mode runs of one command into a policy:
//  1. Paths are taken as the sandbox saw them; sandbox-provided ones (/proc,
//     /dev, /tmp, ...) are dropped, as are paths missing on the host.
//  2. Each access is read, write/create or exec. Symlinks on the way, and the
//     ELF or #! interpreter of anything executed, are added too.
//  3. Under /usr, /lib and /etc/ssl, 3+ entries in one directory collapse into it.
//  4. Nothing collapses into /, $HOME or /etc; listing those (or the workdir's
//     ancestors) is dropped. Both give a warning.
//  5. Workdir paths become the workdir rule, rw only if something was written.
//  6. Syscalls: everything observed except the always-deny list.
//  7. Runs merge by union, with support counts per rule.
Learned generalize(const std::vector<Trace>& runs, const std::string& workdir, const std::string& home);

// The policy as commented TOML that parse_policy accepts. Rules seen in fewer
// than all runs say so, and warnings head the file.
std::string to_toml(const Learned& learned);

}  // namespace zaun
