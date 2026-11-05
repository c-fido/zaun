#pragma once

#include <sys/types.h>

#include <cstdint>
#include <string>

#include "sandbox/plan.h"

namespace zaun {

// A cgroup v2 leaf with `limits` applied, under the user's delegated systemd
// subtree. Removed on destruction, once it is empty.
class Cgroup {
public:
    // Throws std::system_error if this process isn't under user@UID.service or
    // the subtree lacks a controller.
    explicit Cgroup(const Limits& limits);
    ~Cgroup();
    Cgroup(const Cgroup&) = delete;
    Cgroup& operator=(const Cgroup&) = delete;

    void add(pid_t pid);
    // Kills every process in the cgroup.
    void kill();
    // A number from a control file: the whole file, or the "key N" line. 0 if absent.
    uint64_t value(const std::string& file, const std::string& key = "") const;
    const std::string& path() const { return dir_; }

private:
    std::string dir_;
};

}  // namespace zaun
