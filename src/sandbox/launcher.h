#pragma once

#include <string>
#include <vector>

namespace zaun {

// Runs argv in new user/mount/pid/net/ipc/uts namespaces with workdir as the
// only writable host directory. Returns the exit code, or 128+signal.
// Throws std::system_error if setup fails. Blocks SIGCHLD and the forwarded
// signals in the calling thread while it runs and relays the latter to the
// sandbox, so call it from a single-threaded process.
int launch(const std::string& workdir, const std::vector<std::string>& argv);

}  // namespace zaun
