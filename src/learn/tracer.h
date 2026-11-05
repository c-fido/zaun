#pragma once

#include <cstdint>
#include <map>
#include <ostream>
#include <string>
#include <tuple>
#include <vector>

namespace zaun {

// Unique (syscall, access, path) events with their counts. access is 'r'
// (read), 's' (metadata only), 'w' (write or create), 'x' (exec), or '-' with
// an empty path for syscalls that take none.
using Trace = std::map<std::tuple<std::string, char, std::string>, uint64_t>;

// Passes `fd` over the Unix socket `sock` (SCM_RIGHTS).
void send_fd(int sock, int fd);

// Receives an fd sent with send_fd, or returns -1 if the peer closed first.
int recv_fd(int sock);

// Serves one seccomp notification on `listener`. With `trace`, logs the call
// and its path arguments and lets it run; otherwise logs it as denied and fails
// it with EPERM. Paths are read from the caller's memory, so they only describe
// what it asked for: never base a security decision on them.
void handle_notification(int listener, bool trace, Trace& out);

// Writes traces of several runs as tab-separated lines with a header:
// run (from 1), syscall, access, path, count.
void write_traces(std::ostream& out, const std::vector<Trace>& runs);

}  // namespace zaun
