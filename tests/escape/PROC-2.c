// PROC-2: kill host processes. Bare it only kills the victim; kill(-1) runs
// only once we're provably in another PID namespace, so it can't hit the host
// when run bare. The harness checks the victim survived.
#include <signal.h>
#include <unistd.h>

#include "escape.h"

int main(int argc, char** argv) {
    pid_t pid = atoi(arg(argc, argv, 1));
    const char* host_ns = arg(argc, argv, 2);
    if (kill(pid, SIGKILL) == 0) return escaped("killed the host process");
    int err = errno;

    char ns[64];
    ssize_t n = readlink("/proc/self/ns/pid", ns, sizeof ns - 1);
    if (n > 0) {
        ns[n] = '\0';
        if (strcmp(ns, host_ns) != 0) kill(-1, SIGKILL);
    }
    return blocked_errno(err);
}
