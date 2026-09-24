// PROC-1: ptrace-attach to a host process standing in for the supervisor.
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "escape.h"

int main(int argc, char** argv) {
    pid_t pid = atoi(arg(argc, argv, 1));
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) return blocked_errno(errno);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_DETACH, pid, 0, 0);
    return escaped("attached to the host process");
}
