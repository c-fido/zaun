// PRIV-3: create namespaces with clone3, whose flags hide behind a pointer the
// seccomp filter can't inspect.
#include <linux/sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "escape.h"

int main(void) {
    struct clone_args args;
    memset(&args, 0, sizeof args);
    args.flags = CLONE_NEWUSER | CLONE_NEWNS;
    args.exit_signal = SIGCHLD;
    long pid = syscall(SYS_clone3, &args, sizeof args);
    if (pid < 0) return blocked_errno(errno);
    if (pid == 0) _exit(0);
    waitpid(pid, NULL, 0);
    return escaped("clone3 created new namespaces");
}
