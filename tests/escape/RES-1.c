// RES-1: fork bomb, bounded so the bare run can't take the host down.
#include <signal.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "escape.h"

int main(void) {
    for (int i = 0; i < 500; ++i) {
        pid_t pid = fork();
        if (pid < 0) return blocked_errno(errno);
        if (pid == 0) {
            prctl(PR_SET_PDEATHSIG, SIGKILL);
            pause();
            _exit(0);
        }
    }
    return escaped("forked 500 processes");
}
