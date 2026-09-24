// Not a test: a host process for PROC-* to attack. Allows any tracer so Yama
// ptrace_scope=1 doesn't block the bare run, then prints "ready" and waits.
#include <sys/prctl.h>
#include <unistd.h>

#include "escape.h"

int main(void) {
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    printf("ready\n");
    fflush(stdout);
    for (;;) pause();
}
