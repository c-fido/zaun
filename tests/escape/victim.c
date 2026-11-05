// Not a test: a host process for PROC-* and NET-* to attack. Allows any tracer
// so Yama ptrace_scope=1 doesn't block the bare run, listens on an abstract and
// a /tmp Unix socket named after its pid, then prints "ready" and waits.
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "escape.h"

static void listen_on(const char* path, int abstract) {
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    snprintf(addr.sun_path + abstract, sizeof addr.sun_path - 1, "%s", path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0 || bind(fd, (struct sockaddr*)&addr, sizeof addr) < 0 || listen(fd, 8) < 0) {
        perror(path);
        exit(1);
    }
}

int main(void) {
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    char name[64];
    snprintf(name, sizeof name, "zaun-escape-%d", getpid());
    listen_on(name, 1);
    snprintf(name, sizeof name, "/tmp/zaun-escape-%d.sock", getpid());
    listen_on(name, 0);
    printf("ready\n");
    fflush(stdout);
    for (;;) pause();
}
