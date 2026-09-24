// PROC-3: read a secret from another process's /proc/<pid>/environ.
#include <fcntl.h>
#include <unistd.h>

#include "escape.h"

int main(int argc, char** argv) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%s/environ", arg(argc, argv, 1));
    int fd = open(path, O_RDONLY);
    if (fd < 0) return blocked_errno(errno);
    char buf[1 << 16];
    ssize_t n = read(fd, buf, sizeof buf);
    if (n < 0) return blocked_errno(errno);
    static const char key[] = "ANTHROPIC_API_KEY=";
    if (memmem(buf, n, key, sizeof key - 1)) return escaped("read the victim's API key");
    return blocked("key absent");
}
