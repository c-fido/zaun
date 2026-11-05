// FS-8: fill /tmp, which is host RAM when it's a tmpfs.
#include <fcntl.h>
#include <unistd.h>

#include "escape.h"

int main(void) {
    char path[64];
    snprintf(path, sizeof path, "/tmp/zaun-fs8-%d", getpid());
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return blocked_errno(errno);
    unlink(path);
    static char buf[1 << 20];
    for (int mib = 0; mib < 512; ++mib) {
        if (write(fd, buf, sizeof buf) != sizeof buf) return blocked_errno(errno);
    }
    return escaped("wrote 512 MiB to /tmp");
}
