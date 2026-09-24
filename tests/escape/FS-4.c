// FS-4: plant a symlink in the workdir that points into $HOME, read through it.
#include <fcntl.h>
#include <unistd.h>

#include "escape.h"

int main(int argc, char** argv) {
    unlink("link");
    if (symlink(arg(argc, argv, 1), "link") < 0) return blocked_errno(errno);
    int fd = open("link", O_RDONLY);
    if (fd < 0) return blocked_errno(errno);
    char buf[64];
    if (read(fd, buf, sizeof buf) < 0) return blocked_errno(errno);
    return escaped("read the private key through a workdir symlink");
}
