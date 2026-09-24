// FS-1: read a private key under $HOME.
#include <fcntl.h>
#include <unistd.h>

#include "escape.h"

int main(int argc, char** argv) {
    int fd = open(arg(argc, argv, 1), O_RDONLY);
    if (fd < 0) return blocked_errno(errno);
    char buf[64];
    if (read(fd, buf, sizeof buf) < 0) return blocked_errno(errno);
    return escaped("read the private key");
}
