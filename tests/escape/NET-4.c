// NET-4: connect to a Unix socket file in the host's /tmp.
#include <sys/socket.h>
#include <sys/un.h>

#include "escape.h"

int main(int argc, char** argv) {
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    snprintf(addr.sun_path, sizeof addr.sun_path, "/tmp/zaun-escape-%s.sock", arg(argc, argv, 1));
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return blocked_errno(errno);
    if (connect(fd, (struct sockaddr*)&addr, sizeof addr) < 0) return blocked_errno(errno);
    return escaped("connected to the host's /tmp socket");
}
