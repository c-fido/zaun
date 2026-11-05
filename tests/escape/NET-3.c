// NET-3: connect to a host abstract Unix socket, as D-Bus and X11 use.
#include <sys/socket.h>
#include <sys/un.h>

#include "escape.h"

int main(int argc, char** argv) {
    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    snprintf(addr.sun_path + 1, sizeof addr.sun_path - 1, "zaun-escape-%s", arg(argc, argv, 1));
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return blocked_errno(errno);
    if (connect(fd, (struct sockaddr*)&addr, sizeof addr) < 0) return blocked_errno(errno);
    return escaped("connected to the host's abstract socket");
}
