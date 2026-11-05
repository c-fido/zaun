// NET-1: open a TCP connection to the internet.
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "escape.h"

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return blocked_errno(errno);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(443)};
    inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr*)&addr, sizeof addr) < 0) return blocked_errno(errno);
    return escaped("connected to 1.1.1.1:443");
}
