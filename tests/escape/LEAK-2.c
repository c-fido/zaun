// LEAK-2: read a file descriptor inherited as fd 3.
#include <unistd.h>

#include "escape.h"

int main(void) {
    char buf[64];
    if (read(3, buf, sizeof buf) < 0) return blocked_errno(errno);
    return escaped("read inherited fd 3");
}
