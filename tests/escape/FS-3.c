// FS-3: append a line to ~/.bashrc.
#include <fcntl.h>
#include <unistd.h>

#include "escape.h"

int main(int argc, char** argv) {
    int fd = open(arg(argc, argv, 1), O_WRONLY | O_APPEND);
    if (fd < 0) return blocked_errno(errno);
    static const char line[] = "# zaun escape FS-3\n";
    if (write(fd, line, sizeof line - 1) < 0) return blocked_errno(errno);
    return escaped("appended to .bashrc");
}
