// Syscall-heavy loop for the seccomp overhead benchmark: `syscalls getppid N`
// or `syscalls open N` (open + close /dev/null).
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: syscalls getppid|open N\n");
        return 2;
    }
    long n = atol(argv[2]);
    int open_close = strcmp(argv[1], "open") == 0;
    for (long i = 0; i < n; ++i) {
        if (open_close) {
            int fd = open("/dev/null", O_RDONLY);
            if (fd < 0) return 1;
            close(fd);
        } else if (syscall(SYS_getppid) < 0) {  // raw: glibc might cache it
            return 1;
        }
    }
    return 0;
}
