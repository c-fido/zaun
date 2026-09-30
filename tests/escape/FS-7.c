// FS-7: remount / read-write. Tries directly, then from a private mount
// namespace, where an unprivileged process can take CAP_SYS_ADMIN.
#include <fcntl.h>
#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>

#include "escape.h"

static void write_file(const char* path, const char* text) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return;
    write(fd, text, strlen(text));
    close(fd);
}

int main(void) {
    const unsigned long flags = MS_REMOUNT | MS_BIND | MS_RELATIME;
    if (mount(NULL, "/", NULL, flags, NULL) == 0) return escaped("remounted / read-write");

    char map[64];
    snprintf(map, sizeof map, "0 %d 1", getuid());
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) return blocked_errno(errno);
    write_file("/proc/self/setgroups", "deny");
    write_file("/proc/self/uid_map", map);
    if (mount(NULL, "/", NULL, flags, NULL) == 0) return escaped("remounted / read-write in a new user namespace");
    return blocked_errno(errno);
}
