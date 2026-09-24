// FS-6: reach the host root through /proc/<pid>/root. Tries PID 1 first, then
// every visible process; bare, our own entry already leads to the host root.
// Blocked reason is ENOENT if some root was reachable but lacked the file, else
// the errno from PID 1 (in zaun, EACCES: init keeps caps the target lacks).
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include "escape.h"

static int try_read(const char* pid, const char* path) {
    char full[4096];
    snprintf(full, sizeof full, "/proc/%s/root%s", pid, path);
    int fd = open(full, O_RDONLY);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

int main(int argc, char** argv) {
    const char* path = arg(argc, argv, 1);
    if (try_read("1", path) == 0) return escaped("read the key via /proc/1/root");
    int err = errno;

    DIR* proc = opendir("/proc");
    if (!proc) return blocked_errno(err);
    struct dirent* e;
    while ((e = readdir(proc))) {
        if (!isdigit((unsigned char)e->d_name[0])) continue;
        if (try_read(e->d_name, path) == 0) {
            static char msg[300];
            snprintf(msg, sizeof msg, "read the key via /proc/%s/root", e->d_name);
            return escaped(msg);
        }
        if (errno == ENOENT) err = ENOENT;
    }
    return blocked_errno(err);
}
