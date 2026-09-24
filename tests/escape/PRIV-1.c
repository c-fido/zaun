// PRIV-1: gain root by running a setuid-root binary. The binary's euid is read
// from its /proc status after it exits but before it's reaped.
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "escape.h"

static const char* find_setuid(void) {
    static const char* const candidates[] = {"/usr/bin/mount", "/usr/bin/su", "/usr/bin/passwd"};
    for (size_t i = 0; i < sizeof candidates / sizeof *candidates; ++i) {
        struct stat st;
        if (stat(candidates[i], &st) == 0 && (st.st_mode & S_ISUID)) return candidates[i];
    }
    return NULL;
}

int main(void) {
    const char* bin = find_setuid();
    if (!bin) return blocked("no setuid binary");

    int report[2];  // the child writes errno here if exec fails
    if (pipe2(report, O_CLOEXEC) < 0) return blocked_errno(errno);
    pid_t pid = fork();
    if (pid == 0) {
        int null = open("/dev/null", O_RDWR);
        dup2(null, 0);
        dup2(null, 1);
        dup2(null, 2);
        execl(bin, bin, (char*)NULL);
        int err = errno;
        write(report[1], &err, sizeof err);
        _exit(127);
    }
    close(report[1]);
    int exec_err;
    if (read(report[0], &exec_err, sizeof exec_err) == sizeof exec_err) return blocked_errno(exec_err);

    siginfo_t info;
    waitid(P_PID, pid, &info, WEXITED | WNOWAIT);
    char path[64], line[256];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    FILE* status = fopen(path, "r");
    if (!status) return blocked_errno(errno);
    int ruid = -1, euid = -1;
    while (fgets(line, sizeof line, status)) {
        if (sscanf(line, "Uid: %d %d", &ruid, &euid) == 2) break;
    }
    fclose(status);
    waitpid(pid, NULL, 0);

    if (euid == 0 && ruid != 0) return escaped("setuid binary ran with euid 0");
    return blocked("euid unchanged");
}
