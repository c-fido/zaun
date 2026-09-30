// PRIV-5: call bpf, perf_event_open and userfaultfd, each in its own child so
// one kill doesn't hide the others. Each is called in a form an unprivileged
// process may use, so the bare run can succeed.
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "escape.h"

static long try_bpf(void) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = 1;
    return syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof attr);
}

static long try_perf(void) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof attr);
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof attr;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    return syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
}

static long try_uffd(void) {
    return syscall(SYS_userfaultfd, O_CLOEXEC | 1);  // 1 is UFFD_USER_MODE_ONLY
}

int main(void) {
    static const struct {
        const char* name;
        long (*call)(void);
    } attacks[] = {{"bpf", try_bpf}, {"perf_event_open", try_perf}, {"userfaultfd", try_uffd}};
    static char msg[128];
    int killed = 0;

    for (size_t i = 0; i < sizeof attacks / sizeof *attacks; ++i) {
        pid_t pid = fork();
        if (pid == 0) _exit(attacks[i].call() >= 0 ? 0 : errno);
        int status;
        waitpid(pid, &status, 0);
        if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
            ++killed;
        } else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            snprintf(msg, sizeof msg, "%s succeeded", attacks[i].name);
            return escaped(msg);
        } else {
            snprintf(msg, sizeof msg, "%s was not killed", attacks[i].name);
        }
    }
    return killed == 3 ? blocked("SIGSYS") : blocked(msg);
}
