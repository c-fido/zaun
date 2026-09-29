#include "sandbox/seccomp.h"

#include <errno.h>
#include <gtest/gtest.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <functional>

namespace {

// Runs `body` in a forked child under `plan`; returns its wait status.
int run_filtered(const zaun::SeccompPlan& plan, const std::function<int()>& body) {
    pid_t pid = fork();
    if (pid == 0) {
        try {
            zaun::seccomp_install(plan);
        } catch (...) {
            _exit(100);
        }
        // Raw exit: sanitizer hooks in _exit make syscalls an allowlist would deny.
        syscall(SYS_exit_group, body());
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}

bool killed_by_sigsys(int status) { return WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS; }

// 0 if the syscall failed with `err`, else 1.
int fails_with(long rc, int err) { return rc == -1 && errno == err ? 0 : 1; }

TEST(Seccomp, AlwaysDenyKills) {
    zaun::SeccompPlan plan;
    EXPECT_TRUE(killed_by_sigsys(run_filtered(plan, [] { return (int)syscall(SYS_ptrace, 0, 0, 0, 0); })));
    EXPECT_TRUE(killed_by_sigsys(run_filtered(plan, [] { return (int)syscall(SYS_unshare, CLONE_NEWUSER); })));
    EXPECT_TRUE(killed_by_sigsys(run_filtered(plan, [] { return (int)syscall(SYS_io_uring_setup, 1, nullptr); })));
    EXPECT_TRUE(killed_by_sigsys(run_filtered(plan, [] { return (int)syscall(SYS_bpf, 0, nullptr, 0); })));
    EXPECT_TRUE(killed_by_sigsys(run_filtered(plan, [] { return (int)syscall(SYS_keyctl, 0, 0, 0, 0, 0); })));
}

TEST(Seccomp, CloneWithNamespaceFlagKills) {
    zaun::SeccompPlan plan;
    // Raw clone with a namespace flag; the filter fires before the kernel looks at it.
    EXPECT_TRUE(killed_by_sigsys(run_filtered(plan, [] {
        return (int)syscall(SYS_clone, CLONE_NEWNET | SIGCHLD, 0, 0, 0, 0);
    })));
    // Plain fork still works.
    EXPECT_EQ(run_filtered(plan, [] {
        pid_t c = fork();
        if (c == 0) _exit(0);
        int st;
        return waitpid(c, &st, 0) == c && WIFEXITED(st) ? 0 : 1;
    }), 0);
}

TEST(Seccomp, Clone3ReturnsEnosys) {
    EXPECT_EQ(run_filtered({}, [] { return fails_with(syscall(SYS_clone3, nullptr, 0), ENOSYS); }), 0);
}

TEST(Seccomp, TerminalIoctlsReturnEperm) {
    EXPECT_EQ(run_filtered({}, [] {
        char c = 'x';
        // High bits set: the kernel ignores them, so the filter must too.
        unsigned long high = (1UL << 32) | TIOCSTI;
        return fails_with(ioctl(0, TIOCSTI, &c), EPERM) | fails_with(syscall(SYS_ioctl, 0, high, &c), EPERM) |
               fails_with(ioctl(0, TIOCLINUX, &c), EPERM);
    }), 0);
    // Other ioctls pass through: FIONREAD on a pipe succeeds.
    EXPECT_EQ(run_filtered({}, [] {
        int p[2], n;
        return pipe(p) == 0 && ioctl(p[0], FIONREAD, &n) == 0 ? 0 : 1;
    }), 0);
}

TEST(Seccomp, AllowlistFailsOthersWithEperm) {
    zaun::SeccompPlan plan{true, {"getpid"}};
    EXPECT_EQ(run_filtered(plan, [] {
        if (syscall(SYS_getpid) <= 0) return 1;
        return fails_with(syscall(SYS_getppid), EPERM);
    }), 0);
    // The always-deny list still kills, and clone3 still gets ENOSYS.
    EXPECT_TRUE(killed_by_sigsys(run_filtered(plan, [] { return (int)syscall(SYS_unshare, 0); })));
    EXPECT_EQ(run_filtered(plan, [] { return fails_with(syscall(SYS_clone3, nullptr, 0), ENOSYS); }), 0);
}

TEST(Seccomp, Names) {
    EXPECT_TRUE(zaun::syscall_known("openat"));
    EXPECT_FALSE(zaun::syscall_known("frobnicate"));
    EXPECT_TRUE(zaun::always_denied("io_uring_setup"));
    EXPECT_FALSE(zaun::always_denied("read"));
}

}  // namespace
