#include "sandbox/launcher.h"

#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <exception>
#include <optional>

#include "cgroup/cgroup.h"
#include "sandbox/check.h"
#include "sandbox/init.h"

namespace zaun {
namespace {

// `rlimits`: no cgroup, so memory is capped with RLIMIT_AS instead.
[[noreturn]] void run_child(int sync_fd, const SandboxPlan& plan,
                            const std::vector<std::string>& argv, bool rlimits) {
    try {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        char c;
        check(read(sync_fd, &c, 1) == 1, "wait for id maps");
        // Init must not hold host fds either: the target could reach them via /proc/1/fd.
        check(close_range(3, ~0U, 0) == 0, "close_range");
        if (rlimits && plan.limits.memory) {
            // ponytail: caps each process's address space, not the sandbox's total memory.
            rlimit rl{plan.limits.memory, plan.limits.memory};
            check(setrlimit(RLIMIT_AS, &rl) == 0, "setrlimit");
        }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zaun: %s\n", e.what());
        _exit(125);
    }
    run_init(plan, argv);
}

// Blocks `set` for the calling thread until destroyed.
class SignalBlock {
public:
    explicit SignalBlock(const sigset_t& set) {
        check(sigprocmask(SIG_BLOCK, &set, &old_) == 0, "sigprocmask");
    }
    ~SignalBlock() { sigprocmask(SIG_SETMASK, &old_, nullptr); }
    SignalBlock(const SignalBlock&) = delete;
    SignalBlock& operator=(const SignalBlock&) = delete;

private:
    sigset_t old_;
};

}  // namespace

int launch(const SandboxPlan& plan, const std::vector<std::string>& argv) {
    sigset_t waited;
    sigemptyset(&waited);
    sigaddset(&waited, SIGCHLD);
    for (int sig : kForwardedSignals) sigaddset(&waited, sig);
    SignalBlock block(waited);

    // Limits are set before the sandbox runs anything; without a usable cgroup
    // they degrade to rlimits, which can't cover pids or cpu.
    const Limits& limits = plan.limits;
    std::optional<Cgroup> cgroup;
    bool rlimits = false;
    if (limits.memory || limits.pids || limits.cpu > 0) {
        try {
            cgroup.emplace(limits);
        } catch (const std::system_error& e) {
            rlimits = true;
            std::fprintf(stderr,
                         "zaun: warning: no cgroup limits (%s); only memory is enforced, via rlimits. "
                         "Run under `systemd-run --user --scope` for full limits\n",
                         e.what());
        }
    }

    int sync[2];
    check(pipe2(sync, O_CLOEXEC) == 0, "pipe");

    clone_args args{};
    args.flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC |
                 CLONE_NEWUTS;
    args.exit_signal = SIGCHLD;
    pid_t pid = static_cast<pid_t>(syscall(SYS_clone3, &args, sizeof args));
    if (pid == 0) {
        close(sync[1]);
        run_child(sync[0], plan, argv, rlimits);
    }
    int err = errno;
    close(sync[0]);
    if (pid < 0) {
        close(sync[1]);
        errno = err;
        check(false, "clone3");
    }

    try {
        std::string proc = "/proc/" + std::to_string(pid);
        write_file(proc + "/setgroups", "deny");
        write_file(proc + "/uid_map", std::to_string(getuid()) + " " + std::to_string(getuid()) + " 1");
        write_file(proc + "/gid_map", std::to_string(getgid()) + " " + std::to_string(getgid()) + " 1");
        if (cgroup) cgroup->add(pid);
        check(write(sync[1], "1", 1) == 1, "release child");
    } catch (...) {
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        close(sync[1]);
        throw;
    }
    close(sync[1]);

    using Clock = std::chrono::steady_clock;
    const bool timed = limits.timeout.count() > 0;
    const Clock::time_point deadline = Clock::now() + limits.timeout;
    bool timed_out = false;
    for (;;) {
        int sig;
        if (timed && !timed_out) {
            auto left = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - Clock::now());
            if (left.count() <= 0) {
                // Init dying takes every process in the PID namespace with it.
                std::fprintf(stderr, "zaun: timeout, killing the sandbox\n");
                if (cgroup) cgroup->kill();
                kill(pid, SIGKILL);
                timed_out = true;
                continue;
            }
            timespec ts{static_cast<time_t>(left.count() / 1'000'000'000), static_cast<long>(left.count() % 1'000'000'000)};
            sig = sigtimedwait(&waited, nullptr, &ts);
        } else {
            sig = sigwaitinfo(&waited, nullptr);
        }
        if (sig == SIGCHLD) {
            int status;
            pid_t r = waitpid(pid, &status, WNOHANG);
            check(r >= 0, "waitpid");
            if (r == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
        } else if (sig > 0) {
            kill(pid, sig);
        }
    }
}

}  // namespace zaun
