#include "sandbox/launcher.h"

#include <fcntl.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <exception>
#include <optional>

#include "cgroup/cgroup.h"
#include "sandbox/check.h"
#include "sandbox/init.h"

namespace zaun {
namespace {

// `rlimits`: no cgroup, so memory is capped with RLIMIT_AS instead.
// `sock`: the child's end of the notify socket, or -1.
[[noreturn]] void run_child(int sync_fd, int sock, const SandboxPlan& plan,
                            const std::vector<std::string>& argv, bool rlimits) {
    try {
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        char c;
        check(read(sync_fd, &c, 1) == 1, "wait for id maps");
        if (sock >= 0) check(dup2(sock, kNotifyFd) == kNotifyFd, "dup2");
        // Init must not hold host fds either: the target could reach them via /proc/1/fd.
        check(close_range(sock >= 0 ? kNotifyFd + 1 : 3, ~0U, 0) == 0, "close_range");
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

// Closes an fd on scope exit.
struct Fd {
    int fd = -1;
    Fd() = default;
    explicit Fd(int f) : fd(f) {}
    ~Fd() { reset(); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    void reset(int f = -1) {
        if (fd >= 0) close(fd);
        fd = f;
    }
};

}  // namespace

RunResult launch(const SandboxPlan& plan, const std::vector<std::string>& argv) {
    using Clock = std::chrono::steady_clock;
    const Clock::time_point start = Clock::now();

    sigset_t waited;
    sigemptyset(&waited);
    sigaddset(&waited, SIGCHLD);
    for (int sig : kForwardedSignals) sigaddset(&waited, sig);
    SignalBlock block(waited);
    Fd sigfd(signalfd(-1, &waited, SFD_CLOEXEC));
    check(sigfd.fd >= 0, "signalfd");

    // A cgroup is also how the report gets peak memory, so try even without limits.
    // Without one, limits degrade to rlimits, which can't cover pids or cpu.
    const Limits& limits = plan.limits;
    std::optional<Cgroup> cgroup;
    bool rlimits = false;
    try {
        cgroup.emplace(limits);
    } catch (const std::system_error& e) {
        if (limits.memory || limits.pids || limits.cpu > 0) {
            rlimits = true;
            std::fprintf(stderr,
                         "zaun: warning: no cgroup limits (%s); only memory is enforced, via rlimits. "
                         "Run under `systemd-run --user --scope` for full limits\n",
                         e.what());
        }
    }

    Cgroup* cg = cgroup.has_value() ? &cgroup.value() : nullptr;

    int sync[2];
    check(pipe2(sync, O_CLOEXEC) == 0, "pipe");
    Fd sync_r(sync[0]);
    Fd sync_w(sync[1]);
    Fd sock;  // supervisor's end of the notify socket
    Fd child_sock;
    if (uses_notify(plan)) {
        int sv[2];
        check(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) == 0, "socketpair");
        sock.reset(sv[0]);
        child_sock.reset(sv[1]);
    }

    clone_args args{};
    args.flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC |
                 CLONE_NEWUTS;
    args.exit_signal = SIGCHLD;
    pid_t pid = static_cast<pid_t>(syscall(SYS_clone3, &args, sizeof args));
    if (pid == 0) run_child(sync[0], child_sock.fd, plan, argv, rlimits);
    check(pid > 0, "clone3");
    sync_r.reset();
    child_sock.reset();

    Fd listener;
    try {
        std::string proc = "/proc/" + std::to_string(pid);
        write_file(proc + "/setgroups", "deny");
        write_file(proc + "/uid_map", std::to_string(getuid()) + " " + std::to_string(getuid()) + " 1");
        write_file(proc + "/gid_map", std::to_string(getgid()) + " " + std::to_string(getgid()) + " 1");
        if (cg) cg->add(pid);
        check(write(sync[1], "1", 1) == 1, "release child");
        sync_w.reset();
        // -1 if the target failed before installing its filter.
        if (sock.fd >= 0) listener.reset(recv_fd(sock.fd));
    } catch (...) {
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        throw;
    }

    RunResult result{};
    result.cgroup = cg != nullptr;
    const bool timed = limits.timeout.count() > 0;
    const Clock::time_point deadline = start + limits.timeout;
    bool timed_out = false;
    for (;;) {
        int wait_ms = -1;
        if (timed && !timed_out) {
            auto left = std::chrono::ceil<std::chrono::milliseconds>(deadline - Clock::now()).count();
            if (left <= 0) {
                // Init dying takes every process in the PID namespace with it.
                std::fprintf(stderr, "zaun: timeout, killing the sandbox\n");
                if (cg) cg->kill();
                kill(pid, SIGKILL);
                timed_out = true;
                continue;
            }
            wait_ms = static_cast<int>(left);
        }
        pollfd fds[2] = {{sigfd.fd, POLLIN, 0}, {listener.fd, POLLIN, 0}};
        int n = poll(fds, listener.fd >= 0 ? 2 : 1, wait_ms);
        if (n < 0 && errno == EINTR) continue;
        check(n >= 0, "poll");
        if (fds[1].revents & POLLIN) {
            handle_notification(listener.fd, plan.learn, result.notified);
        } else if (fds[1].revents & (POLLHUP | POLLERR)) {
            listener.reset();  // no process left under the filter
        }
        if (!(fds[0].revents & POLLIN)) continue;

        signalfd_siginfo si;
        check(read(sigfd.fd, &si, sizeof si) == sizeof si, "read signalfd");
        if (si.ssi_signo != SIGCHLD) {
            kill(pid, static_cast<int>(si.ssi_signo));
            continue;
        }
        int status;
        pid_t r = waitpid(pid, &status, WNOHANG);
        check(r >= 0, "waitpid");
        if (r != pid) continue;

        result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);
        bool signaled = WIFSIGNALED(status);
        result.exit_code = signaled ? 128 + WTERMSIG(status) : WEXITSTATUS(status);
        result.reason = signaled ? "signal" : "exit";
        if (result.exit_code == 128 + SIGSYS) result.reason = "seccomp";
        if (cg) {
            result.memory_peak = cg->value("memory.peak");
            result.pids_limited = cg->value("pids.events", "max") > 0;
            if (cg->value("memory.events", "oom_kill") > 0) result.reason = "memory";
        }
        if (timed_out) result.reason = "timeout";
        return result;
    }
}

}  // namespace zaun
