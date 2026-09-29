#include "sandbox/init.h"

#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <utility>

#include "sandbox/caps.h"
#include "sandbox/check.h"
#include "sandbox/fs.h"
#include "sandbox/landlock.h"
#include "sandbox/seccomp.h"

namespace zaun {
namespace {

// The kernel drops signals sent to a PID namespace's init unless it has a handler.
void ignore_signal(int) {}

// Keeps the plan's variables; HOME becomes the workdir.
void scrub_env(const SandboxPlan& plan) {
    std::vector<std::pair<std::string, std::string>> keep;
    for (const auto& name : plan.env) {
        if (const char* v = getenv(name.c_str())) keep.emplace_back(name, v);
    }
    check(clearenv() == 0, "clearenv");
    for (const auto& [name, value] : keep) check(setenv(name.c_str(), value.c_str(), 1) == 0, name);
    check(setenv("HOME", plan.workdir.c_str(), 1) == 0, "HOME");
}

// Order is fixed by plan.md's setup invariant; seccomp goes last, right before execve.
[[noreturn]] void exec_target(const SandboxPlan& plan, const std::vector<std::string>& argv) {
    try {
        for (int sig : kForwardedSignals) signal(sig, SIG_DFL);
        sigset_t none;
        sigemptyset(&none);
        check(sigprocmask(SIG_SETMASK, &none, nullptr) == 0, "sigprocmask");
        check(setsid() >= 0, "setsid");
        check(close_range(3, ~0U, 0) == 0, "close_range");
        scrub_env(plan);
        drop_privileges();
        std::vector<PathRule> rules = sandbox_rules();
        rules.insert(rules.end(), plan.landlock.begin(), plan.landlock.end());
        landlock_restrict(rules);

        std::vector<char*> args;
        for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);
        seccomp_install(plan.seccomp);
        execvp(args[0], args.data());
        check(false, argv[0]);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zaun: %s\n", e.what());
    }
    _exit(125);
}

}  // namespace

void run_init(const SandboxPlan& plan, const std::vector<std::string>& argv) {
    sigset_t waited;
    pid_t target = -1;
    try {
        setup_fs(plan);
        // Own session, so terminal signals reach the target once, via the supervisor.
        check(setsid() >= 0, "setsid");

        sigemptyset(&waited);
        sigaddset(&waited, SIGCHLD);
        struct sigaction sa {};
        sa.sa_handler = ignore_signal;
        for (int sig : kForwardedSignals) {
            sigaddset(&waited, sig);
            check(sigaction(sig, &sa, nullptr) == 0, "sigaction");
        }
        check(sigprocmask(SIG_BLOCK, &waited, nullptr) == 0, "sigprocmask");

        target = fork();
        check(target >= 0, "fork");
        if (target == 0) exec_target(plan, argv);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zaun: %s\n", e.what());
        _exit(125);
    }

    // Exiting as PID 1 makes the kernel kill whatever is left in the namespace.
    for (;;) {
        int sig = sigwaitinfo(&waited, nullptr);
        if (sig == SIGCHLD) {
            int status;
            pid_t pid;
            while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
                if (pid == target) {
                    _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
                }
            }
        } else if (sig > 0) {
            kill(target, sig);
        }
    }
}

}  // namespace zaun
