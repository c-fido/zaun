#include "sandbox/launcher.h"

#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <exception>
#include <filesystem>

#include "sandbox/check.h"
#include "sandbox/init.h"

namespace zaun {
namespace {

void write_file(const std::string& path, const std::string& s) {
    int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
    check(fd >= 0, path);
    bool ok = write(fd, s.data(), s.size()) == static_cast<ssize_t>(s.size());
    int err = errno;
    close(fd);
    errno = err;
    check(ok, path);
}

[[noreturn]] void run_child(int sync_fd, const std::string& workdir,
                            const std::vector<std::string>& argv) {
    try {
        char c;
        check(read(sync_fd, &c, 1) == 1, "wait for id maps");
        // Init must not hold host fds either: the target could reach them via /proc/1/fd.
        check(close_range(3, ~0U, 0) == 0, "close_range");
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zaun: %s\n", e.what());
        _exit(125);
    }
    run_init(workdir, argv);
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

int launch(const std::string& workdir, const std::vector<std::string>& argv) {
    std::string dir = std::filesystem::canonical(workdir);
    sigset_t waited;
    sigemptyset(&waited);
    sigaddset(&waited, SIGCHLD);
    for (int sig : kForwardedSignals) sigaddset(&waited, sig);
    SignalBlock block(waited);

    int sync[2];
    check(pipe2(sync, O_CLOEXEC) == 0, "pipe");

    clone_args args{};
    args.flags = CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC |
                 CLONE_NEWUTS;
    args.exit_signal = SIGCHLD;
    pid_t pid = static_cast<pid_t>(syscall(SYS_clone3, &args, sizeof args));
    if (pid == 0) {
        close(sync[1]);
        run_child(sync[0], dir, argv);
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
        check(write(sync[1], "1", 1) == 1, "release child");
    } catch (...) {
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        close(sync[1]);
        throw;
    }
    close(sync[1]);

    for (;;) {
        int sig = sigwaitinfo(&waited, nullptr);
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
