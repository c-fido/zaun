#include "sandbox/launcher.h"

#include <fcntl.h>
#include <linux/sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <filesystem>
#include <system_error>

#include "sandbox/fs.h"

namespace zaun {
namespace {

void check(bool ok, const std::string& what) {
    if (!ok) throw std::system_error(errno, std::generic_category(), what);
}

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
        close(sync_fd);
        setup_fs(workdir);
        std::vector<char*> args;
        for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
        args.push_back(nullptr);
        // ponytail: target runs as PID 1; step 3 adds a reaping init.
        execvp(args[0], args.data());
        check(false, argv[0]);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zaun: %s\n", e.what());
    }
    _exit(125);
}

}  // namespace

int launch(const std::string& workdir, const std::vector<std::string>& argv) {
    std::string dir = std::filesystem::canonical(workdir);
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

    int status = 0;
    check(waitpid(pid, &status, 0) == pid, "waitpid");
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}

}  // namespace zaun
