#include <fcntl.h>
#include <gtest/gtest.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

#include "policy/compile.h"
#include "sandbox/launcher.h"

namespace {

class Launcher : public testing::Test {
protected:
    void SetUp() override {
        char tmpl[] = "/tmp/zaun-test-XXXXXX";
        dir_ = mkdtemp(tmpl);
    }
    void TearDown() override { std::filesystem::remove_all(dir_); }

    // Runs argv in dir_ under `policy` (default: the baseline).
    int launch(const std::vector<std::string>& argv,
               const std::string& policy = zaun::kBaselinePolicy) {
        return zaun::launch(zaun::compile(zaun::parse_policy(policy), dir_), argv);
    }

    std::string dir_;
};

// Each check exits with its own code so a failure names the check.
TEST_F(Launcher, IsolatesFilesystem) {
    std::string script =
        "opts() { while read -r _ mp _ o _; do [ \"$mp\" = \"$1\" ] && echo \",$o,\"; done < /proc/mounts; }\n"
        "test $PPID = 1 || exit 10\n"
        "test \"$(id -u)\" = " + std::to_string(getuid()) + " || exit 11\n"
        "test \"$(pwd)\" = " + dir_ + " || exit 12\n"
        "touch out || exit 13\n"
        "case $(opts /usr) in *,ro,*nosuid,nodev,*) ;; *) exit 14;; esac\n"
        "case $(opts " + dir_ + ") in *,rw,*nosuid,nodev,*) ;; *) exit 15;; esac\n"
        "test -e /home -o -e /sys && exit 16\n"
        "test \"$(ls /dev | wc -l)\" = 5 || exit 17\n"
        "test \"$(wc -l < /proc/net/dev)\" = 3 || exit 18\n"  // header + lo only
        "exit 0\n";
    EXPECT_EQ(launch({"/bin/sh", "-c", script}), 0);
    EXPECT_TRUE(std::filesystem::exists(dir_ + "/out"));
}

TEST_F(Launcher, LocksDownTarget) {
    setenv("ZAUN_TEST_SECRET", "leak", 1);
    int fd = open("/dev/null", O_RDONLY);  // no O_CLOEXEC: must not reach the target
    ASSERT_GE(fd, 3);
    std::string script =
        "test -z \"$ZAUN_TEST_SECRET\" || exit 10\n"
        "test \"$HOME\" = " + dir_ + " || exit 11\n"
        "test \"$(ls /proc/self/fd | wc -l)\" = 4 || exit 12\n"  // 0-2 + ls's own dir fd
        "test \"$(cut -d' ' -f6 /proc/$$/stat)\" = $$ || exit 13\n"  // session leader
        "exit 0\n";
    EXPECT_EQ(launch({"/bin/sh", "-c", script}), 0);
    close(fd);
    unsetenv("ZAUN_TEST_SECRET");
}

TEST_F(Launcher, DropsPrivileges) {
    std::string script =
        "for set in CapInh CapPrm CapEff CapBnd CapAmb; do\n"
        "  grep -q \"^$set:.0000000000000000$\" /proc/self/status || exit 10\n"
        "done\n"
        "grep -q '^NoNewPrivs:.1$' /proc/self/status || exit 11\n";
    EXPECT_EQ(launch({"/bin/sh", "-c", script}), 0);
}

// Mounts leave /, /etc and /dev writable by the target; Landlock must not.
TEST_F(Launcher, LandlockConfinesWrites) {
    std::string script =
        "touch out /tmp/x || exit 10\n"
        "echo hi > /dev/null || exit 11\n"
        "touch /x 2>/dev/null && exit 12\n"
        "echo x 2>/dev/null >> /etc/passwd && exit 13\n"
        "touch /dev/x 2>/dev/null && exit 14\n"
        "cat /etc/passwd > /dev/null || exit 15\n"
        "ls / > /dev/null || exit 16\n"  // ISSUE-1
        "cat /etc/ld.so.cache > /dev/null || exit 17\n"
        "exit 0\n";
    EXPECT_EQ(launch({"/bin/sh", "-c", script}), 0);
}

// Always-deny syscalls kill the target: 128 + SIGSYS.
TEST_F(Launcher, SeccompIsLive) {
    EXPECT_EQ(launch({"/bin/sh", "-c", "exec unshare -U true"}), 128 + SIGSYS);
}

// Grants come from the policy: only listed host paths appear, with the right access.
TEST_F(Launcher, AppliesPolicyGrants) {
    // Not under /tmp: the sandbox owns that path, so policies can't grant it.
    std::string tmpl = std::string(getenv("HOME")) + "/.zaun-grant-XXXXXX";
    std::string host = mkdtemp(tmpl.data());
    std::filesystem::create_directories(host + "/ro");
    std::filesystem::create_directories(host + "/rw");
    std::filesystem::create_directories(host + "/hidden");
    std::string policy = zaun::kBaselinePolicy;
    policy.replace(policy.find("read = ["), 8,
                   "write = [\"" + host + "/rw\"]\nread = [\"" + host + "/ro\", ");
    std::string script =
        "test -d " + host + "/ro || exit 10\n"
        "touch " + host + "/ro/x 2>/dev/null && exit 11\n"
        "touch " + host + "/rw/x || exit 12\n"
        "test -e " + host + "/hidden && exit 13\n"
        "exit 0\n";
    EXPECT_EQ(launch({"/bin/sh", "-c", script}, policy), 0);
    EXPECT_TRUE(std::filesystem::exists(host + "/rw/x"));
    std::filesystem::remove_all(host);
}

TEST_F(Launcher, ReadOnlyWorkdir) {
    std::string policy = std::string(zaun::kBaselinePolicy) + "[workdir]\nmode = \"ro\"\n";
    EXPECT_EQ(launch({"/bin/sh", "-c", "touch out 2>/dev/null && exit 10; ls > /dev/null"}, policy), 0);
}

TEST_F(Launcher, PropagatesExitStatus) {
    EXPECT_EQ(launch({"/bin/sh", "-c", "exit 7"}), 7);
    EXPECT_EQ(launch({"/bin/sh", "-c", "kill -TERM $$"}), 128 + SIGTERM);
    EXPECT_EQ(launch({"/nonexistent"}), 125);
}

TEST_F(Launcher, ReapsOrphans) {
    std::string script =
        "(sh -c 'exit 0' &)\n"
        "sleep 0.3\n"
        "! grep -qs '^State:.Z' /proc/[0-9]*/status\n";
    EXPECT_EQ(launch({"/bin/sh", "-c", script}), 0);
}

TEST_F(Launcher, ForwardsSignals) {
    pid_t child = fork();
    ASSERT_GE(child, 0);
    if (child == 0) _exit(launch({"/bin/sh", "-c", "touch ready; exec sleep 30"}));

    for (int i = 0; i < 500 && !std::filesystem::exists(dir_ + "/ready"); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_TRUE(std::filesystem::exists(dir_ + "/ready"));
    kill(child, SIGTERM);
    int status = 0;
    ASSERT_EQ(waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 128 + SIGTERM);
}

}  // namespace
