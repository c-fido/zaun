#include <gtest/gtest.h>
#include <stdlib.h>

#include <filesystem>
#include <fstream>
#include <string>

#include "learn/generalize.h"
#include "policy/compile.h"
#include "sandbox/launcher.h"

namespace {

class Learn : public testing::Test {
protected:
    void SetUp() override {
        char w[] = "/tmp/zaun-wd-XXXXXX";
        workdir_ = mkdtemp(w);
        // Not under /tmp: the learn view replaces the host's /tmp.
        std::string h = std::string(getenv("HOME")) + "/.zaun-home-XXXXXX";
        home_ = mkdtemp(h.data());
    }
    void TearDown() override {
        std::filesystem::remove_all(workdir_);
        std::filesystem::remove_all(home_);
    }

    zaun::RunResult learn(const std::vector<std::string>& argv) {
        return zaun::launch(zaun::compile_learn(workdir_, home_, {}), argv);
    }

    zaun::RunResult run(const zaun::Learned& l, const std::vector<std::string>& argv) {
        return zaun::launch(zaun::compile(zaun::parse_policy(zaun::to_toml(l)), workdir_), argv);
    }

    std::string workdir_, home_;
};

TEST_F(Learn, ViewHidesSecretsAndHostSockets) {
    std::filesystem::create_directories(home_ + "/.ssh");
    std::ofstream(home_ + "/.ssh/id_ed25519") << "key";
    std::ofstream(home_ + "/.netrc") << "machine x password y";
    std::ofstream(home_ + "/notes") << "visible";
    std::string script =
        "test -s " + home_ + "/notes || exit 10\n"  // the host root is visible...
        "touch " + home_ + "/new 2>/dev/null && exit 11\n"  // ...read-only
        "ls -A " + home_ + "/.ssh | grep -q . && exit 12\n"
        "test -s " + home_ + "/.netrc && exit 13\n"
        "test -e /run/systemd && exit 14\n"
        "test -e /sys/kernel && exit 15\n"
        "touch out || exit 16\n"
        "exit 0\n";
    EXPECT_EQ(learn({"/bin/sh", "-c", script}).exit_code, 0);
}

TEST_F(Learn, LearnedPolicyRunsAndConfines) {
    zaun::RunResult r = learn({"/bin/sh", "-c", "cat /etc/hostname > out"});
    ASSERT_EQ(r.exit_code, 0);
    EXPECT_EQ(r.notified.count({"openat", 'r', "/etc/hostname"}), 1u);
    EXPECT_EQ(r.notified.count({"execve", 'x', "/bin/sh"}), 1u);

    zaun::Learned l = zaun::generalize({r.notified}, workdir_, home_);
    EXPECT_TRUE(l.policy.workdir_writable);
    std::filesystem::remove(workdir_ + "/out");
    zaun::RunResult again = run(l, {"/bin/sh", "-c", "cat /etc/hostname > out"});
    EXPECT_EQ(again.exit_code, 0);
    EXPECT_TRUE(again.notified.empty());
    EXPECT_TRUE(std::filesystem::exists(workdir_ + "/out"));
    // Not in the trace, so not in the sandbox.
    EXPECT_NE(run(l, {"/bin/sh", "-c", "cat /etc/hosts"}).exit_code, 0);
}

TEST_F(Learn, AllowlistReportsDeniedSyscalls) {
    zaun::RunResult r = learn({"python3", "-c", "pass"});
    ASSERT_EQ(r.exit_code, 0);
    zaun::Learned l = zaun::generalize({r.notified}, workdir_, home_);
    zaun::RunResult denied = run(l, {"python3", "-c", "import os; os.getppid()"});
    EXPECT_EQ(denied.notified.count({"getppid", '-', ""}), 1u);
}

}  // namespace
