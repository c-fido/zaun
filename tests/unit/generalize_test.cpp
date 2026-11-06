#include "learn/generalize.h"

#include <gtest/gtest.h>
#include <stdlib.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>

#include "policy/compile.h"

// Traces use real files from an Ubuntu 24.04 base install, since the rules look
// at the host (existence, symlinks, ELF interpreters).
namespace {

bool has(const std::vector<std::string>& v, const std::string& s) {
    return std::find(v.begin(), v.end(), s) != v.end();
}

class Generalize : public testing::Test {
protected:
    void SetUp() override {
        char w[] = "/tmp/zaun-wd-XXXXXX";
        workdir_ = mkdtemp(w);
        // Not under /tmp, which the sandbox provides.
        std::string h = std::string(getenv("HOME")) + "/.zaun-home-XXXXXX";
        home_ = mkdtemp(h.data());
    }
    void TearDown() override {
        std::filesystem::remove_all(workdir_);
        std::filesystem::remove_all(home_);
    }

    zaun::Learned learn(const std::vector<zaun::Trace>& runs) { return zaun::generalize(runs, workdir_, home_); }

    std::string workdir_, home_;
};

TEST_F(Generalize, DropsSandboxPaths) {
    zaun::Learned l = learn({{{{"openat", 'r', "/proc/self/maps"}, 1},
                              {{"openat", 'r', "/dev/null"}, 1},
                              {{"openat", 'w', "/tmp/scratch"}, 1},
                              {{"openat", 'r', "/etc/passwd"}, 1},
                              {{"openat", 'r', "/nonexistent/file"}, 1}}});
    EXPECT_TRUE(l.policy.read.empty());
    EXPECT_TRUE(l.policy.write.empty());
}

TEST_F(Generalize, ClassifiesAndFollowsExec) {
    zaun::Learned l = learn({{{{"execve", 'x', "/bin/sh"}, 1}, {{"openat", 'r', "/etc/hostname"}, 1}}});
    const zaun::Policy& p = l.policy;
    EXPECT_TRUE(has(p.read, "/etc/hostname"));
    // /bin and /usr/bin/sh are symlinks the sandbox must recreate; dash is the real binary.
    EXPECT_TRUE(has(p.read, "/bin"));
    EXPECT_TRUE(has(p.read, "/usr/bin/sh"));
    EXPECT_TRUE(has(p.exec, "/usr/bin/dash"));
    // The dynamic loader is never opened by the program, only by the kernel.
    EXPECT_TRUE(std::any_of(p.exec.begin(), p.exec.end(),
                            [](const std::string& s) { return s.find("/ld-linux") != std::string::npos; }));
}

TEST_F(Generalize, WorkdirBinaryKeepsItsLoader) {
    std::filesystem::copy_file("/usr/bin/true", workdir_ + "/true");
    zaun::Learned l = learn({{{{"execve", 'x', workdir_ + "/true"}, 1}}});
    EXPECT_TRUE(std::any_of(l.policy.exec.begin(), l.policy.exec.end(),
                            [](const std::string& s) { return s.find("/ld-linux") != std::string::npos; }));
}

TEST_F(Generalize, CollapsesUnderPrefixes) {
    const std::string dir = "/usr/share/common-licenses";
    zaun::Learned l = learn({{{{"openat", 'r', dir + "/GPL-2"}, 1},
                              {{"openat", 'r', dir + "/GPL-3"}, 1},
                              {{"openat", 'r', dir + "/Apache-2.0"}, 1}}});
    EXPECT_EQ(l.policy.read, std::vector<std::string>{dir});
    // Two files stay files.
    l = learn({{{{"openat", 'r', dir + "/GPL-2"}, 1}, {{"openat", 'r', dir + "/GPL-3"}, 1}}});
    EXPECT_EQ(l.policy.read.size(), 2u);
}

TEST_F(Generalize, NeverCollapsesEtcOrHome) {
    std::ofstream(home_ + "/a") << "a";
    std::ofstream(home_ + "/b") << "b";
    std::ofstream(home_ + "/c") << "c";
    zaun::Learned l = learn({{{{"openat", 'r', "/etc/hostname"}, 1},
                              {{"openat", 'r', "/etc/hosts"}, 1},
                              {{"openat", 'r', "/etc/environment"}, 1},
                              {{"openat", 'r', home_ + "/a"}, 1},
                              {{"openat", 'r', home_ + "/b"}, 1},
                              {{"openat", 'r', home_ + "/c"}, 1},
                              {{"openat", 'r', home_}, 1},  // listing $HOME
                              {{"newfstatat", 's', "/usr"}, 1}}});
    const zaun::Policy& p = l.policy;
    EXPECT_TRUE(has(p.read, "/etc/hosts"));
    EXPECT_TRUE(has(p.read, home_ + "/a"));
    EXPECT_FALSE(has(p.read, "/etc"));
    EXPECT_FALSE(has(p.read, home_));
    EXPECT_FALSE(has(p.read, "/usr"));  // stat only
    auto warned = [&](const std::string& s) {
        return std::any_of(l.warnings.begin(), l.warnings.end(),
                           [&](const std::string& w) { return w.find(s) != std::string::npos; });
    };
    EXPECT_TRUE(warned("3 files in /etc"));
    EXPECT_TRUE(warned("3 files in " + home_));
    EXPECT_TRUE(warned("listing " + home_));
}

TEST_F(Generalize, WorkdirBecomesItsRule) {
    zaun::Learned l = learn({{{{"openat", 'r', workdir_ + "/in.csv"}, 1}}});
    EXPECT_FALSE(l.policy.workdir_writable);
    EXPECT_TRUE(l.policy.read.empty());
    l = learn({{{{"openat", 'w', workdir_ + "/out.csv"}, 1}}});
    EXPECT_TRUE(l.policy.workdir_writable);
}

TEST_F(Generalize, SyscallsDropAlwaysDenied) {
    zaun::Learned l = learn({{{{"read", '-', ""}, 3}, {{"ptrace", '-', ""}, 1}, {{"syscall_9999", '-', ""}, 1}}});
    EXPECT_EQ(l.policy.syscalls.allow, std::vector<std::string>{"read"});
    EXPECT_TRUE(l.policy.syscalls.allowlist);
}

TEST_F(Generalize, MergesRunsWithSupport) {
    zaun::Learned l = learn({{{{"openat", 'r', "/etc/hostname"}, 1}, {{"read", '-', ""}, 1}},
                             {{{"openat", 'r', "/etc/hosts"}, 1}, {{"read", '-', ""}, 1}}});
    EXPECT_TRUE(has(l.policy.read, "/etc/hostname"));
    EXPECT_TRUE(has(l.policy.read, "/etc/hosts"));
    EXPECT_EQ(l.support["read /etc/hosts"], 1);
    EXPECT_EQ(l.support["syscall read"], 2);
    std::string toml = zaun::to_toml(l);
    EXPECT_NE(toml.find("\"/etc/hosts\",  # seen in 1/2 runs"), std::string::npos) << toml;
    EXPECT_EQ(toml.find("\"read\",  # seen"), std::string::npos) << toml;
}

// The output is a policy zaun accepts as written.
TEST_F(Generalize, TomlRoundTrips) {
    zaun::Learned l = learn({{{{"execve", 'x', "/bin/sh"}, 1},
                              {{"openat", 'r', "/etc/hostname"}, 1},
                              {{"openat", 'w', workdir_ + "/out"}, 1},
                              {{"read", '-', ""}, 1}}});
    l.policy.limits.memory = 64 << 20;
    l.policy.limits.timeout = std::chrono::milliseconds(1500);
    zaun::Policy p = zaun::parse_policy(zaun::to_toml(l));
    EXPECT_EQ(p.read, l.policy.read);
    EXPECT_EQ(p.exec, l.policy.exec);
    EXPECT_EQ(p.syscalls.allow, l.policy.syscalls.allow);
    EXPECT_EQ(p.limits.memory, 64u << 20);
    EXPECT_EQ(p.limits.timeout.count(), 1500);
    EXPECT_EQ(p.learned_from, 1);
    zaun::compile(p, workdir_);
}

}  // namespace
