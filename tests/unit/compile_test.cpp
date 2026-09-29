#include "policy/compile.h"

#include <gtest/gtest.h>
#include <stdlib.h>

#include <filesystem>
#include <map>
#include <string>

namespace {

class Compile : public testing::Test {
protected:
    void SetUp() override {
        char tmpl[] = "/tmp/zaun-test-XXXXXX";
        dir_ = mkdtemp(tmpl);
    }
    void TearDown() override { std::filesystem::remove_all(dir_); }

    zaun::SandboxPlan compile(const std::string& toml) {
        return zaun::compile(zaun::parse_policy(toml), dir_);
    }

    // Expects compiling to fail with a message containing `want`.
    void expect_error(const std::string& toml, const std::string& want) {
        try {
            compile(toml);
            ADD_FAILURE() << "compiled, want error containing: " << want;
        } catch (const zaun::PolicyError& e) {
            EXPECT_NE(std::string(e.what()).find(want), std::string::npos) << e.what();
        }
    }

    std::string dir_;
};

TEST_F(Compile, Baseline) {
    zaun::SandboxPlan plan = zaun::compile(zaun::parse_policy(zaun::kBaselinePolicy), dir_);
    EXPECT_EQ(plan.workdir, std::filesystem::canonical(dir_).string());
    ASSERT_EQ(plan.binds.size(), 7u);  // 4 exec + 2 read + workdir
    EXPECT_EQ(plan.binds[0].path, "/bin");
    for (const auto& b : plan.binds) EXPECT_EQ(b.writable, b.path == plan.workdir) << b.path;
    EXPECT_FALSE(plan.seccomp.allowlist);
    EXPECT_EQ(plan.env, (std::vector<std::string>{"PATH", "LANG", "TERM"}));
}

TEST_F(Compile, LandlockAccess) {
    zaun::SandboxPlan plan = compile(R"(
        version = 1
        [workdir]
        mode = "ro"
        [filesystem]
        read = ["/srv/data"]
        write = ["/srv/out"]
        exec = ["/opt/tool", "/srv/data"]
    )");
    std::map<std::string, unsigned> got;
    for (const auto& r : plan.landlock) got[r.path] = r.access;
    EXPECT_EQ(got["/srv/data"], zaun::kRead | zaun::kExec);
    EXPECT_EQ(got["/srv/out"], zaun::kRead | zaun::kWrite | zaun::kRefer);
    EXPECT_EQ(got["/opt/tool"], zaun::kRead | zaun::kExec);
    EXPECT_EQ(got[plan.workdir], zaun::kRead | zaun::kExec);
}

// A bind already provided by its nearest bound parent is skipped; a writable
// grant under a read-only parent still needs its own.
TEST_F(Compile, SkipsCoveredBinds) {
    zaun::SandboxPlan plan = compile(R"(
        version = 1
        [filesystem]
        read = ["/srv", "/srv/a", "/srv/b/c/d"]
        write = ["/srv/b", "/srv/x"]
        exec = ["/srv/b/c"]
    )");
    std::vector<std::pair<std::string, bool>> got;
    for (const auto& b : plan.binds) {
        if (b.path != plan.workdir) got.emplace_back(b.path, b.writable);
    }
    std::vector<std::pair<std::string, bool>> want = {
        {"/srv", false}, {"/srv/b", true}, {"/srv/x", true}};
    EXPECT_EQ(got, want);
}

TEST_F(Compile, RejectsSandboxPaths) {
    for (const char* path : {"/", "/tmp", "/tmp/x", "/proc", "/proc/sys", "/dev/sda", "/etc",
                             "/etc/passwd"}) {
        expect_error("version = 1\n[filesystem]\nread = [\"" + std::string(path) + "\"]",
                     "filesystem.read: " + std::string(path) + " overlaps");
    }
    expect_error("version = 1\n[filesystem]\nwrite = [\"/dev\"]", "filesystem.write: /dev overlaps");
    // /tmpfoo shares a prefix with /tmp but isn't under it.
    EXPECT_NO_THROW(compile("version = 1\n[filesystem]\nread = [\"/tmpfoo\", \"/etc/hosts\"]"));
}

TEST_F(Compile, RejectsUnsafeWorkdir) {
    zaun::Policy p = zaun::parse_policy("version = 1");
    EXPECT_THROW(zaun::compile(p, "/"), zaun::PolicyError);
    EXPECT_THROW(zaun::compile(p, "/tmp"), zaun::PolicyError);
    EXPECT_THROW(zaun::compile(p, "/proc/self"), zaun::PolicyError);
    EXPECT_THROW(zaun::compile(p, "/nonexistent"), zaun::PolicyError);
    EXPECT_THROW(zaun::compile(p, "/usr/bin/env"), zaun::PolicyError);  // not a directory
}

TEST_F(Compile, ChecksSyscalls) {
    zaun::SandboxPlan plan = compile("version = 1\n[syscalls]\nmode = \"allowlist\"\nallow = [\"read\"]");
    EXPECT_TRUE(plan.seccomp.allowlist);
    expect_error("version = 1\n[syscalls]\nmode = \"allowlist\"\nallow = [\"frobnicate\"]",
                 "frobnicate is not a syscall");
    expect_error("version = 1\n[syscalls]\nmode = \"allowlist\"\nallow = [\"ptrace\"]",
                 "ptrace is always denied");
}

}  // namespace
