#include <gtest/gtest.h>
#include <signal.h>
#include <stdlib.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include "cgroup/cgroup.h"
#include "policy/compile.h"
#include "sandbox/launcher.h"

namespace {

std::string slurp(const std::string& path) {
    std::ifstream in(path);
    std::string s;
    std::getline(in, s);
    return s;
}

// Skips unless this process can create a delegated cgroup (e.g. under `systemd-run --user --scope`).
#define REQUIRE_CGROUP()                                                       \
    do {                                                                       \
        try {                                                                  \
            zaun::Cgroup probe(zaun::Limits{});                                \
        } catch (const std::system_error& e) {                                 \
            GTEST_SKIP() << "no delegated cgroup: " << e.what();               \
        }                                                                      \
    } while (0)

class Limits : public testing::Test {
protected:
    void SetUp() override {
        char tmpl[] = "/tmp/zaun-test-XXXXXX";
        dir_ = mkdtemp(tmpl);
    }
    void TearDown() override { std::filesystem::remove_all(dir_); }

    int launch(const std::string& limits, const std::string& script) {
        std::string policy = std::string(zaun::kBaselinePolicy) + "[limits]\n" + limits;
        return zaun::launch(zaun::compile(zaun::parse_policy(policy), dir_), {"/bin/sh", "-c", script});
    }

    std::string dir_;
};

TEST(Cgroup, WritesLimits) {
    REQUIRE_CGROUP();
    zaun::Limits l;
    l.memory = 64 << 20;
    l.pids = 7;
    l.cpu = 0.5;
    std::string dir;
    {
        zaun::Cgroup cg(l);
        dir = cg.path();
        EXPECT_EQ(slurp(dir + "/memory.max"), std::to_string(64 << 20));
        EXPECT_EQ(slurp(dir + "/memory.swap.max"), "0");
        EXPECT_EQ(slurp(dir + "/pids.max"), "7");
        EXPECT_EQ(slurp(dir + "/cpu.max"), "50000 100000");
    }
    EXPECT_FALSE(std::filesystem::exists(dir));
}

TEST_F(Limits, MemoryLimitKills) {
    REQUIRE_CGROUP();
    // Writes to /tmp's tmpfs count against memory.max, so no interpreter is needed.
    EXPECT_EQ(launch("memory = \"32M\"\n", "head -c 100000000 /dev/zero > /tmp/fill; exit 0"), 128 + SIGKILL);
}

TEST_F(Limits, PidsLimitBlocksFork) {
    REQUIRE_CGROUP();
    // init, sh and the subshell fill the budget; one more fork must fail.
    EXPECT_NE(launch("pids = 3\n", "(sleep 1; true) & wait $! || exit 1; exit 0"), 0);
    EXPECT_EQ(launch("pids = 8\n", "(sleep 0; true) & wait $!"), 0);
}

// Works with or without a cgroup: init dies, taking the PID namespace with it.
TEST_F(Limits, TimeoutKills) {
    auto start = std::chrono::steady_clock::now();
    EXPECT_EQ(launch("timeout = \"300ms\"\n", "sleep 10"), 128 + SIGKILL);
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(3));
}

}  // namespace
