#include "policy/policy.h"

#include <gtest/gtest.h>

#include <string>

namespace {

using zaun::parse_policy;
using zaun::PolicyError;

// Expects parsing to fail with a message containing `want`.
void expect_error(const std::string& text, const std::string& want) {
    try {
        parse_policy(text, "p.toml");
        ADD_FAILURE() << "parsed, want error containing: " << want;
    } catch (const PolicyError& e) {
        EXPECT_NE(std::string(e.what()).find(want), std::string::npos) << e.what();
    }
}

// The example policy from the design doc.
TEST(Policy, ParsesFullExample) {
    zaun::Policy p = parse_policy(R"(
        version = 1
        name = "csv-report"

        [workdir]
        path = "."
        mode = "rw"

        [filesystem]
        read = ["/usr", "/etc/ssl/certs/", "/etc/../etc/ld.so.cache"]
        write = []
        exec = ["/usr/bin/python3.12"]

        [network]
        mode = "none"

        [env]
        keep = ["PATH", "LANG"]

        [limits]
        memory = "512M"
        pids = 128
        cpu = 1.0
        timeout = "60s"

        [syscalls]
        mode = "allowlist"
        allow = ["read", "write", "openat", "mmap"]

        [meta]
        learned_from = 3
    )");
    EXPECT_EQ(p.name, "csv-report");
    EXPECT_EQ(p.workdir, ".");
    EXPECT_TRUE(p.workdir_writable);
    EXPECT_EQ(p.read, (std::vector<std::string>{"/usr", "/etc/ssl/certs", "/etc/ld.so.cache"}));
    EXPECT_TRUE(p.write.empty());
    EXPECT_EQ(p.exec, std::vector<std::string>{"/usr/bin/python3.12"});
    EXPECT_EQ(p.env, (std::vector<std::string>{"PATH", "LANG"}));
    EXPECT_EQ(p.limits.memory, 512ull << 20);
    EXPECT_EQ(p.limits.pids, 128u);
    EXPECT_EQ(p.limits.cpu, 1.0);
    EXPECT_EQ(p.limits.timeout, std::chrono::seconds(60));
    EXPECT_TRUE(p.syscalls.allowlist);
    EXPECT_EQ(p.syscalls.allow.size(), 4u);
    EXPECT_EQ(p.learned_from, 3);
}

TEST(Policy, MinimalUsesDefaults) {
    zaun::Policy p = parse_policy("version = 1");
    EXPECT_FALSE(p.workdir);
    EXPECT_TRUE(p.workdir_writable);
    EXPECT_TRUE(p.read.empty());
    EXPECT_EQ(p.env, (std::vector<std::string>{"PATH", "LANG", "TERM"}));
    EXPECT_FALSE(p.syscalls.allowlist);
    EXPECT_EQ(p.limits.memory, 0u);
}

TEST(Policy, ParsesBaseline) {
    zaun::Policy p = parse_policy(zaun::kBaselinePolicy, "baseline");
    EXPECT_EQ(p.exec.front(), "/usr");
}

TEST(Policy, UnitsAndNumbers) {
    zaun::Policy p = parse_policy(R"(
        version = 1
        [limits]
        memory = 1048576
        cpu = 2
        timeout = 90
    )");
    EXPECT_EQ(p.limits.memory, 1u << 20);
    EXPECT_EQ(p.limits.cpu, 2.0);
    EXPECT_EQ(p.limits.timeout, std::chrono::seconds(90));
    EXPECT_EQ(parse_policy("version = 1\n[limits]\ntimeout = \"250ms\"").limits.timeout,
              std::chrono::milliseconds(250));
    EXPECT_EQ(parse_policy("version = 1\n[limits]\nmemory = \"2G\"").limits.memory, 2ull << 30);
}

TEST(Policy, RejectsUnknownKeys) {
    expect_error("version = 1\nnmae = \"x\"", "p.toml:2: nmae: unknown key");
    expect_error("version = 1\n[filesystem]\nreads = []", "filesystem.reads: unknown key");
    expect_error("version = 1\n[limits]\nswap = 0", "limits.swap: unknown key");
    expect_error("version = 1\n[meta]\nnote = \"x\"", "meta.note: unknown key");
}

TEST(Policy, RejectsBadTypes) {
    expect_error("version = \"1\"", "version: expected an integer");
    expect_error("version = 1\nname = 3", "name: expected a string");
    expect_error("version = 1\nfilesystem = 1", "filesystem: expected a table");
    expect_error("version = 1\n[filesystem]\nread = \"/usr\"", "filesystem.read: expected an array");
    expect_error("version = 1\n[filesystem]\nread = [\"/usr\", 1]", "filesystem.read[1]: expected a string");
    expect_error("version = 1\n[limits]\npids = \"many\"", "limits.pids: expected a positive integer");
    expect_error("version = 1\n[limits]\npids = 0", "limits.pids: expected a positive integer");
    expect_error("version = 1\n[limits]\ncpu = \"1\"", "limits.cpu: expected a positive number");
}

TEST(Policy, RejectsBadValues) {
    expect_error("version = 2", "version: unsupported version");
    expect_error("version = 1\n[workdir]\nmode = \"rwx\"", "workdir.mode");
    expect_error("version = 1\n[filesystem]\nread = [\"usr\"]", "filesystem.read[0]: expected an absolute path");
    expect_error("version = 1\n[filesystem]\nwrite = [\"\"]", "filesystem.write[0]: expected an absolute path");
    expect_error("version = 1\n[network]\nmode = \"host\"", "network.mode: only \"none\"");
    expect_error("version = 1\n[env]\nkeep = [\"A-B\"]", "env.keep[0]: not a variable name");
    expect_error("version = 1\n[env]\nkeep = [\"HOME\"]", "env.keep[0]: HOME is always the workdir");
    expect_error("version = 1\n[limits]\nmemory = \"512MB\"", "limits.memory: expected a size");
    expect_error("version = 1\n[limits]\nmemory = \"M\"", "limits.memory: expected a size");
    expect_error("version = 1\n[limits]\nmemory = \"99999999999999999999\"", "limits.memory: expected a size");
    expect_error("version = 1\n[limits]\ntimeout = \"1d\"", "limits.timeout: expected a duration");
    expect_error("version = 1\n[syscalls]\nmode = \"strict\"", "syscalls.mode");
}

TEST(Policy, RejectsMissingRequired) {
    expect_error("name = \"x\"", "p.toml: version: required");
    expect_error("version = 1\n[syscalls]\nmode = \"allowlist\"", "syscalls.allow: required");
    expect_error("version = 1\n[syscalls]\nallow = [\"read\"]", "syscalls.allow: needs mode");
}

TEST(Policy, ReportsSyntaxErrorLine) {
    expect_error("version = 1\nname = \n", "p.toml:2:");
}

TEST(Policy, LoadMissingFile) {
    EXPECT_THROW(zaun::load_policy("/nonexistent/p.toml"), PolicyError);
}

}  // namespace
