#include <gtest/gtest.h>
#include <stdlib.h>
#include <unistd.h>

#include <filesystem>
#include <string>

#include "sandbox/launcher.h"

// Each check exits with its own code so a failure names the check.
TEST(Launcher, IsolatesFilesystem) {
    char tmpl[] = "/tmp/zaun-test-XXXXXX";
    std::string dir = mkdtemp(tmpl);
    std::string script =
        "test $$ = 1 || exit 10\n"
        "test \"$(id -u)\" = " + std::to_string(getuid()) + " || exit 11\n"
        "test \"$(pwd)\" = " + dir + " || exit 12\n"
        "touch out || exit 13\n"
        "grep -q ' /usr [^ ]* ro,nosuid,nodev' /proc/mounts || exit 14\n"
        "grep -q ' " + dir + " [^ ]* rw,nosuid,nodev' /proc/mounts || exit 15\n"
        "test -e /home -o -e /sys && exit 16\n"
        "test \"$(ls /dev | wc -l)\" = 5 || exit 17\n"
        "test \"$(wc -l < /proc/net/dev)\" = 3 || exit 18\n"  // header + lo only
        "exit 0\n";
    EXPECT_EQ(zaun::launch(dir, {"/bin/sh", "-c", script}), 0);
    EXPECT_TRUE(std::filesystem::exists(dir + "/out"));
    EXPECT_EQ(zaun::launch(dir, {"/bin/sh", "-c", "exit 7"}), 7);
    std::filesystem::remove_all(dir);
}
