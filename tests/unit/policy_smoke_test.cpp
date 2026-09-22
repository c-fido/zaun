#include <gtest/gtest.h>
#include <toml++/toml.hpp>

// Smoke test: toml++ and GoogleTest are wired up.
TEST(PolicySmoke, ParsesExamplePolicy) {
    auto tbl = toml::parse(R"(
        version = 1
        name = "csv-report"
        [limits]
        memory = "512M"
        pids = 128
    )");
    EXPECT_EQ(tbl["version"].value<int>(), 1);
    EXPECT_EQ(tbl["name"].value<std::string>(), "csv-report");
    EXPECT_EQ(tbl["limits"]["pids"].value<int>(), 128);
}
