#pragma once

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "sandbox/plan.h"

namespace zaun {

// A policy file failed to parse, validate or compile. what() names the key.
struct PolicyError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// A validated policy file. See kBaselinePolicy for the format.
struct Policy {
    int version = 1;
    std::string name;
    std::optional<std::string> workdir;  // as written; relative to the current directory
    bool workdir_writable = true;
    // Absolute, lexically normal host paths.
    std::vector<std::string> read, write, exec;
    std::vector<std::string> env = {"PATH", "LANG", "TERM"};
    Limits limits;
    SeccompPlan syscalls;
    int learned_from = 0;  // runs; 0 if hand-written
};

// Used by `zaun run` without --policy.
inline constexpr const char* kBaselinePolicy = R"(version = 1
name = "baseline"

[filesystem]
read = ["/etc/ld.so.cache", "/etc/ssl/certs"]
exec = ["/usr", "/lib", "/lib64", "/bin"]

[syscalls]
mode = "baseline"
)";

// Parses and validates TOML text. Strict: unknown keys and wrong types are
// errors. `source` names the text in error messages. Throws PolicyError.
Policy parse_policy(const std::string& text, const std::string& source = "policy");

// Reads and parses a policy file. Throws PolicyError.
Policy load_policy(const std::string& path);

}  // namespace zaun
