#pragma once

#include <initializer_list>
#include <map>
#include <string>

#include "sandbox/plan.h"

namespace zaun {

struct Options {
    std::map<std::string, std::string> values;  // "--mem" -> "512M"
    int command = 0;  // index of the command's argv[0]

    const char* get(const std::string& name) const {
        auto it = values.find(name);
        return it == values.end() ? nullptr : it->second.c_str();
    }
};

// Parses `--name value` options from `names`, then an optional "--", then a
// command. Prints an error and `usage` and returns false if an option is
// unknown or there is no command.
bool parse_options(int argc, char** argv, std::initializer_list<const char*> names, const char* usage,
                   Options& out);

// Applies --mem, --pids and --timeout. Throws PolicyError.
void apply_limits(const Options& opts, Limits& limits);

}  // namespace zaun
