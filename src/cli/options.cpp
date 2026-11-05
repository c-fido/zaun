#include "options.h"

#include <cstdio>
#include <cstring>

#include "policy/policy.h"

namespace zaun {

bool parse_options(int argc, char** argv, std::initializer_list<const char*> names, const char* usage,
                   Options& out) {
    int i = 0;
    while (i < argc && argv[i][0] == '-') {
        if (std::strcmp(argv[i], "--") == 0) {
            ++i;
            break;
        }
        bool known = false;
        for (const char* n : names) known = known || std::strcmp(argv[i], n) == 0;
        if (!known || i + 1 == argc) {
            std::fprintf(stderr, "zaun: %s option %s\n%s\n", known ? "missing value for" : "unknown",
                         argv[i], usage);
            return false;
        }
        out.values[argv[i]] = argv[i + 1];
        i += 2;
    }
    if (i == argc) {
        std::fprintf(stderr, "%s\n", usage);
        return false;
    }
    out.command = i;
    return true;
}

void apply_limits(const Options& opts, Limits& limits) {
    if (const char* v = opts.get("--mem")) limits.memory = parse_size(v, "--mem");
    if (const char* v = opts.get("--pids")) limits.pids = parse_size(v, "--pids");
    if (const char* v = opts.get("--timeout")) limits.timeout = parse_duration(v, "--timeout");
}

}  // namespace zaun
