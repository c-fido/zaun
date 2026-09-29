#include "run.h"

#include <cstdio>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

#include "policy/compile.h"
#include "policy/policy.h"
#include "sandbox/launcher.h"

namespace zaun {

int run(int argc, char** argv) {
    const char* workdir = nullptr;
    const char* policy_path = nullptr;
    int i = 0;
    for (; i < argc; ++i) {
        if (std::strcmp(argv[i], "--") == 0) {
            ++i;
            break;
        }
        if (std::strcmp(argv[i], "--workdir") == 0 && i + 1 < argc) {
            workdir = argv[++i];
        } else if (std::strcmp(argv[i], "--policy") == 0 && i + 1 < argc) {
            policy_path = argv[++i];
        } else if (argv[i][0] == '-') {
            std::fprintf(stderr, "zaun run: unknown option %s\n", argv[i]);
            return 125;
        } else {
            break;
        }
    }
    if (i == argc) {
        std::fprintf(stderr, "usage: zaun run [--policy FILE] [--workdir DIR] -- CMD...\n");
        return 125;
    }

    try {
        Policy policy = policy_path ? load_policy(policy_path) : parse_policy(kBaselinePolicy, "baseline");
        SandboxPlan plan = compile(policy, workdir ? workdir : policy.workdir.value_or("."));
        const Limits& l = plan.limits;
        if (l.memory || l.pids || l.cpu > 0 || l.timeout.count()) {
            // ponytail: week 3 enforces limits.
            std::fprintf(stderr, "zaun: warning: [limits] are not enforced yet\n");
        }
        return launch(plan, std::vector<std::string>(argv + i, argv + argc));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zaun: %s\n", e.what());
        return 125;
    }
}

}  // namespace zaun
