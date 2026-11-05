#include "run.h"

#include <cstdio>
#include <exception>
#include <string>
#include <vector>

#include "options.h"
#include "policy/compile.h"
#include "policy/policy.h"
#include "report/report.h"
#include "sandbox/launcher.h"

namespace zaun {

int run(int argc, char** argv) {
    Options opts;
    if (!parse_options(argc, argv, {"--policy", "--workdir", "--mem", "--pids", "--timeout", "--report"},
                       "usage: zaun run [--policy FILE] [--workdir DIR] [--mem SIZE] [--pids N] "
                       "[--timeout DURATION] [--report FILE] -- CMD...",
                       opts)) {
        return 125;
    }
    try {
        const char* policy_path = opts.get("--policy");
        Policy policy = policy_path ? load_policy(policy_path) : parse_policy(kBaselinePolicy, "baseline");
        apply_limits(opts, policy.limits);  // flags override the policy's [limits]
        const char* workdir = opts.get("--workdir");
        SandboxPlan plan = compile(policy, workdir ? workdir : policy.workdir.value_or("."));
        RunResult result = launch(plan, std::vector<std::string>(argv + opts.command, argv + argc));
        for (const auto& [key, count] : result.notified) {
            std::fprintf(stderr, "zaun: denied syscall %s (%llu times)\n", std::get<0>(key).c_str(),
                         static_cast<unsigned long long>(count));
        }
        if (const char* report = opts.get("--report")) write_report(report, result);
        return result.exit_code;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zaun: %s\n", e.what());
        return 125;
    }
}

}  // namespace zaun
