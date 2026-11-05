#include "learn.h"

#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>

#include <cstdio>
#include <exception>
#include <fstream>
#include <string>
#include <vector>

#include "learn/generalize.h"
#include "options.h"
#include "policy/compile.h"
#include "sandbox/launcher.h"

namespace zaun {
namespace {

std::string home_dir() {
    if (const char* h = getenv("HOME")) return h;
    const passwd* pw = getpwuid(getuid());
    return pw ? pw->pw_dir : "/";
}

void write_text(const std::string& path, const std::string& text) {
    std::ofstream out(path);
    out << text;
    out.close();
    if (!out) throw PolicyError(path + ": cannot write");
}

}  // namespace

int learn(int argc, char** argv) {
    Options opts;
    if (!parse_options(argc, argv, {"--out", "--runs", "--workdir", "--trace", "--mem", "--pids", "--timeout"},
                       "usage: zaun learn --out FILE [--runs N] [--workdir DIR] [--trace FILE] [--mem SIZE] "
                       "[--pids N] [--timeout DURATION] -- CMD...",
                       opts)) {
        return 125;
    }
    const char* out = opts.get("--out");
    if (!out) {
        std::fprintf(stderr, "zaun learn: --out is required\n");
        return 125;
    }
    try {
        const char* runs_opt = opts.get("--runs");
        uint64_t runs = runs_opt ? parse_size(runs_opt, "--runs") : 1;
        if (runs > 100) throw PolicyError("--runs: at most 100");
        Limits limits;
        apply_limits(opts, limits);
        const char* workdir = opts.get("--workdir");
        std::string home = home_dir();
        SandboxPlan plan = compile_learn(workdir ? workdir : ".", home, limits);
        std::vector<std::string> cmd(argv + opts.command, argv + argc);

        std::vector<Trace> traces;
        for (uint64_t i = 1; i <= runs; ++i) {
            RunResult r = launch(plan, cmd);
            if (r.exit_code != 0) {
                std::fprintf(stderr, "zaun learn: warning: run %llu exited with %d (%s)\n",
                             static_cast<unsigned long long>(i), r.exit_code, r.reason.c_str());
            }
            traces.push_back(std::move(r.notified));
        }
        if (const char* trace = opts.get("--trace")) {
            std::ofstream t(trace);
            write_traces(t, traces);
            t.close();
            if (!t) throw PolicyError(std::string(trace) + ": cannot write");
        }

        Learned learned = generalize(traces, plan.workdir, home);
        learned.policy.limits = limits;
        write_text(out, to_toml(learned));
        for (const auto& w : learned.warnings) std::fprintf(stderr, "zaun learn: warning: %s\n", w.c_str());
        const Policy& p = learned.policy;
        std::fprintf(stderr, "zaun learn: wrote %s: %zu read, %zu write, %zu exec rules, %zu syscalls\n", out,
                     p.read.size(), p.write.size(), p.exec.size(), p.syscalls.allow.size());
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zaun: %s\n", e.what());
        return 125;
    }
}

}  // namespace zaun
