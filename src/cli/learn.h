#pragma once

namespace zaun {

// `zaun learn --out FILE [--runs N] [--workdir DIR] [--trace FILE] [--mem SIZE]
// [--pids N] [--timeout DURATION] -- CMD...`; argv starts after "learn".
// Runs CMD N times in the learn view and writes the generalized policy, plus
// the raw traces with --trace. Returns 0, or 125 on failure.
int learn(int argc, char** argv);

}  // namespace zaun
