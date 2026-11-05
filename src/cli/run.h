#pragma once

namespace zaun {

// `zaun run [--policy FILE] [--workdir DIR] [--mem SIZE] [--pids N]
// [--timeout DURATION] [--report FILE] -- CMD...`; argv starts after "run".
// Without --policy it uses kBaselinePolicy; flags override the policy's.
// Returns the target's exit code, or 125 if zaun fails before execve.
int run(int argc, char** argv);

}  // namespace zaun
