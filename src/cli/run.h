#pragma once

namespace zaun {

// `zaun run [--policy FILE] [--workdir DIR] -- CMD...`; argv starts after "run".
// Without --policy it uses kBaselinePolicy; --workdir overrides the policy's.
// Returns the target's exit code, or 125 if zaun fails before execve.
int run(int argc, char** argv);

}  // namespace zaun
