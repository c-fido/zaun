#pragma once

namespace zaun {

// `zaun run [--workdir DIR] -- CMD...`; argv starts after "run".
// Returns the target's exit code, or 125 if zaun fails before execve.
int run(int argc, char** argv);

}  // namespace zaun
