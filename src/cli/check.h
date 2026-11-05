#pragma once

namespace zaun {

// `zaun check FILE`: validates a policy and warns on broad grants (/, $HOME,
// /etc) and on grants that reach a secret path. Returns 0 if clean, 1 with
// warnings, 125 if the policy is invalid.
int check(int argc, char** argv);

// `zaun diff A B`: prints permissions B adds (+), removes (-) or changes (~)
// relative to A. Returns 0 if they match, 1 if they differ, 125 on error.
int diff(int argc, char** argv);

}  // namespace zaun
