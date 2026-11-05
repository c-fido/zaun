#pragma once

#include <string>

#include "policy/policy.h"
#include "sandbox/plan.h"

namespace zaun {

// True if `dir` is `path` or one of its ancestors, by whole components.
bool contains(const std::string& dir, const std::string& path);

// Turns a policy into the launcher's plan, with `workdir` (resolved against the
// current directory) as the writable or read-only work directory. Throws
// PolicyError if a grant overlaps a path the sandbox builds itself (see
// kSandboxPaths), the workdir is missing or unsafe, or a syscall name is
// unknown or always denied.
SandboxPlan compile(const Policy& policy, const std::string& workdir);

// Credentials and private data under $HOME: hidden in the learn view, and flagged by `zaun check`.
// ponytail: a fixed list; extend it as new tools turn up.
inline const char* const kSecretPaths[] = {
    ".ssh", ".aws", ".gnupg", ".config/gh", ".docker", ".kube", ".config/gcloud", ".azure",
    ".netrc", ".git-credentials", ".npmrc", ".pypirc", ".password-store", ".local/share/keyrings",
    ".mozilla", ".config/google-chrome", ".config/chromium", ".config/BraveSoftware",
    ".claude", ".bash_history", ".zsh_history", ".python_history",
};

// The learn view (see SandboxPlan::learn) for `workdir`, with kSecretPaths under
// `home` hidden. Throws PolicyError if the workdir is missing or unsafe.
SandboxPlan compile_learn(const std::string& workdir, const std::string& home, const Limits& limits);

}  // namespace zaun
