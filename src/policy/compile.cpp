#include "policy/compile.h"

#include <filesystem>
#include <map>

#include "sandbox/fs.h"
#include "sandbox/seccomp.h"

namespace fs = std::filesystem;

namespace zaun {

bool contains(const std::string& dir, const std::string& path) {
    if (dir == "/") return true;
    return path.compare(0, dir.size(), dir) == 0 &&
           (path.size() == dir.size() || path[dir.size()] == '/');
}

namespace {

// The canonical workdir; throws if it is missing or overlaps a sandbox path.
std::string check_workdir(const std::string& workdir) {
    std::error_code ec;
    std::string dir = fs::canonical(workdir, ec).string();
    if (ec) throw PolicyError("workdir " + workdir + ": " + ec.message());
    if (!fs::is_directory(dir)) throw PolicyError("workdir " + workdir + ": not a directory");
    for (std::string owned : kSandboxPaths) {
        // A workdir under /tmp is fine: it's bound on top of the fresh tmpfs.
        if (contains(dir, owned) || (owned != "/tmp" && contains(owned, dir))) {
            throw PolicyError("workdir " + dir + " overlaps " + owned + ", which the sandbox provides");
        }
    }
    return dir;
}

}  // namespace

SandboxPlan compile_learn(const std::string& workdir, const std::string& home, const Limits& limits) {
    SandboxPlan plan;
    plan.workdir = check_workdir(workdir);
    plan.binds.push_back({plan.workdir, true});
    plan.learn = true;
    for (const char* s : kSecretPaths) plan.hide.push_back(home + "/" + s);
    plan.env = Policy{}.env;
    plan.limits = limits;
    return plan;
}

SandboxPlan compile(const Policy& policy, const std::string& workdir) {
    SandboxPlan plan;
    plan.workdir = check_workdir(workdir);

    // Per path: Landlock access and whether the bind is writable.
    std::map<std::string, std::pair<unsigned, bool>> grants;
    auto grant = [&](const char* key, const std::vector<std::string>& paths, unsigned access,
                     bool writable) {
        for (const auto& path : paths) {
            for (std::string owned : kSandboxPaths) {
                if (contains(path, owned) || contains(owned, path)) {
                    throw PolicyError(std::string(key) + ": " + path + " overlaps " + owned +
                                      ", which the sandbox provides");
                }
            }
            auto& g = grants[path];
            g.first |= access;
            g.second = g.second || writable;
        }
    };
    grant("filesystem.read", policy.read, kRead, false);
    grant("filesystem.exec", policy.exec, kRead | kExec, false);
    grant("filesystem.write", policy.write, kRead | kWrite | kRefer, true);
    auto& wd = grants[plan.workdir];  // checked above
    wd.first |= policy.workdir_writable ? kRead | kWrite | kExec | kRefer : kRead | kExec;
    wd.second = wd.second || policy.workdir_writable;

    // Sorted, so parents come first. Skip a bind its nearest bound parent already provides.
    for (const auto& [path, g] : grants) {
        plan.landlock.push_back({path, g.first});
        const Bind* parent = nullptr;
        for (const Bind& b : plan.binds) {
            if (contains(b.path, path)) parent = &b;
        }
        if (!parent || (g.second && !parent->writable)) plan.binds.push_back({path, g.second});
    }

    for (const auto& name : policy.syscalls.allow) {
        if (always_denied(name)) throw PolicyError("syscalls.allow: " + name + " is always denied");
        if (!syscall_known(name)) {
            throw PolicyError("syscalls.allow: " + name + " is not a syscall on this architecture");
        }
    }
    plan.seccomp = policy.syscalls;
    plan.env = policy.env;
    plan.limits = policy.limits;
    return plan;
}

}  // namespace zaun
