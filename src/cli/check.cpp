#include "check.h"

#include <stdlib.h>

#include <algorithm>
#include <cstdio>
#include <exception>
#include <string>
#include <utility>
#include <vector>

#include "policy/compile.h"
#include "policy/policy.h"

namespace zaun {
namespace {

std::vector<std::string> warnings(const Policy& p, const std::string& home) {
    std::vector<std::string> out;
    const std::pair<const char*, const std::vector<std::string>*> lists[] = {
        {"read", &p.read}, {"write", &p.write}, {"exec", &p.exec}};
    for (const auto& [kind, paths] : lists) {
        for (const auto& path : *paths) {
            std::string grant = std::string("filesystem.") + kind + " " + path;
            if (path == "/") {
                out.push_back(grant + ": the whole host filesystem");
                continue;
            }
            if (contains(path, home)) {
                out.push_back(grant + ": all of $HOME, secrets included");
                continue;
            }
            if (path == "/etc") out.push_back(grant + ": all of /etc");
            for (const char* s : kSecretPaths) {
                std::string secret = home + "/" + s;
                if (contains(secret, path) || contains(path, secret)) {
                    out.push_back(grant + ": reaches " + secret);
                }
            }
        }
    }
    return out;
}

std::string limits_value(const Limits& l, const std::string& key) {
    if (key == "memory") return std::to_string(l.memory);
    if (key == "pids") return std::to_string(l.pids);
    if (key == "cpu") return std::to_string(l.cpu);
    return std::to_string(l.timeout.count()) + "ms";
}

}  // namespace

int check(int argc, char** argv) {
    if (argc != 1) {
        std::fprintf(stderr, "usage: zaun check FILE\n");
        return 125;
    }
    try {
        Policy p = load_policy(argv[0]);
        const char* home = getenv("HOME");
        std::vector<std::string> ws = warnings(p, home ? home : "/nonexistent");
        for (const auto& w : ws) std::printf("warning: %s\n", w.c_str());
        compile(p, p.workdir.value_or("."));
        if (ws.empty()) std::printf("%s: ok\n", argv[0]);
        return ws.empty() ? 0 : 1;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zaun: %s\n", e.what());
        return 125;
    }
}

int diff(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: zaun diff A B\n");
        return 125;
    }
    try {
        Policy a = load_policy(argv[0]);
        Policy b = load_policy(argv[1]);
        int changes = 0;
        // Prints what `to` has that `from` lacks.
        auto missing = [&](char sign, const char* key, std::vector<std::string> from,
                           const std::vector<std::string>& to) {
            std::sort(from.begin(), from.end());
            for (const auto& v : to) {
                if (std::binary_search(from.begin(), from.end(), v)) continue;
                std::printf("%c %s %s\n", sign, key, v.c_str());
                ++changes;
            }
        };
        auto lists = [&](const char* key, const std::vector<std::string>& x, const std::vector<std::string>& y) {
            missing('+', key, x, y);
            missing('-', key, y, x);
        };
        auto scalar = [&](const std::string& key, const std::string& x, const std::string& y) {
            if (x == y) return;
            std::printf("~ %s: %s -> %s\n", key.c_str(), x.c_str(), y.c_str());
            ++changes;
        };
        auto mode = [](bool rw) { return std::string(rw ? "rw" : "ro"); };
        auto sys = [](const Policy& p) { return std::string(p.syscalls.allowlist ? "allowlist" : "baseline"); };
        scalar("workdir.mode", mode(a.workdir_writable), mode(b.workdir_writable));
        lists("filesystem.read", a.read, b.read);
        lists("filesystem.write", a.write, b.write);
        lists("filesystem.exec", a.exec, b.exec);
        lists("env.keep", a.env, b.env);
        for (const char* k : {"memory", "pids", "cpu", "timeout"}) {
            scalar(std::string("limits.") + k, limits_value(a.limits, k), limits_value(b.limits, k));
        }
        scalar("syscalls.mode", sys(a), sys(b));
        lists("syscalls.allow", a.syscalls.allow, b.syscalls.allow);
        return changes ? 1 : 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zaun: %s\n", e.what());
        return 125;
    }
}

}  // namespace zaun
