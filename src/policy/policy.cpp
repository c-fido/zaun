#include "policy/policy.h"

#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <sstream>
#include <string_view>
#include <toml++/toml.hpp>

namespace zaun {
namespace {

// Walks one parsed file; every error names the file, line and dotted key.
class Reader {
public:
    explicit Reader(std::string source) : source_(std::move(source)) {}

    [[noreturn]] void fail(const toml::node& at, const std::string& key, const std::string& msg) const {
        std::string where = source_;
        if (at.source().begin) where += ":" + std::to_string(at.source().begin.line);
        throw PolicyError(where + ": " + key + ": " + msg);
    }

    void only_keys(const toml::table& t, const std::string& prefix,
                   std::initializer_list<std::string_view> allowed) const {
        for (const auto& [k, v] : t) {
            bool known = false;
            for (auto a : allowed) known = known || k.str() == a;
            if (!known) fail(v, prefix + std::string(k.str()), "unknown key");
        }
    }

    // The node as a toml::table, toml::array or toml::value<T>.
    template <typename T>
    const auto& as(const toml::node& n, const std::string& key, const char* what) const {
        if (const auto* v = n.as<T>()) return *v;
        fail(n, key, std::string("expected ") + what);
    }

    const std::string& string(const toml::node& n, const std::string& key) const {
        return as<std::string>(n, key, "a string").get();
    }

    int64_t positive(const toml::node& n, const std::string& key) const {
        int64_t v = as<int64_t>(n, key, "a positive integer").get();
        if (v <= 0) fail(n, key, "expected a positive integer");
        return v;
    }

    std::vector<std::string> strings(const toml::node& n, const std::string& key) const {
        std::vector<std::string> out;
        const auto& arr = as<toml::array>(n, key, "an array of strings");
        for (size_t i = 0; i < arr.size(); ++i) {
            out.push_back(string(arr[i], key + "[" + std::to_string(i) + "]"));
        }
        return out;
    }

    // Absolute, without "..", "." or trailing slashes.
    std::vector<std::string> paths(const toml::node& n, const std::string& key) const {
        std::vector<std::string> out = strings(n, key);
        const auto& arr = *n.as_array();
        for (size_t i = 0; i < out.size(); ++i) {
            std::string& p = out[i];
            if (p.empty() || p[0] != '/' || p.find('\0') != std::string::npos) {
                fail(arr[i], key + "[" + std::to_string(i) + "]", "expected an absolute path");
            }
            p = std::filesystem::path(p).lexically_normal().string();
            if (p.size() > 1 && p.back() == '/') p.pop_back();
        }
        return out;
    }

    // "512M" (K, M, G, T are powers of 1024) or an integer number of bytes.
    uint64_t size(const toml::node& n, const std::string& key) const {
        if (n.is_integer()) return static_cast<uint64_t>(positive(n, key));
        const std::string& s = as<std::string>(n, key, "a size like \"512M\"").get();
        size_t digits = 0;
        while (digits < s.size() && std::isdigit(static_cast<unsigned char>(s[digits]))) ++digits;
        std::string_view unit = std::string_view(s).substr(digits);
        static const std::pair<std::string_view, int> kUnits[] = {
            {"", 0}, {"K", 10}, {"M", 20}, {"G", 30}, {"T", 40}};
        for (const auto& [name, shift] : kUnits) {
            if (digits == 0 || unit != name || digits > 15) continue;
            uint64_t v = std::stoull(s.substr(0, digits));
            if (v > 0 && v <= (std::numeric_limits<uint64_t>::max() >> shift)) return v << shift;
        }
        fail(n, key, "expected a size like \"512M\"");
    }

    // "60s" (ms, s, m, h) or an integer number of seconds.
    std::chrono::milliseconds duration(const toml::node& n, const std::string& key) const {
        using std::chrono::milliseconds;
        if (n.is_integer()) {
            int64_t v = positive(n, key);
            if (v > 1'000'000'000) fail(n, key, "too long");
            return milliseconds(v * 1000);
        }
        const std::string& s = as<std::string>(n, key, "a duration like \"60s\"").get();
        size_t digits = 0;
        while (digits < s.size() && std::isdigit(static_cast<unsigned char>(s[digits]))) ++digits;
        std::string_view unit = std::string_view(s).substr(digits);
        static const std::pair<std::string_view, int64_t> kUnits[] = {
            {"ms", 1}, {"s", 1000}, {"m", 60'000}, {"h", 3'600'000}};
        for (const auto& [name, scale] : kUnits) {
            if (digits == 0 || unit != name || digits > 9) continue;
            int64_t v = std::stoll(s.substr(0, digits));
            if (v > 0) return milliseconds(v * scale);
        }
        fail(n, key, "expected a duration like \"60s\"");
    }

    // A table under `key`, or nullptr if absent.
    const toml::table* table(const toml::table& parent, std::string_view key) const {
        const toml::node* n = parent.get(key);
        return n ? &as<toml::table>(*n, std::string(key), "a table") : nullptr;
    }

private:
    std::string source_;
};

bool env_name(const std::string& s) {
    if (s.empty() || std::isdigit(static_cast<unsigned char>(s[0]))) return false;
    for (char c : s) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') return false;
    }
    return true;
}

}  // namespace

Policy parse_policy(const std::string& text, const std::string& source) {
    toml::table root;
    try {
        root = toml::parse(text, source);
    } catch (const toml::parse_error& e) {
        throw PolicyError(source + ":" + std::to_string(e.source().begin.line) + ": " +
                          std::string(e.description()));
    }

    Reader r(source);
    Policy p;
    r.only_keys(root, "",
                {"version", "name", "workdir", "filesystem", "network", "env", "limits", "syscalls",
                 "meta"});

    const toml::node* version = root.get("version");
    if (!version) throw PolicyError(source + ": version: required");
    if (r.as<int64_t>(*version, "version", "an integer").get() != 1) {
        r.fail(*version, "version", "unsupported version (want 1)");
    }
    if (const toml::node* n = root.get("name")) p.name = r.string(*n, "name");

    if (const toml::table* t = r.table(root, "workdir")) {
        r.only_keys(*t, "workdir.", {"path", "mode"});
        if (const toml::node* n = t->get("path")) p.workdir = r.string(*n, "workdir.path");
        if (const toml::node* n = t->get("mode")) {
            const std::string& mode = r.string(*n, "workdir.mode");
            if (mode != "rw" && mode != "ro") r.fail(*n, "workdir.mode", "expected \"rw\" or \"ro\"");
            p.workdir_writable = mode == "rw";
        }
    }

    if (const toml::table* t = r.table(root, "filesystem")) {
        r.only_keys(*t, "filesystem.", {"read", "write", "exec"});
        if (const toml::node* n = t->get("read")) p.read = r.paths(*n, "filesystem.read");
        if (const toml::node* n = t->get("write")) p.write = r.paths(*n, "filesystem.write");
        if (const toml::node* n = t->get("exec")) p.exec = r.paths(*n, "filesystem.exec");
    }

    if (const toml::table* t = r.table(root, "network")) {
        r.only_keys(*t, "network.", {"mode"});
        if (const toml::node* n = t->get("mode")) {
            if (r.string(*n, "network.mode") != "none") {
                r.fail(*n, "network.mode", "only \"none\" is supported");
            }
        }
    }

    if (const toml::table* t = r.table(root, "env")) {
        r.only_keys(*t, "env.", {"keep"});
        if (const toml::node* n = t->get("keep")) {
            p.env = r.strings(*n, "env.keep");
            for (size_t i = 0; i < p.env.size(); ++i) {
                std::string key = "env.keep[" + std::to_string(i) + "]";
                if (!env_name(p.env[i])) r.fail((*n->as_array())[i], key, "not a variable name");
                if (p.env[i] == "HOME") r.fail((*n->as_array())[i], key, "HOME is always the workdir");
            }
        }
    }

    if (const toml::table* t = r.table(root, "limits")) {
        r.only_keys(*t, "limits.", {"memory", "pids", "cpu", "timeout"});
        if (const toml::node* n = t->get("memory")) p.limits.memory = r.size(*n, "limits.memory");
        if (const toml::node* n = t->get("pids")) p.limits.pids = r.positive(*n, "limits.pids");
        if (const toml::node* n = t->get("cpu")) {
            auto cpu = n->value<double>();  // integers convert too
            if (!cpu || !(*cpu > 0 && *cpu <= 4096)) r.fail(*n, "limits.cpu", "expected a positive number");
            p.limits.cpu = *cpu;
        }
        if (const toml::node* n = t->get("timeout")) p.limits.timeout = r.duration(*n, "limits.timeout");
    }

    if (const toml::table* t = r.table(root, "syscalls")) {
        r.only_keys(*t, "syscalls.", {"mode", "allow"});
        if (const toml::node* n = t->get("mode")) {
            const std::string& mode = r.string(*n, "syscalls.mode");
            if (mode != "baseline" && mode != "allowlist") {
                r.fail(*n, "syscalls.mode", "expected \"baseline\" or \"allowlist\"");
            }
            p.syscalls.allowlist = mode == "allowlist";
        }
        const toml::node* allow = t->get("allow");
        if (allow && !p.syscalls.allowlist) r.fail(*allow, "syscalls.allow", "needs mode = \"allowlist\"");
        if (!allow && p.syscalls.allowlist) {
            r.fail(*t->get("mode"), "syscalls.allow", "required when mode = \"allowlist\"");
        }
        if (allow) p.syscalls.allow = r.strings(*allow, "syscalls.allow");
    }

    if (const toml::table* t = r.table(root, "meta")) {
        r.only_keys(*t, "meta.", {"learned_from"});
        if (const toml::node* n = t->get("learned_from")) {
            int64_t runs = r.positive(*n, "meta.learned_from");
            if (runs > 1000) r.fail(*n, "meta.learned_from", "too large");
            p.learned_from = static_cast<int>(runs);
        }
    }
    return p;
}

Policy load_policy(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw PolicyError(path + ": cannot open");
    std::stringstream ss;
    ss << in.rdbuf();
    if (in.bad()) throw PolicyError(path + ": read failed");
    return parse_policy(ss.str(), path);
}

}  // namespace zaun
