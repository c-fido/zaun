#include "learn/generalize.h"

#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <set>
#include <sstream>

#include "policy/compile.h"
#include "sandbox/fs.h"
#include "sandbox/seccomp.h"

namespace fs = std::filesystem;

namespace zaun {
namespace {

// kLink: only a symlink on the way to something else.
enum : unsigned { kR = 1, kW = 2, kX = 4, kStat = 8, kLink = 16 };

struct Entry {
    unsigned access = 0;
    std::set<int> runs;
};

const char* const kCollapsePrefixes[] = {"/usr", "/lib", "/etc/ssl"};
constexpr size_t kCollapseAt = 3;

std::vector<std::string> split(const std::string& path) {
    std::vector<std::string> out;
    std::stringstream ss(path);
    std::string part;
    while (std::getline(ss, part, '/')) {
        if (!part.empty()) out.push_back(part);
    }
    return out;
}

// Resolves `path` on the host like the kernel would, collecting the symlinks
// on the way: the sandbox must recreate them to reach the target.
std::string resolve(const std::string& path, std::vector<std::string>& symlinks) {
    std::vector<std::string> parts = split(path);
    std::deque<std::string> todo(parts.begin(), parts.end());
    std::string cur;  // "" is the root
    for (int budget = 40; !todo.empty();) {
        std::string c = todo.front();
        todo.pop_front();
        if (c == ".") continue;
        if (c == "..") {
            cur = cur.substr(0, cur.rfind('/'));
            continue;
        }
        std::string next = cur + "/" + c;
        std::error_code ec;
        if (!fs::is_symlink(next, ec)) {
            cur = next;
            continue;
        }
        if (--budget == 0) return {};
        symlinks.push_back(next);
        std::string target = fs::read_symlink(next, ec).string();
        if (ec) return {};
        if (!target.empty() && target[0] == '/') cur.clear();
        std::vector<std::string> t = split(target);
        todo.insert(todo.begin(), t.begin(), t.end());
    }
    return cur.empty() ? "/" : cur;
}

// The kernel loads these itself, so the trace never shows them being opened.
std::string interpreter(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY);
    if (fd < 0) return {};
    std::string out;
    struct stat st;
    char buf[256];
    ssize_t n = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) ? pread(fd, buf, sizeof buf, 0) : -1;
    if (n > 2 && buf[0] == '#' && buf[1] == '!') {
        std::string line(buf + 2, n - 2);
        size_t b = line.find_first_not_of(" \t");
        size_t e = line.find_first_of(" \t\n", b);
        if (b != std::string::npos) out = line.substr(b, e - b);
    } else if (n >= static_cast<ssize_t>(sizeof(Elf64_Ehdr)) && std::memcmp(buf, ELFMAG, SELFMAG) == 0 &&
               buf[EI_CLASS] == ELFCLASS64) {  // ponytail: 64-bit ELF only
        Elf64_Ehdr eh;
        std::memcpy(&eh, buf, sizeof eh);
        for (int i = 0; i < eh.e_phnum && out.empty(); ++i) {
            Elf64_Phdr ph;
            auto off = static_cast<off_t>(eh.e_phoff + static_cast<Elf64_Off>(i) * eh.e_phentsize);
            if (pread(fd, &ph, sizeof ph, off) != sizeof ph) break;
            if (ph.p_type != PT_INTERP || ph.p_filesz > 4096) continue;
            std::string s(ph.p_filesz, '\0');
            if (pread(fd, s.data(), s.size(), static_cast<off_t>(ph.p_offset)) == static_cast<ssize_t>(s.size())) {
                out = s.c_str();
            }
        }
    }
    close(fd);
    return out;
}

class Builder {
public:
    Builder(std::string workdir, std::string home) : workdir_(std::move(workdir)), home_(std::move(home)) {}

    void add(const std::string& raw, char access, int run, int depth = 0) {
        std::string path = fs::path(raw).lexically_normal().string();
        if (path.size() > 1 && path.back() == '/') path.pop_back();
        // Before skipping: a binary in the workdir still needs its loader.
        if (access == 'x' && depth < 4 && (contains(workdir_, path) || !sandbox_owned(path))) {
            std::string interp = interpreter(path);
            if (!interp.empty()) add(interp, 'x', run, depth + 1);
        }
        if (skipped(path, access)) return;
        std::vector<std::string> symlinks;
        std::string real = resolve(path, symlinks);
        std::error_code ec;
        if (real.empty() || !fs::exists(real, ec) || skipped(real, access)) return;
        for (const auto& s : symlinks) {
            if (!skipped(s, 'r')) record(s, kR | kLink, run);
        }
        unsigned bits = access == 'x' ? kX : access == 'w' ? kW : access == 's' ? kStat : kR;
        record(real, bits, run);
    }

    void syscall(const std::string& name, int run) {
        if (!always_denied(name) && syscall_known(name)) syscalls_[name].insert(run);
    }

    Learned finish(int runs) {
        Learned out;
        out.runs = runs;
        drop_directories(out.warnings);
        collapse(out.warnings);

        Policy& p = out.policy;
        p.name = "learned";
        p.workdir_writable = workdir_written_;
        p.learned_from = runs;
        p.syscalls.allowlist = true;
        for (const auto& [path, e] : paths_) {
            int seen = static_cast<int>(e.runs.size());
            // Symlinks are still listed: the sandbox must recreate them.
            if (e.access & kW) {
                p.write.push_back(path);
                out.support["write " + path] = seen;
                out.warnings.push_back("write access outside the workdir: " + path);
            }
            if (e.access & kX) {
                p.exec.push_back(path);
                out.support["exec " + path] = seen;
            }
            if (!(e.access & (kW | kX))) {
                p.read.push_back(path);
                out.support["read " + path] = seen;
            }
        }
        for (const auto& [name, rs] : syscalls_) {
            p.syscalls.allow.push_back(name);
            out.support["syscall " + name] = static_cast<int>(rs.size());
        }
        return out;
    }

private:
    // True for paths a rule never needs: the sandbox provides them, or they're the workdir's.
    bool skipped(const std::string& path, char access) {
        // First: the workdir may sit under /tmp.
        if (contains(workdir_, path)) {
            workdir_written_ = workdir_written_ || access == 'w';
            return true;
        }
        return sandbox_owned(path);
    }

    static bool sandbox_owned(const std::string& path) {
        for (const char* owned : kSandboxPaths) {
            if (contains(owned, path)) return true;
        }
        return false;
    }

    void record(const std::string& path, unsigned bits, int run) {
        Entry& e = paths_[path];
        e.access |= bits;
        e.runs.insert(run);
    }

    // Stat-only directories exist anyway as parents of other rules. Listing /, /etc,
    // $HOME or the workdir's ancestors would expose far more than was used.
    void drop_directories(std::vector<std::string>& warnings) {
        for (auto it = paths_.begin(); it != paths_.end();) {
            const std::string& path = it->first;
            std::error_code ec;
            bool dir = fs::is_directory(path, ec);
            bool broad = path == "/" || path == "/etc" || contains(path, home_) || contains(path, workdir_);
            if (dir && broad && (it->second.access & ~kStat)) {
                warnings.push_back("not granted: listing " + path);
            }
            if (dir && (broad || !(it->second.access & ~kStat))) {
                it = paths_.erase(it);
            } else {
                unsigned& a = it->second.access;
                a = (a & ~kStat) ? a & ~kStat : kR;
                ++it;
            }
        }
    }

    static bool collapsible(const std::string& dir) {
        for (const char* prefix : kCollapsePrefixes) {
            if (contains(prefix, dir)) return true;
        }
        return false;
    }

    // Repeats until no directory under a prefix has kCollapseAt entries.
    void collapse(std::vector<std::string>& warnings) {
        std::set<std::string> warned;
        for (bool changed = true; changed;) {
            changed = false;
            std::map<std::string, size_t> children;
            std::map<std::string, size_t> files;  // not counting symlinks, for the warning
            for (const auto& [path, e] : paths_) {
                if (path == "/") continue;
                std::string dir = fs::path(path).parent_path().string();
                ++children[dir];
                if (!(e.access & kLink)) ++files[dir];
            }
            for (const auto& [dir, count] : children) {
                if (count < kCollapseAt) continue;
                if (!collapsible(dir)) {
                    if ((dir == "/" || dir == "/etc" || dir == home_) && files[dir] >= kCollapseAt &&
                        warned.insert(dir).second) {
                        warnings.push_back(std::to_string(files[dir]) + " files in " + dir +
                                           " kept as single-file rules");
                    }
                    continue;
                }
                Entry merged = paths_[dir];
                for (auto it = paths_.begin(); it != paths_.end();) {
                    if (it->first != dir && contains(dir, it->first)) {
                        merged.access |= it->second.access;
                        merged.runs.insert(it->second.runs.begin(), it->second.runs.end());
                        it = paths_.erase(it);
                    } else {
                        ++it;
                    }
                }
                paths_[dir] = merged;
                changed = true;
                break;
            }
        }
    }

    std::string workdir_;
    std::string home_;
    bool workdir_written_ = false;
    std::map<std::string, Entry> paths_;
    std::map<std::string, std::set<int>> syscalls_;
};

std::string quote(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 0x20 || c == 0x7f) {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\u%04x", c);
            out += buf;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out + "\"";
}

void write_list(std::ostream& out, const char* key, const std::vector<std::string>& items,
                const Learned& l, const std::string& kind) {
    out << key << " = [";
    if (items.empty()) {
        out << "]\n";
        return;
    }
    out << "\n";
    for (const auto& item : items) {
        out << "  " << quote(item) << ",";
        auto it = l.support.find(kind + " " + item);
        if (it != l.support.end() && it->second < l.runs) {
            out << "  # seen in " << it->second << "/" << l.runs << " runs";
        }
        out << "\n";
    }
    out << "]\n";
}

}  // namespace

Learned generalize(const std::vector<Trace>& runs, const std::string& workdir, const std::string& home) {
    Builder b(workdir, home);
    for (size_t i = 0; i < runs.size(); ++i) {
        for (const auto& [key, count] : runs[i]) {
            const auto& [syscall, access, path] = key;
            b.syscall(syscall, static_cast<int>(i));
            if (!path.empty()) b.add(path, access, static_cast<int>(i));
        }
    }
    return b.finish(static_cast<int>(runs.size()));
}

std::string to_toml(const Learned& l) {
    const Policy& p = l.policy;
    std::ostringstream out;
    out << "# Learned by `zaun learn` from " << l.runs << (l.runs == 1 ? " run" : " runs")
        << ". Review before use.\n";
    for (const auto& w : l.warnings) out << "# warning: " << w << "\n";
    out << "version = 1\nname = " << quote(p.name) << "\n\n";
    out << "[workdir]\nmode = " << (p.workdir_writable ? "\"rw\"" : "\"ro\"") << "\n\n";
    out << "[filesystem]\n";
    write_list(out, "read", p.read, l, "read");
    write_list(out, "write", p.write, l, "write");
    write_list(out, "exec", p.exec, l, "exec");
    out << "\n[network]\nmode = \"none\"\n";
    const Limits& lim = p.limits;
    if (lim.memory || lim.pids || lim.cpu > 0 || lim.timeout.count()) {
        out << "\n[limits]\n";
        if (lim.memory) out << "memory = " << lim.memory << "\n";
        if (lim.pids) out << "pids = " << lim.pids << "\n";
        if (lim.cpu > 0) out << "cpu = " << lim.cpu << "\n";
        if (lim.timeout.count()) out << "timeout = \"" << lim.timeout.count() << "ms\"\n";
    }
    out << "\n[syscalls]\nmode = \"allowlist\"\n";
    write_list(out, "allow", p.syscalls.allow, l, "syscall");
    out << "\n[meta]\nlearned_from = " << l.runs << "\n";
    return out.str();
}

}  // namespace zaun
