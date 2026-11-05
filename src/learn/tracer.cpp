#include "learn/tracer.h"

#include <fcntl.h>
#include <limits.h>
#include <seccomp.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <system_error>
#include <unordered_map>
#include <vector>

#include "sandbox/check.h"

namespace zaun {
namespace {

// A path argument: its index, and the index of the dirfd it is relative to (-1: cwd).
struct PathArg {
    int path;
    int dirfd;
};

// How a syscall touches its path arguments. 'o' means open-style: the flags
// argument (`flags`) decides read or write; 'h' is openat2's open_how pointer.
struct Spec {
    char access;
    std::vector<PathArg> args;
    int flags = -1;
};

const std::unordered_map<int, Spec>& specs() {
    static const std::unordered_map<int, Spec> table = [] {
        const std::pair<const char*, Spec> named[] = {
            {"open", {'o', {{0, -1}}, 1}},
            {"openat", {'o', {{1, 0}}, 2}},
            {"openat2", {'h', {{1, 0}}, 2}},
            {"creat", {'w', {{0, -1}}}},
            {"execve", {'x', {{0, -1}}}},
            {"execveat", {'x', {{1, 0}}}},
            {"stat", {'s', {{0, -1}}}},
            {"lstat", {'s', {{0, -1}}}},
            {"access", {'s', {{0, -1}}}},
            {"readlink", {'s', {{0, -1}}}},
            {"newfstatat", {'s', {{1, 0}}}},
            {"fstatat64", {'s', {{1, 0}}}},
            {"statx", {'s', {{1, 0}}}},
            {"faccessat", {'s', {{1, 0}}}},
            {"faccessat2", {'s', {{1, 0}}}},
            {"readlinkat", {'s', {{1, 0}}}},
            {"chdir", {'r', {{0, -1}}}},
            {"mkdir", {'w', {{0, -1}}}},
            {"mkdirat", {'w', {{1, 0}}}},
            {"rmdir", {'w', {{0, -1}}}},
            {"unlink", {'w', {{0, -1}}}},
            {"unlinkat", {'w', {{1, 0}}}},
            {"truncate", {'w', {{0, -1}}}},
            {"chmod", {'w', {{0, -1}}}},
            {"fchmodat", {'w', {{1, 0}}}},
            {"fchmodat2", {'w', {{1, 0}}}},
            {"utimensat", {'w', {{1, 0}}}},
            {"rename", {'w', {{0, -1}, {1, -1}}}},
            {"renameat", {'w', {{1, 0}, {3, 2}}}},
            {"renameat2", {'w', {{1, 0}, {3, 2}}}},
            {"link", {'w', {{0, -1}, {1, -1}}}},
            {"linkat", {'w', {{1, 0}, {3, 2}}}},
            {"symlink", {'w', {{1, -1}}}},
            {"symlinkat", {'w', {{2, 1}}}},
        };
        std::unordered_map<int, Spec> t;
        for (const auto& [name, spec] : named) {
            int nr = seccomp_syscall_resolve_name(name);
            if (nr >= 0) t.emplace(nr, spec);
        }
        return t;
    }();
    return table;
}

// Reads `size` bytes at `addr` in `pid`; false if any of it is unmapped.
bool read_memory(pid_t pid, uint64_t addr, void* buf, size_t size) {
    iovec local{buf, size};
    iovec remote{reinterpret_cast<void*>(addr), size};  // NOLINT(performance-no-int-to-ptr): remote address
    return process_vm_readv(pid, &local, 1, &remote, 1, 0) == static_cast<ssize_t>(size);
}

// Reads the NUL-terminated string at `addr` in `pid`; false if it faults or is too long.
bool read_string(pid_t pid, uint64_t addr, std::string& out) {
    constexpr size_t kChunk = 256;  // aligned chunks never straddle a page
    char buf[kChunk];
    out.clear();
    while (out.size() < PATH_MAX) {
        size_t n = kChunk - addr % kChunk;
        if (!read_memory(pid, addr, buf, n)) return false;
        if (const void* nul = std::memchr(buf, '\0', n)) {
            out.append(buf, static_cast<const char*>(nul) - buf);
            return true;
        }
        out.append(buf, n);
        addr += n;
    }
    return false;
}

std::string readlink_str(const std::string& path) {
    char buf[PATH_MAX];
    ssize_t n = readlink(path.c_str(), buf, sizeof buf);
    return n > 0 ? std::string(buf, n) : std::string();
}

// `path` made absolute against `dirfd` of `pid`, as the caller sees it; empty if unknown.
std::string absolute(pid_t pid, int dirfd, const std::string& path) {
    if (!path.empty() && path[0] == '/') return std::filesystem::path(path).lexically_normal().string();
    std::string proc = "/proc/" + std::to_string(pid);
    std::string base = readlink_str(dirfd == AT_FDCWD ? proc + "/cwd" : proc + "/fd/" + std::to_string(dirfd));
    if (base.empty() || base[0] != '/') return {};  // pipes, sockets, anon inodes
    if (path.empty()) return base;
    return (std::filesystem::path(base) / path).lexically_normal().string();
}

char open_access(uint64_t flags) {
    return flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC) ? 'w' : 'r';
}

// A notification and its response buffer, sized for this kernel.
struct NotifyBuffers {
    seccomp_notif* req = nullptr;
    seccomp_notif_resp* resp = nullptr;
    NotifyBuffers() {
        if (seccomp_notify_alloc(&req, &resp) < 0) {
            throw std::system_error(ENOMEM, std::generic_category(), "seccomp_notify_alloc");
        }
    }
    ~NotifyBuffers() { seccomp_notify_free(req, resp); }
    NotifyBuffers(const NotifyBuffers&) = delete;
    NotifyBuffers& operator=(const NotifyBuffers&) = delete;
};

}  // namespace

void send_fd(int sock, int fd) {
    char data = 0;
    iovec iov{&data, 1};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))] = {};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof control;
    cmsghdr* c = CMSG_FIRSTHDR(&msg);
    c->cmsg_level = SOL_SOCKET;
    c->cmsg_type = SCM_RIGHTS;
    c->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(c), &fd, sizeof fd);
    check(sendmsg(sock, &msg, 0) == 1, "send listener fd");
}

int recv_fd(int sock) {
    char data;
    iovec iov{&data, 1};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))] = {};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof control;
    ssize_t n;
    do {
        n = recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
    } while (n < 0 && errno == EINTR);
    check(n >= 0, "receive listener fd");
    cmsghdr* c = CMSG_FIRSTHDR(&msg);
    if (n == 0 || !c || c->cmsg_type != SCM_RIGHTS) return -1;
    int fd;
    std::memcpy(&fd, CMSG_DATA(c), sizeof fd);
    return fd;
}

void handle_notification(int listener, bool trace, Trace& out) {
    static NotifyBuffers buf;  // reused: one supervisor thread
    seccomp_notif* req = buf.req;
    seccomp_notif_resp* resp = buf.resp;
    std::memset(req, 0, sizeof *req);  // the kernel wants it zeroed
    std::memset(resp, 0, sizeof *resp);
    // ENOENT: the caller died before we read it.
    if (seccomp_notify_receive(listener, req) < 0) return;

    std::unique_ptr<char, decltype(&std::free)> name(
        seccomp_syscall_resolve_num_arch(req->data.arch, req->data.nr), std::free);
    std::string syscall = name ? name.get() : "syscall_" + std::to_string(req->data.nr);

    const auto pid = static_cast<pid_t>(req->pid);
    std::vector<std::pair<char, std::string>> events;
    auto spec = specs().find(req->data.nr);
    if (trace && spec != specs().end()) {
        const Spec& s = spec->second;
        const __u64* a = req->data.args;
        char access = s.access;
        if (access == 'o') access = open_access(a[s.flags]);
        uint64_t how_flags;
        if (access == 'h') access = read_memory(pid, a[s.flags], &how_flags, sizeof how_flags) ? open_access(how_flags) : 'r';
        for (const PathArg& p : s.args) {
            std::string raw;
            if (a[p.path] == 0 || !read_string(pid, a[p.path], raw)) continue;
            int dirfd = p.dirfd < 0 ? AT_FDCWD : static_cast<int>(a[p.dirfd]);
            std::string path = absolute(pid, dirfd, raw);
            if (!path.empty()) events.emplace_back(access, path);
        }
    }
    // Only log what we read while the caller was still blocked on this call.
    if (seccomp_notify_id_valid(listener, req->id) == 0) {
        if (events.empty()) ++out[{syscall, '-', ""}];
        for (const auto& [access, path] : events) ++out[{syscall, access, path}];
    }

    resp->id = req->id;
    if (trace) {
        resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    } else {
        resp->error = -EPERM;
    }
    seccomp_notify_respond(listener, resp);  // ENOENT if the caller died meanwhile
}

void write_traces(std::ostream& out, const std::vector<Trace>& runs) {
    out << "run\tsyscall\taccess\tpath\tcount\n";
    for (size_t run = 0; run < runs.size(); ++run) {
        for (const auto& [key, count] : runs[run]) {
            const auto& [syscall, access, path] = key;
            out << run + 1 << '\t' << syscall << '\t' << access << '\t';
            // Paths come from the sandbox; keep one event per line.
            for (char c : path) {
                if (c == '\\' || c == '\t' || c == '\n') {
                    out << '\\' << (c == '\t' ? 't' : c == '\n' ? 'n' : '\\');
                } else {
                    out << c;
                }
            }
            out << '\t' << count << '\n';
        }
    }
}

}  // namespace zaun
