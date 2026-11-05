#include "sandbox/seccomp.h"

#include <errno.h>
#include <sched.h>
#include <seccomp.h>
#include <sys/ioctl.h>

#include <unistd.h>

#include <memory>
#include <system_error>

#include "learn/tracer.h"

namespace zaun {
namespace {

// io_uring runs operations the filter never sees.
const char* const kAlwaysDeny[] = {
    "io_uring_setup", "io_uring_enter", "io_uring_register",
    "bpf", "perf_event_open", "userfaultfd",
    "ptrace", "process_vm_readv", "process_vm_writev",
    "keyctl", "add_key", "request_key",
    "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module",
    "mount", "umount", "umount2", "mount_setattr", "move_mount", "open_tree", "open_tree_attr",
    "fsopen", "fsconfig", "fsmount", "fspick",
    "pivot_root", "unshare", "setns",
};

// Always allowed in allowlist mode. execve starts the target after the filter
// is loaded; clone3 must pass here so the baseline filter's ENOSYS wins.
const char* const kBaseSet[] = {
    "execve", "exit", "exit_group", "rt_sigreturn", "futex", "clone3",
    "clock_gettime", "clock_getres", "clock_nanosleep", "gettimeofday", "nanosleep",
};

// Hand the listener fd to the supervisor; never notified, or the handover would deadlock.
const char* const kHandover[] = {"sendmsg", "close"};

// CLONE_NEWTIME is left out: in clone() that bit is part of the exit signal.
constexpr unsigned long kNamespaceFlags[] = {
    CLONE_NEWNS, CLONE_NEWCGROUP, CLONE_NEWUTS, CLONE_NEWIPC,
    CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNET,
};

// Syscall number on the native architecture, or < 0 if this libseccomp doesn't
// know the name or the architecture lacks the call (e.g. umount on x86_64).
int resolve(const std::string& name) { return seccomp_syscall_resolve_name(name.c_str()); }

// libseccomp returns -errno instead of setting errno.
void check_rc(int rc, const std::string& what) {
    if (rc < 0) throw std::system_error(-rc, std::generic_category(), what);
}

using Filter = std::unique_ptr<void, decltype(&seccomp_release)>;

Filter new_filter(uint32_t default_action) {
    Filter f(seccomp_init(default_action), seccomp_release);
    if (!f) throw std::system_error(ENOMEM, std::generic_category(), "seccomp_init");
    check_rc(seccomp_attr_set(f.get(), SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS),
             "seccomp bad-arch action");
    check_rc(seccomp_attr_set(f.get(), SCMP_FLTATR_CTL_OPTIMIZE, 2), "seccomp binary tree");
    return f;
}

// Always-deny list, clone namespace flags, clone3 and terminal ioctls.
void load_baseline() {
    Filter f = new_filter(SCMP_ACT_ALLOW);
    for (const char* name : kAlwaysDeny) {
        int nr = resolve(name);
        if (nr < 0) continue;
        check_rc(seccomp_rule_add(f.get(), SCMP_ACT_KILL_PROCESS, nr, 0), name);
    }
    // One rule per flag, since "any of these bits set" isn't a single comparison.
    // The flags are argument 0 on x86_64 and aarch64 (s390 swaps them).
    for (unsigned long flag : kNamespaceFlags) {
        scmp_arg_cmp cmp{0, SCMP_CMP_MASKED_EQ, flag, flag};
        check_rc(seccomp_rule_add_array(f.get(), SCMP_ACT_KILL_PROCESS, SCMP_SYS(clone), 1, &cmp),
                 "clone");
    }
    // clone3 hides its flags behind a pointer; glibc falls back to clone on ENOSYS.
    check_rc(seccomp_rule_add(f.get(), SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0), "clone3");
    // The kernel truncates the request to 32 bits, so compare only those.
    for (unsigned long req : {TIOCSTI, TIOCLINUX}) {
        scmp_arg_cmp cmp{1, SCMP_CMP_MASKED_EQ, 0xffffffffUL, req};
        check_rc(seccomp_rule_add_array(f.get(), SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1, &cmp),
                 "ioctl");
    }
    check_rc(seccomp_load(f.get()), "seccomp_load");
}

void allow(const Filter& f, const std::string& name) {
    int nr = resolve(name);
    if (nr < 0) return;
    check_rc(seccomp_rule_add(f.get(), SCMP_ACT_ALLOW, nr, 0), name);
}

// Loads `f` and, with a socket, sends its notification fd to the supervisor.
void load(const Filter& f, int sock) {
    check_rc(seccomp_load(f.get()), "seccomp_load");
    if (sock < 0) return;
    int listener = seccomp_notify_fd(f.get());
    check_rc(listener, "seccomp_notify_fd");
    send_fd(sock, listener);
    close(listener);
    close(sock);
}

// Stacks on the baseline filter; the kernel applies the stricter verdict.
void load_allowlist(const std::vector<std::string>& names, int sock) {
    Filter f = new_filter(sock < 0 ? SCMP_ACT_ERRNO(EPERM) : SCMP_ACT_NOTIFY);
    for (const char* name : kBaseSet) allow(f, name);
    if (sock >= 0) {
        for (const char* name : kHandover) allow(f, name);
    }
    for (const auto& name : names) allow(f, name);
    load(f, sock);
}

// Every call but the handover goes to the supervisor, which lets it run.
void load_tracer(int sock) {
    Filter f = new_filter(SCMP_ACT_NOTIFY);
    for (const char* name : kHandover) allow(f, name);
    load(f, sock);
}

}  // namespace

bool syscall_known(const std::string& name) {
    return resolve(name) >= 0;
}

bool always_denied(const std::string& name) {
    for (const char* denied : kAlwaysDeny) {
        if (name == denied) return true;
    }
    return false;
}

void seccomp_install(const SeccompPlan& plan, bool trace, int sock) {
    load_baseline();
    if (trace) {
        load_tracer(sock);
    } else if (plan.allowlist) {
        load_allowlist(plan.allow, sock);
    }
}

}  // namespace zaun
