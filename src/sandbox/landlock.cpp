#include "sandbox/landlock.h"

#include <fcntl.h>
#include <linux/landlock.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>

#include "sandbox/check.h"

// Added in Linux 6.10 (ABI 5); older headers lack it.
#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

namespace zaun {
namespace {

constexpr uint64_t kFileRights = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                                 LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
                                 LANDLOCK_ACCESS_FS_IOCTL_DEV;

// MAKE_CHAR and MAKE_BLOCK are handled but never granted.
uint64_t fs_rights(unsigned access) {
    uint64_t r = 0;
    if (access & kRead) r |= LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    if (access & kWrite) {
        r |= LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
             LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR |
             LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
             LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_SYM |
             LANDLOCK_ACCESS_FS_TRUNCATE | LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    if (access & kExec) r |= LANDLOCK_ACCESS_FS_EXECUTE;
    if (access & kRefer) r |= LANDLOCK_ACCESS_FS_REFER;
    return r;
}

// Rights this ABI can enforce, among those Zaun uses. Without REFER (ABI 1)
// cross-directory renames and links are always denied.
uint64_t handled_rights(int abi) {
    uint64_t r = (LANDLOCK_ACCESS_FS_MAKE_SYM << 1) - 1;
    if (abi >= 2) r |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3) r |= LANDLOCK_ACCESS_FS_TRUNCATE;
    if (abi >= 5) r |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    return r;
}

}  // namespace

int landlock_abi() {
    return static_cast<int>(
        syscall(SYS_landlock_create_ruleset, nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION));
}

void landlock_restrict(const std::vector<PathRule>& rules) {
    int abi = landlock_abi();
    if (abi < 1) {
        std::fprintf(stderr, "zaun: warning: Landlock unavailable; only mounts isolate the filesystem\n");
        return;
    }
    if (abi < 5) {
        std::fprintf(stderr, "zaun: warning: Landlock ABI %d does not restrict %s\n", abi,
                     abi < 3 ? "truncate or device ioctls" : "device ioctls");
    }
    uint64_t handled = handled_rights(abi);

    landlock_ruleset_attr attr{};
    attr.handled_access_fs = handled;
    int ruleset = static_cast<int>(syscall(SYS_landlock_create_ruleset, &attr, sizeof attr, 0));
    check(ruleset >= 0, "landlock_create_ruleset");

    // Fds leak on throw; the caller exits right after.
    for (const auto& rule : rules) {
        int fd = open(rule.path.c_str(), O_PATH | O_CLOEXEC);
        if (fd < 0) {
            check(errno == ENOENT, "open " + rule.path);
            continue;
        }
        struct stat st;
        check(fstat(fd, &st) == 0, "stat " + rule.path);
        landlock_path_beneath_attr beneath{};
        beneath.allowed_access = fs_rights(rule.access) & handled;
        if (!S_ISDIR(st.st_mode)) beneath.allowed_access &= kFileRights;
        beneath.parent_fd = fd;
        if (beneath.allowed_access) {
            check(syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &beneath, 0) == 0,
                  "landlock rule " + rule.path);
        }
        close(fd);
    }
    check(syscall(SYS_landlock_restrict_self, ruleset, 0) == 0, "landlock_restrict_self");
    close(ruleset);
}

}  // namespace zaun
