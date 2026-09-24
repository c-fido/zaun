#include "sandbox/caps.h"

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>

#include "sandbox/check.h"

namespace zaun {

void drop_privileges() {
    // Bounding set first: dropping it needs CAP_SETPCAP, which capset removes.
    // EINVAL marks the first capability this kernel doesn't know.
    for (int cap = 0;; ++cap) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0) {
            check(errno == EINVAL, "drop bounding capability " + std::to_string(cap));
            break;
        }
    }
    check(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) == 0, "clear ambient caps");

    __user_cap_header_struct header{_LINUX_CAPABILITY_VERSION_3, 0};
    __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {};
    check(syscall(SYS_capset, &header, data) == 0, "capset");

    check(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "PR_SET_NO_NEW_PRIVS");
}

}  // namespace zaun
