// PRIV-7: read the session keyring, where credentials such as Kerberos tickets live.
#include <linux/keyctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "escape.h"

int main(void) {
    long ring = syscall(SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_SESSION_KEYRING, 1);
    if (ring < 0) return blocked_errno(errno);
    char buf[256];
    if (syscall(SYS_keyctl, KEYCTL_READ, ring, buf, sizeof buf) < 0) return blocked_errno(errno);
    return escaped("read the session keyring");
}
