// PRIV-2: enter a new user namespace, which grants a full capability set inside it.
#include <sched.h>

#include "escape.h"

int main(void) {
    if (unshare(CLONE_NEWUSER) < 0) return blocked_errno(errno);
    return escaped("entered a new user namespace");
}
