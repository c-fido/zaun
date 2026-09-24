// Shared protocol for escape tests. A test prints one line and exits:
//   "escaped: <detail>", exit 0 - the attack worked
//   "blocked: <reason>", exit 1 - it failed; <reason> is compared with the sidecar
//   usage error, exit 2
#pragma once

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline int escaped(const char* detail) {
    printf("escaped: %s\n", detail);
    return 0;
}

static inline int blocked(const char* reason) {
    printf("blocked: %s\n", reason);
    return 1;
}

static inline int blocked_errno(int err) { return blocked(strerrorname_np(err)); }

static inline const char* arg(int argc, char** argv, int i) {
    if (i >= argc) {
        fprintf(stderr, "%s: missing argument %d\n", argv[0], i);
        exit(2);
    }
    return argv[i];
}
