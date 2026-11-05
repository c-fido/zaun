// RES-2: allocate and touch more memory than the limit. 1 GiB, not 8, so the
// bare run fits on a small VM.
#include <sys/mman.h>

#include "escape.h"

int main(void) {
    size_t size = 1UL << 30;
    char* p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return blocked_errno(errno);
    for (size_t i = 0; i < size; i += 4096) p[i] = 1;
    return escaped("touched 1 GiB");
}
