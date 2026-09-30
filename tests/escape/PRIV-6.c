// PRIV-6: make a 32-bit system call with int 0x80, which a filter that only
// knows the native ABI would miss. x86_64 only.
#include <unistd.h>

#include "escape.h"

#ifdef __x86_64__
int main(void) {
    long pid;
    __asm__ volatile("int $0x80" : "=a"(pid) : "a"(20) : "memory");  // getpid on i386
    if (pid == getpid()) return escaped("int 0x80 reached the kernel");
    return blocked("int 0x80 failed");
}
#else
int main(void) { return blocked("x86_64 only"); }
#endif
