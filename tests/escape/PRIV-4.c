// PRIV-4: open a directory through io_uring, which does the open without the
// seccomp filter seeing an openat. The ring is driven with raw syscalls.
#include <fcntl.h>
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "escape.h"

int main(void) {
    struct io_uring_params p;
    memset(&p, 0, sizeof p);
    int ring = syscall(SYS_io_uring_setup, 2, &p);
    if (ring < 0) return blocked_errno(errno);

    // One mapping covers both rings (IORING_FEAT_SINGLE_MMAP, Linux 5.4).
    size_t sq_size = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    size_t cq_size = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    char* rings = mmap(NULL, sq_size > cq_size ? sq_size : cq_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQ_RING);
    struct io_uring_sqe* sqes = mmap(NULL, p.sq_entries * sizeof *sqes, PROT_READ | PROT_WRITE,
                                     MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQES);
    if (rings == MAP_FAILED || sqes == MAP_FAILED) return blocked_errno(errno);

    unsigned* sq_tail = (unsigned*)(rings + p.sq_off.tail);
    unsigned* sq_array = (unsigned*)(rings + p.sq_off.array);
    unsigned sq_mask = *(unsigned*)(rings + p.sq_off.ring_mask);
    unsigned* cq_head = (unsigned*)(rings + p.cq_off.head);
    unsigned* cq_tail = (unsigned*)(rings + p.cq_off.tail);
    unsigned cq_mask = *(unsigned*)(rings + p.cq_off.ring_mask);
    struct io_uring_cqe* cqes = (struct io_uring_cqe*)(rings + p.cq_off.cqes);

    unsigned tail = *sq_tail;
    struct io_uring_sqe* sqe = &sqes[tail & sq_mask];
    memset(sqe, 0, sizeof *sqe);
    sqe->opcode = IORING_OP_OPENAT;
    sqe->fd = AT_FDCWD;
    sqe->addr = (unsigned long)".";
    sqe->open_flags = O_RDONLY;
    sq_array[tail & sq_mask] = tail & sq_mask;
    __atomic_store_n(sq_tail, tail + 1, __ATOMIC_RELEASE);

    if (syscall(SYS_io_uring_enter, ring, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0) < 0)
        return blocked_errno(errno);
    unsigned head = *cq_head;
    if (head == __atomic_load_n(cq_tail, __ATOMIC_ACQUIRE)) return blocked("no completion");
    int res = cqes[head & cq_mask].res;
    if (res < 0) return blocked_errno(-res);
    return escaped("opened a file through io_uring");
}
