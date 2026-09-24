// FS-2: reach /etc/shadow. Bare, DAC still refuses the read, so reaching the
// file (EACCES) counts as escaped; the sandbox must not have it at all.
#include <fcntl.h>
#include <unistd.h>

#include "escape.h"

int main(void) {
    int fd = open("/etc/shadow", O_RDONLY);
    if (fd >= 0) return escaped("read /etc/shadow");
    if (errno == EACCES) return escaped("/etc/shadow is visible (DAC denies the read)");
    return blocked_errno(errno);
}
