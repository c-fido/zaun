// FS-5: move a file out of the workdir by hardlink or rename. The destination
// is the workdir's parent; bare, that's a directory on the same filesystem.
#include <fcntl.h>
#include <unistd.h>

#include "escape.h"

#define SRC "fs5-src"
#define DST "../fs5-out"

int main(void) {
    int fd = open(SRC, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return blocked_errno(errno);
    close(fd);

    const char* how = NULL;
    if (link(SRC, DST) == 0) how = "hardlinked a file out of the workdir";
    else if (rename(SRC, DST) == 0) how = "renamed a file out of the workdir";
    int err = errno;
    unlink(SRC);
    unlink(DST);
    return how ? escaped(how) : blocked_errno(err);
}
