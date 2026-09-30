// TTY-1: push a keystroke into the terminal on stdin's input queue, as if typed.
#include <sys/ioctl.h>

#include "escape.h"

int main(void) {
    char c = 'x';
    if (ioctl(0, TIOCSTI, &c) < 0) return blocked_errno(errno);
    return escaped("injected a keystroke");
}
