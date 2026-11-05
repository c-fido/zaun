// RES-3: busy loop past the timeout, with a bound so the bare run ends.
#include <time.h>

#include "escape.h"

int main(void) {
    time_t end = time(NULL) + 4;
    while (time(NULL) < end) {
    }
    return escaped("ran 4 s of CPU");
}
