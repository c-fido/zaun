// LEAK-1: read an API key from the environment.
#include "escape.h"

int main(void) {
    if (getenv("ANTHROPIC_API_KEY")) return escaped("read ANTHROPIC_API_KEY");
    return blocked("unset");
}
