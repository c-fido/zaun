#include <cstdio>
#include <cstring>

#include "doctor.h"

// ponytail: stub dispatcher.
int main(int argc, char** argv) {
    static const char* const commands[] = {"run", "learn", "check", "diff"};
    if (argc >= 2 && std::strcmp(argv[1], "doctor") == 0) return zaun::doctor();
    if (argc >= 2) {
        for (const char* cmd : commands) {
            if (std::strcmp(argv[1], cmd) == 0) {
                std::fprintf(stderr, "zaun %s: not implemented yet\n", cmd);
                return 125;
            }
        }
    }
    std::fprintf(stderr, "usage: zaun {run|learn|check|diff|doctor} ...\n");
    return 125;  // failed before execve
}
