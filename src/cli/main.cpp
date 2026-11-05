#include <cstdio>
#include <cstring>

#include "check.h"
#include "doctor.h"
#include "learn.h"
#include "run.h"

int main(int argc, char** argv) {
    static const struct {
        const char* name;
        int (*fn)(int, char**);
    } commands[] = {
        {"run", zaun::run}, {"learn", zaun::learn}, {"check", zaun::check}, {"diff", zaun::diff},
    };
    if (argc >= 2 && std::strcmp(argv[1], "doctor") == 0) return zaun::doctor();
    if (argc >= 2) {
        for (const auto& c : commands) {
            if (std::strcmp(argv[1], c.name) == 0) return c.fn(argc - 2, argv + 2);
        }
    }
    std::fprintf(stderr, "usage: zaun {run|learn|check|diff|doctor} ...\n");
    return 125;  // failed before execve
}
