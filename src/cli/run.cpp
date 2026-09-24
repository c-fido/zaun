#include "run.h"

#include <cstdio>
#include <cstring>
#include <exception>
#include <string>
#include <vector>

#include "sandbox/launcher.h"

namespace zaun {

int run(int argc, char** argv) {
    std::string workdir = ".";
    int i = 0;
    for (; i < argc; ++i) {
        if (std::strcmp(argv[i], "--") == 0) {
            ++i;
            break;
        }
        if (std::strcmp(argv[i], "--workdir") == 0 && i + 1 < argc) {
            workdir = argv[++i];
        } else if (argv[i][0] == '-') {
            std::fprintf(stderr, "zaun run: unknown option %s\n", argv[i]);
            return 125;
        } else {
            break;
        }
    }
    if (i == argc) {
        std::fprintf(stderr, "usage: zaun run [--workdir DIR] -- CMD...\n");
        return 125;
    }

    try {
        return launch(workdir, std::vector<std::string>(argv + i, argv + argc));
    } catch (const std::exception& e) {
        std::fprintf(stderr, "zaun: %s\n", e.what());
        return 125;
    }
}

}  // namespace zaun
