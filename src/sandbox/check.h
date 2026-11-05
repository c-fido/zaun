#pragma once

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <string>
#include <system_error>

namespace zaun {

// Throws std::system_error carrying errno when `ok` is false.
inline void check(bool ok, const std::string& what) {
    if (!ok) throw std::system_error(errno, std::generic_category(), what);
}

// Writes `s` to an existing file, such as a /proc or cgroup control file.
inline void write_file(const std::string& path, const std::string& s) {
    int fd = open(path.c_str(), O_WRONLY | O_CLOEXEC);
    check(fd >= 0, path);
    bool ok = write(fd, s.data(), s.size()) == static_cast<ssize_t>(s.size());
    int err = errno;
    close(fd);
    errno = err;
    check(ok, path);
}

}  // namespace zaun
