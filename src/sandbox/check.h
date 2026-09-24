#pragma once

#include <cerrno>
#include <string>
#include <system_error>

namespace zaun {

// Throws std::system_error carrying errno when `ok` is false.
inline void check(bool ok, const std::string& what) {
    if (!ok) throw std::system_error(errno, std::generic_category(), what);
}

}  // namespace zaun
