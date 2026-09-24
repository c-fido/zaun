#pragma once

namespace zaun {

// Clears the bounding, ambient, inheritable, permitted and effective capability
// sets, then sets PR_SET_NO_NEW_PRIVS. Throws std::system_error on failure.
void drop_privileges();

}  // namespace zaun
