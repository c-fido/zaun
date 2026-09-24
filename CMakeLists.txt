cmake_minimum_required(VERSION 3.24)
project(zaun LANGUAGES C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "Zaun is Linux-only; build inside the dev VM.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)
FetchContent_Declare(tomlplusplus
  URL https://github.com/marzer/tomlplusplus/archive/refs/tags/v3.4.0.tar.gz)
FetchContent_Declare(nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_Declare(googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz)
FetchContent_MakeAvailable(tomlplusplus nlohmann_json googletest)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SECCOMP REQUIRED IMPORTED_TARGET libseccomp)

add_library(sandbox STATIC src/sandbox/launcher.cpp src/sandbox/init.cpp src/sandbox/fs.cpp)
target_include_directories(sandbox PUBLIC src)
target_compile_options(sandbox PRIVATE -Wall -Wextra -Wpedantic)

add_executable(zaun src/cli/main.cpp src/cli/doctor.cpp src/cli/run.cpp)
target_compile_options(zaun PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(zaun PRIVATE
  sandbox tomlplusplus::tomlplusplus nlohmann_json::nlohmann_json PkgConfig::SECCOMP)

enable_testing()
include(GoogleTest)

add_executable(unit_tests tests/unit/policy_smoke_test.cpp tests/unit/launcher_test.cpp)
target_link_libraries(unit_tests PRIVATE sandbox tomlplusplus::tomlplusplus GTest::gtest_main)
gtest_discover_tests(unit_tests)

# Escape suite: one program per attack, run by tests/escape/run.py.
set(ESCAPE_TESTS FS-1 FS-2 FS-3 FS-4 FS-6 PROC-1 PROC-2 PROC-3 LEAK-1 LEAK-2)
foreach(id IN LISTS ESCAPE_TESTS ITEMS victim)
  add_executable(escape_${id} tests/escape/${id}.c)
  target_compile_definitions(escape_${id} PRIVATE _GNU_SOURCE)
  target_compile_options(escape_${id} PRIVATE -Wall -Wextra)
  set_target_properties(escape_${id} PROPERTIES
    OUTPUT_NAME ${id} RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/escape)
endforeach()
