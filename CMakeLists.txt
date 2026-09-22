cmake_minimum_required(VERSION 3.24)
project(zaun LANGUAGES CXX)

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

add_executable(zaun src/cli/main.cpp src/cli/doctor.cpp)
target_compile_options(zaun PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(zaun PRIVATE
  tomlplusplus::tomlplusplus nlohmann_json::nlohmann_json PkgConfig::SECCOMP)

enable_testing()
include(GoogleTest)
add_executable(unit_tests tests/unit/policy_smoke_test.cpp)
target_link_libraries(unit_tests PRIVATE tomlplusplus::tomlplusplus GTest::gtest_main)
gtest_discover_tests(unit_tests)
