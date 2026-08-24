cmake_minimum_required(VERSION 3.16)

# Plain semver in CMake; the alpha pre-release spelling lives in vcpkg.json /
# conanfile.py / README per the packaging conventions.
project(axiam_cpp_sdk VERSION 1.0.0 LANGUAGES CXX)

# C++17 is the DECLARED FLOOR: the standard the SDK promises to compile under, and
# what every consumer inherits by default. It is deliberately not the newest —
# raising it would exclude long-lived-distro toolchains for nothing the SDK needs.
#
# Overridable from the command line (`-DCMAKE_CXX_STANDARD=23`) rather than
# hardcoded, so CI can compile these exact sources under a newer standard too.
# That matters here in a way it does not in most languages: a C++ standard can
# REMOVE things, and the removals land on exactly the kind of code an SDK writes.
# C++20 made `u8""` literals `char8_t` rather than `char`, C++17 had already
# removed `std::auto_ptr` and `std::random_shuffle`, and `std::char_traits`
# specialisations were narrowed. A consumer whose own project sets
# `-std=c++23` — entirely their prerogative — would otherwise be the first person
# to compile this SDK that way.
#
# `if(NOT DEFINED ...)` rather than a CACHE entry so the default is unchanged for
# every existing consumer: pass nothing and this is still a C++17 build.
if(NOT DEFINED CMAKE_CXX_STANDARD)
  set(CMAKE_CXX_STANDARD 17)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
message(STATUS "AXIAM C++ SDK: compiling against C++${CMAKE_CXX_STANDARD}")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

option(AXIAM_BUILD_TESTS "Build the AXIAM C++ SDK test suite" OFF)
option(AXIAM_BUILD_EXAMPLES "Build the AXIAM C++ SDK example programs" OFF)
option(AXIAM_ENABLE_COVERAGE "Build with coverage instrumentation (gcov/llvm-cov)" OFF)

include(GNUInstallDirs)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)

# ---------------------------------------------------------------------------
# Library target
# ---------------------------------------------------------------------------
add_library(axiam_cpp
  src/account.cpp
  src/authenticator.cpp
  src/client.cpp
  src/http_curl.cpp
  src/jwks.cpp
  src/oidc.cpp
  src/opaque.cpp
  src/reactor.cpp
  src/webauthn.cpp
  src/webhook.cpp
)
add_library(axiam::axiam_cpp ALIAS axiam_cpp)

target_compile_features(axiam_cpp PUBLIC cxx_std_17)

target_include_directories(axiam_cpp
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    # Root is third_party/ so the vendored single header resolves as
    # <nlohmann/json.hpp> (matching the includes in src/); it lives at
    # third_party/nlohmann/json.hpp and is a private implementation detail.
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

target_link_libraries(axiam_cpp
  PUBLIC
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(axiam_cpp PRIVATE -Wall -Wextra)
endif()

if(AXIAM_ENABLE_COVERAGE)
  if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(axiam_cpp PRIVATE --coverage -O0 -g)
    target_link_options(axiam_cpp PUBLIC --coverage)
  endif()
endif()

set_target_properties(axiam_cpp PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  EXPORT_NAME axiam_cpp
)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(AXIAM_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Examples
# ---------------------------------------------------------------------------
if(AXIAM_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

# ---------------------------------------------------------------------------
# Install + package config
# ---------------------------------------------------------------------------
install(TARGETS axiam_cpp
  EXPORT axiam-cpp-sdkTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(DIRECTORY include/axiam DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT axiam-cpp-sdkTargets
  FILE axiam-cpp-sdkTargets.cmake
  NAMESPACE axiam::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/axiam-cpp-sdk
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/axiam-cpp-sdkConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/axiam-cpp-sdkConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/axiam-cpp-sdk
)
write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/axiam-cpp-sdkConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)
install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/axiam-cpp-sdkConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/axiam-cpp-sdkConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/axiam-cpp-sdk
)

# ---------------------------------------------------------------------------
# CPack (.tar.gz)
# ---------------------------------------------------------------------------
set(CPACK_PACKAGE_NAME "axiam-cpp-sdk")
set(CPACK_PACKAGE_VENDOR "AXIAM")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "AXIAM C++ SDK (REST + mTLS)")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_GENERATOR "TGZ")
include(CPack)
