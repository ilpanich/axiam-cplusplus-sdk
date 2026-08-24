// Language-version support policy.
//
// The SDK states which C++ standard it supports in three places that nothing
// compares:
//
//   1. CMAKE_CXX_STANDARD in CMakeLists.txt — what the build passes to the compiler,
//      and the default every consumer inherits;
//   2. axiam::kMinCxxStandard in include/axiam/axiam.hpp — the value the
//      compile-time #error guard enforces, and the only one a consumer can read;
//   3. the CI matrix in .github/workflows/sdk-ci-cpp.yml — the only one ever
//      compiled.
//
// Before this test existed, CI built gcc and clang at one standard: C++17. Two
// compilers, one standard, so the compiler axis was covered twice and the language
// axis not at all — and it was hiding a real defect. `tests/test_opaque_binding.cpp`
// assigned a `u8""` literal to a `std::string`, which is fine in C++17 and a hard
// error from C++20, where such a literal is `const char8_t[]`. Any consumer building
// this SDK at C++20 or later hit it; nothing here did.
//
// AXIAM_REPO_ROOT is handed in by CMake so the test does not guess at its working
// directory.

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include "assert.hpp"
#include "axiam/axiam.hpp"

#ifndef AXIAM_REPO_ROOT
#error "AXIAM_REPO_ROOT must be defined by the build (see tests/CMakeLists.txt)."
#endif

namespace {

/// Reads a repository file, or returns an empty string.
std::string read_repo_file(const std::string& relative) {
    const std::string path = std::string(AXIAM_REPO_ROOT) + "/" + relative;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

/// The standard actually compiling this file, normalised across MSVC.
constexpr long compiling_standard() {
#if defined(_MSVC_LANG)
    return _MSVC_LANG;
#else
    return __cplusplus;
#endif
}

}  // namespace

AXIAM_TEST("version policy: the compiling standard meets the declared floor") {
    // axiam.hpp's #error guard already refuses to compile below the floor, so
    // reaching this at all proves half of it. Asserting anyway keeps the two
    // together: if the guard were removed, this is what would notice.
    AXIAM_CHECK(compiling_standard() >= axiam::kMinCxxStandard);
}

AXIAM_TEST("version policy: the compiling standard is a leg the policy names") {
    const long v = compiling_standard();

    // Compared as ranges rather than equalities on purpose. A compiler still
    // finishing a standard reports a pre-ratification __cplusplus for a build that
    // is doing exactly what it was asked — the same trap the C SDK hit, where gcc
    // reports 202000L for a C23 build and clang reports 202311L. An equality here
    // would fail one compiler and pass the other for identical, correct builds.
    // C++20 is exactly 202002L. Anything PAST it is C++23-or-later, whichever
    // value the compiler settled on: g++ 13 reports 202100L for -std=c++23 and
    // clang 18 reports the ratified 202302L. Testing `>= 202302L` here would
    // classify a perfectly good g++ C++23 build as C++20.
    const bool is_floor = (v == axiam::kMinCxxStandard);
    const bool is_cxx20 = (v == 202002L);                  // between two green legs
    const bool is_cxx23_or_later = (v > 202002L);

    AXIAM_CHECK(is_floor || is_cxx20 || is_cxx23_or_later);

    if (is_cxx23_or_later) {
        // Sanity-check the macro against reality rather than trusting it: whatever
        // the compiler reports for C++23, the declared "newest tested" value must
        // be in the same era rather than left behind at the floor.
        AXIAM_CHECK(axiam::kNewestTestedCxxStandard > 202002L);
    }
}

AXIAM_TEST("version policy: the header floor matches the CMake default") {
    const std::string cmake = read_repo_file("CMakeLists.txt");
    AXIAM_CHECK_FALSE(cmake.empty());
    AXIAM_CHECK(cmake.find("set(CMAKE_CXX_STANDARD 17)") != std::string::npos);
    AXIAM_CHECK(axiam::kMinCxxStandard == 201703L);
}

AXIAM_TEST("version policy: the CMake standard is overridable") {
    // Load-bearing rather than pedantic. A plain set() overrides the command line,
    // so -DCMAKE_CXX_STANDARD=23 would be silently ignored and the newest CI leg
    // would compile C++17 while reporting green — a leg that exists and proves
    // nothing is worse than no leg at all.
    const std::string cmake = read_repo_file("CMakeLists.txt");
    AXIAM_CHECK_FALSE(cmake.empty());
    AXIAM_CHECK(cmake.find("if(NOT DEFINED CMAKE_CXX_STANDARD)") != std::string::npos);
}

AXIAM_TEST("version policy: CI builds both the floor and the newest standard") {
    const std::string workflow = read_repo_file(".github/workflows/sdk-ci-cpp.yml");
    AXIAM_CHECK_FALSE(workflow.empty());
    AXIAM_CHECK(workflow.find("std: 17") != std::string::npos);
    AXIAM_CHECK(workflow.find("std: 23") != std::string::npos);
}
