// version_compatibility.cpp — reports the C++ standard this translation unit was
// compiled under, against the range the SDK is built and tested against.
//
// The floor enforces itself: <axiam/axiam.hpp> carries an #error guard, so a
// toolchain below C++17 fails at the #include with a message that names the problem
// rather than at some later unexplained error. Nothing enforces the upper end, and
// in C++ that gap is worth taking seriously, because a standard can REMOVE things
// and the removals land on exactly the sort of code an SDK writes — C++20 changed
// `u8""` literals from `char` to `char8_t`, C++17 had already removed
// `std::auto_ptr` and `std::random_shuffle`.
//
// That is not hypothetical for this SDK. Adding a C++23 CI leg immediately caught a
// `u8""`-to-`std::string` assignment in the test suite that had been a hard error
// for every consumer building at C++20 or later, and invisible here.
//
// This example is illustrative and self-contained: no server, no network, no
// configuration.
//
// Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
// Run:    ./build/examples/axiam_example_version_compatibility

#include <cstdio>

#include "axiam/axiam.hpp"

namespace {

/// The standard actually compiling this file.
///
/// MSVC reports 199711L in `__cplusplus` unless `/Zc:__cplusplus` is passed, and
/// puts the real value in `_MSVC_LANG` — so reading `__cplusplus` alone would
/// misreport every MSVC build as pre-C++11.
constexpr long compiling_standard() {
#if defined(_MSVC_LANG)
    return _MSVC_LANG;
#else
    return __cplusplus;
#endif
}

/// Renders a `__cplusplus` value as the standard people actually say.
const char* standard_name(long v) {
    if (v >= 202302L) return "C++23";
    // g++ reports this pre-ratification value for -std=c++23; clang reports
    // 202302L for the same build. Both are C++23.
    if (v > 202002L) return "C++23 (pre-ratification)";
    if (v == 202002L) return "C++20";
    if (v >= 201703L) return "C++17";
    if (v >= 201402L) return "C++14";
    if (v >= 201103L) return "C++11";
    return "older than C++11";
}

}  // namespace

int main() {
    const long compiled = compiling_standard();

    std::printf("axiam-cpp-sdk version: %s\n", axiam::kVersion);
    std::printf("compiled under:        %s (__cplusplus = %ldL)\n",
                standard_name(compiled), compiled);
    std::printf("SDK floor:             %s (%ldL)\n",
                standard_name(axiam::kMinCxxStandard), axiam::kMinCxxStandard);
    std::printf("newest tested:         %s (%ldL)\n",
                standard_name(axiam::kNewestTestedCxxStandard),
                axiam::kNewestTestedCxxStandard);

    if (compiled < axiam::kMinCxxStandard) {
        // Unreachable in practice — the header's #error guard rejects this first.
        std::printf("UNSUPPORTED: below the SDK's floor.\n");
        return 1;
    }

    // Compared as a lower bound, never for equality: a compiler still finishing a
    // standard reports a pre-ratification value for a build that is nonetheless
    // doing exactly what it was asked.
    // "Past C++20" rather than ">= kNewestTestedCxxStandard": see standard_name.
    if (compiled > 202002L) {
        std::printf("SUPPORTED: C++23 or later, which CI builds on both g++ and clang++.\n");
    } else if (compiled == axiam::kMinCxxStandard) {
        std::printf("SUPPORTED: the declared floor, which CI builds on both g++ and clang++.\n");
    } else {
        std::printf("SUPPORTED: between the floor and the newest tested standard.\n");
    }
    return 0;
}
