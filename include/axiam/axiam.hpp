// AXIAM C++ SDK — umbrella header. Include this to pull in the full public API.
//
// Conforms to CONTRACT.md §1–§7, §9–§11 and §13 (including §6.1 mTLS).
// See README.md.
#pragma once

// Refuse a toolchain older than the declared floor at the point of inclusion.
// Without this the failure is a cascade of errors from whichever header first uses
// something C++17 introduced, which reads like a broken SDK rather than an
// out-of-date compiler. MSVC reports 199711L in __cplusplus unless /Zc:__cplusplus
// is passed, so it is checked through _MSVC_LANG instead.
#if defined(_MSVC_LANG)
#  if _MSVC_LANG < 201703L
#    error "The AXIAM C++ SDK requires C++17 or newer (see axiam::kMinCxxStandard)."
#  endif
#elif __cplusplus < 201703L
#  error "The AXIAM C++ SDK requires C++17 or newer (see axiam::kMinCxxStandard)."
#endif

#include "axiam/account.hpp"
#include "axiam/authenticator.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/guard.hpp"
#include "axiam/http_curl.hpp"
#include "axiam/jwks.hpp"
#include "axiam/sensitive.hpp"
#include "axiam/transport.hpp"
#include "axiam/types.hpp"
#include "axiam/opaque.hpp"
#include "axiam/reactor.hpp"
#include "axiam/uma.hpp"
#include "axiam/webauthn.hpp"
#include "axiam/webhook.hpp"

namespace axiam {

/// SDK semantic version string (matches CMake project version).
inline constexpr const char* kVersion = "1.0.0";

/// The minimum C++ standard this SDK is compiled against, as `__cplusplus` reports it.
///
/// The SDK is built at this standard and additionally compiled and tested at C++23,
/// so a consumer whose own project selects a newer standard is on ground a green
/// build already covers.
///
/// That upper claim is the one worth stating, because a C++ standard can *remove*
/// things and the removals land on exactly the sort of code an SDK writes. C++20
/// changed `u8""` literals from `char` to `char8_t`; C++17 had already removed
/// `std::auto_ptr` and `std::random_shuffle`. None of that is visible from a
/// C++17-only build.
inline constexpr long kMinCxxStandard = 201703L;

/// The newest C++ standard this SDK has a green build against, as `__cplusplus`
/// reports it for C++23.
///
/// Nothing enforces this and nothing can: it is a statement about what CI covers,
/// not about what the compiler will accept.
///
/// Compare it as a lower bound, never for equality, and prefer testing "past C++20"
/// (`__cplusplus > 202002L`) when what you mean is "C++23 or later". A C++23 build
/// does not report the same value everywhere: g++ 13 reports the pre-ratification
/// `202100L` for `-std=c++23` while clang 18 reports the ratified `202302L`. Both
/// are correct C++23 builds.
inline constexpr long kNewestTestedCxxStandard = 202302L;

}  // namespace axiam
