// AXIAM C++ SDK — umbrella header. Include this to pull in the full public API.
//
// Conforms to CONTRACT.md §1–§7, §9–§11 (including §6.1 mTLS). See README.md.
#pragma once

#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/guard.hpp"
#include "axiam/http_curl.hpp"
#include "axiam/jwks.hpp"
#include "axiam/sensitive.hpp"
#include "axiam/transport.hpp"
#include "axiam/types.hpp"

namespace axiam {

/// SDK semantic version string (matches CMake project version).
inline constexpr const char* kVersion = "1.0.0";

}  // namespace axiam
