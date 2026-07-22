# AXIAM C++ SDK

[![CI](https://github.com/ilpanich/axiam-cplusplus-sdk/actions/workflows/sdk-ci-cpp.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-cplusplus-sdk/actions/workflows/sdk-ci-cpp.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-cplusplus-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-cplusplus-sdk?branch=main)
[![Docs](https://img.shields.io/badge/docs-Doxygen-blue.svg)](https://ilpanich.github.io/axiam-cplusplus-sdk/)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Idiomatic C++17 client for [AXIAM](https://github.com/ilpanich/axiam) (Access
eXtended Identity and Authorization Management) — authentication, authorization
checks, JWKS verification, and framework-agnostic route guards.

**This SDK conforms to CONTRACT.md §1–§7, §9–§11 (including §6.1 mTLS).**

> Scope note: this v1 covers the REST surface. **gRPC** — including the gRPC-only
> `get_user_info` operation (CONTRACT §1.1, contract 1.3) — and **§8 AMQP HMAC** are
> intentionally out of scope for v1 (the cross-language contract does not require
> AMQP of C++); see [Deferred / follow-ups](#deferred--follow-ups). Per §1.1 the REST
> `/oauth2/userinfo` endpoint is not substituted for the gRPC operation.

- Namespace: `axiam` — library target `axiam_cpp` (CMake `axiam::axiam_cpp`).
- Public headers under `include/axiam/`; umbrella header `#include <axiam/axiam.hpp>`.
- Dependencies: **libcurl** (HTTP + strict TLS + mTLS), **OpenSSL** (Ed25519 JWKS
  verification), vendored single-header **nlohmann/json** (`third_party/nlohmann/json.hpp`).
- Version: `1.0.0-alpha16`.

---

## Install

### CMake (FetchContent)

```cmake
include(FetchContent)
FetchContent_Declare(axiam_cpp_sdk
  GIT_REPOSITORY https://github.com/ilpanich/axiam-cplusplus-sdk.git
  GIT_TAG        v1.0.0-alpha16)
FetchContent_MakeAvailable(axiam_cpp_sdk)

target_link_libraries(my_app PRIVATE axiam::axiam_cpp)
```

Or, against an installed copy:

```cmake
find_package(axiam-cpp-sdk CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE axiam::axiam_cpp)
```

### vcpkg

An in-repo port lives at [`ports/axiam-cpp-sdk`](ports/axiam-cpp-sdk). Point vcpkg
at it with an overlay:

```bash
vcpkg install axiam-cpp-sdk --overlay-ports=./ports
```

### Conan

```bash
conan create . --version=1.0.0-alpha16
```

The [`conanfile.py`](conanfile.py) requires `libcurl`, `openssl`, and `nlohmann_json`.

---

## Quickstart

```cpp
#include <axiam/axiam.hpp>
#include <iostream>

int main() {
    // §5: a tenant (slug or id) is mandatory — there is no default tenant.
    axiam::Client client = axiam::Client::builder()
        .base_url("https://api.axiam.example")
        .tenant_slug("acme")
        .org_slug("acme")   // §5.1: login/refresh need org context (a tenant slug is unique only within an org)
        .build();

    auto login = client.login("alice@acme.example", "correct horse battery staple");
    if (login.mfa_required) {
        login = client.verify_mfa(login.challenge_token, "123456");
    }

    // §1: check_access / can / batch_check take (action, resource[, scope]).
    axiam::AccessDecision d = client.check_access("read", "resource-uuid");
    std::cout << "allowed=" << std::boolalpha << d.allowed << "\n";

    auto results = client.batch_check({
        {"read",  "res-1", std::nullopt, std::nullopt},
        {"write", "res-2", std::nullopt, std::nullopt},
    });

    client.logout();
}
```

### Errors (§2)

All failures are exceptions rooted at `axiam::AxiamError`:

| Type | HTTP | Meaning |
|------|------|---------|
| `axiam::AuthError`    | 401 | Authentication failure / expired session / failed refresh |
| `axiam::AuthzError`   | 403, 409 | Authenticated but not authorized (carries `action`/`resource_id` when available) |
| `axiam::NetworkError` | 400, 408, 429, 5xx, transport | Transport/protocol failure (carries the underlying `cause()`) |

Token strings never appear in `what()`, logs, or serialized output (§7).

### Route guards & declarative helpers (§10 / §11)

```cpp
#include <axiam/guard.hpp>

// The host adapter (Crow / Pistache / any server) authenticates the request into
// an AxiamUser; the helpers then compose on top of check_access.
void handler(axiam::Client& client, const std::optional<axiam::AxiamUser>& user) {
    axiam::require_auth(user);                        // 401 if unauthenticated
    axiam::require_role(user, {"editor", "admin"});   // local role check, 403
    AXIAM_REQUIRE_ACCESS(client, user, "read", "resource-uuid");  // 403 if denied
    // ... proceed ...
}
```

`require_access` propagates `subject_id = user.user_id` (§11.2), fails closed on
transport errors (§11.5), and never caches decisions (§11.6).

---

## TLS & mTLS (§6 / §6.1)

Strict server verification is **always on** (`CURLOPT_SSL_VERIFYPEER=1`,
`CURLOPT_SSL_VERIFYHOST=2`). There is **no** API to disable it — the only trust
escape hatch is adding a custom CA:

```cpp
auto client = axiam::Client::builder()
    .base_url("https://dev.axiam.local")
    .tenant_slug("acme")
    .org_slug("acme")                                 // §5.1: org context alongside tenant
    .with_custom_ca(dev_ca_pem)                       // §6: PEM only
    .with_client_cert(device_cert_pem, device_key_pem) // §6.1: mTLS identity
    .build();

auto device = client.authenticate_device();  // POST /api/v1/auth/device
```

The custom CA and the client identity are passed to libcurl as **in-memory
blobs** (`CURLOPT_CAINFO_BLOB`, `CURLOPT_SSLCERT_BLOB`, `CURLOPT_SSLKEY_BLOB`) —
no temporary files touch disk. The mTLS private key is held behind
`axiam::Sensitive<T>` and never logged.

`with_custom_ca` / `with_client_cert` accept **PEM only**; a non-PEM value throws
`std::invalid_argument` at construction.

---

## Build from source

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Coverage (clang / llvm-cov or gcc / gcov): configure with
`-DAXIAM_ENABLE_COVERAGE=ON`.

---

## Deferred / follow-ups

- **gRPC transport** (Tonic-parity authz checks). The §6.1 "both transports" rule
  applies once gRPC lands; the REST client already isolates TLS material for reuse.
- **§8 AMQP HMAC consumer** (not required of C++ by the contract).
- Framework adapter samples for Crow / Pistache (the guard interface is already
  framework-agnostic).
