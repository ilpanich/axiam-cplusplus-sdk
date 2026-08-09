# AXIAM C++ SDK

[![CI](https://github.com/ilpanich/axiam-cplusplus-sdk/actions/workflows/sdk-ci-cpp.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-cplusplus-sdk/actions/workflows/sdk-ci-cpp.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-cplusplus-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-cplusplus-sdk?branch=main)
[![Docs](https://img.shields.io/badge/docs-Doxygen-blue.svg)](https://ilpanich.github.io/axiam-cplusplus-sdk/)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Idiomatic C++17 client for [AXIAM](https://github.com/ilpanich/axiam) (Access
eXtended Identity and Authorization Management) — authentication, authorization
checks, JWKS verification, and framework-agnostic route guards.

**This SDK conforms to CONTRACT.md §1–§7, §9–§11 and §13 (including §6.1 mTLS).**

> Scope note: this v1 covers the REST surface. **gRPC** — including the gRPC-only
> `get_user_info` operation (CONTRACT §1.1, contract 1.3) — and **§8 AMQP HMAC** are
> intentionally out of scope for v1 (the cross-language contract does not require
> AMQP of C++); see [Deferred / follow-ups](#deferred--follow-ups). Per §1.1 the REST
> `/oauth2/userinfo` endpoint is not substituted for the gRPC operation.

- Namespace: `axiam` — library target `axiam_cpp` (CMake `axiam::axiam_cpp`).
- Public headers under `include/axiam/`; umbrella header `#include <axiam/axiam.hpp>`.
- Dependencies: **libcurl** (HTTP + strict TLS + mTLS), **OpenSSL** (Ed25519 JWKS
  verification), vendored single-header **nlohmann/json** (`third_party/nlohmann/json.hpp`).
- Version: `1.0.0-alpha24`.

---

## Install

### CMake (FetchContent)

```cmake
include(FetchContent)
FetchContent_Declare(axiam_cpp_sdk
  GIT_REPOSITORY https://github.com/ilpanich/axiam-cplusplus-sdk.git
  GIT_TAG        v1.0.0-alpha24)
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
conan create . --version=1.0.0-alpha24
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
    std::cout << "allowed=" << std::boolalpha << d.allowed
              << " (" << d.reason_code.value_or("no reason code") << ")\n";

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

### Authenticating a request (§10)

`axiam::TokenAuthenticator` is **the** entry point for turning an inbound
credential into an `AxiamUser`. It verifies the Ed25519 signature **and** the
claims that make a signature meaningful — `exp` (with a small named clock skew),
`nbf` when present, and that the token's `tenant_id` matches the tenant this
server serves — and fails closed on anything missing or malformed.

```cpp
#include <axiam/authenticator.hpp>

axiam::TokenAuthenticator auth(client.jwks(), "11111111-2222-3333-4444-555555555555");

// Wire it into the framework-agnostic guard: you supply the credential
// extraction, the authenticator supplies the verification.
axiam::AxiamGuard<MyRequest> guard(
    auth.guard_authenticator<MyRequest>([](const MyRequest& r) {
        return axiam::TokenAuthenticator::bearer_from_authorization(r.header("Authorization"));
    }));

axiam::AxiamUser user = guard(request);   // throws axiam::AuthError (401) otherwise
```

This is CONTRACT §10.1's minimum local-verification set: the `alg` pin runs
before any key lookup, `exp` is required (absent *and* non-numeric both
hard-fail), `nbf` is honoured when present, and `tenant_id` is asserted — an
empty tenant expectation is refused at construction rather than silently
disabling the check.

Optional `iss` / `aud` pinning and the clock skew live on
`axiam::AuthenticatorOptions`; `AuthenticatorOptions::now` is the injection seam
for tests. `try_authenticate()` is the non-throwing twin. The issuer and
audience checks are **conditional** — leave them unset (the default) and the
claims are not checked; set one and it becomes required, so a token missing that
claim is refused. The skew is a named, bounded constant: it defaults to
`axiam::kDefaultClockSkew` (30 s) and may not exceed `axiam::kMaxClockSkew`
(60 s), because an unbounded leeway would keep expired tokens usable.

> **Do not** build an `AxiamUser` from
> `JwksVerifier::verify_signature_only_unchecked()`. That is a deliberately
> named expert primitive: it validates the signature and nothing else, so a
> guard fed from it accepts expired tokens and tokens minted for another tenant.

### Declarative helpers (§11)

```cpp
#include <axiam/guard.hpp>

void handler(axiam::Client& client, const std::optional<axiam::AxiamUser>& user) {
    axiam::require_auth(user);                        // 401 if unauthenticated
    axiam::require_role(user, {"editor", "admin"});   // local role check, 403
    AXIAM_REQUIRE_ACCESS(client, user, "read", "resource-uuid");  // 403 if denied
    // ... proceed ...
}
```

`require_access` propagates `subject_id = user.user_id` (§11.2), fails closed on
transport errors (§11.5), and never caches decisions (§11.6).

### Decision reason codes (§11 rule 9)

Every `AccessDecision` — from `check_access`, `can`, and each element of
`batch_check` — carries a `reason_code` alongside `allowed`:

| `axiam::ReasonCode::` | value | meaning |
|---|---|---|
| `kAllowed` | `allowed` | an allow grant matched and no deny did |
| `kNoGrant` | `no_grant` | nothing matched — default deny |
| `kDeniedByRule` | `denied_by_rule` | an explicit deny rule matched and overrode any allow |

The two refusals are both `allowed == false`, but they mean opposite things to
the person on the other end: `no_grant` says *ask an admin for access*,
`denied_by_rule` says *an admin has already decided*. Branch on the code when
you are telling a user what to do next:

```cpp
axiam::AccessDecision d = client.check_access("docs:edit", doc_id);
if (!d.allowed) {
    if (d.reason_code == axiam::ReasonCode::kNoGrant)
        show_request_access_button();
    else
        show_plain_denied_message();   // a rule, or a code we don't know
}
```

Three things this field deliberately is **not**:

- **Not an `enum class`.** An unrecognised code is surfaced verbatim, so the
  server can add a fourth code without turning every deployed client into a
  decode failure. Compare against the constants and let anything unknown fall
  through to a default branch.
- **Not the decision.** The outcome is carried by `allowed` alone. Never
  re-derive allow/deny from the code.
- **Not guaranteed present.** A server older than this clause omits the field
  and `reason_code` is `std::nullopt` — that is absence, not an error.

Enforcement is unchanged: `require_access` throws `AuthzError` (403) for both
refusals. The clause is about reporting, and the guard must not vary its
behaviour on the code.

### Webhook signature verification (§13)

```cpp
#include <axiam/webhook.hpp>

// `raw_body` MUST be the exact bytes received off the wire — never a
// re-serialization of parsed JSON, which changes key order and whitespace and
// breaks the MAC.
axiam::webhook::Options opts;
opts.event_type  = request.header("X-Axiam-Event");
opts.delivery_id = request.header("X-Axiam-Delivery");
// opts.tolerance defaults to 300s, applied in BOTH directions.

auto result = axiam::webhook::verify(
    axiam::Sensitive<std::string>(webhook_secret),
    request.header("X-Axiam-Signature"),
    raw_body,
    opts);

if (!result) {
    return respond(400, result.error_message());   // typed, never leaks the MAC
}
// result.event.delivery_id is the at-least-once dedup key: a retry replays a
// valid signature inside the freshness window, so keep a short-lived seen-set
// if your handler is not idempotent.
handle(result.event);
```

`verify_or_throw(...)` is the exception-based twin (`axiam::webhook::VerifyException`).

---

## TLS & mTLS (§6 / §6.1)

Strict server verification is **always on** (`CURLOPT_SSL_VERIFYPEER=1`,
`CURLOPT_SSL_VERIFYHOST=2`). There is **no** API to disable it — the only trust
escape hatch is adding a custom CA.

The base URL must be `https://`: `Client::Builder::build()` throws
`std::invalid_argument` for a plaintext `http://` base, so a misconfiguration
cannot silently send credentials, cookies, the CSRF token and the tenant header
in cleartext. `http://` is accepted only for the loopback development hosts
`localhost`, `127.0.0.1` and `::1`.

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
- **§12 OIDC relying-party surface**, and with it the three sections built on top
  of it: **§12.7** RP-initiated and back-channel logout, **§14** the device
  authorization grant (RFC 8628), and **§15** token exchange (RFC 8693).

  This SDK ships no OIDC layer — no discovery-document cache, no token endpoint,
  no ID-token validation, no PKCE. Each of those sections needs it directly:
  §12.7's `logout_url` must read `end_session_endpoint` *from discovery* (the
  clause exists precisely to forbid concatenating onto the issuer), §14 must read
  `device_authorization_endpoint` from discovery and then poll the token
  endpoint, and §15 is a token-endpoint grant requiring confidential-client
  authentication. Adding them means designing an OIDC stack for C++, not
  extending an existing one, so they are tracked here rather than half-shipped.

  What *is* implemented from the same area is local JWT/JWKS verification
  (§10.1), which the route guards need and which does not depend on discovery.
  Note also that `DeviceAuth` / `authenticate_device()` is **§6.1 mTLS device
  authentication**, not the §14 device *authorization grant* — different
  mechanisms that share a word.
- Framework adapter samples for Crow / Pistache (the guard interface is already
  framework-agnostic).
