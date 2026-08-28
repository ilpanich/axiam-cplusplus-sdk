# AXIAM C++ SDK

[![CI](https://github.com/ilpanich/axiam-cplusplus-sdk/actions/workflows/sdk-ci-cpp.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-cplusplus-sdk/actions/workflows/sdk-ci-cpp.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-cplusplus-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-cplusplus-sdk?branch=main)
[![Docs](https://img.shields.io/badge/docs-Doxygen-blue.svg)](https://ilpanich.github.io/axiam-cplusplus-sdk/)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Idiomatic C++17 client for [AXIAM](https://github.com/ilpanich/axiam) (Access
eXtended Identity and Authorization Management) — authentication, authorization
checks, JWKS verification, and framework-agnostic route guards.

**Platform documentation:** <https://ilpanich.github.io/axiam/> — getting started, the authorization model, the OAuth2/OIDC surface, and the operations guides. This README covers the SDK; the site covers the server it talks to.

**This SDK conforms to CONTRACT.md §1–§7, §9–§13, §14, §15, §17, §19, §20, §21, §22, §23, §24, §25, §26 and §27 (including §6.1 mTLS, §12.7 logout, the §11 rule 9 decision reason codes, the §23 OPAQUE login path — which binds `libaxiam_opaque_ffi` at run time, see below — and §24's six wire operations with §24.6a's JSON bridge, but not §24.6b's ceremony helper, which has no authenticator to link on these targets).**

Sections are named individually rather than folded into ranges: widening a
range silently turns a statement that was true when written into a different
claim. **§16 and §18 are absent by that same rule, not by omission** — the
contract makes retry policy and deterministic shutdown MUST-level and says
they are not named, because an SDK is either conformant on them or it is not.
This one is.

> **§22 note, and it matters at integration time:** "conforms to … §22" is the claim; **"ships an AMQP client" is not**. The reactor *protocol* — verification, canonical signing, the registry, the runtime and the §22.14 binder — is in the library. The *transport* is caller-supplied (§22.11): this SDK vendors no AMQP dependency, and you implement `axiam::ReactorTransport` over whichever client you already trust.

> Scope note: this v1 covers the REST surface plus the §22 reactor protocol core.
> **gRPC** — including the gRPC-only `get_user_info` operation (CONTRACT §1.1,
> contract 1.3) — and the **§8 AMQP HMAC consumer** are intentionally out of scope
> for v1 (the cross-language contract does not require AMQP of C++); see
> [Deferred / follow-ups](#deferred--follow-ups). Per §1.1 the REST
> `/oauth2/userinfo` endpoint is not substituted for the gRPC operation.

- Namespace: `axiam` — library target `axiam_cpp` (CMake `axiam::axiam_cpp`).
- Public headers under `include/axiam/`; umbrella header `#include <axiam/axiam.hpp>`.
- Dependencies: **libcurl** (HTTP + strict TLS + mTLS), **OpenSSL** (Ed25519 JWKS
  verification), vendored single-header **nlohmann/json** (`third_party/nlohmann/json.hpp`).
- Version: `1.0.0-beta02`.

---

## Supported C++ standards

| | Standard | Why this one |
|---|---|---|
| **Floor** | C++17 | `CMAKE_CXX_STANDARD` in `CMakeLists.txt`, and what every consumer inherits by default. Exposed as `axiam::kMinCxxStandard`. Deliberately not newer — raising it would exclude long-lived-distro toolchains for nothing the SDK needs. |
| **Newest** | C++23 | The newest published standard. Exposed as `axiam::kNewestTestedCxxStandard`. |

C++20 sits between the two.

**The SDK is built at the floor and additionally compiled and tested at C++23**, on
**both g++ and clang++** — four legs in `sdk-ci-cpp.yml`.

That second axis is not cosmetic, and this repo is the proof: adding it immediately
caught a `u8""` literal assigned to a `std::string` in the test suite. That is
perfectly legal C++17, and a **hard error from C++20**, where such a literal is
`const char8_t[]`. Every consumer building this SDK at C++20 or later hit it, and
nothing in CI ever did. A C++ standard can *remove* things, and the removals land on
exactly the kind of code an SDK writes.

Nothing changes for you if you build at C++17: it is still the default, and
`cmake -S . -B build` with no flags produces exactly the build it always did. To
compile against a newer standard, pass it:

```bash
cmake -S . -B build -DCMAKE_CXX_STANDARD=23
```

`<axiam/axiam.hpp>` refuses a toolchain below the floor with an `#error` at the point
of inclusion — one message naming the problem rather than a cascade of errors that
reads like a broken SDK. MSVC is checked through `_MSVC_LANG`, since it reports
`199711L` in `__cplusplus` unless `/Zc:__cplusplus` is passed.

> **`__cplusplus` is not the same on both compilers for a C++23 build.** g++ 13
> reports the pre-ratification `202100L` for `-std=c++23`; clang 18 reports
> `202302L`. Both are correct C++23 builds. Test `__cplusplus > 202002L` — "past
> C++20" — when what you mean is "C++23 or later", and never compare
> `kNewestTestedCxxStandard` for equality.

See [`examples/version_compatibility.cpp`](./examples/version_compatibility.cpp) for
a runnable check, and `tests/test_version_policy.cpp` for the gate that fails the
build when `CMakeLists.txt`, the header constants and the CI matrix stop agreeing.

## Install

### CMake (FetchContent)

```cmake
include(FetchContent)
FetchContent_Declare(axiam_cpp_sdk
  GIT_REPOSITORY https://github.com/ilpanich/axiam-cplusplus-sdk.git
  GIT_TAG        v1.0.0-beta02)
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
conan create . --version=1.0.0-beta02
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

## Retry, memo, shutdown and telemetry (§16–§19)

Retry is **on by default** and applies only to operations that change no server
state — `check_access`, `can`, `batch_check` and the JWKS fetch. That is not the
same as "HTTP GET": the authorization check is a `POST` with a body and is the
operation this policy exists for. `login`, `verify_mfa`, `logout`, `refresh` and
`authenticate_device` are never retried automatically, both because they change
state and because their credentials are single-use.

The policy is 3 attempts, 200 ms base, 5 s cap, **full jitter** over
`[0, backoff]`, and `Retry-After` honored as a **floor** — it can lengthen a wait,
never shorten one, so a `Retry-After: 0` cannot defeat the backoff. Only the
switch is public; the attempt cap, base and cap are deliberately not settable,
because §16.1 permits *lowering* the budget and never raising it.

```cpp
auto client = axiam::Client::builder()
    .base_url("https://iam.example.com")
    .tenant_slug("acme")
    .retry_enabled(false)                                  // §16: one attempt
    .decision_memo_ttl(std::chrono::seconds(5))            // §17: opt-in, off by default
    .telemetry_hook([](const axiam::TelemetryEvent& ev) {  // §19
        if (const auto* r = std::get_if<axiam::RetryEvent>(&ev)) {
            std::cerr << "retry " << r->operation << " attempt=" << r->attempt << "\n";
        }
    })
    .build();
```

> **Read-your-own-writes is not guaranteed** with the memo enabled. The staleness
> bound is the TTL in *both* directions: a grant revoked on the server can still
> read as allowed for up to the TTL, and a grant just *added* can still read as
> denied for up to the TTL. An admin UI that grants a role and immediately
> re-checks is the case that breaks, and it breaks silently. A TTL above 5 s is
> **clamped** to 5 s, and the clamp is announced through the `ConfigClampedEvent`
> rather than applied in silence.

`TelemetryEvent` is a closed `std::variant` over five structs with fixed member
lists and no maps, which is what makes "no event carries a token" checkable by
reading one declaration. Events carry the *path template*
(`/api/v1/authz/check`), never a URL with ids substituted in — a metric label
with a UUID in it is a cardinality bomb — and a retried call emits one
`RequestStartEvent`/`RequestEndEvent` pair per **attempt**, so a caller can count
real wire calls. The hook runs on the calling thread and must not block;
buffering is yours to choose. A hook that throws cannot fail the operation that
fired it.

`close()` releases the transport and its connection pool and clears the cookie
jar, the CSRF token and the memo. It issues **no request** — it does not log out,
because the server-side session deliberately outlives the client object. It is
idempotent, and any operation attempted afterwards throws `NetworkError` naming
the cause rather than silently reconnecting. The destructor releases whatever
`close()` has not, so a `Client` that simply goes out of scope still frees its
transport.

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

## OPAQUE — RFC 9807 (§23)

`login_opaque()` proves the password to the server without the password — or
anything from which it can be cheaply recovered — ever crossing the wire. The
server stores a **registration record** sealed under a tenant-scoped oblivious
PRF instead of a password hash, and what travels is a blinded group element and
a MAC, neither of which is useful without that record *and* the tenant's OPRF
seed.

```cpp
axiam::LoginResult result = client.login_opaque("alice", password);
```

It takes the same arguments as `login()` and returns the same `LoginResult`,
MFA branch included, so switching a tenant to OPAQUE needs no change to how the
result is handled. A runnable end-to-end example, including the fallback and the
enrolment call, is [`examples/opaque_login.cpp`](examples/opaque_login.cpp).

### What this buys, and what it does not

OPAQUE closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh sees
  every plaintext password today; under OPAQUE it sees `KE1` and `KE3`;
- an accidental request-body log, a heap dump or a crash reporter can no longer
  capture a plaintext password, because the server never has one;
- **a stolen record database is not offline-crackable on its own.** This is the
  substantive gain over the SRP-6a this replaces. An SRP verifier is
  `g^x mod N` with a public salt: anyone holding the database can grind
  candidate passwords locally, at one KDF evaluation each. An OPAQUE record is
  sealed under the tenant's OPRF seed, so an attacker who takes the records and
  not the seed has nothing to grind against at all. The property is called
  pre-computation resistance and SRP does not have it.

It does **not** protect against a compromised AXIAM server, and this SDK does
not claim it does.

### This SDK does not implement OPAQUE, and that is the design

CONTRACT.md §23.1 forbids it. OPAQUE needs an oblivious PRF, `hash_to_curve`,
`expand_message_xmd`, an envelope construction and a three-message authenticated
key exchange; eleven independent implementations of that is eleven chances to be
subtly and silently wrong, in a way test vectors do not catch because the wrong
answer is still a well-formed group element.

So this SDK binds **`libaxiam_opaque_ffi`**, the C ABI of the same audited
`opaque-ke` core the AXIAM server runs. There is no cryptography in
`src/opaque.cpp`.

The library is a **per-platform release asset** of
[`ilpanich/axiam-opaque`](https://github.com/ilpanich/axiam-opaque), resolved
with `dlopen` at **run time** rather than linked. A consumer who never uses
OPAQUE therefore needs nothing extra at build time — and
`Client::opaque_available()` can honestly answer `false`. Install the library
where the dynamic loader looks, or point `AXIAM_OPAQUE_LIBRARY` at it:

```sh
export AXIAM_OPAQUE_LIBRARY=/usr/local/lib/libaxiam_opaque_ffi.so
```

```cpp
if (!client.opaque_available()) { /* ask BEFORE collecting a password */ }
```

### Your OpenSSL version no longer decides which tenants work

SRP was **conditional** here, and awkwardly so. The arithmetic was `BN_mod_exp`,
available everywhere, but **Argon2id arrives as an `EVP_KDF` only in OpenSSL
3.2** — and it is what a default-configured AXIAM tenant names. A build against
an older libcrypto had to refuse such a tenant outright (substituting PBKDF2
would derive a different `x` and surface as "invalid password"), so operators
either upgraded OpenSSL or weakened the tenant to `pbkdf2_sha256`.

That is gone. Key stretching happens inside `libaxiam_opaque_ffi`, so this SDK
serves `argon2id` and `scrypt` tenants against any OpenSSL it links, and
`srp::argon2_available()` has no successor because it has no question left to
answer.

One condition remains, and it is honest rather than hidden:
`Client::opaque_available()` reports whether the shared library is present.
Unlike the `Client::srp_available()` it replaces — which returned `true`
unconditionally while an `argon2id` tenant still failed at login — a `true` here
**is** a promise that every tenant will work.

### The server names the cost, every time

The `*/start` response names the key-stretching function and its parameters for
**that exchange**. This SDK never caches them across exchanges and never
defaults them locally:

| rule | what it means here |
|---|---|
| §23.4 rule 2 | costs come from the server per exchange — a credential enrolled under one cost keeps working after a tenant raises its policy, so a client that guessed would derive a different randomized password and report "invalid password" for a correct one |
| §23.4 rule 3 | an unrecognised `ksf` is **refused**, never substituted |
| §23.4 rule 5 | a cost field that does not apply to the named function is **absent, not zero** — which is why every cost in `OpaqueKsfParams` is a `std::optional<unsigned>` rather than a zero-defaulted `unsigned` |
| §23.4 rule 7 | nothing is sent to `login/finish` once the envelope fails to open — and what happens next is decided by the tenant's `mode`, below |

Costs are additionally range-checked here, so a refusal names the field:

| field | accepted band |
|---|---|
| `memory_kib` | 8192 – 1048576 (8 MiB – 1 GiB) |
| `iterations` | 1 – 10 |
| `parallelism` | 1 – 16 |
| `log_n` | 14 – 20 |
| `r`, `p` | 1 – 16 |

A server is trusted to name its own policy, not to name a cost that would wedge
every device an account owns. The library range-checks too; doing it here as
well means the error says which field.

### One round trip, and no server-proof step

SRP had to guess a group before the server named one, and restart the exchange
if it guessed wrong. `KE1` does not depend on the key-stretching function, so
there is no such dance.

And where the old §23.3 rule 6 had to mandate an `M2` check **in capitals** —
because an SDK that skipped it implemented only half the protocol and no test
would notice — RFC 9807's AKE authenticates the server during the handshake.
Opening `KE2` *is* the proof that the server holds the record. Mutual
authentication is no longer something a client can forget.

### Tenant policy, and the errors that are not credential failures

`opaque_mode` is an organization baseline a tenant may tighten:

| mode | `login()` | `login_opaque()` |
|---|---|---|
| `disabled` (default) | works | `NetworkError` — the start endpoints answer `404` |
| `optional` | works | works, and a failed exchange **falls back to `login()`** |
| `required` | `AuthzError` (`opaque_required`) | works |

Neither is an `AuthError`:

- `NetworkError` from `login_opaque()` means *this tenant does not offer
  OPAQUE*, *`libaxiam_opaque_ffi` is not installed*, *the server named a
  key-stretching function this SDK cannot ask for*, or *the response was not the
  shape §23 defines* — a property of the tenant, the build or the deployment,
  never of any user. Fall back to `login()`.
- `AuthzError` from `login()` means *this tenant refuses password login*. The
  credentials were never examined. Telling a user their perfectly good password
  is invalid is the failure this mapping exists to prevent.

`AuthError` from `login_opaque()` means the envelope did not open: a wrong
password, an account that does not exist, an account with no registration
record, or a server that does not hold one — indistinguishable by design, and
the whole credential check now that both halves of mutual authentication live in
it. Nothing is sent to `login/finish` after it.

### The `optional` fallback, and why it is not yours to write (§23.4 rule 7)

`login/start` reports the tenant's mode back to the client, and that field —
**and nothing else** — decides what a failed exchange does next. `login_opaque()`
handles both branches itself:

| reported mode | a `KE2` that does not open |
|---|---|
| `optional` | retried once over `POST /api/v1/auth/login`, same username and password; you get that call's outcome — its `LoginResult` on success, its error on failure |
| `required` | `AuthError`, and no retry |
| no `mode` field (a server older than contract 1.29) | `AuthError`, and no retry |
| anything else | `AuthError`, and no retry — fail closed |

The `optional` branch is not a convenience. `optional` is the state a tenant
lives in for the whole migration, and **every account has no registration record
the moment an operator enables OPAQUE** — records accrue only as passwords are
next set. A client that treated the failed exchange as final would lock out every
user of the tenant, which is precisely the outcome `optional` exists to avoid.
Under `required` the opposite holds: `/auth/login` answers `403 opaque_required`
to every principal before looking at a credential, so a retry would put a
plaintext password on the wire for nothing.

So do **not** hand-roll a fallback of your own around `AuthError`. Under
`required` it is exactly the mistake the mode exists to prevent, and under
`optional` this SDK has already made the attempt — a second one is a second
plaintext password on the wire and a second Argon2id cost.

The reported mode is **not downgrade protection**, and this SDK does not present
it as one: a hostile server that wanted the plaintext could answer `404` and get
a fallback whatever mode it claims. What closes that is `required` itself,
server-side.

`required` refuses **every** principal in the tenant, not only the enrolled
ones. Splitting the response on whether an account has a record would turn
`/auth/login` into an enumeration oracle costing one junk password per name. It
also means `required` locks out anyone not yet enrolled: a record needs the
plaintext password, and a stored Argon2id hash is not invertible, so nobody can
be enrolled retroactively. Operators turn it on last, after a password-reset
campaign.

### Enrolment

The server cannot build a registration record, so any request that **sets** a
password has to carry one. `opaque_enrollment()` produces the `opaque` object
for `POST /api/v1/users`, `/auth/password/change`, `/auth/reset/confirm` and
`/admin/bootstrap`:

```cpp
axiam::OpaqueEnrollment enrolment = client.opaque_enrollment(new_password);
// ... attach opaque_session + registration_record as the request's `opaque` member
```

Three things differ from the `srp_enrollment()` it replaces, and all three are
improvements:

- **It performs I/O** — one `register/start` round trip. OPAQUE's envelope is
  sealed under the server's oblivious PRF, so there is no offline computation
  that produces a valid record. The SRP version was pure.
- **There is no `identity` argument.** SRP derived `x` over
  `identity ":" password` using the identity the challenge endpoint handed back,
  so passing an email where a username was wanted produced a verifier no login
  could ever satisfy — and **renaming a user invalidated their verifier**, which
  the server had to clear. An OPAQUE record binds to a credential identifier the
  server chooses. A rename is now just a rename.
- **There is no `group` and no `params`.** Those come from the `register/start`
  response, so a caller cannot pick a cost the server will not honour.

`registration_record` is credential material: never log it.

### Cost

`login_opaque()` runs the tenant's key-stretching function: Argon2id at 19 MiB
and t=2 by default, which is tens to hundreds of milliseconds of CPU plus that
memory, per login attempt. That cost is the point — it is what makes a stolen
record expensive to attack even by someone holding the OPRF seed. It is
synchronous and blocking; size your request handling accordingly, since
`login()` has no such cost.

### Cryptographic parameters

`OPAQUE-3DH` over **ristretto255**, with **SHA-512**, **HKDF-SHA-512** and
**HMAC-SHA-512**. The ciphersuite is fixed in `libaxiam_opaque_ffi`; it is not
negotiated and is deliberately **not** read from the server, because a
server-selected ciphersuite is a downgrade channel.

The bundled RFC 5054 group constants are gone with the arithmetic, and so is the
"never accept a modulus from the server" rule they needed.

### Handle lifetime

`opaque::Exchange` owns one native allocation and is move-only. It is
single-use — a `finish` spends it — and `close()` is idempotent, so the
destructor is a backstop rather than the mechanism: an exchange abandoned on any
failure path (a refused key-stretching function, a malformed response, a non-200
start) is released when it goes out of scope.

The key-stretching handle is built **before** the exchange state is spent, and
the order is load-bearing: built the other way round, a server that names a cost
outside the accepted band would leave the state unreachable — a leaked native
allocation once per login attempt, and the steady state for a misconfigured
tenant. Two tests pin the ordering, and two more pin that moving either handle
type releases exactly once.

### Zeroization

§23.4 rule 8 requires clearing what can be cleared, and C++ is a language where
it can be. `KE1` and the `RegistrationRequest` are `OPENSSL_cleanse`d before
their buffers are released, including on the move paths, because a move of a
short string is a copy and the moved-from buffer would otherwise still hold it.
The sensitive derivations themselves happen and are cleared on the Rust side of
the ABI. The suite runs clean under ASan and UBSan with leak detection on.

The one thing this SDK cannot clear is the `const std::string&` you hand it —
that memory is yours.

## Build from source

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Coverage (clang / llvm-cov or gcc / gcov): configure with
`-DAXIAM_ENABLE_COVERAGE=ON`.

---

## UMA 2.0 — Protection API and ticket grant (§20)

The resource-server side of User-Managed Access: register what you guard, ask
the authorization server what a caller would need, and redeem the resulting
ticket.

```cpp
// A PAT is a client-credentials token carrying `uma_protection` — never a user
// token, and never this client's own session (§20.2 rule 1).
const axiam::Sensitive<std::string> pat{protection_api_token};

const auto resource = client.uma_register_resource(pat, "invoice-7", "document", {"view"});

// The returned id IS the AXIAM resource id — no translation step.
const auto ticket = client.uma_request_ticket(pat, {{*resource.id, {"view"}}});

response.set_header("WWW-Authenticate",
                    axiam::uma_challenge_header("invoices", issuer, ticket));
```

…and on the client side, having caught that `401`:

```cpp
if (auto challenge = axiam::uma_parse_challenge(www_authenticate); challenge && challenge->ticket) {
    axiam::UmaExchangeTicketParams params;
    params.ticket = *challenge->ticket;
    params.claim_token = axiam::Sensitive<std::string>{users_access_token};
    params.credentials = {client_id, axiam::Sensitive<std::string>{client_secret}};
    const auto rpt = client.uma_exchange_ticket(params);
}
```

The rules this surface exists to enforce:

- **A ticket is never retried** — not on `5xx`, not on a transport failure, not
  on `invalid_grant`. It is the one documented exception to §16's retry policy,
  and a security rule rather than a performance one: the ticket is consumed
  *before* the exchange is evaluated, so a failed exchange has already spent it
  and a retry is a *second redemption*. Under concurrency that is exactly the
  redemption a server whose storage engine the SDK cannot attest may admit twice
  ([`ilpanich/axiam#302`](https://github.com/ilpanich/axiam/issues/302)).
  On failure, request a **new** ticket.
- **`uma_parse_challenge` does not exchange what it parsed.** The `as_uri` names
  an authorization server you have not necessarily chosen to trust.
- **`claim_token` is required, never defaulted.** An empty one, an empty PAT, or
  a client configured with only a tenant *slug* throws before any wire call, so
  a request that could not have succeeded never spends a ticket.
- **No auto-narrowing on `access_denied`.** A partial grant is refused whole.
- **The RPT is never adopted** as this client's credential, and
  `RequestingPartyToken` has no refresh-token member.
- **`uma_update_resource` replaces the scope list rather than merging it**, so
  omitting a scope removes it. There is no read-modify-write.

A refusal whose body is an `OAuth2ErrorResponse` throws `OAuthProtocolError`,
which **derives from `AuthError`** — the §2 taxonomy stays at three top-level
types, and a caller that only knows about `AuthError` still catches it. Dispatch
on `error_code()` rather than the HTTP status: §20.4 puts `access_denied` on a
`403` where RFC 8628's is a `400`, and the code is what stays correct if either
moves. The exception's `what()` carries the code, never the server's free text —
a description echoing the ticket must not reach a log line — and
`error_description()` surfaces that text separately for a caller who opts in.

### Emitting the challenge from the §11 guard

The `require_access` overload that takes a `UmaChallenger` mints and formats the challenge for
you, so you do not hand-roll it on every denial:

```cpp
axiam::UmaChallenger challenger{"invoices", configuration.issuer, pat};

try {
    axiam::require_access(client, caller, "invoices:read", invoice_id, challenger);
} catch (const axiam::AuthzChallengeError& denial) {
    response.set_header("WWW-Authenticate", denial.challenge());  // send it; do not log it
    response.status(403);
}
```

`AuthzChallengeError` **derives from `AuthzError`**, so an adapter that knows nothing about UMA
catches what it always caught and returns the same 403; the addition can never turn a denial
into a different outcome. The challenge is not in `what()` — the value carries a live permission
ticket (§20.6), and `what()` is what ends up in a log line.

Two properties are deliberate, and both are asserted by counting Protection API calls:

- **Opt-in.** Emitting a challenge means minting a credential. A guard that did that on every
  denial by default would put a Protection API call — and a live ticket — behind every
  unauthorized request, which is a denial-of-service amplifier pointed at your own authorization
  server. The existing overloads are untouched; an allow mints nothing; an unauthenticated
  request mints nothing, because only a *resource denial* is answerable with a ticket.
- **A minting failure is not an escalation.** An expired PAT or an unreachable Protection API
  still surfaces the original `AuthzError` — never a 503 escaping from the mint, and never an
  allow.

The requested UMA scope is the AXIAM **action**, so the ticket asks for exactly the authority
that was refused and the engine's deny rules keep applying to whatever RPT comes back.

Both halves run in [`examples/uma_resource_server.cpp`](examples/uma_resource_server.cpp) and
[`examples/uma_client.cpp`](examples/uma_client.cpp).

## §12 OIDC, §12.7 logout, §14 device grant, §15 token exchange

These four shipped together in the contract-1.11 port ([`CONTRACT.md` §12.6](CONTRACT.md)).
They were previously deferred here, and the reasoning behind the reversal is
worth keeping. The original deferral argued from persona — this is a device- and
IoT-oriented SDK and the browser-redirect flow has no natural home in it — which
covered `oidc_begin` and `oidc_exchange` and none of the other seven operations.
`login_client_credentials` is the machine-to-machine login an embedded consumer
wants; `introspect` and `revoke` are ordinary questions a device asks about its
own credentials; §14 exists *because* a device cannot show a browser. Meanwhile
§20 had already given this SDK a `/oauth2/token` call, so it was speaking OAuth2
at the token endpoint anyway — without the shared discovery cache and ID-token
validation §12 specifies. The port removed a divergence rather than adding one.

```cpp
auto client = axiam::Client::builder()
                  .base_url("https://iam.example.com")
                  .tenant_id("11111111-1111-1111-1111-111111111111")  // UUID, not a slug
                  .oidc_client_id("example-rp")
                  .oidc_client_secret(secret)   // omit for a public client
                  .build();

const auto doc = client.oidc_discover();          // cached >= 5 min per client
const auto req = client.oidc_begin(doc, redirect_uri, "openid profile");
// No network I/O happened. Keep req.state, req.nonce, req.code_verifier AND your
// redirect_uri — §12.3 rule 1 means the SDK stores none of them.

axiam::OidcExchangeParams p;
p.code = code;                       p.code_verifier = req.code_verifier;
p.redirect_uri = redirect_uri;       p.nonce = req.nonce;
const auto tokens = client.oidc_exchange(p);
// tokens.id_claims is engaged only after every §12.4 rule passed; on any failure
// the WHOLE set is discarded (rule 7) and OidcValidationError::reason() names the
// rule.
```

Three things this surface will not do, each because a section says so:

- **It stores no correlation values** (§12.3 rule 1). See above.
- **It never skips ID-token validation** and has no flag to. §12.4 rule 7 is
  all-or-nothing: a token set whose `id_token` fails any check is discarded
  whole, access and refresh tokens included.
- **It adopts nothing.** Every operation returns tokens; none becomes this
  client's own credential. §15.2 rule 5 makes that a MUST NOT for the exchanged
  token specifically, and this SDK takes one posture everywhere rather than two.

Two error types, two closed vocabularies, deliberately kept apart:
`OAuthProtocolError::error_code()` carries the server's OAuth2 `error`;
`OidcValidationError::reason()` carries the §12.3 rule 3 ID-token code. One of
each pair is nearly a homograph of the other (§14.2's terminal `expired_token`
against §12.4 rule 5's `token_expired`), so catching the wrong one is a mistake
the type system makes visible.

Note that `DeviceAuth` / `authenticate_device()` remains **§6.1 mTLS device
authentication** — a different mechanism from the §14 device *authorization
grant*, sharing a word.

Worked examples: [`examples/oidc_login.cpp`](examples/oidc_login.cpp),
[`examples/device_login.cpp`](examples/device_login.cpp),
[`examples/token_exchange.cpp`](examples/token_exchange.cpp).

### Sender-constrained tokens and DPoP (§10.1 rule 9, §21.7.3)

A token carrying a `cnf` claim is **not** a bearer token: it names a key, and
accepting it without proving the caller holds that key converts it straight
back into one. ``axiam::verify_certificate_binding()`` applies §10.1 rule 9.

**This SDK deliberately declines §21.7.2 DPoP proof verification** (recorded in
the contract's §21.9 per-SDK table). Its role here is resource-server-side
validation, and it ships no JOSE implementation covering PS256/ES256/EdDSA that
could verify a proof without adding a dependency this contract does not
otherwise require.

Declining is a supported answer, and §21.7.3 defines it as exactly three
obligations — all three are met here:

1. **`jkt`-bound tokens are rejected**, never accepted as bearer tokens. That
   includes a `cnf` naming **both** a certificate and a DPoP key: two
   constraints is a conjunction, so a token this SDK can only half-check is
   refused outright rather than admitted on the certificate alone. "Check
   whichever we can" would let a caller holding the certificate but not the
   DPoP key through a door the operator bolted twice.
2. **This section says so** — you are reading it.
3. **The negative tests are present**: see ``tests/test_rule9_binding.cpp``.

What declining does *not* mean is shipping a stub that reports "verified". If
your deployment issues DPoP-bound tokens, guard those endpoints with an SDK
whose §21.9 row says it verifies proofs (Rust, Go, Python, TypeScript, …), or
verify the proof ahead of this SDK and pass only the certificate half here.

### §15.7 — external-IdP subject tokens

The same call exchanges a token minted by a **trusted external IdP** — a
partner's Entra, Okta or Keycloak — for an AXIAM token scoped to what the
resolved AXIAM user may actually do. There is no separate operation:

```cpp
axiam::TokenExchangeParams params;
params.subject_token      = axiam::Sensitive<std::string>(partner_token);
params.subject_token_type = axiam::kJwtTokenType;   // required; named, never guessed
params.audience           = "https://orders.internal";

const auto exchanged = client.token_exchange(params);
```

- **`subject_token_type` is yours to state, and is required** (§15.1). The SDK
  never decodes the subject token to pick it, and never overrides what you
  named. There is no default: an empty value throws `AuthError` client-side
  with no wire call, because a default would be the SDK choosing for you. Pass
  `kAccessTokenType` for the same-domain exchange.
- **No actor token.** Delegation across a trust boundary is unsupported in v1;
  sending one is `invalid_request`, which the SDK will not work around by
  dropping it and re-sending.
- **One refusal is distinguishable.** `invalid_grant` whose
  `error_description()` is `the subject token's issuer is not configured for
  token exchange` means *fix the AXIAM trust configuration*. Every other
  `invalid_grant` means *fix your token*, and is deliberately generic.
- **Forward the result as-is.** It carries an `ext_exchange` claim naming the
  partner issuer; never strip it, and never read it as an authorization input.
  It also cannot be exchanged again — exchanges do not compose.

The operator guide is `docs/api/federated-token-exchange.md`.

## §24 WebAuthn / passkeys

The six relying-party wire operations plus [§24.6a](CONTRACT.md)'s JSON bridge.
What is **not** here is §24.6b's linked-API ceremony helper, and the reason is
not effort: a C++ program has no authenticator. There is no platform API to link
on the targets this SDK serves, and §24.6b rule 2 forbids emulating one in
software — a "credential" held in process memory is not a second factor.

That is a statement about convenience, not capability. The bridge is the whole
interface, and it is enough for every integration this SDK actually sees: an
embedded gateway fronting a browser, a native app talking to a C++ service, a
test harness driving a virtual authenticator.

```cpp
const auto challenge = client.webauthn_register_start();   // needs a session

// §24.6a rule 1: the INNER options object. The `publicKey` wrapper belongs to
// the DOM's CredentialCreationOptions; the platform JSON APIs do not want it.
const std::string response =
    your_platform_runs_the_ceremony(challenge.request_json());   // verbatim

const auto credential =
    client.webauthn_register_finish(challenge.state_token, "Ada's laptop", response);
```

**The server owns the options, and the SDK owns nothing (§24.0).** Nothing in
this surface defaults a field, validates one, or re-encodes a buffer. The
challenge is lifted out of the response body as **raw text** rather than as a
`json` node — `nlohmann::json` stores object members in a `std::map`, so a
parse-then-dump round trip comes back *sorted*, and what the caller would hand
the authenticator is no longer what the server sent. The authenticator's response
travels the same way: spliced into the request body as text, never parsed into a
model and printed back out. A signed buffer that makes a round trip through a
JSON model is a signed buffer that can come out different, and the server's
signature check is what notices. The one thing checked client-side is that the
response IS a JSON object, because the SDK will not POST a body it already knows
the server cannot verify.

**Two ceremonies, not one with a flag (§24.2).**
`webauthn_authenticate_start()` is a *second factor*: it continues a login that
answered `mfa_required`, so it requires that login's challenge token.
`webauthn_discoverable_start()` is a *primary factor*: nothing precedes it,
`allowCredentials` comes back empty, and the assertion itself identifies the
user — which is why it is the one WebAuthn endpoint carrying the workspace
explicitly, and why it accepts slugs where the five `/oauth2` operations of §12.1
rule 2 do not. Both `*_finish` calls sign the client in and clear the §17
decision memo (§24.3).

**Two error cases are not the generic §2 mapping (§24.4).** A `403` on
`register/finish` carries the tenant's attestation-policy message, and that
message is surfaced in the thrown `AuthzError` — "authorization denied" tells the
person holding the key nothing they can act on. A `503` on `register/start` is
**not retried**: it means the policy needs FIDO metadata the server cannot reach,
which is a configuration state, not a transient one.

**The failure classification is required even without a ceremony helper**
(§24.6b rule 5). Whatever *did* run the ceremony reports its failure as one
opaque type whose only machine-readable part is a name;
`axiam::webauthn_classify()` translates it once, and never fails — an
unrecognised name, including an empty one, is `WebauthnFailure::kUnknown`. Note
that `kCancelled` covers **both** an explicit refusal and a silent timeout: the
spec deliberately refuses to distinguish them, because telling a website which
one happened leaks whether an authenticator was present. Copy that says "you
cancelled" is wrong half the time it is shown, and
`axiam::webauthn_failure_message()` does not say it.

Worked example: [`examples/webauthn_passkeys.cpp`](examples/webauthn_passkeys.cpp).

## §25 Account lifecycle and MFA enrolment

Ten operations covering voluntary and forced TOTP enrolment, email
verification, the two resends, and the password-reset triple.

**Six of the ten are deliberately unauthenticated.** A user who cannot log in
is the entire audience for a password reset, and a user whose email is unverified
may have no session at all.

```cpp
const auto enrollment = client.mfa_enroll();
render_qr(axiam::detail::reveal(enrollment.totp_uri));   // BOTH halves are Sensitive
const bool enabled = client.mfa_confirm(code_the_user_typed);
```

**The otpauth URI is the field that actually leaks (§25.3).** It *contains* the
secret, so wrapping `secret_base32` and leaving `totp_uri` a plain string wraps
nothing: the URI is the one you hand to a QR renderer, and therefore the one that
ends up in a log. Both are `Sensitive<std::string>`.

**`mfa_enroll()` does not clear the decision memo (§25.2 rule 3).** The subject
has not changed — offering a factor is a profile action — and discarding a warm
§17 memo over it costs a round trip on every authorization check that follows.
`mfa_setup_confirm()` *does* clear it, because that call **is** the completion of
a login (§25.2 rule 2) and adopts credentials exactly as `login()` does.

**Login has three outcomes now, not two.** `LoginResult` gained
`mfa_setup_required` and `setup_token` — **additive**, because this type is a
flags struct rather than a discriminated union, so an existing caller still
compiles. When the tenant requires MFA and the account has none, the setup token
**is** the credential for `mfa_setup_enroll()` and `mfa_setup_confirm()`; there
is no session yet.

**There is no one-call enrolment helper, and there must not be** (§25.2 rule 4).
The human step in the middle — read the QR code, type six digits — is not
something a helper can wait for.

**Where the tenant goes.** `verify_email`, `resend_verification` and
`confirm_password_reset` take it as a **body** field. These are not `/oauth2`
endpoints, so §12.1 rule 2's query-parameter convention does not reach them, and
putting it in the query earns a `400` that reads exactly like a bad token.

**Password reset discloses nothing (§25.4).** `request_password_reset()` returns
normally whether or not the address exists, and this SDK exposes no way to tell
the two apart. Call `password_reset_context()` before choosing a password path: a
tenant in `opaque_mode: required` refuses a plaintext password, and refuses it
*late* — by which point the user has typed one. A `404` from that call means
unknown, expired **or** already-consumed, deliberately indistinguishable; do not
invent a distinction the server refused to make.

### Two resends, and why neither replaces the other (§25.7)

```cpp
// No session — a sign-up screen. Returns normally whatever happened; that is the point.
client.resend_verification("alice@example.com", tenant_id);

// Signed in — a profile page. Says what happened, and names no address.
try {
    client.resend_own_verification();
} catch (const axiam::AuthzError&) {
    // 409: already verified, or an account state that must not be sent a live token.
} catch (const axiam::NetworkError&) {
    // 429: the daily resend limit.
}
```

They look like one operation and are not. `resend_verification()` takes an
address from an **anonymous** caller, so it must answer identically whether the
address exists, is already verified, or is rate-limited — anything else is an
oracle for which addresses have accounts. `resend_own_verification()` is asked by
a caller already signed in to the account it is asking about, so none of those
outcomes discloses anything it did not bring with it, and this one tells the truth.

**Neither is routed to the other**, in either direction, and this SDK does not
fall back from the authenticated one to the public one on a `409` or a `429`:
that fallback turns both failures back into a silent success and restores the
exact bug §25.7 describes, with an extra round trip. The signed-in one takes
**no address parameter and sends no address field** — a parameter here would let
an authenticated session mail an arbitrary one. With no session it throws
`AuthError` client-side, with no wire call.

Returning means the mail was **enqueued**, not delivered. Delivery is
asynchronous and can still fail at the provider.

### Organization-level principals (§5.2)

`UserInfo` gained `organization_level`. It is true when the account that signed
in is an **organization-level** principal — one whose record lives in its
organization's reserved tenant, so its global grants apply in every tenant of
that organization and it can act on a different one by sending a different
`X-Tenant-ID` on the next request, with no re-login.

```cpp
const auto login = client.login(email, password);
if (login.user && login.user->organization_level) {
    // Offer the tenant selector.
}
```

An ordinary tenant principal is a principal of exactly one tenant; the same
header change produces a `403` for it. The flag is therefore what an application
checks *before* offering a tenant switch, rather than discovering the answer from
a failed request.

It is **derived, never asserted** (§5.2 rule 2): resolved server-side from the
caller's own tenant record, and never sent by this SDK. It is `false` when the
login response omits it — what a server older than contract 1.31 answers — and
`false` when the value is anything but the JSON literal `true`. Both are the safe
direction. The member is appended last and defaulted, so every existing aggregate
initializer of `UserInfo` still compiles.

#### Signing one in (§5.2.1)

The reserved tenant has a fixed slug, `organization`, the same in every
deployment — so signing in as an organization-level principal needs no new
surface, only the ordinary builder:

```cpp
Client c = Client::builder()
               .base_url("https://iam.example.com")
               .tenant_slug("organization")
               .org_slug("globex")
               .build();
c.login("root@example.com", password);
```

Prefer that form. The server also reads a login body naming *no* tenant as "the
organization's own scope", but §5 rule 2 still requires a tenant on the
`X-Tenant-ID` header of every request after the login, so the client needs one
either way.

What §5.2.1 forbids is the third possibility: an empty-string slug. Nothing can
carry one, so `tenant_slug: ""` resolves nothing — and on
`/auth/opaque/login/start` it fails on the workspace *before* the tenant's
OPAQUE mode is read, so the `404` that means "OPAQUE is not offered here" never
arrives and this SDK has no fallback to take. Sign-in then fails even against a
tenant with OPAQUE disabled.

`build()` refuses a blank `tenant_slug`, `tenant_id` or `org_slug`. The §5 check
above is not enough on its own: an engaged `std::optional<std::string>` holding
`""` satisfies `has_value()`, so it passed, and the empty slug reached the wire.

Worked example: [`examples/account_lifecycle.cpp`](examples/account_lifecycle.cpp).

## §26 Pushed Authorization Requests (RFC 9126)

PAR moves the authorization request off the browser. Instead of putting `scope`,
`redirect_uri`, `state` and the PKCE challenge into a URL the user agent carries,
the client POSTs them straight to AXIAM over an authenticated back channel and
puts an opaque handle in the redirect. What travels through the browser is then a
random string that cannot be edited into meaning something else. **Required for a
FAPI 2.0 client**: `profile: "fapi2"` refuses a registration that does not set
`require_par` (§21.1).

```cpp
const auto doc = client.oidc_discover();
if (!doc.pushed_authorization_request_endpoint) { /* this server has no PAR */ }

const auto request = client.oidc_begin(doc, redirect_uri, "openid profile");
const auto pushed  = client.oidc_par(doc, request, redirect_uri, "openid profile");
// pushed.url carries exactly client_id and request_uri — nothing else.
```

**The server answers `201`, not `200`.** RFC 9126 §2.2 specifies Created, and a
success predicate written `== 200` treats every successful push as a failure
while passing every other check.

**The redirect carries exactly two parameters (§26.2 rule 2).** AXIAM refuses a
request that mixes a `request_uri` with inline authorization parameters rather
than merging them, because merging is where parameter confusion lives: an
attacker supplies the inline value they want and lets the pushed copy satisfy
whichever check reads the other one. Re-adding `scope` "for compatibility"
restores the attack — which is why any query the *discovered* authorization
endpoint already carried is dropped here rather than merged.

**One generator, not two (§26.2 rule 1).** The push sends the `state`, `nonce`
and PKCE pair `oidc_begin()` produced, and hands them back out on the result so
the caller has one object to persist. Two sources for those values are two things
that can disagree, and when they do the failure surfaces at the exchange as an
opaque `invalid_grant` a long way from the code that caused it.

**Never retried (§26.2 rule 4).** It is a POST that creates server state, so it
falls outside §16.2's read-only eligibility exactly as `oidc_exchange` does. The
safe recovery is a fresh push: one round trip, and it cannot double-consume
anything. The `request_uri` is single-use, short-lived (`expires_in` is not
advisory) and `Sensitive` — between the push and the redirect it is a bearer
handle to a fully-formed authorization request.

**Never synthesised.** A server that does not advertise
`pushed_authorization_request_endpoint` does not have it; `oidc_par()` throws
`AuthError` client-side with no wire call rather than guessing `/oauth2/par` and
producing a 404 that reads like a broken request.

Worked example: [`examples/par_login.cpp`](examples/par_login.cpp).

## §22 Reactors — the protocol core over your own transport

A **reactor** is an external service AXIAM consults synchronously at five points
in its own flows: it may veto a login, enrich a token, or adjust a user before
creation. This SDK ships §22.1–§22.8 and §22.14 in full — the §8 v2 verification
set on the event, the canonical serialization and MAC in both directions, the
§22.5 registry and its allow-lists, §22.8's strictest-wins default, the runtime,
and the declarative binder.

**What it does not ship is a connection.** §22.11 defers the transport, and only
the transport:

> the convenience that genuinely needed a vendored dependency was the
> **connection**, and the runtime around it needed none.

Until contract 1.28 this SDK shipped nothing from §22 at all while the section
still bound an integrator to §22.1–§22.8. The half deferred for want of a
*dependency* was the transport; the half every integrator was left to hand-roll
from prose was the **protocol** — v2 HMAC over a canonical serialization with a
`null` signature placeholder, freshness in both directions, nonce and correlation
binding, the per-event allow-lists. That is the half with the sharp edges, none
of them AMQP-shaped, and asking every integrator to reimplement it is how a
signing bug ships.

```cpp
// §8b rules 1–5, BEFORE anything opens a socket. A public, tested function
// rather than a doc comment — §22.11 rule 3.
const auto endpoint = axiam::amqps_endpoint(broker_url, ca_pem);

// §22.14: one handler per event. An unregistered name is refused AT BIND TIME.
axiam::ReactorRouter router;
router.on(axiam::kReactorEventLoginPostAuth, [](const axiam::ReactorEvent& e) -> axiam::ReactorAnswer {
    return suspicious(e.payload_json) ? axiam::ReactorDecision::allow_with_step_up()
                                      : axiam::ReactorDecision::allow();
});

axiam::ReactorConfig config{tenant_id, reactor_id, axiam::Sensitive<std::string>(subkey)};
axiam::reactor_serve(config, your_transport, router.build());
```

**The transport interface has exactly two capabilities** (§22.11 rule 1): take
the next delivery, and publish a reply to a named destination. It is not wider
than that on purpose — an interface that also exposed declare, bind or queue-name
derivation would hand you the tools §22.1 forbids using. A reactor that can bind
is a reactor that can bind itself to `*.token.pre_issue` and read another
tenant's issuance events.

**It fails closed on its own errors** (§22.10 rule 2). A handler that throws, a
body it cannot verify, or a window that has closed all produce **no reply**, and
the registration's `failure_policy` decides. A runtime that answered `allow` for a
handler that crashed would have overridden the operator's `fail_closed` setting
from inside the library — which is exactly the defect §22.14 exists to keep out
of *user* code too, where a `default:` arm returning `allow()` does the same thing
from a file nobody reads. An unbound event abstains.

**It does not filter a patch** (§22.4 rule 1). One forbidden key rejects the
whole patch server-side, including the fields that would have been fine — and
dropping the offender to rescue the rest would leave the author believing a field
was set when it was dropped. `reactor_patch_field_allowed()` will *tell* you what
the registry admits; nothing in this SDK calls it to prune anything.

**The three hot-path decision operations are not hookable** (§22.7), and they
appear in no constant here. A reactor round trip is milliseconds; the check path's
budget is microseconds. An application needing external input on an authorization
decision writes a **deny grant**, which the engine evaluates in the hot path at
hot-path cost.

Correctness is not asserted against this implementation's own opinion: the suite
runs the committed **§22.13 reference vectors**, generated by the server's own
sign path, in both directions. Worked example, including a transport skeleton:
[`examples/reactor/`](examples/reactor/README.md).

## §27 Management API

147 operations across 24 namespaces, reached through namespace handles that sit
directly on the client — the form §27.3's C++ row specifies:

```cpp
#include "axiam/management.hpp"   // opt-in; the umbrella header does not pull it in

auto page = client.roles().list();
std::cout << page.size() << " on this page, " << page.total << " in the tenant\n";

axiam::management::CreateRoleRequest req;
req.name = "editor";
req.description = "Read and write documents";
req.is_global = false;
const auto role = client.roles().create(req);

// Or reach the same 24 handles behind one accessor (§27.2 rule 4), which reads
// better where a call site is already dense with §1 operations:
auto mgmt = client.management();
const auto same = mgmt.roles().list();
```

The two forms are **equivalent** — rule 4 requires it, the direct accessors
forward to `management()` so it is structural rather than a promise, and the
suite asserts it per namespace by comparing the method and path each actually
puts on the wire.

Everything below the handles is **generated** from the vendored
`management-registry.json` and `openapi.json` by
[`scripts/gen_management.py`](scripts/gen_management.py), and the output is
committed so building this library needs no code-generation step and no Python.
CI re-runs the generator with `--check` and fails on any drift, which is what
makes committed generated code trustworthy rather than merely convenient.

**It sits on the SDK's existing request path** (§27.8), not beside it. Every
operation inherits §5's tenant/org headers, §6's TLS floor, §9's single-flight
refresh, §16's retry policy and §19's telemetry by construction. An SDK whose
management layer opened its own connection would have 147 endpoints outside its
own refresh guard; the suite asserts against that by driving the fake transport
at the bottom of a real client, so a §27.8 violation fails the tests rather than
passing them.

### The four rules worth knowing before you write against it

**Paging does not lie (§27.4 rule 4).** `Page<T>::total` is the server's count
across every page; `size()` is how many are in your hand. They are separate
members and neither is derived from the other, because deriving one from the
other is how a management tool silently reports the first fifty of four hundred
rows. Auto-paging stops on an **empty** page, never a short one — a server may
return fewer rows than asked for and still have more. A bare JSON array response
is not a page and is never modelled as one; those operations return
`std::vector`.

**Searching a list (§27.4 rule 4).** All twenty paginated operations take an
optional free-text term, matched case-insensitively by the **server** against the
identifying fields of whatever is being listed — a name or username, plus the
record id, so a UUID pasted out of a log line finds its row. `total` then counts
*matches*, not rows.

```cpp
axiam::management::PageRequest page;
page.search = "ada";
const auto matches = client.users().list(page);

for (auto req = page; ; ) {              // the whole walk stays filtered
    const auto batch = client.users().list(req);
    if (batch.empty()) break;
    // ...
    req = batch.next_request();          // next() carries the term
}
```

The term lives on `PageRequest`, beside `offset` and `limit`, rather than as an
extra argument on twenty `list` methods. That is what makes the walk above work
at all: an argument has nowhere to live between one request and the next, so a
walk built on one would return the matches followed by the unfiltered tail.

An empty or all-whitespace term is the **same request** as none: no `search`
parameter is sent at all — a search box that fires on every keystroke sends one
the moment it is cleared, and "rows containing the empty string" is a different
question from "all rows". `PageRequest::normalize_search()` is that
normalisation, exposed because it is the one piece a caller can observe going
wrong. The term is trimmed but never **truncated**: the server caps its length,
and a client-side cap the server would not have applied is a silently different
query.

**Enums are open (§27.11 rule 1).** Every generated enum carries a trailing
`Unknown` enumerator, and `*_from_wire()` returns it for a value this SDK's copy
of the spec does not list rather than throwing. Throwing failed the *whole*
response, so one field of one record would take down the page it arrived on —
including the records the caller did ask for.

It is never mapped to one of the **known** enumerators: reading a new value as
whichever enumerator happens to be first turns a new server state into a wrong
one, and on this surface these values gate access. `to_wire(Unknown)` is the
empty string — which no server value is, so carrying an unrecognised value back
into an update is refused by the server rather than written as a spelling it
never used. **A `switch` over one of these enums needs an `Unknown` arm:**

```cpp
switch (*tenant.kind) {
    case TenantKind::Organization: /* the organization's own scope */ break;
    case TenantKind::Standard:     /* an ordinary tenant */          break;
    case TenantKind::Unknown:      /* a kind this SDK predates */    break;
}
```

`Certificate::bound_service_account_id` is a **projection**, not a member of the
certificate: the server resolves it for a whole page in one query, so
`certificates().list()` populates it and `certificates().get(id)` leaves it
empty. Empty there means "this read does not carry it", not "there is nothing
bound" — the SDK does not issue a second request to fill it in, because a `get`
that silently costs two round trips is the behaviour §27.4 rule 3 forbids for
slug resolution, for the same reason (§27.11 rule 4).

**Re-scoping returns a new handle (§27.4 rule 3).** `in_org()` and
`for_tenant()` hand back a fresh handle rather than repointing the one you called
them on. On a read surface that mistake reads the wrong tenant; on this one it
*writes* to it.

**Sparse means absent, not null (§27.4 rule 5).** An update model's optional
members are omitted from the body when unset, so a field you did not touch keeps
whatever the server holds. Replacement models require every field. They are
distinct types, so the two cannot be confused by accident.

**The error map is not where you would guess (§27.4 rule 7).**

| Status | Type | Parent | Why |
|--------|------|--------|-----|
| 404 | `NotFoundError` | `AuthzError` | AXIAM answers 404 for an object in another tenant *precisely so* a probing caller cannot tell "does not exist" from "exists, not yours". Classifying it as an authorization outcome keeps the SDK from re-drawing a line the server deliberately refused to draw. |
| 409 | `ConflictError` | `AuthzError` | §2 already mapped 409 there; rule 7 keeps that mapping rather than moving it. |
| 400, 422 | `ValidationError` | `NetworkError` | Inherited from §2's 400 row. §16 retries `NetworkError`, so this type is explicitly excluded from retry — a body the server has already rejected does not get sent three times. |

Catch order matters: a `catch (const AuthzError&)` placed first swallows the
first two.

### One-time secrets (§27.5)

`ServiceAccountCreatedResponse::client_secret`, `RotateSecretResponse`,
`GeneratedCertificate::private_key_pem` and the rest are `Sensitive<T>`. They
render **redacted** everywhere — every stream insertion, every log line — and
still reach the wire. Getting the bytes out is deliberate and narrow:
`axiam::detail::reveal()`, at the one point of use. The server returns them once
and stores nothing, so if you do not persist one when it goes past, nobody can
recover it.

### Declarative manifests (§27.6/§27.7)

The imperative surface is fine for one change and a poor way to describe a
*tenant*. A manifest is re-runnable by construction:

```cpp
#include "axiam/management_manifest.hpp"

const auto manifest = AXIAM_MANIFEST(
    AXIAM_RESOURCE(.key = "root", .name = "documents", .resource_type = "folder"),
    AXIAM_PERMISSION(.key = "read", .name = "documents:read", .action = "read"),
    AXIAM_ROLE(.key = "editor", .name = "editor", .description = "Edits documents"),
    AXIAM_GROUP(.key = "editors", .name = "editors", .depends_on = "editor"));

auto manifests = client.management().manifest();

const auto plan = manifests.plan(manifest);   // reads only; safe against production
if (!plan.converged()) {
    const auto report = manifests.apply(manifest);
    for (const auto& line : report.describe()) std::cout << line << "\n";
}
```

`AXIAM_MANIFEST(...)` and its four entity macros are §27.7's C++ form —
designated-initializer aggregate specs over `ManifestEntity`, which is a plain
aggregate with a default for every member. They are sugar: a manifest built this
way and one deserialized from a config file are the same value and go through the
same `plan`/`apply`. A declarative form that talked to the network itself would be
a second implementation of §27.6, and the two would disagree.

Four properties, all load-bearing:

- **`plan()` writes nothing.** Safe in CI, safe on a schedule, safe against a
  live tenant.
- **`apply()` stops at the first failure and does not roll back.** The
  `ApplyReport` names what landed, what failed and what was never attempted, so a
  partial apply is a state you resume from. An automatic rollback would fire a
  second wave of writes at the moment the server is telling you something is
  wrong.
- **Ordering is derived, not declared** — by kind, then dependency, then key. The
  final tie-break on key is what makes a plan stable across runs, and therefore
  readable as a diff.
- **Omission is never deletion.** `ChangeAction` has no `Delete` member at all,
  so an incomplete manifest cannot become a destructive one.

Incoherence is refused *before the first request*: a duplicate key, a
`depends_on` naming nothing, or a dependency cycle throws `ManifestError` from
`validate()`, which `plan()` calls itself. Discovering that halfway through, with
no rollback, is strictly worse.

### Worked examples

- [`examples/management_basics.cpp`](examples/management_basics.cpp) — paging,
  per-call scope, a sparse update, and the three error sub-types.
- [`examples/management_manifest.cpp`](examples/management_manifest.cpp) — plan
  and apply over a manifest built with the `AXIAM_MANIFEST` form.
- [`examples/device_mtls_provisioning.cpp`](examples/device_mtls_provisioning.cpp)
  — the flow the certificate namespaces exist for, end to end: create a service
  account, issue a device certificate from the tenant signing CA, bind it, mark
  the CA an mTLS trust anchor, then authenticate as the device over §6.1 mTLS
  with a second client. This is the one place a §27.5 one-time secret has to be
  caught as it goes past.

## Deferred / follow-ups

- **gRPC transport** (Tonic-parity authz checks). The §6.1 "both transports" rule
  applies once gRPC lands; the REST client already isolates TLS material for reuse.
- **§8 AMQP HMAC consumer** (not required of C++ by the contract).
- **A bundled AMQP client**, and only that. §22.11 keeps the transport deferred:
  there is no maintained AMQP client for these targets this project is willing to
  vendor, which is the same reason §8 has never listed C++ among the SDKs that
  speak AMQP. The **protocol** is no longer deferred with it — see
  [§22 Reactors](#22-reactors-the-protocol-core-over-your-own-transport) — so what
  remains is implementing `axiam::ReactorTransport` over the client you choose.
  Revisit when a vendorable client exists; the wire protocol will not need to
  change for it, and now neither will the runtime.
- **The optional `OidcStateStore`** (§12.3 rule 1). The core §12 operations are
  usable without one and the store is a MAY; a C++ reference implementation with
  the mandated 10-minute TTL, single-use `consume`, and lazy (never
  timer-driven) expiry is a follow-up.
- Framework adapter samples for Crow / Pistache (the guard interface is already
  framework-agnostic).
