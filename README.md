# AXIAM C++ SDK

[![CI](https://github.com/ilpanich/axiam-cplusplus-sdk/actions/workflows/sdk-ci-cpp.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-cplusplus-sdk/actions/workflows/sdk-ci-cpp.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-cplusplus-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-cplusplus-sdk?branch=main)
[![Docs](https://img.shields.io/badge/docs-Doxygen-blue.svg)](https://ilpanich.github.io/axiam-cplusplus-sdk/)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Idiomatic C++17 client for [AXIAM](https://github.com/ilpanich/axiam) (Access
eXtended Identity and Authorization Management) — authentication, authorization
checks, JWKS verification, and framework-agnostic route guards.

**This SDK conforms to CONTRACT.md §1–§7, §9–§13, §14, §15, §16–§19, §20, §21 and §23 (including §6.1 mTLS, §12.7 logout, the §11 rule 9 decision reason codes, and the §23 SRP-6a login path — conditional on OpenSSL ≥ 3.2 for Argon2id, see below).**

> Scope note: this v1 covers the REST surface. **gRPC** — including the gRPC-only
> `get_user_info` operation (CONTRACT §1.1, contract 1.3) — and **§8 AMQP HMAC** are
> intentionally out of scope for v1 (the cross-language contract does not require
> AMQP of C++); see [Deferred / follow-ups](#deferred--follow-ups). Per §1.1 the REST
> `/oauth2/userinfo` endpoint is not substituted for the gRPC operation.

- Namespace: `axiam` — library target `axiam_cpp` (CMake `axiam::axiam_cpp`).
- Public headers under `include/axiam/`; umbrella header `#include <axiam/axiam.hpp>`.
- Dependencies: **libcurl** (HTTP + strict TLS + mTLS), **OpenSSL** (Ed25519 JWKS
  verification), vendored single-header **nlohmann/json** (`third_party/nlohmann/json.hpp`).
- Version: `1.0.0-alpha31`.

---

## Install

### CMake (FetchContent)

```cmake
include(FetchContent)
FetchContent_Declare(axiam_cpp_sdk
  GIT_REPOSITORY https://github.com/ilpanich/axiam-cplusplus-sdk.git
  GIT_TAG        v1.0.0-alpha31)
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
conan create . --version=1.0.0-alpha31
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

## Secure Remote Password (§23)

`login_srp()` proves the password to the server without the password — or
anything from which it can be cheaply recovered — ever crossing the wire. The
server stores a **verifier** `v = g^x mod N` instead of a password hash, and
what travels is `A` and a proof, neither of which is useful without that
verifier.

```cpp
axiam::LoginResult result = client.login_srp("alice", password);
```

It takes the same arguments as `login()` and returns the same `LoginResult`,
MFA branch included, so switching a tenant to SRP needs no change to how the
result is handled. A runnable end-to-end example, including the fallback and the
enrolment call, is [`examples/srp_login.cpp`](examples/srp_login.cpp).

### What this buys, and what it does not

SRP closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh sees
  every plaintext password today; under SRP it sees `A` and `M1`;
- an accidental request-body log, a heap dump or a crash reporter can no longer
  capture a plaintext password, because the server never has one;
- a leaked verifier database still costs a full KDF evaluation per candidate
  password, exactly as a leaked Argon2id database does.

It does **not** protect against a compromised AXIAM server, and this SDK does
not claim it does.

### Conditional on your OpenSSL: Argon2id needs 3.2

The arithmetic is `BN_mod_exp`, available in every OpenSSL this SDK links
against, and PBKDF2-HMAC-SHA256 comes from `PKCS5_PBKDF2_HMAC`, likewise. But
**Argon2id arrives as an `EVP_KDF` only in OpenSSL 3.2**, and it is what a
default-configured AXIAM tenant names.

```cpp
if (!axiam::srp::argon2_available()) { /* cannot serve an argon2id tenant */ }
```

`srp::argon2_available()` fetches the KDF rather than reading a version macro,
because a macro answers for the headers this was *compiled* against rather than
the libcrypto it is *running* against, and those differ routinely where OpenSSL
is shared. When the KDF is absent, `login_srp()` throws `NetworkError` naming it
— it never substitutes PBKDF2, which would derive a different `x` and surface as
"invalid password", the single most misleading failure this code could produce.

`Client::srp_available()` is the §23.1 capability probe and is unconditional
here; the Argon2 probe is the one that can say no.

### Tenant policy, and the errors that are not credential failures

`srp_mode` is an organization baseline a tenant may tighten:

| mode | `login()` | `login_srp()` |
|---|---|---|
| `disabled` (default) | works | `NetworkError` — the endpoint answers `404` |
| `optional` | works | works |
| `required` | `AuthzError` (`srp_required`) | works |

Neither is an `AuthError`:

- `NetworkError` from `login_srp()` means *this tenant does not offer SRP*, or
  *this build cannot do the KDF it named* — a property of the tenant or the
  build, never of any user. Fall back to `login()`.
- `AuthzError` from `login()` means *this tenant refuses password login*. The
  credentials were never examined. Telling a user their perfectly good password
  is invalid is the failure this mapping exists to prevent.

`required` refuses **every** principal in the tenant, not only the enrolled
ones. Splitting the response on whether an account has a verifier would turn
`/auth/login` into an enumeration oracle costing one junk password per name. It
also means `required` locks out anyone not yet enrolled: a verifier needs the
plaintext password, and a stored Argon2id hash is not invertible, so nobody can
be enrolled retroactively. Operators turn it on last, after a password-reset
campaign.

### Enrolment

The server cannot compute a verifier, so any request that **sets** a password
has to carry one. `srp_enrollment()` produces the `srp` object for
`POST /api/v1/users`, `/auth/password/change`, `/auth/reset/confirm` and
`/admin/bootstrap`:

```cpp
axiam::SrpEnrollment enrolment = client.srp_enrollment(
    "alice",                       // the USERNAME, not an email — see below
    new_password,
    std::nullopt,                  // nullopt = the tenant default group
    axiam::SrpKdfParams{axiam::SrpKdfParams::kPbkdf2Sha256, 0, 0, 0});  // 0 = AXIAM's costs
```

The identity must be the account's **username**: `x` is derived over
`identity ":" password` using the identity the challenge endpoint hands back, so
a verifier enrolled against an email address can never satisfy a login. For the
same reason, **renaming a user invalidates their verifier** — the server clears
it, and the user re-enrols at their next password change.

The salt is 32 fresh bytes from `RAND_bytes` on every call.

### Cost

`login_srp()` runs the tenant's KDF: Argon2id at 19 MiB and t=2 by default,
which is tens to hundreds of milliseconds of CPU plus that memory, per login
attempt. That cost is the point — it is what makes a leaked verifier no cheaper
to attack than a leaked Argon2id hash. It is synchronous and blocking; size your
request handling accordingly, since `login()` has no such cost.

### Cryptographic parameters

RFC 5054 Appendix A groups `rfc5054_2048`, `rfc5054_3072` and `rfc5054_4096`
(the AXIAM default), embedded as constants. A modulus is **never** accepted from
the server — a server-supplied `N` is a server-supplied trapdoor — and a group
this SDK does not recognise is refused rather than guessed.

Two deliberate divergences from RFC 5054, both AXIAM-wide: `H` is **SHA-256**,
not SHA-1; and `x` is a **memory-hard KDF output**, not a bare hash, because RFC
5054's bare-hash `x` would make a leaked verifier *cheaper* to attack offline
than the Argon2id hashes AXIAM already stores.

### Zeroization

§23.3 rule 8 requires clearing what can be cleared, and C++ is a language where
it can be. `x`, `S`, `K` and the joined `identity ":" password` are
`OPENSSL_cleanse`d before their buffers are released; every `BIGNUM` uses
`BN_clear_free`; the session's ephemeral `a` is wiped in the destructor **and**
in the move operations, because a move of a short string is a copy and the
moved-from buffer would otherwise still hold it. The suite runs clean under ASan
and UBSan with leak detection on.

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

## Deferred / follow-ups

- **gRPC transport** (Tonic-parity authz checks). The §6.1 "both transports" rule
  applies once gRPC lands; the REST client already isolates TLS material for reuse.
- **§8 AMQP HMAC consumer** (not required of C++ by the contract).
- **§22 reactor runtime.** No `reactor_serve` here, for the same reason: §22.11
  defers the *runtime helper* on Swift, C and C++ because there is no vendorable
  AMQP client for these targets. **That is a scope decision about the helper, not
  a statement that reactors are unavailable to you.** §22.1–§22.8 is a wire
  protocol, so an integrator hand-rolling a reactor against a third-party AMQP
  client MUST satisfy every normative rule in it — the §8 v2 verification set on
  the event, the signed reply shape with its omission rules (note that
  `hmac_signature` serializes as **`null`** inside a reactor body rather than
  being omitted as it is in §8's own two message types), the per-event
  mutable-field allow-lists, and §22.7's hot-path exclusion. The §22.13 vectors
  are the conformance surface and need no SDK to run against. Start from
  [§22 and §22.11 of `CONTRACT.md`](CONTRACT.md) and the non-normative sample in
  [`examples/reactor/`](examples/reactor/README.md), which checks itself against
  those vectors.
- **The optional `OidcStateStore`** (§12.3 rule 1). The core §12 operations are
  usable without one and the store is a MAY; a C++ reference implementation with
  the mandated 10-minute TTL, single-use `consume`, and lazy (never
  timer-driven) expiry is a follow-up.
- Framework adapter samples for Crow / Pistache (the guard interface is already
  framework-agnostic).
