# Changelog

All notable changes to the AXIAM C++ SDK are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
semantic versioning (pre-release track `1.0.0-alpha*`).

## [Unreleased]

### Fixed

- **The transport now performs requests concurrently (D2).** Benchmark runs 4
  and 5 both measured `check_access` at p50 3.2 ms against p95 280 ms — a tail
  this SDK's own acceptance bar (p95 ≤ 3× p50) rejects, and one the run-4
  connection-lifetime work (`MAXAGE_CONN`, Happy-Eyeballs, TCP keepalive) did
  not move. It was never the wire. `CurlTransport::perform` held a mutex over a
  **single** libcurl easy handle, so a `Client` shared across threads served
  requests strictly one at a time: p50 was the uncontended service time, p95
  was fifteen callers queueing — and because `std::mutex` barges rather than
  queues fairly, the tail was heavy rather than merely 16× the median, which is
  why the shape reproduced identically across runs.

  The transport now keeps a pool of easy handles, one per in-flight request,
  each with its own hot connection. Cookies, DNS and TLS session state are
  shared across them through libcurl's `CURLSH`, so the §4 session semantics
  are preserved exactly — a request served by any handle carries the same
  session. Connections are deliberately *not* shared: a shared connection cache
  would put every handle back behind one lock at acquisition time.

### Added

- **`Client::Builder::max_concurrent_requests(unsigned)`** (default 16) — how
  many requests a client may have in flight. Callers beyond the cap wait for a
  handle rather than opening unbounded connections to the server. Ignored when
  a custom `transport()` is supplied.
- `tests/test_transport_concurrency.cpp`: a loopback server that holds each
  request open long enough for its siblings to arrive, asserting the server
  observes more than one request in flight (structural, so it cannot flake on a
  loaded CI box the way a timing assertion would) and that a client capped at 2
  never exceeds 2.

## [1.0.0-alpha24] - 2026-08-04

### Added

- Safe-by-default authenticator, webhook verifier, https-only base URL, keep-alive transport

### Changed

- Add the §10.1 rule-8 guardrail regression tests (#13)
- Device (mTLS) tokens now carry aud=axiam:m2m (#12)
- Service accounts can use login_client_credentials (#11)
- Add ASan+UBSan and valgrind gates (§13.4 observation 10 / §12.6.1) (#10)

### Fixed

- Bound the verification clock skew and fix base64url UB (§10.1)

## [Unreleased]

### Added

- **ASan+UBSan and valgrind CI job (§13.4 observation 10 / §12.6.1).** `OBS-4`
  was a signed-integer overflow — undefined behaviour — in **this repository's**
  base64url decoder, on the token-decode path, and it survived three security
  passes because the only CI legs here were gcc/clang builds plus coverage. An
  ordinary build does not report UB, so nothing was ever going to catch it; it
  surfaced only because a sanitizer run was done by hand.

  The new job runs the suite under ASan+UBSan with `-fno-sanitize-recover=all`
  (so a UBSan diagnostic aborts rather than printing and letting the run stay
  green) and then runs it again under valgrind with `--error-exitcode=9
  --leak-check=full`. Verified locally before wiring: 107 test cases / 380
  checks pass under the sanitizers, and valgrind reports no errors or definite
  leaks.
- **Safe-by-default request authenticator (`axiam::TokenAuthenticator`, SEC-074).**
  New header `<axiam/authenticator.hpp>`. It is now the documented §10 entry point for
  turning an inbound credential into an `AxiamUser`: it verifies the Ed25519 signature
  **and** `exp` (with a named `clock_skew`, default 30 s), **and** `nbf` when present,
  **and** that the token's `tenant_id` claim equals the tenant the resource server was
  configured with — the cross-tenant control the org-wide JWKS endpoint makes necessary.
  Optional `iss`/`aud` pinning and a `now` injection seam live on `AuthenticatorOptions`.
  Missing or unparseable `exp`, a malformed `nbf`, and a missing/empty/non-string
  `tenant_id` all fail closed. `guard_authenticator<Request>()` plugs it straight into
  `AxiamGuard`; `try_authenticate()` is the non-throwing twin; `make_authenticator(client, ...)`
  binds one to a client's JWKS verifier.
- **Webhook signature verification (`axiam::webhook::verify`, T-145 / CONTRACT §13).**
  New header `<axiam/webhook.hpp>`. HMAC-SHA256 over `<t>.<raw_body>`, `t=`/`v1=` header
  parsing with forward-compatible handling of unknown keys, constant-time comparison over
  the **decoded** MAC bytes (`CRYPTO_memcmp`, no early return, all candidates evaluated),
  a two-sided freshness window defaulting to 300 s, a `now` injection seam, and a typed
  fail-closed error that never surfaces the expected signature. A header carrying no `v1`
  is a failure, never a pass. `verify_or_throw()` is the exception-based twin.
- CONTRACT.md §13 "Webhook Signature Verification" added to the vendored contract copy.
- Regression tests pinning connection reuse: N sequential requests must open exactly one
  TCP connection, a GET following a POST must keep both the connection and its own verb,
  and a large POST body must not carry `Expect: 100-continue`.

### Fixed

- **Plaintext `http://` base URL is rejected at construction (SEC-073, §6).**
  `Client::Builder::build()` previously validated only that `base_url` was non-empty, so a
  misconfigured `http://` base sent login credentials, the httpOnly cookie jar, the CSRF
  token and the tenant header in cleartext with no error — strict TLS never got a chance to
  apply. The scheme is now checked and a non-`https` base throws `std::invalid_argument`,
  with a loopback carve-out for development (`localhost`, `127.0.0.1`, `::1`). Userinfo
  cannot smuggle a loopback host past the check, and lookalike hosts such as
  `localhost.evil.example` are rejected.
- **Signed-integer overflow (UB) in the base64url decoder.** `base64url_decode()`
  accumulated symbols into a never-truncated `int`, so decoding any token part longer
  than a handful of characters overflowed — undefined behaviour on the code path that
  decodes every JWT header, payload and signature. The accumulator is now an explicitly
  masked `std::uint32_t`. Caught by an ASan+UBSan run of the suite (`-fno-sanitize-recover=all`),
  which the suite now passes clean; the same latent overflow in the tests' base64url
  encoder was fixed alongside it.
- **`CURLOPT_CUSTOMREQUEST` leaked across requests on the shared easy handle.** The handle
  is reused for the client's lifetime, and `CURLOPT_CUSTOMREQUEST` is sticky: after any POST
  every subsequent GET went out with the previous POST's verb, silently turning the JWKS
  fetch into `POST /oauth2/jwks`. The method-shaped options are now reset on each request.
- **Bimodal latency tail (I11).** libcurl defaults were periodically discarding the pooled
  connection and making its re-establishment expensive. The transport now pins
  `FORBID_REUSE`/`FRESH_CONNECT` off, disables age-based retirement of a healthy pooled
  connection (`CURLOPT_MAXAGE_CONN`, whose 118 s default forced roughly one reconnect per
  worker every two minutes), caps the dual-stack Happy-Eyeballs fallback stall at 50 ms
  (default 200 ms), widens the DNS cache to 300 s (default 60 s), enables TCP keepalive so a
  silently-dropped idle connection is not discovered by a 200 ms TCP retransmit timeout, and
  raises the connection-cache size. `Expect: 100-continue` is also suppressed — measured
  against libcurl 8.5 its threshold is 1 MiB rather than the widely-cited 1 KiB, so it is not
  the cause of the observed tail, but it still matters for very large batch payloads and for
  consumers linking an older libcurl.

### Changed

- **Source-breaking:** `LoginResult::challenge_token` is now `Sensitive<std::string>` rather
  than `std::string` (SEC-076). CONTRACT §7 classes the MFA challenge token as secret
  material, so it now gets the same redaction safety-net as every other secret in this SDK.
  `verify_mfa()` gained a `Sensitive<std::string>` overload, so the common
  `client.verify_mfa(login.challenge_token, code)` call site is unchanged; code that read the
  token as a bare string must go through `axiam::detail::reveal()` or keep it wrapped.
- **Source-breaking:** `JwksVerifier::verify()` is renamed
  `JwksVerifier::verify_signature_only_unchecked()` (SEC-074). The behaviour is unchanged —
  the name and the docs now say what it does. It validates the signature and no claims, so
  it must not be wired into a request guard; use `TokenAuthenticator` instead.
- **Behaviour-breaking:** `AuthenticatorOptions::clock_skew` is now **bounded**
  (CONTRACT §10.1 rule 7). It must lie in `[0, axiam::kMaxClockSkew]` (60 s, the
  value §10.1 recommends); a larger leeway now throws `std::invalid_argument` from
  the `TokenAuthenticator` constructor instead of being honoured. An unbounded
  leeway would let an operator re-open the expiry window indefinitely, defeating
  rule 2. Deployments that set a skew above 60 s must lower it or fix their clock
  synchronisation. The default is unchanged: `axiam::kDefaultClockSkew` (30 s),
  now a named `constexpr` rather than an inline literal, and deliberately stricter
  than the ceiling.

### Conformance

- **CONTRACT §10.1 (minimum local-verification set) — no behavioural change was
  required to the claim checks.** `TokenAuthenticator`, the documented §10 guard
  entry point, already applied all seven rules: the EdDSA `alg` pin runs before
  any key lookup (`src/jwks.cpp`), `exp` is required and both an absent and a
  non-numeric `exp` hard-fail, `nbf` is honoured when present, `tenant_id` is
  required and asserted (with an empty tenant expectation refused at
  construction), and `iss`/`aud` are checked when — and only when — configured.
  The only §10.1 gap was rule 7's bound on the leeway, fixed above. §10.1 also
  cites this SDK's `verify_signature_only_unchecked` as the reference spelling for
  a raw signature-only primitive. The §10.1 negative-test set is now complete: the
  `alg: none` and HS-signed-with-an-EdDSA-`kid` confusion cases were added, along
  with the conditional-`iss`/`aud` fail-closed cases and the skew-ceiling case.
- Vendored `CONTRACT.md` re-synced with §10.1.

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6

### Fixed

- Only the owner vacates the single-flight slot; never serve a settled refresh

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Add line-coverage regression gate (floor 95%) (#5)

## [1.0.0-alpha16] - 2026-07-22

### Changed

- Adopt CONTRACT 1.3; defer gRPC get_user_info

## [Unreleased]

### Fixed

- §9 single-flight refresh: two windows could produce a redundant second
  `POST /api/v1/auth/refresh` — fatal against single-use, rotating refresh tokens
  (`invalid_grant`). (1) A waiting caller cleared the in-flight slot on the failure
  path even when it did not own it, so it could wipe a newer leader's live future
  and let the next caller start a concurrent refresh. (2) The slot was only vacated
  after the shared future had already been read, so a caller arriving in that window
  joined an already-settled future and was handed the result of a refresh that had
  completed before it started, instead of refreshing. The coalescing logic now lives
  in `src/refresh_guard.hpp` with generation-tracked ownership (only the owner
  vacates, and only its own generation) and liveness (not mere occupancy) deciding
  whether a caller may join. Failures still reach every contending caller once, with
  no automatic retry (§9.3), and no lock is held across the wire call.

### Changed

- Adopt CONTRACT.md 1.3: the new gRPC-only `get_user_info` operation (CONTRACT §1.1) is
  documented as a deferred follow-up (this SDK ships no gRPC transport in v1) and the
  vendored contract copy is re-synced. Per §1.1 the REST `/oauth2/userinfo` endpoint is not substituted.

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha12.

## [1.0.0-alpha12] - 2026-07-19

### Changed

- Add C++ examples, README badges, sync CONTRACT §5.1 org context (#3)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Resolve org_id from access-token claim for the refresh body (D-14) (#2)
- Publish API docs to gh-pages branch
- Drop configure-pages step, mirror C SDK template
- Auto-enable GitHub Pages (enablement: true)
- Add docs publish workflow to GitHub Pages

## [Unreleased]

### Added

- Initial greenfield C++17 SDK (`axiam_cpp`, namespace `axiam`).
- `axiam::Client` with a fluent `Client::builder()` enforcing the §5 tenant
  requirement (slug or id; no default tenant).
- §1 operations: `login`, `verify_mfa`, `refresh`, `logout`, `check_access`,
  `can`, `batch_check`, plus `authenticate_device` (mTLS) and `std::future`-based
  `*_async` twins.
- §2 error taxonomy as an exception hierarchy: `AxiamError` →
  `AuthError` / `AuthzError` / `NetworkError` (with HTTP-status mapping).
- §3 CSRF capture-and-echo; §4 libcurl per-client cookie engine; §5 `X-Tenant-ID`
  on every request.
- §6 strict TLS (verify peer + host always on) with `with_custom_ca`; §6.1 mTLS
  client identity via in-memory libcurl blobs (`with_client_cert`), no temp files.
- §7 `Sensitive<T>` wrapper for token + private-key material (redacts to
  `[SENSITIVE]`; raw access only via a friend accessor).
- §9 single-flight token refresh (`std::mutex` + `std::shared_future<TokenPair>`).
- §10/§11 framework-agnostic guard (`AxiamGuard`) and declarative helpers
  (`require_auth`, `require_role`, `require_access`, `AXIAM_REQUIRE_ACCESS`).
- Ed25519 (EdDSA-only) JWKS verification via OpenSSL, with a 300s key cache.
- Injectable `std::function` HTTP transport seam (libcurl default; in-memory fake
  for tests). Unit + real-libcurl integration tests; logic-layer coverage > 90%.
- Packaging: CMake install/export + package config, CPack `.tar.gz`, in-repo
  vcpkg port, Conan recipe, Doxygen config, and GitHub Actions CI + coverage.

### Deferred

- gRPC transport and §8 AMQP HMAC consumer (out of scope for v1).
