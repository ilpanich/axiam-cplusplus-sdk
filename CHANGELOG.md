# Changelog

All notable changes to the AXIAM C++ SDK are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
semantic versioning (pre-release track `1.0.0-alpha*`).

## [Unreleased]

### Added

- **§15.7 external-IdP subject tokens (X4).** `token_exchange()` can now exchange a token minted
  by a trusted external IdP — a partner's Entra, Okta or Keycloak — for an AXIAM token scoped to
  what the resolved AXIAM user may actually do. No new operation: the same call, plus
  `TokenExchangeParams::subject_token_type` and the new `kJwtTokenType` constant alongside
  `kAccessTokenType`.

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and a
  wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. `std::nullopt` still sends `…:access_token`, so every existing caller is
  unaffected; a JWT-shaped subject token does **not** change what is sent, which is asserted by a
  test.

  The new member sits second in `TokenExchangeParams`, next to the `subject_token` it describes
  and matching the other SDKs. Every call site here assigns members by name rather than
  brace-initialising positionally, so nothing needed adjusting.

  Also asserted: an `actor_token` alongside an external subject token surfaces `invalid_request`
  with no retry and no request rewriting; a refused refresh or ID token type is never retried as a
  different type; the one normative description — `the subject token's issuer is not configured
  for token exchange`, meaning *fix the AXIAM trust config* rather than *fix your token* — reaches
  `error_description()` intact; and nothing re-exchanges an exchanged token, which both server
  paths refuse because exchanges do not compose.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.11 → 1.12 plus
  §15.7), which also brings contract 1.12's `/oauth2/*` error rows dispatching on the `error`
  field at any status, and the `TokenExchangeTrust` schemas behind the X4 provider configuration.

- **§12 OIDC relying party, §12.7 logout, §14 device grant, §15 token exchange —
  the contract-1.11 port.** These four were deferred in this SDK through contract
  1.10; [§12.6](CONTRACT.md) reverses that and they ship together, in the new
  `axiam/oidc.hpp`: `oidc_discover/begin/exchange/refresh`,
  `login_client_credentials`, `introspect`, `revoke`, `sso_start/complete`;
  `logout_url` and `verify_logout_token`; `device_authorize/poll/login`;
  `token_exchange`.

  The deferral reasoned from persona — a device- and IoT-oriented SDK with no
  natural home for a browser redirect — which covers `oidc_begin` and
  `oidc_exchange` and none of the other seven. §14 exists *because* a device
  cannot show a browser, and §20 had already given this SDK a `/oauth2/token`
  call, so it was speaking OAuth2 at the token endpoint without §12's discovery
  cache or ID-token validation. The port removes a divergence rather than adding
  one.

  What the surface deliberately does not do: it stores no `state`, `nonce` or
  `code_verifier` (§12.3 rule 1 — the caller keeps them, and the `redirect_uri`
  too); it has no way to skip ID-token validation, and §12.4 rule 7's
  all-or-nothing discard means a bad `id_token` takes the access and refresh
  tokens with it; it adopts no token as the client's own credential; and it does
  not retry a grant whose credential is single-use (§16.2).

- **`OidcValidationError`**, carrying the §12.3 rule 3 closed seven-value
  vocabulary via `reason()`. A SIBLING of `OAuthProtocolError` rather than a
  subtype: the two carry different vocabularies from different clauses, and
  §14.2's terminal `expired_token` is nearly a homograph of §12.4 rule 5's
  `token_expired`. Distinct types make "which vocabulary am I catching?"
  unavoidable.

- **`JwksVerifier::verify_with_reason()`** — the same signature check, plus the
  code naming which part of it failed. `verify_signature_only_unchecked()` is now
  a thin wrapper over it, so the §10 authenticator and the §12 relying party
  cannot drift on what "verified" means.

- **Builder:** `oidc_client_id`, `oidc_client_secret`, `oidc_discovery_ttl`
  (raised to the 5-minute floor), `oidc_clock_skew` (clamped down to 60 s, never
  up).

- **Examples:** `oidc_login.cpp`, `device_login.cpp`, `token_exchange.cpp`.

- **§20.3 challenge emission from the §11 guard.** A `require_access` overload taking a
  `UmaChallenger` (realm, `as_uri`, PAT); on a denial it mints a permission ticket for the
  action that was refused and throws `AuthzChallengeError` carrying the formatted
  `WWW-Authenticate: UMA` value.

  `AuthzChallengeError` **derives from `AuthzError`**, so an adapter that knows nothing about
  UMA catches what it always caught and returns the same 403 — the addition can never turn a
  denial into a different outcome. The challenge is deliberately absent from `what()`: the
  value carries a live ticket (§20.6), and `what()` is what ends up in a log line.

  The overload is **opt-in** because emitting a challenge means minting a credential: a guard
  that did it by default would turn every unauthorized request into a Protection API call,
  which is a denial-of-service amplifier pointed at your own authorization server. An allow
  mints nothing, and neither does an unauthenticated request. And a **minting failure is not an
  escalation** — the original denial is rethrown intact rather than the Protection API's own
  error escaping as a 503. Both are asserted by counting Protection API calls.

  Paired with the new `examples/uma_resource_server.cpp` and `examples/uma_client.cpp`, which
  run both halves — including the trust decision §20.3 keeps in the caller's hands rather than
  auto-exchanging against whatever host a 403 named.

- **UMA 2.0 — Protection API and ticket grant (CONTRACT §20).** New
  `include/axiam/uma.hpp` plus eight methods on `Client`: `uma_discover`,
  `uma_register_resource`, `uma_read_resource`, `uma_update_resource`,
  `uma_delete_resource`, `uma_list_resources`, `uma_request_ticket` and
  `uma_exchange_ticket`, with the two free challenge helpers `uma_parse_challenge` /
  `uma_challenge_header`. New types `UmaConfiguration`, `UmaResourceSet`,
  `UmaRequestedPermission`, `UmaRptPermission`, `RequestingPartyToken`,
  `UmaChallenge`, `UmaClientCredentials`, `UmaExchangeTicketParams` and
  `OAuthProtocolError`.

  **This ships while §12 does not, and that is not an inconsistency.** §12.7, §14
  and §15 stay deferred because each needs an OIDC stack this SDK does not have.
  §20 does not: UMA carries its own discovery document, the Protection API is
  ordinary bearer-authenticated REST, and the ticket grant returns an opaque RPT
  with nothing to validate.

  The load-bearing rules, all asserted in `tests/test_uma.cpp`:

  - **`uma_exchange_ticket` is never retried** — not on `5xx`, not on a transport
    failure, not on `invalid_grant`. This is the one documented exception to §16,
    and a security rule rather than a performance one: the ticket is consumed
    *before* the exchange is evaluated, so a retry is a second redemption — the
    concurrency case whose measured residual `ilpanich/axiam#302` records. The
    grant never enters `execute_retrying()`'s budget.
  - **`uma_parse_challenge` performs no exchange.** The `as_uri` names an
    authorization server the caller has not chosen to trust.
  - **The RPT is never adopted**, and `RequestingPartyToken` has no refresh-token
    member — asserted with a `sizeof` check, so a fourth member cannot be added
    without the test noticing.
  - **`uma_update_resource` replaces the scope list rather than merging it** — no
    read-modify-write, so omitting a scope removes it.
  - **An empty PAT, ticket, `claim_token` or client secret, or a slug-only
    tenant, throws before any wire call**, so a request that could not have
    succeeded never spends a ticket.

- **`OAuthProtocolError`, deriving from `AuthError`.** §20.4 requires dispatching
  on the body's `error` field rather than the HTTP status — `access_denied`
  answers `403` on the ticket grant where RFC 8628's answers `400` — so the code
  has to reach the caller. Deriving from `AuthError` is how the contract models
  it: the §2 taxonomy keeps its three top-level types, and a caller that only
  knows about `AuthError` still catches this. `what()` carries the code and never
  the server's free text, since a failed exchange is exactly when a description
  echoing the ticket would land in a log; `error_description()` surfaces that text
  separately for a caller who opts in.

- **Bounded read-only retry (CONTRACT §16).** `check_access`, `can`, `batch_check`
  and the JWKS fetch now retry a transient failure: 3 attempts total, 200 ms base,
  5 s cap, **full jitter** over `[0, backoff]`, and `Retry-After` honored as a
  **floor** — it can lengthen a wait, never shorten one, so a `Retry-After: 0`
  cannot defeat the backoff. On by default; `Builder::retry_enabled(false)` gives
  exactly one attempt for a caller who owns their own retry layer. The attempt
  cap, base and delay cap are deliberately **not** settable: §16.1 permits
  lowering or disabling, never raising, and a caller who can raise them turns one
  client into the herd a backoff exists to prevent.

  Eligibility is "changes no server state", **not** "is a `GET`". The
  authorization check is a `POST` with a body and is the operation this policy
  exists for; `login`, `verify_mfa`, `logout`, `refresh` and
  `authenticate_device` are never retried, both because they change state and
  because their credentials are single-use. The §9 refresh does not reset the §16
  budget — one refresh, one budget, per logical call.

- **Client-side decision memo (CONTRACT §17).** `Builder::decision_memo_ttl`
  enables a bounded, TTL-clamped cache of authorization decisions. **Disabled by
  default**, and zero means disabled rather than "cache for zero milliseconds". A
  TTL above 5 s is clamped rather than rejected, allows and denies are cached
  identically, `reason_code` comes back with the decision, failures are never
  cached, and any credential change clears it.

  **Read-your-own-writes is not guaranteed.** The staleness bound is the TTL in
  both directions — a grant just *added* can still read as denied for up to the
  TTL — which is the direction that surprises people, and it breaks silently.

- **Deterministic shutdown (CONTRACT §18).** `Client::close()` releases the
  transport and its connection pool, clears the cookie jar, the CSRF token and the
  memo, and is idempotent. It issues **no request**: the server-side session
  deliberately outlives the client object, so a close that logged out would
  silently end every user's session on each deploy. A call on a closed client
  throws `NetworkError` naming the cause rather than silently reconnecting. The
  destructor releases whatever `close()` has not, so a `Client` that simply goes
  out of scope still frees its transport.

- **Telemetry hooks (CONTRACT §19).** `Builder::telemetry_hook` installs a sink for
  `RequestStartEvent`, `RequestEndEvent`, `RetryEvent`, `RefreshEvent` and
  `ConfigClampedEvent`, so metrics can be wired without this library taking a
  dependency on any metrics package. One request pair per **attempt**, so a caller
  can count real wire calls from the events. `TelemetryEvent` is a closed
  `std::variant` — no code outside `telemetry.hpp` can add an alternative — which
  is what makes "no event carries a token" checkable by reading one declaration,
  and it carries the path *template* rather than a URL with ids substituted in. A
  hook that throws is caught and swallowed: telemetry is not permitted to fail an
  authorization check.

- **Decision reason codes (CONTRACT §11 rule 9).** `AccessDecision` gains
  `std::optional<std::string> reason_code`, populated by `check_access`, `can`
  and every element of `batch_check`, with `axiam::ReasonCode::kAllowed`,
  `kNoGrant` and `kDeniedByRule` as comparison constants. The two refusals are
  both `allowed == false` but mean opposite things to the user — *ask an admin*
  versus *an admin already decided* — and an application that cannot tell them
  apart sends people to raise tickets that will be refused.

  Deliberately a string and not an `enum class`: §11 rule 9 requires an
  unrecognised code be surfaced verbatim, so a server that adds a fourth code
  must not become a decode failure in every deployed client. A server that omits
  the field (or sends `null`, or a non-string) yields `std::nullopt` — absence,
  not an error — and the allow/deny outcome stays in `allowed` alone. Guard
  behaviour is unchanged: `require_access` still throws `AuthzError` (403) for
  both refusals, which `tests/test_reason_code.cpp` asserts alongside the
  reporting half.

  `ReasonCode` is a struct of `static constexpr` members rather than a
  namespace, so `ReasonCode::kAllowed` still resolves in a scope holding a local
  named `reason_code`.

### Changed

- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` (the server's `/uma2/*` surface).

- **Re-vendored `CONTRACT.md` and `openapi.json`** from `ilpanich/axiam` at
  contract 1.7. Of the sections 1.7 adds, only §11 rule 9 is implemented here;
  §12.7 (logout), §14 (device grant) and §15 (token exchange) all build on a §12
  OIDC relying-party layer this SDK does not have, and are recorded under
  Deferred / follow-ups in the README rather than half-shipped.

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

### Changed

- **The JWKS verifier now re-fetches at most once per cooldown window on an
  unknown `kid`** (§12.4 rule 2). It previously re-fetched on EVERY unknown
  `kid`, which is the fetch-amplification vector that rule names: an attacker
  presenting arbitrary `kid` values drove one JWKS fetch per forged token. The
  60-second window keeps key rotation working — "never re-fetch" is equally
  forbidden — while bounding the amplification. This tightens the §10/§11 guard
  path as well as the new §12 one.

- `Client::Impl` moved to the non-installed `src/client_impl.hpp`, unchanged, so
  the §12 translation unit can use the same transport, tenant header and §16
  seams the other operations use. The alternative was a second copy of the
  request plumbing beside the first — exactly the "second, parallel stack" the
  §12.6 deferral warned about.

- `oidc_refresh` is governed by its own §9-conformant single-flight guard, keyed
  on the refresh token's digest. AXIAM rotates refresh tokens, so two threads
  redeeming one concurrently would produce a winner and an `invalid_grant` for a
  token that was good a millisecond earlier. Distinct tokens do not contend, and
  a FAILING flight shares its failure with every waiter — §9 rule 2 says one
  outcome, not one success.

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
