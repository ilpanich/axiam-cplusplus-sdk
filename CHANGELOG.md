# Changelog

All notable changes to the AXIAM C++ SDK are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
semantic versioning (pre-release track `1.0.0-alpha*`).

## [Unreleased]

## [1.0.0-beta02] - 2026-08-28

### Added

- **CONTRACT.md contract 1.31 — list search, the truthful resend, and organization scope.**
  The vendored `CONTRACT.md`, `openapi.json` and `management-registry.json` are re-synced
  from `axiam@main`, and four behaviours follow from them.

  **`PageRequest` gained a third member, `search` (§27.4 rule 4).** All twenty paginated
  operations accept an optional free-text term, matched case-insensitively by the
  **server** against the identifying fields of whatever is being listed — a name or
  username, plus the record id, so a UUID pasted out of a log line finds its row.
  `Page<T>::total` then counts *matches*, not rows.

  It lives beside `offset` and `limit` rather than becoming an extra argument on twenty
  `list` methods, and that is what makes `next()` — and so `Page::next_request()` — carry
  it across a whole walk. An argument has nowhere to live between one request and the
  next, so a walk built on one would return the matches followed by the unfiltered tail.
  Appended last and defaulted, so every existing `PageRequest{0, 50}` still compiles and
  still means "unfiltered".

  An empty or all-whitespace term is the same request as none: no `search` parameter at
  all. The new `PageRequest::normalize_search()` is that normalisation, exposed because it
  is the one piece a caller can observe going wrong. The term is trimmed but never
  truncated — the server caps its length, and a client-side cap the server would not have
  applied is a silently different query the caller cannot see.

- **`Client::resend_own_verification()` (§25.1, §25.7).** `POST
  /api/v1/users/me/resend-verification`, session-authenticated, taking **no address** —
  the server reads it off the caller's own record, and the signature deliberately offers
  no way to name a different one. Throws `AuthError` client-side, with no wire call, when
  there is no session.

  It does not replace `resend_verification()`, and neither is routed to the other. The
  unauthenticated one takes an address from an anonymous caller, so it must answer
  identically whether the address exists, is already verified, or is rate-limited:
  anything else is an oracle for which addresses have accounts. This one is asked by a
  caller already signed in to the account it is asking about, so it tells the truth — a
  `409` raises `AuthzError` and a `429` raises `NetworkError`, and this SDK does **not**
  fall back to the public endpoint on either (§25.7 rule 2). That fallback would turn both
  failures back into a silent success and restore the bug this operation exists to fix,
  with an extra round trip. Returning means the mail was *enqueued*, not delivered.

- **`UserInfo::organization_level` (§5.2).** True when the account that signed in is an
  organization-level principal — one whose record lives in its organization's reserved
  tenant, so its global grants apply in every tenant there and it can act on a different
  one by sending a different `X-Tenant-ID`, with no re-login.

  An ordinary tenant principal is a principal of exactly one tenant; the same header change
  produces a `403` for it. The flag is what an application checks *before* offering a
  tenant switch, rather than discovering the answer from a failed request. It is derived
  from the response and never asserted: never sent, and `false` when absent or when the
  value is anything but the JSON literal `true` — which is what a server older than
  contract 1.31 answers, and the safe direction. Appended **last** and defaulted, so every
  existing aggregate initializer of `UserInfo` still compiles. `mfa_setup_confirm()`
  populates it too, because that call *is* the completion of a login (§25.2 rule 2).

- **Three §27.11 model additions**, regenerated: `Tenant::kind`
  (`std::optional<TenantKind>`, with the new `standard` | `organization` enum),
  `MtlsTrustAnchorResponse::trusted_anchors` (`std::optional<std::int64_t>` — empty is
  *not* zero: "the listener trusts no CAs" and "there was no listener to ask" are
  different operational states), and `Certificate::bound_service_account_id`.

  That last one is a **projection**, not a member of the certificate: the server resolves
  it for a whole page in one query, so `certificates().list()` populates it and
  `certificates().get(id)` leaves it empty, with no second request to fill it in (§27.11
  rule 4). `scripts/gen_management.py` learned to read the registry's
  `response.projected_fields` and fold such a field onto its base struct as optional — the
  server expresses a projection as an `allOf` of the named base and an anonymous object,
  and a generator that reads only for a `$ref` sees a response with no element name at all.

### Changed

- Re-vendor openapi.json and management-registry.json from axiam main (#49)

- Contract 1.31: list search, the truthful resend, organization scope (#48)

- Re-vendor the contract artifacts: spec digest + §27.10 posture (#47)

- Delete the dead PHP helpers the C++ generator inherited

- Remove PHP copy-paste residue from the C++ generator

- Put the §27 namespace handles directly on the client, per §27.2/§27.3

- Finish the §27 management port: examples, drift gate, docs, coverage

- Add the §27.6/§27.7 declarative manifest layer to the C++ SDK

- Add the CONTRACT.md §27 management surface to the C++ SDK

- Re-vendor CONTRACT.md, openapi.json and the §27 registry

- **Generated enums are now open (§27.11 rule 1).** Every generated enum gained a trailing
  `Unknown` enumerator, and `*_from_wire()` returns it for a value this SDK's copy of the
  spec does not list instead of throwing `std::invalid_argument`.

  Throwing failed the **whole** response — the exception escapes the entire `Page<T>`
  decode, so one field of one row took the whole page down with it, including the rows the
  caller did ask for. That is the failure §27.11 rule 1 exists to prevent, and it is why
  this is a fix rather than a loosening.

  It still never maps an unrecognised value to one of the **known** enumerators: reading a
  new value as whichever enumerator was declared first turns a new server state into a
  wrong one, and on this surface these values gate access. `to_wire(Unknown)` is the empty
  string — which no server value is, so carrying an unrecognised value back into an update
  is refused by the server rather than written as a spelling it never used.

  **A `switch` over one of these enums now needs an `Unknown` arm**, and a `switch` that
  covered every enumerator will warn without one. The pre-existing
  `"an unknown enum value is refused"` test was rewritten rather than removed, under a
  name that records the inversion, and it kept the two assertions the old one was really
  making.

- **CONTRACT.md §27 — the management API.** 146 operations across 24 namespaces,
  reached through namespace handles hung off `client.management()`
  (`client.management().service_accounts().rotate_secret(id)`), which is the form
  §27.3's table specifies for C++.

  The models, the JSON hooks and one raw call per operation are **generated** by
  `scripts/gen_management.py` from the vendored `management-registry.json` and
  `openapi.json`; the output is committed, so building this library still needs
  no code-generation step and no Python. A new `management-drift-check` CI job
  re-runs the generator with `--check` and fails on drift — committed generated
  code is only trustworthy if something checks it is current, and without that
  gate a re-vendor adding an operation would leave the SDK shipping a surface
  that disagrees with the contract while every test still passed, because the
  generated tests come from the same stale copy.

  The generated layer sits on the **existing** request path (§27.8): every
  operation inherits §5's tenant/org headers, §6's TLS floor, §9's single-flight
  refresh, §16's retry policy and §19's telemetry. The suite drives the fake
  transport at the bottom of a real client, so an operation that opened its own
  request path fails the tests rather than passing them.

  Hand-written on top: `Page<T>` and `PageRequest` (§27.4 rule 4 — `total` is the
  server's count and is never derived from the page in hand; auto-paging stops on
  an empty page, not a short one), `CallScope` with `in_org()` / `for_tenant()`
  returning a **new** handle (§27.4 rule 3), and the error sub-types (§27.4
  rule 7): `NotFoundError` and `ConflictError` under `AuthzError`,
  `ValidationError` under `NetworkError` and excluded from retry.

  The 24 namespace handles sit **directly on the client** —
  `client.service_accounts().rotate_secret(id)`, which is the form §27.3's C++
  row specifies — and `client.management()` reaches the same handles behind one
  accessor (§27.2 rule 4). The direct accessors forward to `management()`, so the
  "equivalent handles" rule 4 requires is structural rather than two code paths
  agreeing to stay in step; the suite asserts it per namespace by comparing the
  method and path each actually puts on the wire.

  New public headers `axiam/management.hpp` and `axiam/management_manifest.hpp`.
  Deliberately **not** pulled in by the `axiam/axiam.hpp` umbrella: they are
  around five thousand lines of declarations, and most programs authenticate and
  check access without ever administering a tenant. `client.management()` is
  declared in `client.hpp` either way, so the surface is still discoverable from
  the umbrella alone.

- **§27.6/§27.7 declarative manifests.** `ManagementApi::manifest()` gives a
  `ManifestApi` with `plan()` (reads only), `apply()` (stops at the first failure
  and does not roll back), `validate()` and `ordered()`. `AXIAM_MANIFEST(...)`
  plus `AXIAM_RESOURCE` / `AXIAM_PERMISSION` / `AXIAM_ROLE` / `AXIAM_GROUP` are
  §27.7's C++ form — designated-initializer aggregate specs that lower to the
  same `Manifest` value a config file deserializes into, and go through the same
  `plan`/`apply`. Ordering is derived from kind and `depends_on` and is stable
  across runs; omission is never deletion, and `ChangeAction` has no `Delete`
  member at all.

- Three worked examples: `examples/management_basics.cpp`,
  `examples/management_manifest.cpp`, and
  `examples/device_mtls_provisioning.cpp` — the last provisioning an IoT device
  end to end (service account, device certificate from the tenant signing CA,
  certificate binding, mTLS trust anchor) and then authenticating as it over §6.1
  mTLS from a second client.

- **Coverage floor 96 → 98.** The §27 surface adds ~5,000 instrumented lines,
  which moves this number on its own: measured, it landed at 74.68% before the
  §27 suites existed. With the generated round-trip, enum and re-scope passes and
  the hand-written semantics and manifest suites it measures **98.78%**
  (9,070/9,182 lines by the gate's own metric), so the floor is ratcheted to a
  value this job actually computed.

### Fixed

- **A manifest naming a resource never converged.** `Resource` has no description
  property, so reading current state could only ever report an empty one — and
  comparing a manifest's resource description against it marked the resource
  drifted, updated it, and marked it drifted again on the next run. §27.6 rule 6
  requires apply-then-plan to be all-`Unchanged`; drift is now computed only for
  the kinds the server actually stores a description for. Caught by the
  every-kind manifest tests added here.

## [1.0.0-alpha44] - 2026-08-25

### Changed

- Re-vendor openapi.json at alpha43 for tenant signing CAs (axiam#379)

- **Re-vendor `openapi.json` at 1.0.0-alpha43** for AXIAM server PR #379, which
  adds **tenant signing CAs**: an intermediate CA created beneath one of the
  organization's CAs and scoped to a single tenant, so a tenant's user, service
  and device certificates chain through a CA that can be revoked, rotated or
  handed to a different operator without redistributing the anchor the rest of
  the estate trusts. `CONTRACT.md` and `proto/` were untouched by that PR and are
  already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto any `/api/v1/organizations/{org_id}/...` CA route — and this SDK
  models none of the schemas below, so nothing here gains, loses, or changes a
  symbol. The spec is vendored so what this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - **`POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas`**
    (`generate_intermediate`) — create a tenant signing CA under an organization
    CA, with AXIAM generating the key. Returns `GeneratedCaCertificate`; the
    private key comes back exactly once, and not at all under `vault_pki`, where
    it was born inside Vault and no API exports it.
  - **`GET .../signing-cas`** (`list_intermediates`) — a paginated list of one
    tenant's signing CAs.
  - **`POST .../signing-cas/sign-csr`** (`sign_intermediate_csr`) — the BYOK
    counterpart: sign a PKCS#10 CSR produced elsewhere, so the private key never
    reaches AXIAM at all. The response carries no `private_key_pem` because there
    is none to carry.
  - **`CaCertificate` gains two nullable fields** — `tenant_id`, the tenant a CA
    signs for, and `parent_ca_id`, the CA in the organization that signed it.
    Both are absent for an organization-level CA, which is the trust anchor and
    the only kind that existed before this change.
  - **Four new schemas**: `CreateIntermediateCa`, `CreateIntermediateCaRequest`,
    `SignIntermediateCsr` and `SignIntermediateCsrRequest`.

  The spec version moves from **1.0.0-alpha40** to **1.0.0-alpha43**; the
  intervening alpha41 and alpha42 releases changed nothing in it but that string.

## [1.0.0-alpha43] - 2026-08-24

### Added

- Compile and test against C++23 alongside the C++17 floor (#43)

- **C++23 is now a built and tested standard, on both g++ and clang++.** The CI
  matrix gains a standard axis: it was two compilers at one standard, so the compiler
  axis was covered twice and the language axis not at all. It is now g++ and clang++
  at **C++17 and C++23** — four legs. C++20 sits between two green legs.

- **`axiam::kMinCxxStandard` and `axiam::kNewestTestedCxxStandard`**, plus an
  `#error` guard in `<axiam/axiam.hpp>` that refuses a toolchain below the floor at
  the point of inclusion. MSVC is checked through `_MSVC_LANG`, which is the only
  correct way — it reports `199711L` in `__cplusplus` unless `/Zc:__cplusplus` is
  passed, so reading `__cplusplus` alone would reject every MSVC build.

- **`tests/test_version_policy.cpp`** — binds `CMAKE_CXX_STANDARD`, the header
  constants and the CI matrix together. It also asserts the CMake default stays
  *overridable*: a plain `set()` silently ignores `-DCMAKE_CXX_STANDARD=23`, and the
  newest leg would compile C++17 while reporting green.

- **`examples/version_compatibility.cpp`** — reports the standard in use against the
  supported range.

- **A "Supported C++ standards" section in the README.**

### Changed

- **`CMAKE_CXX_STANDARD` is now overridable rather than hardcoded.** It was
  `set(CMAKE_CXX_STANDARD 17)`, which overrides anything passed on the command line;
  it is now guarded by `if(NOT DEFINED ...)`. **The default is unchanged** —
  `cmake -S . -B build` with no flags still produces exactly the C++17 build it
  always did. The configure step also prints the standard in effect.

  Documented alongside: a C++23 build does not report the same `__cplusplus` on both
  compilers — g++ 13 reports the pre-ratification `202100L` for `-std=c++23`, clang
  18 reports `202302L`. Comparisons are lower bounds, and "C++23 or later" is
  spelled `__cplusplus > 202002L`.

### Fixed

- **A `u8""` literal assigned to a `std::string` made the SDK's test suite fail to
  compile at C++20 and later.** `tests/test_opaque_binding.cpp` held
  `const std::string accented = u8"pàsswörd-ünïcøde";`, which is fine in C++17 and a
  **hard error from C++20**, where `u8""` is `const char8_t[]` and does not convert
  to `std::string`. Both g++ and clang rejected it.

  Fixed with `reinterpret_cast<const char *>` rather than by dropping the `u8`
  prefix, which preserves the explicit UTF-8 encoding guarantee — a plain literal
  would instead depend on the compiler's execution character set, which is not UTF-8
  everywhere (MSVC without `/utf-8`). Under C++17 the cast is a no-op.

  Found by the new C++23 CI leg, on its first run.

## [1.0.0-alpha41] - 2026-08-24

### Added

- Fall back to /auth/login when a KE2 fails under opaque_mode optional

### Changed

- Re-vendor openapi.json for the vault_pki CA custodian (axiam#368)
- Re-vendor CONTRACT.md 1.29 and openapi.json 1.0.0-alpha40

## [1.0.0-alpha40] - 2026-08-23

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha39.

## [1.0.0-alpha39] - 2026-08-23

### Changed

- Name the conformance sections individually
- Re-vendor CONTRACT.md for the §14.1 anchor repair
- Re-vendor openapi.json at 1.0.0-alpha38

## [1.0.0-alpha38] - 2026-08-22

### Added

- The §22 reactor protocol core over a caller-supplied transport
- WebAuthn (§24), account lifecycle (§25) and PAR (§26)

### Changed

- Re-vendor CONTRACT.md at 1.28
- Keep the reactor sample's plaintext demo scan-safe

## [1.0.0-alpha37] - 2026-08-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha34.

## [1.0.0-alpha34] - 2026-08-21

### Added

- Replace SRP-6a with OPAQUE (RFC 9807)

- **The §22 reactor protocol core, over a caller-supplied transport (CONTRACT
  §22, §22.11).** `include/axiam/reactor.hpp`, `src/reactor.cpp`: §22.1–§22.8 and
  §22.14 in full — the §8 v2 verification set on the event (key version, MAC,
  two-sided freshness, nonce), the canonical serialization and HMAC in both
  directions, the §22.5 registry and its namespace-prefix allow-lists, §22.8's
  strictest-wins default, `reactor_serve`, and the `ReactorRouter` binder.
  Promoted from what used to be a hand-rolled sample: contract 1.28 found the
  earlier deferral cut one notch too wide, because the part that genuinely needed
  a vendored dependency was the *connection* and the runtime around it needed
  none.

- `axiam::amqps_endpoint` — §8b rules 1–5 as a **public, tested function** rather
  than a doc comment (§22.11 rule 3). It refuses every scheme but `amqps://`
  including `amqp://`, with **no loopback exception** (§8b rule 8); requires a
  client certificate and its key together; carries a custom CA bundle for a
  privately-issued broker certificate; and offers no verification-skip parameter
  under any name and no way to express a plaintext fallback.

- `tests/test_reactor.cpp` (44), run against the committed §22.13 reference
  vectors — generated by the server's own sign path, so a byte out of place in
  the canonical form is caught against a number the server computed rather than
  against this implementation's own opinion.

- **WebAuthn / passkeys (CONTRACT §24).** `include/axiam/webauthn.hpp`,
  `src/webauthn.cpp`: the six relying-party wire operations
  (`webauthn_register_start` / `_finish`, `_authenticate_start` / `_finish`,
  `_discoverable_start` / `_finish`) plus §24.6a's JSON bridge —
  `WebauthnChallenge::request_json()` hands out the challenge in the exact form
  the platform authenticator APIs take, and every `*_finish` accepts the
  platform's response JSON back as a string, byte for byte. §24.6b's linked-API
  ceremony helper is deliberately absent: a C++ program has no authenticator on
  these targets, and rule 2 forbids emulating one in software.

- §24.6b rule 5's failure classification, which is required of every SDK claiming
  §24 whether or not it ships a ceremony helper: `axiam::webauthn_classify()` and
  `axiam::webauthn_failure_message()`. The classifier never fails — an
  unrecognised name, including an empty one, is `WebauthnFailure::kUnknown`.

- **Account lifecycle and MFA enrolment (CONTRACT §25).**
  `include/axiam/account.hpp`, `src/account.cpp`: nine operations — voluntary
  enrolment (`mfa_enroll` / `mfa_confirm`), forced enrolment
  (`mfa_setup_enroll` / `mfa_setup_confirm`), email verification
  (`verify_email`, `resend_verification`) and the password-reset triple
  (`request_password_reset`, `password_reset_context`, `confirm_password_reset`).
  Six of the nine are unauthenticated by design.

- **Pushed Authorization Requests, RFC 9126 (CONTRACT §26).** `Client::oidc_par`
  and `PushedAuthorizationRequest`. `OidcConfiguration` gained
  `pushed_authorization_request_endpoint`; when the discovery document does not
  advertise it the call throws `AuthError` client-side with no wire request,
  rather than synthesising `/oauth2/par` from the issuer.

- `examples/webauthn_passkeys.cpp`, `examples/account_lifecycle.cpp` and
  `examples/par_login.cpp`; `tests/test_webauthn.cpp` (31),
  `tests/test_account.cpp` (29) and `tests/test_oidc_par.cpp` (22).

### Changed

- Link to the AXIAM platform documentation site

- Re-vendor openapi.json at alpha32 (#36)

- **Re-vendor `openapi.json`** for AXIAM server PR #368, which adds a third CA
  key custodian, `vault_pki`, having HashiCorp Vault's PKI secrets engine
  generate the CA key inside Vault and sign on AXIAM's behalf. The spec version
  is unchanged at **1.0.0-alpha40**; `CONTRACT.md` and `proto/` are untouched by
  that PR and are already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto `/api/v1/organizations/{org_id}/ca-certificates`, and this SDK
  models none of the five schemas below — so nothing here gains, loses, or
  changes a symbol. It is vendored so the spec this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - `CaCertificate` gains a nullable `chain_pem`: the issuers above
    `public_cert_pem`, concatenated PEM, nearest issuer first and the root last.
    Absent for a CA that is its own root, which is every CA AXIAM generated
    before this. Present for a `vault_pki` CA, where it is the only copy of the
    root certificate anything outside Vault will ever see.
  - `CaCertificate.public_cert_pem` is now documented as the certificate that
    *signs*, which under `vault_pki` custody is the intermediate rather than the
    root beneath which it was created. The field itself is unchanged.
  - `GeneratedCaCertificate.private_key_pem` is **no longer required**. Under
    `vault_pki` custody the key is born inside Vault and no API exports it, so
    there is nothing to return. The field is omitted rather than sent as `null`,
    which keeps a client that has always read it working unchanged against every
    custodian that does produce a key.
  - `GeneratedCertificate` gains a nullable `chain_pem`, present only when the
    signer returned one — the `vault_pki` case, where the root's certificate
    exists nowhere a client could fetch it from.
  - `CreateCaCertificate` and `CreateCaCertificateRequest` gain the optional
    `issue_from_root`, `intermediate_subject` and `intermediate_validity_days`.
    All three are `vault_pki`-only and ignored by every other custodian.
    `issue_from_root` defaults to off: a root that signs only one intermediate
    can have that intermediate revoked and replaced without redistributing the
    trust anchor, and a root that signs leaves directly cannot.

- **`login_opaque()` falls back to `login()` when the tenant reports
  `opaque_mode: optional` and the envelope does not open (CONTRACT §23.4 rule 7,
  contract 1.29).** `login/start` now returns a `mode` field, and that field —
  and nothing else — decides what a failed `KE2` does next: under `optional` the
  same username and password are retried once over `POST /api/v1/auth/login` and
  the caller gets that call's outcome, its success on success and its error on
  failure; under `required`, against a server that reports no `mode` at all, and
  for any value that is not exactly `optional`, the failure stays an `AuthError`
  and no plaintext password leaves the process. `KE3` still never reaches
  `login/finish` on any of those paths, and the `404` "this tenant has OPAQUE
  disabled" mapping is untouched. Without the `optional` branch, enabling that
  mode would lock out every user of a tenant: every account has no registration
  record the moment an operator turns OPAQUE on and acquires one only as it next
  sets a password, so a failed exchange there is the ordinary case rather than an
  error. `mode` is **not** downgrade protection and is not documented as such — a
  hostile server wanting the plaintext could answer `404` and get the fallback
  whatever it claims; `required` closes that server-side. `tests/test_opaque_login.cpp`
  gains seven cases covering both `optional` outcomes, `required`, an absent
  `mode`, an unrecognised one, and the two failures that are *not* rule 7's (a
  `404` and a refused key-stretching function) staying non-fallback.

- Re-vendor `CONTRACT.md` at **1.29** and `openapi.json` at **1.0.0-alpha40**,
  matching the server. The one normative change is §23.4 rule 7 and the `mode`
  field §23.5 adds to the `login/start` response, above.

- README documents the fallback where it previously said "do not retry it over
  `login()`" without qualification — true under `required`, and the advice that
  locks out a migrating tenant under `optional`.

- Re-vendor `CONTRACT.md`. Repairs §14.1's link to the `device_login` heading,
  which dropped a hyphen the em dash leaves behind and so rendered as a link
  that went nowhere; the same heading's other two links were already correct.
  Link target only — no normative change and no contract-version bump.

- **Conformance statement names its sections individually.** `§16–§19` and
  `§24–§26` were ranges where the contract asks for individual naming, since a
  widened range silently turns a true statement into a different claim. §16 and
  §18 are now absent rather than folded in — the contract makes them MUST-level
  and says they are not named — with a note saying so, so their absence does not
  read as a narrowing.

- Re-vendor `openapi.json` at **1.0.0-alpha38**. The server registered the four
  GDPR data-subject endpoints (`POST /api/v1/account/export`,
  `GET /api/v1/account/export/{token}`, `POST /api/v1/account/delete`,
  `GET /api/v1/auth/account/delete/cancel`), taking the document to 181
  operations across 121 paths. Purely additive, and no SDK surface changes with
  it: nothing in this repo is generated from the spec, so the cross-repo
  artifact-drift gate was the only thing reporting `STALE`.

- `LoginResult` gained `mfa_setup_required` and `setup_token` (§25.2 rule 1): a
  `403` carrying `mfa_setup_required` now fills them instead of throwing a
  generic `AuthzError` with the body discarded. **Additive**, because this type
  is a flags struct rather than a discriminated union — an existing caller that
  checks `mfa_required` and otherwise assumes success still compiles.

- `Client::login` routes through `send_raw` rather than `execute` so that body is
  readable; every other status still goes through the same §2 mapping.

- The WebAuthn challenge is lifted out of the response body as **raw text**
  rather than as a `json` node. `nlohmann::json` stores object members in a
  `std::map`, so a parse-then-dump round trip comes back sorted — the server's
  member order gone, numbers through a double — and what the caller hands the
  authenticator would no longer be what the server sent (§24.0). The
  authenticator's response travels the same way, spliced into the request body as
  text.

- Both halves of an MFA enrolment are `Sensitive<std::string>` (§25.3). The
  `otpauth://` URI *contains* the secret, so wrapping `secret_base32` and leaving
  the URI a plain string would wrap nothing — the URI is the field that actually
  gets logged, because it is the one a caller passes to a QR renderer.

- `examples/reactor/` is no longer a hand-rolled reimplementation. It drives the
  library's runtime over a transport skeleton and calls `amqps_endpoint` before
  anything opens a socket, which is what §8b rule 7's second clause asks an
  example to show.

- Re-vendored `CONTRACT.md` at 1.28 and `openapi.json`.

- **BREAKING** — the OPAQUE protocol is NOT implemented in this SDK. CONTRACT
  §23.1 forbids it, so `src/opaque.cpp` is a `dlopen`/`dlsym` binding to
  `libaxiam_opaque_ffi` — the same implementation the AXIAM server links,
  published as a per-platform asset on the axiam-opaque release page. It is
  resolved at RUN time, so a consumer who never uses OPAQUE needs nothing extra
  at build time and `opaque_available()` can honestly answer `false`. Put the
  library on the loader path or point `AXIAM_OPAQUE_LIBRARY` at it.

- **Your OpenSSL version no longer decides which tenants work.** Argon2id
  arrives as an `EVP_KDF` only in OpenSSL 3.2, so the SRP path had to refuse a
  default-configured (`argon2id`) tenant on anything older — operators either
  upgraded OpenSSL or weakened the tenant to `pbkdf2_sha256`. Key stretching now
  happens inside the native library, so OpenSSL 1.1.1 serves every tenant and
  `srp::argon2_available()` has no successor.

- `opaque_enrollment()` performs I/O — one `register/start` round trip — where
  `srp_enrollment()` was pure. OPAQUE's envelope is sealed under the server's
  oblivious PRF, so there is no offline computation that produces a valid
  record. It also loses the `identity`, `group` and `params` arguments: a record
  binds to a credential identifier the server chooses, so passing an email where
  a username was wanted can no longer produce an unusable credential, **renaming
  a user no longer invalidates it**, and the costs are the server's.

- Every cost in `OpaqueKsfParams` is a `std::optional<unsigned>` rather than a
  zero-defaulted `unsigned`: a field that does not apply to the named function
  is absent on the wire, not zero (§23.4 rule 5).

- Re-vendor `openapi.json` at **1.0.0-alpha32**, matching the server. The
  content was already byte-identical in every path and schema; only
  `info.version` differed, which is what the cross-repo artifact-drift gate
  reports as `STALE`.

### Removed

- **BREAKING** — SRP-6a. `Client::login_srp`, `Client::srp_enrollment`,
  `Client::srp_available`, `include/axiam/srp.hpp`, `src/srp.cpp` and
  `srp-test-vectors.json` are all gone. AXIAM's server-side SRP endpoints are
  removed in the same release, so keeping the client would leave a method that
  only ever returns 404.

### Added (§23, earlier in this cycle)

- OPAQUE (RFC 9807) login and enrolment (CONTRACT §23): `Client::login_opaque`
  and `Client::opaque_enrollment`, plus `Client::opaque_available` for choosing
  the password path up front. `login_opaque` returns the same `LoginResult` as
  `login`, MFA branch included.

- `include/axiam/opaque.hpp`, `src/opaque.cpp`, `examples/opaque_login.cpp`,
  `tests/test_opaque_binding.cpp` and `tests/test_opaque_login.cpp`.

## [1.0.0-alpha31] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha30.

## [1.0.0-alpha30] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha29.

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP-6a login client (CONTRACT §23) (#34)

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Re-vendor openapi.json at 1.0.0-alpha27 (#33)

## [1.0.0-alpha27] - 2026-08-17

### Changed

- Re-vendor CONTRACT.md 1.23 (§8b rules 7 and 8)
- Re-vendor CONTRACT.md 1.22 and openapi.json from the server repo
- Ratchet the C++ line-coverage floor 95 -> 96
- Cover the §12 refusal paths and the sender-constrained authenticator

## [1.0.0-alpha25] - 2026-08-16

### Added

- Subject_token_type is required (contract 1.13)
- §15.7 — external-IdP subject tokens at the exchange (X4)
- §12, §12.7, §14 and §15 — the ported deferral (contract 1.11) (#20)
- §20.3 — emit a UMA challenge from the §11 guard (#19)
- §20 UMA 2.0 — Protection API and ticket grant (#18)
- §16 retry, §17 decision memo, §18 close(), §19 telemetry (D5)
- §11 rule 9 decision reason codes; contract 1.7 re-sync (D6) (#15)
- **A NON-NORMATIVE §22 reactor sample — `examples/reactor/` (CONTRACT.md
  §22.11).** §22.11 plans exactly this sample for the C++ SDK and is explicit
  about its standing: "It is an example, not a contract surface: this section
  governs, and the sample conforms to it or is wrong."

  **This SDK still ships no reactor runtime.** Nothing was added under
  `include/axiam/` or `src/`, nothing new is installed, and the conformance
  statement is untouched — §22.11's MUST NOT forbids claiming §22 while shipping
  no runtime. What the sample is, is the worked form of what §22.11 says still
  binds an integrator: the §8 v2 verification set on the event (key version, then
  MAC, then two-sided freshness, then the nonce seen-set — in that order, before
  the payload is decoded), the signed reply shape with its omission rules —
  including that `hmac_signature` serializes as **`null`** inside a reactor body
  rather than being omitted as it is in §8's own two message types — the §22.5
  namespace-prefix allow-lists, §22.8's strictest-wins failure-policy
  composition, and §22.7's hot-path exclusion.

  So "conforms to it or is wrong" is checkable rather than aspirational, the
  program runs the committed **§22.13 reference vectors** (vendored from the
  server's own sign path) in both directions and exits non-zero if a byte
  differs. It needs no broker and no network. The AMQP client stays an abstract
  seam with no declare or bind method (§22.1), because that missing client is the
  whole reason §22.11 defers the runtime.

  Built behind the existing `AXIAM_BUILD_EXAMPLES` option, like every other
  example here.
- **CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens**
  (contract 1.15, RFC 8705 §3 / RFC 7800). A token carrying `cnf` is **not** a bearer
  token; accepting one without proving the caller holds the named key converts it back
  into one.
  - `axiam::verify_certificate_binding(claims_json, presented_thumbprint)` — the rule.
    Returns `bool` and never throws, so every failure path is a rejection.
  - `axiam::certificate_thumbprint_s256(der)` — RFC 8705 §3.1 `x5t#S256`: base64url,
    **unpadded**, SHA-256 over the DER certificate.
  - `TokenAuthenticator::authenticate_sender_constrained(token, presented_thumbprint)` —
    the entry point for a resource server that accepts bound tokens.

  **Not a breaking change, and it does not make certificates mandatory.** An *unbound*
  token is still accepted with or without a certificate.

  `authenticate()` deliberately does **not** apply rule 9: it has no transport to ask for
  a peer certificate. The thumbprint must come from the transport, never from a
  caller-settable header. A `cnf` naming an unimplemented method is **rejected**, never
  read as "unconstrained".

- **CONTRACT.md §21** — the FAPI 2.0 posture as an SDK sees it. Only rule 9 is normative
  for this SDK.
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

- Build and run the §22.11 reactor example as a conformance gate
- Docs+examples: CONTRACT.md §22.11 — README pointer and the non-normative reactor sample (#28)
- Re-vendor CONTRACT.md 1.19 and openapi.json from main (R5.8) (#27)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#25)
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
- Make the §9 single-flight tests wait for arrivals, not a clock
- Runnable §16–§19 example for the C++ SDK (F3) (#17)
- Stop the concurrency test's keep-alive server hanging on shutdown
- Re-vendor `openapi.json` at 1.0.0-alpha27 — the copy was pinned at alpha26 and
  failing the cross-repo artifact-drift gate
- **README now points at CONTRACT.md §22.11 (the deferred reactor runtime).**
  §22.11 carries a SHOULD that these READMEs point at it "so an integrator finds
  the wire chapter rather than concluding reactors are unavailable" — the
  "Deferred / follow-ups" section listed §8 AMQP and said nothing about §22, which
  is exactly where a reader would draw that wrong conclusion. Documentation only,
  and **no §22 conformance claim**.

- **Re-vendored `CONTRACT.md` (1.17 → 1.19) and `openapi.json` from
  `ilpanich/axiam@main`.** The vendored copies had drifted; both are now
  byte-identical to the upstream artifacts. **No code change** — nothing in
  1.18 or 1.19 binds this SDK's implemented surface.
  - **§22 Reactors — AMQP extension actors (contract 1.18).** A new chapter
    describing external allow/deny/mutate actors on the AMQP bus.
    [§22.11](CONTRACT.md) defers the *runtime helper* (`reactor_serve`) in
    Swift, C and C++ for the same reason [§8](CONTRACT.md) has never listed
    them among the SDKs that speak AMQP: no maintained AMQP client for these
    targets this project is willing to vendor. §22.1–§22.8 remain a wire
    protocol that binds a hand-rolled integrator in full, and the §22.13
    vectors are the conformance surface for one. This SDK ships no reactor
    runtime and is exactly as conformant as it was under 1.17.
  - **SDK-Q10 closed (contract 1.19)** — the gRPC decision gains `reason`
    (field 4) and deprecates `deny_reason`, converging on the REST shape this
    SDK already speaks. This SDK is REST-only, so nothing moves:
    `axiam::AccessDecision` already exposes exactly `allowed` + `reason` +
    `reason_code` and has never carried a `resource_type`, which is the shape
    [§11.2](CONTRACT.md) rule 9's amendment now makes canonical for both
    transports.
  - `openapi.json` picks up the X5.1 server surface (`dpop_bound_access_tokens`,
    `dpop_require_nonce`, `jwks`/`jwks_uri` on client registration,
    `private_key_jwt` as a client-auth method, `CnfClaim.jkt`) and the reactor
    registration health counters (`recent_timeout_count`, `recent_veto_count`).
    No paths added or removed, no schemas added or removed.
- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.**
- **Re-sync vendored `CONTRACT.md` to contract 1.14** — documentation only, no code change.
  §20.2 rule 6 (a permission ticket MUST NOT be retried) cited a "measured residual
  (ilpanich/axiam#302) … roughly 1 in 640" as its second reason. That residual is closed: the
  server now decides the ticket race with a transaction its storage engine arbitrates plus a
  redemption nonce read back after the commit. **The rule is unchanged, and this SDK's
  behaviour is unchanged** — `uma_exchange_ticket` stays excluded from every automatic retry
  path. What changed is the reasoning: the first reason (a spent ticket makes the retry
  useless) always stood alone, and the second now rests on what an SDK can actually know —
  it is talking to a server whose storage engine it cannot attest, and the guarantee is
  conditional on that engine being persistent.
- **BREAKING (contract 1.13): `TokenExchangeParams::subject_token_type` is now required**, and
  its type narrows from `std::optional<std::string>` to `std::string`. It shipped optional,
  defaulting to `kAccessTokenType` when unset — which satisfied §15.7's "never inspect the
  subject token" while leaving the rule it serves unenforced: an optional member with a default
  *is* a default the SDK applies whenever the caller says nothing. §15.1 now makes it required.

  C++ cannot make an aggregate member mandatory, so the demand lands at the call: an empty
  `subject_token_type` throws `AuthError` **client-side, with no wire call**, naming both
  constants. A test asserts zero token calls.

  **Migration** — one line, naming what you were previously getting by silence:

  ```cpp
  axiam::TokenExchangeParams params;
  params.subject_token      = axiam::Sensitive<std::string>(user_token);
  params.subject_token_type = axiam::kAccessTokenType;  // <- add this
  ```

  This closes a gap rather than opening one: `subject_token_type` has always been required *on
  the wire*, and the SDK was covering for that with a constant which stopped being the only
  legal value when X4 landed. For a caller who actually held a refresh token, the old default
  traded the `invalid_request` that names the type for a generic `invalid_grant`.
- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` (the server's `/uma2/*` surface).

- **Re-vendored `CONTRACT.md` and `openapi.json`** from `ilpanich/axiam` at
  contract 1.7. Of the sections 1.7 adds, only §11 rule 9 is implemented here;
  §12.7 (logout), §14 (device grant) and §15 (token exchange) all build on a §12
  OIDC relying-party layer this SDK does not have, and are recorded under
  Deferred / follow-ups in the README rather than half-shipped.
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

### Fixed

- Refuse both-bound tokens; document the §21.7.3 declining posture (#26)
- Serve concurrent callers in parallel, not one at a time (D2/J6)
- **CONTRACT.md §10.1 rule 9 conjunction fix, and the §21.7.3 declining posture
  documented (contract 1.16).**

  A `cnf` naming **both** a certificate and a DPoP `jkt` was previously accepted
  on the matching certificate alone, ignoring the `jkt` entirely. Two named
  constraints are a **conjunction**, and this SDK declines §21.7.2 proof
  verification — so it can establish one half and must not answer for the whole.
  Such a token is now refused. The old behaviour would let a caller holding the
  certificate but **not** the DPoP key through a door the operator bolted twice.

  Pure `jkt`-bound tokens were already refused and remain so. The README now
  documents the declining posture, completing §21.7.3's three obligations
  (reject, document, test).

  Not a breaking change for certificate-only deployments: a token naming only
  `x5t#S256` behaves exactly as before, and an unbound token is still accepted
  with or without a certificate.
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

## [1.0.0-alpha24] - 2026-08-04

### Added

- Safe-by-default authenticator, webhook verifier, https-only base URL, keep-alive transport
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

### Changed

- Add the §10.1 rule-8 guardrail regression tests (#13)
- Device (mTLS) tokens now carry aud=axiam:m2m (#12)
- Service accounts can use login_client_credentials (#11)
- Add ASan+UBSan and valgrind gates (§13.4 observation 10 / §12.6.1) (#10)
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

### Fixed

- Bound the verification clock skew and fix base64url UB (§10.1)
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
- Adopt CONTRACT.md 1.3: the new gRPC-only `get_user_info` operation (CONTRACT §1.1) is
  documented as a deferred follow-up (this SDK ships no gRPC transport in v1) and the
  vendored contract copy is re-synced. Per §1.1 the REST `/oauth2/userinfo` endpoint is not substituted.

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

### Changed

- Resolve org_id from access-token claim for the refresh body (D-14) (#2)
- Publish API docs to gh-pages branch
- Drop configure-pages step, mirror C SDK template
- Auto-enable GitHub Pages (enablement: true)
- Add docs publish workflow to GitHub Pages

### Deferred

- gRPC transport and §8 AMQP HMAC consumer (out of scope for v1).
