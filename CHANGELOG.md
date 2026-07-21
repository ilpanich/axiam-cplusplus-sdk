# Changelog

All notable changes to the AXIAM C++ SDK are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project follows
semantic versioning (pre-release track `1.0.0-alpha*`).

## [Unreleased]

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
