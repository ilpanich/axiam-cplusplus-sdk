// JWKS fetch + Ed25519 (EdDSA) JWT *signature* verification.
//
// Fetches GET {base}/oauth2/jwks, caches the key set for 300s, and verifies a
// compact JWS using OpenSSL raw Ed25519 keys. Only alg == "EdDSA" is accepted;
// any other alg is rejected before signature work.
//
// !! This is an EXPERT-ONLY primitive. !!
// It checks the signature and NOTHING ELSE — no `exp`, no `nbf`, no `iss`, no
// `aud`, and no tenant binding. Wiring it directly into a request guard accepts
// expired tokens and tokens minted for a different tenant.
//
// The supported entry point for authenticating an inbound request is
// axiam::TokenAuthenticator in <axiam/authenticator.hpp>, which layers the
// expiry, not-before and tenant checks on top of this primitive and fails
// closed. Reach for JwksVerifier::verify_signature_only_unchecked() only when
// you are deliberately implementing those checks yourself.
#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <string>

#include "axiam/transport.hpp"

namespace axiam {

/// One Ed25519 (OKP) public key from the JWK set.
struct Ed25519Jwk {
    std::string kid;
    std::string x_b64url;  // 32-byte public key, base64url (unpadded)
};

/// Result of a successful verification: the decoded payload (claims) JSON string.
struct VerifiedToken {
    std::string payload_json;
};

/// Result of verify_with_reason(): the same signature check, plus the §12.3
/// rule 3 reason code naming which part of it failed.
///
/// The plain optional-returning entry point cannot say whether a token was
/// rejected for its algorithm, its `kid` or its signature, and §12 needs the
/// distinction: a caller has to be able to tell an attack (`invalid_alg` — a
/// token that chose its own verification algorithm) from a deployment problem
/// (`unknown_kid` — a key rotated out from under a stale cache).
struct JwtVerification {
    bool ok = false;
    /// Decoded claims, when ok.
    std::string payload_json;
    /// One of axiam::OidcValidationReason's constants, when !ok. Only the three
    /// signature-layer codes appear here — `invalid_alg`, `unknown_kid`,
    /// `invalid_signature`; §12.4 rules 3 to 6 are the caller's to apply.
    std::string reason;
};

/// Base64url decode (unpadded or padded). Returns nullopt on malformed input.
std::optional<std::string> base64url_decode(const std::string& in);

class JwksVerifier {
public:
    /// @param transport shared transport seam (same as the client's).
    /// @param base_url  server base URL (no trailing slash required).
    /// @param cache_ttl key-set cache lifetime (default 300s).
    JwksVerifier(Transport transport, std::string base_url,
                 std::chrono::seconds cache_ttl = std::chrono::seconds(300));

    /// EXPERT PRIMITIVE — signature only. Verifies a compact JWS against the
    /// cached Ed25519 key set (EdDSA only) and returns the decoded payload.
    /// Returns nullopt if the alg is not EdDSA, the kid is unknown, the token is
    /// malformed, or the signature does not verify.
    ///
    /// It performs NO claim validation whatsoever: an expired token, a
    /// not-yet-valid token and a token belonging to another tenant all come back
    /// as a successful result. The name says `unchecked` because the claims are
    /// unchecked. Use axiam::TokenAuthenticator (<axiam/authenticator.hpp>)
    /// unless you are implementing those checks yourself.
    std::optional<VerifiedToken> verify_signature_only_unchecked(const std::string& jwt);

    /// As verify_signature_only_unchecked(), but naming the failure.
    ///
    /// This is the entry point §12.4 rules 1 and 2 are implemented against, and
    /// the two share one body so the §10 authenticator and the §12 relying party
    /// cannot drift on what "verified" means — §12.4 says to EXTEND this
    /// verifier, never fork it.
    ///
    /// **§12.4 rule 2's unknown-`kid` handling lives here.** "One re-fetch then
    /// fail", taken literally against a warm cache, is unimplementable without
    /// handing an attacker one JWKS fetch per forged `kid`. The rule is per
    /// WINDOW: the first unknown `kid` triggers exactly one re-fetch and opens a
    /// cooldown; another unknown `kid` inside that window re-consults the cached
    /// set with NO network call and fails immediately. Neither weakening is
    /// permitted — "never re-fetch" breaks key rotation, "always re-fetch" is
    /// the amplification vector.
    JwtVerification verify_with_reason(const std::string& jwt);

    /// Force-refresh the cached key set (also called lazily by verify()).
    void refresh_keys();

    /// Test/introspection helper: number of currently-cached keys.
    std::size_t cached_key_count();

private:
    void ensure_keys_locked();
    void load_from_json(const std::string& body);

    Transport transport_;
    std::string base_url_;
    std::chrono::seconds cache_ttl_;

    std::mutex mtx_;
    std::map<std::string, Ed25519Jwk> keys_;  // kid -> jwk
    std::chrono::steady_clock::time_point fetched_at_{};
    /// When the §12.4 rule 2 unknown-`kid` cooldown window closes. Default-
    /// constructed (the epoch) means no window is open.
    std::chrono::steady_clock::time_point refetch_cooldown_until_{};
    bool have_keys_ = false;
};

}  // namespace axiam
