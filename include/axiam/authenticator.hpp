// §10 safe-by-default request authenticator.
//
// This is THE entry point for turning an inbound credential into an AxiamUser.
//
// <axiam/jwks.hpp> ships a deliberately minimal primitive
// (JwksVerifier::verify_signature_only_unchecked) that proves a token was signed
// by the org's Ed25519 key and stops there. A valid signature is not an
// authentication decision: the JWKS endpoint is org-wide, so a signature alone
// says nothing about whether the token has expired, has started being valid, or
// was minted for THIS tenant. Wiring the raw primitive into a route guard
// therefore accepts expired and cross-tenant tokens.
//
// TokenAuthenticator closes that gap. Every successful authenticate() has
// established, in order:
//
//   1. the compact JWS is well formed and `alg` is EdDSA;
//   2. the signature verifies against the cached JWKS;
//   3. `exp` is present, is an integer, and has not passed (allowing a small,
//      named clock skew);
//   4. `nbf`, when present, is an integer and has arrived (same skew);
//   5. `tenant_id` is present, is a non-empty string, and equals the tenant this
//      authenticator was configured with;
//   6. optionally, `iss` / `aud` match configured expectations.
//
// Anything missing, malformed or mismatched is a failure — the authenticator
// fails closed and never returns a partially-checked identity.
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/guard.hpp"
#include "axiam/jwks.hpp"

namespace axiam {

/// Clock seam: returns the current time as unix seconds. Injected in tests.
using NowFn = std::function<std::int64_t()>;

/// CONTRACT §10.1 rule 7 — the leeway applied to `exp` and `nbf` must be a
/// *named*, documented, bounded constant, never an inline literal and never
/// operator-configurable to an unbounded value.
///
/// `kMaxClockSkew` is the hard ceiling the constructor enforces; it is the
/// value §10.1 recommends (60 s). `kDefaultClockSkew` is deliberately stricter
/// than the ceiling: every second of leeway is a second in which an already
/// expired access token is still admitted, so the default takes only what a
/// well-synchronised deployment actually needs. Anything above the ceiling is
/// rejected at construction rather than silently honoured.
inline constexpr std::chrono::seconds kDefaultClockSkew{30};
inline constexpr std::chrono::seconds kMaxClockSkew{60};

/// Tuning for TokenAuthenticator. The defaults are the safe ones.
struct AuthenticatorOptions {
    /// Tolerance applied to `exp` and `nbf` for small clock differences between
    /// this resource server and the AXIAM issuer. Deliberately small: it widens
    /// the window in which an expired access token is still accepted. Must be
    /// in [0, kMaxClockSkew]; anything else throws from the constructor.
    std::chrono::seconds clock_skew{kDefaultClockSkew};

    /// When set, the `iss` claim must be present and equal to this value.
    std::optional<std::string> expected_issuer;

    /// When set, the `aud` claim must be present and must contain this value
    /// (`aud` may be a string or an array of strings).
    std::optional<std::string> expected_audience;

    /// Time source. Empty => the system clock.
    NowFn now;
};

/// Safe-by-default local verification of an AXIAM access token.
///
/// Holds a non-owning pointer to the JwksVerifier it was built from; that
/// verifier (usually `client.jwks()`) must outlive the authenticator.
class TokenAuthenticator {
public:
    /// @param jwks               key source, typically `client.jwks()`.
    /// @param expected_tenant_id the tenant this resource server serves. Every
    ///        token's `tenant_id` claim must equal it exactly.
    /// @throws std::invalid_argument when expected_tenant_id is empty — an
    ///         empty expectation would silently disable the tenant check — or
    ///         when options.clock_skew is negative or exceeds kMaxClockSkew.
    TokenAuthenticator(JwksVerifier& jwks, std::string expected_tenant_id,
                       AuthenticatorOptions options = {});

    /// Verify `token` and build the authenticated identity.
    /// @throws AuthError on any verification failure. The message never contains
    ///         token material.
    AxiamUser authenticate(const std::string& token) const;

    /// Non-throwing twin, for wiring into AxiamGuard / framework adapters.
    std::optional<AxiamUser> try_authenticate(const std::string& token) const;

    /// authenticate() plus CONTRACT.md §10.1 **rule 9** — the sender constraint
    /// (RFC 8705 §3 / RFC 7800, contract 1.15).
    ///
    /// This is the entry point for a resource server that accepts
    /// **certificate-bound** access tokens. `presented_thumbprint` is the
    /// RFC 8705 §3.1 `x5t#S256` of the peer certificate on the current
    /// connection, or `std::nullopt` when there is none;
    /// axiam::certificate_thumbprint_s256() computes it from DER bytes.
    ///
    /// A separate method rather than a parameter on authenticate() because the
    /// two have different *inputs*: most integrations have no transport-level
    /// certificate to offer, and folding the thumbprint in would force every
    /// caller to thread a `nullopt` they do not have — which reads as "no
    /// certificate" and rejects every bound token.
    ///
    /// **An unbound token is still accepted** here, with or without a
    /// certificate. Rule 9 constrains tokens that claim a constraint; it does
    /// not make certificates mandatory.
    ///
    /// @throws AuthError on any rule violation, rules 1-8 and 9 alike.
    AxiamUser authenticate_sender_constrained(
        const std::string& token,
        const std::optional<std::string>& presented_thumbprint) const;

    /// The tenant every token is bound to.
    const std::string& expected_tenant_id() const noexcept { return tenant_id_; }

    /// Extract a bearer token from an `Authorization` header value.
    /// Returns nullopt when the scheme is absent or is not `Bearer`.
    static std::optional<std::string> bearer_from_authorization(const std::string& header_value);

    /// Extract the `axiam_access` token from a `Cookie` request header value.
    static std::optional<std::string> token_from_cookie_header(const std::string& cookie_header);

    /// Build a §10 guard authenticator: given a way to pull the raw credential
    /// out of a framework request, returns the functor AxiamGuard expects. The
    /// resulting functor borrows this authenticator, so keep it alive.
    template <typename Request>
    typename AxiamGuard<Request>::Authenticator guard_authenticator(
        std::function<std::optional<std::string>(const Request&)> extract_token) const {
        const TokenAuthenticator* self = this;
        return [self, extract_token](const Request& req) -> std::optional<AxiamUser> {
            auto token = extract_token(req);
            if (!token.has_value()) return std::nullopt;
            return self->try_authenticate(*token);
        };
    }

private:
    JwksVerifier* jwks_;
    std::string tenant_id_;
    AuthenticatorOptions options_;
};

/// Convenience factory: an authenticator bound to a client's JWKS verifier.
/// The client must outlive the returned authenticator.
inline TokenAuthenticator make_authenticator(Client& client, std::string expected_tenant_id,
                                             AuthenticatorOptions options = {}) {
    return TokenAuthenticator(client.jwks(), std::move(expected_tenant_id), std::move(options));
}

}  // namespace axiam
