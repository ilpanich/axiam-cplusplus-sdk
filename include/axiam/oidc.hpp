// §12 OIDC relying party, §12.7 logout, §14 device grant, §15 token exchange.
//
// WHY THIS FILE EXISTS AT ALL. Contract 1.10 and earlier deferred §12 in the
// Swift, C and C++ SDKs: these are device- and IoT-oriented, and the
// browser-redirect relying-party flow has no natural home in any of them.
// Contract 1.11 (§12.6) reverses that, and the reason is worth keeping next to
// the code. The persona argument only ever covered two of the nine operations —
// `oidc_begin` and `oidc_exchange`, the pair that genuinely assumes a browser.
// The other seven are exactly what an embedded consumer wants:
// `login_client_credentials` is machine-to-machine login, `introspect` and
// `revoke` are ordinary questions a device asks about its own credentials, and
// `oidc_refresh` is the grant the §9 single-flight guard was built for.
// Meanwhile §14 (device grant) exists *because* a device cannot show a browser,
// and §20 (UMA) already gave this SDK a `/oauth2/token` call — so by 1.10 it was
// speaking OAuth2 at the token endpoint anyway, without the shared discovery
// cache and ID-token validation §12 specifies. This removes a divergence rather
// than adding one.
//
// THE FOUR THINGS THIS SURFACE WILL NOT DO FOR YOU:
//
//  1. It stores no `state`, `nonce` or `code_verifier` (§12.3 rule 1). They come
//     back out of Client::oidc_begin and the caller hands them to
//     Client::oidc_exchange. There is no implicit cache, and the caller must
//     also remember its own `redirect_uri` — RFC 6749 §4.1.3 requires it
//     replayed byte-identically and AuthorizationRequest deliberately does not
//     carry it (§12.1).
//  2. It never skips ID-token validation. There is no flag, no "insecure" entry
//     point, and no partial result: §12.4 rule 7 is all-or-nothing, so a token
//     set whose `id_token` fails any check is discarded whole — the access and
//     refresh tokens from the same response never reach the caller.
//  3. It adopts nothing. Every operation here returns tokens; none of them
//     become this client's own credential. §15.2 rule 5 makes that a MUST NOT
//     for the exchanged token specifically, and this SDK takes the same posture
//     everywhere rather than having two.
//  4. It does not retry a grant. §16.2 lists `oidc_exchange`, `device_authorize`,
//     `device_login` and `token_exchange` as ineligible, because their
//     credentials are single-use: retrying replays a spent authorization code or
//     device code and turns a blip into a hard `invalid_grant`. Only the
//     read-only calls here — discovery, introspection, a `device_poll` that hit
//     a 5xx — go through §16.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "axiam/errors.hpp"
#include "axiam/sensitive.hpp"

namespace axiam {

/// §12.3 rule 6: the discovery cache TTL floor. A smaller configured value is
/// raised to this, never honoured.
inline constexpr int kOidcDiscoveryTtlFloorSeconds = 300;

/// §12.4 rule 5: the clock-skew ceiling. A larger configured value is clamped
/// DOWN to this, not rejected.
inline constexpr int kOidcMaxClockSkewSeconds = 60;

/// §12.4 rule 2: the unknown-`kid` re-fetch cooldown.
///
/// "One re-fetch then fail" taken literally is unimplementable against a warm
/// cache without handing an attacker one JWKS fetch per forged `kid`. The rule
/// is per WINDOW: the first unknown `kid` triggers exactly one re-fetch and
/// opens the window; another unknown `kid` inside it re-consults the cached set
/// with no network call and fails immediately.
inline constexpr int kOidcJwksRefetchCooldownSeconds = 60;

/// RFC 8628 §3.2 default poll interval when the response omits one (§14.2 rule 2).
inline constexpr int kDeviceDefaultIntervalSeconds = 5;
/// §14.2 rule 1: seconds added to the CURRENT interval on every `slow_down`.
inline constexpr int kDeviceSlowDownIncrementSeconds = 5;

inline constexpr const char* kDeviceCodeGrantType =
    "urn:ietf:params:oauth:grant-type:device_code";
inline constexpr const char* kTokenExchangeGrantType =
    "urn:ietf:params:oauth:grant-type:token-exchange";
/// The `actor_token_type` this SDK sends, and the `subject_token_type` it sends
/// when the caller names none — an AXIAM-issued access token (§15.1).
inline constexpr const char* kAccessTokenType =
    "urn:ietf:params:oauth:token-type:access_token";
/// A JWT from a trusted external issuer — the cross-domain exchange of §15.7.
///
/// Pass it as `TokenExchangeParams::subject_token_type` to exchange a partner
/// IdP's token. AXIAM also accepts `kAccessTokenType` for an external issuer,
/// and refuses refresh and ID token types **by name**.
inline constexpr const char* kJwtTokenType =
    "urn:ietf:params:oauth:token-type:jwt";
/// The Back-Channel Logout 1.0 §2.4 event key §12.7.3 rule 3 requires.
inline constexpr const char* kBackchannelLogoutEvent =
    "http://schemas.openid.net/event/backchannel-logout";

/// The §12.3 rule 3 ID-token validation reason codes.
///
/// A CLOSED vocabulary of exactly seven. No SDK may add an eighth, so several
/// distinct failures deliberately share one code and the sharing is normative,
/// not incidental:
///
/// * `token_expired` covers EVERY §12.4 rule 5 time failure — a past `exp`, an
///   ABSENT `exp`, an absent or future `iat`, and a future `nbf`. There is no
///   `token_not_yet_valid` and no `missing_exp`.
/// * `unknown_kid` covers "the JOSE header carries no `kid` at all" as well as
///   "no key matches it", and a JWKS transport failure during the rule-2
///   re-fetch surfaces here rather than as `invalid_signature`.
/// * `invalid_alg` covers a JOSE header that cannot be parsed at all, since the
///   algorithm cannot then be established.
/// * `invalid_signature` is the catch-all, so no unclassified case needs a code
///   of its own.
///
/// (A struct rather than a namespace, matching ReasonCode in types.hpp.)
struct OidcValidationReason {
    static constexpr const char* kInvalidAlg = "invalid_alg";
    static constexpr const char* kUnknownKid = "unknown_kid";
    static constexpr const char* kInvalidSignature = "invalid_signature";
    static constexpr const char* kInvalidIssuer = "invalid_issuer";
    static constexpr const char* kInvalidAudience = "invalid_audience";
    static constexpr const char* kTokenExpired = "token_expired";
    static constexpr const char* kNonceMismatch = "nonce_mismatch";
};

/// An ID-token (or logout-token) validation failure (§12.3 rule 3).
///
/// Derives from AuthError rather than being a fourth top-level type, exactly as
/// the contract models it — a caller that only knows about AuthError still
/// catches this. It is a SIBLING of OAuthProtocolError, not a subtype: the two
/// carry different closed vocabularies, and one of each pair is nearly a
/// homograph of the other (§14.2's terminal `expired_token` against §12.4
/// rule 5's `token_expired`). Keeping them distinct types makes "which
/// vocabulary am I catching?" unavoidable.
///
/// **The message never contains the token** (§2 construction rules, §12.7.3
/// rule 8).
class OidcValidationError : public AuthError {
public:
    OidcValidationError(const std::string& message, std::string reason)
        : AuthError(message), reason_(std::move(reason)) {}

    /// One of the OidcValidationReason:: constants.
    const std::string& reason() const noexcept { return reason_; }

private:
    std::string reason_;
};

/// The OIDC discovery document (§12.1), read from
/// `/.well-known/openid-configuration`.
///
/// `issuer` is the AUTHORITATIVE issuer for the §12.4 rule 3 check. The server
/// derives it from its own configuration, so behind a proxy it may legitimately
/// differ from the base URL this document was fetched from — §12.3 rule 6
/// forbids rejecting a document over that mismatch. Endpoints are likewise read
/// from here rather than concatenated onto the issuer, including `jwks_uri`.
struct OidcConfiguration {
    std::string issuer;
    std::string authorization_endpoint;
    std::string token_endpoint;
    std::string jwks_uri;
    std::optional<std::string> userinfo_endpoint;
    std::optional<std::string> introspection_endpoint;
    std::optional<std::string> revocation_endpoint;
    /// §12.7.2 rule 1: where logout_url() sends the user agent.
    std::optional<std::string> end_session_endpoint;
    /// §14.1: where device_authorize() starts the grant.
    std::optional<std::string> device_authorization_endpoint;
    std::vector<std::string> scopes_supported;
    std::vector<std::string> response_types_supported;
    /// Advertised ID-token algorithms. INFORMATIONAL ONLY: §12.4 rule 1 pins
    /// verification to `EdDSA` regardless of what this list says, so a server
    /// that additionally advertised `RS256` could not talk this SDK into it.
    std::vector<std::string> id_token_signing_alg_values_supported;
};

/// What Client::oidc_begin returns (§12.1).
///
/// **The caller owns all three correlation values** (§12.3 rule 1). This SDK
/// stores none of them — not on the client, not in a global, not in an implicit
/// cache — so they must be persisted by the application (typically in its own
/// session) and handed back to oidc_exchange.
///
/// **There is no `redirect_uri` member**, and that is the contract's shape
/// rather than an omission (§12.1). `oidc_exchange` must replay it
/// byte-identically, so the caller has to remember it alongside the three
/// below. §12.1 calls that footgun out deliberately, and so does this comment.
struct AuthorizationRequest {
    /// The URL to send the user agent to.
    std::string url;
    /// CSRF correlation value. NOT a secret (§12.3 rule 2) — the caller compares
    /// it on return, so it has to be readable.
    std::string state;
    /// Replay-protection value, checked into the ID token by the server and
    /// asserted by §12.4 rule 6. Not a secret, for the same reason.
    std::string nonce;
    /// The PKCE verifier whose S256 challenge went out in the URL. Secret for
    /// its WHOLE lifetime, including while it sits here (§12.5).
    Sensitive<std::string> code_verifier;
};

/// The validated claims of an ID token (§12.4). Present on a token set only when
/// the response carried an `id_token` AND every §12.4 rule passed.
struct IdTokenClaims {
    std::string subject;
    std::string issuer;
    std::vector<std::string> audience;
    std::int64_t expires_at = 0;
    std::int64_t issued_at = 0;
    std::optional<std::string> nonce;
    /// `azp`; required by §12.4 rule 4 when `aud` holds more than one audience.
    std::optional<std::string> authorized_party;
    std::optional<std::string> email;
    std::optional<std::string> preferred_username;
    std::optional<std::string> tenant_id;
    std::vector<std::string> roles;
    /// Every claim the server sent, as raw JSON text.
    ///
    /// §12.1 requires SDKs to PRESERVE claims beyond the named ones and forbids
    /// rejecting unknown ones — the ID token's full claim set is not enumerated
    /// by `openapi.json`. This is the language-idiomatic open map's stand-in for
    /// a header that does not want a JSON type in its public surface.
    std::string raw_claims_json;
};

/// The result of every §12 token-endpoint grant (§12.1).
///
/// `id_claims` is engaged exactly when `id_token` is, because there is no path
/// that returns an unvalidated ID token: §12.4 rule 7 discards the whole set on
/// any validation failure.
struct OidcTokenSet {
    Sensitive<std::string> access_token;
    std::string token_type;
    std::int64_t expires_in = 0;
    std::optional<std::string> scope;
    std::optional<Sensitive<std::string>> refresh_token;
    std::optional<Sensitive<std::string>> id_token;
    std::optional<IdTokenClaims> id_claims;
};

/// RFC 7662 introspection result (§12.1).
///
/// `active` is the only field guaranteed present — an inactive token answers
/// `{"active":false}` and nothing else, which is the whole point of the endpoint.
struct IntrospectionResult {
    bool active = false;
    std::optional<std::string> scope;
    std::optional<std::string> client_id;
    std::optional<std::string> username;
    std::optional<std::string> token_type;
    std::optional<std::string> subject;
    std::optional<std::string> audience;
    std::optional<std::string> issuer;
    std::optional<std::string> jwt_id;
    std::optional<std::int64_t> expires_at;
    std::optional<std::int64_t> issued_at;
};

/// `POST /api/v1/auth/federation/oidc/start` (§12.1) — where to send the user
/// agent for upstream-IdP federation, and the single-use `state` tying the
/// callback to it.
///
/// There is no nonce here, and that is the server's design: it keeps the
/// federation nonce server-side (§12.1 note 7), so an SDK has nothing to store
/// and nothing to check.
struct SsoStartResult {
    std::string authorize_url;
    std::string state;
    std::int64_t expires_in_secs = 0;
};

/// `POST /api/v1/auth/federation/oidc/callback` (§12.1) — the completed
/// federation login.
///
/// **Carries no token material.** The session arrives as `Set-Cookie` and lands
/// in the §4 cookie jar (§12.1 note 6); a client without a persistent cookie
/// store silently loses it.
struct SsoCompleteResult {
    std::string user_id;
    std::string session_id;
    std::int64_t expires_in = 0;
    std::optional<std::string> redirect_uri;
};

/// A verified back-channel logout token (§12.7.3).
///
/// **Never collapsed to a bool**, per §12.7.3: the relying party has to know
/// WHICH session to end, and a verifier that only says "valid" forces the caller
/// to re-parse the token themselves with none of the checks applied.
///
/// `jwt_id` is surfaced so the RP can deduplicate. This SDK deliberately does
/// NOT dedup internally: delivery is at-least-once, so a valid token
/// legitimately arrives twice, and a library with no durable store would
/// silently drop a real second logout after a restart.
///
/// **When `sid` is present, end THAT session only.** Falling back to "every
/// session for `sub`" is an over-reach the server itself refuses to make.
struct VerifiedLogoutToken {
    std::optional<std::string> sid;
    std::optional<std::string> subject;
    std::optional<std::string> jwt_id;
    std::string issuer;
    std::int64_t issued_at = 0;
};

/// `POST /oauth2/device_authorization` (§14.1) — the codes a device shows its
/// user.
struct DeviceAuthorization {
    /// A bearer credential for the life of the grant (§14.5), hence wrapped.
    Sensitive<std::string> device_code;
    /// The code the USER types. Not wrapped — §14.5 is explicit that wrapping it
    /// would defeat the one thing it exists for. It still must not be logged;
    /// displaying it is the caller's job.
    std::string user_code;
    std::string verification_uri;
    /// Embeds the user code so a device that can render a QR code does not make
    /// the user type anything. Surfaced when the server sends it and **never
    /// synthesised by concatenation** when it does not (§14.3): its format is
    /// the server's to choose.
    std::optional<std::string> verification_uri_complete;
    /// Seconds until the whole grant expires. Polling stops here (§14.2 rule 4).
    std::int64_t expires_in = 0;
    /// Seconds between polls, from the RESPONSE (§14.2 rule 2). 5 when omitted.
    std::int64_t interval = kDeviceDefaultIntervalSeconds;
};

/// Called once, BEFORE the first poll, with the codes the device must display
/// (§14.3 rule 2).
///
/// The SDK does not print them on the caller's behalf and does not begin polling
/// until this returns: a device shows them however it can — a screen, a QR code,
/// an e-ink panel — and only the application knows which.
using DeviceCodeDisplay = std::function<void(const DeviceAuthorization&)>;

/// `POST /oauth2/token` with the RFC 8693 grant (§15.1) — a NARROWER token.
///
/// There is no refresh-token member, and §15.2 rule 4 makes that structural
/// rather than incidental: an exchange only ever narrows, and a refresh token
/// would let the holder re-widen later. Re-run the exchange for a fresh one.
struct ExchangedToken {
    Sensitive<std::string> access_token;
    /// §15.2 rule 6: surfaced, never dropped — a client that asked for one type
    /// and received another has to be able to tell.
    std::string issued_token_type;
    std::string token_type;
    std::int64_t expires_in = 0;
    /// The scopes actually GRANTED, which §15.2 rule 7 permits to be narrower
    /// than the ones requested even on success. Read it.
    std::optional<std::string> scope;
};

/// Arguments to Client::oidc_exchange.
struct OidcExchangeParams {
    /// The authorization code from the redirect. Single-use — hence no retry.
    std::string code;
    /// The verifier oidc_begin produced, kept by the caller (§12.3 rule 1).
    Sensitive<std::string> code_verifier;
    /// Replayed BYTE-IDENTICALLY from the authorization request (RFC 6749
    /// §4.1.3).
    std::string redirect_uri;
    /// The nonce oidc_begin produced. REQUIRED: §12.4 rule 6 makes the check
    /// mandatory for this operation — the helper always requests `openid`, so
    /// the server always issues a nonce, and a caller with nothing to compare
    /// against has lost replay protection without noticing.
    std::string nonce;
    /// Tenant UUID for the mandatory `?tenant_id=` query parameter. Falls back
    /// to the client's configured tenant id; a SLUG is never a substitute
    /// (§12.3 rule 4) and is refused client-side, with no wire call.
    std::optional<std::string> tenant_id;
};

/// Arguments to Client::token_exchange.
struct TokenExchangeParams {
    /// The token being exchanged. Required.
    Sensitive<std::string> subject_token;
    /// What kind of token `subject_token` is (§15.7).
    ///
    /// `std::nullopt` sends `kAccessTokenType`, the same-domain exchange of
    /// §15.1. To exchange a token from a **trusted external issuer**, name it
    /// explicitly — normally `kJwtTokenType`.
    ///
    /// This SDK never reads `subject_token` to decide the value: which kind of
    /// token the caller holds is only the caller's to know, AXIAM refuses
    /// refresh and ID token types by name, and a refusal is never retried as a
    /// different type.
    std::optional<std::string> subject_token_type;
    /// **Its presence selects delegation; its absence selects impersonation.**
    ///
    /// Two different operations with different risk, and §15.2 rule 1 forbids
    /// papering over the difference: this SDK supplies no default and never
    /// substitutes the client's own session. Leaving this empty asks for
    /// impersonation, and the server refuses unless this client holds that
    /// grant.
    std::optional<Sensitive<std::string>> actor_token;
    /// Omit to inherit the subject's, bounded by this client's registration —
    /// and read the RESULT's `scope` for what was actually granted.
    std::vector<std::string> scopes;
    std::optional<std::string> audience;
    std::optional<std::string> resource;
    std::optional<std::string> tenant_id;
};

/// Build the RP-Initiated Logout 1.0 URL (§12.7.1). **Pure local computation.**
///
/// @param config   An already-fetched document. `end_session_endpoint` comes
///                 from it — §12.7.2 rule 1 forbids concatenating it onto the
///                 issuer, which works against AXIAM and breaks against every
///                 other OP the same code is pointed at. `std::nullopt` when the
///                 document advertises none: a guess is not an answer.
/// @param id_token Placed in `id_token_hint`. A plain string because §12.7.5 is
///                 explicit: it is about to be embedded in a URL handed to a
///                 browser, and a wrapper whose purpose is to resist
///                 stringification is the wrong type for a value that must be
///                 stringified. It still must never be logged. There is
///                 deliberately NO hint-less mode that names the user some other
///                 way — no such parameter exists on the wire.
/// @param post_logout_redirect_uri Optional, and **not pre-validated against a
///                 local list** (§12.7.2 rule 3): the allow-list lives in the
///                 client's server-side registration, and a client-side copy
///                 would drift and reject a URI an operator had just registered.
/// @param state    Optional, and the CALLER's to generate and check (§12.7.2
///                 rule 2) — the SDK passes it through and never invents one.
///
/// This does NOT end the SDK client's own session (§12.7.2 rule 4). Whether the
/// local session ends is the application's call — a backend holding a
/// service-account session must not lose it because a *user* logged out.
std::optional<std::string> logout_url(
    const OidcConfiguration& config, const std::string& id_token,
    std::optional<std::string> post_logout_redirect_uri = std::nullopt,
    std::optional<std::string> state = std::nullopt);

}  // namespace axiam
