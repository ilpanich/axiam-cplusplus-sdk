// §20 UMA 2.0 — Protection API and ticket grant.
//
// The resource-server side of User-Managed Access: a service that guards
// resources on someone else's behalf registers them, asks the authorization
// server what a caller would need, and exchanges the resulting ticket for a
// Requesting Party Token.
//
// WHY THIS SHIPS WHILE §12 DOES NOT. The README defers §12.7, §14 and §15
// because each needs an OIDC layer this SDK does not have — a discovery cache,
// ID-token validation, PKCE. §20 needs none of it: UMA carries its OWN
// discovery document (`/.well-known/uma2-configuration`, §20.1's named wire
// reference), the Protection API is ordinary bearer-authenticated REST, and the
// ticket grant returns an opaque RPT with no `id_token` to validate. One GET and
// one POST. The parallel-stack objection genuinely does not apply here, so the
// deferral would have been a habit rather than a reason.
//
// THE RULE THIS FILE EXISTS TO ENFORCE. A permission ticket is single-use and
// is NOT retryable. Every other refusal in this SDK can be re-sent after the
// caller fixes something; this one cannot — the ticket is spent whether or not
// the exchange succeeded. See Client::uma_exchange_ticket.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "axiam/errors.hpp"
#include "axiam/sensitive.hpp"

namespace axiam {

/// The scope a PAT must carry (§20.2 rule 1) — for callers minting one.
inline constexpr const char* kUmaProtectionScope = "uma_protection";

/// `grant_type` of the UMA 2.0 ticket grant (§20.1).
inline constexpr const char* kUmaTicketGrantType =
    "urn:ietf:params:oauth:grant-type:uma-ticket";

/// The only `claim_token_format` AXIAM implements. §20.2 rule 2 makes the
/// `claim_token` itself required rather than defaulted; the FORMAT has one
/// value, so the SDK supplies it.
inline constexpr const char* kUmaClaimTokenFormat =
    "urn:ietf:params:oauth:token-type:access_token";

/// The UMA 2.0 discovery document (§20.1).
///
/// Endpoints are read from this document and never hardcoded, for the same
/// reason §12.3 rule 6 gives for the OIDC one: a deployment is free to move them.
struct UmaConfiguration {
    std::string issuer;
    std::string token_endpoint;
    std::string permission_endpoint;
    std::string resource_registration_endpoint;
    /// The ticket TTL the server advertises, so a resource server can size its
    /// own timing against it rather than discovering it by having one expire.
    std::optional<long> permission_ticket_lifetime;
};

/// A UMA resource set — an AXIAM resource seen through the Protection API
/// (§20.1).
///
/// `id` is **the AXIAM resource id**, not a parallel identifier: the same UUID
/// is directly usable as UmaRequestedPermission::resource_id, and as the
/// resource id anywhere else in this SDK.
struct UmaResourceSet {
    /// Assigned by the server on registration; empty on the way in.
    std::optional<std::string> id;
    /// Human-readable name, shown in the admin UI.
    std::string name;
    /// Free-form resource type. Omitted from the payload when empty, so the
    /// server applies its own `uma_resource` default rather than storing an
    /// empty string that sorts oddly next to hand-made resources.
    std::optional<std::string> type;
    /// The scope names a resource server may ask for on this resource.
    ///
    /// **Replaced wholesale by an update, never merged** (§20.2 rule 8) — this
    /// SDK does not read the current scopes and fold them into an update payload
    /// as a convenience, because that would make removing a scope impossible
    /// through it.
    std::vector<std::string> resource_scopes;
};

/// One `(resource, scopes)` pair a resource server requires (§20.1).
struct UmaRequestedPermission {
    /// The AXIAM resource id — the same UUID the Protection API returned.
    std::string resource_id;
    /// Scope names, each of which the resource must already declare. Matched
    /// exactly: no prefix or wildcard semantics in either direction.
    std::vector<std::string> resource_scopes;
};

/// One entry of an RPT's `permissions` claim (§20.1).
///
/// **A record of a decision already made, not a live authorization answer**
/// (§20.2 rule 7). These are the pairs the engine allowed when the RPT was
/// minted; a grant revoked afterwards does not empty a live RPT. Do not cache
/// them beyond the token's own expiry — which is why that expiry is short.
struct UmaRptPermission {
    std::string resource_id;
    std::vector<std::string> resource_scopes;
    /// Absolute expiry, seconds since the epoch.
    long exp = 0;
};

/// The result of the UMA ticket grant (§20.1).
///
/// **There is no `refresh_token` member, and that is deliberate** (§20.2
/// rule 5). The grant issues none, so an RPT cannot outlive the ticket that
/// authorised it; an application that wants a fresh one re-runs the grant. This
/// result never enters the §9 single-flight refresh guard — there is nothing to
/// refresh.
struct RequestingPartyToken {
    /// The RPT itself (§20.6 secret).
    Sensitive<std::string> access_token;
    /// Always `Bearer`.
    std::string token_type;
    /// `min(claim token remaining, server ceiling, 300 s)`.
    long expires_in = 0;
};

/// A parsed `WWW-Authenticate: UMA` challenge (UMA 2.0 §3.2, §20.3).
struct UmaChallenge {
    std::optional<std::string> realm;
    /// The authorization server the resource server nominates.
    /// **Not automatically trusted** — see uma_parse_challenge().
    std::optional<std::string> as_uri;
    /// The ticket to exchange — a bearer credential for its 60-second life.
    std::optional<Sensitive<std::string>> ticket;
};

/// The confidential-client credentials the ticket grant authenticates with
/// (§20.1).
///
/// Passed per call rather than held on the Builder: this SDK implements no other
/// token-endpoint operation, and a client identity on the builder would imply an
/// OIDC client identity it does not otherwise have.
struct UmaClientCredentials {
    std::string client_id;
    Sensitive<std::string> client_secret;
};

/// Arguments to Client::uma_exchange_ticket.
struct UmaExchangeTicketParams {
    /// The permission ticket to redeem (§20.6 secret). Required.
    ///
    /// SINGLE-USE AND NOT RETRYABLE: it is spent whether or not the exchange
    /// succeeds. A failure means "request a NEW ticket", never "send this one
    /// again" (§20.2 rule 6).
    Sensitive<std::string> ticket;
    /// The requesting party's access token (§20.6 secret). Required, and never
    /// defaulted (§20.2 rule 2) — it is the only channel that names the
    /// requesting party.
    Sensitive<std::string> claim_token;
    /// The confidential client authenticating at the token endpoint.
    UmaClientCredentials credentials;
    /// Tenant UUID for the mandatory `?tenant_id=` query parameter (§12.1
    /// note 2). Falls back to the client's configured tenant id; a tenant SLUG
    /// is never a valid substitute (§12.3 rule 4).
    std::optional<std::string> tenant_id;
};

/// An OAuth2 protocol refusal from the ticket grant (§20.4).
///
/// Derives from AuthError rather than being a fourth top-level type, exactly as
/// the contract models it: the §2 taxonomy stays at three, and a caller that
/// only knows about AuthError still catches this.
///
/// **Dispatch on error_code(), not on the HTTP status.** §20.4 puts
/// `access_denied` on a `403` where RFC 8628's is a `400`, and the code is what
/// stays correct if either moves.
class OAuthProtocolError : public AuthError {
public:
    OAuthProtocolError(const std::string& message, std::string error_code,
                       std::optional<std::string> error_description)
        : AuthError(message),
          error_code_(std::move(error_code)),
          error_description_(std::move(error_description)) {}

    /// The `error` field: `invalid_grant`, `access_denied`, `invalid_client`, …
    const std::string& error_code() const noexcept { return error_code_; }
    /// The server's `error_description`, when it sent one.
    const std::optional<std::string>& error_description() const noexcept {
        return error_description_;
    }

private:
    std::string error_code_;
    std::optional<std::string> error_description_;
};

/// Parse a `WWW-Authenticate: UMA …` header value (§20.3), or `std::nullopt`
/// when the header names a different scheme.
///
/// **Pure local computation — it performs no exchange of the ticket it finds**,
/// and that is the point. Parsing a challenge and acting on it are separate
/// decisions: the `as_uri` names an authorization server the client has not
/// necessarily chosen to trust, and auto-exchanging would send the requesting
/// party's `claim_token` to whatever host answered the `401`. The parsed
/// challenge is returned; the caller decides.
std::optional<UmaChallenge> uma_parse_challenge(const std::string& header);

/// Format a `WWW-Authenticate: UMA` header value (§20.3, emit half) — for a
/// resource server that has just minted a ticket and wants to tell the caller
/// where to redeem it.
std::string uma_challenge_header(const std::string& realm, const std::string& as_uri,
                                 const Sensitive<std::string>& ticket);

}  // namespace axiam
