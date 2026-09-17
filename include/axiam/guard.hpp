// §10 route-guard interface + §11 declarative authorization helpers.
//
// Framework-agnostic: the host adapter (Crow / Pistache / any HTTP server) pulls
// the raw credential out of the request; turning it into an AxiamUser is the job
// of axiam::TokenAuthenticator in <axiam/authenticator.hpp>, which is the
// supported §10 verification path (signature + exp + nbf + tenant binding, fail
// closed). Do NOT build an AxiamUser straight from
// JwksVerifier::verify_signature_only_unchecked — that primitive validates the
// signature only, so a guard fed from it accepts expired and cross-tenant tokens.
//
// The helpers here run strictly AFTER that identity exists and compose on top of
// the client's check_access surface; they never re-implement token verification.
#pragma once

#include <exception>
#include <functional>
#include <initializer_list>
#include <optional>
#include <string>
#include <vector>

#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/mcp.hpp"
#include "axiam/sensitive.hpp"
#include "axiam/uma.hpp"

namespace axiam {

/// Authenticated identity injected by the §10 guard into the request context.
struct AxiamUser {
    std::string user_id;
    std::string tenant_id;
    std::vector<std::string> roles;

    bool has_role(const std::string& role) const {
        for (const auto& r : roles) {
            if (r == role) return true;
        }
        return false;
    }
};

/// §11 require_auth — endpoint requires an authenticated identity.
/// @throws AuthError (→ HTTP 401) when no verified user is present.
inline const AxiamUser& require_auth(const std::optional<AxiamUser>& user) {
    if (!user.has_value()) {
        throw AuthError("authentication_failed");
    }
    return *user;
}

/// §11 require_role — local check against the verified token's roles. No server
/// round-trip. Coarser than require_access; not a substitute for it.
/// @throws AuthError (401) when unauthenticated, AuthzError (403) when no role matches.
inline void require_role(const std::optional<AxiamUser>& user,
                         std::initializer_list<std::string> any_of) {
    const AxiamUser& u = require_auth(user);
    for (const auto& role : any_of) {
        if (u.has_role(role)) return;
    }
    throw AuthzError("authorization_denied: missing required role");
}

/// §11 require_access — authorize the REQUEST's user (subject propagation:
/// subject_id = user.user_id) for `action` on `resource_id`.
///
/// - unauthenticated            → AuthError (401)
/// - denied / server 403        → AuthzError (403)
/// - transport/network failure  → AuthzError (fail-closed 503 authz_unavailable)
///
/// Argument order follows §1: action before resource.
inline void require_access(Client& client, const std::optional<AxiamUser>& user,
                           const std::string& action, const std::string& resource_id,
                           std::optional<std::string> scope = std::nullopt) {
    const AxiamUser& u = require_auth(user);
    if (resource_id.empty()) {
        // §11.3: unresolvable resource id is a programming error (400).
        throw std::invalid_argument("invalid_request: unresolved resource id");
    }
    AccessDecision decision;
    try {
        decision = client.check_access(action, resource_id, std::move(scope), u.user_id);
    } catch (const AuthzError&) {
        throw;  // server said 403/409 → denied
    } catch (const NetworkError&) {
        // §11.5: fail closed on transport failure; never allow.
        throw AuthzError("authz_unavailable");
    }
    if (!decision.allowed) {
        throw AuthzError("authorization_denied");
    }
}

/// A configured `WWW-Authenticate: UMA` challenge emitter (§20.3, emit half).
///
/// Pass one to the require_access overload below and a denial stops being a bare
/// AuthzError: the guard mints a fresh permission ticket for the pair the caller
/// lacked and throws an AuthzChallengeError carrying the formatted header, so a
/// UMA-aware adapter can hand the caller something to act on.
///
/// **Opt-in, and deliberately so.** Emitting a challenge means minting a
/// credential — a wire call to the Protection API, and a live ticket, produced
/// on a path the caller did not explicitly request. A guard that did that on
/// every denial by default would turn each unauthorized request into a
/// Protection API call, which is a denial-of-service amplifier pointed at your
/// own authorization server. So the existing overloads are untouched and this is
/// a separate one.
///
/// **Failure is not escalation.** If minting fails — the PAT expired, the
/// Protection API is down, the resource declares none of the requested scopes —
/// the denial still surfaces as a plain AuthzError. A caller who was going to be
/// refused is refused either way; letting a Protection API outage turn a deny
/// into a 503 would hand the outage a second consequence, and letting it turn
/// into an allow would be a security bug.
struct UmaChallenger {
    /// The protection realm to name in the header.
    std::string realm;
    /// The authorization server to send the caller to — normally this
    /// deployment's issuer, read from Client::uma_discover() rather than
    /// concatenated by hand.
    std::string as_uri;
    /// A Protection API Token: a *client-credentials* token carrying the
    /// `uma_protection` scope (§20.2 rule 1). A user token cannot stand in — a
    /// minted ticket is bound to the client_id that minted it.
    Sensitive<std::string> pat;
};

/// §11 require_access, with §20.3 challenge emission on a denial.
///
/// Identical to the overload above in every outcome; additionally, a denial
/// throws AuthzChallengeError (which *is* an AuthzError) carrying a freshly
/// minted ticket for (resource_id, action).
///
/// The requested UMA scope is the AXIAM *action*: asking for anything else would
/// offer the caller authority other than the one they were denied, and would
/// step outside the grants the engine just evaluated — deny rules included.
inline void require_access(Client& client, const std::optional<AxiamUser>& user,
                           const std::string& action, const std::string& resource_id,
                           const UmaChallenger& challenger,
                           std::optional<std::string> scope = std::nullopt) {
    try {
        require_access(client, user, action, resource_id, std::move(scope));
        return;
    } catch (const AuthzError& denial) {
        // Captured before the nested try: inside it, current_exception() would be
        // the *minting* failure, and a bare `throw;` there would surface that
        // instead of the denial — turning a 403 into whatever went wrong at the
        // Protection API, which is exactly the escalation this must not do.
        const std::exception_ptr original = std::current_exception();
        std::string header;
        try {
            auto ticket = client.uma_request_ticket(
                challenger.pat, {UmaRequestedPermission{resource_id, {action}}});
            header = uma_challenge_header(challenger.realm, challenger.as_uri, ticket);
        } catch (const AxiamError&) {
            // Swallowed deliberately — see UmaChallenger. The denial stands on
            // its own; only the sugar is lost.
            std::rethrow_exception(original);
        }
        throw AuthzChallengeError(denial.what(), std::move(header), denial.action(),
                                  denial.resource_id());
    }
}

/// §11 require_access, with CONTRACT.md §28.5 rule 5 challenge emission on a
/// `no_grant` denial.
///
/// Identical to the two-argument overload above in every outcome **except
/// one**: when `scope` was given, `challenges` carries an
/// `insufficient_scope` value (i.e. is not `std::nullopt`, built by
/// `mcp_challenges()`), and the server's decision came back
/// `allowed = false` with `reason_code` `"no_grant"`, the denial is
/// `AuthzChallengeError` (which *is* AuthzError) carrying the challenge
/// naming that scope, verbatim (rule 6). Every other denial — `denied_by_rule`,
/// an absent or unrecognised `reason_code`, no `scope` argument, or
/// `challenges` of `std::nullopt` (§28 off) — throws the same plain
/// `AuthzError` the two-argument overload does, with **no** header: reading
/// this twice matters more than reading it once, because the §11 JSON body
/// never changes either way (§28.5 rule 5's own "read this twice").
inline void require_access(Client& client, const std::optional<AxiamUser>& user,
                           const std::string& action, const std::string& resource_id,
                           const std::optional<McpChallenges>& challenges,
                           std::optional<std::string> scope = std::nullopt) {
    const AxiamUser& u = require_auth(user);
    if (resource_id.empty()) {
        throw std::invalid_argument("invalid_request: unresolved resource id");
    }
    AccessDecision decision;
    try {
        decision = client.check_access(action, resource_id, scope, u.user_id);
    } catch (const AuthzError&) {
        throw;
    } catch (const NetworkError&) {
        throw AuthzError("authz_unavailable");
    }
    if (decision.allowed) return;
    if (challenges.has_value() && scope.has_value() && decision.reason_code.has_value() &&
        *decision.reason_code == ReasonCode::kNoGrant) {
        throw AuthzChallengeError("authorization_denied",
                                  mcp_insufficient_scope_challenge(*challenges, *scope), action,
                                  resource_id);
    }
    throw AuthzError("authorization_denied");
}

/// Resolver-based overload (§11.3c): resolve the resource id from an arbitrary
/// request object via a callback, then delegate to the guard above.
template <typename Request>
void require_access(Client& client, const std::optional<AxiamUser>& user,
                    const std::string& action,
                    const std::function<std::string(const Request&)>& resolver,
                    const Request& request, std::optional<std::string> scope = std::nullopt) {
    require_access(client, user, action, resolver(request), std::move(scope));
}

/// §10 guard functor: a callable that turns a request into an AxiamUser using a
/// caller-supplied authenticator (the §10 verification adapter). Throws AuthError
/// when the request carries no valid session.
///
/// **CONTRACT.md §28.5 rule 4** adds the second constructor below, opt-in:
/// with it unused, this class is unchanged from before §28 existed, and the
/// single-argument constructor and operator() are byte-for-byte what they
/// always were — §28.9's regression is exactly this guarantee.
template <typename Request>
class AxiamGuard {
public:
    using Authenticator = std::function<std::optional<AxiamUser>(const Request&)>;

    /// §28.5's vector 1 / vector 2 choice needs to know whether `request`
    /// carried a credential of any kind — a fact the plain `Authenticator`
    /// above no longer has, because both "no credential" and "credential
    /// rejected" already collapsed to `std::nullopt` by the time it returns.
    /// `true` does not mean the credential was valid, only that one was
    /// presented; used only when the §28 constructor below is.
    using CredentialProbe = std::function<bool(const Request&)>;

    explicit AxiamGuard(Authenticator auth) : auth_(std::move(auth)) {}

    /// CONTRACT.md §28.5: a guard that also emits the `WWW-Authenticate`
    /// challenge on every 401 it produces.
    ///
    /// `challenges` is normally `TokenAuthenticator::mcp_challenges()` — built
    /// from that authenticator's own `resource_metadata_url` /
    /// `expected_audience`, never a value re-entered here — so passing
    /// `std::nullopt` (that authenticator's default) is indistinguishable
    /// from having called the single-argument constructor above (§28.5 rule 1).
    /// `has_credential` is unused when `challenges` is `std::nullopt`.
    AxiamGuard(Authenticator auth, std::optional<McpChallenges> challenges,
              CredentialProbe has_credential)
        : auth_(std::move(auth)),
          challenges_(std::move(challenges)),
          has_credential_(std::move(has_credential)) {}

    AxiamUser operator()(const Request& request) const {
        auto user = auth_(request);
        if (user.has_value()) return *user;
        if (!challenges_.has_value()) return require_auth(user);  // unconfigured: identical to before §28
        const bool presented = has_credential_ && has_credential_(request);
        throw AuthChallengeError("authentication_failed",
                                 presented ? challenges_->invalid_token : challenges_->no_credential);
    }

    /// This guard's own §28 challenges — `std::nullopt` when built from the
    /// single-argument constructor, or from the §28 one with `std::nullopt`
    /// (§28 off either way). An adapter applying this guard globally
    /// (README.md's Crow/Pistache walkthroughs) checks
    /// `is_metadata_document_request(guard.mcp_challenges(), method, path)`
    /// **before** calling the guard, to exempt the document itself (§28.3
    /// rule 2).
    const std::optional<McpChallenges>& mcp_challenges() const noexcept { return challenges_; }

private:
    Authenticator auth_;
    std::optional<McpChallenges> challenges_;
    CredentialProbe has_credential_;
};

}  // namespace axiam

/// §11 C++ analog of the per-language require_access macro. Evaluates the guard
/// for `client`/`user` and throws on failure (AuthError/AuthzError), so it reads
/// as a one-line precondition at the top of a handler.
#define AXIAM_REQUIRE_ACCESS(client, user, action, resource) \
    ::axiam::require_access((client), (user), (action), (resource))

#define AXIAM_REQUIRE_AUTH(user) ::axiam::require_auth((user))
