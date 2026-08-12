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
template <typename Request>
class AxiamGuard {
public:
    using Authenticator = std::function<std::optional<AxiamUser>(const Request&)>;

    explicit AxiamGuard(Authenticator auth) : auth_(std::move(auth)) {}

    AxiamUser operator()(const Request& request) const {
        auto user = auth_(request);
        return require_auth(user);
    }

private:
    Authenticator auth_;
};

}  // namespace axiam

/// §11 C++ analog of the per-language require_access macro. Evaluates the guard
/// for `client`/`user` and throws on failure (AuthError/AuthzError), so it reads
/// as a one-line precondition at the top of a handler.
#define AXIAM_REQUIRE_ACCESS(client, user, action, resource) \
    ::axiam::require_access((client), (user), (action), (resource))

#define AXIAM_REQUIRE_AUTH(user) ::axiam::require_auth((user))
