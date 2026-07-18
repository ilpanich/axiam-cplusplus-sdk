// §10 route-guard interface + §11 declarative authorization helpers.
//
// Framework-agnostic: the host adapter (Crow / Pistache / any HTTP server) is
// responsible for producing an AxiamUser from an incoming request (the §10
// verification path — cookie/Bearer extraction, JWKS check, tenant scope). The
// helpers here run strictly AFTER that identity exists and compose on top of the
// client's check_access surface; they never re-implement token verification.
#pragma once

#include <functional>
#include <initializer_list>
#include <optional>
#include <string>
#include <vector>

#include "axiam/client.hpp"
#include "axiam/errors.hpp"

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
