// token_exchange — RFC 8693 token exchange (CONTRACT.md §15).
//
// A backend holding a user's access token trades it for a NARROWER one before
// calling the next service, so that service receives exactly the authority it
// needs and no more.
//
// The distinction this example exists to make concrete is the one §15.2 rule 1
// refuses to paper over:
//
//   DELEGATION    — actor token present. "I, service A, am acting on behalf of
//                   this user." The downstream token names both.
//   IMPERSONATION — actor token absent. "I am this user." The downstream service
//                   cannot tell a real user request from this one.
//
// They are different operations with different risk, and the SDK supplies no
// default actor token and never substitutes its own session for one. If you pass
// nothing, you asked for impersonation, and the server refuses unless this
// client is registered for it.
//
// Everything else here is about NOT helping: `unauthorized_client` is surfaced
// verbatim, `invalid_scope` is not a hint to retry with fewer scopes, no refresh
// token comes back ever, and the result is not adopted as this client's
// credential.

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "axiam/client.hpp"

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v != nullptr && *v != '\0') ? std::string(v) : fallback;
}

}  // namespace

int main() {
    const std::string subject = env_or("AXIAM_SUBJECT_TOKEN", "");
    if (subject.empty()) {
        std::cerr << "Set AXIAM_SUBJECT_TOKEN to the user access token this service holds.\n";
        return 2;
    }

    try {
        auto client =
            axiam::Client::builder()
                .base_url(env_or("AXIAM_BASE_URL", "https://localhost:8443"))
                .tenant_id(env_or("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111"))
                // §15.1: the exchanging client AUTHENTICATES — unlike §14's
                // device, this is a confidential service, and a client with no
                // secret is refused client-side.
                .oidc_client_id(env_or("AXIAM_OIDC_CLIENT_ID", "example-service"))
                .oidc_client_secret(env_or("AXIAM_OIDC_CLIENT_SECRET", "example-secret"))
                .build();

        axiam::TokenExchangeParams params;
        params.subject_token = axiam::Sensitive<std::string>(subject);
        // Present → delegation. Absent → impersonation. Nothing in between, and
        // no default.
        const std::string actor = env_or("AXIAM_ACTOR_TOKEN", "");
        if (!actor.empty()) params.actor_token = axiam::Sensitive<std::string>(actor);
        params.scopes = {"invoices:read"};
        const std::string audience = env_or("AXIAM_AUDIENCE", "");
        if (!audience.empty()) params.audience = audience;

        std::cout << "Requesting "
                  << (params.actor_token
                          ? "DELEGATION (actor token present)"
                          : "IMPERSONATION (no actor token — the server will refuse unless "
                            "this client holds that grant)")
                  << " of scope \"" << params.scopes.front() << "\"…\n";

        const auto exchanged = client.token_exchange(params);

        std::cout << "\nExchanged.\n"
                  << "  issued_token_type " << exchanged.issued_token_type << "\n"
                  << "  token_type        " << exchanged.token_type << " (expires in "
                  << exchanged.expires_in << "s)\n"
                  << "  access_token      " << exchanged.access_token << "\n"
                  // §15.2 rule 7: READ THIS. The granted set may be narrower
                  // than the one you asked for, even on success.
                  << "  granted scope     " << exchanged.scope.value_or("(inherited)") << "\n"
                  << "\nHand this to the downstream service in one outbound call. It is not\n"
                     "this client's session, and there is no refresh token — re-run the\n"
                     "exchange when it expires.\n";
        return 0;
    } catch (const axiam::OAuthProtocolError& e) {
        // §15.3 dispatches on the `error` field, and each of these is a
        // different thing to do next — which is why the SDK surfaces the code
        // rather than a single "exchange failed".
        if (e.error_code() == "unauthorized_client") {
            std::cerr << "\nThis client is not registered for the exchange (or for "
                         "impersonation). An operator has to fix the registration; there is "
                         "nothing to retry.\n";
        } else if (e.error_code() == "invalid_scope") {
            std::cerr << "\nThe subject does not hold that scope. The SDK did NOT quietly "
                         "retry with fewer — narrowing the ask is your decision to make "
                         "explicitly.\n";
        } else if (e.error_code() == "invalid_grant") {
            // §15.3: a cross-tenant subject token answers exactly this, and the
            // server collapses "wrong tenant" into "bad token" deliberately —
            // telling them apart is a tenant-enumeration signal. Do not guess.
            std::cerr << "\nThe subject token is not usable here (expired, revoked, or from "
                         "another tenant — the server does not say which).\n";
        } else {
            std::cerr << "\nexchange failed: " << e.what() << "\n";
        }
        return 1;
    } catch (const axiam::AxiamError& e) {
        std::cerr << "\nerror: " << e.what() << "\n";
        return 1;
    }
}
