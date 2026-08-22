// par_login.cpp — Pushed Authorization Requests, RFC 9126 (CONTRACT.md §26).
//
// PAR moves the authorization request off the browser. Instead of putting
// `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the user
// agent carries, the client POSTs them straight to AXIAM over an authenticated
// back channel and puts an opaque handle in the redirect. What travels through
// the browser is then a random string that cannot be edited into meaning
// something else — no `redirect_uri` to swap, no `scope` to widen, nothing for a
// referrer header or a shoulder to leak.
//
// TWO THINGS TO NOTICE, because both are easy to get wrong:
//
//  1. The server answers 201, not 200 — RFC 9126 §2.2 specifies Created. Code
//     written `if (status == 200)` treats every successful push as a failure.
//  2. The redirect carries EXACTLY `client_id` and `request_uri`. AXIAM refuses
//     a request that mixes a request_uri with inline authorization parameters
//     rather than merging them, because merging is where parameter confusion
//     lives: an attacker supplies the inline value they want and lets the pushed
//     copy satisfy whichever check reads the other one. Re-adding `scope` "for
//     compatibility" restores the attack.
//
// REQUIRED FOR A FAPI 2.0 CLIENT: `profile: "fapi2"` refuses a registration that
// does not set `require_par`, so such a client cannot authorize any other way
// (§21.1).
//
// Build:  cmake -S . -B build && cmake --build build
// Run:    ./build/examples/axiam_example_par_login
#include <cstdlib>
#include <iostream>
#include <string>

#include "axiam/axiam.hpp"

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v && *v) ? std::string(v) : fallback;
}

}  // namespace

int main() {
    const std::string base_url = env_or("AXIAM_BASE_URL", "https://localhost:8443");
    const std::string tenant_id =
        env_or("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000");
    const std::string client_id = env_or("AXIAM_OIDC_CLIENT_ID", "example-rp");
    const std::string client_secret = env_or("AXIAM_OIDC_CLIENT_SECRET", "example-secret");
    const std::string redirect_uri =
        env_or("AXIAM_REDIRECT_URI", "https://app.example.com/callback");

    try {
        auto client = axiam::Client::builder()
                          .base_url(base_url)
                          // §12.1 rule 2: the /oauth2 family takes the tenant as
                          // a query parameter in UUID form. A slug is never a
                          // substitute here and is refused client-side.
                          .tenant_id(tenant_id)
                          .oidc_client_id(client_id)
                          .oidc_client_secret(client_secret)
                          .build();

        // Discovery is what says whether this server supports PAR at all. §26.1
        // forbids synthesising the endpoint from the issuer — a server that does
        // not advertise it does not have it, and guessing `/oauth2/par` produces
        // a 404 that reads like a broken request.
        const auto doc = client.oidc_discover();
        if (!doc.pushed_authorization_request_endpoint) {
            std::cout << "this server does not advertise a PAR endpoint — "
                         "use examples/oidc_login.cpp instead\n";
            return 0;
        }

        // §26.2 rule 1: everything the push sends was computed HERE. There is no
        // second generator inside oidc_par, and there must not be — two sources
        // for `state` or the PKCE pair are two things that can disagree, and
        // when they do the failure surfaces at the exchange as an opaque
        // `invalid_grant` a long way from the code that caused it.
        const auto request = client.oidc_begin(doc, redirect_uri, "openid profile");

        // The push itself. NOT RETRIED on a 5xx or a transport failure (§26.2
        // rule 4): it is a POST that creates server state, so it falls outside
        // §16.2's read-only eligibility exactly as oidc_exchange does. The safe
        // recovery is a fresh push — one round trip, and it cannot
        // double-consume anything.
        const auto pushed = client.oidc_par(doc, request, redirect_uri, "openid profile");

        // Exactly two parameters, and the handle is single-use with a short life
        // (§26.2 rule 3 — `expires_in` is not advisory). It is Sensitive because
        // between this line and the redirect it is a bearer handle to a
        // fully-formed authorization request; `state` and `nonce` stay readable
        // because the caller has to compare them when the IdP comes back.
        std::cout << "send the user agent to:\n  " << pushed.url << "\n";
        std::cout << "the handle expires in " << pushed.expires_in
                  << " s (in a log it reads: " << pushed.request_uri << ")\n";

        // §12.3 rule 1: the SDK stores none of this. Persist `state`, `nonce`
        // and the PKCE verifier in your own session — plus the redirect_uri,
        // which RFC 6749 §4.1.3 requires replayed byte-identically and which
        // §12.1 deliberately does not carry for you.
        std::cout << "persist across the redirect: state=" << pushed.state
                  << " nonce=" << pushed.nonce << " (+ the code_verifier)\n";

        const std::string code = env_or("AXIAM_AUTH_CODE", "");
        if (code.empty()) {
            std::cout << "(set AXIAM_AUTH_CODE to run the exchange)\n";
            return 0;
        }

        // The exchange is unchanged by PAR — same code, same verifier, same
        // nonce. PAR protected the request on its way to the IdP; it does not
        // change what comes back.
        axiam::OidcExchangeParams params;
        params.code = code;
        params.code_verifier = pushed.code_verifier;
        params.redirect_uri = redirect_uri;
        params.nonce = pushed.nonce;
        const auto tokens = client.oidc_exchange(params);
        std::cout << "exchanged: token_type=" << tokens.token_type
                  << " expires_in=" << tokens.expires_in << "\n";
    } catch (const axiam::AxiamError& e) {
        std::cerr << "axiam: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
