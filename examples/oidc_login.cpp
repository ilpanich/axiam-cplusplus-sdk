// oidc_login — the OIDC relying-party flow (CONTRACT.md §12), plus §12.7 logout.
//
// A browser redirect has an awkward home in a C++ program, and that is exactly
// why this example is worth reading: the SDK does the two halves the redirect
// sits between, and it deliberately does NOT do the middle.
//
//   1. oidc_discover()  — fetch the document once; the client caches it.
//   2. oidc_begin()     — build the authorization URL. NO NETWORK I/O.
//   3. …your application sends the user agent there and receives the callback…
//   4. oidc_exchange()  — trade the code for a validated token set.
//   5. logout_url()     — build the end-session URL when they leave.
//
// THE PART THIS EXAMPLE EXISTS TO MAKE UNMISSABLE (§12.3 rule 1): the SDK stores
// NOTHING between steps 2 and 4. `state`, `nonce` and `code_verifier` come out
// of oidc_begin() and the application has to keep them — and so does the
// `redirect_uri`, which AuthorizationRequest deliberately does not carry,
// because RFC 6749 §4.1.3 requires it replayed byte-identically. A web
// application parks all four in its own session; a CLI writes them to a
// temporary file. Either way it is the caller's storage, and there is no
// SDK-side cache that will quietly cover for losing them.
//
// Step 3 is not shown because this SDK is an AXIAM client, not an HTTP server:
// an example that shipped its own listener would be demonstrating that instead
// of §12. Feed the code and state your callback received through the
// environment.
//
// Note also what is NOT printed below. `state` and `nonce` are correlation
// values and are safe to display; the access token, the refresh token, the ID
// token and the code verifier are not, and none of them reaches stdout here.

#include <cstdlib>
#include <iostream>
#include <string>

#include "axiam/client.hpp"

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v != nullptr && *v != '\0') ? std::string(v) : fallback;
}

}  // namespace

int main() {
    const std::string redirect_uri =
        env_or("AXIAM_REDIRECT_URI", "https://app.example.com/callback");

    try {
        auto builder = axiam::Client::builder()
                           .base_url(env_or("AXIAM_BASE_URL", "https://localhost:8443"))
                           // §12.3 rule 4: five of the nine operations put the
                           // tenant in a `?tenant_id=` query parameter, which
                           // requires a UUID. A slug-only client is refused
                           // client-side rather than sent to fail on the server.
                           .tenant_id(env_or("AXIAM_TENANT_ID",
                                             "11111111-1111-1111-1111-111111111111"))
                           // §12.1: the client_id is CONFIGURATION, not a
                           // per-call argument, because §12.4 rule 4 compares an
                           // ID token's `aud` against the same value.
                           .oidc_client_id(env_or("AXIAM_OIDC_CLIENT_ID", "example-rp"));
        // Optional. A public client omits it and no `client_secret` goes out.
        const std::string secret = env_or("AXIAM_OIDC_CLIENT_SECRET", "");
        if (!secret.empty()) builder.oidc_client_secret(secret);
        auto client = builder.build();

        // --- 1. discovery ------------------------------------------------
        const auto doc = client.oidc_discover();
        std::cout << "issuer:        " << doc.issuer << "\n"
                  << "authorization: " << doc.authorization_endpoint << "\n"
                  << "end_session:   "
                  << doc.end_session_endpoint.value_or("(not advertised)") << "\n";

        // --- 2. begin (no network I/O) -----------------------------------
        const auto request = client.oidc_begin(doc, redirect_uri, "openid profile");

        std::cout << "\nSend the user agent to:\n  " << request.url << "\n";
        // Safe to print: §12.3 rule 2 classes these as correlation values rather
        // than secrets, and the caller has to be able to compare them on return.
        std::cout << "\nKeep these until the callback arrives — the SDK does not:\n"
                  << "  state         " << request.state << "\n"
                  << "  nonce         " << request.nonce << "\n"
                  // Streams the placeholder, always (§7). The value is still
                  // there; it just does not go to a terminal.
                  << "  code_verifier " << request.code_verifier << " (keep it, never log it)\n"
                  << "  redirect_uri  " << redirect_uri << "\n";

        // --- 4. exchange, once the callback has happened ------------------
        const std::string code = env_or("AXIAM_AUTH_CODE", "");
        if (code.empty()) {
            std::cout << "\nSet AXIAM_AUTH_CODE (and AXIAM_RETURNED_STATE) to continue "
                         "past the redirect.\n";
            return 0;
        }
        // The CSRF check is the application's, not the SDK's — the SDK never saw
        // the callback. Comparing the returned `state` against the one from step
        // 2 is what stops an attacker's authorization code being exchanged
        // inside this user's session.
        const std::string returned_state = env_or("AXIAM_RETURNED_STATE", "");
        if (!returned_state.empty() && returned_state != request.state) {
            std::cerr << "state mismatch — refusing to exchange\n";
            return 1;
        }

        axiam::OidcExchangeParams params;
        params.code = code;
        params.code_verifier = request.code_verifier;
        params.redirect_uri = redirect_uri;  // byte-identical to step 2
        params.nonce = request.nonce;        // §12.4 rule 6 is mandatory here

        const auto tokens = client.oidc_exchange(params);

        // §12.4 rule 7 already ran: had any rule failed there would be no token
        // set at all, not a token set with unvalidated claims.
        std::cout << "\nSigned in.\n"
                  << "  token_type   " << tokens.token_type << " (expires in "
                  << tokens.expires_in << "s)\n"
                  << "  access_token " << tokens.access_token << "\n";
        if (tokens.id_claims) {
            std::cout << "  sub          " << tokens.id_claims->subject << "\n"
                      << "  iss          " << tokens.id_claims->issuer << "\n";
            if (tokens.id_claims->email) {
                std::cout << "  email        " << *tokens.id_claims->email << "\n";
            }
            // §12.3 rule 5: a relying party's claims come from HERE. There is no
            // userinfo operation in this SDK, and calling GET /oauth2/userinfo
            // is forbidden.
        }

        // --- 5. logout (§12.7, no network I/O) ---------------------------
        if (tokens.id_token) {
            // The ID token goes in whole, as a plain string: §12.7.5 is explicit
            // that a wrapper whose purpose is to resist stringification is the
            // wrong type for a value about to be embedded in a URL. It still
            // must not be logged, which is why the URL is not printed in full.
            const auto url = axiam::logout_url(doc, axiam::detail::reveal(*tokens.id_token));
            if (url) {
                std::cout << "\nOn sign-out, redirect to the end-session endpoint "
                             "(URL withheld — it embeds the ID token).\n";
            }
        }
        return 0;
    } catch (const axiam::OidcValidationError& e) {
        // An ID-token validation failure names the §12.4 rule that failed.
        std::cerr << "id_token rejected (" << e.reason() << "): " << e.what() << "\n";
        return 1;
    } catch (const axiam::OAuthProtocolError& e) {
        // An OAuth2 refusal names itself. Separate vocabularies, separate types.
        std::cerr << "refused (" << e.error_code() << "): " << e.what() << "\n";
        return 1;
    } catch (const axiam::AxiamError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
