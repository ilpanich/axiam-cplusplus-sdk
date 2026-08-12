// uma_client.cpp — UMA 2.0 (CONTRACT.md §20), the CLIENT half of the example
// pair.
//
// Run examples/uma_resource_server first; this program consumes the challenge
// that one emits.
//
// The flow, which is the whole reason UMA exists:
//
//   1. Ask for the invoice with the user's ordinary token. The resource server
//      refuses — but its 403 carries `WWW-Authenticate: UMA` naming a ticket and
//      an authorization server.
//   2. PARSE the challenge. Note what happens next, and what does not: parsing
//      performs no exchange (§20.3). The as_uri in that header is a host the
//      *server we just failed against* chose; auto-redeeming would send the
//      user's token wherever a 403 pointed.
//   3. Decide to trust it, then EXCHANGE the ticket for an RPT.
//   4. Retry with the RPT.
//
// Step 3 is a decision, not a formality — this example makes it explicitly, by
// comparing the nominated as_uri against the issuer this client already trusts,
// and refusing when they differ.
//
// The refusal in step 1 arrives here as a header string from the environment
// rather than from a live HTTP call: this SDK is an AXIAM client, not a general
// HTTP client, and an example that shipped its own socket code would be
// demonstrating that instead of §20. Feed it the header your resource server
// returned.
//
// Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
// Run:    ./build/examples/axiam_example_uma_client

#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>

#include <axiam/axiam.hpp>

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v && *v) ? std::string(v) : fallback;
}

/// Compares issuers without letting a trailing slash decide a security question.
std::string without_trailing_slash(std::string value) {
    while (!value.empty() && value.back() == '/') value.pop_back();
    return value;
}

}  // namespace

int main() {
    auto client = axiam::Client::builder()
                      .base_url(env_or("AXIAM_BASE_URL", "https://localhost:8443"))
                      .tenant_slug(env_or("AXIAM_TENANT_SLUG", "acme"))
                      .build();

    // ---- 1. The refusal ----
    const std::string header = env_or("AXIAM_WWW_AUTHENTICATE", "");
    if (header.empty()) {
        // A resource server that refuses without a challenge is telling you it
        // has nothing to offer — there is no ticket to redeem, and retrying the
        // same request would be pointless.
        std::cout << "no WWW-Authenticate header: this refusal is not actionable.\n";
        std::cout << "set AXIAM_WWW_AUTHENTICATE to the header your resource server returned.\n";
        return 0;
    }

    // ---- 2. Parse, and only parse ----
    auto challenge = axiam::uma_parse_challenge(header);
    if (!challenge.has_value() || !challenge->ticket.has_value()) {
        std::cout << "the challenge names no ticket; nothing to redeem.\n";
        return 0;
    }

    // Nothing from the challenge is echoed, and there are two separate reasons.
    //
    // The ticket, because §20.6 says so: its 60-second life does not make it
    // harmless — for those 60 seconds it IS the credential that converts into an
    // RPT, so a header in a log line is a live credential in a log line.
    //
    // The realm and as_uri, because they are strings a *remote* server chose.
    // They are not secrets, but echoing attacker-controlled text into a terminal
    // or a log file is its own small hazard (escape sequences, log forging), and
    // an example is the last place to teach the habit. What matters here is the
    // shape of the challenge, not its contents.
    std::cout << "challenge parsed: as_uri present="
              << (challenge->as_uri.has_value() ? "yes" : "no") << ", ticket present=yes\n";

    try {
        // ---- 3. The trust decision ----
        //
        // This is the step §20.3 exists to keep in the caller's hands. The SDK
        // parsed the header and stopped; deciding whether to send the user's
        // token to the host it names is this program's call, and it is a real
        // one — a compromised or merely misconfigured resource server could
        // nominate anything here.
        auto configuration = client.uma_discover();
        if (challenge->as_uri.has_value() &&
            without_trailing_slash(*challenge->as_uri) !=
                without_trailing_slash(configuration.issuer)) {
            // Neither side of the comparison is echoed. The nominated value for
            // the reasons above; our own issuer because printing values read
            // back off a configured client is a habit that is fine here and
            // wrong three refactors later. The decision and its outcome are what
            // a reader needs; the values are two lines away in a debugger.
            std::cout << "refusing to redeem: the challenge nominates an authorization server\n";
            std::cout << "that is not the issuer this client already trusts.\n";
            std::cout << "this is the auto-exchange §20.3 forbids, and why it forbids it.\n";
            return 0;
        }
        std::cout << "as_uri matches the issuer we already trust; redeeming.\n";

        // ---- 4. Exchange ----
        //
        // One request. A ticket is spent whether or not this succeeds (§20.2
        // rule 6), so on failure the next step is a *new* ticket — which means
        // going back to step 1, not resending this one.
        axiam::UmaExchangeTicketParams params;
        params.ticket = *challenge->ticket;
        params.claim_token = axiam::Sensitive<std::string>(
            env_or("AXIAM_USER_TOKEN", "the-requesting-partys-access-token"));
        params.credentials = axiam::UmaClientCredentials{
            env_or("AXIAM_OIDC_CLIENT_ID", "invoices-client"),
            axiam::Sensitive<std::string>(env_or("AXIAM_OIDC_CLIENT_SECRET", "client-secret"))};

        auto rpt = client.uma_exchange_ticket(params);
        std::cout << "got an RPT, valid for " << rpt.expires_in << "s\n";
        // Step 4 in a real program: send rpt.access_token as the bearer on the
        // retried request. It is not printed here, for the reason above.
    } catch (const axiam::OAuthProtocolError& error) {
        // The machine-readable code is safe to print: it is one of a fixed set
        // of protocol constants, not anything a remote server composed.
        std::cout << "exchange failed (" << error.error_code() << "); the ticket is spent\n";
        std::cout << "either way — request a new one by retrying the call from step 1.\n";
    } catch (const axiam::AxiamError&) {
        std::cout << "exchange failed; the ticket is spent either way —\n";
        std::cout << "request a new one by retrying the call from step 1.\n";
    }
    return 0;
}
