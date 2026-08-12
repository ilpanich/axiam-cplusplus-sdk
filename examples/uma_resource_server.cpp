// uma_resource_server.cpp — UMA 2.0 (CONTRACT.md §20), the RESOURCE-SERVER half
// of the example pair.
//
// The situation: this service holds invoices that belong to *users*, not to
// itself. When someone asks for one, the useful answer is not just "no" — it is
// "not with what you're carrying, and here is where to go and get better". That
// actionable refusal is what UMA adds over plain RBAC.
//
// What this shows, in order:
//
//   1. The PAT — a client-credentials token carrying `uma_protection`. §20.2
//      rule 1 requires a *client* token: a minted ticket is bound to the
//      client_id that minted it, so a user token cannot stand in. This SDK mints
//      no tokens of its own, so the PAT arrives from the environment.
//   2. Register the resource this service guards. The returned id IS the AXIAM
//      resource id — there is no parallel resource store to keep in sync.
//   3. Guard a request with the require_access overload that takes a
//      UmaChallenger, so a denial arrives as an AuthzChallengeError carrying a
//      fresh ticket.
//
// Its counterpart is examples/uma_client.cpp, which consumes that header.
//
// Illustrative and self-contained: it reads connection details from environment
// variables and compiles without a live AXIAM server.
//
// Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
// Run:    ./build/examples/axiam_example_uma_resource_server

#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <axiam/axiam.hpp>

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v && *v) ? std::string(v) : fallback;
}

}  // namespace

int main() {
    auto client = axiam::Client::builder()
                      .base_url(env_or("AXIAM_BASE_URL", "https://localhost:8443"))
                      .tenant_slug(env_or("AXIAM_TENANT_SLUG", "acme"))
                      .build();

    // ---- 1. The PAT ----
    //
    // §20.2 rule 1: a client-credentials token carrying `uma_protection`. Not a
    // user token, and not this client's ambient session — the SDK will not
    // substitute either, and the Protection API would refuse them anyway.
    axiam::Sensitive<std::string> pat(env_or("AXIAM_PAT", "a-protection-api-token"));

    try {
        // ---- 2. Registration ----
        //
        // Registering the same name twice creates two resources, so a real
        // service registers once at provisioning time and stores the id, or
        // reconciles by listing. Inline here because it is the step that shows
        // the returned id is the AXIAM resource id.
        //
        // The declared scopes are the allow-list the permission endpoint
        // validates a ticket request against: a resource registered with none
        // can never appear in a ticket.
        auto registered = client.uma_register_resource(
            pat, "invoice-7", "invoice", {"invoices:read", "invoices:approve"});

        const std::string invoice_id = registered.id.value_or("");
        std::cout << "registered invoice-7 as " << invoice_id << "\n";

        // ---- 3. The challenger ----
        //
        // as_uri names where the caller should redeem the ticket. Read it from
        // the discovery document rather than assembling it by hand — a
        // deployment is free to move its endpoints, which is why UMA ships a
        // discovery document at all.
        auto configuration = client.uma_discover();
        axiam::UmaChallenger challenger{"invoices", configuration.issuer, pat};

        // What a guarded handler does. The identity comes from the §10
        // authenticator (see authenticator.hpp); it is inlined here so the
        // example stays about §20.
        std::optional<axiam::AxiamUser> caller =
            axiam::AxiamUser{env_or("AXIAM_USER_ID", "end-user-42"),
                             env_or("AXIAM_TENANT_SLUG", "acme"), {}};

        // The load-bearing argument is the challenger. Without it this is the
        // ordinary §11 guard and a denial is a bare AuthzError; with it, the
        // error carries a ticket and the adapter can hand the caller something
        // to act on.
        axiam::require_access(client, caller, "invoices:read", invoice_id, challenger);

        // Reached only when the engine allowed it — including honouring any deny
        // rule, which UMA does not bypass: the ticket minted on a refusal asks
        // for the same action this check just evaluated, so the same grants and
        // denies apply to whatever RPT comes back.
        std::cout << "allowed: the caller may read invoice-7\n";
    } catch (const axiam::AuthzChallengeError& denial) {
        std::cout << "refused with 403\n";
        // The header itself is NOT printed: it carries a live ticket (§20.6),
        // and a credential in a log line is a credential in a log line,
        // 60-second life or not. A real adapter sends it, and nothing else.
        std::cout << "challenge present: " << (denial.challenge().empty() ? "no" : "yes") << "\n";
    } catch (const axiam::AuthzError&) {
        // A denial the Protection API could not be asked about — the challenge
        // is sugar, and losing it changes nothing about the refusal.
        std::cout << "refused with 403 (no challenge available)\n";
    } catch (const axiam::AxiamError& error) {
        std::cout << "failed: " << error.what() << "\n";
        return 1;
    }
    return 0;
}
