// webauthn_passkeys.cpp — enrolling and using a passkey from C++ (CONTRACT.md §24).
//
// THE THING THIS EXAMPLE IS REALLY ABOUT. A C++ program has no authenticator.
// There is no platform API to link on the targets this SDK serves, and §24.6b
// rule 2 forbids emulating one in software — a "credential" held in process
// memory is not a second factor. So this SDK ships the six wire operations and
// §24.6a's JSON bridge, and nothing else.
//
// That is a statement about convenience, not capability. The bridge is the whole
// interface: WebauthnChallenge::request_json() hands out the challenge in the
// exact JSON form every platform authenticator API takes, and every *_finish
// takes the platform's response JSON back as a string, byte for byte. An
// embedded gateway fronting a browser, a native app talking to a C++ service, or
// a test harness driving a virtual authenticator all use the same two seams —
// and the bytes the authenticator signed reach the server unchanged, which is
// the only reason any of it verifies.
//
// Where the ceremony actually happens is marked below. In a real program those
// two blocks are an IPC round trip, a WebSocket message, or a local HTTP
// endpoint your front end calls.
//
// Build:  cmake -S . -B build && cmake --build build
// Run:    ./build/examples/axiam_example_webauthn_passkeys
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>

#include "axiam/axiam.hpp"

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v && *v) ? std::string(v) : fallback;
}

/// Stand-in for the platform. In a real program this is where the challenge
/// crosses into something that owns an authenticator, and what comes back is
/// that platform's response JSON — returned here verbatim, exactly as it must be
/// forwarded.
///
/// The SDK will not touch these bytes: it splices the string into the request
/// body without parsing it into a model and printing it back out, because a
/// signed buffer that makes a round trip through a JSON model is a signed buffer
/// that can come out different. Member order, unmodelled fields and large
/// integers all survive, and the server's signature check is the reason that
/// matters.
std::optional<std::string> run_ceremony_on_the_platform(const std::string& request_json) {
    std::cout << "  → hand this to the authenticator, unchanged:\n    " << request_json << "\n";
    std::cout << "  ← the platform answers with its response JSON; forward it verbatim\n";
    return std::nullopt;  // no authenticator here — see the header comment
}

void enrol_a_passkey(axiam::Client& client) {
    // register/start requires a session and refuses CLIENT-SIDE with no wire
    // call when there is none: a passkey is enrolled BY a signed-in user, for
    // themselves. A 503 here is a configuration state, not a transient one — the
    // tenant's attestation policy needs FIDO metadata the server cannot reach —
    // and §24.4 rule 2 deliberately does not retry it.
    const auto challenge = client.webauthn_register_start();

    // §24.6a rule 1: the INNER options object. The `publicKey` wrapper the
    // server sends belongs to the DOM's CredentialCreationOptions, and the
    // platform JSON APIs — parseCreationOptionsFromJSON() in a browser,
    // CreatePublicKeyCredentialRequest on Android — do not want it.
    const auto response = run_ceremony_on_the_platform(challenge.request_json());
    if (!response) {
        std::cout << "  (no authenticator in this process — stopping here)\n";
        return;
    }

    try {
        const auto credential =
            client.webauthn_register_finish(challenge.state_token, "Ada's laptop", *response);
        std::cout << "  enrolled " << credential.name << " (" << credential.credential_type
                  << "), created " << credential.created_at << "\n";
    } catch (const axiam::AuthzError& e) {
        // The one error whose BODY matters (§24.4 rule 1). A 403 here means the
        // tenant's attestation policy rejected THIS authenticator, and the
        // server's message is the only place that says which one would be
        // accepted — a generic "authorization denied" tells the person holding
        // the key nothing they can act on.
        std::cerr << "  attestation policy refused this authenticator: " << e.what() << "\n";
    }
}

void sign_in_with_a_discoverable_credential(axiam::Client& client) {
    // A PRIMARY factor, and a different flow from the second-factor ceremony
    // rather than the same one with a flag (§24.2). Nothing precedes it, so
    // there is no challenge token to carry the workspace — which is why this is
    // the one WebAuthn endpoint that names the workspace explicitly. Passing
    // none fills it from the client's own configuration.
    const auto challenge = client.webauthn_discoverable_start();

    const auto response = run_ceremony_on_the_platform(challenge.request_json());
    if (!response) {
        std::cout << "  (no authenticator in this process — stopping here)\n";
        return;
    }

    // §24.3: on success the client is signed in. The server set the same cookie
    // triple POST /api/v1/auth/login sets, the §17 decision memo was cleared
    // because the subject changed, and a caller who only wanted a session can
    // drop this result immediately.
    const auto login = client.webauthn_discoverable_finish(challenge.state_token, *response);
    std::cout << "  signed in, session " << login.session_id << " (" << login.expires_in
              << " s)\n";
}

/// §24.6b rule 5, and required of every SDK claiming §24 even where no ceremony
/// helper exists. Whatever DID run the ceremony reports its failure as one
/// opaque type whose only machine-readable part is a name; translating that once
/// beats translating it in every caller.
///
/// Note what WebauthnFailure::kCancelled covers: both an explicit refusal AND a
/// silent timeout. The spec deliberately refuses to distinguish them, because
/// telling a website which one happened leaks whether an authenticator was
/// present — so copy that says "you cancelled" is wrong half the time it shows.
void explain_a_ceremony_failure(const std::string& platform_error_name) {
    const auto failure = axiam::webauthn_classify(platform_error_name);
    std::cout << "  " << platform_error_name << " → "
              << axiam::webauthn_failure_message(failure) << "\n";
}

}  // namespace

int main() {
    const std::string base_url = env_or("AXIAM_BASE_URL", "https://localhost:8443");
    const std::string tenant_slug = env_or("AXIAM_TENANT_SLUG", "acme");
    const std::string org_slug = env_or("AXIAM_ORG_SLUG", "acme");
    const std::string email = env_or("AXIAM_EMAIL", "user@example.com");
    const std::string password = env_or("AXIAM_PASSWORD", "changeme");

    try {
        auto client = axiam::Client::builder()
                          .base_url(base_url)
                          .tenant_slug(tenant_slug)  // §5
                          .org_slug(org_slug)        // §5.1
                          .build();

        std::cout << "failure classification (§24.6b rule 5):\n";
        explain_a_ceremony_failure("NotAllowedError");
        explain_a_ceremony_failure("InvalidStateError");
        explain_a_ceremony_failure("NotSupportedError");
        explain_a_ceremony_failure("SomeFutureError");

        std::cout << "\nusernameless sign-in (§24.2):\n";
        sign_in_with_a_discoverable_credential(client);

        const auto login = client.login(email, password);
        if (login.user) {
            std::cout << "\nenrolling a passkey for the signed-in user (§24.1):\n";
            enrol_a_passkey(client);
        } else {
            std::cout << "\n(sign in to enrol a passkey — register/* requires a session)\n";
        }
    } catch (const axiam::AxiamError& e) {
        std::cerr << "axiam: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
