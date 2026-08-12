// device_login — the RFC 8628 device grant (CONTRACT.md §14).
//
// The flow for a thing that cannot show a browser: a TV, a headless
// commissioning tool, a CLI on a machine with no display. The device shows a
// short code, the user types it somewhere else, and the device polls until they
// have.
//
// WHAT THE SDK WILL NOT DO FOR YOU, and why each one is deliberate:
//
//   * It does not print the user code. §14.3 rule 2 forbids it, because only the
//     application knows how this device can display anything — a screen, a QR
//     code, an e-ink panel, a line of serial output. The callback below is where
//     that decision lives, and polling does not start until it returns.
//   * It does not send a client_secret on device_authorize() (§14.1). A device
//     that cannot show a browser also cannot hold a secret, and the SDK equally
//     will not refuse to run from a client that has none.
//   * It does not adopt the resulting token as this client's credential
//     (§14.3 rule 4). The tokens are returned; installing them is the
//     application's call.
//
// And what it DOES do, in the polling loop you never see: honour the server's
// interval, add five seconds permanently on every `slow_down`, keep
// `access_denied` and `expired_token` distinguishable, and stop at `expires_in`
// even if the server never says so.

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
    try {
        // A public client: no secret configured, and §14.1 requires the grant to
        // work exactly like this.
        auto client =
            axiam::Client::builder()
                .base_url(env_or("AXIAM_BASE_URL", "https://localhost:8443"))
                .tenant_id(env_or("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111"))
                .oidc_client_id(env_or("AXIAM_OIDC_CLIENT_ID", "example-device"))
                .build();

        const std::string scope = env_or("AXIAM_SCOPE", "");

        const auto tokens = client.device_login(
            // §14.3 rule 2's callback. Called ONCE, before the first poll.
            //
            // A real device renders this however it can. The user code is not
            // wrapped in Sensitive (§14.5) precisely because it exists to be
            // read aloud and typed — but "not a secret" is not "log it":
            // displaying is this callback's job and nothing else's.
            [](const axiam::DeviceAuthorization& a) {
                std::cout << "\n  ┌────────────────────────────────────────────┐\n"
                          << "  │  Visit: " << a.verification_uri << "\n"
                          << "  │  Code:  " << a.user_code << "\n"
                          << "  └────────────────────────────────────────────┘\n";
                if (a.verification_uri_complete) {
                    // Surfaced when the server sends it, and never synthesised
                    // by concatenation when it does not (§14.3) — its format is
                    // the server's to choose. This is what a QR code should
                    // encode.
                    std::cout << "  (QR target: " << *a.verification_uri_complete << ")\n";
                }
                std::cout << "\nWaiting for approval — polling every " << a.interval
                          << "s, giving up after " << a.expires_in << "s.\n";
            },
            scope.empty() ? std::nullopt : std::optional<std::string>(scope));

        std::cout << "\nApproved.\n"
                  << "  token_type   " << tokens.token_type << " (expires in "
                  << tokens.expires_in << "s)\n"
                  // §7: the token streams redacted, always. Reach it with
                  // axiam::detail::reveal() at the point of use — building one
                  // outbound Authorization header — and let the result die there.
                  << "  access_token " << tokens.access_token << "\n";
        if (tokens.refresh_token) {
            // §14.3 rule 4: a refresh token from this grant is refreshed through
            // oidc_refresh(), which is §9 single-flighted like any other.
            std::cout << "  refresh_token " << *tokens.refresh_token << "\n";
        }
        // The client itself is NOT authenticated by this call — the tokens are
        // yours to install wherever your application keeps credentials.
        return 0;
    } catch (const axiam::OAuthProtocolError& e) {
        // §14.2 rule 3: the two refusals are DISTINCT, and this is the only
        // place the difference matters. "A human said no" means stop asking.
        // "Nobody answered" means the codes went stale and a fresh grant might
        // work. An SDK that collapsed them would leave this switch unwritable.
        if (e.error_code() == "access_denied") {
            std::cerr << "\nThe user declined. Not retrying.\n";
        } else if (e.error_code() == "expired_token") {
            std::cerr << "\nNobody approved in time. Start a new grant to try again.\n";
        } else {
            std::cerr << "\nRefused: " << e.error_code() << "\n";
        }
        return 1;
    } catch (const axiam::AxiamError& e) {
        std::cerr << "\ndevice login failed: " << e.what() << "\n";
        return 1;
    }
}
