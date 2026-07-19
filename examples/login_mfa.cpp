// login_mfa.cpp — the two-phase login + MFA flow (CONTRACT.md §1, §5, §5.1).
//
// Demonstrates:
//   - Building an axiam::Client with a non-optional tenant context AND the
//     organization context that §5.1 requires: login is rejected with HTTP 400
//     ("must provide org_id or org_slug") unless the client also supplies an
//     org identifier, because a tenant slug is only unique within an org.
//   - Calling login(), branching on LoginResult::mfa_required, and completing
//     the challenge with verify_mfa() when the server asks for a TOTP code.
//
// This example is illustrative and self-contained: it reads connection details
// from environment variables and compiles without a live AXIAM server. Running
// it end-to-end needs a reachable server matching AXIAM_BASE_URL.
//
// Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
// Run:    ./build/examples/axiam_example_login_mfa

#include <cstdlib>
#include <iostream>
#include <string>

#include <axiam/axiam.hpp>

namespace {

// getenv with a fallback default (std::getenv returns nullptr when unset).
std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v && *v) ? std::string(v) : fallback;
}

}  // namespace

int main() {
    const std::string base_url    = env_or("AXIAM_BASE_URL", "https://localhost:8443");
    const std::string tenant_slug = env_or("AXIAM_TENANT_SLUG", "acme");
    const std::string org_slug    = env_or("AXIAM_ORG_SLUG", "acme");
    const std::string email       = env_or("AXIAM_EMAIL", "user@example.com");
    const std::string password    = env_or("AXIAM_PASSWORD", "changeme");
    const std::string totp_code   = env_or("AXIAM_TOTP_CODE", "000000");

    try {
        // §5: tenant context is mandatory (no default tenant).
        // §5.1: org context is mandatory for login — supply org_slug alongside
        //       tenant_slug so the login body carries an org identifier.
        axiam::Client client = axiam::Client::builder()
            .base_url(base_url)
            .tenant_slug(tenant_slug)
            .org_slug(org_slug)
            .build();

        // POST /api/v1/auth/login
        axiam::LoginResult login = client.login(email, password);

        if (login.mfa_required) {
            std::cout << "MFA required — available methods:";
            for (const auto& m : login.available_methods) std::cout << " " << m;
            std::cout << "\n";

            // POST /api/v1/auth/mfa/verify — replay the challenge token from the
            // login response together with the user-supplied TOTP code.
            login = client.verify_mfa(login.challenge_token, totp_code);
            std::cout << "MFA verified — session_id=" << login.session_id
                      << " expires_in=" << login.expires_in << "s\n";
        } else {
            std::cout << "Login complete (no MFA) — session_id=" << login.session_id
                      << " expires_in=" << login.expires_in << "s\n";
        }

        if (login.user) {
            std::cout << "Authenticated user: " << login.user->email
                      << " (tenant_id=" << login.user->tenant_id << ")\n";
        }

        client.logout();
        return 0;
    } catch (const axiam::AuthError& e) {
        std::cerr << "authentication failed: " << e.what() << "\n";
    } catch (const axiam::NetworkError& e) {
        std::cerr << "transport error: " << e.what() << " (cause: " << e.cause() << ")\n";
    } catch (const axiam::AxiamError& e) {
        std::cerr << "axiam error: " << e.what() << "\n";
    }
    return 1;
}
