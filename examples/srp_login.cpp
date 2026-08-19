/// \file
/// The SRP-6a login path (CONTRACT.md §23), using only the public API.
///
/// SRP proves the password to the server without the password — or anything
/// from which it can be cheaply recovered — ever crossing the wire. What the
/// server receives is `A` and a proof, neither of which is useful without the
/// account's verifier, so a TLS-terminating proxy, an accidentally verbose
/// request log or a heap dump cannot capture a plaintext password.
///
/// It does **not** protect against a compromised AXIAM server.
///
/// Three things this example is built to show:
///
///   1. `login_srp()` returns the SAME `LoginResult` as `login()`, MFA branch
///      included, so the result handling below is identical to
///      `examples/login_mfa.cpp`.
///   2. A tenant with `srp_mode: disabled` answers the challenge endpoint with
///      404, which reaches the caller as `NetworkError` and NOT as a credential
///      failure — so falling back to `login()` is correct and safe.
///   3. A tenant with `srp_mode: required` answers `/auth/login` with
///      `403 srp_required`, which is an `AuthzError`. A user whose password is
///      perfectly good must never be told it is invalid.
///
/// §23.8 makes SRP conditional here in one respect: Argon2id arrives as an
/// OpenSSL `EVP_KDF` in 3.2, so a build linked against an older libcrypto
/// cannot serve a tenant configured for it. `srp::argon2_available()` answers
/// that up front, and the login path refuses rather than substituting PBKDF2 —
/// which would derive a different `x` and report a good password as wrong.
///
/// Illustrative: connection details come from the environment and it builds
/// without a live AXIAM server.
#include <cstdlib>
#include <iostream>
#include <string>

#include "axiam/axiam.hpp"

namespace {

std::string getenv_or(const char* key, const char* fallback) {
    const char* v = std::getenv(key);
    return (v && *v) ? std::string(v) : std::string(fallback);
}

}  // namespace

int main() {
    const std::string base_url = getenv_or("AXIAM_BASE_URL", "https://localhost:8443");
    const std::string tenant_slug = getenv_or("AXIAM_TENANT_SLUG", "acme");
    const std::string org_slug = getenv_or("AXIAM_ORG_SLUG", "acme");
    const std::string username = getenv_or("AXIAM_USERNAME", "alice");
    const std::string password = getenv_or("AXIAM_PASSWORD", "changeme");
    const std::string totp_code = getenv_or("AXIAM_TOTP_CODE", "000000");

    auto client = axiam::Client::builder()
                      .base_url(base_url)
                      .tenant_slug(tenant_slug)
                      .org_slug(org_slug)
                      .build();

    // §23.1 puts this probe in every SDK's vocabulary. Here it is
    // unconditional; the Argon2 probe below is the one that can say no.
    if (!client.srp_available()) {
        std::cerr << "this build cannot perform SRP\n";
        return 1;
    }
    if (!axiam::srp::argon2_available()) {
        std::cout << "note: this OpenSSL has no argon2id (it arrives in 3.2); a tenant\n"
                     "      configured for argon2id will be refused with a clear message\n"
                     "      rather than served a wrong derivation.\n";
    }

    try {
        axiam::LoginResult result = [&] {
            try {
                return client.login_srp(username, password);
            } catch (const axiam::NetworkError& e) {
                // A tenant that has not enabled SRP, or a KDF this build cannot
                // do, is not a failed login. Fall back rather than reporting a
                // credential problem the user does not have.
                std::cout << "SRP unavailable here (" << e.what()
                          << ") — falling back to password login\n";
                return client.login(username, password);
            }
        }();

        if (result.mfa_required) {
            // Identical to the non-SRP path — that is the point of §23.1's
            // same-result-type requirement.
            result = client.verify_mfa(result.challenge_token, totp_code);
        }

        std::cout << "authenticated: session=" << result.session_id
                  << " expires_in=" << result.expires_in << "s\n";

        // Enrolment, for any request that SETS a password. The server cannot
        // compute a verifier — it never sees the plaintext — so it has to
        // arrive with the request or not at all. Read the tenant's parameters
        // from GET /api/v1/auth/me (or the reset context) rather than
        // hard-coding them: the server dictates the costs per exchange, and a
        // verifier enrolled under different costs stays valid.
        const char* new_password = std::getenv("AXIAM_NEW_PASSWORD");
        if (new_password && *new_password) {
            axiam::SrpEnrollment enrolment = client.srp_enrollment(
                // The account's USERNAME, which is the canonical identity the
                // challenge endpoint hands back. An email here produces a
                // verifier no login can ever satisfy.
                username, new_password, std::nullopt,
                axiam::SrpKdfParams{axiam::SrpKdfParams::kPbkdf2Sha256, 0, 0, 0});
            // Send this as the `srp` member of the change-password body. Never
            // log the salt or verifier: they are §23.3 rule 12 material, which
            // is why only the parameters are printed here.
            std::cout << "enrolment ready: group=" << enrolment.group
                      << " kdf=" << enrolment.kdf << " iterations=" << enrolment.iterations
                      << "\n";
        }
    } catch (const axiam::AuthzError& e) {
        // srp_mode: required, reached through login(). The credentials were
        // never examined.
        std::cerr << "this tenant refuses password login: " << e.what() << "\n";
        return 1;
    } catch (const axiam::AxiamError& e) {
        // Illustrative: without a reachable server this is the expected path.
        std::cerr << "login failed: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
