// opaque_login.cpp — the OPAQUE login path, RFC 9807 (CONTRACT.md §23).
//
// OPAQUE proves the password to the server without the password — or anything
// from which it can be cheaply recovered — ever crossing the wire. What the
// server receives is a blinded group element and a MAC, neither of which is
// useful without the account's registration record AND the tenant's OPRF seed.
// So a TLS-terminating proxy, an accidentally verbose request log or a heap
// dump cannot capture a plaintext password: the server never has one.
//
// It also does something the SRP-6a this replaces could not: a stolen record
// database is not offline-crackable on its own. That is pre-computation
// resistance, and it is the substantive reason for the migration.
//
// It does NOT protect against a compromised AXIAM server. Nothing client-side
// can.
//
// Four things this example is built to show:
//
//   1. Client::login_opaque returns the SAME LoginResult as Client::login, MFA
//      branch included, so the result handling below is identical to
//      examples/login_mfa.cpp.
//   2. A tenant with opaque_mode: disabled answers the two start endpoints with
//      404, which reaches the caller as NetworkError and NOT as a credential
//      failure — so falling back to login() is correct and safe.
//   3. AuthError means the envelope did not open. That is the whole credential
//      check, and it is NOT a case to retry over login(): retrying would hand
//      the plaintext to an endpoint that has just failed to prove it holds the
//      record. RFC 9807's AKE authenticates the server during the handshake, so
//      there is no separate M2 step of the kind SRP needed.
//   4. A tenant with opaque_mode: required answers /auth/login with
//      403 opaque_required, which is AuthzError. A user whose password is
//      perfectly good must never be told it is invalid.
//
// WHAT CHANGED FOR THIS SDK. SRP was CONDITIONAL here: Argon2id arrives as an
// OpenSSL EVP_KDF only in 3.2, so a build linked against an older libcrypto
// could not serve a tenant on AXIAM's default KDF, and the login path had to
// refuse rather than substitute PBKDF2. Key stretching now happens inside
// libaxiam_opaque_ffi, so the OpenSSL version no longer decides which tenants
// work. The one remaining condition is having that library, which
// Client::opaque_available reports honestly — and unlike the old
// srp_available(), a true from it IS a promise that every tenant works.
//
// The library is a per-platform GitHub release asset of ilpanich/axiam-opaque,
// resolved with dlopen at run time so a consumer who never uses OPAQUE is not
// made to link it. Point AXIAM_OPAQUE_LIBRARY at it, or install it where the
// dynamic loader already looks.
//
// This example is illustrative — connection details come from environment
// variables and it compiles/links without a live AXIAM server.
//
// Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
// Run:    ./build/examples/axiam_example_opaque_login

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

    // §23.2 puts this probe in every SDK's vocabulary, and here it genuinely can
    // say no. Ask it BEFORE collecting a password: there is no point prompting
    // for one this installation cannot use.
    if (!client.opaque_available()) {
        std::cerr << "this installation cannot perform OPAQUE: libaxiam_opaque_ffi was\n"
                     "not found. Install the release asset for this platform from\n"
                     "ilpanich/axiam-opaque and set "
                  << axiam::opaque::kLibraryPathEnv << " to its path.\n";
        return 1;
    }

    try {
        axiam::LoginResult result = [&] {
            try {
                return client.login_opaque(username, password);
            } catch (const axiam::NetworkError& e) {
                // The ONLY case that may fall back. A tenant that has not
                // enabled OPAQUE, a missing library, a key-stretching function
                // this SDK cannot ask for, and a malformed response are all
                // configuration facts, not credential facts — reporting them as
                // a bad password would send a user off to reset one that works.
                //
                // AuthError is deliberately NOT caught here. See point 3 in the
                // header: it is caught below, and never retried over login().
                std::cout << "OPAQUE unavailable here (" << e.what()
                          << ") — falling back to password login\n";
                return client.login(username, password);
            }
        }();

        if (result.mfa_required) {
            // Identical to the non-OPAQUE path — that is the point of §23.1's
            // same-result-type requirement.
            result = client.verify_mfa(result.challenge_token, totp_code);
        }

        std::cout << "authenticated: session=" << result.session_id
                  << " expires_in=" << result.expires_in << "s\n";

        // Enrolment, for any request that SETS a password. The server cannot
        // build a registration record — it never sees the plaintext — so it has
        // to arrive with the request or not at all.
        //
        // Unlike the SRP enrolment this replaces, it performs I/O: one
        // register/start round trip, because OPAQUE's envelope is sealed under
        // the server's oblivious PRF and there is no offline computation that
        // produces a valid record.
        //
        // Note the arguments that are GONE. There is no identity: SRP needed the
        // account's canonical username, and an email there produced a verifier
        // no login could ever satisfy — a record binds to a credential
        // identifier the server chooses, so renaming a user no longer
        // invalidates their credential. There is no group and no kdf either: the
        // server names the key-stretching function per exchange, so a caller
        // cannot pick a cost it will not honour.
        const char* new_password = std::getenv("AXIAM_NEW_PASSWORD");
        if (new_password && *new_password) {
            axiam::OpaqueEnrollment enrolment = client.opaque_enrollment(new_password);
            // Send this as the `opaque` member of the change-password body.
            // Never log registration_record: it is the credential material,
            // which is why only the session handle's presence is printed here.
            std::cout << "enrolment ready: opaque_session="
                      << (enrolment.opaque_session.empty() ? "<missing>" : "<issued>") << "\n";
        }
    } catch (const axiam::AuthError& e) {
        // The envelope did not open: a wrong password, an account that does not
        // exist, or a server that does not hold the record — indistinguishable
        // by design. Nothing was sent to login/finish (§23.4 rule 7).
        std::cerr << "invalid credentials: " << e.what() << "\n";
        return 1;
    } catch (const axiam::AuthzError& e) {
        // opaque_mode: required, reached through login(). The credentials were
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
