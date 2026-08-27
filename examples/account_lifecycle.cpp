// account_lifecycle.cpp — the calls a user makes about their own account
// (CONTRACT.md §25): TOTP enrolment, email verification, password reset.
//
// NONE OF THIS IS ADMINISTRATION, and six of the ten operations are
// deliberately UNAUTHENTICATED. A user who cannot log in is the entire audience
// for a password reset, and a user whose email is unverified may have no session
// at all — an SDK that required one would make both unreachable.
//
// Two shapes in here are easy to get wrong and expensive to get wrong:
//
//  1. verify_email, resend_verification and confirm_password_reset take the
//     tenant as a BODY field. These are not /oauth2 endpoints, so §12.1 rule 2's
//     query-parameter convention does not reach them, and sending it in the
//     query gets a 400 that reads exactly like a bad token.
//  2. The otpauth:// URI CONTAINS the secret. Wrapping `secret_base32` and
//     leaving the URI a plain string wraps nothing — the URI is the field that
//     actually gets logged, because it is the one you pass to a QR renderer.
//
// Build:  cmake -S . -B build && cmake --build build
// Run:    ./build/examples/axiam_example_account_lifecycle
#include <cstdlib>
#include <iostream>
#include <string>

#include "axiam/axiam.hpp"

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v && *v) ? std::string(v) : fallback;
}

/// Stand-in for the human step. There is no way around it, which is exactly why
/// §25.2 rule 4 forbids an SDK helper that composes enrol and confirm: a helper
/// cannot wait for someone to read a QR code and type six digits.
std::string read_the_code_the_user_typed() { return env_or("AXIAM_TOTP_CODE", "000000"); }

void enrol_a_totp_factor(axiam::Client& client) {
    const auto enrollment = client.mfa_enroll();

    // Both halves are Sensitive (§25.3). axiam::detail::reveal is the module
    // accessor §7 rule 3 permits — call it at the point of use, hand the string
    // straight to the QR renderer, and let the value die there. It must never
    // reach a log, a trace or an error message.
    //
    // Note also what this call did NOT do: it did not clear the §17 decision
    // memo (§25.2 rule 3). The subject has not changed — offering a factor is a
    // profile action — and discarding a warm memo over it costs a round trip on
    // every authorization check that follows.
    std::cout << "  scan this: " << axiam::detail::reveal(enrollment.totp_uri) << "\n";
    std::cout << "  (in a log it would read: " << enrollment.totp_uri << ")\n";

    // The factor is NOT active yet. Two calls, with a human in between.
    const bool enabled = client.mfa_confirm(read_the_code_the_user_typed());
    std::cout << "  MFA is now " << (enabled ? "on" : "off") << "\n";
}

/// The forced path (§25.2 rule 2). Reached when login answers
/// `mfa_setup_required`: the tenant requires MFA and this account has none.
///
/// There is no session yet — the setup token IS the credential — and
/// mfa_setup_confirm adopts credentials exactly as login does, because it IS the
/// completion of the login that was interrupted. Before §25 an SDK either
/// reported this as a generic failure or as a successful login with no session;
/// both leave the caller with nothing to do next.
void complete_forced_enrolment(axiam::Client& client,
                               const axiam::Sensitive<std::string>& setup_token) {
    const auto enrollment = client.mfa_setup_enroll(setup_token);
    std::cout << "  scan this: " << axiam::detail::reveal(enrollment.totp_uri) << "\n";

    const auto result = client.mfa_setup_confirm(setup_token, read_the_code_the_user_typed());
    std::cout << "  enrolled and signed in, session " << result.session_id << "\n";
}

void reset_a_password(axiam::Client& client, const std::string& email,
                      const std::string& tenant_id) {
    // §25.4: this returns normally whether or not the address exists, and this
    // SDK exposes no way to tell the two apart — not a boolean, not a distinct
    // error. A client that surfaced "no such user", even inferred from timing,
    // would turn the endpoint into the account-enumeration oracle its uniform
    // response exists to prevent. Say "if that address is registered, check your
    // mail" and mean it.
    axiam::PasswordResetRequest request;
    request.email = email;
    client.request_password_reset(request);
    std::cout << "  if " << email << " is registered, a reset mail is on its way\n";

    const std::string token_from_the_mail = env_or("AXIAM_RESET_TOKEN", "");
    if (token_from_the_mail.empty()) {
        std::cout << "  (set AXIAM_RESET_TOKEN to continue past this point)\n";
        return;
    }
    const axiam::Sensitive<std::string> token{token_from_the_mail};

    // Ask what the account's tenant expects BEFORE choosing a password path. A
    // tenant in `opaque_mode: required` refuses a plaintext password, and
    // refuses it late (§25.4 rule 1) — by which point the user has typed one.
    //
    // A 404 here means unknown, expired OR already-consumed, deliberately
    // without distinguishing them; do not invent a distinction the server
    // refused to make.
    axiam::PasswordResetContext context;
    try {
        context = client.password_reset_context(token);
    } catch (const axiam::AxiamError& e) {
        std::cerr << "  that reset link is not usable: " << e.what() << "\n";
        return;
    }

    if (context.opaque_json) {
        // Hand this block to the §23 helpers untouched — this SDK does not
        // model, validate or re-encode it, and anything it did to it would be a
        // guess about a protocol it deliberately does not implement.
        std::cout << "  this tenant uses OPAQUE: " << *context.opaque_json << "\n";
        std::cout << "  build a record with opaque_enrollment() and pass it as opaque_json\n";
        return;
    }

    axiam::PasswordResetConfirmation confirmation;
    confirmation.token = token;
    confirmation.new_password =
        axiam::Sensitive<std::string>(env_or("AXIAM_NEW_PASSWORD", "correct horse battery staple"));
    confirmation.tenant_id = tenant_id;
    client.confirm_password_reset(confirmation);
    std::cout << "  password changed\n";
}

}  // namespace

int main() {
    const std::string base_url = env_or("AXIAM_BASE_URL", "https://localhost:8443");
    const std::string tenant_slug = env_or("AXIAM_TENANT_SLUG", "acme");
    const std::string tenant_id =
        env_or("AXIAM_TENANT_ID", "00000000-0000-0000-0000-000000000000");
    const std::string org_slug = env_or("AXIAM_ORG_SLUG", "acme");
    const std::string email = env_or("AXIAM_EMAIL", "user@example.com");
    const std::string password = env_or("AXIAM_PASSWORD", "changeme");

    try {
        auto client = axiam::Client::builder()
                          .base_url(base_url)
                          .tenant_slug(tenant_slug)  // §5
                          .tenant_id(tenant_id)      // the BODY field, §25.1
                          .org_slug(org_slug)        // §5.1
                          .build();

        // Unauthenticated, and the tenant travels in the BODY.
        //
        // This one answers the SAME WAY whatever happened — the address may not exist,
        // may already be verified, or may be over the daily limit. That constancy is the
        // point: it takes an address from an anonymous caller, and anything else would be
        // an oracle for which addresses have accounts (§25.4).
        std::cout << "resending a verification mail (§25.1, unauthenticated):\n";
        client.resend_verification(email, tenant_id);
        std::cout << "  requested\n";

        std::cout << "\npassword reset (§25.4):\n";
        reset_a_password(client, email, tenant_id);

        std::cout << "\nlogin (§25.2 rule 1 — three outcomes, not two):\n";
        const auto login = client.login(email, password);
        if (login.mfa_setup_required) {
            std::cout << "  this tenant requires MFA and this account has none\n";
            complete_forced_enrolment(client, login.setup_token);
        } else if (login.mfa_required) {
            std::cout << "  MFA required — see examples/login_mfa.cpp\n";
        } else {
            std::cout << "  signed in\n";

            // §5.2: an ORGANIZATION-LEVEL principal's record lives in its organization's
            // reserved tenant, so it can act on a different tenant by sending a different
            // X-Tenant-ID on the next request — no re-login. An ordinary tenant principal
            // is a principal of exactly one tenant, and the same header change would 403,
            // so a UI checks this flag BEFORE offering a tenant selector rather than
            // finding out from a failure. Derived from the response, never sent.
            if (login.user && login.user->organization_level) {
                std::cout << "  organization-level: a tenant switch is available\n";
            }

            // §25.7: the OTHER resend. This caller is signed in to the account it is
            // asking about, so none of the outcomes tells it anything it did not bring
            // with it — and this one therefore says which happened. It names no address:
            // a parameter here would let an authenticated session mail an arbitrary one.
            //
            // It is not a replacement for the public resend above, and neither is routed
            // to the other. There is deliberately no fallback to the public endpoint on
            // 409 or 429: that would turn both failures back into a silent success and
            // restore the bug this operation exists to fix (§25.7 rule 2).
            std::cout << "\nresending your OWN verification mail (§25.7):\n";
            try {
                client.resend_own_verification();
                std::cout << "  enqueued — delivery is asynchronous and can still fail\n";
            } catch (const axiam::AuthzError&) {
                std::cout << "  nothing to send: already verified\n";
            } catch (const axiam::NetworkError&) {
                std::cout << "  the daily resend limit is reached\n";
            }

            std::cout << "\nvoluntary TOTP enrolment (§25.1):\n";
            enrol_a_totp_factor(client);
        }
    } catch (const axiam::AxiamError& e) {
        std::cerr << "axiam: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
