// axiam account lifecycle and MFA enrolment — CONTRACT.md §25.
//
// Nine operations, six of them deliberately unauthenticated. A user who cannot
// log in is the entire audience for a password reset, and a user whose email is
// unverified may have no session at all — an SDK that required one would make
// both unreachable.
#include "axiam/account.hpp"

#include <cstdio>
#include <mutex>
#include <string>

#include <nlohmann/json.hpp>

#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "client_impl.hpp"

namespace axiam {
namespace {

using json = nlohmann::json;

constexpr const char* kMfaEnroll = "/api/v1/auth/mfa/enroll";
constexpr const char* kMfaConfirm = "/api/v1/auth/mfa/confirm";
constexpr const char* kMfaSetupEnroll = "/api/v1/auth/mfa/setup/enroll";
constexpr const char* kMfaSetupConfirm = "/api/v1/auth/mfa/setup/confirm";
constexpr const char* kVerifyEmail = "/api/v1/auth/verify-email";
constexpr const char* kResendVerification = "/api/v1/auth/resend-verification";
constexpr const char* kResendOwnVerification = "/api/v1/users/me/resend-verification";
constexpr const char* kReset = "/api/v1/auth/reset";
constexpr const char* kResetContext = "/api/v1/auth/reset/context";
constexpr const char* kResetConfirm = "/api/v1/auth/reset/confirm";

/// RFC 3986 percent-encoding for a query-parameter value.
///
/// A token spliced into a query raw can end the query early or land in the path,
/// and the 404 that produces reads EXACTLY like an expired token — the worst
/// possible failure mode for someone trying to debug a reset link.
std::string pct(const std::string& in) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size() * 3);
    for (unsigned char c : in) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                                (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
                                c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 0x0F]);
        }
    }
    return out;
}

/// POST a JSON body, accepting the whole 2xx range.
///
/// Three of the nine answer `204 No Content`. An SDK that insists on a JSON body
/// reports every successful reset as a failure.
HttpResponse post(Client::Impl& impl, const char* path, const std::string& body) {
    const HttpResponse resp = impl.send_raw(impl.build_request("POST", path, body));
    if (resp.status < 200 || resp.status >= 300) Client::Impl::raise_for_status(resp);
    return resp;
}

/// Read an `MfaEnrollResponse`, wrapping BOTH halves (§25.3).
MfaEnrollment read_enrollment(const HttpResponse& resp) {
    const json j = json::parse(resp.body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        // A 200 whose body cannot be parsed is not an enrolment with missing
        // fields: there is no secret to show, and an empty wrapper would send
        // the user to scan a QR code for a factor that can never confirm.
        throw NetworkError("mfa enrolment: response body is not a JSON object",
                           "malformed_body");
    }
    MfaEnrollment enrollment;
    enrollment.secret_base32 = Sensitive<std::string>(j.value("secret_base32", std::string{}));
    // §25.3: the URI CONTAINS the secret, so it is wrapped too. Wrapping the
    // bare secret and leaving this one a plain string wraps nothing — the URI is
    // the field that actually gets logged, because it is the one the caller
    // passes to a QR renderer.
    enrollment.totp_uri = Sensitive<std::string>(j.value("totp_uri", std::string{}));
    return enrollment;
}

}  // namespace

// ---------------------------------------------------------------------------
// Voluntary enrolment
// ---------------------------------------------------------------------------

MfaEnrollment Client::mfa_enroll() {
    p_->ensure_open();
    // §25.2 rule 3: the memo is NOT cleared. The subject has not changed, and
    // discarding a warm memo on an unrelated profile action is a needless round
    // trip for every check that follows.
    return read_enrollment(post(*p_, kMfaEnroll, "{}"));
}

bool Client::mfa_confirm(const std::string& totp_code) {
    p_->ensure_open();
    json body = json::object();
    body["totp_code"] = totp_code;
    const HttpResponse resp = post(*p_, kMfaConfirm, body.dump());
    const json j = json::parse(resp.body, nullptr, false);
    // The SERVER's answer, not the status code: a 200 that says
    // `mfa_enabled: false` is a successful call reporting a factor that did not
    // turn on, and collapsing the two loses that.
    return !j.is_discarded() && j.value("mfa_enabled", false);
}

// ---------------------------------------------------------------------------
// Forced enrolment (§25.2 rule 2)
// ---------------------------------------------------------------------------

MfaEnrollment Client::mfa_setup_enroll(const Sensitive<std::string>& setup_token) {
    p_->ensure_open();
    // No session yet — the login that produced this token stopped short of one.
    // An SDK that required a session here would make the forced path
    // unreachable.
    json body = json::object();
    body["setup_token"] = detail::reveal(setup_token);
    return read_enrollment(post(*p_, kMfaSetupEnroll, body.dump()));
}

LoginResult Client::mfa_setup_confirm(const Sensitive<std::string>& setup_token,
                                      const std::string& totp_code) {
    p_->ensure_open();
    // §25.2 rule 2: this IS the completion of a login, so §24.3's adoption rules
    // apply verbatim — including clearing the §17 memo, on the caller's intent,
    // before the wire.
    if (p_->memo) p_->memo->clear();

    json body = json::object();
    body["setup_token"] = detail::reveal(setup_token);
    body["totp_code"] = totp_code;
    const HttpResponse resp = post(*p_, kMfaSetupConfirm, body.dump());

    const json j = json::parse(resp.body, nullptr, false);
    LoginResult result;
    if (!j.is_discarded() && j.is_object()) {
        result.session_id = j.value("session_id", std::string{});
        result.expires_in = j.value("expires_in", static_cast<std::int64_t>(0));
        // §5.2 / §5.2.2 / §5.2.3, through the SAME reader the login path uses:
        // mfa_setup_confirm IS the completion of a login (§25.2 rule 2), so the
        // principal it establishes carries the same flag and the same scope. A
        // second hand-rolled reader here was one more place for §5.2.2's "absent
        // means EQUAL" fallback to be forgotten.
        if (j.contains("user") && j["user"].is_object())
            result.user = detail::parse_user(j["user"]);
    }
    {
        std::lock_guard<std::mutex> lock(p_->state_mtx);
        p_->session = true;
        if (result.user) {
            p_->resolved_tenant_id = result.user->tenant_id;
            // §5.2.2 rule 2, as in the login path: mfa_setup_confirm completes a login.
            if (!result.user->principal_tenant_id.empty())
                p_->principal_tenant_id = result.user->principal_tenant_id;
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Email verification (§25.1)
// ---------------------------------------------------------------------------

void Client::verify_email(const Sensitive<std::string>& token, const std::string& tenant_id) {
    p_->ensure_open();
    json body = json::object();
    body["token"] = detail::reveal(token);
    // A BODY field: this is not an /oauth2 endpoint, so §12.1 rule 2's
    // query-parameter convention does not reach it, and putting it in the query
    // earns a 400 that reads like a bad token.
    body["tenant_id"] = tenant_id;
    post(*p_, kVerifyEmail, body.dump());
}

void Client::resend_verification(const std::string& email, const std::string& tenant_id) {
    p_->ensure_open();
    json body = json::object();
    body["email"] = email;
    body["tenant_id"] = tenant_id;
    post(*p_, kResendVerification, body.dump());
}

void Client::resend_own_verification() {
    p_->ensure_open();
    // §25.7: session-authenticated, and the refusal is raised HERE, with no wire call.
    // Sending it anyway would leave a rejected request in the audit log for what is a
    // programming error on this side.
    {
        std::lock_guard<std::mutex> lock(p_->state_mtx);
        if (!p_->session) {
            throw AuthError(
                "resend_own_verification requires an authenticated session: it resends the "
                "mail for the account you are signed in to, and names no address "
                "(CONTRACT.md §25.7). Use resend_verification(email, tenant_id) when there "
                "is no session.");
        }
    }
    // The empty object, exactly as mfa_enroll() sends: the server takes the address off
    // the caller's own record, and §25.6 asks for a request carrying NO address field.
    post(*p_, kResendOwnVerification, "{}");
}

// ---------------------------------------------------------------------------
// Password reset (§25.4)
// ---------------------------------------------------------------------------

void Client::request_password_reset(const PasswordResetRequest& request) {
    p_->ensure_open();
    if (request.email.empty()) throw AuthError("request_password_reset needs an email address");

    json body = json::object();
    body["email"] = request.email;
    // Only ONE form per level, and an override beats the configured value: a
    // server handed both has to decide which one it trusts.
    if (request.org_slug) {
        body["org_slug"] = *request.org_slug;
    } else if (p_->org_slug) {
        body["org_slug"] = *p_->org_slug;
    } else if (p_->org_id) {
        body["org_id"] = *p_->org_id;
    }
    if (request.tenant_id) {
        body["tenant_id"] = *request.tenant_id;
    } else if (request.tenant_slug) {
        body["tenant_slug"] = *request.tenant_slug;
    } else if (p_->tenant_id) {
        body["tenant_id"] = *p_->tenant_id;
    } else if (p_->tenant_slug) {
        body["tenant_slug"] = *p_->tenant_slug;
    }
    // §25.4: the server answers identically whether or not the address exists,
    // and nothing here tells the two apart.
    post(*p_, kReset, body.dump());
}

PasswordResetContext Client::password_reset_context(const Sensitive<std::string>& token) {
    p_->ensure_open();
    const std::string path = std::string(kResetContext) + "?token=" + pct(detail::reveal(token));
    const HttpResponse resp = p_->send_raw(p_->build_request("GET", path, ""));
    if (resp.status < 200 || resp.status >= 300) {
        // §25.4 rule 3: a 404 means unknown, expired OR already-consumed,
        // deliberately without distinguishing them; this SDK does not
        // distinguish them either, and the message must not invent a
        // distinction the server refused to make.
        Client::Impl::raise_for_status(resp);
    }

    const json j = json::parse(resp.body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        // A 200 whose body did not parse is NOT "this tenant has no OPAQUE".
        // Reporting it as one hands the caller permission to send a plaintext
        // password to a tenant that may be in `opaque_mode: required`.
        throw NetworkError("reset context: response body is not a JSON object",
                           "malformed_body");
    }

    PasswordResetContext context;
    if (j.contains("opaque") && j["opaque"].is_object()) {
        // Forwarded to the §23 helpers as TEXT. This SDK does not model,
        // validate or re-encode the block — it cannot, and anything it did to it
        // would be a guess about a protocol it deliberately does not implement.
        context.opaque_json = j["opaque"].dump();
    }
    return context;
}

void Client::confirm_password_reset(const PasswordResetConfirmation& confirmation) {
    p_->ensure_open();
    if (confirmation.tenant_id.empty()) {
        throw AuthError("confirm_password_reset needs a tenant_id (a BODY field, CONTRACT.md §25.1)");
    }

    json body = json::object();
    body["token"] = detail::reveal(confirmation.token);
    body["new_password"] = detail::reveal(confirmation.new_password);
    body["tenant_id"] = confirmation.tenant_id;
    if (confirmation.opaque_json && !confirmation.opaque_json->empty()) {
        const json opaque = json::parse(*confirmation.opaque_json, nullptr, false);
        if (opaque.is_discarded()) {
            throw AuthError("confirm_password_reset: opaque_json is not valid JSON");
        }
        body["opaque"] = opaque;
    }
    post(*p_, kResetConfirm, body.dump());
}

}  // namespace axiam
