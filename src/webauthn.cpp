// axiam WebAuthn / passkeys, the relying-party layer — CONTRACT.md §24.
//
// The eight wire operations plus §24.6a's JSON bridge. §24.6b's linked-API
// ceremony helper is deliberately absent: a C++ program has no authenticator on
// the targets this SDK serves, and rule 2 forbids emulating one in software.
//
// THE ONE THING THIS FILE IS CAREFUL ABOUT. Both *_finish bodies are assembled
// as TEXT, with the caller's response JSON spliced in unmodified. Parsing it
// into nlohmann::json and dumping it back out would reorder members, round every
// number through a double, and hand the server a byte sequence the authenticator
// never signed. The only thing this file checks about that string is that it IS
// a JSON object — the SDK will not POST a body it already knows the server
// cannot verify.
#include "axiam/webauthn.hpp"

#include <algorithm>
#include <cctype>
#include <mutex>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "client_impl.hpp"

namespace axiam {
namespace {

using json = nlohmann::json;

constexpr const char* kRegisterStart = "/api/v1/auth/webauthn/register/start";
constexpr const char* kRegisterFinish = "/api/v1/auth/webauthn/register/finish";
constexpr const char* kAuthStart = "/api/v1/auth/webauthn/authenticate/start";
constexpr const char* kAuthFinish = "/api/v1/auth/webauthn/authenticate/finish";
constexpr const char* kDiscoverableStart =
    "/api/v1/auth/webauthn/authenticate/discoverable/start";
constexpr const char* kDiscoverableFinish =
    "/api/v1/auth/webauthn/authenticate/discoverable/finish";
constexpr const char* kSetupRegisterStart = "/api/v1/auth/webauthn/setup/register/start";
constexpr const char* kSetupRegisterFinish = "/api/v1/auth/webauthn/setup/register/finish";

std::string lower_trim(const std::string& in) {
    std::size_t b = 0;
    std::size_t e = in.size();
    auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
    while (b < e && is_space(static_cast<unsigned char>(in[b]))) ++b;
    while (e > b && is_space(static_cast<unsigned char>(in[e - 1]))) --e;
    std::string out = in.substr(b, e - b);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/// The RAW TEXT of `key`'s value inside a JSON object, or none.
///
/// §24.0 is why this exists rather than a `j[key].dump()`. nlohmann::json stores
/// object members in a std::map, so a parse-then-dump round trip comes back
/// SORTED — the server's member order is gone, numbers have been through a
/// double, and what the caller hands the authenticator is no longer what the
/// server sent. For the options that is merely wrong; for anything the server
/// later verifies it is a signature failure with no visible cause.
///
/// So the value is lifted as a substring of the response body: brace and bracket
/// depth tracked, string literals and their escapes skipped so a `}` inside a
/// base64url-adjacent string cannot end the scan early.
std::optional<std::string> raw_member(const std::string& body, const std::string& key) {
    const std::string needle = "\"" + key + "\"";
    std::size_t at = 0;
    bool in_string = false;
    int depth = 0;
    // Find the key at depth 1 — a nested object may carry the same name, and the
    // one that matters is the response's own member.
    for (; at < body.size(); ++at) {
        const char c = body[at];
        if (in_string) {
            if (c == '\\') { ++at; continue; }
            if (c == '"') in_string = false;
            continue;
        }
        if (c == '"') {
            if (depth == 1 && body.compare(at, needle.size(), needle) == 0) {
                at += needle.size();
                break;
            }
            in_string = true;
            continue;
        }
        if (c == '{' || c == '[') ++depth;
        if (c == '}' || c == ']') --depth;
    }
    if (at >= body.size()) return std::nullopt;

    while (at < body.size() && (std::isspace(static_cast<unsigned char>(body[at])) || body[at] == ':')) {
        ++at;
    }
    if (at >= body.size()) return std::nullopt;

    const std::size_t start = at;
    int value_depth = 0;
    in_string = false;
    for (; at < body.size(); ++at) {
        const char c = body[at];
        if (in_string) {
            if (c == '\\') { ++at; continue; }
            if (c == '"') {
                in_string = false;
                if (value_depth == 0) { ++at; break; }
            }
            continue;
        }
        if (c == '"') { in_string = true; continue; }
        if (c == '{' || c == '[') { ++value_depth; continue; }
        if (c == '}' || c == ']') {
            --value_depth;
            if (value_depth == 0) { ++at; break; }
            if (value_depth < 0) break;
            continue;
        }
        if (value_depth == 0 && (c == ',' || c == '}')) break;
    }
    return body.substr(start, at - start);
}

/// §24.1: register/… needs a session, and the refusal is raised client-side with
/// NO WIRE CALL — the shape §1.1 rule 3 requires of get_user_info. An SDK that
/// let the request out and mapped the 401 has told the caller the same thing
/// while leaking that the account exists.
void require_session(Client::Impl& impl, const char* operation) {
    bool have;
    {
        std::lock_guard<std::mutex> lock(impl.state_mtx);
        have = impl.session;
    }
    if (!have) {
        throw AuthError(std::string(operation) +
                        " requires an authenticated session: enrol a passkey while signed in "
                        "(CONTRACT.md §24.1)");
    }
}

/// Build a *_finish body as TEXT, splicing `response` in verbatim (§24.0,
/// §24.6a rule 2).
///
/// The one thing validated is that the string IS a JSON object, and it is
/// validated client-side so no unverifiable body is ever POSTed.
std::string finish_body(const std::string& state_token,
                        const std::optional<std::string>& credential_name,
                        const std::string& response, const char* operation,
                        const std::optional<std::string>& setup_token = std::nullopt) {
    // Trim leading whitespace so the object check sees the first real byte; the
    // spliced text keeps whatever the platform produced from there on.
    std::size_t b = 0;
    while (b < response.size() && std::isspace(static_cast<unsigned char>(response[b]))) ++b;
    const std::string trimmed = response.substr(b);

    const json parsed = json::parse(trimmed, nullptr, false);
    if (parsed.is_discarded()) {
        throw AuthError(std::string(operation) +
                        ": the authenticator response string is not valid JSON. Pass the "
                        "platform's response JSON verbatim (CONTRACT.md §24.6a)");
    }
    if (!parsed.is_object()) {
        throw AuthError(std::string(operation) +
                        ": the authenticator response must be a JSON object "
                        "(CONTRACT.md §24.6a)");
    }

    std::string body = "{";
    // §24.1 (contract 1.45): setup/register/finish's wire shape is
    // `{ setup_token, state_token, credential_name, response }` — the setup
    // token leads because it, not state_token, is the credential this call
    // accepts.
    if (setup_token) {
        body += "\"setup_token\":";
        body += json(*setup_token).dump();
        body += ",";
    }
    body += "\"state_token\":";
    body += json(state_token).dump();
    if (credential_name) {
        body += ",\"credential_name\":";
        body += json(*credential_name).dump();
    }
    body += ",\"response\":";
    body += trimmed;  // VERBATIM — the whole point of this function.
    body += "}";
    return body;
}

/// Run either *_start call and return the options untouched.
///
/// `no_stored_cookies` is §24.1's setup/register/start exception: it takes no
/// session, and MUST NOT carry the client's session credential even when one
/// is configured (contract 1.45). Default false leaves the six ordinary wire
/// operations untouched.
WebauthnChallenge start(Client::Impl& impl, const char* path, const std::string& body,
                        bool no_stored_cookies = false) {
    HttpRequest req = impl.build_request("POST", path, body);
    req.no_stored_cookies = no_stored_cookies;
    const HttpResponse resp = impl.send_raw(req);
    if (resp.status < 200 || resp.status >= 300) Client::Impl::raise_for_status(resp);

    const json j = json::parse(resp.body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        // A 200 whose body cannot be parsed is not a challenge with missing
        // fields: there is nothing to hand an authenticator, and an empty
        // options object would send the caller into a ceremony that cannot
        // succeed.
        throw NetworkError("webauthn start: response body is not a JSON object",
                           "malformed_body");
    }

    WebauthnChallenge challenge;
    // The RAW substring, not `j["challenge"].dump()`: see raw_member() above for
    // why a parse-then-dump round trip loses the server's bytes (§24.0).
    challenge.challenge_json = raw_member(resp.body, "challenge").value_or(std::string("{}"));
    challenge.state_token = Sensitive<std::string>(
        j.contains("state_token") && j["state_token"].is_string()
            ? j["state_token"].get<std::string>()
            : std::string{});
    return challenge;
}

/// The shared tail of both authentication ceremonies.
WebauthnLoginResult finish_login(Client::Impl& impl, const char* path,
                                 const Sensitive<std::string>& state_token,
                                 const std::string& response, const char* operation) {
    impl.ensure_open();
    const std::string body =
        finish_body(detail::reveal(state_token), std::nullopt, response, operation);

    // §17.1 rule 9 / §24.3: memo entries are keyed by subject, and this call
    // changes the subject. Cleared before the wire, on the caller's INTENT,
    // exactly as login() does it.
    if (impl.memo) impl.memo->clear();

    const HttpResponse resp = impl.send_raw(impl.build_request("POST", path, body));
    if (resp.status < 200 || resp.status >= 300) Client::Impl::raise_for_status(resp);

    const json j = json::parse(resp.body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        // Returning an empty result here would tell the caller they are signed
        // in while handing them no tokens to prove it.
        throw NetworkError("webauthn finish: response body is not a JSON object",
                           "malformed_body");
    }

    WebauthnLoginResult out;
    out.access_token = Sensitive<std::string>(j.value("access_token", std::string{}));
    out.refresh_token = Sensitive<std::string>(j.value("refresh_token", std::string{}));
    out.session_id = j.value("session_id", std::string{});
    out.expires_in = j.value("expires_in", static_cast<std::int64_t>(0));

    // §24.3: the cookie triple arrived on this response and the transport stored
    // it; this is the in-memory half.
    {
        std::lock_guard<std::mutex> lock(impl.state_mtx);
        impl.session = true;
        // C-12 N4.4: a WebAuthn authentication completes a session, so it
        // replaces any device credential this client had previously adopted.
        impl.release_device_credential_locked();
        // CONTRACT.md §5.2 rule 1 (contract 1.51): WebauthnLoginResult carries no
        // `LoginUserInfo` -- this ceremony completes a session without one, so
        // the acting-tenant gate resets to UNKNOWN (never to "not
        // organization-level"). A later acting_tenant() sends the header and
        // lets the server's 403 decide, per §5.2's "which sessions count as
        // holding a login result" clause.
        impl.login_user_info = std::nullopt;
    }
    return out;
}

/// Fill the discoverable ceremony's workspace from the client's own
/// configuration when the caller passed none.
///
/// Only fields that actually have a value are emitted, and only ONE form per
/// level: the server takes either, and sending both makes it decide which one to
/// trust. A UUID wins over a slug because it is unambiguous.
std::string workspace_body(const Client::Impl& impl,
                           const std::optional<WebauthnWorkspace>& ws) {
    json body = json::object();

    std::optional<std::string> org_id = ws ? ws->org_id : std::nullopt;
    std::optional<std::string> org_slug = ws ? ws->org_slug : std::nullopt;
    if (!org_id && !org_slug) {
        org_id = impl.org_id;
        org_slug = impl.org_slug;
    }
    if (org_id) {
        body["org_id"] = *org_id;
    } else if (org_slug) {
        body["org_slug"] = *org_slug;
    } else {
        throw AuthError(
            "webauthn_discoverable_start needs an organization: build the client with one, "
            "or pass it in the workspace argument (CONTRACT.md §24.1)");
    }

    std::optional<std::string> tenant_id = ws ? ws->tenant_id : std::nullopt;
    std::optional<std::string> tenant_slug = ws ? ws->tenant_slug : std::nullopt;
    if (tenant_id) {
        body["tenant_id"] = *tenant_id;
    } else if (tenant_slug) {
        body["tenant_slug"] = *tenant_slug;
    } else if (impl.tenant_id) {
        body["tenant_id"] = *impl.tenant_id;
    } else {
        // §5 makes one of the two mandatory at construction — there is no
        // default tenant — so this arm always has a slug to fall back on. The
        // ORGANIZATION guard above is different, and stays: an org is optional.
        body["tenant_slug"] = *impl.tenant_slug;
    }
    return body.dump();
}

}  // namespace

// ---------------------------------------------------------------------------
// §24.6a — the JSON bridge
// ---------------------------------------------------------------------------

std::string WebauthnChallenge::request_json() const {
    // Wrapper REMOVAL, by substring — not a re-serialisation with a filter.
    // Everything inside crosses untouched, in the order the server chose (§24.0).
    if (auto inner = raw_member(challenge_json, "publicKey")) return *inner;
    // A server that sent the bare options rather than the wrapper is not wrong
    // for every consumer, and this call has one job: hand a caller something a
    // platform API accepts.
    return challenge_json;
}

// ---------------------------------------------------------------------------
// §24.6b rule 5 — the failure classification
// ---------------------------------------------------------------------------

WebauthnFailure webauthn_classify(const std::string& platform_error_name) {
    const std::string name = lower_trim(platform_error_name);
    if (name == "notallowederror" || name == "cancelled" || name == "canceled") {
        return WebauthnFailure::kCancelled;
    }
    if (name == "invalidstateerror") return WebauthnFailure::kAlreadyRegistered;
    if (name == "aborterror" || name == "timeout") return WebauthnFailure::kTimeout;
    if (name == "notsupportederror" || name == "securityerror") {
        return WebauthnFailure::kUnsupported;
    }
    return WebauthnFailure::kUnknown;
}

std::string webauthn_failure_message(WebauthnFailure failure) {
    switch (failure) {
        case WebauthnFailure::kCancelled:
            // Deliberately does not accuse anyone of cancelling: the same
            // classification covers a silent timeout, and the spec will not say
            // which happened.
            return "The request was cancelled or timed out. You can try again.";
        case WebauthnFailure::kAlreadyRegistered:
            return "This device is already registered on your account. "
                   "Try a different device, or remove the existing one first.";
        case WebauthnFailure::kTimeout:
            return "The request timed out before it completed. Please try again.";
        case WebauthnFailure::kUnsupported:
            return "This browser or device cannot be used for passkeys. "
                   "Try a different browser, or use another sign-in method.";
        case WebauthnFailure::kUnknown:
            break;
    }
    return "Something went wrong. Please try again.";
}

// ---------------------------------------------------------------------------
// §24.1 — the eight wire operations
// ---------------------------------------------------------------------------

WebauthnChallenge Client::webauthn_register_start() {
    p_->ensure_open();
    require_session(*p_, "webauthn_register_start");
    // No retry budget: §24.4 rule 2 makes the 503 here a configuration state
    // rather than a transient one, and send_raw makes exactly one attempt.
    return start(*p_, kRegisterStart, "{}");
}

WebauthnCredential Client::webauthn_register_finish(const Sensitive<std::string>& state_token,
                                                    const std::string& credential_name,
                                                    const std::string& response) {
    p_->ensure_open();
    require_session(*p_, "webauthn_register_finish");
    if (credential_name.empty()) {
        // The label is what the user later recognises the key by in a list. An
        // SDK that defaulted it would produce an account with four
        // indistinguishable entries and no way to tell which device to remove.
        throw AuthError("webauthn_register_finish needs a credential name");
    }

    const std::string body = finish_body(detail::reveal(state_token), credential_name, response,
                                         "webauthn_register_finish");
    const HttpResponse resp = p_->send_raw(p_->build_request("POST", kRegisterFinish, body));

    if (resp.status == 403) {
        // §24.4 rule 1: the 403 from register/finish is the one whose BODY
        // matters. The generic §2 mapping would say "authorization denied",
        // which tells the person holding the key nothing they can act on: the
        // tenant's attestation policy rejected THIS authenticator, and the
        // server's message is the only place that says which one would be
        // accepted. Only the named `message` field is read; the rest of the body
        // is still discarded.
        const json j = json::parse(resp.body, nullptr, false);
        std::string message = "the tenant's attestation policy rejected this authenticator";
        if (!j.is_discarded() && j.contains("message") && j["message"].is_string()) {
            message = j["message"].get<std::string>();
        }
        throw AuthzError("webauthn_register_finish: " + message);
    }
    // The RFC status for a created credential. A success predicate written
    // `== 200` fails every real enrolment while passing everything else.
    if (resp.status < 200 || resp.status >= 300) Client::Impl::raise_for_status(resp);

    const json j = json::parse(resp.body, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        // A credential the caller cannot name is one they can never find again
        // to remove.
        throw NetworkError("webauthn register/finish: response body is not a JSON object",
                           "malformed_body");
    }

    WebauthnCredential cred;
    cred.id = j.value("id", std::string{});
    cred.credential_id = j.value("credential_id", std::string{});
    cred.name = j.value("name", std::string{});
    cred.credential_type = j.value("credential_type", std::string{});
    cred.created_at = j.value("created_at", std::string{});
    if (j.contains("last_used_at") && j["last_used_at"].is_string()) {
        cred.last_used_at = j["last_used_at"].get<std::string>();
    }
    return cred;
}

WebauthnChallenge Client::webauthn_authenticate_start(
    const Sensitive<std::string>& challenge_token) {
    p_->ensure_open();
    if (detail::reveal(challenge_token).empty()) {
        // §24.2: the second-factor ceremony cannot run without the token that
        // names the user. Merging it with the discoverable one behind an empty
        // argument reproduces a bug the server already fixed.
        throw AuthError(
            "webauthn_authenticate_start needs the challenge token from a login that answered "
            "mfa_required (CONTRACT.md §24.2)");
    }
    json body = json::object();
    body["challenge_token"] = detail::reveal(challenge_token);
    return start(*p_, kAuthStart, body.dump());
}

WebauthnLoginResult Client::webauthn_authenticate_finish(
    const Sensitive<std::string>& state_token, const std::string& response) {
    return finish_login(*p_, kAuthFinish, state_token, response, "webauthn_authenticate_finish");
}

WebauthnChallenge Client::webauthn_discoverable_start(
    std::optional<WebauthnWorkspace> workspace) {
    p_->ensure_open();
    return start(*p_, kDiscoverableStart, workspace_body(*p_, workspace));
}

WebauthnLoginResult Client::webauthn_discoverable_finish(
    const Sensitive<std::string>& state_token, const std::string& response) {
    return finish_login(*p_, kDiscoverableFinish, state_token, response,
                        "webauthn_discoverable_finish");
}

// ---------------------------------------------------------------------------
// §24.1 (contract 1.45) — setup/register/*, the WebAuthn twin of
// mfa_setup_enroll() / mfa_setup_confirm() (CONTRACT.md §25.1, §25.2 rule 2).
//
// Both take NO session: the setup token in the request body is the only
// credential, exactly as it is for the TOTP pair, and an SDK MUST NOT attach
// its own session credential regardless of whether one is configured (§24.1).
// `start()` and the body built below both carry `no_stored_cookies = true`
// for that reason; see transport.hpp and http_curl.cpp for what that does at
// the transport layer.
// ---------------------------------------------------------------------------

WebauthnChallenge Client::webauthn_setup_register_start(
    const Sensitive<std::string>& setup_token) {
    p_->ensure_open();
    // No require_session() call, deliberately: unlike register/start, this is
    // the exception §24.1 names — there is no session yet, and the setup
    // token is the credential.
    json body = json::object();
    body["setup_token"] = detail::reveal(setup_token);
    return start(*p_, kSetupRegisterStart, body.dump(), /*no_stored_cookies=*/true);
}

LoginResult Client::webauthn_setup_register_finish(const Sensitive<std::string>& setup_token,
                                                    const Sensitive<std::string>& state_token,
                                                    const std::string& credential_name,
                                                    const std::string& response) {
    p_->ensure_open();
    if (credential_name.empty()) {
        // Same reasoning as webauthn_register_finish(): the label is how the
        // user later recognises this credential in a list.
        throw AuthError("webauthn_setup_register_finish needs a credential name");
    }

    // §25.2 rule 2 / §24.3 rule 4: this IS the completion of a login, so the
    // memo is cleared on the caller's INTENT, before the wire — mirroring
    // mfa_setup_confirm() exactly (account.cpp), not webauthn_authenticate_finish()'s
    // WebauthnLoginResult shape, because the wire response here is a plain
    // LoginSuccessResponse.
    if (p_->memo) p_->memo->clear();

    const std::string body =
        finish_body(detail::reveal(state_token), credential_name, response,
                   "webauthn_setup_register_finish", detail::reveal(setup_token));

    HttpRequest req = p_->build_request("POST", kSetupRegisterFinish, body);
    // §24.1: no session credential outbound, even if one is configured — the
    // setup token is the only credential this call accepts.
    req.no_stored_cookies = true;
    const HttpResponse resp = p_->send_raw(req);
    if (resp.status < 200 || resp.status >= 300) Client::Impl::raise_for_status(resp);

    const json j = json::parse(resp.body, nullptr, false);
    LoginResult result;
    if (!j.is_discarded() && j.is_object()) {
        result.session_id = j.value("session_id", std::string{});
        result.expires_in = j.value("expires_in", static_cast<std::int64_t>(0));
        // Through the SAME reader mfa_setup_confirm() and login() use — see
        // account.cpp's comment on why a second hand-rolled reader here would
        // be one more place for §5.2.2's "absent means EQUAL" fallback to be
        // forgotten.
        if (j.contains("user") && j["user"].is_object())
            result.user = detail::parse_user(j["user"]);
    }
    {
        std::lock_guard<std::mutex> lock(p_->state_mtx);
        p_->session = true;
        // C-12 N4.4: the WebAuthn setup ceremony completes a login (same as
        // mfa_setup_confirm()), so it replaces any device credential this
        // client had previously adopted.
        p_->release_device_credential_locked();
        // §5.2 rule 1 gate: reset to exactly what THIS response reported (the
        // WebAuthn passkey/security-key setup carve-out of "which sessions
        // count as holding a login result" -- disengaged when the server sent
        // no `user`, never carried over from an earlier login).
        p_->login_user_info = result.user;
        if (result.user) {
            p_->resolved_tenant_id = result.user->tenant_id;
            if (!result.user->principal_tenant_id.empty())
                p_->principal_tenant_id = result.user->principal_tenant_id;
        }
    }
    return result;
}

}  // namespace axiam
