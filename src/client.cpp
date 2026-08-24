#include <openssl/crypto.h>

#include "axiam/client.hpp"

#include <algorithm>
#include <atomic>
#include <functional>
#include <mutex>
#include <random>
#include <thread>

#include <nlohmann/json.hpp>

#include "axiam/http_curl.hpp"
#include "axiam/jwks.hpp"
#include "client_impl.hpp"
#include "decision_memo.hpp"
#include "refresh_guard.hpp"
#include "retry.hpp"

namespace axiam {

using json = nlohmann::json;

namespace {

/// Extract a cookie's value from a `Set-Cookie` header value list (each entry
/// is "name=value; attr; attr"). Returns nullopt if the cookie is absent.
std::optional<std::string> cookie_value(const std::vector<std::string>& set_cookies,
                                        const std::string& name) {
    const std::string prefix = name + "=";
    for (const auto& sc : set_cookies) {
        if (sc.rfind(prefix, 0) == 0) {
            std::string rest = sc.substr(prefix.size());
            const auto semi = rest.find(';');
            return semi == std::string::npos ? rest : rest.substr(0, semi);
        }
    }
    return std::nullopt;
}

/// Decode a claim string out of a compact JWT WITHOUT verifying its signature.
/// Used only to recover the tenant_id/org_id the client must echo in the
/// refresh body (the server re-derives and re-validates the authoritative
/// org_id, so this carries no trust weight). Returns nullopt when the token is
/// malformed or the claim is absent/not a string.
std::optional<std::string> jwt_claim(const std::string& jwt, const std::string& claim) {
    const auto dot1 = jwt.find('.');
    if (dot1 == std::string::npos) return std::nullopt;
    const auto dot2 = jwt.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return std::nullopt;
    const auto payload = base64url_decode(jwt.substr(dot1 + 1, dot2 - dot1 - 1));
    if (!payload) return std::nullopt;
    auto j = json::parse(*payload, nullptr, false);
    if (j.is_discarded() || !j.contains(claim) || !j[claim].is_string()) return std::nullopt;
    return j[claim].get<std::string>();
}

/// §6 / SEC-073: refuse a plaintext base URL at construction.
///
/// The base URL is concatenated verbatim into every request, so an `http://`
/// base silently downgrades the whole session — login credentials, the httpOnly
/// cookie jar, the CSRF token and the tenant header all go out in cleartext,
/// with strict TLS never getting a chance to apply. Only `https` is accepted,
/// with the usual loopback carve-out (`localhost`, `127.0.0.1`, `::1`) so local
/// development against a plaintext dev server still works. Mirrors the Rust
/// SDK's `ensure_secure_scheme`.
void ensure_secure_scheme(const std::string& base_url) {
    const auto scheme_end = base_url.find("://");
    if (scheme_end == std::string::npos) {
        throw std::invalid_argument(
            "AxiamClient: base_url must be an absolute https:// URL");
    }
    const std::string scheme = CaseInsensitiveLess::lower(base_url.substr(0, scheme_end));
    if (scheme == "https") return;
    if (scheme != "http") {
        throw std::invalid_argument("AxiamClient: base_url scheme '" + scheme +
                                    "' is not supported; https:// is required");
    }

    // http:// — permitted only for loopback development hosts.
    std::string authority = base_url.substr(scheme_end + 3);
    const auto path_start = authority.find_first_of("/?#");
    if (path_start != std::string::npos) authority.erase(path_start);
    const auto userinfo = authority.rfind('@');
    if (userinfo != std::string::npos) authority.erase(0, userinfo + 1);

    std::string host;
    if (!authority.empty() && authority.front() == '[') {  // [::1]:8080
        const auto close = authority.find(']');
        if (close != std::string::npos) host = authority.substr(1, close - 1);
    } else {
        const auto colon = authority.find(':');
        host = (colon == std::string::npos) ? authority : authority.substr(0, colon);
    }
    host = CaseInsensitiveLess::lower(host);

    if (host == "localhost" || host == "127.0.0.1" || host == "::1") return;

    throw std::invalid_argument(
        "AxiamClient: refusing a plaintext http:// base_url for host '" + host +
        "' (CONTRACT §6 requires https; http is allowed only for localhost, "
        "127.0.0.1 and ::1)");
}

/// Resolve the org_id (UUID) from the access-token cookie set by a login
/// response, if present. See jwt_claim for the trust rationale.
std::optional<std::string> org_id_from_cookies(const std::vector<std::string>& set_cookies) {
    const auto access = cookie_value(set_cookies, "axiam_access");
    if (!access) return std::nullopt;
    return jwt_claim(*access, "org_id");
}

}  // namespace


// ------------------------- Builder -------------------------

Client::Builder Client::builder() { return Builder{}; }

Client::Builder& Client::Builder::base_url(std::string url) {
    while (!url.empty() && url.back() == '/') url.pop_back();
    base_url_ = std::move(url);
    return *this;
}
Client::Builder& Client::Builder::tenant_slug(std::string slug) {
    tenant_slug_ = std::move(slug);
    return *this;
}
Client::Builder& Client::Builder::tenant_id(std::string id) {
    tenant_id_ = std::move(id);
    return *this;
}
Client::Builder& Client::Builder::oidc_client_id(std::string id) {
    oidc_client_id_ = std::move(id);
    return *this;
}
Client::Builder& Client::Builder::oidc_client_secret(std::string secret) {
    // An empty secret is UNSET, not a secret whose value is "": a public client
    // must send no `client_secret` field at all (§12.1's absent-optional rule),
    // and an empty one would authenticate as a confidential client with a blank
    // password.
    if (!secret.empty()) oidc_client_secret_ = std::move(secret);
    return *this;
}
Client::Builder& Client::Builder::oidc_discovery_ttl(std::chrono::seconds ttl) {
    oidc_discovery_ttl_ = ttl;
    return *this;
}
Client::Builder& Client::Builder::oidc_clock_skew(std::chrono::seconds skew) {
    oidc_clock_skew_ = skew;
    return *this;
}

Client::Builder& Client::Builder::retry_enabled(bool enabled) {
    retry_enabled_ = enabled;
    return *this;
}
Client::Builder& Client::Builder::decision_memo_ttl(std::chrono::milliseconds ttl) {
    decision_memo_ttl_ = ttl;
    return *this;
}
Client::Builder& Client::Builder::telemetry_hook(TelemetryHook hook) {
    telemetry_hook_ = std::move(hook);
    return *this;
}
Client::Builder& Client::Builder::org_slug(std::string slug) {
    org_slug_ = std::move(slug);
    return *this;
}
Client::Builder& Client::Builder::org_id(std::string id) {
    org_id_ = std::move(id);
    return *this;
}
Client::Builder& Client::Builder::with_custom_ca(std::string ca_pem) {
    if (ca_pem.find("-----BEGIN") == std::string::npos) {
        throw std::invalid_argument("with_custom_ca: expected PEM-encoded certificate");
    }
    custom_ca_pem_ = std::move(ca_pem);
    return *this;
}
Client::Builder& Client::Builder::with_client_cert(std::string cert_pem, std::string key_pem) {
    if (cert_pem.find("-----BEGIN") == std::string::npos ||
        key_pem.find("-----BEGIN") == std::string::npos) {
        throw std::invalid_argument("with_client_cert: expected PEM cert chain and PEM private key");
    }
    client_cert_pem_ = std::move(cert_pem);
    client_key_pem_ = std::move(key_pem);
    return *this;
}
Client::Builder& Client::Builder::connect_timeout(std::chrono::milliseconds ms) {
    connect_timeout_ = ms;
    return *this;
}
Client::Builder& Client::Builder::request_timeout(std::chrono::milliseconds ms) {
    request_timeout_ = ms;
    return *this;
}
Client::Builder& Client::Builder::max_concurrent_requests(unsigned n) {
    max_concurrent_requests_ = n == 0 ? 1u : n;
    return *this;
}
Client::Builder& Client::Builder::transport(Transport t) {
    transport_ = std::move(t);
    return *this;
}

Client Client::Builder::build() {
    if (base_url_.empty()) {
        throw std::invalid_argument("AxiamClient: base_url is required");
    }
    // §6 / SEC-073: no plaintext transport (loopback dev exception).
    ensure_secure_scheme(base_url_);
    // §5: tenant context is non-optional. No default tenant.
    if (!tenant_slug_.has_value() && !tenant_id_.has_value()) {
        throw AuthError("AxiamClient: tenant_slug or tenant_id is required (no default tenant)");
    }

    auto impl = std::make_shared<Client::Impl>();
    impl->base_url = base_url_;
    impl->tenant_slug = tenant_slug_;
    impl->tenant_id = tenant_id_;
    impl->org_slug = org_slug_;
    impl->org_id = org_id_;
    impl->tenant_header = tenant_id_.value_or(tenant_slug_.value_or(""));

    if (transport_) {
        impl->transport = transport_;
    } else {
        TlsConfig tls;
        tls.custom_ca_pem = custom_ca_pem_;
        tls.client_cert_pem = client_cert_pem_;
        tls.client_key_pem = Sensitive<std::string>(client_key_pem_);
        tls.connect_timeout_ms = static_cast<long>(connect_timeout_.count());
        tls.request_timeout_ms = static_cast<long>(request_timeout_.count());
        tls.max_concurrent_requests = max_concurrent_requests_;
        impl->transport = CurlTransport::make_transport(std::move(tls));
    }

    impl->jwks_verifier = std::make_unique<JwksVerifier>(impl->transport, impl->base_url);

    impl->oidc_client_id = oidc_client_id_;                                 // §12
    if (oidc_client_secret_) {
        impl->oidc_client_secret = Sensitive<std::string>(*oidc_client_secret_);
    }
    // §12.3 rule 6: 5 minutes is a FLOOR — a smaller request is raised, not
    // refused. §12.4 rule 5: 60 seconds is a CEILING — a larger request is
    // clamped DOWN rather than rejected, because an operator who asked for five
    // minutes should get a working client with a conformant window, not a
    // construction failure they will route around by disabling something.
    impl->oidc_discovery_ttl =
        std::max(oidc_discovery_ttl_, std::chrono::seconds(kOidcDiscoveryTtlFloorSeconds));
    impl->oidc_clock_skew =
        std::clamp(oidc_clock_skew_, std::chrono::seconds(0),
                   std::chrono::seconds(kOidcMaxClockSkewSeconds));

    impl->retry_enabled = retry_enabled_;                                   // §16
    impl->memo = std::make_unique<detail::DecisionMemo>(decision_memo_ttl_);  // §17
    impl->telemetry = telemetry_hook_;                                      // §19

    // §19.2 rule 6: a setting we lowered is reported, not swallowed. An operator
    // who set a 60-second memo TTL believes their staleness bound is 60 seconds;
    // it is five, and without this nothing anywhere says so. Nothing is emitted
    // when the request was already inside the limit — an event that fires when
    // nothing happened trains its reader to ignore it. The memo TTL is the only
    // clamped setting here: §16.1's table is not configurable, only switchable.
    if (decision_memo_ttl_ > std::chrono::milliseconds{0} &&
        decision_memo_ttl_ != impl->memo->effective_ttl()) {
        impl->emit(ConfigClampedEvent{
            "decision_memo_ttl", std::to_string(decision_memo_ttl_.count()) + "ms",
            std::to_string(impl->memo->effective_ttl().count()) + "ms", "\u00a717.1 rule 2"});
    }

    return Client(std::move(impl));
}

// ------------------------- Client -------------------------

Client::Client(std::shared_ptr<Impl> impl) : p_(std::move(impl)) {}

namespace {
UserInfo parse_user(const json& u) {
    UserInfo info;
    info.id = u.value("id", "");
    info.username = u.value("username", "");
    info.email = u.value("email", "");
    info.tenant_id = u.value("tenant_id", "");
    if (u.contains("org_slug") && u["org_slug"].is_string())
        info.org_slug = u["org_slug"].get<std::string>();
    if (u.contains("tenant_slug") && u["tenant_slug"].is_string())
        info.tenant_slug = u["tenant_slug"].get<std::string>();
    return info;
}

AccessDecision parse_decision(const json& d) {
    AccessDecision dec;
    dec.allowed = d.value("allowed", false);
    if (d.contains("reason") && d["reason"].is_string()) dec.reason = d["reason"].get<std::string>();
    // §11 rule 9. Copied verbatim, with no validation against the three known
    // codes: an unrecognised code must reach the caller, and a server that omits
    // the field (or sends null) must read as absent rather than as an error.
    if (d.contains("reason_code") && d["reason_code"].is_string())
        dec.reason_code = d["reason_code"].get<std::string>();
    return dec;
}
}  // namespace

LoginResult Client::login(const std::string& username_or_email, const std::string& password) {
    p_->ensure_open();
    // §17.1 rule 9: cleared on the CALLER'S INTENT to change credentials, not on
    // the server's answer. Entries are keyed by subject rather than session, so a
    // login that failed still means this caller is done with the principal whose
    // decisions are cached.
    if (p_->memo) p_->memo->clear();
    json body;
    body["username_or_email"] = username_or_email;
    body["password"] = password;
    if (p_->tenant_slug) body["tenant_slug"] = *p_->tenant_slug;
    if (p_->tenant_id) body["tenant_id"] = *p_->tenant_id;
    if (p_->org_slug) body["org_slug"] = *p_->org_slug;
    if (p_->org_id) body["org_id"] = *p_->org_id;

    // send_raw rather than execute(): §25.2 rule 1 gives the 403 from this
    // endpoint a specific, non-error meaning when its body says
    // `mfa_setup_required`, and execute()'s raise_for_status would collapse it
    // into an AuthzError with the body discarded — leaving the caller with a
    // generic denial and no setup token to act on. Every other status still goes
    // through the same mapping, below.
    HttpResponse resp = p_->send_raw(p_->build_request("POST", "/api/v1/auth/login", body.dump()));
    auto j = json::parse(resp.body, nullptr, false);

    LoginResult result;
    if (resp.status == 403 && !j.is_discarded() && j.is_object() &&
        j.value("mfa_setup_required", false)) {
        // §25.2 rule 1: the tenant requires MFA and this account has none, so
        // the login stopped short of a session. Before §25 an SDK either
        // reported this as a generic failure or, worse, as a successful login
        // with no session — both leave the caller with nothing to do next. The
        // setup token IS the credential for mfa_setup_enroll /
        // mfa_setup_confirm.
        result.mfa_setup_required = true;
        result.setup_token = Sensitive<std::string>(j.value("setup_token", std::string{}));
        return result;
    }
    if (resp.status < 200 || resp.status >= 300) Client::Impl::raise_for_status(resp);

    if (resp.status == 202 || (!j.is_discarded() && j.value("mfa_required", false))) {
        result.mfa_required = true;
        if (!j.is_discarded()) {
            result.challenge_token =
                Sensitive<std::string>(j.value("challenge_token", std::string{}));
            if (j.contains("available_methods") && j["available_methods"].is_array()) {
                for (const auto& m : j["available_methods"]) {
                    if (m.is_string()) result.available_methods.push_back(m.get<std::string>());
                }
            }
        }
        return result;
    }

    if (!j.is_discarded()) {
        result.session_id = j.value("session_id", "");
        result.expires_in = j.value("expires_in", static_cast<std::int64_t>(0));
        if (j.contains("user") && j["user"].is_object()) result.user = parse_user(j["user"]);
    }
    {
        std::lock_guard<std::mutex> lock(p_->state_mtx);
        p_->session = true;
        if (result.user) p_->resolved_tenant_id = result.user->tenant_id;
        // D-14: the login response body carries tenant_id/org_slug but NOT
        // org_id — recover the org_id UUID from the access-token cookie so
        // refresh() can supply it even when the client was built with a slug.
        if (auto oid = org_id_from_cookies(resp.set_cookies)) p_->resolved_org_id = *oid;
    }
    return result;
}

// ---------------------------------------------------------------------------
// §23 Secure Remote Password
// ---------------------------------------------------------------------------

namespace {

std::string json_str(const json& j, const char* name) {
    return (!j.is_discarded() && j.contains(name) && j[name].is_string())
               ? j[name].get<std::string>()
               : std::string{};
}

/// Reads an optional unsigned cost.
///
/// The `optional` is the point: a field that does not apply to the named
/// function is ABSENT, not zero (§23.4 rule 5), and reading a missing
/// `memory_kib` as `0` would stretch at the wrong cost and fail against a
/// record that is perfectly good.
std::optional<unsigned> json_cost(const json& j, const char* name) {
    if (j.is_discarded() || !j.contains(name) || !j[name].is_number_unsigned()) {
        return std::nullopt;
    }
    return j[name].get<unsigned>();
}

/// The key-stretching function and cost the server named for THIS exchange.
///
/// Never cached across exchanges and never defaulted locally (§23.4 rule 2): a
/// credential enrolled under one cost keeps working after a tenant raises its
/// policy, so a client that guessed would derive a different randomized
/// password and report "invalid password" for one that is entirely correct.
OpaqueKsfParams read_ksf(const json& j) {
    OpaqueKsfParams ksf;
    ksf.ksf = json_str(j, "ksf");
    ksf.memory_kib = json_cost(j, "memory_kib");
    ksf.iterations = json_cost(j, "iterations");
    ksf.parallelism = json_cost(j, "parallelism");
    ksf.log_n = json_cost(j, "log_n");
    ksf.r = json_cost(j, "r");
    ksf.p = json_cost(j, "p");
    return ksf;
}

/// The wire value of `opaque_mode` that makes a failed exchange non-final
/// (§23.6). Every other value, and no value at all, is final.
constexpr const char* kOpaqueModeOptional = "optional";

/// The `POST /api/v1/auth/opaque/login/start` response (§23.5), in the terms the
/// login path needs it.
///
/// `mode` carries the tenant's `opaque_mode` — `"optional"` or `"required"`,
/// never `"disabled"` (that path answers 404). It is a `std::optional` because
/// a server older than contract 1.29 does not send the field at all, and
/// absence is not the same as any value it could send: §23.4 rule 7 treats
/// absence as `required`, so an old server never draws a plaintext retry out of
/// this SDK.
///
/// It is **not** downgrade protection, and this SDK must not present it as
/// such: a hostile server that wanted the plaintext could answer `404` and get
/// the fallback whatever it puts here. What closes that is `required` itself,
/// server-side, by refusing `/auth/login` before examining any credential.
struct OpaqueLoginStart {
    std::string opaque_session;  ///< The handle to echo back verbatim.
    std::string ke2;             ///< The hex `KE2`.
    OpaqueKsfParams ksf;         ///< The cost named for THIS exchange.
    std::optional<std::string> mode;  ///< The tenant's `opaque_mode`, if reported.
};

/// One `*/start` round trip, shared by both OPAQUE paths so the meaning of a
/// failure cannot drift between them.
///
/// `what` names the endpoint in the malformed-response message only.
json opaque_start(Client::Impl& impl, const char* path, const json& body, const char* what) {
    // send_raw rather than execute(): §23.5 gives 404 a specific, non-error
    // meaning on these endpoints ("this tenant has OPAQUE disabled"), and
    // execute()'s raise_for_status would collapse it into the same NetworkError
    // every other 4xx produces.
    HttpResponse resp = impl.send_raw(impl.build_request("POST", path, body.dump()));
    if (resp.status == 404) {
        // A property of the tenant, not of the user, and not a credential
        // failure — so a caller can fall back to login() without mistaking it
        // for a bad password.
        throw NetworkError(
            "OPAQUE: this tenant does not offer OPAQUE (opaque_mode is disabled); "
            "use login() instead",
            "opaque_disabled");
    }
    if (resp.status < 200 || resp.status >= 300) Client::Impl::raise_for_status(resp);

    json parsed = json::parse(resp.body, nullptr, false);
    if (parsed.is_discarded()) {
        throw NetworkError(std::string("OPAQUE: the ") + what +
                               " response was not the shape §23 defines",
                           "opaque_malformed");
    }
    return parsed;
}

/// Parses a `login/start` body. A field the server omitted stays absent rather
/// than becoming an empty string — `mode` in particular, where "" and "absent"
/// would both read as "not optional" today but only one of them stays correct
/// if a later contract gives the field another value.
OpaqueLoginStart read_login_start(const json& j) {
    OpaqueLoginStart out;
    out.opaque_session = json_str(j, "opaque_session");
    out.ke2 = json_str(j, "ke2");
    out.ksf = read_ksf(j);
    if (!j.is_discarded() && j.contains("mode") && j["mode"].is_string()) {
        out.mode = j["mode"].get<std::string>();
    }
    return out;
}

/// The tenant/org resolution every login-shaped body shares, so the OPAQUE and
/// password paths cannot drift.
void add_scope_fields(const Client::Impl& impl, json& body) {
    if (impl.tenant_slug) body["tenant_slug"] = *impl.tenant_slug;
    if (impl.tenant_id) body["tenant_id"] = *impl.tenant_id;
    if (impl.org_slug) body["org_slug"] = *impl.org_slug;
    if (impl.org_id) body["org_id"] = *impl.org_id;
}

}  // namespace

LoginResult Client::login_opaque(const std::string& username_or_email,
                                 const std::string& password) {
    p_->ensure_open();
    if (p_->memo) p_->memo->clear();  // §17.1 rule 9

    // The exchange's destructor releases the native handle on every path where
    // finish() did not spend it -- a refused KSF, a malformed response, a
    // non-200 start. Without that a misconfigured tenant leaks once per login
    // attempt.
    opaque::LoginExchange exchange = opaque::start_login(password);

    json body;
    body["username_or_email"] = username_or_email;
    // Note what is absent: `password`. Not sending it is the entire point of
    // the exchange, and a field that does not exist cannot be added back by
    // accident.
    body["ke1"] = exchange.ke1();
    add_scope_fields(*p_, body);

    const OpaqueLoginStart started = read_login_start(
        opaque_start(*p_, "/api/v1/auth/opaque/login/start", body, "login/start"));

    if (started.ke2.empty()) {
        throw NetworkError("OPAQUE: login/start returned no `ke2`", "opaque_malformed");
    }

    // §23.4 rule 7. A KE2 that does not open ends the exchange: nothing goes to
    // login/finish, and the exchange's own destructor clears what it holds. What
    // happens next depends on the tenant's mode and ONLY on that.
    std::string ke3;
    bool retry_over_password_login = false;
    try {
        ke3 = exchange.finish(password, started.ke2, started.ksf);
    } catch (const AuthError&) {
        // `optional` is the mid-migration state: every account has no record the
        // moment an operator enables OPAQUE and acquires one only as it next
        // sets a password, so a failed exchange there is the ordinary case and
        // treating it as final would lock out the whole tenant. Anything else —
        // `required`, an unrecognised value, or no `mode` at all from a server
        // older than the field — is final, and retrying would put a plaintext
        // password on the wire for an endpoint that answers 403 to everyone.
        if (!(started.mode && *started.mode == kOpaqueModeOptional)) throw;
        retry_over_password_login = true;
    }
    // Outside the handler, so the fallback does not run with an in-flight
    // exception and its own failure reaches the caller as itself.
    if (retry_over_password_login) {
        // login() rather than a second hand-rolled request: the fallback must be
        // the SAME login, MFA branches, session adoption and error mapping the
        // caller would have got from login() directly.
        return login(username_or_email, password);
    }

    json finish_body;
    finish_body["opaque_session"] = started.opaque_session;
    finish_body["ke3"] = ke3;

    HttpResponse resp = p_->execute("POST", "/api/v1/auth/opaque/login/finish",
                                    finish_body.dump(), /*allow_refresh=*/false);
    auto j = json::parse(resp.body, nullptr, false);

    // Identical adoption to login(): the union is the same, so the session
    // state, the cached user and the MFA branches are too. An application must
    // be able to keep one result handler when a tenant moves to OPAQUE, which
    // it cannot if a branch is missing here.
    LoginResult result;
    if (resp.status == 202 || (!j.is_discarded() && j.value("mfa_required", false))) {
        result.mfa_required = true;
        if (!j.is_discarded()) {
            result.challenge_token =
                Sensitive<std::string>(j.value("challenge_token", std::string{}));
            if (j.contains("available_methods") && j["available_methods"].is_array()) {
                for (const auto& m : j["available_methods"]) {
                    if (m.is_string()) result.available_methods.push_back(m.get<std::string>());
                }
            }
        }
        return result;
    }

    if (!j.is_discarded()) {
        result.session_id = j.value("session_id", "");
        result.expires_in = j.value("expires_in", static_cast<std::int64_t>(0));
        if (j.contains("user") && j["user"].is_object()) result.user = parse_user(j["user"]);
    }
    {
        std::lock_guard<std::mutex> lock(p_->state_mtx);
        p_->session = true;
        if (result.user) p_->resolved_tenant_id = result.user->tenant_id;
        if (auto oid = org_id_from_cookies(resp.set_cookies)) p_->resolved_org_id = *oid;
    }
    return result;
}

OpaqueEnrollment Client::opaque_enrollment(const std::string& password) {
    p_->ensure_open();

    opaque::RegistrationExchange exchange = opaque::start_registration(password);

    json body;
    // This one names no account at all — not even a username. A record binds to
    // a credential identifier the SERVER chooses, which is why a later rename
    // cannot invalidate a credential, and why the SRP enrolment's `identity`
    // argument has no successor.
    body["registration_request"] = exchange.request();
    add_scope_fields(*p_, body);

    const json started =
        opaque_start(*p_, "/api/v1/auth/opaque/register/start", body,
                     "register/start");

    const std::string response = json_str(started, "registration_response");
    if (response.empty()) {
        throw NetworkError("OPAQUE: register/start returned no `registration_response`",
                           "opaque_malformed");
    }

    OpaqueEnrollment out;
    out.registration_record = exchange.finish(password, response, read_ksf(started));
    out.opaque_session = json_str(started, "opaque_session");
    return out;
}

bool Client::opaque_available() const { return opaque::available(); }

LoginResult Client::verify_mfa(const Sensitive<std::string>& challenge_token,
                               const std::string& totp_code) {
    return verify_mfa(detail::reveal(challenge_token), totp_code);
}

LoginResult Client::verify_mfa(const std::string& challenge_token, const std::string& totp_code) {
    p_->ensure_open();
    if (p_->memo) p_->memo->clear();  // §17.1 rule 9
    json body;
    body["challenge_token"] = challenge_token;
    body["totp_code"] = totp_code;
    HttpResponse resp = p_->execute("POST", "/api/v1/auth/mfa/verify", body.dump(), false);
    auto j = json::parse(resp.body, nullptr, false);
    LoginResult result;
    if (!j.is_discarded()) {
        result.session_id = j.value("session_id", "");
        result.expires_in = j.value("expires_in", static_cast<std::int64_t>(0));
        if (j.contains("user") && j["user"].is_object()) result.user = parse_user(j["user"]);
    }
    {
        std::lock_guard<std::mutex> lock(p_->state_mtx);
        p_->session = true;
        if (result.user) p_->resolved_tenant_id = result.user->tenant_id;
        // D-14: the login response body carries tenant_id/org_slug but NOT
        // org_id — recover the org_id UUID from the access-token cookie so
        // refresh() can supply it even when the client was built with a slug.
        if (auto oid = org_id_from_cookies(resp.set_cookies)) p_->resolved_org_id = *oid;
    }
    return result;
}

TokenPair Client::refresh() {
    p_->ensure_open();
    return p_->do_single_flight_refresh();
}

void Client::logout() {
    p_->ensure_open();
    if (p_->memo) p_->memo->clear();  // §17.1 rule 9, before the wire
    try {
        p_->execute("POST", "/api/v1/auth/logout", "{}", false);
    } catch (const AxiamError&) {
        // Logout is best-effort; local state is cleared regardless.
    }
    std::lock_guard<std::mutex> lock(p_->state_mtx);
    p_->session = false;
    p_->csrf.clear();
}

void Client::close() {
    {
        std::lock_guard<std::mutex> lock(p_->state_mtx);
        // §18.1 rule 2: idempotent. The flag is checked and set under the same
        // lock, so two threads racing on close cannot both reach the release
        // below — cleanup runs from error paths, and an error path that
        // double-releases hides the original failure.
        if (p_->closed) return;
        p_->closed = true;
        p_->session = false;
        p_->csrf.clear();
    }
    // NO REQUEST IS ISSUED HERE (§18.1 rule 5). The server-side session
    // deliberately outlives the client object — that is what lets a process
    // restart and resume — so a close() that logged out would silently end every
    // user's session on each deploy.
    if (p_->memo) p_->memo->clear();
    // Dropping the std::function releases the last reference this client holds to
    // the transport, and with it the libcurl handle pool. Cleared under no lock
    // because a transport destructor may block on in-flight handles, and holding
    // state_mtx across that would deadlock any concurrent operation trying to
    // observe `closed`.
    p_->transport = Transport{};
}

AccessDecision Client::check_access(const std::string& action, const std::string& resource_id,
                                    std::optional<std::string> scope,
                                    std::optional<std::string> subject_id) {
    p_->ensure_open();

    // §17: consulted before the wire, written only after a decision the server
    // actually returned.
    std::string key;
    const bool use_memo = p_->memo && p_->memo->enabled();
    if (use_memo) {
        key = detail::DecisionMemo::key(subject_id, resource_id, action, scope);
        if (auto cached = p_->memo->get(key)) return *cached;
    }

    json body;
    body["action"] = action;
    body["resource_id"] = resource_id;
    if (scope) body["scope"] = *scope;
    if (subject_id) body["subject_id"] = *subject_id;
    HttpResponse resp = p_->execute_retrying("check_access", "/api/v1/authz/check", body.dump());
    auto j = json::parse(resp.body, nullptr, false);
    if (j.is_discarded()) return AccessDecision{};
    AccessDecision decision = parse_decision(j);

    // §17.1 rule 7: only a decision the server actually returned — a thrown
    // NetworkError never reaches here. Rule 4: allows and denies are stored
    // identically, because asymmetric caching changes the timing of the two
    // outcomes and so leaks which one occurred to anyone who can observe latency.
    if (use_memo) p_->memo->put(key, decision);
    return decision;
}

AccessDecision Client::can(const std::string& action, const std::string& resource_id,
                           std::optional<std::string> scope, std::optional<std::string> subject_id) {
    return check_access(action, resource_id, std::move(scope), std::move(subject_id));
}

std::vector<AccessDecision> Client::batch_check(const std::vector<AccessCheck>& checks) {
    p_->ensure_open();
    json body;
    json arr = json::array();
    for (const auto& c : checks) {
        json item;
        item["action"] = c.action;
        item["resource_id"] = c.resource_id;
        if (c.scope) item["scope"] = *c.scope;
        if (c.subject_id) item["subject_id"] = *c.subject_id;
        arr.push_back(item);
    }
    body["checks"] = arr;
    // Deliberately not memoized: the §17 key is per-check, so a batch would have
    // to be split into n entries with n keys — the right design, but it changes
    // what a partial hit means (some rows from the wire, some from the memo, one
    // composite result). §17 says nothing about batch, so this SDK does the
    // conservative thing rather than inventing semantics.
    HttpResponse resp =
        p_->execute_retrying("batch_check", "/api/v1/authz/check/batch", body.dump());
    std::vector<AccessDecision> out;
    auto j = json::parse(resp.body, nullptr, false);
    if (!j.is_discarded() && j.contains("results") && j["results"].is_array()) {
        for (const auto& r : j["results"]) out.push_back(parse_decision(r));
    }
    return out;
}

DeviceAuth Client::authenticate_device() {
    p_->ensure_open();
    HttpResponse resp = p_->execute("POST", "/api/v1/auth/device", "{}", false);
    auto j = json::parse(resp.body, nullptr, false);
    DeviceAuth da;
    if (!j.is_discarded()) {
        da.access_token = Sensitive<std::string>(j.value("access_token", ""));
        da.token_type = j.value("token_type", "");
        da.expires_in = j.value("expires_in", static_cast<std::int64_t>(0));
    }
    {
        std::lock_guard<std::mutex> lock(p_->state_mtx);
        p_->session = true;
    }
    return da;
}

std::future<LoginResult> Client::login_async(std::string username_or_email, std::string password) {
    auto self = p_;
    return std::async(std::launch::async, [self, username_or_email, password] {
        Client c(self);
        return c.login(username_or_email, password);
    });
}

std::future<TokenPair> Client::refresh_async() {
    auto self = p_;
    return std::async(std::launch::async, [self] { return self->do_single_flight_refresh(); });
}

std::future<AccessDecision> Client::check_access_async(std::string action, std::string resource_id,
                                                       std::optional<std::string> scope,
                                                       std::optional<std::string> subject_id) {
    auto self = p_;
    return std::async(std::launch::async, [self, action, resource_id, scope, subject_id] {
        Client c(self);
        return c.check_access(action, resource_id, scope, subject_id);
    });
}

std::future<std::vector<AccessDecision>> Client::batch_check_async(std::vector<AccessCheck> checks) {
    auto self = p_;
    return std::async(std::launch::async, [self, checks] {
        Client c(self);
        return c.batch_check(checks);
    });
}

void Client::_set_retry_test_seams(std::function<double()> jitter,
                                   std::function<void(std::chrono::milliseconds)> sleeper) {
    p_->jitter = std::move(jitter);
    p_->sleeper = std::move(sleeper);
}

int Client::refresh_call_count() const { return p_->refresh_count.load(); }

std::optional<std::string> Client::csrf_token() const {
    std::lock_guard<std::mutex> lock(p_->state_mtx);
    if (p_->csrf.empty()) return std::nullopt;
    return p_->csrf;
}

bool Client::has_session() const {
    std::lock_guard<std::mutex> lock(p_->state_mtx);
    return p_->session;
}

JwksVerifier& Client::jwks() { return *p_->jwks_verifier; }

const std::string& Client::tenant_header() const { return p_->tenant_header; }

// ---------------------------------------------------------------------------
// §20 UMA 2.0 — Protection API and ticket grant
// ---------------------------------------------------------------------------
//
// The one rule worth repeating where the code lives: uma_exchange_ticket()
// issues EXACTLY ONE request, on every outcome. It does not enter
// execute_retrying()'s budget, and it must not be made to.

namespace {

/// Percent-encode a string for a URL path segment or a form value.
std::string percent_encode(const std::string& in) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size());
    for (unsigned char ch : in) {
        const bool unreserved = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                                (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' ||
                                ch == '_' || ch == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(ch));
        } else {
            out.push_back('%');
            out.push_back(kHex[ch >> 4]);
            out.push_back(kHex[ch & 0xF]);
        }
    }
    return out;
}

std::string trim(const std::string& s) {
    const auto first = s.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    const auto last = s.find_last_not_of(" \t");
    return s.substr(first, last - first + 1);
}

/// Strip one layer of surrounding double quotes, if present.
std::string unquote(std::string s) {
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        return s.substr(1, s.size() - 2);
    }
    return s;
}

json parse_or_object(const std::string& body) {
    auto j = json::parse(body, nullptr, false);
    return j.is_discarded() ? json::object() : j;
}

/// The string members of a JSON array, in order.
///
/// A non-string member is dropped rather than fataling the call: neither a scope
/// list nor an id list is a credential, and a server that grows a richer member
/// should not take an otherwise-usable response down with it.
std::vector<std::string> string_array(const json& j) {
    std::vector<std::string> out;
    if (!j.is_array()) return out;
    for (const auto& item : j) {
        if (item.is_string()) out.push_back(item.get<std::string>());
    }
    return out;
}

UmaResourceSet resource_set_from_wire(const json& j) {
    if (!j.contains("name") || !j["name"].is_string()) {
        throw NetworkError("uma: malformed ResourceSet (missing name)", "malformed_body");
    }
    UmaResourceSet rs;
    rs.name = j["name"].get<std::string>();
    if (j.contains("_id") && j["_id"].is_string() && !j["_id"].get<std::string>().empty()) {
        rs.id = j["_id"].get<std::string>();
    }
    if (j.contains("type") && j["type"].is_string() && !j["type"].get<std::string>().empty()) {
        rs.type = j["type"].get<std::string>();
    }
    if (j.contains("resource_scopes")) rs.resource_scopes = string_array(j["resource_scopes"]);
    return rs;
}

/// §12.1's absent-optional rule: `type` is omitted rather than sent empty, so
/// the server applies its own `uma_resource` default. `resource_scopes` is
/// always present, because it is the complete new list (§20.2 rule 8) and an
/// absent one would read as "no change".
json resource_set_to_wire(const std::string& name, const std::optional<std::string>& type,
                          const std::vector<std::string>& scopes) {
    json body;
    body["name"] = name;
    if (type && !type->empty()) body["type"] = *type;
    body["resource_scopes"] = scopes;
    return body;
}

/// Looks like a UUID: 8-4-4-4-12 hex. A tenant SLUG is not one, and §12.3
/// rule 4 forbids substituting it.
bool looks_like_uuid(const std::string& s) {
    static const int kGroups[] = {8, 4, 4, 4, 12};
    std::size_t at = 0;
    for (int g = 0; g < 5; ++g) {
        for (int i = 0; i < kGroups[g]; ++i) {
            if (at >= s.size()) return false;
            const char ch = s[at++];
            const bool hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                             (ch >= 'A' && ch <= 'F');
            if (!hex) return false;
        }
        if (g < 4) {
            if (at >= s.size() || s[at++] != '-') return false;
        }
    }
    return at == s.size();
}

}  // namespace

UmaConfiguration Client::uma_discover() {
    p_->ensure_open();
    {
        std::lock_guard<std::mutex> lock(p_->state_mtx);
        if (p_->uma_config &&
            std::chrono::steady_clock::now() < p_->uma_config_expires_at) {
            return *p_->uma_config;
        }
    }

    HttpRequest req = p_->build_request("GET", "/.well-known/uma2-configuration", "");
    HttpResponse resp = p_->send_raw(req);
    if (resp.status < 200 || resp.status >= 300) Client::Impl::raise_for_status(resp);

    const json j = parse_or_object(resp.body);
    if (!j.contains("token_endpoint") || !j["token_endpoint"].is_string() ||
        !j.contains("permission_endpoint") || !j["permission_endpoint"].is_string() ||
        !j.contains("resource_registration_endpoint") ||
        !j["resource_registration_endpoint"].is_string()) {
        // A document missing an endpoint is not "mostly usable": the operation
        // that needed the missing one would otherwise build a request against
        // nothing.
        throw NetworkError(
            "uma discovery: missing token/permission/resource_registration endpoint",
            "malformed_body");
    }

    UmaConfiguration cfg;
    cfg.issuer = j.value("issuer", std::string{});
    cfg.token_endpoint = j["token_endpoint"].get<std::string>();
    cfg.permission_endpoint = j["permission_endpoint"].get<std::string>();
    cfg.resource_registration_endpoint = j["resource_registration_endpoint"].get<std::string>();
    if (j.contains("permission_ticket_lifetime") && j["permission_ticket_lifetime"].is_number()) {
        cfg.permission_ticket_lifetime = j["permission_ticket_lifetime"].get<long>();
    }

    {
        std::lock_guard<std::mutex> lock(p_->state_mtx);
        p_->uma_config = cfg;
        p_->uma_config_expires_at = std::chrono::steady_clock::now() + std::chrono::minutes(5);
    }
    return cfg;
}

UmaResourceSet Client::uma_register_resource(const Sensitive<std::string>& pat,
                                             const std::string& name,
                                             std::optional<std::string> type,
                                             std::vector<std::string> resource_scopes) {
    const UmaConfiguration cfg = uma_discover();
    HttpResponse resp = p_->uma_protection_request(
        "POST", cfg.resource_registration_endpoint, pat,
        resource_set_to_wire(name, type, resource_scopes).dump());
    return resource_set_from_wire(parse_or_object(resp.body));
}

UmaResourceSet Client::uma_read_resource(const Sensitive<std::string>& pat,
                                         const std::string& id) {
    const UmaConfiguration cfg = uma_discover();
    HttpResponse resp = p_->uma_protection_request(
        "GET", cfg.resource_registration_endpoint + "/" + percent_encode(id), pat, "");
    return resource_set_from_wire(parse_or_object(resp.body));
}

UmaResourceSet Client::uma_update_resource(const Sensitive<std::string>& pat,
                                           const std::string& id, const std::string& name,
                                           std::optional<std::string> type,
                                           std::vector<std::string> resource_scopes) {
    const UmaConfiguration cfg = uma_discover();
    // §20.2 rule 8: exactly the scopes given, with no read first.
    HttpResponse resp = p_->uma_protection_request(
        "PUT", cfg.resource_registration_endpoint + "/" + percent_encode(id), pat,
        resource_set_to_wire(name, type, resource_scopes).dump());
    return resource_set_from_wire(parse_or_object(resp.body));
}

void Client::uma_delete_resource(const Sensitive<std::string>& pat, const std::string& id) {
    const UmaConfiguration cfg = uma_discover();
    p_->uma_protection_request("DELETE",
                               cfg.resource_registration_endpoint + "/" + percent_encode(id),
                               pat, "");
}

std::vector<std::string> Client::uma_list_resources(const Sensitive<std::string>& pat) {
    const UmaConfiguration cfg = uma_discover();
    HttpResponse resp =
        p_->uma_protection_request("GET", cfg.resource_registration_endpoint, pat, "");
    const json j = parse_or_object(resp.body);
    if (!j.is_array()) {
        throw NetworkError("uma list resources: body is not a JSON array", "malformed_body");
    }
    return string_array(j);
}

Sensitive<std::string> Client::uma_request_ticket(
    const Sensitive<std::string>& pat,
    const std::vector<UmaRequestedPermission>& permissions) {
    const UmaConfiguration cfg = uma_discover();

    json body = json::array();
    for (const auto& permission : permissions) {
        json entry;
        entry["resource_id"] = permission.resource_id;
        entry["resource_scopes"] = permission.resource_scopes;
        body.push_back(std::move(entry));
    }

    HttpResponse resp =
        p_->uma_protection_request("POST", cfg.permission_endpoint, pat, body.dump());
    const json j = parse_or_object(resp.body);
    if (!j.contains("ticket") || !j["ticket"].is_string() ||
        j["ticket"].get<std::string>().empty()) {
        throw NetworkError("uma request ticket: malformed PermissionTicketResponse",
                           "malformed_body");
    }
    // §20.6: wrapped on the way out. For its 60-second life the ticket IS the
    // credential that converts into an RPT.
    return Sensitive<std::string>(j["ticket"].get<std::string>());
}

RequestingPartyToken Client::uma_exchange_ticket(const UmaExchangeTicketParams& params) {
    p_->ensure_open();

    // Everything that can be refused client-side is refused BEFORE the wire
    // call, so a request that could not have succeeded never spends a ticket
    // (§20.2 rules 2 and 6 together).
    if (detail::reveal(params.ticket).empty()) {
        throw AuthError("the UMA ticket grant requires a ticket (CONTRACT.md §20.1)");
    }
    if (detail::reveal(params.claim_token).empty()) {
        throw AuthError(
            "the UMA ticket grant requires a claim_token naming the requesting party; it is "
            "never defaulted (CONTRACT.md §20.2 rule 2)");
    }
    if (params.credentials.client_id.empty() ||
        detail::reveal(params.credentials.client_secret).empty()) {
        throw AuthError(
            "the UMA ticket grant is a token-endpoint grant and requires confidential-client "
            "credentials (CONTRACT.md §20.1)");
    }

    std::string tenant = params.tenant_id ? *params.tenant_id
                                          : p_->tenant_id.value_or(std::string{});
    if (!looks_like_uuid(tenant)) {
        throw AuthError(
            "the UMA ticket grant requires a tenant_id UUID for the /oauth2 query parameter; a "
            "tenant slug cannot be substituted (CONTRACT.md §12.3 rule 4)");
    }

    const UmaConfiguration cfg = uma_discover();

    // §12.1 note 2, which §20.1 applies to this grant unchanged. Existing query
    // parameters on the discovered endpoint are preserved.
    std::string url = cfg.token_endpoint;
    url += (url.find('?') == std::string::npos) ? '?' : '&';
    url += "tenant_id=" + percent_encode(tenant);

    std::string form;
    const std::pair<const char*, std::string> fields[] = {
        {"grant_type", kUmaTicketGrantType},
        {"ticket", detail::reveal(params.ticket)},
        {"claim_token", detail::reveal(params.claim_token)},
        {"claim_token_format", kUmaClaimTokenFormat},
        {"client_id", params.credentials.client_id},
        {"client_secret", detail::reveal(params.credentials.client_secret)},
    };
    for (const auto& [key, value] : fields) {
        if (!form.empty()) form.push_back('&');
        form += key;
        form.push_back('=');
        form += percent_encode(value);
    }

    // ONE REQUEST. No retry wrapper, on any outcome — see the rule 6 note on the
    // declaration. The client authenticates through the form body, so no
    // Authorization header goes with it, and no session cookie either: a second,
    // unasked-for identity on the same request is not a convenience.
    HttpRequest req;
    req.method = "POST";
    req.url = url;
    req.headers["X-Tenant-ID"] = p_->tenant_header;
    req.headers["Accept"] = "application/json";
    req.headers["Content-Type"] = "application/x-www-form-urlencoded";
    req.body = form;

    HttpResponse resp = p_->send_raw(req);
    if (resp.status < 200 || resp.status >= 300) {
        // §20.4: dispatch on the `error` field at ANY status before the §2
        // status mapping. access_denied answers 403 here where RFC 8628's is a
        // 400, and the field is what stays correct if either moves.
        const json j = parse_or_object(resp.body);
        if (j.contains("error") && j["error"].is_string() &&
            !j["error"].get<std::string>().empty()) {
            const auto code = j["error"].get<std::string>();
            std::optional<std::string> description;
            if (j.contains("error_description") && j["error_description"].is_string()) {
                description = j["error_description"].get<std::string>();
            }
            // The message carries the CODE, never the server's free text: a
            // failed exchange is exactly when a description echoing the ticket
            // would land in a caller's log.
            throw OAuthProtocolError("uma ticket exchange refused: " + code, code,
                                     std::move(description));
        }
        // Not an OAuth2ErrorResponse — a proxy's HTML 502, say. The ordinary §2
        // mapping still applies rather than a protocol error with no code.
        Client::Impl::raise_for_status(resp);
    }

    const json j = parse_or_object(resp.body);
    if (!j.contains("access_token") || !j["access_token"].is_string() ||
        j["access_token"].get<std::string>().empty()) {
        throw NetworkError("uma ticket exchange: malformed TokenResponse (missing access_token)",
                           "malformed_body");
    }
    RequestingPartyToken rpt;
    rpt.access_token = Sensitive<std::string>(j["access_token"].get<std::string>());
    rpt.token_type = j.value("token_type", std::string("Bearer"));
    rpt.expires_in = j.value("expires_in", 0L);
    // §20.2 rule 5: any refresh_token the server sent is ignored — there is no
    // member for it, and synthesising one would let an RPT outlive its ticket.
    return rpt;
}

// ---- §20.3 the challenge helpers ----

std::optional<UmaChallenge> uma_parse_challenge(const std::string& header) {
    const std::string trimmed = trim(header);
    if (trimmed.rfind("UMA", 0) != 0) return std::nullopt;
    const std::string rest = trimmed.substr(3);
    // "UMA" alone is a valid, if useless, challenge; anything else must be
    // separated by whitespace so `UMAX realm="…"` is not read as UMA.
    if (!rest.empty() && rest.front() != ' ' && rest.front() != '\t') return std::nullopt;

    UmaChallenge challenge;
    std::size_t at = 0;
    while (at <= rest.size()) {
        const std::size_t comma = rest.find(',', at);
        const std::string part =
            rest.substr(at, comma == std::string::npos ? std::string::npos : comma - at);
        const std::size_t equals = part.find('=');
        if (equals != std::string::npos) {
            const std::string key = trim(part.substr(0, equals));
            const std::string value = unquote(trim(part.substr(equals + 1)));
            if (key == "realm") {
                challenge.realm = value;
            } else if (key == "as_uri") {
                challenge.as_uri = value;
            } else if (key == "ticket") {
                challenge.ticket = Sensitive<std::string>(value);
            }
            // Unknown parameters are ignored rather than rejected: UMA 2.0
            // permits a server to add its own, and refusing the whole challenge
            // over one would lose the ticket with it.
        }
        if (comma == std::string::npos) break;
        at = comma + 1;
    }
    return challenge;
}

std::string uma_challenge_header(const std::string& realm, const std::string& as_uri,
                                 const Sensitive<std::string>& ticket) {
    return "UMA realm=\"" + realm + "\", as_uri=\"" + as_uri + "\", ticket=\"" +
           detail::reveal(ticket) + "\"";
}

}  // namespace axiam
