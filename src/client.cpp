#include "axiam/client.hpp"

#include <atomic>
#include <functional>
#include <mutex>
#include <random>
#include <thread>

#include <nlohmann/json.hpp>

#include "axiam/http_curl.hpp"
#include "axiam/jwks.hpp"
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

struct Client::Impl {
    Transport transport;
    std::string base_url;
    std::string tenant_header;  // value for X-Tenant-ID (slug or id)

    std::optional<std::string> tenant_slug;
    std::optional<std::string> tenant_id;
    std::optional<std::string> org_slug;
    std::optional<std::string> org_id;

    // Session state (§3 CSRF, session flag).
    std::mutex state_mtx;
    std::string csrf;
    bool session = false;
    std::optional<std::string> resolved_tenant_id;  // captured from login user info
    std::optional<std::string> resolved_org_id;     // decoded from the access-token org_id claim (D-14)

    // §9 single-flight refresh. The guard owns all of the coalescing state and
    // its invariants (see src/refresh_guard.hpp); this class only supplies the
    // wire call.
    detail::RefreshGuard refresh_guard;
    std::atomic<int> refresh_count{0};

    std::unique_ptr<JwksVerifier> jwks_verifier;

    // §16. The seams are internal on purpose: §16.1 forbids raising the table,
    // and a public knob for the jitter source or the sleep would be an
    // attractive nuisance. Tests reach them through src/ being on the include
    // path, the same way test_refresh_guard.cpp reaches the §9 guard.
    bool retry_enabled = true;
    std::function<double()> jitter = [] {
        // Not cryptographic; §16.1 says the source need not be — the jitter is a
        // load-spreading device, not a secret. thread_local so concurrent callers
        // do not serialise on one generator or share a sequence.
        static thread_local std::mt19937 gen{std::random_device{}()};
        static thread_local std::uniform_real_distribution<double> dist(0.0, 1.0);
        return dist(gen);
    };
    std::function<void(std::chrono::milliseconds)> sleeper = [](std::chrono::milliseconds d) {
        if (d > std::chrono::milliseconds{0}) std::this_thread::sleep_for(d);
    };

    // §17. Constructed by build(); disabled unless a TTL was configured.
    std::unique_ptr<detail::DecisionMemo> memo;

    // §19.
    TelemetryHook telemetry;

    // §18 shutdown flag, guarded by state_mtx and read on every operation.
    bool closed = false;

    /// §19.2 rule 2: a hook that throws cannot fail the operation that fired it.
    /// Telemetry is not permitted to fail an authorization check, and letting a
    /// broken sink unwind here would turn a metrics problem into one.
    void emit(const TelemetryEvent& ev) const {
        if (!telemetry) return;
        try {
            telemetry(ev);
        } catch (...) {
            // Deliberately swallowed; see above.
        }
    }

    /// §18.1 rule 4: use after close is an error, not undefined.
    void ensure_open() {
        std::lock_guard<std::mutex> lock(state_mtx);
        if (closed) {
            throw NetworkError("client is closed (CONTRACT.md \u00a718.1 rule 4)", "closed");
        }
    }

    static bool is_state_changing(const std::string& method) {
        return method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE";
    }

    HttpRequest build_request(const std::string& method, const std::string& path,
                              const std::string& body) {
        HttpRequest req;
        req.method = method;
        req.url = base_url + path;
        req.headers["X-Tenant-ID"] = tenant_header;  // §5: every request
        req.headers["Accept"] = "application/json";
        if (!body.empty()) req.headers["Content-Type"] = "application/json";
        req.body = body;
        // §3: echo captured CSRF token on state-changing requests.
        if (is_state_changing(method)) {
            std::lock_guard<std::mutex> lock(state_mtx);
            if (!csrf.empty()) req.headers["X-CSRF-Token"] = csrf;
        }
        return req;
    }

    void capture_csrf(const HttpResponse& resp) {
        auto it = resp.headers.find("X-CSRF-Token");
        if (it != resp.headers.end() && !it->second.empty()) {
            std::lock_guard<std::mutex> lock(state_mtx);
            csrf = it->second;
        }
    }

    // Low-level send: performs the exchange, captures CSRF, and translates
    // transport failures. Does NOT map HTTP status codes or trigger refresh.
    HttpResponse send_raw(const HttpRequest& req) {
        HttpResponse resp = transport(req);
        if (!resp.transport_error.empty()) {
            throw NetworkError("transport failure: " + resp.transport_error,
                               resp.transport_error);
        }
        capture_csrf(resp);
        return resp;
    }

    [[noreturn]] static void raise_for_status(const HttpResponse& resp) {
        // Try to extract structured detail for authz errors.
        auto parse = [&]() -> json {
            auto j = json::parse(resp.body, nullptr, false);
            return j.is_discarded() ? json::object() : j;
        };
        const long s = resp.status;
        if (s == 401) {
            throw AuthError("authentication failed (401)");
        } else if (s == 403 || s == 409) {
            json j = parse();
            std::optional<std::string> action;
            std::optional<std::string> resource;
            std::string msg = j.value("message", std::string("authorization denied"));
            if (j.contains("action") && j["action"].is_string()) action = j["action"].get<std::string>();
            if (j.contains("resource_id") && j["resource_id"].is_string())
                resource = j["resource_id"].get<std::string>();
            throw AuthzError(msg + " (" + std::to_string(s) + ")", action, resource);
        } else if (s == 400) {
            throw NetworkError("malformed request (400)", "http_400");
        } else if (s == 408 || s == 429) {
            throw NetworkError("timeout / rate limited (" + std::to_string(s) + ")",
                               "http_" + std::to_string(s));
        } else if (s >= 500) {
            throw NetworkError("server error (" + std::to_string(s) + ")",
                               "http_" + std::to_string(s));
        }
        throw NetworkError("unexpected HTTP status (" + std::to_string(s) + ")",
                           "http_" + std::to_string(s));
    }

    // One §16-eligible operation: the bounded retry budget plus the §19 pairs
    // around it.
    //
    // §16.2: eligibility is "changes no server state", NOT "is a GET". The
    // authorization check is a POST with a body and is the single most important
    // operation in that section — an SDK that gated retry on the HTTP verb would
    // retry nothing that matters. This method is reached only from the authz
    // paths; login, verify_mfa, logout, refresh and authenticate_device call
    // execute() directly and make exactly one attempt.
    //
    // One RequestStart/RequestEnd pair PER ATTEMPT (§19.2 rule 5), with a Retry
    // between consecutive pairs: a caller must be able to count real wire calls
    // from the events, which one pair per logical operation would hide.
    HttpResponse execute_retrying(const std::string& op, const std::string& path,
                                  const std::string& body) {
        const int budget = retry_enabled ? detail::kRetryMaxAttempts : 1;

        for (int attempt = 1;; ++attempt) {
            emit(RequestStartEvent{op, "POST", path, attempt});
            const auto started = std::chrono::steady_clock::now();

            std::optional<long> status;
            std::optional<HttpResponse> resp;
            std::exception_ptr thrown;
            try {
                resp = send_raw(build_request("POST", path, body));
                status = resp->status;
            } catch (const NetworkError&) {
                // No HTTP response arrived at all, so the request may never have
                // been seen. Held rather than rethrown so the pair still closes.
                thrown = std::current_exception();
            }

            const bool ok = status && *status >= 200 && *status < 300;
            emit(RequestEndEvent{op, "POST", path, attempt, status,
                                 std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::steady_clock::now() - started),
                                 ok ? Outcome::kSuccess : Outcome::kFailure});

            if (attempt < budget && detail::retry_should_retry(status)) {
                std::optional<std::chrono::milliseconds> hint;
                if (resp) {
                    auto it = resp->headers.find("Retry-After");
                    if (it != resp->headers.end()) {
                        hint = detail::retry_after_from_header(it->second);
                    }
                }
                const auto wait = detail::retry_delay(attempt, hint, jitter());
                // §16.5: a retried-then-succeeded operation is otherwise
                // invisible. The reason carries a status or a transport
                // category, never a token.
                emit(RetryEvent{op, attempt, wait,
                                status ? "HTTP " + std::to_string(*status)
                                       : std::string("transport failure")});
                sleeper(wait);
                continue;
            }

            if (thrown) std::rethrow_exception(thrown);
            if (resp->status >= 200 && resp->status < 300) return *resp;

            // The §9 refresh-then-retry-once path. §16.2: the two mechanisms
            // compose in one direction only — the §16 budget is NOT reset by a §9
            // refresh occurring mid-operation, so the post-refresh call below is
            // exactly one attempt.
            if (resp->status == 401) {
                bool have_session;
                {
                    std::lock_guard<std::mutex> lock(state_mtx);
                    have_session = session;
                }
                if (have_session) {
                    do_single_flight_refresh();  // throws AuthError on failure
                    emit(RequestStartEvent{op, "POST", path, attempt + 1});
                    const auto retry_started = std::chrono::steady_clock::now();
                    HttpResponse retried = send_raw(build_request("POST", path, body));
                    const bool retried_ok = retried.status >= 200 && retried.status < 300;
                    emit(RequestEndEvent{op, "POST", path, attempt + 1, retried.status,
                                         std::chrono::duration_cast<std::chrono::milliseconds>(
                                             std::chrono::steady_clock::now() - retry_started),
                                         retried_ok ? Outcome::kSuccess : Outcome::kFailure});
                    if (retried_ok) return retried;
                    raise_for_status(retried);
                }
            }
            raise_for_status(*resp);
        }
    }

    // Execute a request with §2 status mapping and §9 refresh-on-401.
    HttpResponse execute(const std::string& method, const std::string& path,
                         const std::string& body, bool allow_refresh) {
        HttpResponse resp = send_raw(build_request(method, path, body));
        if (resp.status >= 200 && resp.status < 300) return resp;

        if (resp.status == 401 && allow_refresh) {
            bool have_session;
            {
                std::lock_guard<std::mutex> lock(state_mtx);
                have_session = session;
            }
            if (have_session) {
                try {
                    do_single_flight_refresh();  // throws AuthError on failure
                } catch (const AuthError&) {
                    throw;  // §9.3: no retry loop; surface AuthError
                }
                // Retry exactly once with a freshly-built request (current CSRF).
                HttpResponse retry = send_raw(build_request(method, path, body));
                if (retry.status >= 200 && retry.status < 300) return retry;
                raise_for_status(retry);
            }
        }
        raise_for_status(resp);
    }

    // §9: exactly one in-flight refresh; concurrent callers share its outcome.
    // The owner runs perform_refresh() on its own thread with no lock held;
    // waiters block on the shared future. See src/refresh_guard.hpp for the
    // ownership/publication-ordering invariants.
    TokenPair do_single_flight_refresh() {
        const auto started = std::chrono::steady_clock::now();
        const int before = refresh_count.load();
        TokenPair tp = refresh_guard.run([this] { return perform_refresh(); });
        // §17.1 rule 9: a refresh is a credential change.
        if (memo) memo->clear();
        // §19.1 refresh. The role is the whole value of the event: a follower's
        // latency is the leader's, so without it a §9 coalescing problem looks
        // like a slow server. This caller led iff the wire count moved while it
        // was inside the guard.
        emit(RefreshEvent{refresh_count.load() > before ? RefreshRole::kLeader
                                                        : RefreshRole::kFollower,
                          std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::steady_clock::now() - started)});
        return tp;
    }

    // The actual refresh network call (invoked at most once per single-flight).
    TokenPair perform_refresh() {
        refresh_count.fetch_add(1);
        json body;
        {
            std::lock_guard<std::mutex> lock(state_mtx);
            body["tenant_id"] = resolved_tenant_id.value_or(tenant_id.value_or(""));
            // Prefer the org_id decoded from the access token (§5, D-14) so a
            // slug-only-configured client still sends a valid UUID; fall back
            // to a UUID-form construction option.
            body["org_id"] = resolved_org_id.value_or(org_id.value_or(""));
        }
        HttpResponse resp = send_raw(build_request("POST", "/api/v1/auth/refresh", body.dump()));
        if (resp.status < 200 || resp.status >= 300) {
            // §2 / §9.3: a failed refresh is an AuthError; the user must re-auth.
            throw AuthError("token refresh failed (" + std::to_string(resp.status) + ")");
        }
        TokenPair tp;
        auto j = json::parse(resp.body, nullptr, false);
        if (!j.is_discarded() && j.contains("expires_in") && j["expires_in"].is_number()) {
            tp.expires_in = j["expires_in"].get<std::int64_t>();
        }
        return tp;
    }
};

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

    HttpResponse resp = p_->execute("POST", "/api/v1/auth/login", body.dump(), /*allow_refresh=*/false);
    auto j = json::parse(resp.body, nullptr, false);

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
        // D-14: the login response body carries tenant_id/org_slug but NOT
        // org_id — recover the org_id UUID from the access-token cookie so
        // refresh() can supply it even when the client was built with a slug.
        if (auto oid = org_id_from_cookies(resp.set_cookies)) p_->resolved_org_id = *oid;
    }
    return result;
}

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

}  // namespace axiam
