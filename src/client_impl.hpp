// axiam::Client::Impl — the shared private state behind every Client method.
//
// EXTRACTED FROM client.cpp, unchanged, so that src/oidc.cpp can reach it. The
// §12 / §12.7 / §14 / §15 port needs the same transport, tenant header, base
// URL, §16 seams and §18 close flag every other operation uses, and the
// alternative — a second copy of the request plumbing living beside the first —
// is exactly the "second, parallel stack" the §12.6 deferral warned about. One
// Impl, one set of §5/§6/§16 guarantees.
//
// NOT INSTALLED. This header is internal to src/.
#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <condition_variable>
#include <exception>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/jwks.hpp"
#include "axiam/oidc.hpp"
#include "axiam/transport.hpp"
#include "axiam/uma.hpp"
#include "decision_memo.hpp"
#include "refresh_guard.hpp"
#include "retry.hpp"

namespace axiam {

namespace detail {
/// Builds a `UserInfo` from a login response's `user` object.
///
/// Shared rather than duplicated because §5.2.2's "absent means EQUAL" fallback lives
/// inside it, and mfa_setup_confirm is the completion of a login (§25.2 rule 2) — a
/// second hand-rolled reader there is a second place for that rule to be forgotten.
UserInfo parse_user(const nlohmann::json& u);
}  // namespace detail

using json = nlohmann::json;

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

    // CONTRACT.md §5.2.2 — the tenant the signed-in principal's record LIVES in, as
    // reported by the login response. Distinct from `tenant_id`/`tenant_slug`, which
    // name the tenant being ACTED ON: the two diverge for an organization-level
    // principal that has selected another one. Read by
    // Client::opaque_enrollment_for_self(), which must seal a §23 record against the
    // account's own tenant rather than whichever one this client is pointed at.
    // Disengaged until a login completes. Guarded by state_mtx.
    std::optional<std::string> principal_tenant_id;

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

    // §12 relying-party identity. `client_id` is not a per-call argument
    // (§12.1): §12.4 rule 4 compares an ID token's `aud` against the SAME value,
    // and two sources could disagree.
    std::optional<std::string> oidc_client_id;
    std::optional<Sensitive<std::string>> oidc_client_secret;
    // §12.3 rule 6 / §12.4 rule 5, AFTER clamping.
    std::chrono::seconds oidc_discovery_ttl{kOidcDiscoveryTtlFloorSeconds};
    std::chrono::seconds oidc_clock_skew{kOidcMaxClockSkewSeconds};

    // §12 discovery cache. Per-client-instance, which satisfies §12.3 rule 6's
    // origin rule by construction (a client is bound to one base URL for its
    // lifetime) and is NOT keyed on the tenant, because the document carries no
    // tenant-specific content. oidc_config_mtx is held across the FETCH as well
    // as the read: that is the single-flight rule 6 requires, in its simplest
    // correct form — a second caller blocks, then finds the cache warm.
    std::mutex oidc_config_mtx;
    std::optional<OidcConfiguration> oidc_config;
    std::chrono::steady_clock::time_point oidc_config_expires_at{};

    // §12.1 / §9 rule 2 single-flight for oidc_refresh, keyed on the refresh
    // token's digest. AXIAM rotates refresh tokens, so two threads racing on one
    // would spend it twice and the loser would see an invalid_grant for a token
    // that was good a millisecond earlier. Keyed on the DIGEST so the registry
    // never holds a second copy of a live credential.
    struct OidcRefreshFlight {
        bool done = false;
        std::optional<OidcTokenSet> result;
        std::exception_ptr error;
    };
    std::mutex oidc_refresh_mtx;
    std::condition_variable oidc_refresh_cv;
    std::map<std::string, std::shared_ptr<OidcRefreshFlight>> oidc_refresh_flights;
    std::atomic<int> oidc_refresh_count{0};

    // §20 UMA discovery cache, guarded by state_mtx. An endpoint map is not a
    // credential, and re-fetching it on every guarded request is a
    // self-inflicted round trip.
    std::optional<UmaConfiguration> uma_config;
    std::chrono::steady_clock::time_point uma_config_expires_at{};

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

    /// One §20 Protection API call, PAT-authenticated (§20.2 rule 1).
    ///
    /// The PAT is an explicit Authorization header on a request built against an
    /// ABSOLUTE url — an endpoint read from the UMA discovery document rather
    /// than joined onto the base URL. A minted ticket is bound to the client_id
    /// that minted it, so the credential here must be the caller's PAT; an empty
    /// one is refused rather than becoming a request with no credential.
    ///
    /// Deliberately not routed through execute_retrying(): nothing here is a
    /// §16-eligible read, and the ticket grant next door must issue exactly one
    /// request.
    HttpResponse uma_protection_request(const std::string& method, const std::string& url,
                                        const Sensitive<std::string>& pat,
                                        const std::string& body) {
        ensure_open();
        if (detail::reveal(pat).empty()) {
            throw AuthError(
                "the UMA Protection API requires a PAT — a client-credentials token carrying "
                "the uma_protection scope; this SDK does not fall back to its own session "
                "(CONTRACT.md §20.2 rule 1)");
        }

        HttpRequest req;
        req.method = method;
        req.url = url;
        req.headers["X-Tenant-ID"] = tenant_header;  // §5
        req.headers["Accept"] = "application/json";
        req.headers["Authorization"] = "Bearer " + detail::reveal(pat);
        if (!body.empty()) {
            req.headers["Content-Type"] = "application/json";
            req.body = body;
        }

        HttpResponse resp = send_raw(req);
        if (resp.status < 200 || resp.status >= 300) {
            // §20.4 maps the Protection API by status (401 / 403 / 400), not
            // through the OAuth2 `error` rows — those belong to the token
            // endpoint.
            raise_for_status(resp);
        }
        return resp;
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

}  // namespace axiam
