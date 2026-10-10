// §32.7 the SSF receiver helper — see include/axiam/ssf.hpp.

#include "axiam/ssf.hpp"

#include <utility>

#include "axiam/jwks.hpp"
#include "client_impl.hpp"
#include "jose.hpp"
#include "management_transport.hpp"
#include "url_origin.hpp"

namespace axiam::ssf {
namespace {

/// `j[key]` when it is a string. `json::value(key, default)` is not a safe
/// substitute: it THROWS the vendored library's type_error when the member is
/// present with another type, which would carry a hostile document's shape out
/// of this SDK's error taxonomy.
std::string string_member(const nlohmann::json& j, const char* key) {
    const auto it = j.find(key);
    return (it != j.end() && it->is_string()) ? it->get<std::string>() : std::string{};
}

}  // namespace

const char* reason_code(SetFailureReason reason) noexcept {
    switch (reason) {
        case SetFailureReason::kMalformed: return "malformed";
        case SetFailureReason::kInvalidType: return "invalid_type";
        case SetFailureReason::kInvalidKey: return "invalid_key";
        case SetFailureReason::kInvalidIssuer: return "invalid_issuer";
        case SetFailureReason::kInvalidAudience: return "invalid_audience";
        case SetFailureReason::kInvalidRequest: return "invalid_request";
        case SetFailureReason::kReplayed: return "replayed";
    }
    return "malformed";
}

const char* push_error_code(SetFailureReason reason) noexcept {
    switch (reason) {
        case SetFailureReason::kInvalidKey:
        case SetFailureReason::kInvalidIssuer:
        case SetFailureReason::kInvalidAudience:
            return reason_code(reason);
        // `malformed`, `invalid_type` and `replayed` are not RFC 8935 §2.4 codes;
        // a push endpoint answers them as the request being unacceptable.
        default:
            return "invalid_request";
    }
}

SetErr SetErr::from_reason(SetFailureReason reason) {
    return SetErr{push_error_code(reason), std::nullopt};
}

bool MemoryReplayStore::check_and_record(const std::string& jti, std::chrono::seconds window) {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = seen_.begin(); it != seen_.end();) {
        it = it->second <= now ? seen_.erase(it) : std::next(it);
    }
    return seen_.emplace(jti, now + window).second;
}

// ---------------------------------------------------------------------------

/// Shared by every copy of one SsfReceiver: the key cache must be one cache, and
/// the replay store one store, or a copy would accept what the original refused.
struct SsfReceiver::State {
    std::shared_ptr<Client::Impl> impl;
    SsfReceiverConfig config;

    std::mutex keys_mtx;  // held across a fetch: one fetch at a time, no stampede
    bool have_keys = false;
    std::optional<std::string> jwks_uri;  // resolved from the key source, once
    std::map<std::string, std::string> keys;  // kid -> raw Ed25519 public key
    /// The last fetch that counts toward step 4's once-a-minute limit: every
    /// unknown-kid refetch, and every FAILED fetch — the cold-cache fill
    /// included (§34.2 P6). A successful fill does not count: it is not "the
    /// refetch", and leaves the one refetch available.
    std::optional<std::chrono::steady_clock::time_point> last_limited_fetch;
    std::function<std::chrono::steady_clock::time_point()> now = [] {
        return std::chrono::steady_clock::now();
    };

    /// One unauthenticated, session-free GET over the client's transport (§6 TLS
    /// policy, no cookie jar, no SDK credential) returning the JSON object it
    /// answered, or NetworkError — a fetch failure is never a verdict on a SET.
    nlohmann::json fetch_object(const std::string& url, const char* what) const {
        HttpRequest req;
        req.method = "GET";
        req.url = url;
        req.headers["Accept"] = "application/json";
        req.sessionless = true;
        const HttpResponse resp = impl->transport(req);
        if (!resp.transport_error.empty()) {
            throw NetworkError(std::string("ssf: ") + what + " fetch failed: " +
                                   resp.transport_error,
                               resp.transport_error);
        }
        auto doc = nlohmann::json::parse(resp.body, nullptr, false);
        if (resp.status != 200 || !doc.is_object()) {
            throw NetworkError(std::string("ssf: ") + what + " fetch failed (HTTP " +
                                   std::to_string(resp.status) + ")",
                               "http_" + std::to_string(resp.status));
        }
        return doc;
    }

    /// The JWKS URL: the configured one, or the discovery document's, whose
    /// `issuer` must be the configured issuer (§32.7).
    std::string resolve_jwks_uri() {
        if (jwks_uri) return *jwks_uri;
        std::string uri = config.keys.url;
        if (config.keys.kind == SsfKeySource::Kind::kDiscoveryUrl) {
            const auto doc = fetch_object(config.keys.url, "SSF configuration");
            const auto issuer = doc.find("issuer");
            const auto found = doc.find("jwks_uri");
            if (issuer == doc.end() || !issuer->is_string() ||
                issuer->get<std::string>() != config.issuer || found == doc.end() ||
                !found->is_string()) {
                throw NetworkError(
                    "ssf: the SSF configuration names another issuer, or no jwks_uri "
                    "(CONTRACT.md §32.7)",
                    "ssf_configuration");
            }
            uri = found->get<std::string>();
            const auto origin = detail::origin_of(uri);
            if (!origin || !detail::is_secure_or_loopback(*origin)) {
                throw NetworkError("ssf: the SSF configuration's jwks_uri is not an https URL",
                                   "ssf_configuration");
            }
        }
        jwks_uri = uri;
        return uri;
    }

    void load_keys() {
        const auto doc = fetch_object(resolve_jwks_uri(), "JWKS");
        std::map<std::string, std::string> fresh;
        const auto list = doc.find("keys");
        if (list != doc.end() && list->is_array()) {
            for (const auto& k : *list) {
                // Ed25519 only, and only the public half: a JWKS member that is
                // anything else cannot verify an EdDSA SET (step 3 refused the rest).
                if (!k.is_object() || string_member(k, "kty") != "OKP" ||
                    string_member(k, "crv") != "Ed25519") {
                    continue;
                }
                const auto raw = base64url_decode(string_member(k, "x"));
                if (raw && raw->size() == 32) fresh[string_member(k, "kid")] = *raw;
            }
        }
        keys = std::move(fresh);
        have_keys = true;
    }

    /// Step 4: the key for `kid`, with at most one limited fetch per minute.
    std::optional<std::string> key_for(const std::string& kid) {
        std::lock_guard<std::mutex> lock(keys_mtx);
        const auto at = now();
        const bool limited =
            last_limited_fetch && at - *last_limited_fetch < std::chrono::seconds(60);
        if (!have_keys) {
            if (limited) {
                throw NetworkError(
                    "ssf: the JWKS fetch failed less than a minute ago and is not retried "
                    "yet (CONTRACT.md §32.7 step 4, §34.2 P6)",
                    "jwks_unavailable");
            }
            try {
                load_keys();
            } catch (...) {
                last_limited_fetch = at;  // a failed fill counts toward the limit
                throw;
            }
        }
        if (auto it = keys.find(kid); it != keys.end()) return it->second;
        if (limited) return std::nullopt;
        last_limited_fetch = at;
        load_keys();
        if (auto it = keys.find(kid); it != keys.end()) return it->second;
        return std::nullopt;
    }

    SecurityEvent verify(const std::string& set, const std::string* expected_jti);
};

namespace {

[[noreturn]] void refuse(SetFailureReason reason, const char* why) {
    throw SetVerificationError(std::string("SET refused (") + reason_code(reason) + "): " + why +
                                   " (CONTRACT.md §32.7)",
                               reason);
}

/// A base64url segment that decodes to a JSON object.
std::optional<nlohmann::json> json_object_of(const std::string& part) {
    const auto bytes = base64url_decode(part);
    if (!bytes) return std::nullopt;
    auto j = nlohmann::json::parse(*bytes, nullptr, false);
    if (!j.is_object()) return std::nullopt;
    return j;
}

bool typ_is_secevent(const nlohmann::json& header) {
    const auto it = header.find("typ");
    if (it == header.end() || !it->is_string()) return false;
    const std::string typ = CaseInsensitiveLess::lower(it->get<std::string>());
    return typ == "secevent+jwt" || typ == "application/secevent+jwt";
}

}  // namespace

SecurityEvent SsfReceiver::State::verify(const std::string& set,
                                         const std::string* expected_jti) {
    // 1. Exactly three parts, every one of them base64url, the first two JSON
    //    objects.
    const auto dot1 = set.find('.');
    const auto dot2 = dot1 == std::string::npos ? dot1 : set.find('.', dot1 + 1);
    if (dot2 == std::string::npos || set.find('.', dot2 + 1) != std::string::npos) {
        refuse(SetFailureReason::kMalformed, "not three base64url parts");
    }
    const std::string signing_input = set.substr(0, dot2);
    const auto header = json_object_of(set.substr(0, dot1));
    const auto claims = json_object_of(set.substr(dot1 + 1, dot2 - dot1 - 1));
    const auto signature = base64url_decode(set.substr(dot2 + 1));
    if (!header || !claims || !signature) {
        refuse(SetFailureReason::kMalformed, "a part is not base64url-encoded JSON");
    }

    // 2.
    if (!typ_is_secevent(*header)) refuse(SetFailureReason::kInvalidType, "typ is not secevent+jwt");

    // 3. EdDSA, exactly: `none`, every HS* and every other value end here, before
    //    any key is consulted.
    if (string_member(*header, "alg") != "EdDSA") refuse(SetFailureReason::kInvalidKey, "alg is not EdDSA");

    // 4. Only the configured JWKS — a `jwk` or `x5c` header member is never read.
    const std::string kid = string_member(*header, "kid");
    if (kid.empty()) refuse(SetFailureReason::kInvalidKey, "the header names no kid");
    const auto key = key_for(kid);
    if (!key) refuse(SetFailureReason::kInvalidKey, "no key for the kid in the JWKS");

    // 5.
    if (!detail::jose::ed25519_verify(*key, signing_input, *signature)) {
        refuse(SetFailureReason::kInvalidKey, "the signature does not verify");
    }

    // 6.
    const std::string iss = string_member(*claims, "iss");
    if (iss != config.issuer) refuse(SetFailureReason::kInvalidIssuer, "iss is not the configured issuer");

    // 7.
    const auto aud = claims->find("aud");
    bool aud_ok = false;
    if (aud != claims->end() && aud->is_string()) {
        aud_ok = aud->get<std::string>() == config.audience;
    } else if (aud != claims->end() && aud->is_array()) {
        for (const auto& a : *aud) aud_ok = aud_ok || (a.is_string() && a.get<std::string>() == config.audience);
    }
    if (!aud_ok) refuse(SetFailureReason::kInvalidAudience, "aud does not name this receiver");

    // 8.
    if (claims->contains("exp") || claims->contains("sub")) {
        refuse(SetFailureReason::kInvalidRequest, "a SET carries no exp and no sub");
    }
    const auto jti = claims->find("jti");
    const auto iat = claims->find("iat");
    const auto sub_id = claims->find("sub_id");
    const auto events = claims->find("events");
    if (jti == claims->end() || !jti->is_string() || jti->get<std::string>().empty() ||
        iat == claims->end() || !iat->is_number_integer() || sub_id == claims->end() ||
        !sub_id->is_object() || events == claims->end() || !events->is_object() ||
        events->size() != 1) {
        refuse(SetFailureReason::kInvalidRequest,
               "a SET needs a jti, a numeric iat, an object sub_id and exactly one event");
    }
    const std::string id = jti->get<std::string>();
    if (expected_jti && *expected_jti != id) {
        refuse(SetFailureReason::kInvalidRequest, "the poll key is not the SET's jti");
    }

    // 9. Recorded only now, once everything else passed. The store has three answers
    //    (§34.2 P4): seen, not seen, and CANNOT ANSWER -- which a C++ store gives by
    //    throwing. That is no verdict: it is raised as the §2 NetworkError, never as a
    //    SetVerificationError (so it carries no reason code and can never be read as
    //    `replayed`, which poll() would hand back to the transmitter as a refusal), and
    //    poll() leaves the SET unjudged and unrecorded.
    bool first_sight = false;
    try {
        first_sight = config.replay_store->check_and_record(id, config.replay_window);
    } catch (const std::exception& e) {
        throw NetworkError(std::string("ssf: the replay store could not answer: ") + e.what(),
                           "replay_store_unavailable");
    } catch (...) {
        throw NetworkError("ssf: the replay store could not answer", "replay_store_unavailable");
    }
    if (!first_sight) refuse(SetFailureReason::kReplayed, "this jti was already accepted");

    SecurityEvent out;
    out.jti = id;
    out.iat = iat->get<std::int64_t>();
    out.iss = iss;
    out.aud_json = aud->dump();
    if (const auto txn = claims->find("txn"); txn != claims->end() && txn->is_string()) {
        out.txn = txn->get<std::string>();
    }
    out.event_type = events->begin().key();
    out.event_json = events->begin().value().dump();
    out.sub_id_json = sub_id->dump();
    return out;
}

SsfReceiver::SsfReceiver(const Client& client, SsfReceiverConfig config)
    : state_(std::make_shared<State>()) {
    if (config.replay_window < kMinReplayWindow) {
        throw std::invalid_argument(
            "SsfReceiver: replay_window must be at least seven days, the transmitter's buffer "
            "retention (CONTRACT.md §32.7)");
    }
    const auto origin = detail::origin_of(config.keys.url);
    if (config.issuer.empty() || config.audience.empty() || !origin ||
        !detail::is_secure_or_loopback(*origin)) {
        throw std::invalid_argument(
            "SsfReceiver: issuer, audience and an https jwks_uri or discovery_url are required "
            "(CONTRACT.md §32.7)");
    }
    if (!config.replay_store) config.replay_store = std::make_shared<MemoryReplayStore>();
    state_->impl = client.p_;
    state_->config = std::move(config);
}

void SsfReceiver::_set_clock_for_testing(
    std::function<std::chrono::steady_clock::time_point()> now) {
    std::lock_guard<std::mutex> lock(state_->keys_mtx);
    state_->now = std::move(now);
}

SecurityEvent SsfReceiver::verify_set(const std::string& set) {
    return state_->verify(set, nullptr);
}

SsfPollResult SsfReceiver::poll(const std::string& stream_id, const SsfPollOptions& options) {
    Client::Impl& impl = *state_->impl;
    impl.ensure_open();
    if (!state_->config.access_token_provider) {
        throw AuthError(
            "ssf.poll needs an access_token_provider: a client-credentials token carrying "
            "ssf.manage (CONTRACT.md §32.7)");
    }

    nlohmann::json body = nlohmann::json::object();
    if (options.max_events) body["maxEvents"] = *options.max_events;
    if (options.return_immediately) body["returnImmediately"] = *options.return_immediately;
    if (options.ack) body["ack"] = *options.ack;
    if (options.set_errs) {
        nlohmann::json errs = nlohmann::json::object();
        for (const auto& [jti, e] : *options.set_errs) {
            nlohmann::json entry{{"err", e.err}};
            if (e.description) entry["description"] = *e.description;
            errs[jti] = std::move(entry);
        }
        body["setErrs"] = std::move(errs);
    }

    const Sensitive<std::string> token = state_->config.access_token_provider();
    HttpRequest req;
    req.method = "POST";
    req.url = impl.base_url + "/ssf/v1/poll/" + management::Transport::encode_segment(stream_id);
    req.headers["Accept"] = "application/json";
    req.headers["Content-Type"] = "application/json";
    req.headers["Authorization"] = "Bearer " + detail::reveal(token);
    req.body = body.dump();
    // The receiver's bearer only: no SDK session, no cookie jar, no redirects.
    req.sessionless = true;

    const int budget = impl.retry_enabled ? detail::kRetryMaxAttempts : 1;
    req.replayable = budget > 1;  // §34.2 P11: only a request the SDK itself repeats keeps the pool
    HttpResponse resp;
    for (int attempt = 1;; ++attempt) {
        resp = impl.transport(req);
        const std::optional<long> status =
            resp.transport_error.empty() ? std::optional<long>(resp.status) : std::nullopt;
        if (status && *status >= 200 && *status < 300) break;
        if (attempt >= budget || !detail::retry_should_retry(status)) {
            if (!status) throw NetworkError("ssf.poll: " + resp.transport_error, resp.transport_error);
            management::Transport::raise_management_status("ssf.poll", resp);
        }
        const auto hint = resp.headers.find("Retry-After");
        impl.sleeper(detail::retry_delay(
            attempt,
            hint == resp.headers.end() ? std::nullopt
                                       : detail::retry_after_from_header(hint->second),
            impl.jitter()));
    }

    const auto reply = nlohmann::json::parse(resp.body, nullptr, false);
    if (!reply.is_object()) {
        throw NetworkError("ssf.poll: the response is not a JSON object", "malformed_body");
    }
    SsfPollResult out;
    const auto more = reply.find("moreAvailable");
    out.more_available = more != reply.end() && more->is_boolean() && more->get<bool>();
    const auto sets = reply.find("sets");
    if (sets != reply.end() && sets->is_object()) {
        for (auto it = sets->begin(); it != sets->end(); ++it) {
            const std::string& jti = it.key();
            if (!it.value().is_string()) {
                out.refused.push_back({jti, SetFailureReason::kMalformed});
                continue;
            }
            // §34.2 P1: a verdict is `events` or `refused`; anything else — a key
            // fetch or a replay store that failed — leaves the SET unjudged and
            // its jti unrecorded (verify() records only at step 9, and a store
            // that throws has recorded nothing), so the transmitter offers it
            // again instead of the next poll reading it `replayed`.
            try {
                out.events.push_back(state_->verify(it.value().get<std::string>(), &jti));
            } catch (const SetVerificationError& e) {
                out.refused.push_back({jti, e.reason()});
            } catch (const std::exception& e) {
                out.unjudged.push_back({jti, e.what()});
            } catch (...) {
                out.unjudged.push_back({jti, "unknown failure"});
            }
        }
    }
    return out;
}

}  // namespace axiam::ssf
