// axiam Reactor — CONTRACT.md §22, the protocol core.
//
// Promoted from the non-normative sample this SDK used to ship in
// examples/reactor/. The move is contract 1.28's: the half of §22 deferred for
// want of a DEPENDENCY is the transport, and the half an integrator was left to
// hand-roll from prose was the PROTOCOL — which is the half with the sharp
// edges, none of them AMQP-shaped.
//
// THE ONE THING THIS FILE IS CAREFUL ABOUT. Both canonical forms are built by
// hand rather than dumped from a JSON object. The signed bytes are the message in
// its DECLARED FIELD ORDER with `hmac_signature` present and set to **null** —
// not omitted, unlike §8's own two message types — and a JSON library will order
// keys its own way and will drop or reorder the null. Every MAC in this file
// depends on getting that exactly right, and §22.13's committed vectors are what
// says it is.
#include "axiam/reactor.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <nlohmann/json.hpp>

#include "axiam/errors.hpp"

namespace axiam {
namespace {

using json = nlohmann::json;

// §8 v2 / §22.2: a body carrying less than this is refused before anything else
// about it is considered — including its signature.
constexpr int kKeyVersion = 2;
// ±freshness window, applied in BOTH directions. A future timestamp is not
// "extra fresh"; it is the shape of a captured message held for later.
constexpr std::int64_t kFreshnessSkewSecs = 300;

struct EventSpec {
    const char* name;
    bool mutable_event;
    std::vector<std::string> mutable_fields;  // exact names, or a `.`-suffixed namespace
    const char* default_failure_policy;
};

const std::vector<EventSpec>& registry() {
    static const std::vector<EventSpec> kRegistry = {
        // `ext.` is the COMPLETE allow-list here: no standard claim begins with
        // it, so `sub`, `aud`, `exp`, `scope` and the rest are unreachable. A
        // hook that could rewrite `sub` is a hook that could mint a token for
        // anyone, and a CORRECTLY SIGNED reply setting it is refused exactly as a
        // forged one is.
        {kReactorEventTokenPreIssue, true, {"ext."}, "fail_open"},
        {kReactorEventLoginPostAuth, false, {}, "fail_closed"},
        {kReactorEventUserPreCreate, true, {"username", "email", "metadata."}, "fail_closed"},
        {kReactorEventUserPreUpdate, true, {"username", "email", "metadata."}, "fail_closed"},
        {kReactorEventGrantPreAssign, false, {}, "fail_closed"},
    };
    return kRegistry;
}

const EventSpec* spec_for(const std::string& name) {
    for (const auto& spec : registry()) {
        if (name == spec.name) return &spec;
    }
    return nullptr;  // includes every operation §22.7 keeps out of the registry
}

std::string hmac_sha256_hex(const std::string& key, const std::string& bytes) {
    unsigned char mac[EVP_MAX_MD_SIZE] = {0};
    unsigned int len = 0;
    ::HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
           reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), mac, &len);

    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; ++i) out << std::setw(2) << static_cast<int>(mac[i]);
    return out.str();
}

/// Constant-time comparison. Never `==` on the hex strings.
bool constant_time_equals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

/// serde_json's string escaping: the two mandatory escapes, the five short
/// forms, `\u00XX` for the remaining control characters — and NOTHING else.
/// Forward slashes stay literal and UTF-8 passes through unescaped, which is
/// where a naive port usually diverges.
std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (unsigned char c : value) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<int>(c) << std::dec;
                } else {
                    out << static_cast<char>(c);
                }
        }
    }
    return out.str();
}

std::string quoted(const std::string& value) { return "\"" + json_escape(value) + "\""; }

/// Field order, event (server → reactor): tenant_id, event, correlation_id,
/// payload, timeout_ms, key_version, nonce, issued_at, hmac_signature (null).
///
/// `payload` is re-emitted through the JSON library's compact dump. That is safe
/// here and ONLY here: the server's payload map is a BTreeMap, so its keys are
/// already in byte order, which is the order nlohmann's default object type emits
/// too. Everything above this line is hand-ordered because the top-level order is
/// the server's STRUCT DECLARATION order, which no library will reproduce.
std::string canonical_event(const json& message) {
    std::ostringstream out;
    out << "{"
        << "\"tenant_id\":" << quoted(message.at("tenant_id").get<std::string>()) << ","
        << "\"event\":" << quoted(message.at("event").get<std::string>()) << ","
        << "\"correlation_id\":" << quoted(message.at("correlation_id").get<std::string>()) << ","
        << "\"payload\":" << message.at("payload").dump() << ","
        << "\"timeout_ms\":" << message.at("timeout_ms").get<std::int64_t>() << ","
        << "\"key_version\":" << message.at("key_version").get<std::int64_t>() << ","
        << "\"nonce\":" << quoted(message.at("nonce").get<std::string>()) << ","
        << "\"issued_at\":" << quoted(message.at("issued_at").get<std::string>()) << ","
        << "\"hmac_signature\":null"
        << "}";
    return out.str();
}

/// std::map is byte-ordered, which is what the server's BTreeMap emits. An
/// unordered container here would produce a MAC that verifies only by luck.
std::string canonical_patch(const std::map<std::string, std::string>& patch) {
    std::ostringstream out;
    out << "{";
    bool first = true;
    for (const auto& [key, value] : patch) {
        if (!first) out << ",";
        first = false;
        out << quoted(key) << ":" << quoted(value);
    }
    out << "}";
    return out.str();
}

std::int64_t parse_rfc3339_utc(const std::string& value) {
    std::tm tm{};
    if (::strptime(value.c_str(), "%Y-%m-%dT%H:%M:%SZ", &tm) == nullptr) return -1;
    return static_cast<std::int64_t>(::timegm(&tm));
}

std::string rfc3339_utc(std::int64_t unix_seconds) {
    const std::time_t t = static_cast<std::time_t>(unix_seconds);
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

/// A v4-shaped random nonce. Not parsed by anyone — the server treats it as an
/// opaque string — but a UUID is what the fixtures look like and what an operator
/// expects to see in a log.
std::string random_nonce() {
    unsigned char b[16];
    if (RAND_bytes(b, sizeof(b)) != 1) {
        // A reactor that cannot get randomness must not invent a predictable
        // nonce: a guessable one is a replay window an attacker can aim at.
        throw NetworkError("reactor: no entropy available for a reply nonce", "no_entropy");
    }
    b[6] = static_cast<unsigned char>((b[6] & 0x0F) | 0x40);
    b[8] = static_cast<unsigned char>((b[8] & 0x3F) | 0x80);
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (int i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out.push_back('-');
        out.push_back(kHex[b[i] >> 4]);
        out.push_back(kHex[b[i] & 0x0F]);
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// §22.5 — the registry
// ---------------------------------------------------------------------------

const std::vector<std::string>& reactor_event_names() {
    static const std::vector<std::string> kNames = [] {
        std::vector<std::string> names;
        for (const auto& spec : registry()) names.emplace_back(spec.name);
        return names;
    }();
    return kNames;
}

bool reactor_patch_field_allowed(const std::string& event, const std::string& field) {
    const EventSpec* spec = spec_for(event);
    if (spec == nullptr || !spec->mutable_event) return false;
    for (const auto& allowed : spec->mutable_fields) {
        // §22.5's namespace-prefix rule: an entry ending in `.` matches a field
        // starting with the entry AND carrying at least one character after the
        // dot. `ext.` admits `ext.department` and `ext.a.b.c`; it refuses `ext.`
        // itself (that names the namespace, not a claim), `ext`, `extra`,
        // `external_id` (a prefix match on the string is not a match on the
        // namespace) and `evil.ext.department`.
        if (!allowed.empty() && allowed.back() == '.') {
            if (field.size() > allowed.size() &&
                field.compare(0, allowed.size(), allowed) == 0) {
                return true;
            }
            continue;
        }
        if (field == allowed) return true;
    }
    return false;
}

std::string reactor_default_failure_policy(const std::vector<std::string>& events) {
    if (events.empty()) return "fail_closed";
    for (const auto& name : events) {
        const EventSpec* spec = spec_for(name);
        if (spec == nullptr || std::string(spec->default_failure_policy) == "fail_closed") {
            return "fail_closed";
        }
    }
    return "fail_open";
}

std::string reactor_routing_key(const std::string& tenant_id, const std::string& event) {
    return tenant_id + "." + event;
}

std::string reactor_queue_name(const std::string& tenant_id, const std::string& reactor_id) {
    return "axiam.reactor.q." + tenant_id + "." + reactor_id;
}

// ---------------------------------------------------------------------------
// §22.4 — the decision
// ---------------------------------------------------------------------------

ReactorDecision ReactorDecision::allow() {
    ReactorDecision d;
    d.decision_ = "allow";
    return d;
}

ReactorDecision ReactorDecision::allow_with_step_up() {
    ReactorDecision d;
    d.decision_ = "allow";
    d.require_mfa_ = true;
    return d;
}

ReactorDecision ReactorDecision::deny(std::string reason) {
    ReactorDecision d;
    d.decision_ = "deny";
    // An empty reason is OMITTED, not sent as "": the server substitutes
    // "denied by reactor", and the omission changes the canonical bytes.
    if (!reason.empty()) d.reason_ = std::move(reason);
    return d;
}

ReactorDecision ReactorDecision::mutate(std::map<std::string, std::string> patch) {
    ReactorDecision d;
    d.decision_ = "mutate";
    d.patch_ = std::move(patch);
    return d;
}

std::string reactor_canonical_reply(const std::string& correlation_id,
                                    const std::string& tenant_id, const std::string& event,
                                    const ReactorDecision& decision, const std::string& nonce,
                                    const std::string& issued_at) {
    // Field order: correlation_id, tenant_id, event, decision, reason (OMITTED
    // when absent), patch (OMITTED when absent), require_mfa (OMITTED when
    // false), key_version, nonce, issued_at, hmac_signature (null while
    // signing).
    //
    // The three conditional omissions are load-bearing. A reply that serializes
    // `"require_mfa": false` rather than omitting it produces different canonical
    // bytes and therefore a different MAC.
    std::ostringstream out;
    out << "{"
        << "\"correlation_id\":" << quoted(correlation_id) << ","
        << "\"tenant_id\":" << quoted(tenant_id) << ","
        << "\"event\":" << quoted(event) << ","
        << "\"decision\":" << quoted(decision.decision());
    if (decision.reason().has_value()) out << ",\"reason\":" << quoted(*decision.reason());
    if (!decision.patch().empty()) out << ",\"patch\":" << canonical_patch(decision.patch());
    if (decision.require_mfa()) out << ",\"require_mfa\":true";
    out << ",\"key_version\":" << kKeyVersion << ","
        << "\"nonce\":" << quoted(nonce) << ","
        << "\"issued_at\":" << quoted(issued_at) << ","
        << "\"hmac_signature\":null"
        << "}";
    return out.str();
}

std::string reactor_build_reply(const Sensitive<std::string>& signing_key,
                                const std::string& correlation_id, const std::string& tenant_id,
                                const std::string& event, const ReactorDecision& decision,
                                const std::string& nonce, const std::string& issued_at) {
    // Two client-side refusals §22.13 asks for. Both must result in NO REPLY
    // rather than a corrected one: the registration's failure_policy decides,
    // never a synthesized allow.
    if (decision.require_mfa() && event != std::string(kReactorEventLoginPostAuth)) {
        throw AuthError("require_mfa is valid on login.post_auth only (CONTRACT.md §22.4 row 7)");
    }
    if (decision.decision() == "mutate" && decision.patch().empty()) {
        throw AuthError("a mutate answer requires a non-empty patch (malformed_mutation)");
    }

    const std::string canonical =
        reactor_canonical_reply(correlation_id, tenant_id, event, decision, nonce, issued_at);
    const std::string signature = hmac_sha256_hex(detail::reveal(signing_key), canonical);

    const std::string placeholder = "\"hmac_signature\":null";
    const std::size_t at = canonical.rfind(placeholder);
    return canonical.substr(0, at) + "\"hmac_signature\":\"" + signature + "\"" +
           canonical.substr(at + placeholder.size());
}

// ---------------------------------------------------------------------------
// §22.3 — verification
// ---------------------------------------------------------------------------

ReactorVerification reactor_verify_event(const Sensitive<std::string>& signing_key,
                                         const std::string& body,
                                         const std::string& expected_tenant, std::int64_t now,
                                         std::map<std::string, std::int64_t>* seen_nonces) {
    ReactorVerification result;
    auto refuse = [&result](ReactorRefusal why) {
        result.ok = false;
        result.refusal = why;  // a CATEGORY, never the MAC, the key or the payload
        return result;
    };

    const json message = json::parse(body, nullptr, false);
    if (message.is_discarded() || !message.is_object()) {
        return refuse(ReactorRefusal::kMalformed);
    }

    // 1. key_version, before anything else about the body is considered.
    if (!message.contains("key_version") || !message["key_version"].is_number_integer() ||
        message["key_version"].get<std::int64_t>() < kKeyVersion) {
        return refuse(ReactorRefusal::kKeyVersionTooOld);
    }

    // Every field canonical_event() reads has to be there before it reads them;
    // a body missing one is malformed, not badly signed.
    for (const char* key : {"tenant_id", "event", "correlation_id", "payload", "timeout_ms",
                            "nonce", "issued_at"}) {
        if (!message.contains(key)) return refuse(ReactorRefusal::kMalformed);
    }
    if (!message["tenant_id"].is_string() || !message["event"].is_string() ||
        !message["correlation_id"].is_string() || !message["nonce"].is_string() ||
        !message["issued_at"].is_string() || !message["timeout_ms"].is_number_integer()) {
        return refuse(ReactorRefusal::kMalformed);
    }

    // 2. The MAC, over the body with hmac_signature set to null.
    if (!message.contains("hmac_signature") || !message["hmac_signature"].is_string()) {
        return refuse(ReactorRefusal::kBadSignature);
    }
    const std::string presented = message["hmac_signature"].get<std::string>();
    const std::string expected =
        hmac_sha256_hex(detail::reveal(signing_key), canonical_event(message));
    if (!constant_time_equals(presented, expected)) {
        return refuse(ReactorRefusal::kBadSignature);
    }

    // 3. Freshness, in BOTH directions.
    const std::int64_t issued_at = parse_rfc3339_utc(message.at("issued_at").get<std::string>());
    if (issued_at < 0) return refuse(ReactorRefusal::kMalformed);
    const std::int64_t drift = now - issued_at;
    if (drift > kFreshnessSkewSecs || drift < -kFreshnessSkewSecs) {
        return refuse(ReactorRefusal::kStale);
    }

    // 4. The nonce, against the seen-set.
    const std::string nonce = message.at("nonce").get<std::string>();
    if (seen_nonces != nullptr) {
        for (auto it = seen_nonces->begin(); it != seen_nonces->end();) {
            it = (it->second <= now) ? seen_nonces->erase(it) : std::next(it);
        }
        if (seen_nonces->count(nonce) != 0) return refuse(ReactorRefusal::kReplay);
        (*seen_nonces)[nonce] = now + 2 * kFreshnessSkewSecs;
    }

    // Identity and registry membership come AFTER the MAC: neither is
    // cryptography, and spending them on unauthenticated bytes tells an
    // unauthenticated party what this reactor accepts.
    ReactorEvent event;
    event.tenant_id = message.at("tenant_id").get<std::string>();
    if (event.tenant_id != expected_tenant) return refuse(ReactorRefusal::kTenantMismatch);
    event.event = message.at("event").get<std::string>();
    if (spec_for(event.event) == nullptr) {
        // Also how §22.7's exclusion refuses: those operations are in no
        // registry, so a delivery naming one never reaches a handler.
        return refuse(ReactorRefusal::kUnknownEvent);
    }
    event.correlation_id = message.at("correlation_id").get<std::string>();
    event.payload_json = message.at("payload").dump();
    event.timeout_ms = message.at("timeout_ms").get<std::int64_t>();
    event.nonce = nonce;

    result.ok = true;
    result.event = std::move(event);
    return result;
}

// ---------------------------------------------------------------------------
// §22.10 — the runtime
// ---------------------------------------------------------------------------

void reactor_serve(const ReactorConfig& config, ReactorTransport& transport,
                   const ReactorHandler& handler) {
    if (!handler) throw AuthError("reactor_serve needs a handler");
    if (config.tenant_id.empty()) throw AuthError("reactor_serve needs a tenant_id");

    const auto clock = config.clock ? config.clock : [] {
        return static_cast<std::int64_t>(std::time(nullptr));
    };
    const auto nonce_source = config.nonce_source ? config.nonce_source : random_nonce;

    // ONE seen-set for this call's whole lifetime. A fresh one per delivery
    // defeats replay dedup entirely, which is the failure §22.3 rule 4 names.
    std::map<std::string, std::int64_t> seen_nonces;

    while (true) {
        const auto delivery = transport.next_delivery();
        if (!delivery) return;

        const std::int64_t received_at = clock();
        const ReactorVerification verified = reactor_verify_event(
            config.signing_key, delivery->body, config.tenant_id, received_at, &seen_nonces);
        if (!verified.ok) {
            // §22.10 rule 2: NO REPLY. A body this runtime could not verify is
            // not a body it may answer on the handler's behalf — the
            // registration's failure_policy decides.
            continue;
        }

        ReactorAnswer answer;
        try {
            answer = handler(verified.event);
        } catch (...) {
            // Same rule, the other source. A runtime that answered `allow` for a
            // handler that crashed would have overridden the operator's
            // fail_closed setting from inside the library.
            continue;
        }
        if (!answer) continue;  // the handler abstained (§22.14 rule 4)

        // §22.10 rule 4: work whose window has closed is abandoned rather than
        // answered late. The server has already resolved the event by its
        // failure_policy, and a reply arriving after that is at best ignored and
        // at worst applied to a decision nobody is waiting on.
        if (verified.event.timeout_ms > 0) {
            const std::int64_t elapsed_ms = (clock() - received_at) * 1000;
            if (elapsed_ms > verified.event.timeout_ms) continue;
        }

        std::string reply;
        try {
            reply = reactor_build_reply(config.signing_key, verified.event.correlation_id,
                                        verified.event.tenant_id, verified.event.event, *answer,
                                        nonce_source(), rfc3339_utc(clock()));
        } catch (...) {
            // A refusal from the reply builder — `require_mfa` on the wrong
            // event, an empty mutate — is the runtime's own error, and rule 2
            // applies to it exactly as to a handler that threw.
            continue;
        }

        const std::string destination =
            delivery->reply_to.empty() ? std::string("axiam.reactor.replies")
                                       : delivery->reply_to;
        transport.publish_reply(destination, verified.event.correlation_id, reply);
    }
}

// ---------------------------------------------------------------------------
// §22.14 — the binder
// ---------------------------------------------------------------------------

ReactorRouter& ReactorRouter::on(const std::string& event, ReactorHandler handler) {
    if (!handler) throw AuthError("reactor router: a binding needs a handler");
    if (spec_for(event) == nullptr) {
        // Rule 2: refused AT BIND TIME. The message names the registry; it does
        // not name what is absent from it — a separate hot-path list would be a
        // constant naming the three operations §22.13's hot-path assertion
        // forbids this SDK from exposing.
        std::string known;
        for (const auto& name : reactor_event_names()) {
            if (!known.empty()) known += ", ";
            known += name;
        }
        throw AuthError("reactor router: '" + event +
                        "' is not in the CONTRACT.md §22.5 event registry. Bindable events: " +
                        known);
    }
    for (const auto& [bound, _] : bindings_) {
        if (bound == event) {
            // Rule 3: never a silent overwrite. Which of two handlers runs is not
            // something the author of either can see from their own file.
            throw AuthError("reactor router: '" + event + "' already has a handler bound");
        }
    }
    bindings_.emplace_back(event, std::move(handler));
    return *this;
}

ReactorRouter& ReactorRouter::fallback(ReactorHandler handler) {
    if (!handler) throw AuthError("reactor router: a fallback needs a handler");
    fallback_ = std::move(handler);
    return *this;
}

std::vector<std::string> ReactorRouter::bound_events() const {
    std::vector<std::string> names;
    names.reserve(bindings_.size());
    for (const auto& [event, _] : bindings_) names.push_back(event);
    return names;
}

ReactorHandler ReactorRouter::build() const {
    // Copied into the closure so the router may go out of scope: a builder whose
    // output outlives it is the shape every caller writes by accident.
    auto bindings = bindings_;
    auto fallback = fallback_;
    return [bindings, fallback](const ReactorEvent& event) -> ReactorAnswer {
        for (const auto& [name, handler] : bindings) {
            // Rule 5: the handler's own failure propagates UNCHANGED. Nothing
            // here catches it — §22.10 rule 2 puts the fail-closed obligation on
            // the runtime, and a binder that swallowed a failure first would
            // satisfy the letter of that rule while defeating it.
            if (name == event.event) return handler(event);
        }
        // Rule 4: an unbound event ABSTAINS. Not `allow`, and not `deny` either —
        // the binder does not know what the registration was for, and the
        // operator's policy does.
        if (fallback) return fallback(event);
        return std::nullopt;
    };
}

// ---------------------------------------------------------------------------
// §8b rules 1–5
// ---------------------------------------------------------------------------

AmqpsEndpoint amqps_endpoint(const std::string& url, std::string ca_pem,
                             std::string client_cert_pem, std::string client_key_pem) {
    // Rule 3, checked first because it is about the caller's arguments rather
    // than about the URL: half a client identity fails closed rather than
    // connecting without the mutual half.
    if (client_cert_pem.empty() != client_key_pem.empty()) {
        throw AuthError(
            "amqps_endpoint: a client certificate and its key must be supplied together — half a "
            "client identity fails closed rather than connecting without the mutual half "
            "(CONTRACT.md §8b rule 3)");
    }

    // Rule 1, and there is NO LOOPBACK EXCEPTION (§8b rule 8): this applies to
    // localhost, 127.0.0.1 and ::1 exactly as to any other host. §6's
    // `http://localhost` dev carve-out does not extend here — §6 and §8b are
    // different rules, and the server has no plaintext listener for such an
    // exception to reach.
    const std::string scheme_sep = "://";
    const std::size_t sep = url.find(scheme_sep);
    if (sep == std::string::npos) {
        // Rule 5's posture applied to parsing: a URL this cannot read is not a
        // URL it can vouch for, so it fails closed rather than being passed on
        // for a socket to interpret.
        throw AuthError("amqps_endpoint: '" + url +
                        "' is not a URL. The broker URL must be amqps:// (CONTRACT.md §8b rule 1)");
    }
    std::string scheme = url.substr(0, sep);
    std::transform(scheme.begin(), scheme.end(), scheme.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (scheme != "amqps") {
        throw AuthError("amqps_endpoint: scheme '" + scheme +
                        "' is refused; the broker URL must be amqps:// and there is no plaintext "
                        "fallback and no loopback exception (CONTRACT.md §8b rules 1, 5 and 8)");
    }

    std::string rest = url.substr(sep + scheme_sep.size());
    // Strip any userinfo — credentials belong to the connection, not to this
    // check, and leaving them in `host` would put them wherever host is logged.
    const std::size_t at = rest.rfind('@');
    if (at != std::string::npos) rest = rest.substr(at + 1);

    std::string authority = rest;
    std::string vhost = "/";
    const std::size_t slash = rest.find('/');
    if (slash != std::string::npos) {
        authority = rest.substr(0, slash);
        const std::string path = rest.substr(slash + 1);
        if (!path.empty()) vhost = path;
    }
    if (authority.empty()) {
        throw AuthError("amqps_endpoint: '" + url + "' names no broker host (CONTRACT.md §8b)");
    }

    AmqpsEndpoint endpoint;
    endpoint.url = url;
    endpoint.port = 5671;  // the broker TLS port
    // An IPv6 literal is bracketed; its colons are not a port separator.
    if (!authority.empty() && authority.front() == '[') {
        const std::size_t close = authority.find(']');
        if (close == std::string::npos) {
            throw AuthError("amqps_endpoint: '" + url +
                            "' has an unterminated IPv6 host (CONTRACT.md §8b)");
        }
        endpoint.host = authority.substr(1, close - 1);
        if (close + 1 < authority.size() && authority[close + 1] == ':') {
            endpoint.port = std::atoi(authority.c_str() + close + 2);
        }
    } else {
        const std::size_t colon = authority.rfind(':');
        if (colon == std::string::npos) {
            endpoint.host = authority;
        } else {
            endpoint.host = authority.substr(0, colon);
            endpoint.port = std::atoi(authority.c_str() + colon + 1);
        }
    }
    if (endpoint.host.empty() || endpoint.port <= 0 || endpoint.port > 65535) {
        throw AuthError("amqps_endpoint: '" + url + "' names no usable broker endpoint "
                                                    "(CONTRACT.md §8b)");
    }

    endpoint.virtual_host = vhost;
    // Rule 2: a custom CA, for a privately-issued broker certificate. This is
    // the common case — an in-cluster broker's certificate is not issued by a
    // public CA — and it exists so nobody has a legitimate reason to want rule 4
    // relaxed. Rule 4 itself needs no code: there is no parameter for it, under
    // any name, and none may be added.
    endpoint.ca_pem = std::move(ca_pem);
    endpoint.client_cert_pem = std::move(client_cert_pem);
    endpoint.client_key_pem = std::move(client_key_pem);
    return endpoint;
}

}  // namespace axiam
