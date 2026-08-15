// A hand-rolled AXIAM Reactor — CONTRACT.md §22, and NON-NORMATIVE throughout.
//
// READ THIS FIRST. This SDK ships **no reactor runtime**. §22.11 defers the
// `reactor_serve` helper on Swift, C and C++ for the same reason §8 has never
// listed those targets among the SDKs that speak AMQP: there is no vendorable
// AMQP client this project is willing to put on embedded and mobile
// deployments. Nothing in this file is part of the library, nothing here is
// installed, and no header under `include/axiam/` gained a reactor API.
//
// What §22.11 *does* say is that the absence of a helper changes nothing about
// the protocol: "§22.1–§22.8 is a wire protocol, and a wire protocol does not
// become optional because no helper wraps it." An integrator hand-rolling a
// reactor against a third-party AMQP client MUST satisfy every normative rule in
// those subsections. This file is a worked example of doing that, and §22.11 is
// explicit about its standing: "It is an example, not a contract surface: this
// section governs, and the sample conforms to it or is wrong."
//
// So that "conforms to it or is wrong" is checkable rather than aspirational,
// `main()` runs the committed §22.13 reference vectors — the ones the AXIAM
// server generated with its own sign path — in both directions, and returns
// non-zero if a single byte differs.
//
// WHAT AN INTEGRATOR STILL HAS TO SUPPLY: the AMQP transport. Everything below
// the `ReactorTransport` comment is deliberately abstract, because that is the
// one piece this project will not pick for you. rabbitmq-c, SimpleAmqpClient and
// AMQP-CPP are all commonly used; whichever you pick, §8b applies — `amqps://`
// only, a supplied CA bundle, no verification-skip switch, no plaintext
// fallback. Consume the queue the SERVER declared for your reactor
// (`axiam.reactor.q.<tenant_id>.<reactor_id>`) and DECLARE NOTHING: §22.1 makes
// that a MUST NOT, because a reactor that can bind is a reactor that can bind
// itself to `*.token.pre_issue` and read another tenant's issuance events.
//
// Build: cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build -j
// Run:   ./build/examples/axiam_example_reactor

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// §22.5 — the event registry and its mutable-field allow-lists
//
// The live copy is served at GET /api/v1/reactors/events and is what an admin UI
// should read; a reactor mirrors it because the delivery path validates against
// it with no network call available.
//
// WHAT IS ABSENT IS LOAD-BEARING. §22.7 is a normative MUST NOT: the three
// hot-path decision operations (the single authorization check, the batch check
// and token introspection) are not hookable and no SDK or sample may present
// them as such. They are in no list here and in no comment here. A reactor
// round-trip is milliseconds; the check path's budget is microseconds. An
// application needing external input on an authorization decision writes a
// **deny grant**, which the engine evaluates in the hot path at hot-path cost.
// ---------------------------------------------------------------------------

constexpr const char* kEventTokenPreIssue = "token.pre_issue";
constexpr const char* kEventLoginPostAuth = "login.post_auth";
constexpr const char* kEventUserPreCreate = "user.pre_create";
constexpr const char* kEventUserPreUpdate = "user.pre_update";
constexpr const char* kEventGrantPreAssign = "grant.pre_assign";

// §8 v2 / §22.2: a body carrying less than this is refused before anything else
// about it is considered — including its signature.
constexpr int kKeyVersion = 2;
// ±freshness window, applied in BOTH directions. A future timestamp is not
// "extra fresh", it is the shape of a captured message held for later.
constexpr std::int64_t kFreshnessSkewSecs = 300;
// §22.3: the payload key under which the server inserts the patch accumulated by
// earlier reactors in the chain. READ-ONLY context — echoing it back inside your
// own patch is not how a field is preserved; the server merges (§22.6).
constexpr const char* kChainPatchKey = "_reactor_patch";

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
        {kEventTokenPreIssue, true, {"ext."}, "fail_open"},
        {kEventLoginPostAuth, false, {}, "fail_closed"},
        {kEventUserPreCreate, true, {"username", "email", "metadata."}, "fail_closed"},
        {kEventUserPreUpdate, true, {"username", "email", "metadata."}, "fail_closed"},
        {kEventGrantPreAssign, false, {}, "fail_closed"},
    };
    return kRegistry;
}

const EventSpec* spec_for(const std::string& name) {
    for (const auto& spec : registry()) {
        if (name == spec.name) {
            return &spec;
        }
    }
    return nullptr;  // includes every operation §22.7 keeps out of the registry
}

// §22.5's namespace-prefix rule: an entry ending in `.` matches a field starting
// with the entry AND carrying at least one character after the dot. `ext.`
// admits `ext.department` and `ext.a.b.c`; it refuses `ext.` itself (that names
// the namespace, not a claim), `ext`, `extra`, `external_id` (a prefix match on
// the string is not a match on the namespace) and `evil.ext.department`.
bool patch_field_allowed(const EventSpec& spec, const std::string& field) {
    if (!spec.mutable_event) {
        return false;
    }
    for (const auto& allowed : spec.mutable_fields) {
        if (!allowed.empty() && allowed.back() == '.') {
            if (field.size() > allowed.size() && field.compare(0, allowed.size(), allowed) == 0) {
                return true;
            }
            continue;
        }
        if (field == allowed) {
            return true;
        }
    }
    return false;
}

// §22.8: the STRICTEST default wins, in either array order. A reactor registered
// for both `token.pre_issue` (open) and `login.post_auth` (closed) can veto a
// login, so it inherits fail_closed. Reducing this to "take the first event's
// default" would let the order of a JSON array decide whether an unreachable
// fraud check passes, which is why §22.8 states it as a MUST NOT reimplement.
std::string default_failure_policy(const std::vector<std::string>& events) {
    if (events.empty()) {
        return "fail_closed";
    }
    for (const auto& name : events) {
        const EventSpec* spec = spec_for(name);
        if (spec == nullptr || std::string(spec->default_failure_policy) == "fail_closed") {
            return "fail_closed";
        }
    }
    return "fail_open";
}

// §22.1 topology. Rendering these names is not the same as declaring them: a
// reactor consumes the queue the server declared and never declares or binds
// anything.
std::string routing_key(const std::string& tenant_id, const std::string& event) {
    return tenant_id + "." + event;
}
std::string queue_name(const std::string& tenant_id, const std::string& reactor_id) {
    return "axiam.reactor.q." + tenant_id + "." + reactor_id;
}

// ---------------------------------------------------------------------------
// §22.2 — canonicalization and the HMAC, in both directions
//
// The signing key is the tenant's HKDF-derived AMQP subkey (§8.1), the same key
// in both directions: the server signs the event, the reactor signs the reply.
// There is no second key and no asymmetric variant in v1.
//
// WHAT EXACTLY IS SIGNED: the message serialized to JSON in its DECLARED FIELD
// ORDER, with `hmac_signature` present and set to **null** — not omitted. That
// differs from §8's own two message types, whose `hmac_signature` is absent from
// their canonical bytes, and it is the single most likely place to produce a MAC
// that will not verify. It is why this file builds the canonical string by hand
// instead of dumping a JSON object: a JSON library will order keys its own way
// and will drop or reorder the null.
// ---------------------------------------------------------------------------

std::string hmac_sha256_hex(const std::string& key, const std::string& bytes) {
    unsigned char mac[EVP_MAX_MD_SIZE] = {0};
    unsigned int len = 0;
    ::HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
           reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), mac, &len);

    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; ++i) {
        out << std::setw(2) << static_cast<int>(mac[i]);
    }
    return out.str();
}

// Constant-time comparison. Never `==` on the hex strings.
bool constant_time_equals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

// serde_json's string escaping: the two mandatory escapes, the five short forms,
// \u00XX for the remaining control characters — and NOTHING else. Forward
// slashes stay literal and UTF-8 passes through unescaped, which is where a
// naive port usually diverges.
std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (unsigned char c : value) {
        switch (c) {
            case '"':  out << "\\\""; break;
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
                    out << c;
                }
        }
    }
    return out.str();
}

std::string quoted(const std::string& value) { return "\"" + json_escape(value) + "\""; }

// Field order, event (server -> reactor): tenant_id, event, correlation_id,
// payload, timeout_ms, key_version, nonce, issued_at, hmac_signature (null).
//
// `payload` is re-emitted through the JSON library's compact dump. That is safe
// here and only here: the server's payload map is a BTreeMap, so its keys are
// already in byte order, which is the order nlohmann's default object type emits
// too. Everything above this line is hand-ordered because the top-level order is
// the server's STRUCT DECLARATION order, which no library will reproduce.
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

// ---------------------------------------------------------------------------
// §22.4 — the reply
//
// Field order: correlation_id, tenant_id, event, decision, reason (OMITTED when
// absent), patch (OMITTED when absent), require_mfa (OMITTED when false),
// key_version, nonce, issued_at, hmac_signature (null while signing).
//
// The three conditional omissions are load-bearing. A reply that serializes
// "require_mfa": false rather than omitting it produces different canonical
// bytes and therefore a different MAC. Reproduce the omission rule, not merely
// the values.
// ---------------------------------------------------------------------------

struct Answer {
    std::string decision;                       // "allow" | "deny" | "mutate"
    std::optional<std::string> reason;          // deny only; omitted when absent
    std::optional<std::map<std::string, std::string>> patch;  // mutate only
    bool require_mfa = false;                   // login.post_auth only

    static Answer allow() { return Answer{"allow", std::nullopt, std::nullopt, false}; }
    // `require_mfa` is NOT a separate decision value: it rides on `allow`, and
    // `allow` + require_mfa:true on login.post_auth means "proceed only after
    // step-up". On the federated paths (SAML ACS, OIDC callback) there is no
    // step-up branch, so it FAILS the sign-in rather than being dropped — answer
    // deny there and drive enrolment out of band (§22.5).
    static Answer allow_with_step_up() { return Answer{"allow", std::nullopt, std::nullopt, true}; }
    // A deny with no reason still denies; the server substitutes "denied by
    // reactor". An empty reason is therefore omitted, not sent as "".
    static Answer deny(std::string why) {
        Answer a{"deny", std::nullopt, std::nullopt, false};
        if (!why.empty()) {
            a.reason = std::move(why);
        }
        return a;
    }
    // §22.4 rule 1 / §22.10 rule 3: a patch is sent UNFILTERED. One forbidden key
    // rejects the WHOLE patch server-side, including the fields that would have
    // been fine — and dropping the offender to rescue the rest would leave the
    // author believing a field was set when it was dropped, which is the exact
    // failure the server refuses to produce. Note there is no way to spell
    // `allow` + `patch`: the two allow constructors take none (§22.4 rule 2).
    static Answer mutate(std::map<std::string, std::string> patch) {
        return Answer{"mutate", std::nullopt, std::move(patch), false};
    }
};

// std::map is byte-ordered, which is what the server's BTreeMap emits. An
// unordered container here would produce a MAC that verifies only by luck.
std::string canonical_patch(const std::map<std::string, std::string>& patch) {
    std::ostringstream out;
    out << "{";
    bool first = true;
    for (const auto& [key, value] : patch) {
        if (!first) {
            out << ",";
        }
        first = false;
        out << quoted(key) << ":" << quoted(value);
    }
    out << "}";
    return out.str();
}

std::string canonical_reply(const std::string& correlation_id, const std::string& tenant_id,
                            const std::string& event, const Answer& answer,
                            const std::string& nonce, const std::string& issued_at) {
    std::ostringstream out;
    out << "{"
        << "\"correlation_id\":" << quoted(correlation_id) << ","
        << "\"tenant_id\":" << quoted(tenant_id) << ","
        << "\"event\":" << quoted(event) << ","
        << "\"decision\":" << quoted(answer.decision);
    if (answer.reason.has_value()) {
        out << ",\"reason\":" << quoted(*answer.reason);
    }
    if (answer.patch.has_value() && !answer.patch->empty()) {
        out << ",\"patch\":" << canonical_patch(*answer.patch);
    }
    if (answer.require_mfa) {
        out << ",\"require_mfa\":true";
    }
    out << ",\"key_version\":" << kKeyVersion << ","
        << "\"nonce\":" << quoted(nonce) << ","
        << "\"issued_at\":" << quoted(issued_at) << ","
        << "\"hmac_signature\":null"
        << "}";
    return out.str();
}

// Renders the reply as it goes on the wire: the canonical bytes with the null
// placeholder replaced by the MAC computed over them.
std::string build_reply(const std::string& signing_key, const std::string& correlation_id,
                        const std::string& tenant_id, const std::string& event,
                        const Answer& answer, const std::string& nonce,
                        const std::string& issued_at) {
    // Two client-side refusals §22.13 asks for. Both must result in NO REPLY
    // rather than a corrected one: the registration's failure_policy decides,
    // never a synthesized allow.
    if (answer.require_mfa && event != std::string(kEventLoginPostAuth)) {
        throw std::runtime_error("require_mfa is valid on login.post_auth only (§22.4 row 7)");
    }
    if (answer.decision == "mutate" && (!answer.patch.has_value() || answer.patch->empty())) {
        throw std::runtime_error("a mutate answer requires a non-empty patch (malformed_mutation)");
    }

    const std::string canonical =
        canonical_reply(correlation_id, tenant_id, event, answer, nonce, issued_at);
    const std::string signature = hmac_sha256_hex(signing_key, canonical);

    const std::string placeholder = "\"hmac_signature\":null";
    const std::size_t at = canonical.rfind(placeholder);
    return canonical.substr(0, at) + "\"hmac_signature\":\"" + signature + "\"" +
           canonical.substr(at + placeholder.size());
}

// ---------------------------------------------------------------------------
// §22.3 — what a reactor MUST do before invoking a handler, in this order:
// reject key_version < 2; verify the MAC; check freshness; check the nonce
// against a seen-set. Only then decode the payload.
//
// A runtime that hands an unverified payload to user code has already lost — the
// handler will act on it, and "we checked afterwards" is not a check.
// ---------------------------------------------------------------------------

struct VerifiedEvent {
    std::string tenant_id;
    std::string event;
    std::string correlation_id;
    json payload;
    std::int64_t timeout_ms = 0;
    std::string nonce;
};

std::int64_t parse_rfc3339_utc(const std::string& value) {
    std::tm tm{};
    if (::strptime(value.c_str(), "%Y-%m-%dT%H:%M:%SZ", &tm) == nullptr) {
        return -1;
    }
    return static_cast<std::int64_t>(::timegm(&tm));
}

// A tiny in-memory nonce seen-set. A real reactor keeps one per process for its
// whole lifetime; building a fresh one per delivery defeats replay dedup
// entirely.
class NonceSeenSet {
public:
    bool claim(const std::string& nonce, std::int64_t now) {
        for (auto it = seen_.begin(); it != seen_.end();) {
            it = (it->second <= now) ? seen_.erase(it) : std::next(it);
        }
        if (seen_.count(nonce) != 0) {
            return false;
        }
        seen_[nonce] = now + 2 * kFreshnessSkewSecs;
        return true;
    }

private:
    std::map<std::string, std::int64_t> seen_;
};

std::optional<VerifiedEvent> verify_event(const std::string& signing_key, const std::string& body,
                                          const std::string& expected_tenant, std::int64_t now,
                                          NonceSeenSet* seen, std::string* why) {
    auto refuse = [why](const char* reason) -> std::optional<VerifiedEvent> {
        if (why != nullptr) {
            *why = reason;  // a category, never the MAC, the key or the payload
        }
        return std::nullopt;
    };

    json message = json::parse(body, nullptr, false);
    if (message.is_discarded() || !message.is_object()) {
        return refuse("malformed");
    }

    // 1. key_version, before anything else about the body is considered.
    if (!message.contains("key_version") || !message["key_version"].is_number_integer() ||
        message["key_version"].get<std::int64_t>() < kKeyVersion) {
        return refuse("key_version_too_old");
    }

    // 2. The MAC, over the body with hmac_signature set to null.
    if (!message.contains("hmac_signature") || !message["hmac_signature"].is_string()) {
        return refuse("bad_signature");
    }
    const std::string presented = message["hmac_signature"].get<std::string>();
    const std::string expected = hmac_sha256_hex(signing_key, canonical_event(message));
    if (!constant_time_equals(presented, expected)) {
        return refuse("bad_signature");
    }

    // 3. Freshness, in BOTH directions.
    const std::int64_t issued_at = parse_rfc3339_utc(message.at("issued_at").get<std::string>());
    if (issued_at < 0) {
        return refuse("malformed");
    }
    if (std::llabs(static_cast<long long>(now - issued_at)) > kFreshnessSkewSecs) {
        return refuse("stale");
    }

    // 4. The nonce, against the seen-set.
    const std::string nonce = message.at("nonce").get<std::string>();
    if (seen != nullptr && !seen->claim(nonce, now)) {
        return refuse("replay");
    }

    // Identity and registry membership come AFTER the MAC: neither is
    // cryptography, and spending them on unauthenticated bytes tells an
    // unauthenticated party what this reactor accepts.
    VerifiedEvent verified;
    verified.tenant_id = message.at("tenant_id").get<std::string>();
    if (verified.tenant_id != expected_tenant) {
        return refuse("tenant_mismatch");
    }
    verified.event = message.at("event").get<std::string>();
    if (spec_for(verified.event) == nullptr) {
        // Also how §22.7's exclusion refuses: those operations are in no
        // registry, so a delivery naming one never reaches a handler.
        return refuse("unknown_event");
    }
    verified.correlation_id = message.at("correlation_id").get<std::string>();
    verified.payload = message.at("payload");
    verified.timeout_ms = message.at("timeout_ms").get<std::int64_t>();
    verified.nonce = nonce;
    return verified;
}

// ---------------------------------------------------------------------------
// The handler an integrator writes
// ---------------------------------------------------------------------------

Answer decide(const VerifiedEvent& event) {
    // §22.3: `timeout_ms` is how long the server will wait for THIS dispatch, and
    // it is inside the signed body so it cannot be widened in transit. Shed load
    // rather than answering into a window that has already closed — a late reply
    // is discarded and the work spent producing it was spent for nothing.

    // Chained events carry the accumulated patch so a later reactor decides
    // against the state that will actually be committed. READ-ONLY context.
    if (event.payload.contains(kChainPatchKey)) {
        std::cout << "  an earlier reactor in the chain already set "
                  << event.payload[kChainPatchKey].size() << " field(s)\n";
    }

    if (event.event == kEventTokenPreIssue) {
        return Answer::mutate({{"ext.cost_center", "42"}, {"ext.department", "eng"}});
    }
    if (event.event == kEventLoginPostAuth) {
        const std::string ip =
            event.payload.value("ip", std::string{});
        if (ip.rfind("203.0.113.", 0) == 0) {
            return Answer::deny("embargoed region");
        }
        return Answer::allow();  // or Answer::allow_with_step_up()
    }
    return Answer::allow();
}

// ---------------------------------------------------------------------------
// ReactorTransport — the seam this project does not fill for you
//
// Bind whichever AMQP client you already trust. The obligations are §22.1's and
// §8b's, not this file's:
//
//   * connect over `amqps://` with a supplied CA bundle, no verification-skip
//     switch and no plaintext fallback;
//   * consume `queue_name(tenant_id, reactor_id)` — the queue the SERVER
//     declared — with manual acknowledgement;
//   * DECLARE NOTHING. No exchange, no queue, no binding. §22.1 is a MUST NOT;
//   * publish the reply to the delivery's `reply_to` queue through the default
//     exchange, echoing its `correlation_id` property. What the server actually
//     authenticates is the `correlation_id` INSIDE the signed reply body — copy
//     it from the event body, because copying it only into the AMQP property
//     produces a reply the server discards;
//   * on ANY failure of your own — a handler that throws, a body you cannot
//     decode, a window that closed — publish NOTHING. The registration's
//     `failure_policy` decides, and a synthesized `allow` would override the
//     operator's `fail_closed` from inside your process.
// ---------------------------------------------------------------------------

class ReactorTransport {
public:
    virtual ~ReactorTransport() = default;
    virtual void publish_reply(const std::string& reply_queue, const std::string& correlation_id,
                               const std::string& body) = 0;
    // Note the absence of any declare or bind method (§22.1).
};

class PrintingTransport final : public ReactorTransport {
public:
    void publish_reply(const std::string& reply_queue, const std::string& correlation_id,
                       const std::string& body) override {
        std::cout << "  would publish to " << reply_queue << " (correlation " << correlation_id
                  << ")\n    " << body << "\n";
    }
};

// ---------------------------------------------------------------------------
// §22.13 self-check against the server-generated reference vectors
// ---------------------------------------------------------------------------

int failures = 0;

void check(bool ok, const std::string& what) {
    std::cout << (ok ? "  ok   " : "  FAIL ") << what << "\n";
    if (!ok) {
        ++failures;
    }
}

std::string wire_body(const json& vector) {
    const std::string canonical = vector.at("canonical_signed_json").get<std::string>();
    const std::string placeholder = "\"hmac_signature\":null";
    const std::size_t at = canonical.rfind(placeholder);
    return canonical.substr(0, at) + "\"hmac_signature\":\"" +
           vector.at("hmac_signature_hex").get<std::string>() + "\"" +
           canonical.substr(at + placeholder.size());
}

std::string hex_to_bytes(const std::string& hex) {
    std::string out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

void run_vectors(const json& vectors) {
    const std::string key = hex_to_bytes(vectors.at("hkdf").at("derived_subkey_hex").get<std::string>());
    const std::string tenant = vectors.at("tenant_id").get<std::string>();
    const std::string reactor_id = vectors.at("reactor_id").get<std::string>();
    const std::string correlation = vectors.at("expected_correlation_id").get<std::string>();
    const std::int64_t now = parse_rfc3339_utc(vectors.at("verified_at").get<std::string>());
    const std::string issued_at = "2026-07-10T12:00:00Z";
    const std::string reply_nonce = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

    std::cout << "§22.1 topology\n";
    check(queue_name(tenant, reactor_id) == vectors.at("topology").at("queue").get<std::string>(),
          "queue name matches the server's rendering");
    check(routing_key(tenant, kEventTokenPreIssue) ==
              vectors.at("topology").at("routing_key_token_pre_issue").get<std::string>(),
          "routing key matches the server's rendering");

    std::cout << "§22.13 verify direction (server -> reactor)\n";
    for (const auto& [name, vector] : vectors.at("server_to_reactor").items()) {
        NonceSeenSet seen;
        std::string why;
        const std::string body = wire_body(vector);
        auto verified = verify_event(key, body, tenant, now, &seen, &why);
        check(verified.has_value(), name + " verifies under the derived subkey (" + why + ")");

        std::string other = key;
        other[0] = static_cast<char>(other[0] ^ 0xFF);
        NonceSeenSet fresh;
        check(!verify_event(other, body, tenant, now, &fresh, nullptr).has_value(),
              name + " does NOT verify under any other key");

        // The nonce seen-set refuses the redelivery.
        check(!verify_event(key, body, tenant, now, &seen, &why).has_value(),
              name + " is refused on redelivery (replay)");
    }

    std::cout << "§22.13 tampering, key_version, freshness\n";
    {
        std::string body = wire_body(vectors.at("server_to_reactor").at("token_pre_issue"));
        const std::string tampered =
            body.substr(0, body.find("\"sub\":\"alice\"")) + "\"sub\":\"root\"" +
            body.substr(body.find("\"sub\":\"alice\"") + std::strlen("\"sub\":\"alice\""));
        NonceSeenSet seen;
        check(!verify_event(key, tampered, tenant, now, &seen, nullptr).has_value(),
              "a payload edited after signing invalidates the event");

        std::string downgraded = body;
        downgraded.replace(downgraded.find("\"key_version\":2"), std::strlen("\"key_version\":2"),
                           "\"key_version\":1");
        std::string why;
        NonceSeenSet seen2;
        verify_event(key, downgraded, tenant, now, &seen2, &why);
        check(why == "key_version_too_old",
              "key_version < 2 is refused BEFORE the signature is computed");

        NonceSeenSet a, b, c, d;
        check(verify_event(key, body, tenant, now + kFreshnessSkewSecs, &a, nullptr).has_value(),
              "accepted at the stale-side edge");
        check(!verify_event(key, body, tenant, now + kFreshnessSkewSecs + 1, &b, nullptr).has_value(),
              "refused one second past the stale-side edge");
        check(verify_event(key, body, tenant, now - kFreshnessSkewSecs, &c, nullptr).has_value(),
              "accepted at the future-side edge");
        check(!verify_event(key, body, tenant, now - kFreshnessSkewSecs - 1, &d, nullptr).has_value(),
              "refused one second past the future-side edge — a future timestamp is not extra fresh");

        NonceSeenSet e;
        std::string why2;
        verify_event(key, body, "99999999-9999-9999-9999-999999999999", now, &e, &why2);
        check(why2 == "tenant_mismatch", "another tenant's event is refused even when validly signed");
    }

    std::cout << "§22.13 sign direction (reactor -> server)\n";
    struct Case {
        const char* vector_name;
        const char* event;
        Answer answer;
    };
    const std::vector<Case> cases = {
        {"allow", kEventLoginPostAuth, Answer::allow()},
        {"deny", kEventLoginPostAuth, Answer::deny("embargoed region")},
        {"mutate", kEventTokenPreIssue,
         Answer::mutate({{"ext.cost_center", "42"}, {"ext.department", "eng"}})},
        {"require_mfa", kEventLoginPostAuth, Answer::allow_with_step_up()},
    };
    for (const auto& c : cases) {
        const json& vector = vectors.at("reactor_to_server").at(c.vector_name);
        const std::string built =
            build_reply(key, correlation, tenant, c.event, c.answer, reply_nonce, issued_at);
        check(built == wire_body(vector),
              std::string(c.vector_name) + " reply reproduces canonical_signed_json byte-for-byte");
    }

    std::cout << "§22.2 omission rules and nonce binding\n";
    {
        const std::string allow =
            build_reply(key, correlation, tenant, kEventLoginPostAuth, Answer::allow(), reply_nonce,
                        issued_at);
        check(allow.find("require_mfa") == std::string::npos, "an allow omits require_mfa entirely");
        check(allow.find("\"reason\"") == std::string::npos, "an allow omits reason entirely");
        check(allow.find("\"patch\"") == std::string::npos, "an allow omits patch entirely");
        check(build_reply(key, correlation, tenant, kEventLoginPostAuth, Answer::deny(""),
                          reply_nonce, issued_at)
                      .find("\"reason\"") == std::string::npos,
              "a deny with no reason omits the field — the server substitutes its own");

        const json& binding = vectors.at("nonce_binding");
        const std::string a = build_reply(key, correlation, tenant, kEventLoginPostAuth,
                                          Answer::allow(),
                                          binding.at("nonce_a").get<std::string>(), issued_at);
        const std::string b = build_reply(key, correlation, tenant, kEventLoginPostAuth,
                                          Answer::allow(),
                                          binding.at("nonce_b").get<std::string>(), issued_at);
        check(a.find(binding.at("hmac_a_hex").get<std::string>()) != std::string::npos &&
                  b.find(binding.at("hmac_b_hex").get<std::string>()) != std::string::npos,
              "two replies differing only in nonce carry different MACs");
    }

    std::cout << "§22.13 rejected replies — signed as committed, refused by the SERVER\n";
    {
        // A forbidden key is sent UNFILTERED. The server names it in its audit
        // record; dropping it here would hide the mistake from everyone.
        const json& forbidden = vectors.at("rejected_replies").at("forbidden_patch_field");
        check(build_reply(key, correlation, tenant, kEventTokenPreIssue,
                          Answer::mutate({{"ext.department", "eng"}, {"sub", "root"}}), reply_nonce,
                          issued_at) == wire_body(forbidden),
              "a patch carrying `sub` is sent unfiltered (server answers forbidden_patch_field:sub)");

        const json& veto = vectors.at("rejected_replies").at("mutation_on_veto_only_event");
        check(build_reply(key, correlation, tenant, kEventGrantPreAssign,
                          Answer::mutate({{"role", "admin"}}), reply_nonce, issued_at) ==
                  wire_body(veto),
              "a mutation on a veto-only event is sent as written (server answers not_mutable)");
    }

    std::cout << "§22.5 allow-lists and §22.8 failure-policy composition\n";
    {
        const EventSpec* token = spec_for(kEventTokenPreIssue);
        check(patch_field_allowed(*token, "ext.department") &&
                  patch_field_allowed(*token, "ext.a.b.c"),
              "`ext.` admits a namespaced claim");
        check(!patch_field_allowed(*token, "ext.") && !patch_field_allowed(*token, "ext") &&
                  !patch_field_allowed(*token, "extra") &&
                  !patch_field_allowed(*token, "external_id") &&
                  !patch_field_allowed(*token, "evil.ext.department"),
              "`ext.` refuses the namespace itself and every near miss");
        check(!patch_field_allowed(*token, "sub") && !patch_field_allowed(*token, "aud") &&
                  !patch_field_allowed(*token, "exp") && !patch_field_allowed(*token, "scope"),
              "no standard claim is reachable");

        const EventSpec* user = spec_for(kEventUserPreCreate);
        check(patch_field_allowed(*user, "email") && patch_field_allowed(*user, "metadata.source"),
              "user.pre_create admits email and the metadata namespace");
        check(!patch_field_allowed(*user, "metadata") && !patch_field_allowed(*user, "password") &&
                  !patch_field_allowed(*user, "tenant_id") && !patch_field_allowed(*user, "roles"),
              "user.pre_create refuses bare metadata, password, tenant_id and roles");

        check(!patch_field_allowed(*spec_for(kEventLoginPostAuth), "anything") &&
                  !patch_field_allowed(*spec_for(kEventGrantPreAssign), "role"),
              "the veto-only events accept no patch field at all");

        check(default_failure_policy({kEventTokenPreIssue}) == "fail_open",
              "an enrichment-only registration inherits fail_open");
        check(default_failure_policy({kEventTokenPreIssue, kEventLoginPostAuth}) == "fail_closed" &&
                  default_failure_policy({kEventLoginPostAuth, kEventTokenPreIssue}) == "fail_closed",
              "the strictest default wins in EITHER array order");
        check(default_failure_policy({}) == "fail_closed" &&
                  default_failure_policy({"nope.not_an_event"}) == "fail_closed",
              "an empty or unrecognised event list is fail_closed");
    }

    std::cout << "§22.7 hot-path exclusion\n";
    check(registry().size() == 5, "the registry holds exactly the five v1 events");
    check(spec_for("authz.check") == nullptr && spec_for("authz.check_batch") == nullptr &&
              spec_for("token.introspect") == nullptr,
          "the hot-path decision operations are not hookable and are in no list here");
}

}  // namespace

int main(int argc, char** argv) {
    const std::string path = (argc > 1) ? argv[1] : AXIAM_REACTOR_VECTORS;

    std::ifstream file(path);
    if (!file) {
        std::cerr << "cannot open the §22.13 reference vectors at " << path << "\n";
        return 2;
    }
    json vectors = json::parse(file, nullptr, false);
    if (vectors.is_discarded()) {
        std::cerr << "the §22.13 reference vectors at " << path << " are not valid JSON\n";
        return 2;
    }

    std::cout << "AXIAM reactor sample — CONTRACT.md §22, NON-NORMATIVE (§22.11).\n"
              << "This SDK ships no reactor runtime; the wire protocol below still binds you.\n\n";

    run_vectors(vectors);

    std::cout << "\nOne dispatch, end to end\n";
    {
        const std::string key =
            hex_to_bytes(vectors.at("hkdf").at("derived_subkey_hex").get<std::string>());
        const std::string tenant = vectors.at("tenant_id").get<std::string>();
        const std::int64_t now = parse_rfc3339_utc(vectors.at("verified_at").get<std::string>());
        NonceSeenSet seen;
        std::string why;

        const std::string body =
            wire_body(vectors.at("server_to_reactor").at("token_pre_issue"));
        auto verified = verify_event(key, body, tenant, now, &seen, &why);
        if (!verified.has_value()) {
            std::cerr << "  refused (" << why << ") — no reply is published, and the "
                      << "registration's failure_policy decides\n";
            return 1;
        }
        std::cout << "  verified event=" << verified->event
                  << " correlation=" << verified->correlation_id
                  << " budget=" << verified->timeout_ms << "ms\n";

        PrintingTransport transport;
        transport.publish_reply("amq.rabbitmq.reply-to.example", verified->correlation_id,
                                build_reply(key, verified->correlation_id, verified->tenant_id,
                                            verified->event, decide(*verified),
                                            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                                            "2026-07-10T12:00:00Z"));
    }

    std::cout << "\n" << (failures == 0 ? "all checks passed" : "CHECKS FAILED") << "\n";
    return failures == 0 ? 0 : 1;
}
