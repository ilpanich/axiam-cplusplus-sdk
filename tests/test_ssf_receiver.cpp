// CONTRACT.md §32.7 / §32.8 (contract 1.56) — the SSF receiver helper: the
// eight required tests, plus poll's retry boundary, discovery, a JWKS failure
// and the configuration refusals.
//
// Every key is generated here (tests/test_key.hpp) and every SET is signed by
// the test: no key literal, and a signature this suite did not make cannot
// verify.

#include <memory>
#include <set>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/management.hpp"
#include "axiam/ssf.hpp"
#include "fake_transport.hpp"
#include "secret_util.hpp"
#include "test_key.hpp"
#include "url_origin.hpp"

using namespace axiam;
using axiam::ssf::SetFailureReason;
using axtest::FakeState;
using axtest::json_response;
using nlohmann::json;

namespace {

const char* kBase = "https://iam.example.com";
const char* kIssuer = "https://iam.example.com/t/6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b";
const char* kAudience = "https://rp.example.com/ssf";
const char* kJwks = "https://iam.example.com/oauth2/jwks";

json claims(const std::string& jti) {
    return {{"iss", kIssuer},
            {"aud", kAudience},
            {"iat", 1760000000},
            {"jti", jti},
            {"txn", "txn-1"},
            {"sub_id", {{"format", "iss_sub"}, {"iss", kIssuer}, {"sub", "user-1"}}},
            {"events",
             {{ssf::event_types::kSessionRevoked,
               {{"initiating_entity", "admin"}, {"event_timestamp", 1760000000}}}}}};
}

json header(const axtest::TestKey& key) {
    return {{"alg", "EdDSA"}, {"typ", "secevent+jwt"}, {"kid", key.kid}};
}

std::string sign(const axtest::TestKey& key, const json& hdr, const json& body) {
    const std::string input = axtest::b64url_encode(hdr.dump()) + "." + axtest::b64url_encode(body.dump());
    return input + "." + axtest::b64url_encode(key.sign(input));
}

std::string set_for(const axtest::TestKey& key, const json& body) {
    return sign(key, header(key), body);
}

struct Rig {
    axtest::TestKey key;
    std::shared_ptr<FakeState> st = std::make_shared<FakeState>();
    std::function<HttpResponse(const HttpRequest&)> poll = [](const HttpRequest&) {
        return json_response(200, R"({"sets":{},"moreAvailable":false})");
    };
    std::string jwks_body;
    long jwks_status = 200;

    Rig() {
        key.kid = axtest::random_secret("kid-", 4);
        jwks_body = key.jwks_json();
    }

    Client client(bool retry = true) {
        st->router = [this](const HttpRequest& req, FakeState&) -> HttpResponse {
            if (req.url == kJwks) return json_response(jwks_status, jwks_body);
            if (req.url.find("/.well-known/ssf-configuration") != std::string::npos) {
                return json_response(200, json{{"issuer", kIssuer}, {"jwks_uri", kJwks}}.dump());
            }
            return poll(req);
        };
        auto c = Client::builder()
                     .base_url(kBase)
                     .tenant_id("6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b")
                     .transport(axtest::make_fake(st))
                     .retry_enabled(retry)
                     .build();
        c._set_retry_test_seams([] { return 0.0; }, [](std::chrono::milliseconds) {});
        return c;
    }

    ssf::SsfReceiverConfig config() const {
        ssf::SsfReceiverConfig cfg;
        cfg.issuer = kIssuer;
        cfg.audience = kAudience;
        cfg.keys = ssf::SsfKeySource::jwks_uri(kJwks);
        cfg.access_token_provider = [] {
            return Sensitive<std::string>(axtest::random_secret("at-"));
        };
        return cfg;
    }

    std::size_t jwks_fetches() { return st->count_path("/oauth2/jwks"); }

    /// The most recent poll request (a JWKS fetch may follow it).
    axtest::RecordedReq last_poll() {
        std::lock_guard<std::mutex> lock(st->mtx);
        for (auto it = st->requests.rbegin(); it != st->requests.rend(); ++it) {
            if (it->url.find("/ssf/v1/poll/") != std::string::npos) return *it;
        }
        return {};
    }
};

std::optional<SetFailureReason> refusal(ssf::SsfReceiver& r, const std::string& set) {
    try {
        r.verify_set(set);
    } catch (const ssf::SetVerificationError& e) {
        return e.reason();
    }
    return std::nullopt;
}

// ── 1. A valid SET ──────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 helper (1): a SET signed by the JWKS key verifies, every field the claim's") {
    Rig rig;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());
    const std::string jti = axtest::random_secret("jti-", 16);

    const auto event = receiver.verify_set(set_for(rig.key, claims(jti)));
    AXIAM_CHECK(event.jti == jti);
    AXIAM_CHECK(event.iat == 1760000000);
    AXIAM_CHECK(event.iss == kIssuer);
    AXIAM_CHECK(json::parse(event.aud_json) == kAudience);
    AXIAM_CHECK(event.txn == std::optional<std::string>("txn-1"));
    AXIAM_CHECK(event.event_type == ssf::event_types::kSessionRevoked);
    AXIAM_CHECK(json::parse(event.event_json).at("initiating_entity") == "admin");
    AXIAM_CHECK(json::parse(event.sub_id_json).at("sub") == "user-1");

    // An array `aud` containing ours, `application/secevent+jwt` in another case,
    // and no txn.
    json body = claims(axtest::random_secret("jti-", 16));
    body["aud"] = json::array({"https://other.example.com", kAudience});
    body.erase("txn");
    json hdr = header(rig.key);
    hdr["typ"] = "Application/SecEvent+JWT";
    const auto second = receiver.verify_set(sign(rig.key, hdr, body));
    AXIAM_CHECK(json::parse(second.aud_json).size() == 2);
    AXIAM_CHECK(!second.txn);
}

AXIAM_TEST("§32.7: the eight event-type URIs are named constants") {
    for (const char* uri : {ssf::event_types::kSessionRevoked, ssf::event_types::kCredentialChange,
                            ssf::event_types::kAssuranceLevelChange,
                            ssf::event_types::kAccountDisabled, ssf::event_types::kAccountEnabled,
                            ssf::event_types::kAccountPurged, ssf::event_types::kVerification,
                            ssf::event_types::kStreamUpdated}) {
        AXIAM_CHECK(std::string(uri).rfind("https://schemas.openid.net/secevent/", 0) == 0);
    }
}

// ── 2. typ and alg ──────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 helper (2): typ absent or JWT is invalid_type; alg none or HS256 is invalid_key") {
    Rig rig;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());
    const json body = claims(axtest::random_secret("jti-", 16));

    json hdr = header(rig.key);
    hdr.erase("typ");
    AXIAM_CHECK(refusal(receiver, sign(rig.key, hdr, body)) == SetFailureReason::kInvalidType);
    hdr["typ"] = "JWT";
    AXIAM_CHECK(refusal(receiver, sign(rig.key, hdr, body)) == SetFailureReason::kInvalidType);
    hdr["typ"] = 5;
    AXIAM_CHECK(refusal(receiver, sign(rig.key, hdr, body)) == SetFailureReason::kInvalidType);

    hdr = header(rig.key);
    hdr["alg"] = "none";
    AXIAM_CHECK(refusal(receiver, sign(rig.key, hdr, body)) == SetFailureReason::kInvalidKey);
    hdr["alg"] = "HS256";
    AXIAM_CHECK(refusal(receiver, sign(rig.key, hdr, body)) == SetFailureReason::kInvalidKey);
    hdr["alg"] = 1;  // a non-string alg is refused, never a JSON library exception
    AXIAM_CHECK(refusal(receiver, sign(rig.key, hdr, body)) == SetFailureReason::kInvalidKey);
    hdr = header(rig.key);
    hdr.erase("kid");
    AXIAM_CHECK(refusal(receiver, sign(rig.key, hdr, body)) == SetFailureReason::kInvalidKey);
    AXIAM_CHECK(rig.jwks_fetches() == 0);  // none of these consulted a key
}

AXIAM_TEST("§32.7 step 1: anything but three base64url JSON parts is malformed") {
    Rig rig;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());
    const std::string good = set_for(rig.key, claims(axtest::random_secret("jti-", 16)));
    const auto parts = good.find('.');
    for (const std::string& bad :
         {std::string("only-one-part"), std::string("a.b"), good + ".extra",
          std::string("!!!.") + good.substr(parts + 1),
          axtest::b64url_encode("[1]") + good.substr(parts),
          good.substr(0, good.rfind('.')) + ".***"}) {
        AXIAM_CHECK(refusal(receiver, bad) == SetFailureReason::kMalformed);
    }
}

// ── 3. The signature ────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 helper (3): another key with the same kid, and a tampered payload, are invalid_key") {
    Rig rig;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());

    axtest::TestKey other;
    other.kid = rig.key.kid;
    AXIAM_CHECK(refusal(receiver, set_for(other, claims(axtest::random_secret("jti-", 16)))) ==
                SetFailureReason::kInvalidKey);

    const std::string good = set_for(rig.key, claims(axtest::random_secret("jti-", 16)));
    json forged = claims(axtest::random_secret("jti-", 16));
    forged["iss"] = "https://evil.example.com";
    const auto first = good.find('.');
    const auto last = good.rfind('.');
    const std::string tampered =
        good.substr(0, first + 1) + axtest::b64url_encode(forged.dump()) + good.substr(last);
    AXIAM_CHECK(refusal(receiver, tampered) == SetFailureReason::kInvalidKey);
}

// ── 4. iss and aud ──────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 helper (4): another iss is invalid_issuer, another aud invalid_audience") {
    Rig rig;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());

    json body = claims(axtest::random_secret("jti-", 16));
    body["iss"] = "https://iam.example.com";
    AXIAM_CHECK(refusal(receiver, set_for(rig.key, body)) == SetFailureReason::kInvalidIssuer);

    for (const json& aud : {json("https://other.example.com"), json::array({"x", 7}), json(5)}) {
        body = claims(axtest::random_secret("jti-", 16));
        body["aud"] = aud;
        AXIAM_CHECK(refusal(receiver, set_for(rig.key, body)) == SetFailureReason::kInvalidAudience);
    }
    body.erase("aud");
    AXIAM_CHECK(refusal(receiver, set_for(rig.key, body)) == SetFailureReason::kInvalidAudience);
}

// ── 5. The claim set ────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 helper (5): exp, sub, two events or a missing jti/iat/sub_id is invalid_request") {
    Rig rig;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());
    const auto with = [&](const std::function<void(json&)>& edit) {
        json body = claims(axtest::random_secret("jti-", 16));
        edit(body);
        return refusal(receiver, set_for(rig.key, body));
    };
    const auto invalid = std::optional<SetFailureReason>(SetFailureReason::kInvalidRequest);
    AXIAM_CHECK(with([](json& b) { b["exp"] = 1; }) == invalid);
    AXIAM_CHECK(with([](json& b) { b["sub"] = "user-1"; }) == invalid);
    AXIAM_CHECK(with([](json& b) { b["events"][ssf::event_types::kAccountPurged] = json::object(); }) ==
                invalid);
    AXIAM_CHECK(with([](json& b) { b["events"] = json::object(); }) == invalid);
    AXIAM_CHECK(with([](json& b) { b["events"] = "x"; }) == invalid);
    AXIAM_CHECK(with([](json& b) { b.erase("events"); }) == invalid);
    AXIAM_CHECK(with([](json& b) { b.erase("jti"); }) == invalid);
    AXIAM_CHECK(with([](json& b) { b["jti"] = ""; }) == invalid);
    AXIAM_CHECK(with([](json& b) { b["jti"] = 3; }) == invalid);
    AXIAM_CHECK(with([](json& b) { b.erase("iat"); }) == invalid);
    AXIAM_CHECK(with([](json& b) { b["iat"] = "now"; }) == invalid);
    AXIAM_CHECK(with([](json& b) { b.erase("sub_id"); }) == invalid);
    AXIAM_CHECK(with([](json& b) { b["sub_id"] = "user-1"; }) == invalid);
}

// ── 6. Replay ───────────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 helper (6): the same SET twice is replayed; a window under seven days is refused") {
    Rig rig;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());
    const std::string set = set_for(rig.key, claims(axtest::random_secret("jti-", 16)));
    receiver.verify_set(set);
    AXIAM_CHECK(refusal(receiver, set) == SetFailureReason::kReplayed);

    // A copy shares the store: it refuses what the original accepted.
    ssf::SsfReceiver copy = receiver;
    AXIAM_CHECK(refusal(copy, set) == SetFailureReason::kReplayed);

    auto cfg = rig.config();
    cfg.replay_window = ssf::kMinReplayWindow - std::chrono::seconds(1);
    AXIAM_REQUIRE_THROWS_AS(ssf::SsfReceiver(client, cfg), std::invalid_argument);
}

AXIAM_TEST("§32.7 step 9: a refused SET records nothing, so its jti stays usable") {
    Rig rig;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());
    const std::string jti = axtest::random_secret("jti-", 16);
    json body = claims(jti);
    body["iss"] = "https://evil.example.com";
    AXIAM_CHECK(refusal(receiver, set_for(rig.key, body)) == SetFailureReason::kInvalidIssuer);
    AXIAM_CHECK(receiver.verify_set(set_for(rig.key, claims(jti))).jti == jti);
}

AXIAM_TEST("§32.7: the memory store forgets after the window; a custom store is used") {
    ssf::MemoryReplayStore store;
    AXIAM_CHECK(store.check_and_record("a", std::chrono::seconds(60)));
    AXIAM_CHECK(!store.check_and_record("a", std::chrono::seconds(60)));
    AXIAM_CHECK(store.check_and_record("b", std::chrono::seconds(0)));
    AXIAM_CHECK(store.check_and_record("b", std::chrono::seconds(0)));  // expired: new again

    struct Refusing : ssf::ReplayStore {
        int calls = 0;
        bool check_and_record(const std::string&, std::chrono::seconds window) override {
            ++calls;
            return window < ssf::kMinReplayWindow;  // false for every window we are given
        }
    };
    Rig rig;
    auto client = rig.client();
    auto custom = std::make_shared<Refusing>();
    auto cfg = rig.config();
    cfg.replay_store = custom;
    cfg.replay_window = ssf::kMinReplayWindow * 2;
    ssf::SsfReceiver receiver(client, cfg);
    AXIAM_CHECK(refusal(receiver, set_for(rig.key, claims(axtest::random_secret("jti-", 16)))) ==
                SetFailureReason::kReplayed);
    AXIAM_CHECK(custom->calls == 1);
}

// ── 7. The JWKS refetch ─────────────────────────────────────────────────────

AXIAM_TEST("§32.8 helper (7): an unknown kid refetches once, then invalid_key; again within the minute, no refetch") {
    Rig rig;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());
    receiver.verify_set(set_for(rig.key, claims(axtest::random_secret("jti-", 16))));
    AXIAM_CHECK(rig.jwks_fetches() == 1);  // primed

    axtest::TestKey stranger;
    stranger.kid = axtest::random_secret("kid-", 4);
    AXIAM_CHECK(refusal(receiver, set_for(stranger, claims(axtest::random_secret("jti-", 16)))) ==
                SetFailureReason::kInvalidKey);
    AXIAM_CHECK(rig.jwks_fetches() == 2);  // exactly one refetch

    stranger.kid = axtest::random_secret("kid-", 4);
    AXIAM_CHECK(refusal(receiver, set_for(stranger, claims(axtest::random_secret("jti-", 16)))) ==
                SetFailureReason::kInvalidKey);
    AXIAM_CHECK(rig.jwks_fetches() == 2);  // inside the minute: none
}

AXIAM_TEST("§32.7 step 4: a rotated key is found by the one refetch") {
    Rig rig;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());
    receiver.verify_set(set_for(rig.key, claims(axtest::random_secret("jti-", 16))));

    axtest::TestKey rotated;
    rotated.kid = axtest::random_secret("kid-", 4);
    rig.jwks_body = json{{"keys",
                          {json::parse(rotated.jwks_json())["keys"][0],
                           {{"kty", "RSA"}, {"kid", "rsa-1"}},
                           {{"kty", "OKP"}, {"crv", "Ed25519"}, {"kid", "short"}, {"x", "AAAA"}},
                           "not-an-object"}}}
                         .dump();
    AXIAM_CHECK(receiver.verify_set(set_for(rotated, claims(axtest::random_secret("jti-", 16))))
                    .event_type == ssf::event_types::kSessionRevoked);
    AXIAM_CHECK(rig.jwks_fetches() == 2);
}

AXIAM_TEST("§32.7: a JWKS fetch failure is a NetworkError, not a verdict on the SET") {
    Rig rig;
    rig.jwks_status = 503;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());
    const std::string set = set_for(rig.key, claims(axtest::random_secret("jti-", 16)));
    // Each failed fetch holds the next one off for a minute (§34.2 P6): step past it.
    auto clock = std::chrono::steady_clock::now();
    receiver._set_clock_for_testing([&clock] { return clock; });
    AXIAM_REQUIRE_THROWS_AS(receiver.verify_set(set), NetworkError);
    rig.jwks_status = 200;
    rig.jwks_body = "not json";
    clock += std::chrono::seconds(61);
    AXIAM_REQUIRE_THROWS_AS(receiver.verify_set(set), NetworkError);
    AXIAM_CHECK(rig.jwks_fetches() == 2);
    rig.jwks_body = R"({"keys":"nope"})";
    clock += std::chrono::seconds(61);
    AXIAM_CHECK(refusal(receiver, set) == SetFailureReason::kInvalidKey);  // fetched, no keys
    AXIAM_CHECK(rig.jwks_fetches() == 4);  // the (empty) fill, then the kid miss's one refetch

    // A transport failure, and the fetch is session-free.
    Rig dropped;
    auto c2 = dropped.client();
    dropped.st->router = [](const HttpRequest&, FakeState&) {
        HttpResponse r;
        r.transport_error = "connection refused";
        return r;
    };
    ssf::SsfReceiver r2(c2, dropped.config());
    AXIAM_REQUIRE_THROWS_AS(r2.verify_set(set), NetworkError);
    AXIAM_CHECK(dropped.st->last().sessionless);
}

AXIAM_TEST("§32.7 step 4, contract 1.59 P6: a failed first JWKS fetch is rate-limited too, so an outage is not one fetch per SET") {
    Rig rig;
    rig.jwks_status = 503;
    auto client = rig.client();
    ssf::SsfReceiver receiver(client, rig.config());
    AXIAM_REQUIRE_THROWS_AS(receiver.verify_set(set_for(rig.key, claims(axtest::random_secret("jti-", 16)))),
                            NetworkError);
    AXIAM_CHECK(rig.jwks_fetches() == 1);

    // Inside the minute: no fetch, and still no verdict (NetworkError, not invalid_key).
    rig.jwks_status = 200;
    for (int i = 0; i < 3; ++i) {
        AXIAM_REQUIRE_THROWS_AS(
            receiver.verify_set(set_for(rig.key, claims(axtest::random_secret("jti-", 16)))),
            NetworkError);
    }
    AXIAM_CHECK(rig.jwks_fetches() == 1);

    // Once the minute has passed, the cache is filled and the SET verifies.
    const auto later = std::chrono::steady_clock::now() + std::chrono::seconds(61);
    receiver._set_clock_for_testing([later] { return later; });
    AXIAM_CHECK(receiver.verify_set(set_for(rig.key, claims(axtest::random_secret("jti-", 16))))
                    .event_type == ssf::event_types::kSessionRevoked);
    AXIAM_CHECK(rig.jwks_fetches() == 2);

    // A successful fill is not "the refetch": an unknown kid right after it still
    // gets its one refetch (§34.2 P6), and a failed refetch also waits the minute.
    Rig cold;
    auto c2 = cold.client();
    ssf::SsfReceiver r2(c2, cold.config());
    axtest::TestKey stranger;
    stranger.kid = axtest::random_secret("kid-", 4);
    cold.jwks_status = 200;
    AXIAM_CHECK(refusal(r2, set_for(stranger, claims(axtest::random_secret("jti-", 16)))) ==
                SetFailureReason::kInvalidKey);
    AXIAM_CHECK(cold.jwks_fetches() == 2);  // the fill, then the one refetch
}

AXIAM_TEST("§32.7: a discovery URL is used for its jwks_uri when its issuer matches") {
    Rig rig;
    auto client = rig.client();
    auto cfg = rig.config();
    cfg.keys = ssf::SsfKeySource::discovery_url(
        "https://iam.example.com/.well-known/ssf-configuration/t/6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b");
    ssf::SsfReceiver receiver(client, cfg);
    receiver.verify_set(set_for(rig.key, claims(axtest::random_secret("jti-", 16))));
    receiver.verify_set(set_for(rig.key, claims(axtest::random_secret("jti-", 16))));
    AXIAM_CHECK(rig.st->count_path("/.well-known/ssf-configuration") == 1);  // resolved once

    // Another issuer, a missing jwks_uri, or a plaintext one: refused.
    for (const json& doc : {json{{"issuer", "https://evil.example.com"}, {"jwks_uri", kJwks}},
                            json{{"issuer", kIssuer}},
                            json{{"issuer", kIssuer}, {"jwks_uri", "http://iam.example.com/jwks"}}}) {
        Rig other;
        auto c = other.client();
        other.st->router = [doc](const HttpRequest&, FakeState&) {
            return json_response(200, doc.dump());
        };
        ssf::SsfReceiver r(c, cfg);
        AXIAM_REQUIRE_THROWS_AS(r.verify_set(set_for(rig.key, claims("j"))), NetworkError);
    }
}

AXIAM_TEST("§32.7: the receiver refuses an incomplete or plaintext configuration") {
    Rig rig;
    auto client = rig.client();
    for (const auto& edit : std::vector<std::function<void(ssf::SsfReceiverConfig&)>>{
             [](ssf::SsfReceiverConfig& c) { c.issuer.clear(); },
             [](ssf::SsfReceiverConfig& c) { c.audience.clear(); },
             [](ssf::SsfReceiverConfig& c) { c.keys = ssf::SsfKeySource::jwks_uri(""); },
             [](ssf::SsfReceiverConfig& c) {
                 c.keys = ssf::SsfKeySource::jwks_uri("http://iam.example.com/oauth2/jwks");
             }}) {
        auto cfg = rig.config();
        edit(cfg);
        AXIAM_REQUIRE_THROWS_AS(ssf::SsfReceiver(client, cfg), std::invalid_argument);
    }
    auto loopback = rig.config();
    loopback.keys = ssf::SsfKeySource::jwks_uri("http://127.0.0.1:8080/oauth2/jwks");
    AXIAM_REQUIRE_NOTHROW(ssf::SsfReceiver(client, loopback));
}

AXIAM_TEST("§32.7: push codes are RFC 8935 codes, and reasons spell as §32.7 names them") {
    using R = SetFailureReason;
    const std::vector<std::tuple<R, std::string, std::string>> table = {
        {R::kMalformed, "malformed", "invalid_request"},
        {R::kInvalidType, "invalid_type", "invalid_request"},
        {R::kInvalidKey, "invalid_key", "invalid_key"},
        {R::kInvalidIssuer, "invalid_issuer", "invalid_issuer"},
        {R::kInvalidAudience, "invalid_audience", "invalid_audience"},
        {R::kInvalidRequest, "invalid_request", "invalid_request"},
        {R::kReplayed, "replayed", "invalid_request"},
    };
    for (const auto& [reason, code, err] : table) {
        AXIAM_CHECK(ssf::reason_code(reason) == code);
        AXIAM_CHECK(ssf::push_error_code(reason) == err);
        AXIAM_CHECK(ssf::SetErr::from_reason(reason).err == err);
        const ssf::SetVerificationError e("m", reason);
        AXIAM_CHECK(e.reason_code() == code && e.push_error_code() == err);
    }
    AXIAM_CHECK(!ssf::SetErr::from_reason(R::kReplayed).description);
}

// ── 8. poll ─────────────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 helper (8): poll sends ack and setErrs exactly as given and returns verified and refused apart") {
    Rig rig;
    const std::string good_jti = axtest::random_secret("jti-", 16);
    const std::string bad_jti = axtest::random_secret("jti-", 16);
    const std::string token = axtest::random_secret("at-");
    std::string good, bad, keyed_wrong;
    rig.poll = [&](const HttpRequest&) {
        json body = claims(bad_jti);
        body["iss"] = "https://evil.example.com";
        return json_response(
            200, json{{"sets",
                       {{good_jti, set_for(rig.key, claims(good_jti))},
                        {bad_jti, set_for(rig.key, body)},
                        {"other-key", set_for(rig.key, claims(axtest::random_secret("jti-", 16)))},
                        {"not-a-string", 5}}},
                      {"moreAvailable", true}}
                     .dump());
    };
    auto client = rig.client();
    auto cfg = rig.config();
    cfg.access_token_provider = [&token] { return Sensitive<std::string>(token); };
    ssf::SsfReceiver receiver(client, cfg);

    ssf::SsfPollOptions options;
    options.max_events = 10;
    options.return_immediately = true;
    options.ack = std::vector<std::string>{"a-1", "a-2"};
    options.set_errs = std::map<std::string, ssf::SetErr>{
        {"e-1", ssf::SetErr::from_reason(SetFailureReason::kInvalidIssuer)},
        {"e-2", ssf::SetErr{"invalid_key", std::string("rotated")}}};
    const auto result = receiver.poll("stream/1", options);

    const auto sent = rig.last_poll();
    AXIAM_CHECK(sent.method == "POST");
    AXIAM_CHECK(sent.url == std::string(kBase) + "/ssf/v1/poll/stream%2F1");
    AXIAM_CHECK(sent.headers.at("Authorization") == "Bearer " + token);
    AXIAM_CHECK(sent.sessionless);
    AXIAM_CHECK(json::parse(sent.body) ==
                json::parse(R"({"maxEvents":10,"returnImmediately":true,"ack":["a-1","a-2"],)"
                            R"("setErrs":{"e-1":{"err":"invalid_issuer"},)"
                            R"("e-2":{"err":"invalid_key","description":"rotated"}}})"));

    AXIAM_REQUIRE(result.events.size() == 1);
    AXIAM_CHECK(result.events[0].jti == good_jti);
    AXIAM_CHECK(result.more_available);
    AXIAM_REQUIRE(result.refused.size() == 3);
    for (const auto& r : result.refused) {
        if (r.jti == bad_jti) AXIAM_CHECK(r.reason == SetFailureReason::kInvalidIssuer);
        else if (r.jti == "other-key") AXIAM_CHECK(r.reason == SetFailureReason::kInvalidRequest);
        else AXIAM_CHECK(r.jti == "not-a-string" && r.reason == SetFailureReason::kMalformed);
    }

    // A second poll with no options sends `{}` — and acknowledged nothing on its own.
    rig.poll = [](const HttpRequest&) { return json_response(200, R"({"sets":{}})"); };
    const auto empty = receiver.poll("stream-1");
    AXIAM_CHECK(rig.last_poll().body == "{}");
    AXIAM_CHECK(empty.events.empty() && empty.refused.empty() && !empty.more_available);
}

/// A store that remembers what it recorded, so a test can ask whether a jti is
/// in it — and that can be told to fail (a store that cannot answer, §34.2 P3).
struct RecordingStore : ssf::ReplayStore {
    std::set<std::string> recorded;
    std::set<std::string> fail_on;
    bool check_and_record(const std::string& jti, std::chrono::seconds) override {
        if (fail_on.count(jti)) throw std::runtime_error("replay store unavailable");
        return recorded.insert(jti).second;
    }
};

AXIAM_TEST("§32.8 helper (8), contract 1.59 P1: a two-SET batch whose second SET's key refetch fails leaves no unreturned jti recorded") {
    Rig rig;
    const std::string first = axtest::random_secret("jti-", 16);
    const std::string second = axtest::random_secret("jti-", 16);
    axtest::TestKey stranger;  // a kid the JWKS does not hold
    stranger.kid = axtest::random_secret("kid-", 4);
    rig.poll = [&](const HttpRequest&) {
        return json_response(200, json{{"sets",
                                        {{first, set_for(rig.key, claims(first))},
                                         {second, set_for(stranger, claims(second))}}}}
                                      .dump());
    };
    auto client = rig.client();
    auto store = std::make_shared<RecordingStore>();
    auto cfg = rig.config();
    cfg.replay_store = store;
    ssf::SsfReceiver receiver(client, cfg);
    // Prime the key cache, then take the JWKS down: the second SET's refetch fails.
    receiver.verify_set(set_for(rig.key, claims(axtest::random_secret("jti-", 16))));
    rig.jwks_status = 503;

    bool first_returned = false;
    std::optional<ssf::SsfPollResult> result;
    try {
        result = receiver.poll("s-1");
        for (const auto& e : result->events) first_returned = first_returned || e.jti == first;
    } catch (const NetworkError&) {
    }
    // The contract's assertion, either form (§34.2 P1).
    AXIAM_CHECK(first_returned || store->recorded.count(first) == 0);
    // And this SDK's form: what was judged is returned, the unjudged SET is in
    // neither list, is not recorded, and is named so the caller can tell.
    AXIAM_REQUIRE(result.has_value());
    AXIAM_CHECK(first_returned && store->recorded.count(first) == 1);
    AXIAM_CHECK(store->recorded.count(second) == 0);
    AXIAM_CHECK(result->refused.empty());
    AXIAM_REQUIRE(result->unjudged.size() == 1);
    AXIAM_CHECK(result->unjudged[0].jti == second);
    AXIAM_CHECK(!result->unjudged[0].error.empty());
}

AXIAM_TEST("§32.7 contract 1.59 P1/P3: a store that cannot answer leaves that SET unjudged, and the earlier ones returned") {
    Rig rig;
    const std::string first = axtest::random_secret("jti-", 16);
    const std::string second = axtest::random_secret("jti-", 16);
    rig.poll = [&](const HttpRequest&) {
        return json_response(200, json{{"sets",
                                        {{first, set_for(rig.key, claims(first))},
                                         {second, set_for(rig.key, claims(second))}}}}
                                      .dump());
    };
    auto client = rig.client();
    auto store = std::make_shared<RecordingStore>();
    store->fail_on.insert(second);
    auto cfg = rig.config();
    cfg.replay_store = store;
    ssf::SsfReceiver receiver(client, cfg);
    const auto result = receiver.poll("s-1");
    AXIAM_REQUIRE(result.events.size() == 1);
    AXIAM_CHECK(result.events[0].jti == first);
    AXIAM_CHECK(result.refused.empty());  // a store failure is no verdict: never `refused`
    AXIAM_REQUIRE(result.unjudged.size() == 1);
    AXIAM_CHECK(result.unjudged[0].jti == second);
    AXIAM_CHECK(store->recorded.count(second) == 0);

    // verify_set alone still raises the failure: it fails closed, never accepts.
    AXIAM_REQUIRE_THROWS_AS(receiver.verify_set(set_for(rig.key, claims(second))), std::runtime_error);
}

AXIAM_TEST("§32.7: poll is never retried on a 400, and is on a 503 (retry enabled)") {
    Rig rig;
    rig.poll = [](const HttpRequest&) {
        return json_response(400, R"({"error":"invalid_request","message":"maxEvents"})");
    };
    auto client = rig.client(/*retry=*/true);
    ssf::SsfReceiver receiver(client, rig.config());
    AXIAM_REQUIRE_THROWS_AS(receiver.poll("s-1"), management::ValidationError);
    AXIAM_CHECK(rig.st->count_path("/ssf/v1/poll/") == 1);

    rig.poll = [](const HttpRequest&) { return json_response(404, ""); };
    AXIAM_REQUIRE_THROWS_AS(receiver.poll("s-1"), management::NotFoundError);
    AXIAM_CHECK(rig.st->count_path("/ssf/v1/poll/") == 2);

    rig.poll = [](const HttpRequest&) { return json_response(503, ""); };
    AXIAM_REQUIRE_THROWS_AS(receiver.poll("s-1"), NetworkError);
    AXIAM_CHECK(rig.st->count_path("/ssf/v1/poll/") == 5);

    int calls = 0;
    rig.poll = [&calls](const HttpRequest&) {
        HttpResponse r;
        if (++calls == 1) {
            r.transport_error = "connection reset";
            return r;
        }
        return json_response(200, R"({"sets":{},"moreAvailable":"yes"})");
    };
    AXIAM_CHECK(!receiver.poll("s-1").more_available);  // transport failure retried, then ok
    AXIAM_CHECK(calls == 2);

    rig.poll = [](const HttpRequest&) {
        HttpResponse r;
        r.transport_error = "connection reset";
        return r;
    };
    AXIAM_REQUIRE_THROWS_AS(receiver.poll("s-1"), NetworkError);
    rig.poll = [](const HttpRequest&) { return json_response(200, "[]"); };
    AXIAM_REQUIRE_THROWS_AS(receiver.poll("s-1"), NetworkError);
}

AXIAM_TEST("§32.7: poll without a provider is a local AuthError; a JWKS failure leaves the SET unjudged") {
    Rig rig;
    auto client = rig.client();
    auto cfg = rig.config();
    cfg.access_token_provider = nullptr;
    ssf::SsfReceiver push_only(client, cfg);
    AXIAM_REQUIRE_THROWS_AS(push_only.poll("s-1"), AuthError);
    AXIAM_CHECK(rig.st->count() == 0);

    rig.jwks_status = 500;
    rig.poll = [&rig](const HttpRequest&) {
        return json_response(200, json{{"sets", {{"j1", set_for(rig.key, claims("j1"))}}}}.dump());
    };
    auto store = std::make_shared<RecordingStore>();
    auto with_store = rig.config();
    with_store.replay_store = store;
    ssf::SsfReceiver receiver(client, with_store);
    const auto result = receiver.poll("s-1");  // §34.2 P1: no throw, no verdict
    AXIAM_CHECK(result.events.empty() && result.refused.empty());
    AXIAM_REQUIRE(result.unjudged.size() == 1);
    AXIAM_CHECK(result.unjudged[0].jti == "j1");
    AXIAM_CHECK(store->recorded.empty());
}

AXIAM_TEST("§32.7: the origin helper splits what it can and refuses the rest") {
    using axiam::detail::origin_of;
    AXIAM_CHECK(origin_of("https://[::1]:8443/x")->host == "::1");
    AXIAM_CHECK(origin_of("https://[::1]:8443/x")->port == 8443);
    AXIAM_CHECK(origin_of("http://[::1]")->port == 80);
    AXIAM_CHECK(origin_of("ftp://h")->port == 0);
    for (const char* bad : {"no-scheme", "://h", "https://", "https://[::1", "https://[::1]x",
                            "https://h:123456", "https://h:8a", "https://u@h/"}) {
        AXIAM_CHECK(!origin_of(bad));
    }
    AXIAM_CHECK(axiam::detail::is_secure_or_loopback(*origin_of("http://localhost:1/")));
    AXIAM_CHECK(!axiam::detail::is_secure_or_loopback(*origin_of("http://h/")));
}

}  // namespace
