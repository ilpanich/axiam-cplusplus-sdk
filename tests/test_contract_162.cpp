// CONTRACT.md §34.6 (contract 1.62) -- the items that are not the `network` namespace:
//
//   (e) / §32.8 test 7  the change-taking read-modify-write form for a stream, and the plain
//                       converter's documented duty;
//   (h)                 the three meanings of `events_requested` at the `update_stream` call site;
//   (f)                 an assigned `null` on `user_id` / `expected_updated_at` is "none": the key
//                       is omitted and `null` is never sent;
//   (g)                 `expected_updated_at` is the server's own string;
//   (i)                 the request `user_id` is an untyped string.
//
// (f), (g) and (i) already held in this SDK -- `std::optional` has no `null` to send, the stream's
// `updated_at` is a string, and no request `user_id` is a UUID type -- so the tests here pin that
// they keep holding.

#include <fstream>
#include <sstream>
#include <string>
#include <type_traits>

#include <nlohmann/json.hpp>

#include "assert.hpp"
#include "axiam/axiam.hpp"
#include "axiam/management.hpp"
#include "management_json.hpp"
#include "management_test_util.hpp"

#ifndef AXIAM_REPO_ROOT
#error "AXIAM_REPO_ROOT must be defined by the build (see tests/CMakeLists.txt)."
#endif

using namespace axiam;
using namespace axiam::management;
using nlohmann::json;

namespace {

const char* kRevoked = ssf_event_type::kSessionRevoked;
const char* kCredential = ssf_event_type::kCredentialChange;
const char* kPurged = ssf_event_type::kAccountPurged;

json stream_body(const json& extra = json::object()) {
    json body = {{"id", "ffffffff-1111-4111-8111-111111111111"},
                 {"tenant_id", "11111111-1111-4111-8111-111111111111"},
                 {"receiver_client_id", "rp-1"},
                 {"audience", "https://rp.example.com/ssf"},
                 {"description", nullptr},
                 {"delivery_method", "push"},
                 {"endpoint_url", "https://rp.example.com/ssf/push"},
                 {"authorization_header_set", true},
                 {"events_allowed", {kRevoked, kCredential, kPurged}},
                 {"events_requested", {kRevoked, kPurged}},
                 {"events_delivered", {kRevoked, kPurged}},
                 {"subject_format", "iss_sub"},
                 {"status", "enabled"},
                 {"status_reason", nullptr},
                 {"status_actor", "admin"},
                 {"last_verification_at", nullptr},
                 {"created_at", "2026-10-05T00:00:00Z"},
                 {"updated_at", "2026-10-05T00:00:00.123456789+00:00"},
                 {"transmitter_active", true}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

std::string read_repo_file(const std::string& relative) {
    std::ifstream in(std::string(AXIAM_REPO_ROOT) + "/" + relative, std::ios::binary);
    std::ostringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

// ---- (e) the change-taking form, §32.8 test 7 -----------------------------------------------------------

AXIAM_TEST("§32.8 mgmt (7): lowering events_allowed cuts events_requested to the new ceiling, in its order") {
    const auto read = stream_body().get<SsfStream>();
    SsfStreamChanges changes;
    changes.events_allowed = std::vector<SsfEventType>{kRevoked};

    const auto in = read.to_input(changes);

    AXIAM_REQUIRE(in.events_requested.has_value());
    AXIAM_CHECK(*in.events_requested == std::vector<SsfEventType>({kRevoked}));
    AXIAM_CHECK(in.events_allowed == std::vector<SsfEventType>({kRevoked}));

    // The order of the read list is kept: [revoked, purged] cut to {purged, revoked} stays in
    // the READ order, not the ceiling's.
    SsfStreamChanges reordered;
    reordered.events_allowed = std::vector<SsfEventType>{kPurged, kRevoked};
    const auto both = read.to_input(reordered);
    AXIAM_CHECK(*both.events_requested == std::vector<SsfEventType>({kRevoked, kPurged}));

    // A ceiling that leaves none of them: [] -- the receiver's "none" -- and never omitted
    // (omitting would widen the stream to every allowed event).
    SsfStreamChanges disjoint;
    disjoint.events_allowed = std::vector<SsfEventType>{kCredential};
    const auto none = read.to_input(disjoint);
    AXIAM_REQUIRE(none.events_requested.has_value());
    AXIAM_CHECK(none.events_requested->empty());

    // On the wire: the cut list, as an array.
    auto fixture = axtest::mgmt::signed_in(200, stream_body().dump());
    fixture.client.ssf().update_stream("s-1", in);
    const auto sent = json::parse(fixture.state->last().body);
    AXIAM_CHECK(sent.at("events_requested") == json::array({kRevoked}));
    AXIAM_CHECK(sent.at("events_allowed") == json::array({kRevoked}));
}

AXIAM_TEST("§32.8 mgmt (7): a change that touches no events sends events_requested as read, [] as [], and expected_updated_at as the response's own string byte for byte") {
    // A fixture whose updated_at carries a `+00:00` offset and nine fraction digits.
    const std::string at = "2026-10-05T00:00:00.123456789+00:00";
    const auto read = stream_body({{"updated_at", at}}).get<SsfStream>();
    SsfStreamChanges changes;
    changes.status = SsfStreamStatus::Paused;
    changes.description = std::optional<std::string>("paused for the audit");

    const auto in = read.to_input(changes);
    AXIAM_CHECK(in.status == std::optional<SsfStreamStatus>(SsfStreamStatus::Paused));
    AXIAM_CHECK(in.description == std::optional<std::string>("paused for the audit"));
    AXIAM_CHECK(*in.events_requested == std::vector<SsfEventType>({kRevoked, kPurged}));
    AXIAM_CHECK(in.events_allowed == std::vector<SsfEventType>({kRevoked, kCredential, kPurged}));
    AXIAM_CHECK(in.expected_updated_at == std::optional<std::string>(at));

    auto fixture = axtest::mgmt::signed_in_three(200, stream_body().dump(), 200, stream_body().dump(),
                                                 200, stream_body().dump());
    fixture.client.ssf().update_stream("s-1", in);
    auto sent = json::parse(fixture.state->last().body);
    AXIAM_CHECK(sent.at("expected_updated_at").get<std::string>() == at);  // never re-rendered
    AXIAM_CHECK(sent.at("events_requested") == json::array({kRevoked, kPurged}));

    // A receiver's "none" goes back as [].
    const auto empty = stream_body({{"events_requested", json::array()}}).get<SsfStream>();
    SsfStreamChanges ceiling;
    ceiling.events_allowed = std::vector<SsfEventType>{kRevoked};
    for (const auto& body : {empty.to_input(SsfStreamChanges{}), empty.to_input(ceiling)}) {
        fixture.client.ssf().update_stream("s-1", body);
        sent = json::parse(fixture.state->last().body);
        AXIAM_CHECK(sent.contains("events_requested"));
        AXIAM_CHECK(sent.at("events_requested") == json::array());
    }
}

AXIAM_TEST("§32.8 mgmt (7): an assigned null for expected_updated_at leaves the key out; one the caller names is sent as given") {
    const auto read = stream_body().get<SsfStream>();

    SsfStreamChanges none;
    none.expected_updated_at = std::optional<std::string>{};  // an assigned null: "none"
    const auto unconditional = read.to_input(none);
    AXIAM_CHECK(!unconditional.expected_updated_at.has_value());

    auto fixture = axtest::mgmt::signed_in(200, stream_body().dump());
    fixture.client.ssf().update_stream("s-1", unconditional);
    const auto sent = json::parse(fixture.state->last().body);
    AXIAM_CHECK(!sent.contains("expected_updated_at"));  // omitted, and in particular not null
    for (auto it = sent.begin(); it != sent.end(); ++it) AXIAM_CHECK(!it.value().is_null());

    // Named by the caller: as given, whatever the read said.
    SsfStreamChanges named;
    named.expected_updated_at = std::optional<std::string>("2026-10-06T00:00:00Z");
    AXIAM_CHECK(read.to_input(named).expected_updated_at == std::optional<std::string>("2026-10-06T00:00:00Z"));

    // An events_requested the caller names is sent as given even when it lowers the ceiling at
    // the same time: the server judges it (and refuses 400 one outside events_allowed).
    SsfStreamChanges explicit_list;
    explicit_list.events_allowed = std::vector<SsfEventType>{kRevoked};
    explicit_list.events_requested = std::vector<SsfEventType>{kPurged};
    AXIAM_CHECK(*read.to_input(explicit_list).events_requested == std::vector<SsfEventType>({kPurged}));
    SsfStreamChanges explicit_none;
    explicit_none.events_requested = std::vector<SsfEventType>{};
    AXIAM_CHECK(read.to_input(explicit_none).events_requested->empty());

    // The plain converter is still there and unchanged: it sends the stream back as read.
    const auto plain = read.to_input();
    AXIAM_CHECK(plain.expected_updated_at == std::optional<std::string>(read.updated_at));
    AXIAM_CHECK(*plain.events_requested == std::vector<SsfEventType>({kRevoked, kPurged}));
}

AXIAM_TEST("§32.8 mgmt (7): the change-taking form leaves the authorization header absent unless the changes set it, and never copies one from a read") {
    const auto read = stream_body().get<SsfStream>();
    const auto in = read.to_input(SsfStreamChanges{});
    AXIAM_CHECK(!in.authorization_header.has_value());
    AXIAM_CHECK(!in.clear_authorization_header.has_value());

    SsfStreamChanges changes;
    changes.clear_authorization_header = true;
    AXIAM_CHECK(read.to_input(changes).clear_authorization_header == std::optional<bool>(true));
}

// ---- (h) the call-site text: a documentation check, not a mock ------------------------------------------------

AXIAM_TEST("§32.8 mgmt (7) / (h): the update_stream documentation states the three meanings of events_requested") {
    const std::string header = read_repo_file("include/axiam/management.hpp");
    const auto at = header.find("SsfStream update_stream(");
    AXIAM_REQUIRE(at != std::string::npos);
    // The doc comment sits directly above the declaration: take the block before it.
    const auto start = header.rfind("/// `PUT /api/v1/tenants/{tenant_id}/ssf/streams/{stream_id}`", at);
    AXIAM_REQUIRE(start != std::string::npos);
    std::string doc = header.substr(start, at - start);
    // Doxygen continuation markers are not part of the sentences being checked.
    std::string flat;
    for (std::size_t i = 0; i < doc.size(); ++i) {
        if (doc[i] == '\n') {
            flat += ' ';
            while (i + 1 < doc.size() && (doc[i + 1] == ' ' || doc[i + 1] == '/')) ++i;
        } else {
            flat += doc[i];
        }
    }
    AXIAM_CHECK(flat.find("three meanings of `events_requested`") != std::string::npos);
    AXIAM_CHECK(flat.find("absent") != std::string::npos);
    AXIAM_CHECK(flat.find("resets") != std::string::npos);
    AXIAM_CHECK(flat.find("every event of `events_allowed`") != std::string::npos);
    AXIAM_CHECK(flat.find("`{}`") != std::string::npos);
    AXIAM_CHECK(flat.find("none") != std::string::npos);
    AXIAM_CHECK(flat.find("stored as given") != std::string::npos);
    AXIAM_CHECK(flat.find("refused `400`") != std::string::npos);
    AXIAM_CHECK(flat.find("outside `events_allowed`") != std::string::npos);
    AXIAM_CHECK(flat.find("omitted optional member takes its default") != std::string::npos);
    AXIAM_CHECK(flat.find("raw API client") != std::string::npos);
    AXIAM_CHECK(flat.find("SsfStreamChanges") != std::string::npos);

    // And the plain converter's doc names the caller's duty, with the three meanings and the 409.
    const auto models = read_repo_file("include/axiam/management_models.hpp");
    const auto plain = models.find("The PLAIN converter");
    AXIAM_REQUIRE(plain != std::string::npos);
    std::string converter = models.substr(plain, 1600);
    std::string flat2;
    for (std::size_t i = 0; i < converter.size(); ++i) {
        if (converter[i] == '\n') {
            flat2 += ' ';
            while (i + 1 < converter.size() && (converter[i + 1] == ' ' || converter[i + 1] == '/')) ++i;
        } else {
            flat2 += converter[i];
        }
    }
    AXIAM_CHECK(flat2.find("caller's duty") != std::string::npos);
    AXIAM_CHECK(flat2.find("cutting `events_requested` to the new `events_allowed` is yours") !=
                std::string::npos);
    AXIAM_CHECK(flat2.find("`409`") != std::string::npos);
}

// ---- (f) an assigned null is "none" ---------------------------------------------------------------------------

AXIAM_TEST("§27.11 rule 5 (f): an unset or reset user_id and expected_updated_at are omitted, and null is never sent") {
    // `std::optional` has no null to send: assigning std::nullopt IS "none".
    CreateCertificateRequest generate{};
    generate.user_id = "11111111-1111-4111-8111-111111111111";
    generate.user_id = std::nullopt;  // an explicitly assigned null
    AXIAM_CHECK(!json(generate).contains("user_id"));

    SignCertificateCsrRequest sign{};
    sign.user_id = "x";
    sign.user_id = std::nullopt;
    AXIAM_CHECK(!json(sign).contains("user_id"));

    SsfStreamInput stream("rp-1", "https://rp.example.com/ssf", SsfDeliveryMethod::Push, {kRevoked});
    stream.expected_updated_at = "2026-10-05T00:00:00Z";
    stream.expected_updated_at = std::nullopt;
    const json wire = stream;
    AXIAM_CHECK(!wire.contains("expected_updated_at"));
    for (auto it = wire.begin(); it != wire.end(); ++it) AXIAM_CHECK(!it.value().is_null());

    // scim_targets.update (the second operation §34.6 (f) names).
    ScimTargetInput target("n", "https://idp.example.com/scim/v2", ScimTargetAuth::bearer(),
                           ScimTargetScope::all_users());
    target.expected_updated_at = "2026-10-05T00:00:00Z";
    target.expected_updated_at = std::nullopt;
    AXIAM_CHECK(!json(target).contains("expected_updated_at"));
}

// ---- (g) the server's own string -------------------------------------------------------------------------------

AXIAM_TEST("§32.2 (g): updated_at is the server's own string -- the type holds no date to re-render") {
    static_assert(std::is_same_v<decltype(SsfStream::updated_at), std::string>,
                  "§32.2: SsfStream::updated_at is the response's own string");
    static_assert(std::is_same_v<decltype(SsfStreamInput::expected_updated_at), std::optional<std::string>>,
                  "§32.2: expected_updated_at is sent as the string the caller holds");
    static_assert(std::is_same_v<decltype(ScimTargetResponse::updated_at), std::string>, "");
    static_assert(std::is_same_v<decltype(ScimTargetInput::expected_updated_at), std::optional<std::string>>, "");

    // A timestamp rounded to fewer digits than the server stored does not match: every spelling
    // survives the round trip untouched.
    for (const char* spelling : {"2026-10-05T02:00:00.123456789+02:00", "2026-10-05T00:00:00Z",
                                 "2026-10-05T00:00:00.5+00:00", "2026-10-05T00:00:00.000000Z"}) {
        const auto in = stream_body({{"updated_at", spelling}}).get<SsfStream>().to_input();
        AXIAM_CHECK(in.expected_updated_at == std::optional<std::string>(spelling));
        AXIAM_CHECK(json(in).at("expected_updated_at") == spelling);
    }
}

// ---- (i) the request user_id is an untyped string -----------------------------------------------------------------

AXIAM_TEST("§27.11 rule 5 (i): the request user_id is an untyped string -- a malformed value reaches the server and its 400 is surfaced; the response user_id is typed as the language types it") {
    static_assert(std::is_same_v<decltype(CreateCertificateRequest::user_id), std::optional<std::string>>, "");
    static_assert(std::is_same_v<decltype(SignCertificateCsrRequest::user_id), std::optional<std::string>>, "");

    auto fixture = axtest::mgmt::signed_in(
        400, R"({"error":"validation_error","message":"user_id: not a valid UUID"})");
    CreateCertificateRequest body{};
    body.user_id = "not-a-uuid";
    bool surfaced = false;
    try {
        fixture.client.certificates().generate(body);
    } catch (const ValidationError& e) {
        surfaced = std::string(e.what()).find("user_id: not a valid UUID") != std::string::npos;
    }
    AXIAM_CHECK(surfaced);
    // The malformed value was sent, not refused locally.
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("user_id") == "not-a-uuid");

    // The response member is the server's string too, decoded without a UUID check: this SDK
    // types no UUID, so "typed where the language types it" is a string here.
    static_assert(std::is_same_v<decltype(Certificate::user_id), std::optional<std::string>>, "");
}

}  // namespace
