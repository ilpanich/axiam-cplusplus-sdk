// CONTRACT.md §32.1–§32.5 (contract 1.56) — the `ssf` management namespace:
// §32.8's six management tests, plus the read-modify-write helper. The
// authorization header is generated at run time.

#include <sstream>
#include <string>
#include <type_traits>

#include <nlohmann/json.hpp>

#include "assert.hpp"
#include "axiam/axiam.hpp"
#include "axiam/management.hpp"
#include "management_json.hpp"
#include "management_test_util.hpp"
#include "secret_util.hpp"

using namespace axiam;
using namespace axiam::management;
using nlohmann::json;

namespace {

const std::string kStreams = "/api/v1/tenants/11111111-1111-4111-8111-111111111111/ssf/streams";
const char* kRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
const char* kPurged = "https://schemas.openid.net/secevent/risc/event-type/account-purged";

json stream_body(const json& extra = json::object()) {
    json body = {{"id", "ffffffff-1111-4111-8111-111111111111"},
                 {"tenant_id", "11111111-1111-4111-8111-111111111111"},
                 {"receiver_client_id", "rp-1"},
                 {"audience", "https://rp.example.com/ssf"},
                 {"description", nullptr},
                 {"delivery_method", "push"},
                 {"endpoint_url", "https://rp.example.com/ssf/push"},
                 {"authorization_header_set", true},
                 {"events_allowed", {kRevoked, kPurged}},
                 {"events_requested", {kRevoked}},
                 {"events_delivered", {kRevoked}},
                 {"subject_format", "iss_sub"},
                 {"status", "enabled"},
                 {"status_reason", nullptr},
                 {"status_actor", "admin"},
                 {"last_verification_at", nullptr},
                 {"created_at", "2026-10-05T00:00:00Z"},
                 {"updated_at", "2026-10-05T00:00:00Z"},
                 {"transmitter_active", true}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

SsfStreamInput input() {
    SsfStreamInput in("rp-1", "https://rp.example.com/ssf", SsfDeliveryMethod::Push,
                      {ssf_event_type::kSessionRevoked});
    in.endpoint_url = "https://rp.example.com/ssf/push";
    return in;
}

template <typename T, typename = void>
struct has_authorization_header : std::false_type {};
template <typename T>
struct has_authorization_header<T, std::void_t<decltype(std::declval<T>().authorization_header)>>
    : std::true_type {};
static_assert(!has_authorization_header<SsfStream>::value, "§32.5: no header on a response");

template <typename E, typename F>
std::string what_of(F&& f) {
    try {
        f();
    } catch (const E& e) {
        return std::string("caught:") + e.what();
    } catch (...) {
        return "other";
    }
    return "none";
}

// ── 1. Replacement ──────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 management (1): update_stream PUTs every member it models and decodes the 200") {
    auto fixture = axtest::mgmt::signed_in(200, stream_body().dump());
    auto body = stream_body().get<SsfStream>().to_input();
    body.description = "payroll RP";
    const auto stream = fixture.client.ssf().update_stream("s-1", body);
    AXIAM_CHECK(stream.receiver_client_id == "rp-1");
    AXIAM_CHECK(fixture.state->last().method == "PUT");
    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == kStreams + "/s-1");
    const auto sent = json::parse(fixture.state->last().body);
    for (const char* member : {"receiver_client_id", "audience", "delivery_method", "events_allowed",
                               "description", "endpoint_url", "events_requested", "subject_format",
                               "status"}) {
        AXIAM_CHECK(sent.contains(member));
    }
    AXIAM_CHECK(!sent.contains("authorization_header"));  // absent keeps the stored one
    AXIAM_CHECK(sent.at("events_allowed") == json({kRevoked, kPurged}));
    // The input cannot be built without its four required members (the R-27 trait
    // test below); built with them, they are always serialized.
    const json bare = input();
    for (const char* m : {"receiver_client_id", "audience", "delivery_method", "events_allowed"}) {
        AXIAM_CHECK(bare.contains(m));
    }
}

// ── 2. The header is Sensitive ──────────────────────────────────────────────

AXIAM_TEST("§32.8 management (2): the header is sent, rendered nowhere, and dropped from a response") {
    const std::string header = "Bearer " + axtest::random_secret("push-");
    auto body = input();
    body.authorization_header = Sensitive<std::string>(header);
    std::ostringstream printed;
    printed << *body.authorization_header << body.authorization_header->to_string();
    AXIAM_CHECK(axtest::no_fragment(printed.str(), header));

    auto fixture = axtest::mgmt::signed_in(
        201, stream_body({{"authorization_header", header}}).dump());
    const auto stream = fixture.client.ssf().create_stream(body);
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("authorization_header") == header);
    const json rendered = stream;
    AXIAM_CHECK(axtest::no_fragment(rendered.dump(), header));
    AXIAM_CHECK(stream.authorization_header_set);
}

// ── 3. Open decoding ────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 management (3): unknown values and an inactive transmitter decode, with or without the reason") {
    auto fixture = axtest::mgmt::signed_in_two(
        200, stream_body({{"status", "suspended"},
                          {"delivery_method", "websocket"},
                          {"subject_format", "opaque"},
                          {"status_actor", "system"},
                          {"events_allowed", {kRevoked, "https://example.com/event/new"}},
                          {"transmitter_active", false},
                          {"transmitter_inactive_reason", "shared issuer"}})
                 .dump(),
        200, stream_body({{"transmitter_active", false}}).dump());
    const auto odd = fixture.client.ssf().get_stream("s-1");
    AXIAM_CHECK(odd.status == SsfStreamStatus::Unknown);
    AXIAM_CHECK(odd.delivery_method == SsfDeliveryMethod::Unknown);
    AXIAM_CHECK(odd.subject_format == SsfSubjectFormat::Unknown);
    AXIAM_CHECK(odd.status_actor == SsfStatusActor::Unknown);
    // §32.2: event types are strings, so an unlisted URI decodes as ITSELF.
    AXIAM_CHECK(odd.events_allowed.at(1) == "https://example.com/event/new");
    AXIAM_CHECK(!is_known_ssf_event_type(odd.events_allowed.at(1)));
    AXIAM_CHECK(!odd.transmitter_active &&
                odd.transmitter_inactive_reason == std::optional<std::string>("shared issuer"));
    const auto plain = fixture.client.ssf().get_stream("s-1");
    AXIAM_CHECK(!plain.transmitter_active && !plain.transmitter_inactive_reason);
    AXIAM_CHECK(std::string(ssf_event_type::kSessionRevoked) == kRevoked);
}

// ── 4. Pagination ───────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 management (4): list_streams pages with total and search on every request") {
    const auto page = [](bool items) {
        return json{{"items", items ? json::array({stream_body()}) : json::array()},
                    {"total", 1}, {"offset", 0}, {"limit", 1}}
            .dump();
    };
    auto fixture = axtest::mgmt::signed_in_two(200, page(true), 200, page(false));
    PageRequest request;
    request.limit = 1;
    request.search = "payroll";
    const auto first = fixture.client.ssf().list_streams(request);
    AXIAM_CHECK(first.total == 1 && first.size() == 1);
    AXIAM_CHECK(axtest::mgmt::query_of(fixture.state->last().url).find("search=payroll") != std::string::npos);
    const auto second = fixture.client.ssf().list_streams(first.next_request());
    AXIAM_CHECK(second.empty());
    AXIAM_CHECK(axtest::mgmt::query_of(fixture.state->last().url).find("search=payroll") != std::string::npos);
}

// ── 5. No retry ─────────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 management (5): the three writes are each sent once on a 503") {
    auto fixture = axtest::mgmt::signed_in_many({{503, ""}, {503, ""}, {503, ""}});
    auto s = fixture.client.ssf();  // retry ENABLED
    const auto before = fixture.state->count();
    int network = 0;
    const auto count = [&](const std::string& o) { network += o.rfind("caught:", 0) == 0; };
    count(what_of<NetworkError>([&] { s.create_stream(input()); }));
    count(what_of<NetworkError>([&] { s.update_stream("s-1", input()); }));
    count(what_of<NetworkError>([&] { s.delete_stream("s-1"); }));
    AXIAM_CHECK(network == 3);
    AXIAM_CHECK(fixture.state->count() - before == 3);
}

// ── 6. Errors ───────────────────────────────────────────────────────────────

AXIAM_TEST("§32.8 management (6): 400 with the message, 409, 404 and 401 map per §2") {
    auto fixture = axtest::mgmt::signed_in_many(
        {{400, R"({"error":"validation_error","message":"endpoint_url: not https"})"},
         {409, R"({"error":"conflict","message":"audience"})"},
         {404, R"({"error":"not_found","message":"none"})"},
         {401, R"({"error":"unauthorized"})"}});
    auto s = fixture.client.ssf();
    AXIAM_CHECK(what_of<ValidationError>([&] { s.update_stream("s-1", input()); })
                    .find("endpoint_url: not https") != std::string::npos);
    AXIAM_CHECK(what_of<ConflictError>([&] { s.create_stream(input()); }).rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<NotFoundError>([&] { s.get_stream("s-1"); }).rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<AuthError>([&] { s.list_streams(); }).rfind("caught:", 0) == 0);
}

// Contract 1.59 §34.2 P12.2 (R-22), 1.60 (a): "MUST NOT send a value it does not know"
// binds the request path. A value decoded as unknown -- an open enum's Unknown -- is refused
// LOCALLY, before any request, never sent as "" for the server to refuse, and the refusal is
// the SDK's validation error: std::invalid_argument in C++, not a bare NetworkError (B5).
AXIAM_TEST("§32.2 / P12.2 (R-22, B5): a read-modify-write carrying a value this SDK does not know is refused locally with std::invalid_argument") {
    auto fixture = axtest::mgmt::signed_in(200, stream_body().dump());
    const auto before = fixture.state->count();
    auto s = fixture.client.ssf();

    const auto new_method =
        stream_body({{"delivery_method", "websocket"}}).get<SsfStream>().to_input();
    AXIAM_CHECK(what_of<std::invalid_argument>([&] { s.update_stream("s-1", new_method); })
                    .rfind("caught:", 0) == 0);
    AXIAM_CHECK(fixture.state->count() == before);  // no request reached the wire
    const auto new_status = stream_body({{"status", "suspended"}}).get<SsfStream>().to_input();
    AXIAM_CHECK(what_of<std::invalid_argument>([&] { s.create_stream(new_status); })
                    .rfind("caught:", 0) == 0);
    AXIAM_CHECK(fixture.state->count() == before);

    // Never a bare NetworkError (B5): a caller catching the §2 transport type does not see a
    // local refusal, and a caller catching the validation type does.
    bool network_error = false;
    try {
        s.update_stream("s-1", new_method);
    } catch (const NetworkError&) {
        network_error = true;
    } catch (const std::invalid_argument&) {
    }
    AXIAM_CHECK(!network_error);

    // Rendering an unknown value for a log line never fails.
    AXIAM_REQUIRE_NOTHROW(to_wire(SsfDeliveryMethod::Unknown));
    AXIAM_CHECK(to_wire(SsfDeliveryMethod::Unknown).empty());
}

// Contract 1.60 B4 / §34.2 P12.2 (b): event types are sent as the strings the caller holds.
// An event-type URI this SDK has never seen, READ from the server, decodes with its value and
// is sent back unchanged on update_stream -- the server judging it. This SDK keeps no
// client-side list that refuses a URI the caller typed (such a list goes stale), so there is
// no refusal to document.
AXIAM_TEST("§32.2 / P12.2 (b) (B4): an unseen event-type URI read from the server is sent back unchanged on update_stream") {
    const std::string unseen = "https://example.com/event/new";
    auto fixture = axtest::mgmt::signed_in_many(
        {{200, stream_body({{"events_allowed", {kRevoked, unseen}},
                            {"events_requested", {unseen}},
                            {"events_delivered", {unseen}}})
                   .dump()},
         {200, stream_body().dump()},
         {200, stream_body().dump()}});
    auto s = fixture.client.ssf();
    const auto read = s.get_stream("s-1");
    AXIAM_REQUIRE(read.events_allowed.size() == 2);
    AXIAM_CHECK(read.events_allowed[1] == unseen);  // decoded with its value, not as Unknown

    s.update_stream("s-1", read.to_input());
    const auto last = fixture.state->last();
    AXIAM_CHECK(last.method == "PUT");
    const auto sent = json::parse(last.body);
    AXIAM_CHECK(sent.at("events_allowed") == json::array({kRevoked, unseen}));  // unchanged
    AXIAM_CHECK(sent.at("events_requested") == json::array({unseen}));

    // A URI the caller types is sent as typed as well; the server judges it.
    auto typed = read.to_input();
    typed.events_allowed = {"urn:example:typed-by-the-caller"};
    s.update_stream("s-1", typed);
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("events_allowed") ==
                json::array({"urn:example:typed-by-the-caller"}));
}

AXIAM_TEST("§32.2: SsfStream::to_input() keeps every member but the header") {
    const auto in = stream_body({{"status", "paused"}, {"status_reason", "maintenance"}})
                        .get<SsfStream>()
                        .to_input();
    AXIAM_CHECK(!in.authorization_header && !in.clear_authorization_header);
    AXIAM_CHECK(in.status == std::optional<SsfStreamStatus>(SsfStreamStatus::Paused));
    AXIAM_CHECK(in.status_reason == std::optional<std::string>("maintenance"));
    AXIAM_CHECK(in.events_requested->size() == 1);
    AXIAM_CHECK(in.subject_format == std::optional<SsfSubjectFormat>(SsfSubjectFormat::IssSub));
}

// Contract 1.59 R-27: "the input cannot be built without" its required members is
// a compile-time property in C++ -- a constructor taking every required member, in
// the contract's order, and no public default constructor. Checked as traits so a
// regression reads as a failed check rather than as a test that no longer builds.
AXIAM_TEST("§32.8 management (1) (R-27): SsfStreamInput cannot be built without receiver_client_id, audience, delivery_method and events_allowed") {
    AXIAM_CHECK(!std::is_default_constructible<SsfStreamInput>::value);
    AXIAM_CHECK((!std::is_constructible<SsfStreamInput, std::string, std::string, SsfDeliveryMethod>::value));
    AXIAM_CHECK((std::is_constructible<SsfStreamInput, std::string, std::string, SsfDeliveryMethod, std::vector<SsfEventType>>::value));
}

}  // namespace
