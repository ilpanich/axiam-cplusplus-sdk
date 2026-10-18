// CONTRACT.md §36 (contract 1.62) -- the `network` management namespace: §36.8's five required
// tests, against a mocked HTTP server. The twelve operations, their versions, their closed
// bodies, open decoding and the error mapping; and the one route that is NOT here, the RADIUS
// decision (§36.11), which no handle reaches.

#include <fstream>
#include <set>
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

const char* kSeg = "aaaaaaaa-1111-4111-8111-111111111111";
const char* kTenant = "11111111-1111-4111-8111-111111111111";

json segment_body(const json& extra = json::object()) {
    json body = {{"id", kSeg},
                 {"tenant_id", kTenant},
                 {"path", "/network/zones/default/staff"},
                 {"name", "staff"},
                 {"site_key", "default"},
                 {"kind", "access"},
                 {"vlan_id", 110},
                 {"filter_ids", {"staff-filter"}},
                 {"rank", 1},
                 {"enabled", true},
                 {"version", 3},
                 {"created_by", "cccccccc-1111-4111-8111-111111111111"},
                 {"updated_by", "cccccccc-1111-4111-8111-111111111111"},
                 {"created_at", "2026-10-16T08:00:00Z"},
                 {"updated_at", "2026-10-16T08:00:00Z"}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

json profile_body(const json& extra = json::object()) {
    json body = {{"segment_id", kSeg},
                 {"tenant_id", kTenant},
                 {"dictionary", "axiam-radius-reply/1"},
                 {"session_timeout_secs", 3600},
                 {"session_timeout_clamped", false},
                 {"termination_action", "radius_request"},
                 {"idle_timeout_secs", 600},
                 {"filter_id", "staff-filter"},
                 {"service_type", "framed_user"},
                 {"version", 2},
                 {"created_by", "cccccccc-1111-4111-8111-111111111111"},
                 {"updated_by", "cccccccc-1111-4111-8111-111111111111"},
                 {"created_at", "2026-10-16T08:00:00Z"},
                 {"updated_at", "2026-10-16T08:00:00Z"}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

json policy_body(const json& extra = json::object()) {
    json body = {{"tenant_id", kTenant}, {"session_timeout_max_secs", 3600}, {"version", 0}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

json page_of(const json& item) {
    return {{"items", json::array({item})}, {"total", 1}, {"offset", 0}, {"limit", 1}};
}

NetworkReplyProfileInput profile_input() {
    NetworkReplyProfileInput in;
    in.session_timeout_secs = 3600;
    return in;
}

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

bool caught(const std::string& s) { return s.rfind("caught:", 0) == 0; }

std::string read_repo_file(const std::string& relative) {
    std::ifstream in(std::string(AXIAM_REPO_ROOT) + "/" + relative, std::ios::binary);
    std::ostringstream buf;
    buf << in.rdbuf();
    return buf.str();
}

std::set<std::string> keys_of(const json& j) {
    std::set<std::string> out;
    for (auto it = j.begin(); it != j.end(); ++it) out.insert(it.key());
    return out;
}

using Keys = std::set<std::string>;

// -- 1. The surface -------------------------------------------------------------------

AXIAM_TEST("§36.8 (1): the twelve operations are on the network handle with the paths and methods of §36.1") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page_of(segment_body()).dump()},   // list_segments
        {201, segment_body().dump()},            // create_segment
        {200, segment_body().dump()},            // get_segment
        {200, segment_body().dump()},            // replace_segment
        {204, ""},                               // delete_segment
        {200, page_of(profile_body()).dump()},   // list_profiles
        {201, profile_body().dump()},            // create_profile
        {200, profile_body().dump()},            // get_profile
        {200, profile_body().dump()},            // replace_profile
        {204, ""},                               // delete_profile
        {200, policy_body().dump()},             // get_policy
        {200, policy_body({{"version", 1}}).dump()},  // replace_policy
    });
    auto n = fixture.client.network();

    struct Seen {
        std::string method, path, query;
    };
    std::vector<Seen> seen;
    const auto note = [&] {
        const auto r = fixture.state->last();
        seen.push_back({r.method, axtest::mgmt::path_of(r.url), axtest::mgmt::query_of(r.url)});
    };

    n.list_segments();
    note();
    CreateNetworkSegmentRequest create_segment;
    create_segment.kind = NetworkSegmentKind::Access;
    create_segment.site_key = "default";
    create_segment.name = "staff";
    create_segment.vlan_id = 110;
    create_segment.rank = 1;
    n.create_segment(create_segment);
    note();
    n.get_segment(kSeg);
    note();
    n.replace_segment(kSeg, ReplaceNetworkSegmentRequest(3, 110, {"staff-filter"}, true));
    note();
    n.delete_segment(kSeg, 3);
    note();
    n.list_profiles();
    note();
    n.create_profile(CreateNetworkReplyProfileRequest{profile_input(), kSeg, 3});
    note();
    n.get_profile(kSeg);
    note();
    n.replace_profile(kSeg, ReplaceNetworkReplyProfileRequest(2, 3, profile_input()));
    note();
    n.delete_profile(kSeg, 2);
    note();
    n.get_policy();
    note();
    n.replace_policy(ReplaceNetworkPolicyRequest(3600, 0));
    note();

    const std::string segs = "/api/v1/network/segments";
    const std::string profs = "/api/v1/network/profiles";
    const std::string seg = segs + "/" + kSeg;
    const std::string prof = profs + "/" + kSeg;
    AXIAM_REQUIRE(seen.size() == 12);
    AXIAM_CHECK(seen[0].method == "GET" && seen[0].path == segs);
    AXIAM_CHECK(seen[1].method == "POST" && seen[1].path == segs);
    AXIAM_CHECK(seen[2].method == "GET" && seen[2].path == seg);
    AXIAM_CHECK(seen[3].method == "PUT" && seen[3].path == seg);
    AXIAM_CHECK(seen[4].method == "DELETE" && seen[4].path == seg && seen[4].query == "version=3");
    AXIAM_CHECK(seen[5].method == "GET" && seen[5].path == profs);
    AXIAM_CHECK(seen[6].method == "POST" && seen[6].path == profs);
    AXIAM_CHECK(seen[7].method == "GET" && seen[7].path == prof);
    AXIAM_CHECK(seen[8].method == "PUT" && seen[8].path == prof);
    AXIAM_CHECK(seen[9].method == "DELETE" && seen[9].path == prof && seen[9].query == "version=2");
    AXIAM_CHECK(seen[10].method == "GET" && seen[10].path == "/api/v1/network/policy");
    AXIAM_CHECK(seen[11].method == "PUT" && seen[11].path == "/api/v1/network/policy");

    // The tenant is the token's: no path of the namespace carries a tenant id (§36.1).
    for (const auto& s : seen) AXIAM_CHECK(s.path.find("/tenants/") == std::string::npos);

    // client.network() and client.management().network() are the same route (§27.2 rule 4).
    auto again = axtest::mgmt::signed_in(200, policy_body().dump());
    again.client.management().network().get_policy();
    AXIAM_CHECK(axtest::mgmt::path_of(again.state->last().url) == "/api/v1/network/policy");
}

AXIAM_TEST("§36.8 (1): no method reaches POST /api/v1/network/decide, and the registry excludes it") {
    // The decision route is FreeRADIUS's, over mutual TLS, with a token bound to its own
    // certificate (§36.11). The generated sources are what keep it out; so is the registry.
    for (const char* file : {"src/management_ops.cpp", "include/axiam/management.hpp"}) {
        const std::string text = read_repo_file(file);
        AXIAM_REQUIRE(!text.empty());
        AXIAM_CHECK(text.find("network/decide") == std::string::npos);
    }
    const auto registry = json::parse(read_repo_file("management-registry.json"));
    AXIAM_CHECK(registry.at("excluded_operations").contains("POST /api/v1/network/decide"));
    const auto& ops = registry.at("namespaces").at("network").at("operations");
    AXIAM_CHECK(ops.size() == 12);
    for (auto it = ops.begin(); it != ops.end(); ++it) {
        AXIAM_CHECK(it.value().at("path").get<std::string>().find("decide") == std::string::npos);
    }
    // 202 operations across 29 namespaces (§34.6 (l), (s)).
    std::size_t total = 0;
    for (const auto& ns : registry.at("namespaces")) total += ns.at("operations").size();
    AXIAM_CHECK(total == 202 && registry.at("namespaces").size() == 29);
}

AXIAM_TEST("§36.8 (1): the eleven replace_* and sparse counts of §27.4 rule 5 are the registry's") {
    // §34.6 (o): the registry holds eleven `replace` operations, the three network PUTs among
    // them; this SDK generates the full-body input of each (REQUIRED_CTOR for the network ones).
    const auto registry = json::parse(read_repo_file("management-registry.json"));
    std::size_t replace = 0;
    std::set<std::string> network_replace;
    for (auto ns = registry.at("namespaces").begin(); ns != registry.at("namespaces").end(); ++ns) {
        for (auto op = ns.value().at("operations").begin(); op != ns.value().at("operations").end();
             ++op) {
            const auto& style = op.value().at("update_style");
            if (style.is_string() && style.get<std::string>() == "replace") {
                ++replace;
                if (ns.key() == "network") network_replace.insert(op.key());
            }
        }
    }
    AXIAM_CHECK(replace == 11);
    AXIAM_CHECK(network_replace ==
                std::set<std::string>({"replace_policy", "replace_profile", "replace_segment"}));
}

// -- 2. Versions ------------------------------------------------------------------------

AXIAM_TEST("§36.8 (2): every write sends the version it was given, exactly") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, segment_body().dump()},  // replace_segment
        {204, ""},                     // delete_segment
        {201, profile_body().dump()},  // create_profile
        {200, profile_body().dump()},  // replace_profile
        {204, ""},                     // delete_profile
        {200, policy_body().dump()},   // replace_policy
    });
    auto n = fixture.client.network();

    n.replace_segment(kSeg, ReplaceNetworkSegmentRequest(41, 110, {"a", "b"}, false));
    auto sent = json::parse(fixture.state->last().body);
    AXIAM_CHECK(sent.at("version") == 41);

    n.delete_segment(kSeg, 42);
    AXIAM_CHECK(axtest::mgmt::query_of(fixture.state->last().url) == "version=42");
    AXIAM_CHECK(fixture.state->last().body.empty());

    n.create_profile(CreateNetworkReplyProfileRequest{profile_input(), kSeg, 43});
    sent = json::parse(fixture.state->last().body);
    AXIAM_CHECK(sent.at("segment_version") == 43);
    AXIAM_CHECK(sent.at("segment_id") == kSeg);
    AXIAM_CHECK(!sent.contains("version"));

    n.replace_profile(kSeg, ReplaceNetworkReplyProfileRequest(45, 44, profile_input()));
    sent = json::parse(fixture.state->last().body);
    AXIAM_CHECK(sent.at("segment_version") == 44 && sent.at("version") == 45);

    n.delete_profile(kSeg, 46);
    AXIAM_CHECK(axtest::mgmt::query_of(fixture.state->last().url) == "version=46");

    // The first write of a tenant that has never written a cap: version 0, sent as 0.
    n.replace_policy(ReplaceNetworkPolicyRequest(1800, 0));
    sent = json::parse(fixture.state->last().body);
    AXIAM_CHECK(sent.at("version") == 0 && sent.at("session_timeout_max_secs") == 1800);
}

// The delete operations cannot be called without a version: `version` is a required parameter
// of the signature, with no default.
static_assert(std::is_invocable_v<decltype(&NetworkApi::delete_segment), NetworkApi&,
                                  const std::string&, std::int64_t>,
              "delete_segment(id, version)");
static_assert(!std::is_invocable_v<decltype(&NetworkApi::delete_segment), NetworkApi&,
                                   const std::string&>,
              "§36.8 (2): delete_segment cannot be called without a version");
static_assert(!std::is_invocable_v<decltype(&NetworkApi::delete_profile), NetworkApi&,
                                   const std::string&>,
              "§36.8 (2): delete_profile cannot be called without a version");

AXIAM_TEST("§36.8 (2): a 409 to each write is a ConflictError after exactly one request, exposing reason_code") {
    const std::string stale =
        R"({"error":"conflict","message":"the row changed since it was read","reason_code":"stale_version"})";
    auto fixture = axtest::mgmt::signed_in_many(
        {{409, stale}, {409, stale}, {409, stale}, {409, stale}, {409, stale}, {409, stale},
         {409, stale}});
    auto n = fixture.client.network();
    const auto before = fixture.state->count();

    const auto reason_of = [&](auto&& call) -> std::optional<std::string> {
        try {
            call();
        } catch (const ConflictError& e) {
            return e.reason_code();
        } catch (...) {
            return "wrong-type";
        }
        return "no-throw";
    };
    CreateNetworkSegmentRequest create_segment;
    create_segment.kind = NetworkSegmentKind::Quarantine;
    create_segment.site_key = "default";
    create_segment.name = "q";
    create_segment.vlan_id = 999;

    std::vector<std::optional<std::string>> reasons;
    reasons.push_back(reason_of([&] { n.create_segment(create_segment); }));
    reasons.push_back(
        reason_of([&] { n.replace_segment(kSeg, ReplaceNetworkSegmentRequest(1, 2, {}, true)); }));
    reasons.push_back(reason_of([&] { n.delete_segment(kSeg, 1); }));
    reasons.push_back(reason_of(
        [&] { n.create_profile(CreateNetworkReplyProfileRequest{profile_input(), kSeg, 1}); }));
    reasons.push_back(reason_of([&] {
        n.replace_profile(kSeg, ReplaceNetworkReplyProfileRequest(1, 1, profile_input()));
    }));
    reasons.push_back(reason_of([&] { n.delete_profile(kSeg, 1); }));
    reasons.push_back(
        reason_of([&] { n.replace_policy(ReplaceNetworkPolicyRequest(3600, 0)); }));

    AXIAM_CHECK(fixture.state->count() - before == 7);  // one request each, never retried
    for (const auto& r : reasons) AXIAM_CHECK(r == std::optional<std::string>("stale_version"));
}

AXIAM_TEST("§36.8 (2): a 409 already_exists / duplicate_vlan is a ConflictError exposing reason_code; an unknown or absent one is surfaced as it is") {
    auto fixture = axtest::mgmt::signed_in_three(
        409, R"({"error":"already_exists","message":"the site has that VLAN","reason_code":"duplicate_vlan"})",
        409, R"({"error":"conflict","message":"new","reason_code":"a_code_from_the_future"})",
        409, R"({"error":"conflict","message":"a server before 1.1.0"})");
    auto n = fixture.client.network();
    CreateNetworkSegmentRequest create_segment;
    create_segment.kind = NetworkSegmentKind::Access;
    create_segment.site_key = "default";
    create_segment.name = "x";
    create_segment.vlan_id = 110;
    create_segment.rank = 2;

    const auto reason = [&] {
        try {
            n.create_segment(create_segment);
        } catch (const ConflictError& e) {
            return std::make_pair(true, e.reason_code());
        }
        return std::make_pair(false, std::optional<std::string>{});
    };
    auto r = reason();
    AXIAM_CHECK(r.first && r.second == std::optional<std::string>("duplicate_vlan"));
    r = reason();  // open vocabulary: verbatim
    AXIAM_CHECK(r.first && r.second == std::optional<std::string>("a_code_from_the_future"));
    r = reason();  // absent when the server predating it omits it
    AXIAM_CHECK(r.first && !r.second.has_value());

    // §2 maps 409 to AuthzError and §27.4 rule 7 keeps that: a ConflictError is one.
    static_assert(std::is_base_of_v<AuthzError, ConflictError>, "");
}

// -- 3. Closed bodies -------------------------------------------------------------------

AXIAM_TEST("§36.8 (3): the serialized requests carry exactly the keys of §36.2 for the members set") {
    CreateNetworkSegmentRequest quarantine;
    quarantine.kind = NetworkSegmentKind::Quarantine;
    quarantine.site_key = "default";
    quarantine.name = "isolation";
    quarantine.vlan_id = 999;
    // No rank: absent for a quarantine segment, and absent is not null.
    AXIAM_CHECK(keys_of(json(quarantine)) == Keys({"kind", "site_key", "name", "vlan_id"}));
    AXIAM_CHECK(json(quarantine).at("kind") == "quarantine");

    CreateNetworkSegmentRequest access = quarantine;
    access.kind = NetworkSegmentKind::Access;
    access.rank = 4;
    access.filter_ids = std::vector<std::string>{"staff-filter"};
    access.enabled = false;
    AXIAM_CHECK(keys_of(json(access)) ==
                Keys({"kind", "site_key", "name", "vlan_id", "rank", "filter_ids", "enabled"}));
    AXIAM_CHECK(json(access).at("kind") == "access");

    // A replacement has no kind, site_key or name (§36.3 rule 4); an unset rank is absent.
    const ReplaceNetworkSegmentRequest replace_segment(7, 110, {"a"}, true);
    AXIAM_CHECK(keys_of(json(replace_segment)) == Keys({"version", "vlan_id", "filter_ids", "enabled"}));
    ReplaceNetworkSegmentRequest ranked(7, 110, {}, true);
    ranked.rank = 2;
    AXIAM_CHECK(keys_of(json(ranked)) == Keys({"version", "vlan_id", "filter_ids", "enabled", "rank"}));
    AXIAM_CHECK(json(ranked).at("filter_ids") == json::array());  // an empty envelope is sent

    // An unset idle_timeout_secs, filter_id, service_type, dictionary and termination_action
    // are absent, not null; and the profile has no VLAN member (§36.2).
    const CreateNetworkReplyProfileRequest create_profile{profile_input(), kSeg, 3};
    const json cp = create_profile;
    AXIAM_CHECK(keys_of(cp) == Keys({"segment_id", "segment_version", "profile"}));
    AXIAM_CHECK(keys_of(cp.at("profile")) == Keys({"session_timeout_secs"}));
    for (auto it = cp.at("profile").begin(); it != cp.at("profile").end(); ++it) {
        AXIAM_CHECK(!it.value().is_null());
    }
    AXIAM_CHECK(!cp.at("profile").contains("vlan_id") && !cp.at("profile").contains("vlan"));

    auto full = profile_input();
    full.idle_timeout_secs = 300;
    full.filter_id = "staff-filter";
    full.service_type = RadiusServiceType::FramedUser;
    full.termination_action = RadiusTerminationAction::Default_;
    full.dictionary = "axiam-radius-reply/1";
    const json fp = ReplaceNetworkReplyProfileRequest(2, 3, full);
    AXIAM_CHECK(keys_of(fp) == Keys({"version", "segment_version", "profile"}));
    AXIAM_CHECK(keys_of(fp.at("profile")) ==
                Keys({"session_timeout_secs", "idle_timeout_secs", "filter_id", "service_type",
                      "termination_action", "dictionary"}));
    AXIAM_CHECK(fp.at("profile").at("termination_action") == "default");
    AXIAM_CHECK(fp.at("profile").at("service_type") == "framed_user");

    AXIAM_CHECK(keys_of(json(ReplaceNetworkPolicyRequest(900, 2))) ==
                Keys({"session_timeout_max_secs", "version"}));
}

// The replace types cannot be built without their required members (the compile-time check
// §36.8 test 3 allows a language that has one): no default constructor, and a constructor over
// every required member.
static_assert(!std::is_default_constructible_v<ReplaceNetworkSegmentRequest>, "§36.8 (3)");
static_assert(!std::is_default_constructible_v<ReplaceNetworkReplyProfileRequest>, "§36.8 (3)");
static_assert(!std::is_default_constructible_v<ReplaceNetworkPolicyRequest>, "§36.8 (3)");
static_assert(std::is_constructible_v<ReplaceNetworkSegmentRequest, std::int64_t, std::int64_t,
                                      std::vector<std::string>, bool>, "");
static_assert(std::is_constructible_v<ReplaceNetworkReplyProfileRequest, std::int64_t, std::int64_t,
                                      NetworkReplyProfileInput>, "");
static_assert(std::is_constructible_v<ReplaceNetworkPolicyRequest, std::int64_t, std::int64_t>, "");

// -- 4. Open decoding and pagination -----------------------------------------------------

AXIAM_TEST("§36.8 (4): unknown enumerations decode; a clamped profile decodes with both members") {
    const auto seg = segment_body({{"kind", "tarpit"}, {"rank", nullptr}}).get<NetworkSegmentResponse>();
    AXIAM_CHECK(seg.kind == NetworkSegmentKind::Unknown);
    AXIAM_CHECK(!seg.rank.has_value());
    AXIAM_CHECK(seg.vlan_id == 110 && seg.version == 3 && seg.filter_ids.size() == 1);

    const auto prof = profile_body({{"termination_action", "disconnect"},
                                    {"service_type", "callback_user"}})
                          .get<NetworkReplyProfile>();
    AXIAM_CHECK(prof.termination_action == RadiusTerminationAction::Unknown);
    AXIAM_CHECK(prof.service_type == std::optional<RadiusServiceType>(RadiusServiceType::Unknown));

    const auto clamped = profile_body({{"session_timeout_secs", 1800},
                                       {"session_timeout_clamped", true},
                                       {"idle_timeout_secs", nullptr},
                                       {"filter_id", nullptr},
                                       {"service_type", nullptr}})
                             .get<NetworkReplyProfile>();
    AXIAM_CHECK(clamped.session_timeout_clamped && clamped.session_timeout_secs == 1800);
    AXIAM_CHECK(!clamped.idle_timeout_secs && !clamped.filter_id && !clamped.service_type);

    // The policy is the default until the tenant writes one: updated_at / updated_by absent.
    const auto policy = policy_body().get<NetworkPolicyResponse>();
    AXIAM_CHECK(policy.session_timeout_max_secs == 3600 && policy.version == 0);
    AXIAM_CHECK(!policy.updated_at && !policy.updated_by);
    const auto written = policy_body({{"version", 4}, {"updated_by", "cccccccc-1111-4111-8111-111111111111"},
                                      {"updated_at", "2026-10-16T09:00:00Z"}})
                             .get<NetworkPolicyResponse>();
    AXIAM_CHECK(written.version == 4 && written.updated_at && written.updated_by);

    // An enumeration value this SDK does not know is never sent back as one: refused locally.
    CreateNetworkSegmentRequest unknown_kind;
    unknown_kind.kind = NetworkSegmentKind::Unknown;
    unknown_kind.site_key = "default";
    unknown_kind.name = "x";
    unknown_kind.vlan_id = 5;
    AXIAM_CHECK(caught(what_of<std::invalid_argument>([&] { (void)json(unknown_kind); })));
}

AXIAM_TEST("§36.8 (4): both lists return Page<T> with total; search (and site) are on every request") {
    const auto seg_page = [](bool items) {
        return json{{"items", items ? json::array({segment_body()}) : json::array()},
                    {"total", 7}, {"offset", 0}, {"limit", 1}}
            .dump();
    };
    auto fixture = axtest::mgmt::signed_in_many(
        {{200, seg_page(true)}, {200, seg_page(false)}, {200, page_of(profile_body()).dump()},
         {200, json{{"items", json::array()}, {"total", 1}, {"offset", 1}, {"limit", 1}}.dump()}});
    auto n = fixture.client.network();

    PageRequest request;
    request.limit = 1;
    request.search = "staff";
    const auto first = n.list_segments(request, std::string("default"));
    AXIAM_CHECK(first.total == 7 && first.size() == 1);
    AXIAM_CHECK(first.items[0].kind == NetworkSegmentKind::Access);
    auto query = axtest::mgmt::query_of(fixture.state->last().url);
    AXIAM_CHECK(query.find("search=staff") != std::string::npos);
    AXIAM_CHECK(query.find("site=default") != std::string::npos);
    AXIAM_CHECK(query.find("limit=1") != std::string::npos);

    // The page after it carries the term (PageRequest::next); `site` is an argument of the call
    // and is given again, as for every filter that is not the free-text search.
    const auto second = n.list_segments(first.next_request(), std::string("default"));
    AXIAM_CHECK(second.empty());
    query = axtest::mgmt::query_of(fixture.state->last().url);
    AXIAM_CHECK(query.find("search=staff") != std::string::npos);
    AXIAM_CHECK(query.find("site=default") != std::string::npos);
    AXIAM_CHECK(query.find("offset=1") != std::string::npos);

    // No site: no `site` parameter at all (never an empty one).
    auto no_site = axtest::mgmt::signed_in(200, seg_page(false));
    no_site.client.network().list_segments();
    AXIAM_CHECK(axtest::mgmt::query_of(no_site.state->last().url).find("site") == std::string::npos);

    PageRequest profiles;
    profiles.limit = 1;
    profiles.search = "staff-filter";
    const auto p1 = n.list_profiles(profiles);
    AXIAM_CHECK(p1.total == 1 && p1.size() == 1 && p1.items[0].segment_id == kSeg);
    AXIAM_CHECK(axtest::mgmt::query_of(fixture.state->last().url).find("search=staff-filter") !=
                std::string::npos);
    const auto p2 = n.list_profiles(p1.next_request());
    AXIAM_CHECK(p2.empty());
    AXIAM_CHECK(axtest::mgmt::query_of(fixture.state->last().url).find("search=staff-filter") !=
                std::string::npos);
}

// -- 5. Errors ----------------------------------------------------------------------------

AXIAM_TEST("§36.8 (5): 403, 400, 404, 401, 429 and 503 map to the §2 taxonomy") {
    auto fixture = axtest::mgmt::signed_in_many({
        {403, R"({"error":"authorization_denied","message":"missing permission","action":"network:grant","resource_id":"bbbbbbbb-1111-4111-8111-111111111111"})"},
        {400, R"({"error":"validation_error","message":"vlan_id: must be 1 to 4094"})"},
        {404, R"({"error":"not_found","message":"no such profile"})"},
        {401, R"({"error":"unauthorized"})"},
        {429, ""}, {503, ""},   // create_segment
        {429, ""}, {503, ""},   // replace_segment
        {429, ""}, {503, ""},   // delete_segment
        {429, ""}, {503, ""},   // create_profile
        {429, ""}, {503, ""},   // replace_profile
        {429, ""}, {503, ""},   // delete_profile
        {429, ""}, {503, ""},   // replace_policy
    });
    auto n = fixture.client.network();

    try {
        n.replace_profile(kSeg, ReplaceNetworkReplyProfileRequest(1, 1, profile_input()));
        AXIAM_CHECK(false);
    } catch (const AuthzError& e) {
        AXIAM_CHECK(e.action() == std::optional<std::string>("network:grant"));
        AXIAM_CHECK(e.resource_id() == std::optional<std::string>("bbbbbbbb-1111-4111-8111-111111111111"));
    }
    AXIAM_CHECK(what_of<ValidationError>([&] { n.get_segment(kSeg); })
                    .find("vlan_id: must be 1 to 4094") != std::string::npos);
    AXIAM_CHECK(caught(what_of<NotFoundError>([&] { n.get_profile(kSeg); })));
    AXIAM_CHECK(caught(what_of<AuthError>([&] { n.get_policy(); })));

    // 429 and 503 on each of the seven writes: NetworkError after exactly one request each --
    // never retried (§36.7), though retry is enabled on this client.
    CreateNetworkSegmentRequest create_segment;
    create_segment.kind = NetworkSegmentKind::Access;
    create_segment.site_key = "default";
    create_segment.name = "x";
    create_segment.vlan_id = 5;
    create_segment.rank = 1;
    const std::vector<std::function<void()>> writes = {
        [&] { n.create_segment(create_segment); },
        [&] { n.replace_segment(kSeg, ReplaceNetworkSegmentRequest(1, 5, {}, true)); },
        [&] { n.delete_segment(kSeg, 1); },
        [&] { n.create_profile(CreateNetworkReplyProfileRequest{profile_input(), kSeg, 1}); },
        [&] { n.replace_profile(kSeg, ReplaceNetworkReplyProfileRequest(1, 1, profile_input())); },
        [&] { n.delete_profile(kSeg, 1); },
        [&] { n.replace_policy(ReplaceNetworkPolicyRequest(3600, 0)); },
    };
    for (const auto& write : writes) {
        for (int status = 0; status < 2; ++status) {
            const auto before = fixture.state->count();
            AXIAM_CHECK(caught(what_of<NetworkError>(write)));
            AXIAM_CHECK(fixture.state->count() - before == 1);
        }
    }
}

AXIAM_TEST("§36.3 rule 5 / §36.4: a 403 naming network:grant_admin is an AuthzError, whichever status the server answers") {
    // R110W6-02: the administrative Service-Type is a 403 today (ilpanich/axiam#700 tracks a 400).
    // An SDK never sends either value and depends on neither status.
    auto fixture = axtest::mgmt::signed_in(
        403, R"({"error":"authorization_denied","message":"denied","action":"network:grant_admin"})");
    try {
        fixture.client.network().replace_profile(
            kSeg, ReplaceNetworkReplyProfileRequest(1, 1, profile_input()));
        AXIAM_CHECK(false);
    } catch (const AuthzError& e) {
        AXIAM_CHECK(e.action() == std::optional<std::string>("network:grant_admin"));
    }
    // The schema lists only framed_user: there is no enumerator for the administrative values.
    AXIAM_CHECK(to_wire(RadiusServiceType::FramedUser) == "framed_user");
    AXIAM_CHECK(radius_service_type_from_wire("administrative_user") == RadiusServiceType::Unknown);
}

}  // namespace
