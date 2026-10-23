// CONTRACT.md §27.6.2 (contract 1.62) -- the `network` namespace in a manifest, and the
// "Manifest, `network`" tests of §27.9: the natural keys, the order, `plan` reading with GETs
// only, the version-conditional full-body `replace_*` built from the read, a `409` and its
// `reason_code` as the action's failure, a `kind` that is the wire spelling, `filter_ids` as a
// set, and a clamped profile judged on the read.

#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "assert.hpp"
#include "axiam/axiam.hpp"
#include "axiam/management_manifest.hpp"
#include "management_test_util.hpp"

namespace {

using namespace axiam;
using namespace axiam::management;
using nlohmann::json;

const char* kTenant = "11111111-1111-4111-8111-111111111111";
const char* kSegA = "aaaaaaaa-1111-4111-8111-111111111111";
const char* kSegB = "bbbbbbbb-1111-4111-8111-111111111111";
const char* kUser = "cccccccc-1111-4111-8111-111111111111";

json segment_json(const std::string& id, const std::string& name, const json& extra = json::object()) {
    json body = {{"id", id},
                 {"tenant_id", kTenant},
                 {"path", "/network/zones/default/" + name},
                 {"name", name},
                 {"site_key", "default"},
                 {"kind", "access"},
                 {"vlan_id", 110},
                 {"filter_ids", {"staff-filter", "guest-filter"}},
                 {"rank", 1},
                 {"enabled", true},
                 {"version", 7},
                 {"created_by", kUser},
                 {"updated_by", kUser},
                 {"created_at", "2026-10-16T08:00:00Z"},
                 {"updated_at", "2026-10-16T08:00:00Z"}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

json profile_json(const std::string& segment_id, const json& extra = json::object()) {
    json body = {{"segment_id", segment_id},
                 {"tenant_id", kTenant},
                 {"dictionary", "axiam-radius-reply/1"},
                 {"session_timeout_secs", 3600},
                 {"session_timeout_clamped", false},
                 {"termination_action", "radius_request"},
                 {"idle_timeout_secs", 600},
                 {"filter_id", "staff-filter"},
                 {"service_type", "framed_user"},
                 {"version", 4},
                 {"created_by", kUser},
                 {"updated_by", kUser},
                 {"created_at", "2026-10-16T08:00:00Z"},
                 {"updated_at", "2026-10-16T08:00:00Z"}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

json policy_json(int cap = 3600, int version = 0) {
    return {{"tenant_id", kTenant}, {"session_timeout_max_secs", cap}, {"version", version}};
}

std::string page(const std::vector<json>& items) {
    return json{{"items", items}, {"total", items.size()}, {"offset", 0}, {"limit", 200}}.dump();
}

// ---- manifests --------------------------------------------------------------------------

ManifestEntity policy_entity(std::int64_t cap) {
    ManifestEntity e;
    e.kind = ManifestKind::NetworkPolicy;
    e.key = "cap";
    e.network_policy = ManifestNetworkPolicy{cap};
    return e;
}

ManifestEntity segment_entity(const std::string& key, const std::string& name, std::int64_t vlan = 110) {
    ManifestEntity e;
    e.kind = ManifestKind::NetworkSegment;
    e.key = key;
    ManifestNetworkSegment s;
    s.site = "default";
    s.kind = "access";
    s.name = name;
    s.vlan_id = vlan;
    e.network_segment = s;
    return e;
}

ManifestEntity profile_entity(const std::string& key, const std::string& segment_key,
                              std::int64_t timeout = 3600) {
    ManifestEntity e;
    e.kind = ManifestKind::NetworkProfile;
    e.key = key;
    ManifestNetworkProfile p;
    p.segment = segment_key;
    p.session_timeout_secs = timeout;
    e.network_profile = p;
    return e;
}

// ---- reading what went on the wire -------------------------------------------------------

struct Wire {
    std::string method;
    std::string path;
    json body;
};

std::vector<Wire> wire_of(axtest::mgmt::Fixture& fixture) {
    std::vector<Wire> out;
    std::lock_guard<std::mutex> lock(fixture.state->mtx);
    for (const auto& r : fixture.state->requests) {
        if (r.url.find("/auth/login") != std::string::npos) continue;
        Wire w{r.method, axtest::mgmt::path_of(r.url), json()};
        if (!r.body.empty()) w.body = json::parse(r.body);
        out.push_back(std::move(w));
    }
    return out;
}

std::set<std::string> keys_of(const json& j) {
    std::set<std::string> out;
    for (auto it = j.begin(); it != j.end(); ++it) out.insert(it.key());
    return out;
}

using Keys = std::set<std::string>;

const std::string kPolicyPath = "/api/v1/network/policy";
const std::string kSegmentsPath = "/api/v1/network/segments";
const std::string kProfilesPath = "/api/v1/network/profiles";

// ---- the order ---------------------------------------------------------------------------

AXIAM_TEST("§27.6.2 item 2: the order is policy, then segments, then profiles -- a profile follows its segment") {
    // Declared backwards on purpose.
    Manifest manifest{{profile_entity("p-b", "seg-b"), profile_entity("p-a", "seg-a"),
                       segment_entity("seg-b", "guest"), segment_entity("seg-a", "staff"),
                       policy_entity(7200)}};

    const auto ordered = ManifestApi::ordered(manifest);

    AXIAM_REQUIRE(ordered.size() == 5);
    AXIAM_CHECK(ordered[0].kind == ManifestKind::NetworkPolicy);
    AXIAM_CHECK(ordered[1].kind == ManifestKind::NetworkSegment && ordered[1].key == "seg-a");
    AXIAM_CHECK(ordered[2].kind == ManifestKind::NetworkSegment && ordered[2].key == "seg-b");
    // Within the profiles, the segments' order: seg-a's profile first.
    AXIAM_CHECK(ordered[3].kind == ManifestKind::NetworkProfile && ordered[3].key == "p-a");
    AXIAM_CHECK(ordered[4].kind == ManifestKind::NetworkProfile && ordered[4].key == "p-b");
}

AXIAM_TEST("§27.6.2 item 2: appended last, so a manifest without a network section plans exactly as before") {
    ManifestEntity role;
    role.kind = ManifestKind::Role;
    role.key = "r";
    role.name = "auditor";
    ManifestEntity sa;
    sa.kind = ManifestKind::ServiceAccount;
    sa.key = "sa";
    sa.name = "svc";
    Manifest manifest{{policy_entity(3600), sa, role}};
    const auto ordered = ManifestApi::ordered(manifest);
    AXIAM_CHECK(ordered[0].kind == ManifestKind::Role);
    AXIAM_CHECK(ordered[1].kind == ManifestKind::ServiceAccount);
    AXIAM_CHECK(ordered[2].kind == ManifestKind::NetworkPolicy);
}

// ---- plan reads, with GETs only ------------------------------------------------------------

AXIAM_TEST("§27.9 manifest network (1): plan of a policy, a segment and a profile issues GETs only, in the order get_policy, list_segments, list_profiles") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, policy_json().dump()},
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({profile_json(kSegA)})},
    });
    Manifest manifest{{policy_entity(3600), segment_entity("seg", "staff"), profile_entity("prof", "seg")}};
    manifest.entities[1].network_segment->rank = 1;
    manifest.entities[2].network_profile->session_timeout_secs = 3600;

    const auto plan = fixture.client.management().manifest().plan(manifest);

    const auto wire = wire_of(fixture);
    AXIAM_REQUIRE(wire.size() == 3);
    for (const auto& w : wire) AXIAM_CHECK(w.method == "GET");
    AXIAM_CHECK(wire[0].path == kPolicyPath);
    AXIAM_CHECK(wire[1].path == kSegmentsPath);
    AXIAM_CHECK(wire[2].path == kProfilesPath);
    AXIAM_CHECK(plan.converged());
    AXIAM_CHECK(plan.changes.size() == 3);
}

AXIAM_TEST("§27.6.2 item 3: both lists are walked to exhaustion, a page that carried nothing ending the walk") {
    auto first = json{{"items", {segment_json(kSegA, "staff")}}, {"total", 2}, {"offset", 0}, {"limit", 1}};
    auto second = json{{"items", {segment_json(kSegB, "guest", {{"vlan_id", 120}})}}, {"total", 2}, {"offset", 1}, {"limit", 1}};
    auto fixture = axtest::mgmt::signed_in_many({{200, first.dump()}, {200, second.dump()}});
    Manifest manifest{{segment_entity("a", "staff"), segment_entity("b", "guest", 120)}};

    const auto plan = fixture.client.management().manifest().plan(manifest);

    // Two requests, the second one advanced past the first page: both segments were found.
    const auto wire = wire_of(fixture);
    AXIAM_REQUIRE(wire.size() == 2);
    AXIAM_CHECK(axtest::mgmt::query_of(fixture.state->last().url).find("offset=") != std::string::npos);
    AXIAM_CHECK(plan.changes.size() == 2);
    AXIAM_CHECK(plan.changes[0].action != ChangeAction::Create);
    AXIAM_CHECK(plan.changes[1].action != ChangeAction::Create);
}

// ---- an empty tenant ------------------------------------------------------------------------

AXIAM_TEST("§27.9 manifest network (2): on an empty tenant apply creates the segment, then the profile with the new segment's id and version; plan afterwards is all NoChange") {
    const json created_segment = segment_json(kSegA, "staff", {{"version", 5}});
    const json created_profile = profile_json(kSegA);
    auto fixture = axtest::mgmt::signed_in_many({
        // apply -> plan
        {200, policy_json().dump()},
        {200, page({})},
        {200, page({})},
        // the two writes
        {201, created_segment.dump()},
        {201, created_profile.dump()},
        // plan(m) afterwards
        {200, policy_json().dump()},
        {200, page({created_segment})},
        {200, page({created_profile})},
    });
    Manifest manifest{{policy_entity(3600), segment_entity("seg", "staff"), profile_entity("prof", "seg")}};
    auto& segment = *manifest.entities[1].network_segment;
    segment.rank = 1;
    segment.filter_ids = std::vector<std::string>{"staff-filter", "guest-filter"};
    segment.enabled = true;
    auto& profile = *manifest.entities[2].network_profile;
    profile.idle_timeout_secs = 600;
    profile.filter_id = std::string("staff-filter");
    profile.service_type = RadiusServiceType::FramedUser;
    profile.termination_action = RadiusTerminationAction::RadiusRequest;

    auto api = fixture.client.management().manifest();
    const auto report = api.apply(manifest);

    AXIAM_CHECK(report.complete());
    AXIAM_CHECK(report.applied.size() == 2);
    const auto wire = wire_of(fixture);
    AXIAM_REQUIRE(wire.size() == 5);
    AXIAM_CHECK(wire[3].method == "POST" && wire[3].path == kSegmentsPath);
    AXIAM_CHECK(wire[4].method == "POST" && wire[4].path == kProfilesPath);
    // The profile names the segment the create just produced, at the version that response
    // carried (5) -- there was no read of it to take one from.
    AXIAM_CHECK(wire[4].body.at("segment_id") == kSegA);
    AXIAM_CHECK(wire[4].body.at("segment_version") == 5);
    AXIAM_CHECK(!wire[4].body.contains("version"));
    AXIAM_CHECK(wire[4].body.at("profile").at("session_timeout_secs") == 3600);

    const auto after = api.plan(manifest);
    AXIAM_CHECK(after.converged());
    for (const auto& c : after.changes) AXIAM_CHECK(c.action == ChangeAction::Unchanged);
}

// ---- an Update is a full body built from the read -----------------------------------------

AXIAM_TEST("§27.9 manifest network (3): a segment Update sends version as read, the stated members and every unstated one from the read -- and no kind, site_key or name") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},  // list_segments
        {200, segment_json(kSegA, "staff", {{"vlan_id", 120}, {"version", 8}}).dump()},  // PUT
    });
    Manifest manifest{{segment_entity("seg", "staff", 120)}};  // states only the VLAN

    const auto report = fixture.client.management().manifest().apply(manifest);

    AXIAM_CHECK(report.complete());
    const auto wire = wire_of(fixture);
    AXIAM_REQUIRE(wire.size() == 2);
    AXIAM_CHECK(wire[1].method == "PUT" && wire[1].path == kSegmentsPath + "/" + kSegA);
    const auto& body = wire[1].body;
    AXIAM_CHECK(keys_of(body) == Keys({"version", "vlan_id", "filter_ids", "enabled", "rank"}));
    AXIAM_CHECK(body.at("version") == 7);  // exactly the version plan read
    AXIAM_CHECK(body.at("vlan_id") == 120);
    AXIAM_CHECK(body.at("filter_ids") == json::array({"staff-filter", "guest-filter"}));  // carried
    AXIAM_CHECK(body.at("enabled") == true);                                              // carried
    AXIAM_CHECK(body.at("rank") == 1);                                                    // carried
}

AXIAM_TEST("§27.9 manifest network (3): a stated null on an optional profile member leaves the key out, and the rest is carried from the read") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({profile_json(kSegA)})},
        {200, profile_json(kSegA, {{"version", 5}, {"idle_timeout_secs", nullptr}}).dump()},
    });
    Manifest manifest{{segment_entity("seg", "staff"), profile_entity("prof", "seg")}};
    manifest.entities[1].network_profile->idle_timeout_secs = stated_none<std::int64_t>();

    const auto report = fixture.client.management().manifest().apply(manifest);

    AXIAM_CHECK(report.complete());
    const auto wire = wire_of(fixture);
    AXIAM_REQUIRE(wire.size() == 3);
    AXIAM_CHECK(wire[2].method == "PUT" && wire[2].path == kProfilesPath + "/" + kSegA);
    const auto& body = wire[2].body;
    AXIAM_CHECK(keys_of(body) == Keys({"version", "segment_version", "profile"}));
    AXIAM_CHECK(body.at("version") == 4 && body.at("segment_version") == 7);  // as read
    const auto& profile = body.at("profile");
    // No idle_timeout_secs (stated none: left out, never null); the others carried.
    AXIAM_CHECK(keys_of(profile) ==
                Keys({"dictionary", "session_timeout_secs", "termination_action", "filter_id",
                      "service_type"}));
    AXIAM_CHECK(profile.at("filter_id") == "staff-filter");
    AXIAM_CHECK(profile.at("service_type") == "framed_user");
    AXIAM_CHECK(profile.at("termination_action") == "radius_request");
}

AXIAM_TEST("§27.9 manifest network (4): a segment and its profile changed in one apply -- the profile's segment_version is the replace_segment response's, not the one plan read") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},                 // read version 7
        {200, page({profile_json(kSegA)})},
        {200, segment_json(kSegA, "staff", {{"vlan_id", 130}, {"version", 8}}).dump()},
        {200, profile_json(kSegA, {{"version", 5}, {"idle_timeout_secs", 300}}).dump()},
    });
    Manifest manifest{{segment_entity("seg", "staff", 130), profile_entity("prof", "seg")}};
    manifest.entities[1].network_profile->idle_timeout_secs = 300;

    const auto report = fixture.client.management().manifest().apply(manifest);

    AXIAM_CHECK(report.complete());
    const auto wire = wire_of(fixture);
    AXIAM_REQUIRE(wire.size() == 4);
    AXIAM_CHECK(wire[2].method == "PUT" && wire[2].path == kSegmentsPath + "/" + kSegA);
    AXIAM_CHECK(wire[3].method == "PUT" && wire[3].path == kProfilesPath + "/" + kSegA);
    AXIAM_CHECK(wire[2].body.at("version") == 7);
    AXIAM_CHECK(wire[3].body.at("segment_version") == 8);  // the write's, not plan's 7
    AXIAM_CHECK(wire[3].body.at("version") == 4);          // the profile's own, as read
}

AXIAM_TEST("§27.6.2 item 4: the policy is written with the version it read, and before a profile that needs the higher cap") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, policy_json(3600, 2).dump()},
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({profile_json(kSegA)})},
        {200, policy_json(7200, 3).dump()},
        {200, profile_json(kSegA, {{"session_timeout_secs", 7200}, {"version", 5}}).dump()},
    });
    Manifest manifest{{profile_entity("prof", "seg", 7200), segment_entity("seg", "staff"),
                       policy_entity(7200)}};

    const auto report = fixture.client.management().manifest().apply(manifest);

    AXIAM_CHECK(report.complete());
    const auto wire = wire_of(fixture);
    AXIAM_REQUIRE(wire.size() == 5);
    AXIAM_CHECK(wire[3].method == "PUT" && wire[3].path == kPolicyPath);
    AXIAM_CHECK(wire[3].body == json({{"session_timeout_max_secs", 7200}, {"version", 2}}));
    AXIAM_CHECK(wire[4].method == "PUT" && wire[4].path == kProfilesPath + "/" + kSegA);
}

AXIAM_TEST("§27.6.2 item 3: the tenant's policy always exists, so it is never Create") {
    auto fixture = axtest::mgmt::signed_in(200, policy_json(3600, 0).dump());
    const auto plan = fixture.client.management().manifest().plan(Manifest{{policy_entity(900)}});
    AXIAM_REQUIRE(plan.changes.size() == 1);
    AXIAM_CHECK(plan.changes[0].action == ChangeAction::Update);
    AXIAM_CHECK(plan.changes[0].read_policy && plan.changes[0].read_policy->version == 0);
}

// ---- a 409 is that action's failure -----------------------------------------------------------

AXIAM_TEST("§27.9 manifest network (5): a 409 stale_version makes exactly one request, stops the apply and exposes reason_code") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({profile_json(kSegA)})},
        {409, R"({"error":"conflict","message":"the segment changed since it was read","reason_code":"stale_version"})"},
    });
    Manifest manifest{{segment_entity("seg", "staff", 140), profile_entity("prof", "seg", 1800)}};

    const auto report = fixture.client.management().manifest().apply(manifest);

    AXIAM_CHECK(!report.complete());
    AXIAM_REQUIRE(report.failed.has_value());
    AXIAM_CHECK(report.failed->entity.kind == ManifestKind::NetworkSegment);
    AXIAM_CHECK(report.failed_reason_code == std::optional<std::string>("stale_version"));
    // The profile's write was never attempted, and no write was repeated.
    AXIAM_CHECK(report.remaining.size() == 1);
    AXIAM_CHECK(report.remaining[0].entity.kind == ManifestKind::NetworkProfile);
    const auto wire = wire_of(fixture);
    AXIAM_REQUIRE(wire.size() == 3);  // two reads and the one refused write
    AXIAM_CHECK(wire[2].method == "PUT");
    std::size_t writes = 0;
    for (const auto& w : wire) writes += w.method != "GET";
    AXIAM_CHECK(writes == 1);
}

AXIAM_TEST("§27.9 manifest network (5): a 409 already_exists with duplicate_vlan does the same") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({})},
        {409, R"({"error":"already_exists","message":"the site has that VLAN","reason_code":"duplicate_vlan"})"},
    });
    Manifest manifest{{segment_entity("seg", "staff")}};

    const auto report = fixture.client.management().manifest().apply(manifest);

    AXIAM_CHECK(!report.complete());
    AXIAM_CHECK(report.failed_reason_code == std::optional<std::string>("duplicate_vlan"));
    AXIAM_CHECK(report.failure.find("the site has that VLAN") != std::string::npos);
    const auto wire = wire_of(fixture);
    AXIAM_CHECK(wire.size() == 2 && wire[1].method == "POST");
}

// ---- deletion is not offered ------------------------------------------------------------------

AXIAM_TEST("§27.9 manifest network (6): omission is never deletion -- a segment the manifest does not state is left alone, and no DELETE is ever sent") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff"), segment_json(kSegB, "guest", {{"vlan_id", 200}})})},
        {200, page({profile_json(kSegA), profile_json(kSegB)})},
    });
    Manifest manifest{{segment_entity("seg", "staff"), profile_entity("prof", "seg")}};

    const auto report = fixture.client.management().manifest().apply(manifest);

    AXIAM_CHECK(report.complete() && report.applied.empty());
    for (const auto& w : wire_of(fixture)) AXIAM_CHECK(w.method == "GET");
}

// ---- refused before any request ------------------------------------------------------------------

AXIAM_TEST("§27.9 manifest network (7): a duplicate natural key, a second profile for a segment, a second policy and a dangling segment are each refused with zero wire calls") {
    const auto expect_refused = [](const Manifest& manifest) {
        auto fixture = axtest::mgmt::signed_in(200, "{}");
        const auto before = fixture.state->count();
        bool refused = false;
        try {
            fixture.client.management().manifest().plan(manifest);
        } catch (const ManifestError&) {
            refused = true;
        }
        AXIAM_CHECK(refused);
        bool refused_apply = false;
        try {
            fixture.client.management().manifest().apply(manifest);
        } catch (const ManifestError&) {
            refused_apply = true;
        }
        AXIAM_CHECK(refused_apply);
        AXIAM_CHECK(fixture.state->count() == before);
    };

    // Two segments with one site, kind and name (the keys differ; the natural key does not).
    expect_refused(Manifest{{segment_entity("one", "staff"), segment_entity("two", "staff", 120)}});
    // Two profiles for one segment.
    expect_refused(Manifest{{segment_entity("seg", "staff"), profile_entity("p1", "seg"),
                             profile_entity("p2", "seg", 1800)}});
    // Two policies.
    ManifestEntity second = policy_entity(900);
    second.key = "cap-2";
    expect_refused(Manifest{{policy_entity(3600), second}});
    // A profile whose `segment` names no segment spec of the manifest.
    expect_refused(Manifest{{profile_entity("prof", "nowhere")}});
    // A spec of the kind, or none: each of the three needs its own.
    for (const auto kind : {ManifestKind::NetworkSegment, ManifestKind::NetworkProfile,
                            ManifestKind::NetworkPolicy}) {
        ManifestEntity bare;
        bare.kind = kind;
        bare.key = "bare";
        expect_refused(Manifest{{bare}});
    }

    // The same name on another site, or of another kind, is a different key: accepted.
    Manifest ok{{segment_entity("one", "staff"), segment_entity("two", "staff", 120)}};
    ok.entities[1].network_segment->site = "annex";
    AXIAM_REQUIRE_NOTHROW(ManifestApi::validate(ok));
    ok.entities[1].network_segment->site = "default";
    ok.entities[1].network_segment->kind = "quarantine";
    AXIAM_REQUIRE_NOTHROW(ManifestApi::validate(ok));
}

// ---- kind is the wire spelling ---------------------------------------------------------------------

AXIAM_TEST("§27.9 manifest network (8): a segment stated as access is NoChange against a read that says \"access\", and its create body carries \"access\"") {
    auto unchanged = axtest::mgmt::signed_in(200, page({segment_json(kSegA, "staff")}));
    Manifest manifest{{segment_entity("seg", "staff")}};
    AXIAM_CHECK(manifest.entities[0].network_segment->kind == "access");
    const auto plan = unchanged.client.management().manifest().plan(manifest);
    AXIAM_CHECK(plan.changes[0].action == ChangeAction::Unchanged);

    auto creating = axtest::mgmt::signed_in_many({{200, page({})}, {201, segment_json(kSegA, "staff").dump()}});
    creating.client.management().manifest().apply(manifest);
    const auto wire = wire_of(creating);
    AXIAM_REQUIRE(wire.size() == 2);
    AXIAM_CHECK(wire[1].body.at("kind") == "access");
    AXIAM_CHECK(wire[1].body.at("site_key") == "default");  // the `site` member is the wire site_key

    // A quarantine segment: the other wire value, and no rank unless stated.
    Manifest quarantine{{segment_entity("q", "isolation", 999)}};
    quarantine.entities[0].network_segment->kind = "quarantine";
    auto q = axtest::mgmt::signed_in_many(
        {{200, page({})}, {201, segment_json(kSegB, "isolation", {{"kind", "quarantine"}, {"rank", nullptr}}).dump()}});
    q.client.management().manifest().apply(quarantine);
    const auto qwire = wire_of(q);
    AXIAM_CHECK(qwire[1].body.at("kind") == "quarantine");
    AXIAM_CHECK(!qwire[1].body.contains("rank"));

    // There is no `zones` spelling: it is a different (unknown) kind, which this SDK never sends.
    Manifest zones{{segment_entity("z", "staff")}};
    zones.entities[0].network_segment->kind = "zones";
    auto z = axtest::mgmt::signed_in_many({{200, page({})}});
    const auto zreport = z.client.management().manifest().apply(zones);
    AXIAM_CHECK(!zreport.complete());
    AXIAM_CHECK(wire_of(z).size() == 1);  // refused locally, after the one read
}

// ---- filter_ids is a set ---------------------------------------------------------------------------

AXIAM_TEST("§27.9 manifest network (9): the same Filter-Ids in another order are NoChange and apply writes nothing") {
    auto fixture = axtest::mgmt::signed_in(200, page({segment_json(kSegA, "staff")}));
    Manifest manifest{{segment_entity("seg", "staff")}};
    manifest.entities[0].network_segment->filter_ids = std::vector<std::string>{"guest-filter", "staff-filter"};

    const auto report = fixture.client.management().manifest().apply(manifest);

    AXIAM_CHECK(report.complete() && report.applied.empty());
    for (const auto& w : wire_of(fixture)) AXIAM_CHECK(w.method == "GET");
}

AXIAM_TEST("§27.9 manifest network (9): a write sends filter_ids in the order the manifest states -- an Update for another member, and a Create") {
    auto update = axtest::mgmt::signed_in_many(
        {{200, page({segment_json(kSegA, "staff")})}, {200, segment_json(kSegA, "staff").dump()}});
    Manifest manifest{{segment_entity("seg", "staff", 150)}};
    manifest.entities[0].network_segment->filter_ids = std::vector<std::string>{"z-filter", "a-filter", "m-filter"};
    update.client.management().manifest().apply(manifest);
    auto wire = wire_of(update);
    AXIAM_REQUIRE(wire.size() == 2);
    AXIAM_CHECK(wire[1].body.at("filter_ids") == json::array({"z-filter", "a-filter", "m-filter"}));

    auto create = axtest::mgmt::signed_in_many({{200, page({})}, {201, segment_json(kSegA, "staff").dump()}});
    create.client.management().manifest().apply(manifest);
    wire = wire_of(create);
    AXIAM_REQUIRE(wire.size() == 2);
    AXIAM_CHECK(wire[1].body.at("filter_ids") == json::array({"z-filter", "a-filter", "m-filter"}));
}

AXIAM_TEST("§27.9 manifest network (9): a segment listing one Filter-Id twice is refused with zero wire calls, at plan and at apply") {
    auto fixture = axtest::mgmt::signed_in(200, "{}");
    const auto before = fixture.state->count();
    Manifest manifest{{segment_entity("seg", "staff")}};
    manifest.entities[0].network_segment->filter_ids = std::vector<std::string>{"staff-filter", "staff-filter"};
    AXIAM_REQUIRE_THROWS_AS(fixture.client.management().manifest().plan(manifest), ManifestError);
    AXIAM_REQUIRE_THROWS_AS(fixture.client.management().manifest().apply(manifest), ManifestError);
    AXIAM_CHECK(fixture.state->count() == before);
}

// ---- a clamped profile is judged on the read -------------------------------------------------------------

AXIAM_TEST("§27.9 manifest network (10): a clamped profile -- the cap stated is NoChange; a value above it is an Update, and apply sends one replace_profile, meets 403, stops with no retry") {
    const json clamped = profile_json(kSegA, {{"session_timeout_secs", 1800}, {"session_timeout_clamped", true}});

    // Stating the effective (clamped) value: NoChange -- the stored value is neither restored nor rewritten.
    {
        auto fixture = axtest::mgmt::signed_in_many({{200, page({segment_json(kSegA, "staff")})}, {200, page({clamped})}});
        Manifest manifest{{segment_entity("seg", "staff"), profile_entity("prof", "seg", 1800)}};
        const auto plan = fixture.client.management().manifest().plan(manifest);
        AXIAM_CHECK(plan.converged());
    }

    // Stating a value above the cap: differs from the read, so an Update; the server refuses it.
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff"), segment_json(kSegB, "guest", {{"vlan_id", 120}})})},
        {200, page({clamped, profile_json(kSegB, {{"session_timeout_secs", 1800}, {"session_timeout_clamped", true}})})},
        {403, R"({"error":"authorization_denied","message":"session_timeout_secs is above the tenant's cap of 1800"})"},
    });
    Manifest manifest{{segment_entity("a", "staff"), segment_entity("b", "guest", 120),
                       profile_entity("pa", "a", 7200), profile_entity("pb", "b", 7200)}};

    const auto plan = fixture.client.management().manifest().plan(manifest);
    AXIAM_REQUIRE(plan.changes.size() == 4);
    AXIAM_CHECK(plan.changes[2].action == ChangeAction::Update);
    AXIAM_CHECK(plan.changes[3].action == ChangeAction::Update);

    // Rewind: a fresh fixture for the apply (the plan above consumed the queue).
    auto applying = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff"), segment_json(kSegB, "guest", {{"vlan_id", 120}})})},
        {200, page({clamped, profile_json(kSegB, {{"session_timeout_secs", 1800}, {"session_timeout_clamped", true}})})},
        {403, R"({"error":"authorization_denied","message":"session_timeout_secs is above the tenant's cap of 1800"})"},
    });
    const auto report = applying.client.management().manifest().apply(manifest);

    AXIAM_CHECK(!report.complete());
    AXIAM_REQUIRE(report.failed.has_value());
    AXIAM_CHECK(report.failed->entity.key == "pa");
    AXIAM_CHECK(report.failure.find("session_timeout_secs is above the tenant's cap of 1800") !=
                std::string::npos);
    AXIAM_CHECK(!report.failed_reason_code.has_value());  // a 403, not a 409
    AXIAM_CHECK(report.remaining.size() == 1 && report.remaining[0].entity.key == "pb");
    const auto wire = wire_of(applying);
    AXIAM_REQUIRE(wire.size() == 3);  // two reads and exactly one replace_profile
    AXIAM_CHECK(wire[2].method == "PUT" && wire[2].path == kProfilesPath + "/" + kSegA);
    // Sent as stated -- not lowered to the cap by the SDK.
    AXIAM_CHECK(wire[2].body.at("profile").at("session_timeout_secs") == 7200);
}

// ---- the report -----------------------------------------------------------------------------------------------

AXIAM_TEST("§27.6.2: a plan and an apply report describe the network kinds") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, policy_json(3600, 1).dump()},
        {200, page({})},
        {200, page({})},
    });
    Manifest manifest{{policy_entity(900), segment_entity("seg", "staff"), profile_entity("prof", "seg")}};
    const auto plan = fixture.client.management().manifest().plan(manifest);
    AXIAM_REQUIRE(plan.changes.size() == 3);
    AXIAM_CHECK(plan.changes[0].describe() == "update network_policy:cap");
    AXIAM_CHECK(plan.changes[1].describe() == "create network_segment:seg");
    AXIAM_CHECK(plan.changes[2].describe() == "create network_profile:prof");
    // A plan holds what it read, for apply to build the version-conditional bodies from.
    AXIAM_CHECK(plan.changes[0].read_policy && plan.changes[0].read_policy->version == 1);
    AXIAM_CHECK(!plan.changes[1].read_segment && !plan.changes[2].read_profile);

    auto failing = axtest::mgmt::signed_in_many({
        {200, policy_json(3600, 1).dump()},
        {200, page({})},
        {200, page({})},
        {409, R"({"error":"conflict","message":"the policy changed","reason_code":"stale_version"})"},
    });
    const auto report = failing.client.management().manifest().apply(manifest);
    const auto lines = report.describe();
    AXIAM_REQUIRE(lines.size() == 3);
    AXIAM_CHECK(lines[0].find("update network_policy:cap") != std::string::npos);
    AXIAM_CHECK(lines[0].find("FAILED") != std::string::npos);
    AXIAM_CHECK(lines[1].find("skipped") != std::string::npos);
    AXIAM_CHECK(report.failed_reason_code == std::optional<std::string>("stale_version"));
}

// ---- the specs in the aggregate macros ------------------------------------------------------------------------

AXIAM_TEST("§27.7 / §27.6.2: the designated-initializer macros build the network specs") {
    const auto manifest = AXIAM_MANIFEST(
        AXIAM_NETWORK_POLICY(.key = "cap", .network_policy = ManifestNetworkPolicy{1800}),
        AXIAM_NETWORK_SEGMENT(.key = "staff",
                              .network_segment = (ManifestNetworkSegment{.site = "default",
                                                                         .kind = "access",
                                                                         .name = "staff",
                                                                         .vlan_id = 110,
                                                                         .rank = 1})),
        AXIAM_NETWORK_PROFILE(.key = "staff-profile",
                              .network_profile = (ManifestNetworkProfile{.segment = "staff",
                                                                         .session_timeout_secs = 1200})));
    AXIAM_REQUIRE_NOTHROW(ManifestApi::validate(manifest));
    const auto ordered = ManifestApi::ordered(manifest);
    AXIAM_REQUIRE(ordered.size() == 3);
    AXIAM_CHECK(ordered[0].kind == ManifestKind::NetworkPolicy);
    AXIAM_CHECK(ordered[1].network_segment->rank == ManifestNullable<std::int64_t>(1));
    AXIAM_CHECK(ordered[2].network_profile->segment == "staff");
    AXIAM_CHECK(stated_none<std::int64_t>().has_value() && !stated_none<std::int64_t>()->has_value());
}

}  // namespace

// ---- C162-07 / §27.6.2 item 4 (as amended in 1.62) -----------------------------------------

AXIAM_TEST("§27.6.2 item 4 (C162-07): plan refuses an Update that would carry an open-enum value read as unknown on an unstated member -- no write is sent") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({profile_json(kSegA, {{"termination_action", "future"}})})},
    });
    // States another member (idle_timeout_secs drifts) but not termination_action.
    Manifest manifest{{segment_entity("seg", "staff"), profile_entity("prof", "seg")}};
    manifest.entities[0].network_segment->vlan_id = 110;
    manifest.entities[1].network_profile->idle_timeout_secs = 900;

    bool refused = false;
    try {
        fixture.client.management().manifest().plan(manifest);
    } catch (const std::invalid_argument& e) {  // C163-07: a local refusal, not the server's 400/422 class
        refused = true;
        const std::string what = e.what();
        AXIAM_CHECK(what.find("termination_action") != std::string::npos);
        AXIAM_CHECK(what.find("\"future\"") != std::string::npos);  // C163-10: the value, quoted
    }
    AXIAM_CHECK(refused);
    for (const auto& w : wire_of(fixture)) AXIAM_CHECK(w.method == "GET");
}

AXIAM_TEST("§27.6.2 item 4 (C163-09/10): the same refusal for service_type, naming the member and quoting the value; no write is sent") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({profile_json(kSegA, {{"service_type", "future_type"}})})},
    });
    Manifest manifest{{segment_entity("seg", "staff"), profile_entity("prof", "seg")}};
    manifest.entities[1].network_profile->idle_timeout_secs = 900;

    bool refused = false;
    try {
        fixture.client.management().manifest().plan(manifest);
    } catch (const std::invalid_argument& e) {
        refused = true;
        const std::string what = e.what();
        AXIAM_CHECK(what.find("service_type") != std::string::npos);
        AXIAM_CHECK(what.find("\"future_type\"") != std::string::npos);
    }
    AXIAM_CHECK(refused);
    for (const auto& w : wire_of(fixture)) AXIAM_CHECK(w.method == "GET");
}

AXIAM_TEST("§27.6.2 item 4 (C163-10): a profile read keeps the wire text of its open-enum members beside the enum") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({profile_json(kSegA, {{"termination_action", "future"}, {"service_type", "future_type"}})})},
    });
    Manifest manifest{{segment_entity("seg", "staff"), profile_entity("prof", "seg")}};
    const auto plan = fixture.client.management().manifest().plan(manifest);
    AXIAM_REQUIRE(plan.changes.size() == 2 && plan.changes[1].read_profile);
    const auto& read = *plan.changes[1].read_profile;
    AXIAM_CHECK(read.termination_action == RadiusTerminationAction::Unknown);
    AXIAM_CHECK(read.termination_action_wire == std::optional<std::string>("future"));
    AXIAM_CHECK(read.service_type_wire == std::optional<std::string>("future_type"));
}

AXIAM_TEST("§27.6.2 item 4 (C163-10): a known value keeps its wire text; an absent service_type has none") {
    auto absent = profile_json(kSegA);
    absent.erase("service_type");
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({absent})},
    });
    Manifest manifest{{segment_entity("seg", "staff"), profile_entity("prof", "seg")}};
    const auto plan = fixture.client.management().manifest().plan(manifest);
    AXIAM_REQUIRE(plan.changes.size() == 2 && plan.changes[1].read_profile);
    AXIAM_CHECK(plan.changes[1].read_profile->termination_action_wire ==
                std::optional<std::string>("radius_request"));
    AXIAM_CHECK(!plan.changes[1].read_profile->service_type_wire);
}

AXIAM_TEST("§27.6.2 item 4 (C163-09): applying with the member stated sends the STATED value in the replace_profile body, never the unknown one") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({profile_json(kSegA, {{"termination_action", "future"}})})},
        {200, profile_json(kSegA, {{"version", 5}}).dump()},  // PUT
    });
    Manifest manifest{{segment_entity("seg", "staff"), profile_entity("prof", "seg")}};
    manifest.entities[1].network_profile->termination_action = RadiusTerminationAction::RadiusRequest;

    const auto report = fixture.client.management().manifest().apply(manifest);
    AXIAM_CHECK(report.complete());
    const auto wire = wire_of(fixture);
    AXIAM_REQUIRE(wire.size() == 3);
    AXIAM_CHECK(wire[2].method == "PUT");
    const auto& body = wire[2].body;
    AXIAM_CHECK(body.dump().find("future") == std::string::npos);
    const auto& profile = body.contains("profile") ? body.at("profile") : body;
    AXIAM_CHECK(profile.at("termination_action") == "radius_request");
}

AXIAM_TEST("§27.6.2 item 4 (C163-09): an unknown value on an unstated member with nothing else drifted is NoChange -- plan does not refuse and nothing is written") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({profile_json(kSegA, {{"termination_action", "future"}})})},
    });
    Manifest manifest{{segment_entity("seg", "staff"), profile_entity("prof", "seg")}};
    const auto plan = fixture.client.management().manifest().plan(manifest);
    AXIAM_REQUIRE(plan.changes.size() == 2);
    AXIAM_CHECK(plan.changes[1].action == ChangeAction::Unchanged);
    for (const auto& w : wire_of(fixture)) AXIAM_CHECK(w.method == "GET");
}

AXIAM_TEST("§27.6.2 item 4 (C162-07): stating the member replaces the unknown value, so plan proceeds") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({profile_json(kSegA, {{"termination_action", "future"}})})},
    });
    Manifest manifest{{segment_entity("seg", "staff"), profile_entity("prof", "seg")}};
    manifest.entities[1].network_profile->termination_action = RadiusTerminationAction::RadiusRequest;

    const auto plan = fixture.client.management().manifest().plan(manifest);
    AXIAM_REQUIRE(plan.changes.size() == 2);
    AXIAM_CHECK(plan.changes[1].action == ChangeAction::Update);
}

AXIAM_TEST("§36.8 test 4 (C162-16): PageRequest::next() carries site, and list_segments sends it on every page") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, page({segment_json(kSegA, "staff")})},
        {200, page({})},
    });
    auto net = fixture.client.management().network();
    PageRequest first;
    first.limit = 1;
    const auto p1 = net.list_segments(first, std::string("lab"));
    AXIAM_CHECK(p1.request.site == std::optional<std::string>("lab"));
    const auto next = p1.next_request();
    AXIAM_CHECK(next.site == std::optional<std::string>("lab"));
    net.list_segments(next);  // no site argument: the page request's own is used

    std::vector<std::string> urls;
    {
        std::lock_guard<std::mutex> lock(fixture.state->mtx);
        for (const auto& r : fixture.state->requests) {
            if (r.url.find("/network/segments") != std::string::npos) urls.push_back(r.url);
        }
    }
    AXIAM_REQUIRE(urls.size() == 2);
    for (const auto& u : urls) AXIAM_CHECK(u.find("site=lab") != std::string::npos);
    AXIAM_CHECK(urls[1].find("offset=1") != std::string::npos);
}
