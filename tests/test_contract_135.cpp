// Contract 1.34 §5.2.2 and contract 1.35 §5.2.3 — the acting tenant vs the principal
// tenant, and tenant-scoped role assignments.
//
// Two of these rules are the kind an SDK breaks silently rather than loudly, which is
// why they are pinned here rather than left to the generated conformance suite:
//
// - §5.2.2 rule 2. A registration record for the caller's OWN password is sealed
//   against the tenant the account lives in, not the one the client is pointed at. Get
//   it wrong and the server answers "the OPAQUE session was issued for a different
//   tenant" — but only for an organization-level principal that has switched tenant, so
//   it passes every test written against an ordinary account.
// - §5.2.3 rule 1. `tenant_scope: []` is refused with 400. An engaged-optional check
//   alone does not prevent it: `std::optional<std::vector<std::string>>` holding an
//   EMPTY vector is engaged, and an empty vector is exactly what building the field
//   from a filtered collection produces for "no tenants named".

#include <memory>
#include <random>
#include <string>
#include <vector>

#include <json.hpp>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/management.hpp"
#include "fake_transport.hpp"
#include "management_test_util.hpp"
#include "opaque_fake.hpp"

using namespace axiam;
using namespace axiam::management;
using axtest::FakeNative;
using axtest::FakeState;
using axtest::json_response;
using axtest::ScopedFakeNative;
using json = nlohmann::json;

namespace {

constexpr const char* kActingTenant = "33333333-3333-4333-8333-333333333333";
constexpr const char* kPrincipalTenant = "55555555-5555-4555-8555-555555555555";
constexpr const char* kOrgId = "11111111-1111-4111-8111-111111111111";
constexpr const char* kReachableTenant = "66666666-6666-4666-8666-666666666666";
constexpr const char* kScopedTenant = "88888888-8888-4888-8888-888888888888";
constexpr const char* kSomeId = "99999999-9999-4999-8999-999999999999";
constexpr const char* kWireRegistrationResponse = "726573703a";

// Minted per run; nothing here depends on the value — the login stub answers 200
// regardless, so what is under test is which tenant the body names, never whether a
// credential matched — and a literal that reads like a credential is a finding for
// every secret scanner.
std::string mint_password() {
    static std::mt19937_64 rng{std::random_device{}()};
    static const char* digits = "0123456789abcdef";
    std::string out = "fixture-";
    std::uint64_t bits = rng();
    for (int i = 0; i < 16; i++) {
        out.push_back(digits[bits & 0xf]);
        bits >>= 4;
    }
    return out;
}

// A client pointed at the acting tenant BY SLUG.
//
// A slug rather than the UUID on purpose: `add_scope_fields` writes `tenant_slug` for
// one and `tenant_id` for the other, and §5.2.2 rule 2's override has to REPLACE the
// slug it finds. Against a UUID tenant there is no slug to displace, so "no tenant_slug
// in the body" would pass against an implementation that never displaced anything.
Client make_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://api.example.test")
        .tenant_slug("acme")
        .org_id(kOrgId)
        .transport(axtest::make_fake(st))
        .build();
}

// Answers /auth/login with `user` as the login response's user object, and
// /auth/opaque/register/start with a record the fake library can finish.
void install_router(std::shared_ptr<FakeState> st, std::string user) {
    st->router = [user](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/opaque/register/start") != std::string::npos) {
            return json_response(
                200,
                std::string(R"({"opaque_session":"reg-handle","registration_response":")") +
                    kWireRegistrationResponse +
                    R"(","ksf":"argon2id","memory_kib":19456,"iterations":2,"parallelism":1})");
        }
        if (req.url.find("/auth/login") != std::string::npos) {
            auto r = json_response(
                200,
                R"({"session_id":"sess-1","expires_in":900,"user":)" + user + "}");
            r.headers["X-CSRF-Token"] = "csrf-abc";
            return r;
        }
        return json_response(404, R"({"message":"not found"})");
    };
}

// The parsed body of the last request whose URL contains `needle`.
json body_of(const std::shared_ptr<FakeState>& st, const std::string& needle) {
    std::lock_guard<std::mutex> lock(st->mtx);
    for (auto it = st->requests.rbegin(); it != st->requests.rend(); ++it) {
        if (it->url.find(needle) != std::string::npos) {
            return json::parse(it->body, nullptr, false);
        }
    }
    return json();
}

// Signs in against `user` and returns the resulting UserInfo.
UserInfo sign_in(Client& c, const std::string&) {
    LoginResult res = c.login("alice@example.com", mint_password());
    AXIAM_REQUIRE(res.user.has_value());
    return *res.user;
}

}  // namespace

// ---------------------------------------------------------------------------
// §5.2.2 — acting tenant vs principal tenant
// ---------------------------------------------------------------------------

AXIAM_TEST("§5.2.2 rule 1: an absent principal tenant reads as the acting tenant") {
    // A server older than contract 1.34 omits `principal_tenant_id` and cannot switch
    // the acting tenant either, so reading `tenant_id` there is not a guess — it is the
    // only value the field could have had.
    auto st = std::make_shared<FakeState>();
    install_router(st, std::string(R"({"id":"u-1","tenant_id":")") + kActingTenant + R"("})");
    Client c = make_client(st);

    const UserInfo user = sign_in(c, "");

    AXIAM_CHECK(user.tenant_id == kActingTenant);
    AXIAM_CHECK(user.principal_tenant_id == kActingTenant);
    AXIAM_CHECK_FALSE(user.principal_tenant_slug.has_value());
}

AXIAM_TEST("§5.2.2: a divergent principal tenant is reported separately") {
    auto st = std::make_shared<FakeState>();
    install_router(st, std::string(R"({"id":"u-1","tenant_id":")") + kActingTenant +
                           R"(","principal_tenant_id":")" + kPrincipalTenant +
                           R"(","principal_tenant_slug":"organization","org_id":")" + kOrgId +
                           R"(","organization_level":true})");
    Client c = make_client(st);

    const UserInfo user = sign_in(c, "");

    AXIAM_CHECK(user.organization_level);
    AXIAM_CHECK(user.tenant_id == kActingTenant);
    AXIAM_CHECK(user.principal_tenant_id == kPrincipalTenant);
    AXIAM_CHECK(user.principal_tenant_slug.value_or("") == "organization");
    // Rule 3: read the organization from the session rather than resolving a slug
    // through the `super-admin`-only GET /api/v1/organizations.
    AXIAM_CHECK(user.org_id.value_or("") == kOrgId);
}

AXIAM_TEST("§5.2.3 rule 3: reachable_tenant_ids narrows an organization-level principal") {
    auto st = std::make_shared<FakeState>();
    install_router(st, std::string(R"({"id":"u-1","tenant_id":")") + kActingTenant +
                           R"(","organization_level":true,"reachable_tenant_ids":[")" +
                           kReachableTenant + R"("]})");
    Client c = make_client(st);

    const UserInfo user = sign_in(c, "");

    // Still true — which is exactly why gating a tenant switcher on this flag alone
    // offers tenants the server refuses at the header.
    AXIAM_CHECK(user.organization_level);
    AXIAM_REQUIRE(user.reachable_tenant_ids.has_value());
    AXIAM_CHECK(user.reachable_tenant_ids->size() == 1);
    AXIAM_CHECK(user.reachable_tenant_ids->at(0) == kReachableTenant);
}

AXIAM_TEST("§5.2.3: absent reach is unrestricted, and so is an empty one") {
    // Disengaged means UNRESTRICTED. An empty list would read as "reaches nothing", the
    // opposite of what an omitted field means here — so an empty list on the wire
    // arrives disengaged too.
    auto absent_state = std::make_shared<FakeState>();
    install_router(absent_state,
                   std::string(R"({"id":"u-1","tenant_id":")") + kActingTenant + R"("})");
    Client absent = make_client(absent_state);
    AXIAM_CHECK_FALSE(sign_in(absent, "").reachable_tenant_ids.has_value());

    auto empty_state = std::make_shared<FakeState>();
    install_router(empty_state, std::string(R"({"id":"u-1","tenant_id":")") + kActingTenant +
                                    R"(","reachable_tenant_ids":[]})");
    Client empty = make_client(empty_state);
    AXIAM_CHECK_FALSE(sign_in(empty, "").reachable_tenant_ids.has_value());
}

// ---------------------------------------------------------------------------
// §5.2.2 rule 2 — which tenant a registration record is sealed against
// ---------------------------------------------------------------------------

AXIAM_TEST("§5.2.2 rule 2: enrolment for self seals against the principal tenant") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    install_router(st, std::string(R"({"id":"u-1","tenant_id":")") + kActingTenant +
                           R"(","principal_tenant_id":")" + kPrincipalTenant +
                           R"(","organization_level":true})");
    Client c = make_client(st);
    (void)sign_in(c, "");

    const axiam::OpaqueEnrollment enrollment = c.opaque_enrollment_for_self(mint_password());

    const json body = body_of(st, "/auth/opaque/register/start");
    AXIAM_CHECK(body.value("tenant_id", "") == kPrincipalTenant);
    // A slug naming the acting tenant would out-vote the principal tenant id
    // server-side, which is the exact confusion this overload exists to avoid.
    AXIAM_CHECK_FALSE(body.contains("tenant_slug"));
    // The organization half of the workspace still travels: it identifies the
    // organization, not the tenant.
    AXIAM_CHECK(body.value("org_id", "") == kOrgId);
    AXIAM_CHECK(enrollment.opaque_session == "reg-handle");
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("§5.2.2 rule 2: plain enrolment still seals against the acting tenant") {
    // The other call site, unchanged: a record for ANOTHER account is sealed against
    // the tenant being acted on, which is what the client is already pointed at.
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    install_router(st, std::string(R"({"id":"u-1","tenant_id":")") + kActingTenant +
                           R"(","principal_tenant_id":")" + kPrincipalTenant +
                           R"(","organization_level":true})");
    Client c = make_client(st);
    (void)sign_in(c, "");

    (void)c.opaque_enrollment(mint_password());

    const json body = body_of(st, "/auth/opaque/register/start");
    AXIAM_CHECK(body.value("tenant_slug", "") == "acme");
    AXIAM_CHECK_FALSE(body.contains("tenant_id"));
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("§5.2.2 rule 2: enrolment for self refuses before a login") {
    // There is no principal tenant to seal against yet, and falling back to the acting
    // one is exactly the bug this overload exists to prevent.
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    install_router(st, "{}");
    Client c = make_client(st);

    bool threw = false;
    try {
        (void)c.opaque_enrollment_for_self(mint_password());
    } catch (const NetworkError& e) {
        threw = true;
        AXIAM_CHECK(std::string(e.what()).find("principal tenant") != std::string::npos);
    }
    AXIAM_CHECK(threw);
    // The request that must NOT happen.
    AXIAM_CHECK(st->count() == 0);
    AXIAM_CHECK_FALSE(fake.leaked());
}

// ---------------------------------------------------------------------------
// §5.2.3 rules 1 and 2 — tenant_scope on an assignment
// ---------------------------------------------------------------------------

AXIAM_TEST("§5.2.3 rule 1: an empty tenant_scope never reaches the wire") {
    // `[]` is refused with 400, and an engaged optional holding an empty vector is what
    // "no tenants named" naturally produces — so both spellings of absent must travel
    // the same way: by not appearing.
    auto fixture = axtest::mgmt::signed_in(204, "");

    AssignRoleToUserRequest body;
    body.user_id = kSomeId;
    body.tenant_scope = std::vector<std::string>{};  // engaged, empty: the shape the
                                                     // ordinary guard misses
    fixture.client.management().roles().assign_to_user(kSomeId, body);

    const json sent = json::parse(fixture.state->last().body, nullptr, false);
    AXIAM_CHECK_FALSE(sent.contains("tenant_scope"));
    // ...and the rest of the body survives the removal.
    AXIAM_CHECK(sent.value("user_id", "") == kSomeId);
}

AXIAM_TEST("§5.2.3 rule 2: a named tenant_scope is sent on all three bodies") {
    // Dropping a scope the caller DID name would turn a refusal they need to see into a
    // success that silently applied no restriction.
    auto fixture = axtest::mgmt::signed_in_three(204, "", 204, "", 204, "");
    const std::vector<std::string> scope{kScopedTenant};

    AssignRoleToUserRequest user_body;
    user_body.user_id = kSomeId;
    user_body.tenant_scope = scope;
    fixture.client.management().roles().assign_to_user(kSomeId, user_body);
    AXIAM_CHECK(json::parse(fixture.state->last().body, nullptr, false)["tenant_scope"] ==
                json(scope));

    AssignRoleToGroupRequest group_body;
    group_body.group_id = kSomeId;
    group_body.tenant_scope = scope;
    fixture.client.management().roles().assign_to_group(kSomeId, group_body);
    AXIAM_CHECK(json::parse(fixture.state->last().body, nullptr, false)["tenant_scope"] ==
                json(scope));

    AssignRoleToServiceAccountRequest sa_body;
    sa_body.service_account_id = kSomeId;
    sa_body.tenant_scope = scope;
    fixture.client.management().roles().assign_to_service_account(kSomeId, sa_body);
    AXIAM_CHECK(json::parse(fixture.state->last().body, nullptr, false)["tenant_scope"] ==
                json(scope));
}

AXIAM_TEST("§5.2.3 rule 1: the allowlist is one field wide") {
    // Elsewhere an empty array is meaningful — a replacement body clearing a list — and
    // dropping it would make "remove every entry" inexpressible.
    auto fixture = axtest::mgmt::signed_in(
        200,
        R"json({"created_at":"2026-08-30T00:00:00Z","enabled":true,"events":[],)json"
        R"json("id":"99999999-9999-4999-8999-999999999999",)json"
        R"json("retry_policy":{"backoff_multiplier":1.5,"initial_delay_secs":1,"max_retries":1},)json"
        R"json("tenant_id":"11111111-1111-4111-8111-111111111111",)json"
        R"json("updated_at":"2026-08-30T00:00:00Z","url":"https://hook.example"})json");

    UpdateWebhookRequest body;
    body.events = std::vector<std::string>{};
    fixture.client.management().webhooks().update(kSomeId, body);

    const json sent = json::parse(fixture.state->last().body, nullptr, false);
    AXIAM_REQUIRE(sent.contains("events"));
    AXIAM_CHECK(sent["events"].is_array());
    AXIAM_CHECK(sent["events"].empty());
}
