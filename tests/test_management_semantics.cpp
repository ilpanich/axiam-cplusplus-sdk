// The CONTRACT.md §27.9 required-test list, hand-written.
//
// The generated suite next door asserts that all 146 operations reach the right route.
// These assert the RULES -- the behaviours §27.4 specifies that hold across the whole
// surface and that no per-operation test would catch.

#include <string>

#include "assert.hpp"
#include "axiam/axiam.hpp"
#include "axiam/management.hpp"
#include "management_test_util.hpp"

namespace {

using namespace axiam;
using namespace axiam::management;

constexpr const char* kUuid = "11111111-1111-4111-8111-111111111111";
constexpr const char* kOtherOrg = "22222222-2222-4222-8222-222222222222";

const char* kRole =
    R"json({"created_at":"2026-08-26T00:00:00Z","description":"d",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","is_global":false,)json"
    R"json("name":"auditor","tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"})json";


// A `Tenant` whose `kind` this SDK knows.
const char* kTenantStandard =
    R"json({"created_at":"2026-08-26T00:00:00Z",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","kind":"standard","metadata":{},)json"
    R"json("name":"ordinary","organization_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("slug":"ordinary","status":"Active","updated_at":"2026-08-26T00:00:00Z"})json";

// The same, with a `kind` only a newer server sends.
const char* kTenantFuture =
    R"json({"created_at":"2026-08-26T00:00:00Z",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","kind":"sandbox","metadata":{},)json"
    R"json("name":"future","organization_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("slug":"future","status":"Active","updated_at":"2026-08-26T00:00:00Z"})json";

// A row written before organization scope existed: no `kind` at all.
const char* kTenantLegacy =
    R"json({"created_at":"2026-08-26T00:00:00Z",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","metadata":{},)json"
    R"json("name":"legacy","organization_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("slug":"legacy","status":"Active","updated_at":"2026-08-26T00:00:00Z"})json";

// A `Certificate` as `certificates.list` projects it.
const char* kCertBound =
    R"json({"bound_service_account_id":"22222222-2222-4222-8222-222222222222",)json"
    R"json("cert_type":"Device","created_at":"2026-08-26T00:00:00Z","fingerprint":"aa:bb",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("issuer_ca_id":"11111111-1111-4111-8111-111111111111","key_algorithm":"Ed25519",)json"
    R"json("metadata":{},"not_after":"2027-08-26T00:00:00Z",)json"
    R"json("not_before":"2026-08-26T00:00:00Z","public_cert_pem":"-----BEGIN CERTIFICATE-----",)json"
    R"json("status":"Active","subject":"CN=device-001",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111"})json";

// The same certificate as `certificates.get` returns it: no projection.
const char* kCertUnbound =
    R"json({"cert_type":"Device","created_at":"2026-08-26T00:00:00Z","fingerprint":"aa:bb",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("issuer_ca_id":"11111111-1111-4111-8111-111111111111","key_algorithm":"Ed25519",)json"
    R"json("metadata":{},"not_after":"2027-08-26T00:00:00Z",)json"
    R"json("not_before":"2026-08-26T00:00:00Z","public_cert_pem":"-----BEGIN CERTIFICATE-----",)json"
    R"json("status":"Active","subject":"CN=device-001",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111"})json";

// ---- rule 1: no session, no wire call ---------------------------------

AXIAM_TEST("§27.4 rule 1: without a session nothing is sent") {
    auto fixture = axtest::mgmt::anonymous();
    bool threw = false;
    try {
        fixture.client.management().roles().get(kUuid);
    } catch (const AuthError& e) {
        threw = true;
        AXIAM_CHECK(std::string(e.what()).find("roles.get") != std::string::npos);
        AXIAM_CHECK(std::string(e.what()).find("rule 1") != std::string::npos);
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(fixture.state->count() == 0);
}

// ---- rule 3: implicit ids, with a per-handle override ------------------

AXIAM_TEST("§27.4 rule 3: org_id is implicit from the client") {
    auto fixture = axtest::mgmt::signed_in(200, R"json({"items":[],"total":0})json");
    fixture.client.management().ca_certificates().list();
    AXIAM_CHECK(fixture.state->last().url.find(kUuid) != std::string::npos);
}

AXIAM_TEST("§27.4 rule 3: in_org overrides the implicit org_id") {
    auto fixture = axtest::mgmt::signed_in(200, R"json({"items":[],"total":0})json");
    fixture.client.management().ca_certificates().in_org(kOtherOrg).list();
    AXIAM_CHECK(fixture.state->last().url.find(kOtherOrg) != std::string::npos);
}

// The failure this pins is not hypothetical on a management surface: a shared handle
// silently repointed by an unrelated code path WRITES to the wrong tenant.
AXIAM_TEST("§27.4 rule 3: in_org returns a copy and leaves the original alone") {
    auto fixture = axtest::mgmt::signed_in_two(200, R"json({"items":[],"total":0})json",
                                               200, R"json({"items":[],"total":0})json");
    auto handle = fixture.client.management().ca_certificates();

    handle.in_org(kOtherOrg).list();
    AXIAM_CHECK(fixture.state->last().url.find(kOtherOrg) != std::string::npos);

    handle.list();
    AXIAM_CHECK(fixture.state->last().url.find(kOtherOrg) == std::string::npos);
    AXIAM_CHECK(fixture.state->last().url.find(kUuid) != std::string::npos);
}

AXIAM_TEST("§27.4 rule 3: a missing scope id refuses instead of sending an empty segment") {
    auto fixture = axtest::mgmt::unscoped();
    bool threw = false;
    try {
        fixture.client.management().ca_certificates().list();
    } catch (const AxiamError& e) {
        threw = true;
        AXIAM_CHECK(std::string(e.what()).find("organization id") != std::string::npos);
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(fixture.state->count() == 1);  // the login, and nothing after it
}

// ---- rule 4: paging ----------------------------------------------------

AXIAM_TEST("§27.4 rule 4: Page::total is the server's count, not the item count") {
    const std::string body =
        std::string(R"json({"items":[)json") + kRole + "," + kRole + R"json(],"total":97})json";
    auto fixture = axtest::mgmt::signed_in(200, body);

    const auto page = fixture.client.management().roles().list();

    AXIAM_CHECK(page.total == 97);
    AXIAM_CHECK(page.size() == 2);
    AXIAM_CHECK(page.total != static_cast<std::int64_t>(page.size()));
}

AXIAM_TEST("§27.4 rule 4: next() advances by the requested limit, not the item count") {
    PageRequest first{0, 25};
    const auto second = first.next();
    AXIAM_CHECK(second.offset == 25);
    AXIAM_CHECK(second.limit == 25);
    AXIAM_CHECK(second.next().offset == 50);
}

AXIAM_TEST("§27.4 rule 4: nonsense paging values are clamped") {
    PageRequest weird{-10, 0};
    const auto next = weird.next();
    AXIAM_CHECK(next.limit == 50);
    AXIAM_CHECK(next.offset == 50);
}

AXIAM_TEST("§27.4 rule 4: paging reaches the query string") {
    auto fixture = axtest::mgmt::signed_in(200, R"json({"items":[],"total":0})json");
    fixture.client.management().roles().list(PageRequest{100, 25});

    const auto query = axtest::mgmt::query_of(fixture.state->last().url);
    AXIAM_CHECK(query.find("offset=100") != std::string::npos);
    AXIAM_CHECK(query.find("limit=25") != std::string::npos);
}

// A bare-array endpoint returns a vector, never a Page. The type system carries the
// distinction here: there is no `total` to misread.
AXIAM_TEST("§27.4 rule 4: a bare array is a vector, not a Page") {
    auto fixture = axtest::mgmt::signed_in(200, R"json([{"resource_id": "11111111-1111-4111-8111-111111111111", "user": {"created_at": "2026-08-26T00:00:00Z", "email": "example", "email_verified": true, "failed_login_attempts": 1, "id": "11111111-1111-4111-8111-111111111111", "is_locked": true, "locked_until": "2026-08-26T00:00:00Z", "metadata": {}, "mfa_enabled": true, "status": "Active", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z", "username": "example"}}])json");

    const auto users = fixture.client.management().roles().list_users(kUuid);

    AXIAM_CHECK(users.size() == 1);
    static_assert(std::is_same_v<decltype(users), const std::vector<RoleUserAssignment>>,
                  "a bare-array endpoint must not be modelled as a Page");
}

// ---- rule 4: search ----------------------------------------------------

// Asserted on the request URI, not on the argument: a term the SDK accepts and never
// sends is exactly the failure this test exists for -- every caller-side assertion still
// passes while the server returns the unfiltered set.
AXIAM_TEST("§27.4 rule 4: a search term reaches the query string") {
    auto fixture = axtest::mgmt::signed_in(200, R"json({"items":[],"total":0})json");
    PageRequest page{0, 25};
    page.search = "ada";

    fixture.client.management().roles().list(page);

    const auto query = axtest::mgmt::query_of(fixture.state->last().url);
    AXIAM_CHECK(query.find("search=ada") != std::string::npos);
}

// `?search=` is a filter matching nothing, which is a different request from not
// filtering -- so the key is ABSENT, not empty.
AXIAM_TEST("§27.4 rule 4: no search term sends no search key") {
    auto fixture = axtest::mgmt::signed_in(200, R"json({"items":[],"total":0})json");

    fixture.client.management().roles().list(PageRequest{0, 25});

    const auto query = axtest::mgmt::query_of(fixture.state->last().url);
    AXIAM_CHECK(query == "offset=0&limit=25");
}

// A search box that fires on every keystroke sends one the moment it is cleared, and
// "rows containing the empty string" is a different question from "all rows".
AXIAM_TEST("§27.4 rule 4: a blank search term is the same request as none") {
    for (const char* blank : {"", "   ", "\t\n "}) {
        auto fixture = axtest::mgmt::signed_in(200, R"json({"items":[],"total":0})json");
        PageRequest page{0, 25};
        page.search = blank;

        fixture.client.management().roles().list(page);

        AXIAM_CHECK(axtest::mgmt::query_of(fixture.state->last().url) == "offset=0&limit=25");
    }
}

// The server caps the term's length. Re-implementing that cap here would make a
// client-side truncation the server would not have made into a silently different query
// the caller cannot see.
AXIAM_TEST("§27.4 rule 4: a search term is trimmed but never truncated") {
    const std::string long_term(300, 'a');
    auto fixture = axtest::mgmt::signed_in(200, R"json({"items":[],"total":0})json");
    PageRequest page{0, 25};
    page.search = "  " + long_term + "  ";

    fixture.client.management().roles().list(page);

    const auto query = axtest::mgmt::query_of(fixture.state->last().url);
    AXIAM_CHECK(query == "offset=0&limit=25&search=" + long_term);
}

AXIAM_TEST("§27.4 rule 4: normalize_search trims, and blank means absent") {
    AXIAM_CHECK(PageRequest::normalize_search("").empty());
    AXIAM_CHECK(PageRequest::normalize_search("   ").empty());
    AXIAM_CHECK(PageRequest::normalize_search("\t\n\r ").empty());
    AXIAM_CHECK(PageRequest::normalize_search("ada") == "ada");
    AXIAM_CHECK(PageRequest::normalize_search("  ada  ") == "ada");
}

// next() carries the term, and matching() returns a COPY -- a shared request cannot be
// repointed at a different query by unrelated code.
AXIAM_TEST("§27.4 rule 4: next() carries the term and matching() copies") {
    PageRequest first{10, 25};
    first.search = "ada";

    const auto second = first.next();
    AXIAM_CHECK(second.search == "ada");
    AXIAM_CHECK(second.offset == 35);

    const auto other = first.matching("grace");
    AXIAM_CHECK(first.search == "ada");
    AXIAM_CHECK(other.search == "grace");
    AXIAM_CHECK(other.offset == 10);
    AXIAM_CHECK(other.limit == 25);
}

// Asserted on EVERY recorded request, not on the count: a walk that filtered only its
// first request returns the matches followed by the unfiltered tail, which reads as a
// server bug from the caller's side.
AXIAM_TEST("§27.4 rule 4: a walk carries the term on every request") {
    const std::string one =
        std::string(R"json({"items":[)json") + kRole + R"json(],"total":3})json";
    auto fixture = axtest::mgmt::signed_in_three(
        200, one, 200, one, 200, R"json({"items":[],"total":3})json");

    PageRequest page{0, 1};
    page.search = "ad";
    for (;;) {
        const auto batch = fixture.client.management().roles().list(page);
        if (batch.empty()) break;
        // Derived from the PAGE's own request, which is how a caller walks -- so this
        // asserts the term survived the round trip through the page, not merely that
        // next() copies a struct member.
        page = batch.next_request();
    }

    std::size_t seen = 0;
    {
        std::lock_guard<std::mutex> lock(fixture.state->mtx);
        for (const auto& r : fixture.state->requests) {
            if (r.url.find("/api/v1/roles") == std::string::npos) continue;
            ++seen;
            AXIAM_CHECK(r.url.find("search=ad") != std::string::npos);
        }
    }
    AXIAM_CHECK(seen == 3);
}

// ---- §27.11: model additions -------------------------------------------

// The page below carries two tenants and only the second has a `kind` this SDK has never
// seen. A closed enum would throw while decoding it and take the first one -- which the
// caller did ask for -- down with it. That blast radius is what rule 1 is about.
AXIAM_TEST("§27.11 rule 1: an unknown enum value does not lose the page") {
    const std::string body = std::string(R"json({"items":[)json") + kTenantStandard + "," +
                             kTenantFuture + R"json(],"total":2})json";
    auto fixture = axtest::mgmt::signed_in(200, body);

    const auto page = fixture.client.management().tenants().list();

    AXIAM_CHECK(page.size() == 2);
    AXIAM_CHECK(page.items[0].kind == std::optional<TenantKind>(TenantKind::Standard));
    AXIAM_CHECK(page.items[1].kind == std::optional<TenantKind>(TenantKind::Unknown));
}

// A row written before organization scope existed carries no `kind` at all, and that is
// not an error.
AXIAM_TEST("§27.11 rule 1: an absent tenant kind stays absent") {
    const std::string body =
        std::string(R"json({"items":[)json") + kTenantLegacy + R"json(],"total":1})json";
    auto fixture = axtest::mgmt::signed_in(200, body);

    const auto page = fixture.client.management().tenants().list();

    AXIAM_CHECK(!page.items[0].kind.has_value());
}

// §27.11 rule 2: an organization's scope tenant is reserved at organization creation and
// enforced by a unique index. A client able to set the field could ask for a second one,
// and the request would be refused at the database rather than at the type. Asserted on
// the ENCODED body, which is what reaches the server.
AXIAM_TEST("§27.11 rule 2: tenant kind is read-only") {
    {
        auto fixture = axtest::mgmt::signed_in(200, kTenantStandard);
        CreateTenantRequest body{};
        body.name = "acme";
        body.slug = "acme";
        fixture.client.management().tenants().create(body);
        AXIAM_CHECK(fixture.state->last().body.find("kind") == std::string::npos);
    }
    {
        auto fixture = axtest::mgmt::signed_in(200, kTenantStandard);
        UpdateTenant body{};
        body.name = "renamed";
        fixture.client.management().tenants().update(kUuid, body);
        AXIAM_CHECK(fixture.state->last().body.find("kind") == std::string::npos);
    }
}

// §27.11 rule 3: "the listener trusts no CAs" and "there was no listener to ask" are
// different operational states, and only one of them is a problem. Coalescing the first
// to 0 reports a healthy plaintext deployment as a broken TLS one.
AXIAM_TEST("§27.11 rule 3: trusted_anchors keeps absent distinct from zero") {
    // Nothing was reloaded: a plaintext deployment, or client_auth off. The server says
    // so by omitting the count, and the SDK must not report that as "trusts zero CAs".
    {
        auto fixture = axtest::mgmt::signed_in(
            200,
            R"json({"ca_certificate_id":"11111111-1111-4111-8111-111111111111",)json"
            R"json("message":"stored","mtls_trust_anchor":true,"restart_required":true})json");
        const auto absent = fixture.client.management().ca_certificates()
                                .set_mtls_trust_anchor(kUuid, SetMtlsTrustAnchor{true});
        AXIAM_CHECK(!absent.trusted_anchors.has_value());
    }
    // The listener WAS reloaded and now trusts none. A different operational state, and
    // the only one of the two that is a problem.
    {
        auto fixture = axtest::mgmt::signed_in(
            200,
            R"json({"ca_certificate_id":"11111111-1111-4111-8111-111111111111",)json"
            R"json("message":"reloaded","mtls_trust_anchor":false,)json"
            R"json("restart_required":false,"trusted_anchors":0})json");
        const auto zero = fixture.client.management().ca_certificates()
                              .set_mtls_trust_anchor(kUuid, SetMtlsTrustAnchor{true});
        AXIAM_CHECK(zero.trusted_anchors == std::optional<std::int64_t>(0));
    }
}

// §27.11 rule 4: the server resolves this for a whole page in one query, so `list`
// populates it and `get` leaves it empty -- with no second request to fill it in. A `get`
// that silently costs two round trips is what §27.4 rule 3 forbids elsewhere.
AXIAM_TEST("§27.11 rule 4: the certificate projection is list-only") {
    const std::string page_body =
        std::string(R"json({"items":[)json") + kCertBound + R"json(],"total":1})json";
    auto fixture = axtest::mgmt::signed_in_two(200, page_body, 200, kCertUnbound);

    const auto listed = fixture.client.management().certificates().list();
    const auto fetched = fixture.client.management().certificates().get(kUuid);

    AXIAM_CHECK(listed.items[0].bound_service_account_id ==
                std::optional<std::string>(kOtherOrg));
    AXIAM_CHECK(!fetched.bound_service_account_id.has_value());
    AXIAM_CHECK(fixture.state->count_path("/api/v1/certificates") == 2);
}

// ---- rule 5: sparse bodies ---------------------------------------------

AXIAM_TEST("§27.4 rule 5: a sparse update sends only what you set") {
    auto fixture = axtest::mgmt::signed_in(200, kRole);
    UpdateRole body{};
    body.name = "renamed";

    fixture.client.management().roles().update(kUuid, body);

    AXIAM_CHECK(fixture.state->last().body == R"json({"name":"renamed"})json");
}

// An engaged optional holding `false` is SENT. This is why the members are
// std::optional rather than a sentinel: `is_global == false` is a value a caller means,
// and no sentinel could represent both it and "unset".
AXIAM_TEST("§27.4 rule 5: an engaged false is sent, not swallowed") {
    auto fixture = axtest::mgmt::signed_in(200, kRole);
    UpdateRole body{};
    body.is_global = false;

    fixture.client.management().roles().update(kUuid, body);

    AXIAM_CHECK(fixture.state->last().body == R"json({"is_global":false})json");
}

AXIAM_TEST("§27.4 rule 5: an empty sparse body sends {}") {
    auto fixture = axtest::mgmt::signed_in(200, kRole);
    fixture.client.management().roles().update(kUuid, UpdateRole{});
    AXIAM_CHECK(fixture.state->last().body == "{}");
}

// ---- rule 6 + rule 7 ----------------------------------------------------

AXIAM_TEST("§27.4 rule 6: a second delete raises NotFoundError") {
    auto fixture = axtest::mgmt::signed_in_two(204, "", 404, "");
    fixture.client.management().roles().delete_(kUuid);

    bool threw = false;
    try {
        fixture.client.management().roles().delete_(kUuid);
    } catch (const NotFoundError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
}

// Rule 7's parent column -- the counter-intuitive half, and the one a port gets wrong.
// A sibling SDK shipped ConflictError under NetworkError; this is what caught it.
AXIAM_TEST("§27.4 rule 7: every classification keeps the parent §2 gave it") {
    static_assert(std::is_base_of_v<AuthzError, NotFoundError>,
                  "404 belongs under AuthzError: a multi-tenant server answers it for "
                  "another tenant's object precisely so a caller cannot enumerate it");
    static_assert(std::is_base_of_v<AuthzError, ConflictError>,
                  "§2 already maps 409 to AuthzError; rule 7 keeps that mapping");
    static_assert(std::is_base_of_v<NetworkError, ValidationError>,
                  "400/422 are inherited from §2's own 400 row");

    static_assert(!std::is_base_of_v<NetworkError, NotFoundError>, "");
    static_assert(!std::is_base_of_v<NetworkError, ConflictError>, "");
    static_assert(!std::is_base_of_v<AuthzError, ValidationError>, "");

    // A catch written before §27 existed still catches the first two, which is the
    // property the rule asks for.
    AXIAM_CHECK(true);
}

AXIAM_TEST("§27.4 rule 7: 404, 409, 400 and 422 each map to their sub-type") {
    struct Case { long status; int which; };
    const Case cases[] = {{404, 0}, {409, 1}, {400, 2}, {422, 2}};

    for (const auto& c : cases) {
        auto fixture = axtest::mgmt::signed_in(c.status, "");
        int caught = -1;
        try {
            fixture.client.management().roles().get(kUuid);
        } catch (const NotFoundError&) {
            caught = 0;
        } catch (const ConflictError&) {
            caught = 1;
        } catch (const ValidationError&) {
            caught = 2;
        } catch (const AxiamError&) {
            caught = 9;
        }
        AXIAM_CHECK(caught == c.which);
    }
}

// A status rule 7 does not name keeps §2's own mapping.
AXIAM_TEST("§27.4 rule 7: an unrelated status keeps the §2 mapping") {
    auto fixture = axtest::mgmt::signed_in(403, "");
    bool authz = false, subtype = false;
    try {
        fixture.client.management().roles().get(kUuid);
    } catch (const NotFoundError&) {
        subtype = true;
    } catch (const ConflictError&) {
        subtype = true;
    } catch (const AuthzError&) {
        authz = true;
    }
    AXIAM_CHECK(authz);
    AXIAM_CHECK(!subtype);
}

// ---- rule 8: only GET is retried ---------------------------------------

AXIAM_TEST("§27.4 rule 8: a failed GET is retried") {
    auto fixture = axtest::mgmt::signed_in_two(503, "", 200, kRole);
    const auto role = fixture.client.management().roles().get(kUuid);
    AXIAM_CHECK(role.name == "auditor");
    AXIAM_CHECK(fixture.state->count() == 3);  // login + two GET attempts
}

AXIAM_TEST("§27.4 rule 8: a failed write is NOT retried") {
    auto fixture = axtest::mgmt::signed_in_two(503, "", 200, kRole);
    try {
        fixture.client.management().roles().update(kUuid, UpdateRole{});
    } catch (const AxiamError&) {
    }
    AXIAM_CHECK(fixture.state->count() == 2);  // login + exactly one attempt
}

// A 4xx is a decisive answer, not a transport failure: re-sending it just spends the
// caller's rate limit to be told the same thing again.
AXIAM_TEST("§27.4 rule 8: a rejected GET is not retried") {
    auto fixture = axtest::mgmt::signed_in(422, "");
    try {
        fixture.client.management().roles().get(kUuid);
    } catch (const ValidationError&) {
    }
    AXIAM_CHECK(fixture.state->count() == 2);
}

// ---- rule 10: nothing is cached ----------------------------------------

AXIAM_TEST("§27.4 rule 10: the same read twice is two wire calls") {
    auto fixture = axtest::mgmt::signed_in_two(200, kRole, 200, kRole);
    auto roles = fixture.client.management().roles();
    roles.get(kUuid);
    roles.get(kUuid);
    AXIAM_CHECK(fixture.state->count() == 3);
}

// ---- rule 11: telemetry carries the path TEMPLATE ----------------------

// A metrics label carrying a user id is an unbounded-cardinality series and, on this
// surface, a slow identifier leak into whatever consumes the telemetry.
AXIAM_TEST("§27.4 rule 11: telemetry names the path template, never the substituted path") {
    auto fixture = axtest::mgmt::signed_in_telemetry(200, kRole);
    fixture.client.management().roles().get(kUuid);

    bool saw_template = false;
    for (const auto& path : *fixture.paths) {
        AXIAM_CHECK(path.find(kUuid) == std::string::npos);
        if (path == "/api/v1/roles/{role_id}") saw_template = true;
    }
    AXIAM_CHECK(saw_template);
}

// ---- §27.5: one-time secrets -------------------------------------------

AXIAM_TEST("§27.5: a secret reaches the wire in the clear") {
    auto fixture = axtest::mgmt::signed_in(200, R"json({"created_at": "2026-08-26T00:00:00Z", "email": "example", "email_verified": true, "failed_login_attempts": 1, "id": "11111111-1111-4111-8111-111111111111", "is_locked": true, "locked_until": "2026-08-26T00:00:00Z", "metadata": {}, "mfa_enabled": true, "status": "Active", "tenant_id": "11111111-1111-4111-8111-111111111111", "updated_at": "2026-08-26T00:00:00Z", "username": "example"})json");
    CreateUserRequest body{};
    body.username = "alice";
    body.email = "alice@example.com";
    body.password = Sensitive<std::string>("hunter2");

    fixture.client.management().users().create(body);

    AXIAM_CHECK(fixture.state->last().body.find("hunter2") != std::string::npos);
    AXIAM_CHECK(fixture.state->last().body.find("[SENSITIVE]") == std::string::npos);
}

// ...and the same value renders redacted everywhere else (§7 rule 3).
AXIAM_TEST("§27.5: the same secret is redacted in an ordinary rendering") {
    const Sensitive<std::string> secret("hunter2");
    AXIAM_CHECK(secret.to_string() == "[SENSITIVE]");
}

// ---- transport edges ----------------------------------------------------

AXIAM_TEST("a non-JSON success body is a NetworkError") {
    auto fixture = axtest::mgmt::signed_in(200, "not json at all");
    bool threw = false;
    try {
        fixture.client.management().roles().get(kUuid);
    } catch (const NetworkError& e) {
        threw = true;
        AXIAM_CHECK(std::string(e.what()).find("expected a JSON") != std::string::npos);
    }
    AXIAM_CHECK(threw);
}

// A path parameter is percent-encoded: an identifier is caller-supplied, and a raw '/'
// in one would silently retarget the request at a different route.
AXIAM_TEST("a path parameter is percent-encoded") {
    auto fixture = axtest::mgmt::signed_in(200, kRole);
    fixture.client.management().roles().get("a/b");

    const auto path = axtest::mgmt::path_of(fixture.state->last().url);
    AXIAM_CHECK(path.find("roles/a/b") == std::string::npos);
    AXIAM_CHECK(path.find("a%2Fb") != std::string::npos);
}

// A response missing a field openapi.json marks required is a SERVER problem, and must
// surface inside the §2 taxonomy. Left to nlohmann it throws its own exception type,
// which a caller who wrote `catch (const AxiamError&)` around a management call would
// not catch -- and whose message names neither the operation nor the fact that the body
// was short.
AXIAM_TEST("a short response body is a NetworkError, not a raw JSON exception") {
    auto fixture = axtest::mgmt::signed_in(200, R"json({"id":"only-this"})json");

    bool caught_sdk_error = false;
    try {
        fixture.client.management().roles().get(kUuid);
    } catch (const NetworkError& e) {
        caught_sdk_error = true;
        AXIAM_CHECK(std::string(e.what()).find("roles.get") != std::string::npos);
        AXIAM_CHECK(std::string(e.what()).find("expected shape") != std::string::npos);
    } catch (const std::exception&) {
        // A raw nlohmann exception reaching here is the failure this test exists for.
    }
    AXIAM_CHECK(caught_sdk_error);
}

// The same applies inside a page: one malformed item must not escape as a JSON exception.
AXIAM_TEST("a malformed item inside a page is a NetworkError") {
    auto fixture = axtest::mgmt::signed_in(
        200, R"json({"items":[{"id":"only-this"}],"total":1})json");

    bool caught_sdk_error = false;
    try {
        fixture.client.management().roles().list();
    } catch (const NetworkError&) {
        caught_sdk_error = true;
    } catch (const std::exception&) {
    }
    AXIAM_CHECK(caught_sdk_error);
}

// An unknown enum value DECODES, to an enumerator of its own -- it is never mapped to
// whichever known enumerator happens to be first (CONTRACT.md §27.11 rule 1).
//
// This assertion was inverted in contract 1.31. It used to require `from_wire` to throw on
// an unrecognised value, and the reason that was wrong is blast radius: the throw escapes
// the whole `Page<T>` decode, so one field of one row took the entire page down with it --
// including the rows the caller did ask for.
//
// What the old assertion was PROTECTING is still true and still asserted below: the value
// is not silently read as `Active`. `Unknown` is an enumerator of its own, and its wire
// spelling is the empty string -- which no server value is, so carrying it back into an
// update is refused by the server rather than written as a spelling it never used.
AXIAM_TEST("an unknown enum value decodes without becoming a known one") {
    AXIAM_CHECK(user_status_from_wire("Active") == UserStatus::Active);
    AXIAM_CHECK(to_wire(UserStatus::Active) == "Active");

    AXIAM_CHECK(user_status_from_wire("Ascended") == UserStatus::Unknown);
    AXIAM_CHECK(UserStatus::Unknown != UserStatus::Active);
    AXIAM_CHECK(to_wire(UserStatus::Unknown).empty());
}

}  // namespace
