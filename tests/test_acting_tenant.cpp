// CONTRACT.md §5.2 rule 1 (contract 1.51) — the acting-tenant helper.
//
// An organization-level principal acts on another tenant of its organization by
// sending X-Axiam-Tenant. The assertions here are about the WIRE, not the arguments:
// the header is sent when set, ABSENT when not (the I4 twin — a client that never asked
// for one must send byte-for-byte what it sent before 1.51), never coupled to
// X-Tenant-ID or a {tenant_id} path segment, and refused client-side when a held login
// result says the server would refuse it.

#include <memory>
#include <string>
#include <vector>

#include <json.hpp>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/management.hpp"
#include "fake_transport.hpp"

using namespace axiam;
using namespace axiam::management;
using axtest::FakeState;
using axtest::json_response;
using json = nlohmann::json;

namespace {

constexpr const char* kUuid = "11111111-1111-4111-8111-111111111111";
constexpr const char* kOrgId = "11111111-1111-4111-8111-111111111111";
constexpr const char* kOtherTenant = "44444444-4444-4444-8444-444444444444";
constexpr const char* kThirdTenant = "55555555-5555-4555-8555-555555555555";
constexpr const char* kReachableOnly = "66666666-6666-4666-8666-666666666666";

std::string login_body(bool org_level, const std::vector<std::string>& reachable = {}) {
    json user;
    user["id"] = "user-1";
    user["username"] = "root";
    user["email"] = "root@example.com";
    user["tenant_id"] = kUuid;
    user["organization_level"] = org_level;
    if (!reachable.empty()) user["reachable_tenant_ids"] = reachable;
    json body;
    body["session_id"] = "sess-1";
    body["expires_in"] = 900;
    body["user"] = user;
    return body.dump();
}

Client make_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://iam.example.com")
        .tenant_id(kUuid)
        .org_id(kOrgId)
        .transport(axtest::make_fake(st))
        .build();
}

/// Router that answers /auth/login with `login_body`, and every other request with
/// `status`/`resp_body` (default 200/empty envelope for a bare-array or Page read).
std::shared_ptr<FakeState> router_for(bool org_level, const std::vector<std::string>& reachable,
                                      long status = 200,
                                      std::string resp_body = R"({"items":[],"total":0})") {
    auto st = std::make_shared<FakeState>();
    const std::string login = login_body(org_level, reachable);
    st->router = [login, status, resp_body](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(200, login);
        }
        return json_response(status, resp_body);
    };
    return st;
}

std::optional<std::string> acting_header_of(const axtest::RecordedReq& r) {
    auto it = r.headers.find(kActingTenantHeader);
    if (it == r.headers.end()) return std::nullopt;
    return it->second;
}

// ---------------------------------------------------------------------------
// Sent when set, ABSENT when not (the I4 twin)
// ---------------------------------------------------------------------------

// The builder form puts X-Axiam-Tenant on a management request and leaves X-Tenant-ID
// naming the constructor tenant — the two headers are read by different mechanisms and
// this SDK does not couple them (§5, §5.2 rule 1).
AXIAM_TEST("§5.2 rule 1: the builder form sends the header beside an unchanged X-Tenant-ID") {
    auto st = router_for(true, {});
    auto client = Client::builder()
                     .base_url("https://iam.example.com")
                     .tenant_id(kUuid)
                     .org_id(kOrgId)
                     .with_acting_tenant(kOtherTenant)
                     .transport(axtest::make_fake(st))
                     .build();
    client.login("root@example.com", "pw");

    client.management().groups().list();

    const auto req = st->last();
    AXIAM_CHECK(acting_header_of(req) == std::optional<std::string>(kOtherTenant));
    auto tid = req.headers.find("X-Tenant-ID");
    AXIAM_CHECK(tid != req.headers.end() && tid->second == kUuid);
}

// The on-client form, on management, check_access, refresh, logout and a self-service
// POST — the axiam-java-sdk C-4 lesson: "a client acting on a tenant sends
// X-Axiam-Tenant on EVERY /api/v1 REST call", not only the ones an SDK happens to
// route through one code path.
AXIAM_TEST("§5.2 rule 1: acting_tenant() reaches management, check_access, refresh, logout "
          "and a self-service POST") {
    auto st = router_for(true, {});
    auto client = make_client(st);
    client.login("root@example.com", "pw");
    client.acting_tenant(kOtherTenant);

    client.management().groups().list();
    AXIAM_CHECK(acting_header_of(st->last()) == std::optional<std::string>(kOtherTenant));

    client.check_access("read", kUuid);
    AXIAM_CHECK(acting_header_of(st->last()) == std::optional<std::string>(kOtherTenant));

    client.batch_check({AccessCheck{"read", kUuid, std::nullopt, std::nullopt}});
    AXIAM_CHECK(acting_header_of(st->last()) == std::optional<std::string>(kOtherTenant));

    client.refresh();
    AXIAM_CHECK(acting_header_of(st->last()) == std::optional<std::string>(kOtherTenant));

    client.logout();
    AXIAM_CHECK(acting_header_of(st->last()) == std::optional<std::string>(kOtherTenant));
}

// A self-service POST specifically — CONTRACT.md §5.2.2 rule 4: "An SDK MUST NOT work
// around that by clearing or rewriting X-Axiam-Tenant for those calls."
AXIAM_TEST("§5.2.2 rule 4: acting_tenant() reaches a self-service POST unchanged") {
    auto st = router_for(true, {}, 204, "");
    auto client = make_client(st);
    client.login("root@example.com", "pw");
    client.acting_tenant(kOtherTenant);

    client.resend_own_verification();

    AXIAM_CHECK(acting_header_of(st->last()) == std::optional<std::string>(kOtherTenant));
}

// The I4 twin: a client that never called acting_tenant()/with_acting_tenant() sends
// NO X-Axiam-Tenant at all, on any of the same five call shapes — byte-for-byte what it
// sent before 1.51.
AXIAM_TEST("§5.2 rule 1 (I4): a client that never set an acting tenant sends no header") {
    auto st = router_for(true, {});
    auto client = make_client(st);
    client.login("root@example.com", "pw");

    client.management().groups().list();
    AXIAM_CHECK(!acting_header_of(st->last()).has_value());

    client.check_access("read", kUuid);
    AXIAM_CHECK(!acting_header_of(st->last()).has_value());

    client.refresh();
    AXIAM_CHECK(!acting_header_of(st->last()).has_value());

    client.logout();
    AXIAM_CHECK(!acting_header_of(st->last()).has_value());
}

// clear_acting_tenant() stops the header, and is idempotent / harmless on a client that
// never set one.
AXIAM_TEST("§5.2 rule 1: clear_acting_tenant() stops the header") {
    auto st = router_for(true, {});
    auto client = make_client(st);
    client.login("root@example.com", "pw");
    client.acting_tenant(kOtherTenant);
    client.clear_acting_tenant();
    client.clear_acting_tenant();  // idempotent

    client.management().groups().list();

    AXIAM_CHECK(!acting_header_of(st->last()).has_value());
    AXIAM_CHECK(!client.acting_tenant_id().has_value());
}

// ---------------------------------------------------------------------------
// UUID validation, client-side, zero wire calls
// ---------------------------------------------------------------------------

AXIAM_TEST("§5.2 rule 1: a non-UUID acting tenant is refused client-side (on-client form)") {
    auto st = router_for(true, {});
    auto client = make_client(st);
    client.login("root@example.com", "pw");
    const std::size_t before = st->count();

    bool threw = false;
    try {
        client.acting_tenant("acme-tenant");
    } catch (const NetworkError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(st->count() == before);
    AXIAM_CHECK(!client.acting_tenant_id().has_value());
}

AXIAM_TEST("§5.2 rule 1: a non-UUID acting tenant is refused client-side (builder form)") {
    bool threw = false;
    try {
        Client::builder().base_url("https://iam.example.com").tenant_id(kUuid)
            .with_acting_tenant("not-a-uuid");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
}

// ---------------------------------------------------------------------------
// Gating: refused client-side, zero wire calls, when a held login result says so
// ---------------------------------------------------------------------------

AXIAM_TEST("§5.2 rule 1: acting_tenant() refuses client-side for a non-organization-level "
          "principal") {
    auto st = router_for(/*org_level=*/false, {});
    auto client = make_client(st);
    client.login("alice@example.com", "pw");
    const std::size_t before = st->count();

    bool threw = false;
    try {
        client.acting_tenant(kOtherTenant);
    } catch (const AuthzError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(st->count() == before);  // zero wire calls
}

AXIAM_TEST("§5.2.3 rule 4: acting_tenant() refuses a tenant outside reachable_tenant_ids") {
    auto st = router_for(true, {kReachableOnly});
    auto client = make_client(st);
    client.login("root@example.com", "pw");
    const std::size_t before = st->count();

    bool threw = false;
    try {
        client.acting_tenant(kThirdTenant);
    } catch (const AuthzError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(st->count() == before);

    // The one IN reachable_tenant_ids is accepted.
    client.acting_tenant(kReachableOnly);
    client.management().groups().list();
    AXIAM_CHECK(acting_header_of(st->last()) == std::optional<std::string>(kReachableOnly));
}

// A client holding NO login result — here, one that has never logged in at all — has
// nothing to gate on: the header is sent as asked and the server's 403 is the answer.
AXIAM_TEST("§5.2 rule 1: a client holding no login result sends the header regardless") {
    auto st = router_for(true, {});
    auto client = make_client(st);
    // No login() call.

    client.acting_tenant(kOtherTenant);  // must not throw

    AXIAM_CHECK(client.acting_tenant_id() == std::optional<std::string>(kOtherTenant));
}

// ---------------------------------------------------------------------------
// Reset to UNKNOWN, not to false: which sessions count as holding a login result
// ---------------------------------------------------------------------------

// logout() resets the gate to unknown: a later acting_tenant() must not still refuse on
// the PREVIOUS principal's (non-organization-level) report.
AXIAM_TEST("§5.2 rule 1: logout() resets the acting-tenant gate to unknown") {
    auto st = router_for(/*org_level=*/false, {});
    auto client = make_client(st);
    client.login("alice@example.com", "pw");
    client.logout();

    client.acting_tenant(kOtherTenant);  // must not throw: the gate is unknown now

    AXIAM_CHECK(client.acting_tenant_id() == std::optional<std::string>(kOtherTenant));
}

// The C-5 lesson (axiam-csharp-sdk, and the same bug in the merged Go and TypeScript
// ports): every call that completes a NEW session resets the gate to what THAT
// response reported, never carrying a stale login result forward. An
// organization_level=false login followed by a session-completing call that reports NO
// user object must not still refuse acting_tenant() on the first login's report.
AXIAM_TEST("§5.2 rule 1 (C-5 lesson): a session-completing call with no user object "
          "resets the gate to unknown, not to the previous login's report") {
    auto st = std::make_shared<FakeState>();
    const std::string non_org_login = login_body(/*org_level=*/false, {});
    // mfa/verify completes a NEW session but this fixture's response carries no `user`
    // at all — the shape §5.2's "which sessions count as holding a login result"
    // carve-out is about.
    st->router = [non_org_login](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(200, non_org_login);
        }
        if (req.url.find("/auth/mfa/verify") != std::string::npos) {
            return json_response(200, R"({"session_id":"sess-2","expires_in":900})");
        }
        return json_response(200, R"({"items":[],"total":0})");
    };
    auto client = make_client(st);
    client.login("alice@example.com", "pw");  // organization_level: false, recorded
    client.verify_mfa(std::string("chal"), "000000");  // completes a session, no `user`

    // Must NOT throw: the gate reset to unknown, so acting_tenant() sends the header
    // and lets the server's 403 decide, rather than refusing on the first login's
    // (non-organization-level) report.
    client.acting_tenant(kOtherTenant);
    AXIAM_CHECK(client.acting_tenant_id() == std::optional<std::string>(kOtherTenant));
}

// ---------------------------------------------------------------------------
// §17 decision memo: the acting tenant is part of the key
// ---------------------------------------------------------------------------

// Two acting tenants must not share one memoized decision: the server can answer the
// same check differently per tenant, and the memo key drops the acting tenant on
// exactly the mutation this test exists to catch.
AXIAM_TEST("§17 / §5.2: the decision memo is keyed on the acting tenant") {
    auto st = std::make_shared<FakeState>();
    const std::string login = login_body(true, {});
    int calls = 0;
    st->router = [&login, &calls](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(200, login);
        }
        if (req.url.find("/authz/check") != std::string::npos) {
            ++calls;
            // Different tenants get different answers -- if the memo key drops the
            // acting tenant, the second check reuses the first tenant's cached
            // `true` instead of reaching the wire for `false`.
            const bool first_tenant_only = calls == 1;
            return json_response(200, std::string("{\"allowed\":") +
                                          (first_tenant_only ? "true" : "false") + "}");
        }
        return json_response(200, "{}");
    };
    auto client = Client::builder()
                     .base_url("https://iam.example.com")
                     .tenant_id(kUuid)
                     .org_id(kOrgId)
                     .decision_memo_ttl(std::chrono::milliseconds(5000))
                     .transport(axtest::make_fake(st))
                     .build();
    client.login("root@example.com", "pw");

    client.acting_tenant(kOtherTenant);
    const auto first = client.check_access("read", kUuid);
    AXIAM_CHECK(first.allowed == true);

    client.acting_tenant(kThirdTenant);
    const auto second = client.check_access("read", kUuid);
    AXIAM_CHECK(second.allowed == false);  // NOT the first tenant's cached `true`
    AXIAM_CHECK(calls == 2);  // both reached the wire -- no cross-tenant hit
}

}  // namespace
