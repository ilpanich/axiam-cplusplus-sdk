// CONTRACT.md §27.6.1 (contract 1.51) — the three manifest additions: resource
// metadata, the two-shape role binding (plain / resource-scoped with `inherit`), and
// `service_accounts`. Required by §27.9's "Manifest additions" list, alongside §27.6
// rule 6's idempotence test, which every scenario here also satisfies where it applies.

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <json.hpp>

#include "assert.hpp"
#include "axiam/axiam.hpp"
#include "axiam/management_manifest.hpp"
#include "fake_transport.hpp"

using namespace axiam;
using namespace axiam::management;
using axtest::FakeState;
using json = nlohmann::json;

namespace {

constexpr const char* kUuid = "11111111-1111-4111-8111-111111111111";
constexpr const char* kResourceId = "22222222-2222-4222-8222-222222222222";
constexpr const char* kRoleId = "33333333-3333-4333-8333-333333333333";
constexpr const char* kGroupId = "44444444-4444-4444-8444-444444444444";
constexpr const char* kResourceIdTwo = "55555555-5555-4555-8555-555555555555";
constexpr const char* kGroupIdTwo = "66666666-6666-4666-8666-666666666666";

// Every response in this file is built from a real json value and dumped explicitly --
// never handed to json_response() as a bare json object, which would implicitly (and
// wrongly) stringify it as a JSON STRING rather than serialize it.
HttpResponse ok(const json& body) {
    HttpResponse r;
    r.status = 200;
    r.body = body.dump();
    return r;
}
HttpResponse ok_empty() {
    HttpResponse r;
    r.status = 200;
    r.body = "{}";
    return r;
}
HttpResponse status_only(long status, const json& body) {
    HttpResponse r;
    r.status = status;
    r.body = body.dump();
    return r;
}

// The caller sets st->router BEFORE calling this.
Client login_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://iam.example.com")
        .tenant_id(kUuid)
        .org_id(kUuid)
        .transport(axtest::make_fake(st))
        .build();
}

json role_json(const std::string& id, const std::string& name, bool is_global = false) {
    return json{{"id", id},         {"name", name},
               {"description", "d"}, {"is_global", is_global},
               {"tenant_id", kUuid}, {"created_at", "2026-08-26T00:00:00Z"},
               {"updated_at", "2026-08-26T00:00:00Z"}};
}

// Resource.metadata is a genuine JSON OBJECT on the wire; this SDK's model holds it as
// JSON TEXT (a std::string), converted via .dump()/parse() at the edge (see
// gen_management.py's "json_text" field kind). `metadata_text` is parsed here so the
// fixture embeds the object, not its text.
json resource_json(const std::string& id, const std::string& name,
                   const std::string& metadata_text) {
    return json{{"id", id},
               {"name", name},
               {"resource_type", "folder"},
               {"metadata", json::parse(metadata_text)},
               {"tenant_id", kUuid},
               {"created_at", "2026-08-26T00:00:00Z"},
               {"updated_at", "2026-08-26T00:00:00Z"}};
}

json group_json(const std::string& id, const std::string& name) {
    return json{{"id", id},         {"name", name},        {"description", "d"},
               {"metadata", json::object()}, {"tenant_id", kUuid},
               {"created_at", "2026-08-26T00:00:00Z"}, {"updated_at", "2026-08-26T00:00:00Z"}};
}

json service_account_json(const std::string& id, const std::string& name) {
    return json{{"id", id},         {"name", name},        {"client_id", "client-" + id},
               {"status", "Active"}, {"tenant_id", kUuid},
               {"created_at", "2026-08-26T00:00:00Z"}, {"updated_at", "2026-08-26T00:00:00Z"}};
}

json role_assignment_json(const json& role, std::optional<std::string> resource_id,
                          std::optional<bool> inherit,
                          std::optional<std::vector<std::string>> tenant_scope = std::nullopt) {
    json j{{"role", role}};
    if (resource_id) j["resource_id"] = *resource_id;
    if (inherit) j["inherit"] = *inherit;
    if (tenant_scope) j["tenant_scope"] = *tenant_scope;
    return j;
}

json page_of(const json& items) { return json{{"items", items}, {"total", items.size()}}; }

ManifestEntity resource_entity(const std::string& key, const std::string& name,
                               std::optional<std::string> metadata_json) {
    ManifestEntity e;
    e.kind = ManifestKind::Resource;
    e.key = key;
    e.name = name;
    e.resource_type = "folder";
    e.metadata_json = std::move(metadata_json);
    return e;
}

ManifestEntity role_entity(const std::string& key, const std::string& name,
                           bool is_global = false) {
    ManifestEntity e;
    e.kind = ManifestKind::Role;
    e.key = key;
    e.name = name;
    e.is_global = is_global;
    return e;
}

// ---------------------------------------------------------------------------
// §27.6.1 item 1: resources[].metadata
// ---------------------------------------------------------------------------

AXIAM_TEST("§27.6.1 item 1: metadata round-trips -- apply then plan is NoChange") {
    auto st = std::make_shared<FakeState>();
    bool created = false;
    st->router = [&](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) return ok_empty();
        if (req.method == "GET" && req.url.find("/resources") != std::string::npos) {
            if (!created) return ok(page_of(json::array()));
            return ok(page_of(
                json::array({resource_json(kResourceId, "docs", R"({"team":"docs"})")})));
        }
        if (req.method == "POST" && req.url.find("/resources") != std::string::npos) {
            created = true;
            const auto body = json::parse(req.body);
            AXIAM_REQUIRE(body.at("metadata") == json::parse(R"({"team":"docs"})"));
            return ok(resource_json(kResourceId, "docs", R"({"team":"docs"})"));
        }
        return ok_empty();
    };
    auto client = login_client(st);
    client.login("a", "b");

    Manifest m{{resource_entity("docs", "docs", R"({"team":"docs"})")}};
    const auto report = client.management().manifest().apply(m);
    AXIAM_CHECK(report.complete());

    const auto replan = client.management().manifest().plan(m);
    AXIAM_CHECK(replan.converged());
}

AXIAM_TEST("§27.6.1 item 1: a changed metadata key yields Update whose body carries "
          "the WHOLE object") {
    auto st = std::make_shared<FakeState>();
    st->router = [&](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) return ok_empty();
        if (req.method == "GET" && req.url.find("/resources") != std::string::npos) {
            return ok(page_of(json::array(
                {resource_json(kResourceId, "docs", R"({"team":"docs","old":"x"})")})));
        }
        if (req.method == "PUT" && req.url.find("/resources/") != std::string::npos) {
            const auto body = json::parse(req.body);
            // The WHOLE new object, not a merge -- "old" is gone, not preserved.
            AXIAM_REQUIRE(body.at("metadata") == json::parse(R"({"team":"eng"})"));
            return ok(resource_json(kResourceId, "docs", R"({"team":"eng"})"));
        }
        return ok_empty();
    };
    auto client = login_client(st);
    client.login("a", "b");

    Manifest m{{resource_entity("docs", "docs", R"({"team":"eng"})")}};
    const auto plan = client.management().manifest().plan(m);
    AXIAM_CHECK(plan.changes[0].action == ChangeAction::Update);

    const auto report = client.management().manifest().apply(m);
    AXIAM_CHECK(report.complete());
}

// ---------------------------------------------------------------------------
// §27.6.1 item 2: the two-shape role binding
// ---------------------------------------------------------------------------

AXIAM_TEST("§27.6.1 item 2: a resource-scoped binding with inherit:false sends "
          "resource_id and inherit:false; inherit omitted sends no inherit key") {
    auto st = std::make_shared<FakeState>();
    std::string captured_scoped_body, captured_plain_body;
    st->router = [&](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) return ok_empty();
        if (req.method == "GET" && req.url.find("/resources") != std::string::npos) {
            return ok(page_of(json::array({resource_json(kResourceId, "docs", "{}")})));
        }
        if (req.method == "GET" && req.url.find("/roles") != std::string::npos &&
            req.url.find("/groups") == std::string::npos) {
            return ok(page_of(json::array({role_json(kRoleId, "editor")})));
        }
        if (req.method == "GET" && req.url.find("/groups") != std::string::npos &&
            req.url.find("/roles") == std::string::npos) {
            return ok(page_of(json::array()));  // both groups are new
        }
        if (req.method == "POST" && req.url.find("/groups") != std::string::npos &&
            req.url.find("/roles") == std::string::npos) {
            const auto body = json::parse(req.body);
            const std::string name = body.value("name", "");
            return ok(group_json(name == "scoped-group" ? kGroupId : kGroupIdTwo, name));
        }
        if (req.method == "POST" && req.url.find("/roles/") != std::string::npos &&
            req.url.find("/groups") != std::string::npos) {
            if (req.body.find(kResourceId) != std::string::npos) {
                captured_scoped_body = req.body;
            } else {
                captured_plain_body = req.body;
            }
            return ok_empty();
        }
        return ok_empty();
    };
    auto client = login_client(st);
    client.login("a", "b");

    ManifestEntity group_scoped;
    group_scoped.kind = ManifestKind::Group;
    group_scoped.key = "g1";
    group_scoped.name = "scoped-group";
    group_scoped.roles = {ManifestRoleBinding{"editor_role", std::string("docs"), false}};

    ManifestEntity group_plain;
    group_plain.kind = ManifestKind::Group;
    group_plain.key = "g2";
    group_plain.name = "plain-group";
    group_plain.roles = {ManifestRoleBinding{"editor_role", std::nullopt, std::nullopt}};

    Manifest m{{resource_entity("docs", "docs", std::nullopt), role_entity("editor_role", "editor"),
               group_scoped, group_plain}};
    const auto report = client.management().manifest().apply(m);
    AXIAM_CHECK(report.complete());

    AXIAM_CHECK(!captured_scoped_body.empty());
    const auto scoped = json::parse(captured_scoped_body);
    AXIAM_CHECK(scoped.at("resource_id") == kResourceId);
    AXIAM_CHECK(scoped.at("inherit") == false);

    AXIAM_CHECK(!captured_plain_body.empty());
    const auto plain = json::parse(captured_plain_body);
    AXIAM_CHECK(!plain.contains("resource_id"));
    AXIAM_CHECK(!plain.contains("inherit"));
}

// A manifest binding one role to one subject TWICE is rejected with zero wire calls
// (the server's has_role UNIQUE(in, out) makes the state unsatisfiable -- §27.6.1).
AXIAM_TEST("§27.6.1 item 2: one role bound twice to one subject is rejected client-side, "
          "zero wire calls") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) -> HttpResponse { return ok_empty(); };
    auto client = login_client(st);
    // No login() -- this must fail before ANY wire call, login included.

    ManifestEntity group;
    group.kind = ManifestKind::Group;
    group.key = "g";
    group.name = "g";
    group.roles = {ManifestRoleBinding{"r", std::nullopt, std::nullopt},
                   ManifestRoleBinding{"r", std::string("docs"), false}};

    Manifest m{{resource_entity("docs", "docs", std::nullopt), role_entity("r", "editor"), group}};

    bool threw = false;
    try {
        client.management().manifest().plan(m);
    } catch (const ManifestError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(st->count() == 0);
}

// Changing a binding's resource is an unassign followed by an assign, in that order;
// tenant_scope on the server binding survives the change.
AXIAM_TEST("§27.6.1 item 2: changing a binding's resource is unassign-then-assign and "
          "carries tenant_scope") {
    auto st = std::make_shared<FakeState>();
    std::vector<std::string> call_order;
    st->router = [&](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) return ok_empty();
        if (req.method == "GET" && req.url.find("/resources") != std::string::npos) {
            return ok(page_of(json::array({resource_json(kResourceId, "docs", "{}"),
                                          resource_json(kResourceIdTwo, "eng", "{}")})));
        }
        if (req.method == "GET" && req.url.find("/roles") != std::string::npos &&
            req.url.find("/groups") == std::string::npos) {
            return ok(page_of(json::array({role_json(kRoleId, "editor")})));
        }
        if (req.method == "GET" && req.url.find("/groups") != std::string::npos &&
            req.url.find("/roles") == std::string::npos) {
            return ok(page_of(json::array({group_json(kGroupId, "g")})));
        }
        if (req.method == "GET" && req.url.find("/groups/") != std::string::npos &&
            req.url.find("/roles") != std::string::npos) {
            // Currently bound to the FIRST resource, with a tenant_scope that must
            // survive the rebind.
            return status_only(
                200, json::array({role_assignment_json(role_json(kRoleId, "editor"), kResourceId,
                                                       std::nullopt,
                                                       std::vector<std::string>{kUuid})}));
        }
        if (req.method == "DELETE" && req.url.find("/roles/") != std::string::npos) {
            call_order.push_back("unassign");
            return ok_empty();
        }
        if (req.method == "POST" && req.url.find("/roles/") != std::string::npos &&
            req.url.find("/groups") != std::string::npos) {
            call_order.push_back("assign");
            const auto body = json::parse(req.body);
            AXIAM_REQUIRE(body.contains("tenant_scope"));
            return ok_empty();
        }
        return ok_empty();
    };
    auto client = login_client(st);
    client.login("a", "b");

    ManifestEntity group;
    group.kind = ManifestKind::Group;
    group.key = "g";
    group.name = "g";
    // Declares the SECOND resource -- the server currently has it bound to the first.
    group.roles = {ManifestRoleBinding{"r", std::string("eng"), std::nullopt}};

    Manifest m{{resource_entity("docs", "docs", std::nullopt), resource_entity("eng", "eng", std::nullopt),
               role_entity("r", "editor"), group}};

    const auto report = client.management().manifest().apply(m);
    AXIAM_CHECK(report.complete());
    AXIAM_CHECK(call_order.size() == 2);
    AXIAM_CHECK(call_order[0] == "unassign");
    AXIAM_CHECK(call_order[1] == "assign");
}

// When the assign half of a rebind fails, the previous binding is assigned again and
// the original failure is still what apply() reports.
AXIAM_TEST("§27.6.1 item 2: a failed rebind assign restores the previous binding") {
    auto st = std::make_shared<FakeState>();
    int assign_calls = 0;
    std::vector<std::string> assign_resource_ids;
    st->router = [&](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) return ok_empty();
        if (req.method == "GET" && req.url.find("/resources") != std::string::npos) {
            return ok(page_of(json::array({resource_json(kResourceId, "docs", "{}"),
                                          resource_json(kResourceIdTwo, "eng", "{}")})));
        }
        if (req.method == "GET" && req.url.find("/roles") != std::string::npos &&
            req.url.find("/groups") == std::string::npos) {
            return ok(page_of(json::array({role_json(kRoleId, "editor")})));
        }
        if (req.method == "GET" && req.url.find("/groups") != std::string::npos &&
            req.url.find("/roles") == std::string::npos) {
            return ok(page_of(json::array({group_json(kGroupId, "g")})));
        }
        if (req.method == "GET" && req.url.find("/groups/") != std::string::npos &&
            req.url.find("/roles") != std::string::npos) {
            return status_only(
                200, json::array({role_assignment_json(role_json(kRoleId, "editor"), kResourceId,
                                                       std::nullopt, std::nullopt)}));
        }
        if (req.method == "DELETE" && req.url.find("/roles/") != std::string::npos) {
            return ok_empty();
        }
        if (req.method == "POST" && req.url.find("/roles/") != std::string::npos &&
            req.url.find("/groups") != std::string::npos) {
            ++assign_calls;
            const auto body = json::parse(req.body);
            assign_resource_ids.push_back(body.value("resource_id", std::string("<none>")));
            // The FIRST assign (the new binding, to "eng") fails; the RESTORE assign
            // (back to "docs") must still succeed.
            if (assign_calls == 1) {
                return status_only(500, json{{"message", "server error"}});
            }
            return ok_empty();
        }
        return ok_empty();
    };
    auto client = login_client(st);
    client.login("a", "b");

    ManifestEntity group;
    group.kind = ManifestKind::Group;
    group.key = "g";
    group.name = "g";
    group.roles = {ManifestRoleBinding{"r", std::string("eng"), std::nullopt}};

    Manifest m{{resource_entity("docs", "docs", std::nullopt), resource_entity("eng", "eng", std::nullopt),
               role_entity("r", "editor"), group}};

    const auto report = client.management().manifest().apply(m);
    AXIAM_CHECK(!report.complete());  // the original failure is still reported
    AXIAM_CHECK(assign_calls == 2);   // the failed attempt, then the restore
    AXIAM_CHECK(assign_resource_ids.size() == 2);
    AXIAM_CHECK(assign_resource_ids[0] == kResourceIdTwo);  // tried the new binding
    AXIAM_CHECK(assign_resource_ids[1] == kResourceId);     // restored the old one
}

// ---------------------------------------------------------------------------
// §27.6.1 item 3: service_accounts
// ---------------------------------------------------------------------------

AXIAM_TEST("§27.6.1 item 3: a Create outcome carries client_secret as Sensitive<T>, "
          "still returned when a LATER action of the same apply fails") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) return ok_empty();
        if (req.method == "GET" && req.url.find("/service-accounts") != std::string::npos) {
            return ok(page_of(json::array()));
        }
        if (req.method == "POST" && req.url.find("/service-accounts") != std::string::npos) {
            const auto body = json::parse(req.body);
            const std::string name = body.value("name", "");
            if (name == "device-a") {
                json resp = service_account_json("sa-1", "device-a");
                resp["client_secret"] = "the-one-time-secret";
                return ok(resp);
            }
            // The SECOND service account (ordered after "device-a" by manifest key)
            // fails -- the first one's secret above must still be reported on ITS OWN
            // outcome, in `applied`, exactly as §27.6 rule 7 already requires for any
            // action attempted before a failure.
            return status_only(409, json{{"message", "already exists"}});
        }
        return ok_empty();
    };
    auto client = login_client(st);
    client.login("a", "b");

    ManifestEntity sa_a;
    sa_a.kind = ManifestKind::ServiceAccount;
    sa_a.key = "a";  // sorts before "b" -- processed first, within the same kind
    sa_a.name = "device-a";

    ManifestEntity sa_b;
    sa_b.kind = ManifestKind::ServiceAccount;
    sa_b.key = "b";
    sa_b.name = "device-b";

    Manifest m{{sa_a, sa_b}};
    const auto report = client.management().manifest().apply(m);

    AXIAM_CHECK(!report.complete());
    AXIAM_CHECK(report.applied.size() == 1);
    AXIAM_CHECK(report.applied[0].entity.key == "a");
    AXIAM_CHECK(report.applied[0].service_account_secret.has_value());
    AXIAM_CHECK(axiam::detail::reveal(*report.applied[0].service_account_secret) ==
               "the-one-time-secret");
    AXIAM_CHECK(report.applied[0].service_account_secret->to_string() == "[SENSITIVE]");
}

AXIAM_TEST("§27.6.1 item 3: a second apply is NoChange and issues no rotate-secret "
          "request") {
    auto st = std::make_shared<FakeState>();
    int rotate_calls = 0;
    st->router = [&](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) return ok_empty();
        if (req.url.find("/rotate-secret") != std::string::npos) {
            ++rotate_calls;
            return ok(json{{"client_secret", "rotated"}});
        }
        if (req.method == "GET" && req.url.find("/service-accounts") != std::string::npos) {
            return ok(page_of(json::array({service_account_json("sa-1", "device-fleet")})));
        }
        return ok_empty();
    };
    auto client = login_client(st);
    client.login("a", "b");

    ManifestEntity sa;
    sa.kind = ManifestKind::ServiceAccount;
    sa.key = "device";
    sa.name = "device-fleet";
    Manifest m{{sa}};

    const auto report = client.management().manifest().apply(m);
    AXIAM_CHECK(report.complete());
    AXIAM_CHECK(report.applied.empty());  // already existed, description matches -> NoChange
    AXIAM_CHECK(rotate_calls == 0);
}

AXIAM_TEST("§27.6.1 item 3: two existing service accounts with a stated name make plan "
          "fail before any write") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) return ok_empty();
        if (req.method == "GET" && req.url.find("/service-accounts") != std::string::npos) {
            return ok(page_of(json::array({service_account_json("sa-1", "device-fleet"),
                                          service_account_json("sa-2", "device-fleet")})));
        }
        return status_only(500, json{{"message", "unexpected write"}});
    };
    auto client = login_client(st);
    client.login("a", "b");

    ManifestEntity sa;
    sa.kind = ManifestKind::ServiceAccount;
    sa.key = "device";
    sa.name = "device-fleet";
    Manifest m{{sa}};

    bool threw = false;
    try {
        client.management().manifest().plan(m);
    } catch (const ManifestError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
}

}  // namespace
