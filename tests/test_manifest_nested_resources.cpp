// §13 row-17 of the dogfooding remediation plan: the flat-entity-tier manifests (PHP,
// Swift, C, C++) never sent a resource's `parent_id` on Create, so a nested manifest was
// created flat; and Swift/C/C++ silently defaulted `resource_type` to `"folder"` when a
// spec gave none. Each defect gets its own idempotence test over a NESTED manifest,
// asserting the parent on the wire.

#include <memory>
#include <string>

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
constexpr const char* kRootId = "22222222-2222-4222-8222-222222222222";
constexpr const char* kChildId = "33333333-3333-4333-8333-333333333333";

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

Client login_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://iam.example.com")
        .tenant_id(kUuid)
        .org_id(kUuid)
        .transport(axtest::make_fake(st))
        .build();
}

json resource_json(const std::string& id, const std::string& name,
                   const std::string& resource_type,
                   std::optional<std::string> parent_id = std::nullopt) {
    json j{{"id", id},
          {"name", name},
          {"resource_type", resource_type},
          {"metadata", json::object()},
          {"tenant_id", kUuid},
          {"created_at", "2026-08-26T00:00:00Z"},
          {"updated_at", "2026-08-26T00:00:00Z"}};
    if (parent_id) j["parent_id"] = *parent_id;
    return j;
}

json page_of(const json& items) { return json{{"items", items}, {"total", items.size()}}; }

// ---------------------------------------------------------------------------
// §13 row-17, defect 1: parent_id never sent for a nested resource
// ---------------------------------------------------------------------------

AXIAM_TEST("§13 row-17: a nested resource's Create body carries the created parent's "
          "parent_id, and apply-then-plan is empty") {
    auto st = std::make_shared<FakeState>();
    bool root_created = false, child_created = false;
    json captured_child_body;
    st->router = [&](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) return ok_empty();
        if (req.method == "GET" && req.url.find("/resources") != std::string::npos) {
            json items = json::array();
            if (root_created) items.push_back(resource_json(kRootId, "root", "folder"));
            if (child_created) {
                items.push_back(resource_json(kChildId, "child", "folder", kRootId));
            }
            return ok(page_of(items));
        }
        if (req.method == "POST" && req.url.find("/resources") != std::string::npos) {
            const auto body = json::parse(req.body);
            if (body.at("name") == "root") {
                root_created = true;
                AXIAM_REQUIRE(!body.contains("parent_id"));  // the root has none to send
                return ok(resource_json(kRootId, "root", "folder"));
            }
            // The child: this is the assertion the defect is about.
            captured_child_body = body;
            child_created = true;
            AXIAM_REQUIRE(body.contains("parent_id"));
            AXIAM_REQUIRE(body.at("parent_id") == kRootId);
            return ok(resource_json(kChildId, "child", "folder", kRootId));
        }
        return ok_empty();
    };
    auto client = login_client(st);
    client.login("a", "b");

    ManifestEntity root;
    root.kind = ManifestKind::Resource;
    root.key = "root";
    root.name = "root";
    root.resource_type = "folder";

    ManifestEntity child;
    child.kind = ManifestKind::Resource;
    child.key = "child";
    child.name = "child";
    child.resource_type = "folder";
    child.depends_on = "root";  // the nesting

    Manifest m{{root, child}};
    const auto report = client.management().manifest().apply(m);
    AXIAM_CHECK(report.complete());
    AXIAM_CHECK(root_created);
    AXIAM_CHECK(child_created);
    AXIAM_CHECK(!captured_child_body.is_null());
    AXIAM_CHECK(captured_child_body.at("parent_id") == kRootId);

    // apply(m) then plan(m) is all-NoChange (§27.6 rule 6) -- the tree the SECOND read
    // reports (with the real parent_id, from root_created/child_created above) matches
    // what was declared, because the parent is now genuinely part of the created state.
    const auto replan = client.management().manifest().plan(m);
    AXIAM_CHECK(replan.converged());
}

// ---------------------------------------------------------------------------
// §13 row-17, defect 2: resource_type silently defaulted to "folder"
// ---------------------------------------------------------------------------

// The stated type reaches the wire verbatim -- never silently "folder" for a resource
// that asked for something else. A NESTED manifest (parent "space", child "endpoint")
// so the assertion is not vacuously true of a lone root.
AXIAM_TEST("§13 row-17: the resource_type sent is the one stated, never a silent "
          "\"folder\", and apply-then-plan is empty") {
    auto st = std::make_shared<FakeState>();
    bool root_created = false, child_created = false;
    json captured_root_type, captured_child_type;
    st->router = [&](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) return ok_empty();
        if (req.method == "GET" && req.url.find("/resources") != std::string::npos) {
            json items = json::array();
            if (root_created) items.push_back(resource_json(kRootId, "space", "workspace"));
            if (child_created) {
                items.push_back(resource_json(kChildId, "endpoint", "service", kRootId));
            }
            return ok(page_of(items));
        }
        if (req.method == "POST" && req.url.find("/resources") != std::string::npos) {
            const auto body = json::parse(req.body);
            if (body.at("name") == "space") {
                root_created = true;
                captured_root_type = body.at("resource_type");
                return ok(resource_json(kRootId, "space", "workspace"));
            }
            child_created = true;
            captured_child_type = body.at("resource_type");
            return ok(resource_json(kChildId, "endpoint", "service", kRootId));
        }
        return ok_empty();
    };
    auto client = login_client(st);
    client.login("a", "b");

    ManifestEntity root;
    root.kind = ManifestKind::Resource;
    root.key = "space";
    root.name = "space";
    root.resource_type = "workspace";  // deliberately NOT "folder"

    ManifestEntity child;
    child.kind = ManifestKind::Resource;
    child.key = "endpoint";
    child.name = "endpoint";
    child.resource_type = "service";  // also deliberately NOT "folder"
    child.depends_on = "space";

    Manifest m{{root, child}};
    const auto report = client.management().manifest().apply(m);
    AXIAM_CHECK(report.complete());

    AXIAM_CHECK(captured_root_type == "workspace");
    AXIAM_CHECK(captured_child_type == "service");

    const auto replan = client.management().manifest().plan(m);
    AXIAM_CHECK(replan.converged());
}

// The other half: a resource that states NO type is refused client-side, before any
// request -- never silently sent as "folder".
AXIAM_TEST("§13 row-17: a resource with no stated resource_type is refused client-side, "
          "zero wire calls") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) -> HttpResponse { return ok_empty(); };
    auto client = login_client(st);
    // No login() -- this must fail before ANY wire call.

    ManifestEntity res;
    res.kind = ManifestKind::Resource;
    res.key = "r";
    res.name = "r";
    // res.resource_type left empty on purpose.

    Manifest m{{res}};
    bool threw = false;
    try {
        client.management().manifest().plan(m);
    } catch (const ManifestError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(st->count() == 0);
}

}  // namespace
