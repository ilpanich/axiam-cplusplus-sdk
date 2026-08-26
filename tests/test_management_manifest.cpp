// The §27.6/§27.7 declarative layer.
//
// Everything here is about the properties that make a manifest safe to run more than
// once against a live tenant: plan writes nothing, ordering is derived and stable,
// incoherence is refused before the first request, apply stops at the first failure
// without rolling back, and omission is never deletion.

#include <string>

#include "assert.hpp"
#include "axiam/axiam.hpp"
#include "axiam/management_manifest.hpp"
#include "management_test_util.hpp"

namespace {

using namespace axiam;
using namespace axiam::management;

constexpr const char* kUuid = "11111111-1111-4111-8111-111111111111";
const char* kEmptyPage = R"json({"items":[],"total":0})json";

const char* kPermPage =
    R"json({"items":[{"action":"documents:read","created_at":"2026-08-26T00:00:00Z",)json"
    R"json("description":"Read documents","id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"}],"total":1})json";

const char* kPermPageStale =
    R"json({"items":[{"action":"documents:read","created_at":"2026-08-26T00:00:00Z",)json"
    R"json("description":"stale","id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"}],"total":1})json";

const char* kPermObject =
    R"json({"action":"documents:read","created_at":"2026-08-26T00:00:00Z",)json"
    R"json("description":"Read documents","id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"})json";

ManifestEntity one_permission() {
    ManifestEntity e;
    e.kind = ManifestKind::Permission;
    e.key = "read";
    e.name = "documents:read";
    e.action = "documents:read";
    e.description = "Read documents";
    return e;
}

// ---- plan writes nothing ----------------------------------------------

AXIAM_TEST("§27.6: plan issues only reads") {
    auto fixture = axtest::mgmt::signed_in(200, kEmptyPage);
    const Manifest manifest{{one_permission()}};

    const auto plan = fixture.client.management().manifest().plan(manifest);

    AXIAM_CHECK(fixture.state->last().method == "GET");
    AXIAM_CHECK(plan.pending().size() == 1);
    AXIAM_CHECK(plan.changes[0].action == ChangeAction::Create);
}

AXIAM_TEST("§27.6: a converged tenant plans nothing") {
    auto fixture = axtest::mgmt::signed_in(200, kPermPage);
    const Manifest manifest{{one_permission()}};

    const auto plan = fixture.client.management().manifest().plan(manifest);

    AXIAM_CHECK(plan.converged());
    AXIAM_CHECK(plan.changes[0].action == ChangeAction::Unchanged);
}

AXIAM_TEST("§27.6: a converged tenant applies nothing") {
    auto fixture = axtest::mgmt::signed_in(200, kPermPage);
    const Manifest manifest{{one_permission()}};

    const auto report = fixture.client.management().manifest().apply(manifest);

    AXIAM_CHECK(report.complete());
    AXIAM_CHECK(report.applied.empty());
    // login + the one read plan() needed, and nothing else.
    AXIAM_CHECK(fixture.state->count() == 2);
}

AXIAM_TEST("§27.6: drift is updated in place, carrying only the drifted field") {
    auto fixture = axtest::mgmt::signed_in_two(200, kPermPageStale, 200, kPermObject);
    const Manifest manifest{{one_permission()}};

    const auto report = fixture.client.management().manifest().apply(manifest);

    AXIAM_CHECK(report.complete());
    AXIAM_REQUIRE(report.applied.size() == 1);
    AXIAM_CHECK(report.applied[0].action == ChangeAction::Update);
    AXIAM_CHECK(fixture.state->last().method == "PUT");
    // The sparse body of §27.4 rule 5 -- only what drifted.
    AXIAM_CHECK(fixture.state->last().body == R"json({"description":"Read documents"})json");
}

// ---- ordering is derived and stable ------------------------------------

AXIAM_TEST("§27.6: apply order is derived from kind, not from declaration order") {
    // Declared backwards on purpose: group, role, permission, resource.
    Manifest manifest;
    ManifestEntity g; g.kind = ManifestKind::Group;      g.key = "g";   g.name = "engineers";
    ManifestEntity r; r.kind = ManifestKind::Role;       r.key = "r";   r.name = "auditor";
    ManifestEntity p; p.kind = ManifestKind::Permission; p.key = "p";   p.name = "docs:read";
    p.action = "docs:read";
    ManifestEntity s; s.kind = ManifestKind::Resource;   s.key = "res"; s.name = "root";
    manifest.entities = {g, r, p, s};

    const auto ordered = ManifestApi::ordered(manifest);

    AXIAM_CHECK(ordered[0].kind == ManifestKind::Resource);
    AXIAM_CHECK(ordered[1].kind == ManifestKind::Permission);
    AXIAM_CHECK(ordered[2].kind == ManifestKind::Role);
    AXIAM_CHECK(ordered[3].kind == ManifestKind::Group);
}

AXIAM_TEST("§27.6: a parent resource is ordered before its child") {
    Manifest manifest;
    ManifestEntity child; child.kind = ManifestKind::Resource; child.key = "child";
    child.name = "child"; child.depends_on = "parent";
    ManifestEntity parent; parent.kind = ManifestKind::Resource; parent.key = "parent";
    parent.name = "parent";
    manifest.entities = {child, parent};

    const auto ordered = ManifestApi::ordered(manifest);

    AXIAM_CHECK(ordered[0].key == "parent");
    AXIAM_CHECK(ordered[1].key == "child");
}

// Ties break on KEY, deterministically -- without which a plan diff is unreadable.
AXIAM_TEST("§27.6: ordering is stable across runs") {
    Manifest manifest;
    for (const char* key : {"zeta", "alpha", "mid"}) {
        ManifestEntity e;
        e.kind = ManifestKind::Permission;
        e.key = key;
        e.name = key;
        e.action = key;
        manifest.entities.push_back(e);
    }

    const auto first = ManifestApi::ordered(manifest);
    const auto second = ManifestApi::ordered(manifest);

    AXIAM_CHECK(first[0].key == "alpha");
    AXIAM_CHECK(first[1].key == "mid");
    AXIAM_CHECK(first[2].key == "zeta");
    AXIAM_CHECK(first[0].key == second[0].key);
    AXIAM_CHECK(first[2].key == second[2].key);
}

// ---- incoherence is refused BEFORE any request -------------------------

AXIAM_TEST("§27.6: a dangling reference is refused before any request") {
    auto fixture = axtest::mgmt::signed_in(200, kEmptyPage);
    Manifest manifest;
    ManifestEntity e; e.kind = ManifestKind::Role; e.key = "auditor"; e.name = "auditor";
    e.depends_on = "a-permission-nobody-declared";
    manifest.entities = {e};

    bool threw = false;
    try {
        fixture.client.management().manifest().plan(manifest);
    } catch (const ManifestError& err) {
        threw = true;
        AXIAM_CHECK(std::string(err.what()).find("does not declare") != std::string::npos);
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(fixture.state->count() == 1);  // only the login
}

AXIAM_TEST("§27.6: a cycle is refused before any request") {
    auto fixture = axtest::mgmt::signed_in(200, kEmptyPage);
    Manifest manifest;
    ManifestEntity a; a.kind = ManifestKind::Resource; a.key = "a"; a.name = "a";
    a.depends_on = "b";
    ManifestEntity b; b.kind = ManifestKind::Resource; b.key = "b"; b.name = "b";
    b.depends_on = "a";
    manifest.entities = {a, b};

    bool threw = false;
    try {
        fixture.client.management().manifest().plan(manifest);
    } catch (const ManifestError& err) {
        threw = true;
        AXIAM_CHECK(std::string(err.what()).find("cycle") != std::string::npos);
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(fixture.state->count() == 1);
}

AXIAM_TEST("§27.6: a duplicate key is refused") {
    Manifest manifest;
    ManifestEntity a = one_permission();
    ManifestEntity b = one_permission();
    b.action = "documents:write";
    manifest.entities = {a, b};

    bool threw = false;
    try {
        ManifestApi::validate(manifest);
    } catch (const ManifestError& err) {
        threw = true;
        AXIAM_CHECK(std::string(err.what()).find("twice") != std::string::npos);
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§27.6: an entity without a key is refused") {
    Manifest manifest;
    ManifestEntity e; e.kind = ManifestKind::Role; e.name = "nameless";
    manifest.entities = {e};

    bool threw = false;
    try {
        ManifestApi::validate(manifest);
    } catch (const ManifestError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
}

// ---- apply stops at the first failure, without rolling back ------------

AXIAM_TEST("§27.7: apply stops at the first failure and does not roll back") {
    auto fixture = axtest::mgmt::signed_in_three(
        200, kEmptyPage,   // plan: the permissions read
        200, kPermObject,  // create #1 -> ok
        500, "");          // create #2 -> boom

    Manifest manifest;
    for (const char* key : {"a", "b", "c"}) {
        ManifestEntity e;
        e.kind = ManifestKind::Permission;
        e.key = key;
        e.name = key;
        e.action = key;
        e.description = "d";
        manifest.entities.push_back(e);
    }

    const auto report = fixture.client.management().manifest().apply(manifest);

    AXIAM_CHECK(!report.complete());
    AXIAM_CHECK(report.applied.size() == 1);   // the first landed and STAYS landed
    AXIAM_CHECK(report.failed.has_value());
    AXIAM_CHECK(report.failed->entity.key == "b");
    AXIAM_CHECK(report.remaining.size() == 1);  // the third was never attempted
    AXIAM_CHECK(report.remaining[0].entity.key == "c");
    // login + 1 read + 2 creates. No rollback traffic.
    AXIAM_CHECK(fixture.state->count() == 4);
}

AXIAM_TEST("§27.7: the report reads as a recovery instruction") {
    auto fixture = axtest::mgmt::signed_in_three(200, kEmptyPage, 200, kPermObject, 500, "");
    Manifest manifest;
    for (const char* key : {"a", "b", "c"}) {
        ManifestEntity e;
        e.kind = ManifestKind::Permission;
        e.key = key; e.name = key; e.action = key; e.description = "d";
        manifest.entities.push_back(e);
    }

    const auto lines = fixture.client.management().manifest().apply(manifest).describe();

    AXIAM_CHECK(lines.size() == 3);
    AXIAM_CHECK(lines[0].rfind("applied  create permission:a", 0) == 0);
    AXIAM_CHECK(lines[1].rfind("FAILED   create permission:b", 0) == 0);
    AXIAM_CHECK(lines[2].rfind("skipped  create permission:c", 0) == 0);
}

// ---- omission is never deletion ----------------------------------------

// An object the manifest does not mention is left strictly alone. There is no
// ChangeAction::Delete in the enum at all, which is the structural version of the
// guarantee: a manifest cannot express deletion, so an incomplete one cannot become
// destructive.
AXIAM_TEST("§27.6: omission is never deletion") {
    auto fixture = axtest::mgmt::signed_in(
        200,
        R"json({"items":[{"action":"documents:read","created_at":"x","description":)json"
        R"json("Read documents","id":"11111111-1111-4111-8111-111111111111",)json"
        R"json("tenant_id":"11111111-1111-4111-8111-111111111111","updated_at":"x"},)json"
        R"json({"action":"secrets:read","created_at":"x","description":"nobody declared this",)json"
        R"json("id":"11111111-1111-4111-8111-111111111111",)json"
        R"json("tenant_id":"11111111-1111-4111-8111-111111111111","updated_at":"x"}],"total":2})json");

    const Manifest manifest{{one_permission()}};
    const auto plan = fixture.client.management().manifest().plan(manifest);

    AXIAM_CHECK(plan.changes.size() == 1);
    AXIAM_CHECK(plan.converged());
}


// ---- §27.7's C++ declarative form -------------------------------------
//
// The macro form is sugar over the aggregate, and the whole point of §27.7's
// closing rule is that it stays sugar: "whatever the surface syntax, it MUST
// lower to the same ManagementManifest value and go through the same
// plan/apply." So the assertions here are equality against a manifest built
// the plain way, and then a plan over the macro-built one.

AXIAM_TEST("§27.7: the declarative macros lower to the same value as plain construction") {
    const auto declarative = AXIAM_MANIFEST(
        AXIAM_PERMISSION(.key = "read", .name = "documents:read", .description = "Read documents",
                         .action = "documents:read"));

    const Manifest plain{{one_permission()}};

    AXIAM_CHECK(declarative.entities.size() == plain.entities.size());
    AXIAM_CHECK(declarative.entities[0].kind == plain.entities[0].kind);
    AXIAM_CHECK(declarative.entities[0].key == plain.entities[0].key);
    AXIAM_CHECK(declarative.entities[0].name == plain.entities[0].name);
    AXIAM_CHECK(declarative.entities[0].description == plain.entities[0].description);
    AXIAM_CHECK(declarative.entities[0].action == plain.entities[0].action);
    // Members nobody named still hold their declared defaults — that is what
    // makes a partial designated-initializer list legal in the first place.
    AXIAM_CHECK(declarative.entities[0].resource_type.empty());
    AXIAM_CHECK(declarative.entities[0].is_global == false);
    AXIAM_CHECK(!declarative.entities[0].depends_on.has_value());
}

AXIAM_TEST("§27.7: a macro-built manifest goes through the same plan/apply") {
    auto fixture = axtest::mgmt::signed_in(200, kPermPage);

    const auto manifest = AXIAM_MANIFEST(
        AXIAM_PERMISSION(.key = "read", .name = "documents:read", .description = "Read documents",
                         .action = "documents:read"));

    // Same tenant state, same manifest content, therefore the same verdict the
    // plain-construction test above gets: converged, nothing to send.
    AXIAM_CHECK(fixture.client.management().manifest().plan(manifest).converged());
}

AXIAM_TEST("§27.7: every kind has a macro, and each sets only its kind") {
    const auto manifest = AXIAM_MANIFEST(
        AXIAM_RESOURCE(.key = "root", .name = "documents", .resource_type = "folder"),
        AXIAM_PERMISSION(.key = "read", .name = "documents:read", .action = "read"),
        AXIAM_ROLE(.key = "editor", .name = "editor", .depends_on = "read"),
        AXIAM_GROUP(.key = "editors", .name = "editors", .depends_on = "editor"));

    AXIAM_CHECK(manifest.entities.size() == 4);
    AXIAM_CHECK(manifest.entities[0].kind == ManifestKind::Resource);
    AXIAM_CHECK(manifest.entities[1].kind == ManifestKind::Permission);
    AXIAM_CHECK(manifest.entities[2].kind == ManifestKind::Role);
    AXIAM_CHECK(manifest.entities[3].kind == ManifestKind::Group);

    // Declaration order above is deliberately NOT apply order: ordered() must
    // still put the resource first and the group last, derived from kind.
    const auto ordered = ManifestApi::ordered(manifest);
    AXIAM_CHECK(ordered.size() == 4);
    AXIAM_CHECK(ordered[0].key == "root");
    AXIAM_CHECK(ordered[1].key == "read");
    AXIAM_CHECK(ordered[2].key == "editor");
    AXIAM_CHECK(ordered[3].key == "editors");
}

// ---- every kind, read and written -------------------------------------
//
// The cases above all use permissions, which leaves the resource, role and group
// branches of the manifest's read-current-state and perform-one-change switches
// unexercised — and those are exactly the branches that pick a request body. A wrong
// one there is invisible to a permission-only suite and produces a manifest that
// silently applies the wrong shape.

const char* kResourcePage =
    R"json({"items":[{"created_at":"2026-08-26T00:00:00Z",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","metadata":{},"name":"documents",)json"
    R"json("resource_type":"folder","tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"}],"total":1})json";

const char* kRolePage =
    R"json({"items":[{"created_at":"2026-08-26T00:00:00Z","description":"Edits documents",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","is_global":false,"name":"editor",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"}],"total":1})json";

const char* kRolePageStale =
    R"json({"items":[{"created_at":"2026-08-26T00:00:00Z","description":"stale",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","is_global":false,"name":"editor",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"}],"total":1})json";

const char* kGroupPage =
    R"json({"items":[{"created_at":"2026-08-26T00:00:00Z","description":"The editors",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","metadata":{},"name":"editors",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"}],"total":1})json";

const char* kResourceObject =
    R"json({"created_at":"2026-08-26T00:00:00Z",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","metadata":{},"name":"documents",)json"
    R"json("resource_type":"folder","tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"})json";

const char* kRoleObject =
    R"json({"created_at":"2026-08-26T00:00:00Z","description":"Edits documents",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","is_global":false,"name":"editor",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"})json";

const char* kGroupObject =
    R"json({"created_at":"2026-08-26T00:00:00Z","description":"The editors",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","metadata":{},"name":"editors",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"})json";

Manifest four_kinds() {
    return AXIAM_MANIFEST(
        AXIAM_RESOURCE(.key = "root", .name = "documents", .description = "The document tree",
                       .resource_type = "folder"),
        AXIAM_PERMISSION(.key = "read", .name = "documents:read",
                         .description = "Read documents", .action = "documents:read"),
        AXIAM_ROLE(.key = "editor", .name = "editor", .description = "Edits documents"),
        AXIAM_GROUP(.key = "editors", .name = "editors", .description = "The editors"));
}

AXIAM_TEST("§27.6: a manifest spanning every kind reads each kind exactly once") {
    // Four empty pages: one read per KIND, not one per entity. A manifest declaring ten
    // roles must still be one list call.
    auto fixture = axtest::mgmt::signed_in_many({
        {200, kEmptyPage}, {200, kEmptyPage}, {200, kEmptyPage}, {200, kEmptyPage},
    });

    const auto plan = fixture.client.management().manifest().plan(four_kinds());

    AXIAM_REQUIRE(plan.changes.size() == 4);
    AXIAM_CHECK(plan.pending().size() == 4);
    // login + four list calls, and nothing else: plan writes nothing.
    AXIAM_CHECK(fixture.state->count() == 5);
    for (const auto& change : plan.changes) {
        AXIAM_CHECK(change.action == ChangeAction::Create);
    }
}

AXIAM_TEST("§27.6: a manifest spanning every kind creates each in derived order") {
    auto fixture = axtest::mgmt::signed_in_many({
        // apply re-plans first: four reads, all empty.
        {200, kEmptyPage}, {200, kEmptyPage}, {200, kEmptyPage}, {200, kEmptyPage},
        // then four creates.
        {201, kResourceObject}, {201, kPermObject}, {201, kRoleObject}, {201, kGroupObject},
    });

    const auto report = fixture.client.management().manifest().apply(four_kinds());

    AXIAM_CHECK(report.complete());
    AXIAM_REQUIRE(report.applied.size() == 4);
    // Derived from kind, not from the order four_kinds() happens to declare.
    AXIAM_CHECK(report.applied[0].entity.kind == ManifestKind::Resource);
    AXIAM_CHECK(report.applied[1].entity.kind == ManifestKind::Permission);
    AXIAM_CHECK(report.applied[2].entity.kind == ManifestKind::Role);
    AXIAM_CHECK(report.applied[3].entity.kind == ManifestKind::Group);
}

AXIAM_TEST("§27.6: a manifest spanning every kind converges against a matching tenant") {
    auto fixture = axtest::mgmt::signed_in_many({
        {200, kResourcePage}, {200, kPermPage}, {200, kRolePage}, {200, kGroupPage},
    });

    const auto plan = fixture.client.management().manifest().plan(four_kinds());

    AXIAM_CHECK(plan.converged());
    for (const auto& change : plan.changes) {
        AXIAM_CHECK(change.action == ChangeAction::Unchanged);
        // An existing object contributes its server id, which is what an Update would
        // need and what makes a resumed apply able to tell create from update.
        AXIAM_CHECK(change.id.has_value());
    }
}

AXIAM_TEST("§27.6: drifted role and group descriptions are updated, not recreated") {
    auto fixture = axtest::mgmt::signed_in_many({
        // re-plan: the role's description differs, everything else matches.
        {200, kResourcePage}, {200, kPermPage}, {200, kRolePageStale}, {200, kGroupPage},
        // one update.
        {200, kRoleObject},
    });

    const auto report = fixture.client.management().manifest().apply(four_kinds());

    AXIAM_CHECK(report.complete());
    AXIAM_REQUIRE(report.applied.size() == 1);
    AXIAM_CHECK(report.applied[0].action == ChangeAction::Update);
    AXIAM_CHECK(report.applied[0].entity.kind == ManifestKind::Role);
    // In place: PUT/PATCH against the existing id, never a delete-then-create.
    AXIAM_CHECK(fixture.state->last().method != "POST");
    AXIAM_CHECK(fixture.state->last().url.find(kUuid) != std::string::npos);
}

AXIAM_TEST("§27.6: describe() names every kind and every action") {
    // A report a caller pastes into a ticket is only useful if it says which object it
    // is about. Every kind and every action must render as something other than "?".
    const ManifestKind kinds[] = {ManifestKind::Resource, ManifestKind::Permission,
                                  ManifestKind::Role, ManifestKind::Group};
    const ChangeAction actions[] = {ChangeAction::Unchanged, ChangeAction::Create,
                                    ChangeAction::Update};

    for (const auto kind : kinds) {
        for (const auto action : actions) {
            PlannedChange change;
            change.entity.kind = kind;
            change.entity.key = "thing";
            change.action = action;
            const auto rendered = change.describe();
            AXIAM_CHECK(rendered.find('?') == std::string::npos);
            AXIAM_CHECK(rendered.find("thing") != std::string::npos);
        }
    }
}

}  // namespace
