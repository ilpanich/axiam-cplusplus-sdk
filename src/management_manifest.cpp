// CONTRACT.md §27.6/§27.7 declarative layer. See axiam/management_manifest.hpp for the
// four properties that constrain everything below.

#include "axiam/management_manifest.hpp"

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <utility>

#include <nlohmann/json.hpp>

#include "management_json.hpp"
#include "management_transport.hpp"

namespace axiam::management {
namespace {

// Page size used when reading existing state; large enough to make one call usual.
constexpr std::int64_t kScanLimit = 200;

const ManifestEntity* find_key(const Manifest& m, const std::string& key) {
    for (const auto& e : m.entities) {
        if (e.key == key) return &e;
    }
    return nullptr;
}

const ManifestEntity* find_key_of_kind(const Manifest& m, const std::string& key,
                                       ManifestKind kind) {
    for (const auto& e : m.entities) {
        if (e.key == key && e.kind == kind) return &e;
    }
    return nullptr;
}

// The name a declaration is matched against: a permission is known by its action, and
// everything else (including a service account, §27.6.1 item 3) by its name.
const std::string& match_name(const ManifestEntity& e) {
    return e.kind == ManifestKind::Permission ? e.action : e.name;
}

const char* kind_name(ManifestKind kind) {
    switch (kind) {
        case ManifestKind::Resource: return "resource";
        case ManifestKind::Permission: return "permission";
        case ManifestKind::Role: return "role";
        case ManifestKind::Group: return "group";
        case ManifestKind::ServiceAccount: return "service_account";
    }
    return "?";
}

const char* action_name(ChangeAction action) {
    switch (action) {
        case ChangeAction::Unchanged: return "unchanged";
        case ChangeAction::Create: return "create";
        case ChangeAction::Update: return "update";
    }
    return "?";
}

// One existing object: the id an update needs, the fields manifests currently compare
// (a description; a resource's metadata as JSON text), and -- service accounts only,
// whose only unique index is client_id (§27.6.1 item 3) -- whether the natural key
// (name) matched more than one existing account.
struct Existing {
    std::string id;
    std::string description;
    std::string metadata;    // resources only; "" elsewhere (never compared elsewhere)
    bool ambiguous = false;  // service accounts only
};

using ExistingSet = std::map<std::string, Existing>;

// JSON value equality of a resource's metadata (§27.6.1 item 1): "never a key-by-key
// merge". Two malformed/empty strings compare equal to one another (both parse to
// `null`, which is never what a real `metadata` object is), so an unparsed stored value
// never silently forces a spurious drift-free reading, and a declared value that fails
// to parse is caught here as "differs" rather than crashing the plan.
bool metadata_equal(const std::string& declared, const std::string& stored) {
    const auto a = nlohmann::json::parse(declared, nullptr, false);
    const auto b = nlohmann::json::parse(stored, nullptr, false);
    return !a.is_discarded() && !b.is_discarded() && a == b;
}

}  // namespace

std::string PlannedChange::describe() const {
    return std::string(action_name(action)) + " " + kind_name(entity.kind) + ":" + entity.key;
}

std::vector<PlannedChange> Plan::pending() const {
    std::vector<PlannedChange> out;
    for (const auto& c : changes) {
        if (c.action != ChangeAction::Unchanged) out.push_back(c);
    }
    return out;
}

std::vector<std::string> ApplyReport::describe() const {
    std::vector<std::string> lines;
    for (const auto& c : applied) lines.push_back("applied  " + c.describe());
    if (failed) {
        lines.push_back("FAILED   " + failed->describe() + ": " + failure);
        for (const auto& c : remaining) lines.push_back("skipped  " + c.describe());
    }
    return lines;
}

ManifestApi::ManifestApi(std::shared_ptr<Transport> transport, CallScope scope)
    : transport_(std::move(transport)), scope_(std::move(scope)) {}

void ManifestApi::validate(const Manifest& manifest) {
    // A duplicate key does not merge -- one silently wins, and which one is an accident
    // of ordering. Since the key is also how an entity is referenced, the loser takes
    // every reference to it along.
    std::set<std::pair<int, std::string>> seen;
    for (const auto& e : manifest.entities) {
        if (e.key.empty()) {
            throw ManifestError("manifest: every entity needs a key");
        }
        const auto identity = std::make_pair(static_cast<int>(e.kind), e.key);
        if (!seen.insert(identity).second) {
            throw ManifestError("manifest declares \"" + e.key +
                                "\" twice -- a key must be unique within its kind");
        }
    }

    // A dangling reference is invisible until apply reaches the entity that needs it, by
    // which point the objects before it are already created.
    for (const auto& e : manifest.entities) {
        if (e.depends_on && !find_key(manifest, *e.depends_on)) {
            throw ManifestError("\"" + e.key + "\" depends on \"" + *e.depends_on +
                                "\", which this manifest does not declare");
        }
    }

    // Resources are the realistic source of a cycle: parent_id makes them a tree, and a
    // manifest can describe a shape that is not one. No ordering satisfies a cycle, so
    // the only correct response is to refuse.
    for (const auto& start : manifest.entities) {
        const ManifestEntity* at = &start;
        std::size_t steps = 0;
        while (at && at->depends_on) {
            if (++steps > manifest.entities.size()) {
                throw ManifestError("manifest has a dependency cycle reachable from \"" +
                                    start.key + "\"");
            }
            at = find_key(manifest, *at->depends_on);
        }
    }

    // §27.6.1 item 2: the two-shape role binding, for Group and ServiceAccount specs.
    for (const auto& e : manifest.entities) {
        if (e.kind != ManifestKind::Group && e.kind != ManifestKind::ServiceAccount) continue;
        std::set<std::string> role_keys_seen;
        for (const auto& b : e.roles) {
            const ManifestEntity* role = find_key_of_kind(manifest, b.role, ManifestKind::Role);
            if (!role) {
                throw ManifestError("\"" + e.key + "\" binds role \"" + b.role +
                                    "\", which this manifest does not declare as a role");
            }
            // The server keys assignments on (subject, role) with no resource component
            // (has_role is UNIQUE(in, out)); a repeat is 409. One role bound twice to one
            // subject -- at two resources, or once plain and once scoped -- describes a
            // state the server cannot hold (§27.6.1, D-3 of the dogfooding plan). Rejected
            // before any request, naming the subject and the role.
            if (!role_keys_seen.insert(b.role).second) {
                throw ManifestError("\"" + e.key + "\" binds role \"" + b.role +
                                    "\" more than once -- a subject can hold one role at "
                                    "most once (CONTRACT.md §27.6.1)");
            }
            if (b.resource && !find_key_of_kind(manifest, *b.resource, ManifestKind::Resource)) {
                throw ManifestError("\"" + e.key + "\" scopes role \"" + b.role +
                                    "\" to resource \"" + *b.resource +
                                    "\", which this manifest does not declare as a resource");
            }
            // §27.6.1 item 2: "An SDK MUST NOT send inherit: true explicitly" -- refused
            // here rather than silently downgraded to omitted, which would describe a
            // DIFFERENT manifest than the one written.
            if (b.inherit && *b.inherit) {
                throw ManifestError("\"" + e.key + "\" states inherit: true for role \"" +
                                    b.role +
                                    "\" -- omit the field for an inheritable binding "
                                    "(CONTRACT.md §27.6.1 item 2)");
            }
            // §27.6.1 item 2, last bullet: a global role bound with inherit: false is a
            // 400 the server would refuse in any case ("a global role ignores resource
            // scope"); checked here only because the role IS in the manifest, exactly
            // the case §27.6.1 says an SDK MAY pre-empt (C-1's "For C-12" question 6:
            // refused, matching the reference).
            if (b.inherit && !*b.inherit && role->is_global) {
                throw ManifestError("\"" + e.key + "\" binds the global role \"" + b.role +
                                    "\" with inherit: false -- a global role ignores "
                                    "resource scope (CONTRACT.md §27.6.1 item 2)");
            }
        }
    }
}

std::vector<ManifestEntity> ManifestApi::ordered(const Manifest& manifest) {
    validate(manifest);

    // Depth of an entity's dependency chain WITHIN its kind -- a parent sorts before its
    // child. Across kinds the enumerator order already decides.
    const auto depth_of = [&manifest](const ManifestEntity& e) {
        int depth = 0;
        const ManifestEntity* at = &e;
        std::size_t guard = 0;
        while (at && at->depends_on && guard++ <= manifest.entities.size()) {
            const auto* parent = find_key(manifest, *at->depends_on);
            if (!parent || parent->kind != at->kind) break;
            ++depth;
            at = parent;
        }
        return depth;
    };

    std::vector<ManifestEntity> out = manifest.entities;
    std::stable_sort(out.begin(), out.end(),
                     [&depth_of](const ManifestEntity& a, const ManifestEntity& b) {
                         if (a.kind != b.kind) return a.kind < b.kind;
                         const int da = depth_of(a);
                         const int db = depth_of(b);
                         if (da != db) return da < db;
                         // The tie-break that makes a plan stable across runs.
                         return a.key < b.key;
                     });
    return out;
}

namespace {

// Whether the SERVER stores a description for this kind.
//
// A resource does not: `Resource` has no description property, so read_existing() can
// only ever report an empty one, and drift must not be computed from a field that does
// not exist.
bool has_description(ManifestKind kind) {
    return kind != ManifestKind::Resource;
}

// Read the tenant's current state for one kind. Only the kinds a manifest mentions are
// scanned: a manifest declaring two permissions has no business listing every group in
// the tenant, and on a large tenant that is one request instead of dozens.
ExistingSet read_existing(const ManagementApi& api, ManifestKind kind) {
    // No `search`: a manifest scan reads the tenant's current state for one kind in
    // full, and a filtered read would make the plan's "does this exist?" answer depend
    // on a term nobody asked for.
    const PageRequest page{0, kScanLimit, {}};
    ExistingSet out;

    switch (kind) {
        case ManifestKind::Resource:
            for (const auto& r : api.resources().list(page)) {
                out[r.name] = Existing{r.id, "", r.metadata, false};
            }
            break;
        case ManifestKind::Permission:
            for (const auto& p : api.permissions().list(page)) {
                out[p.action] = Existing{p.id, p.description, "", false};
            }
            break;
        case ManifestKind::Role:
            for (const auto& r : api.roles().list(page)) {
                out[r.name] = Existing{r.id, r.description, "", false};
            }
            break;
        case ManifestKind::Group:
            for (const auto& g : api.groups().list(page)) {
                out[g.name] = Existing{g.id, g.description, "", false};
            }
            break;
        case ManifestKind::ServiceAccount:
            // §27.6.1 item 3: "The natural key is `name`, and the server does not
            // enforce it." A second match for one name marks the FIRST entry ambiguous
            // (the id it carries is never used -- plan() refuses before reading it) so
            // the caller sees a fixed, reproducible refusal rather than one that depends
            // on page order.
            for (const auto& s : api.service_accounts().list(page)) {
                auto it = out.find(s.name);
                if (it == out.end()) {
                    out[s.name] = Existing{s.id, s.description.value_or(""), "", false};
                } else {
                    it->second.ambiguous = true;
                }
            }
            break;
    }
    return out;
}

// Server-side role bindings currently held by a Group or ServiceAccount, by ROLE NAME
// -- what reconciliation compares each declared binding against. Fetched fresh at
// apply() time (never carried from plan()'s read, which may be stale by the time apply()
// reaches this entity -- the same "re-plans internally" discipline ManifestApi::apply()
// already documents for the manifest as a whole).
std::map<std::string, RoleAssignment> bound_role_bindings(const ManagementApi& api,
                                                          ManifestKind kind,
                                                          const std::string& subject_id) {
    std::map<std::string, RoleAssignment> out;
    if (kind == ManifestKind::Group) {
        for (auto& a : api.groups().list_roles(subject_id)) out[a.role.name] = a;
    } else if (kind == ManifestKind::ServiceAccount) {
        for (auto& a : api.service_accounts().list_roles(subject_id)) out[a.role.name] = a;
    }
    return out;
}

// Whether an EXISTING binding already matches a DECLARED one: the same resource (by
// server id; disengaged means "plain, no resource" on both sides) and the same
// `inherit` narrowing (§27.6.1 item 2's binding's natural key is `(subject, role)`,
// with resource/inherit as fields that decide NoChange vs Update). `RoleAssignment` may
// report `inherit` as either disengaged or `true` for "inherits" -- both mean the same
// thing on the wire, so only an engaged `false` counts as narrowed.
bool binding_satisfied(const RoleAssignment& existing, const std::optional<std::string>& resource_id,
                       bool declared_narrowed) {
    const bool existing_narrowed = existing.inherit.has_value() && !*existing.inherit;
    return existing.resource_id == resource_id && existing_narrowed == declared_narrowed;
}

}  // namespace

// (kind, manifest-local key) -> server id, accumulated as apply() proceeds through
// ordered() so a later entity can resolve an EARLIER one it depends on -- a resource
// this same run just created, a role a binding names, a resource a binding scopes to.
// Seeded from every EXISTING entity's id before any write (see apply()), so an entity
// that needs no change of its own can still be somebody else's dependency.
using ResolvedIds = std::map<std::pair<ManifestKind, std::string>, std::string>;

namespace {

std::string require_resolved(const ResolvedIds& resolved, ManifestKind kind,
                             const std::string& key, const char* what) {
    auto it = resolved.find({kind, key});
    if (it == resolved.end()) {
        // Defensive: validate() already refused a dangling reference, and ordered()
        // already guarantees a dependency is processed first, so reaching here means
        // an ordering invariant broke, not a manifest authoring mistake.
        throw ManifestError(std::string("manifest: \"") + key + "\" (" + what +
                            ") has no resolved server id -- internal ordering error");
    }
    return it->second;
}

// Reconciles every declared role binding of `e` against `subject_id`'s CURRENT
// bindings, via the two functors `assign`/`unassign` (the Group or ServiceAccount pair
// -- see the two call sites in perform()). A role the manifest does not name is left
// exactly as the tenant already has it, whichever subjects hold it (the additive scope
// this SDK documents). A role the manifest DOES name:
//
//   - absent entirely       -> assign (nothing to restore if this fails).
//   - present, same shape   -> untouched (NoChange).
//   - present, different    -> Update: unassign the old binding, then assign the new
//                              one carrying the OLD binding's tenant_scope across
//                              (§27.6.1: dropping it would silently widen an
//                              organization-level account's reach). If the assign
//                              fails, the previous binding is assigned again
//                              (best-effort) before the original failure is rethrown,
//                              so the subject is not left holding neither.
void reconcile_role_bindings(
    const ManifestEntity& e, const Manifest& manifest, const ResolvedIds& resolved,
    const std::map<std::string, RoleAssignment>& current,
    const std::function<void(const std::string& role_id, const std::optional<std::string>&,
                             const std::optional<bool>&,
                             const std::optional<std::vector<std::string>>&)>& assign,
    const std::function<void(const std::string& role_id, const std::optional<std::string>&)>&
        unassign) {
    for (const auto& b : e.roles) {
        const auto* role = find_key_of_kind(manifest, b.role, ManifestKind::Role);
        const std::string role_id = require_resolved(resolved, ManifestKind::Role, b.role, "role");
        std::optional<std::string> resource_id;
        if (b.resource) {
            resource_id = require_resolved(resolved, ManifestKind::Resource, *b.resource,
                                           "resource");
        }
        const bool declared_narrowed = b.inherit.has_value() && !*b.inherit;
        const std::optional<bool> wire_inherit = declared_narrowed ? std::optional<bool>(false)
                                                                    : std::nullopt;

        const auto it = role ? current.find(role->name) : current.end();
        if (it == current.end()) {
            assign(role_id, resource_id, wire_inherit, std::nullopt);
            continue;
        }
        if (binding_satisfied(it->second, resource_id, declared_narrowed)) {
            continue;  // NoChange
        }

        const RoleAssignment& existing = it->second;
        unassign(role_id, existing.resource_id);
        try {
            assign(role_id, resource_id, wire_inherit, existing.tenant_scope);
        } catch (const AxiamError&) {
            const bool existing_narrowed =
                existing.inherit.has_value() && !*existing.inherit;
            try {
                assign(role_id, existing.resource_id,
                      existing_narrowed ? std::optional<bool>(false) : std::nullopt,
                      existing.tenant_scope);
            } catch (const AxiamError&) {
                // Best-effort restore also failed; nothing more this call can do --
                // the ORIGINAL failure below is what the caller must see and act on.
            }
            throw;
        }
    }
}

// Executes one planned change against the server, resolving cross-entity references
// through `resolved`. On a Create, fills `change.id` (empty before -- the entity did
// not exist) and, for a ServiceAccount, `change.service_account_secret` (§27.5 rule 5:
// the one-time secret, returned on THIS outcome and never again). Inserts this entity's
// own (kind, key) -> id into `resolved` so a LATER entity in the same run that depends
// on this one can find it.
void perform(const ManagementApi& api, const Manifest& manifest, PlannedChange& change,
            ResolvedIds& resolved) {
    const auto& e = change.entity;
    const bool create = change.action == ChangeAction::Create;
    const std::string id = change.id.value_or("");

    switch (e.kind) {
        case ManifestKind::Resource: {
            // §13 row-17 (dogfooding plan): a nested resource's PARENT, resolved
            // through `resolved` exactly like a role binding's role/resource keys --
            // ordered() already guarantees the parent (a lower-depth Resource) was
            // processed first, so it is always present here when `depends_on` names
            // another Resource. A `depends_on` naming something else (a Role depending
            // on a Permission, say) is a different kind entirely and irrelevant here.
            std::optional<std::string> parent_id;
            if (e.depends_on) {
                const auto* parent = find_key_of_kind(manifest, *e.depends_on,
                                                      ManifestKind::Resource);
                if (parent) {
                    parent_id = require_resolved(resolved, ManifestKind::Resource, *e.depends_on,
                                                 "parent resource");
                }
            }

            std::string new_id;
            if (create) {
                CreateResourceRequest body{};
                body.name = e.name;
                body.resource_type = e.resource_type.empty() ? "folder" : e.resource_type;
                body.parent_id = parent_id;
                // §27.6.1 item 1: sent on Create when stated; omitted (never `{}` or
                // `null`) when the manifest says nothing about metadata (rule 3).
                if (e.metadata_json) body.metadata = *e.metadata_json;
                new_id = api.resources().create(body).id;
            } else {
                UpdateResourceRequest body{};
                body.name = e.name;
                body.parent_id = parent_id;
                if (e.metadata_json) body.metadata = *e.metadata_json;
                new_id = api.resources().update(id, body).id;
            }
            change.id = new_id;
            resolved[{ManifestKind::Resource, e.key}] = new_id;
            break;
        }
        case ManifestKind::Permission: {
            std::string new_id;
            if (create) {
                CreatePermissionRequest body{};
                body.action = e.action;
                body.description = e.description;
                new_id = api.permissions().create(body).id;
            } else {
                UpdatePermissionRequest body{};
                body.description = e.description;
                new_id = api.permissions().update(id, body).id;
            }
            change.id = new_id;
            resolved[{ManifestKind::Permission, e.key}] = new_id;
            break;
        }
        case ManifestKind::Role: {
            std::string new_id;
            if (create) {
                CreateRoleRequest body{};
                body.name = e.name;
                body.description = e.description;
                body.is_global = e.is_global;
                new_id = api.roles().create(body).id;
            } else {
                UpdateRole body{};
                body.description = e.description;
                new_id = api.roles().update(id, body).id;
            }
            change.id = new_id;
            resolved[{ManifestKind::Role, e.key}] = new_id;
            break;
        }
        case ManifestKind::Group: {
            std::string new_id = id;
            if (create) {
                CreateGroupRequest body{};
                body.name = e.name;
                body.description = e.description;
                new_id = api.groups().create(body).id;
            } else if (!e.description.empty()) {
                // Group is the first kind where `Update` can be reached for a reason
                // OTHER than its own description (a role-binding difference, below) --
                // sending description unconditionally, as this SDK's other manifest
                // kinds safely do (their only drift reason IS description drift), would
                // send `description: ""` and CLEAR the server's real value whenever this
                // entity's Update was actually about a role binding. Skipped entirely
                // (no PUT at all, not even an empty no-op one) when the manifest states
                // no description.
                UpdateGroup body{};
                body.description = e.description;
                new_id = api.groups().update(id, body).id;
            }
            change.id = new_id;
            resolved[{ManifestKind::Group, e.key}] = new_id;

            if (!e.roles.empty()) {
                const auto current =
                    create ? std::map<std::string, RoleAssignment>{}
                           : bound_role_bindings(api, e.kind, new_id);
                reconcile_role_bindings(
                    e, manifest, resolved, current,
                    [&api, &new_id](const std::string& role_id,
                                    const std::optional<std::string>& resource_id,
                                    const std::optional<bool>& inherit,
                                    const std::optional<std::vector<std::string>>& tenant_scope) {
                        AssignRoleToGroupRequest req{};
                        req.group_id = new_id;
                        req.resource_id = resource_id;
                        req.inherit = inherit;
                        req.tenant_scope = tenant_scope;
                        api.roles().assign_to_group(role_id, req);
                    },
                    [&api, &new_id](const std::string& role_id,
                                    const std::optional<std::string>& resource_id) {
                        api.roles().unassign_from_group(role_id, new_id, resource_id);
                    });
            }
            break;
        }
        case ManifestKind::ServiceAccount: {
            std::string new_id = id;
            if (create) {
                CreateServiceAccountRequest body{};
                body.name = e.name;
                if (!e.description.empty()) body.description = e.description;
                const auto created = api.service_accounts().create(body);
                new_id = created.id;
                // §27.5 rule 5: the one-time secret, on THIS outcome, even when a LATER
                // action of the same apply fails -- the caller reads it off
                // ApplyReport::applied / ::failed, never re-derives it.
                change.service_account_secret = created.client_secret;
            } else if (!e.description.empty()) {
                // §27.6.1 item 3: description is the only field Update reconciles. As
                // with Group above, `Update` can be reached here for a role-binding
                // reason alone, so this is skipped entirely -- never an empty no-op PUT
                // -- when the manifest states no description.
                UpdateServiceAccount body{};
                body.description = e.description;
                new_id = api.service_accounts().update(id, body).id;
            }
            change.id = new_id;
            resolved[{ManifestKind::ServiceAccount, e.key}] = new_id;

            if (!e.roles.empty()) {
                const auto current =
                    create ? std::map<std::string, RoleAssignment>{}
                           : bound_role_bindings(api, e.kind, new_id);
                reconcile_role_bindings(
                    e, manifest, resolved, current,
                    [&api, &new_id](const std::string& role_id,
                                    const std::optional<std::string>& resource_id,
                                    const std::optional<bool>& inherit,
                                    const std::optional<std::vector<std::string>>& tenant_scope) {
                        AssignRoleToServiceAccountRequest req{};
                        req.service_account_id = new_id;
                        req.resource_id = resource_id;
                        req.inherit = inherit;
                        req.tenant_scope = tenant_scope;
                        api.roles().assign_to_service_account(role_id, req);
                    },
                    [&api, &new_id](const std::string& role_id,
                                    const std::optional<std::string>& resource_id) {
                        api.roles().unassign_from_service_account(role_id, new_id, resource_id);
                    });
            }
            break;
        }
    }
}

}  // namespace

Plan ManifestApi::plan(const Manifest& manifest) const {
    const auto entities = ordered(manifest);
    const ManagementApi api(transport_, scope_);

    // One read per KIND, not one per entity: ten roles is one list call.
    std::map<ManifestKind, ExistingSet> cache;

    Plan out;
    for (const auto& e : entities) {
        if (cache.find(e.kind) == cache.end()) {
            cache[e.kind] = read_existing(api, e.kind);
        }
        const auto& existing = cache[e.kind];
        const auto found = existing.find(match_name(e));

        PlannedChange change;
        change.entity = e;
        if (found == existing.end()) {
            change.action = ChangeAction::Create;
        } else {
            // §27.6.1 item 3: a service account's only unique index is client_id, so a
            // stated name matching two accounts fails plan -- before apply writes
            // anything -- rather than picking one at random.
            if (e.kind == ManifestKind::ServiceAccount && found->second.ambiguous) {
                throw ManifestError("manifest: \"" + e.name +
                                    "\" (service account) matches more than one existing "
                                    "account -- only client_id is unique, so plan cannot "
                                    "tell which one this declares (CONTRACT.md §27.6.1 "
                                    "item 3)");
            }
            change.id = found->second.id;
            // Compare ONLY what the manifest names. A server object carries plenty a
            // manifest says nothing about, and treating that as drift would make every
            // plan report a change and every apply overwrite work nobody claimed.
            //
            // And only what the SERVER carries, which is why has_description() exists: a
            // resource has no description field at all, so a manifest that gives one is
            // documenting its own file. Comparing that against the empty string the read
            // necessarily produced would mark the resource drifted, update it, and mark
            // it drifted again on the next run -- §27.6 rule 6 says apply-then-plan is
            // all-Unchanged, and a manifest that never converges is the exact failure it
            // rules out.
            bool drifted = has_description(e.kind) && !e.description.empty() &&
                           e.description != found->second.description;
            // §27.6.1 item 1: metadata drift is JSON VALUE equality of the whole object.
            if (e.kind == ManifestKind::Resource && e.metadata_json) {
                drifted = drifted || !metadata_equal(*e.metadata_json, found->second.metadata);
            }
            // §27.6.1 item 2: a role binding that does not yet match what the manifest
            // declares -- absent entirely, or present with a different resource/inherit
            // -- is drift too, even when the description matches exactly. Without this,
            // apply() would never be asked to send the assignment or the rebind, and
            // rule 6's idempotence test (apply(m) then plan(m) is all-NoChange) would
            // fail for the very case it exists to cover.
            if ((e.kind == ManifestKind::Group || e.kind == ManifestKind::ServiceAccount) &&
                !e.roles.empty() && !drifted) {
                if (cache.find(ManifestKind::Resource) == cache.end()) {
                    // Defensive: validate() guarantees any resource a binding scopes to
                    // is declared in this manifest, so ordered() (resources before
                    // groups/service accounts) already populated this above -- reached
                    // only if a manifest somehow named no resource entities at all.
                    cache[ManifestKind::Resource] = read_existing(api, ManifestKind::Resource);
                }
                const auto& resources_existing = cache[ManifestKind::Resource];
                const auto held = bound_role_bindings(api, e.kind, found->second.id);
                for (const auto& b : e.roles) {
                    const auto* role = find_key_of_kind(manifest, b.role, ManifestKind::Role);
                    if (!role) continue;  // validate() already refused a dangling key

                    std::optional<std::string> resource_id;
                    bool resource_unresolved = false;
                    if (b.resource) {
                        const auto* res = find_key_of_kind(manifest, *b.resource,
                                                           ManifestKind::Resource);
                        const auto rit = res ? resources_existing.find(res->name)
                                             : resources_existing.end();
                        if (rit == resources_existing.end()) {
                            // The resource itself does not exist on the server yet (it is
                            // about to be Created by this same apply), so no existing
                            // binding could already be scoped to it.
                            resource_unresolved = true;
                        } else {
                            resource_id = rit->second.id;
                        }
                    }
                    const bool declared_narrowed = b.inherit.has_value() && !*b.inherit;
                    const auto hit = held.find(role->name);
                    if (hit == held.end() || resource_unresolved ||
                        !binding_satisfied(hit->second, resource_id, declared_narrowed)) {
                        drifted = true;
                        break;
                    }
                }
            }
            change.action = drifted ? ChangeAction::Update : ChangeAction::Unchanged;
        }
        out.changes.push_back(std::move(change));
    }
    return out;
}

ApplyReport ManifestApi::apply(const Manifest& manifest) const {
    const auto computed = plan(manifest);
    const ManagementApi api(transport_, scope_);

    // Seeded with every entity's EXISTING id (Update and Unchanged alike) before any
    // write, so a Create processed later in this run can resolve a dependency that
    // needed no change of its own -- an unmodified parent resource, an unmodified role
    // a new group's binding names.
    ResolvedIds resolved;
    for (const auto& c : computed.changes) {
        if (c.id) resolved[{c.entity.kind, c.entity.key}] = *c.id;
    }

    auto pending = computed.pending();

    ApplyReport report;
    for (std::size_t i = 0; i < pending.size(); ++i) {
        try {
            perform(api, manifest, pending[i], resolved);
        } catch (const AxiamError& e) {
            // §27.7: stop here, do not undo what landed. A partial apply against a live
            // IAM tenant is a state an operator inspects and resumes from; an automatic
            // rollback would issue a second wave of writes at exactly the moment the
            // server is already saying something is wrong.
            report.failed = pending[i];
            report.failure = e.what();
            report.remaining.assign(pending.begin() + static_cast<long>(i) + 1, pending.end());
            return report;
        }
        report.applied.push_back(pending[i]);
    }
    return report;
}

}  // namespace axiam::management

namespace axiam::management {

// Defined here rather than in the generated ops so management_ops.cpp keeps knowing
// nothing about the manifest layer -- the generated file's only job is the 147
// operations.
ManifestApi ManagementApi::manifest() const { return ManifestApi(transport_, scope_); }

}  // namespace axiam::management
