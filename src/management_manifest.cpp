// CONTRACT.md §27.6/§27.7 declarative layer. See axiam/management_manifest.hpp for the
// four properties that constrain everything below.

#include "axiam/management_manifest.hpp"

#include <algorithm>
#include <map>
#include <set>

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

// The name a declaration is matched against: a permission is known by its action, and
// everything else by its name.
const std::string& match_name(const ManifestEntity& e) {
    return e.kind == ManifestKind::Permission ? e.action : e.name;
}

const char* kind_name(ManifestKind kind) {
    switch (kind) {
        case ManifestKind::Resource: return "resource";
        case ManifestKind::Permission: return "permission";
        case ManifestKind::Role: return "role";
        case ManifestKind::Group: return "group";
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

// One existing object: the name a manifest matches on, the id an update needs, and the
// one field manifests currently compare.
struct Existing {
    std::string id;
    std::string description;
};

using ExistingSet = std::map<std::string, Existing>;

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

// Read the tenant's current state for one kind. Only the kinds a manifest mentions are
// scanned: a manifest declaring two permissions has no business listing every group in
// the tenant, and on a large tenant that is one request instead of dozens.
ExistingSet read_existing(const ManagementApi& api, ManifestKind kind) {
    const PageRequest page{0, kScanLimit};
    ExistingSet out;

    switch (kind) {
        case ManifestKind::Resource:
            for (const auto& r : api.resources().list(page)) {
                out[r.name] = Existing{r.id, ""};
            }
            break;
        case ManifestKind::Permission:
            for (const auto& p : api.permissions().list(page)) {
                out[p.action] = Existing{p.id, p.description};
            }
            break;
        case ManifestKind::Role:
            for (const auto& r : api.roles().list(page)) {
                out[r.name] = Existing{r.id, r.description};
            }
            break;
        case ManifestKind::Group:
            for (const auto& g : api.groups().list(page)) {
                out[g.name] = Existing{g.id, g.description};
            }
            break;
    }
    return out;
}

void perform(const ManagementApi& api, const PlannedChange& change) {
    const auto& e = change.entity;
    const bool create = change.action == ChangeAction::Create;
    const std::string id = change.id.value_or("");

    switch (e.kind) {
        case ManifestKind::Resource: {
            if (create) {
                CreateResourceRequest body{};
                body.name = e.name;
                body.resource_type = e.resource_type.empty() ? "folder" : e.resource_type;
                api.resources().create(body);
            } else {
                UpdateResourceRequest body{};
                body.name = e.name;
                api.resources().update(id, body);
            }
            break;
        }
        case ManifestKind::Permission: {
            if (create) {
                CreatePermissionRequest body{};
                body.action = e.action;
                body.description = e.description;
                api.permissions().create(body);
            } else {
                UpdatePermissionRequest body{};
                body.description = e.description;
                api.permissions().update(id, body);
            }
            break;
        }
        case ManifestKind::Role: {
            if (create) {
                CreateRoleRequest body{};
                body.name = e.name;
                body.description = e.description;
                body.is_global = e.is_global;
                api.roles().create(body);
            } else {
                UpdateRole body{};
                body.description = e.description;
                api.roles().update(id, body);
            }
            break;
        }
        case ManifestKind::Group: {
            if (create) {
                CreateGroupRequest body{};
                body.name = e.name;
                body.description = e.description;
                api.groups().create(body);
            } else {
                UpdateGroup body{};
                body.description = e.description;
                api.groups().update(id, body);
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
            change.id = found->second.id;
            // Compare ONLY what the manifest names. A server object carries plenty a
            // manifest says nothing about, and treating that as drift would make every
            // plan report a change and every apply overwrite work nobody claimed.
            const bool drifted = !e.description.empty() &&
                                 e.description != found->second.description;
            change.action = drifted ? ChangeAction::Update : ChangeAction::Unchanged;
        }
        out.changes.push_back(std::move(change));
    }
    return out;
}

ApplyReport ManifestApi::apply(const Manifest& manifest) const {
    const auto computed = plan(manifest);
    const auto pending = computed.pending();
    const ManagementApi api(transport_, scope_);

    ApplyReport report;
    for (std::size_t i = 0; i < pending.size(); ++i) {
        try {
            perform(api, pending[i]);
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
// nothing about the manifest layer -- the generated file's only job is the 146
// operations.
ManifestApi ManagementApi::manifest() const { return ManifestApi(transport_, scope_); }

}  // namespace axiam::management
