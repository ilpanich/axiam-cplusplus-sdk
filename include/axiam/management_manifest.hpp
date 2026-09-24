/// @file management_manifest.hpp
/// @brief CONTRACT.md §27.6/§27.7 declarative layer — describe a tenant, plan, apply.
///
/// The imperative surface is fine for one change. It is a poor way to describe a TENANT,
/// because re-running it either fails on the second run or makes the caller hand-write
/// "does this exist already?" for every object. A manifest is re-runnable by
/// construction: apply it twice and the second run sends nothing.
///
/// Four properties constrain everything here, and are worth knowing before running one
/// against production:
///
/// - **plan() writes nothing.** It reads the tenant and reports the difference. Safe
///   against production, safe in CI, safe on a schedule.
/// - **apply() stops at the first failure and does NOT roll back** (§27.7). The report
///   says what landed, what failed and what was never attempted — a partial apply is a
///   state an operator resumes from, and an automatic rollback would fire a second wave
///   of writes at exactly the moment the server is saying something is wrong.
/// - **Ordering is derived, not declared.** By kind, then dependency, then key. The
///   tie-break on key is what makes a plan stable across runs.
/// - **Omission is never deletion.** There is no delete action at all, so an incomplete
///   manifest cannot become a destructive one.
///
/// Entities are addressed by a manifest-local `key`, never by a server-assigned UUID —
/// that is what lets the same manifest mean the same thing against a fresh tenant and an
/// existing one, since a UUID does not exist until the first apply.

#ifndef AXIAM_MANAGEMENT_MANIFEST_HPP
#define AXIAM_MANAGEMENT_MANIFEST_HPP

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "axiam/errors.hpp"
#include "axiam/management.hpp"
#include "axiam/sensitive.hpp"

namespace axiam::management {

/// The entity kinds a manifest can declare.
///
/// The order of these enumerators IS the order an apply runs them in — the dependency
/// order §27.6 requires be derived rather than written down by the caller. A role cannot
/// be granted a permission that does not exist yet, and a group cannot be assigned a role
/// that does not exist yet.
enum class ManifestKind {
    Resource = 0,  ///< Hierarchical resource; parents before children.
    Permission,    ///< A permission (an action). Depends on nothing.
    Role,          ///< A role. Depends on permissions.
    Group,         ///< A group. Depends on roles.
    /// A machine identity (CONTRACT.md §27.6.1 item 3, contract 1.51). Depends on
    /// roles (its `roles[]` bindings) and, when a binding is resource-scoped, on the
    /// resource it names — both already ordered ahead of this by the enumerator
    /// values above.
    ServiceAccount,
};

/// What a plan intends to do to one declared entity.
///
/// There is deliberately no Delete. §27.6 is explicit that omission is never deletion: a
/// manifest describes what must exist, not everything that may exist, and a tenant almost
/// always holds objects no manifest mentions. Leaving the action out of the enum makes
/// that structural rather than a matter of discipline.
enum class ChangeAction {
    Unchanged = 0,  ///< Already matches; nothing will be sent.
    Create,         ///< Does not exist; will be created.
    Update,         ///< Exists but differs; updated in place.
};

/// One CONTRACT.md §27.6.1 role binding (contract 1.51): a `groups[].roles[]` or
/// `service_accounts[].roles[]` entry. Either shape the contract specifies —
///
/// - a bare role key (`{.role = "editor"}`): no resource, so no inheritance question,
///   the binding as every SDK had it before 1.51; or
/// - the resource-scoped shape (`{.role = "editor", .resource = "docs-root", .inherit
///   = false}`): `resource` and `inherit` are both optional, and `inherit` reaches the
///   wire ONLY as `false` — an engaged `true` is refused client-side (§27.6.1: "An SDK
///   MUST NOT send `inherit: true` explicitly, so that an inheritable binding's body
///   stays byte-for-byte a pre-1.51 body").
///
/// is this one struct; a bare role key is simply `resource`/`inherit` both disengaged.
struct ManifestRoleBinding {
    std::string role;                     ///< Manifest-local key of the role (a Role entity).
    std::optional<std::string> resource;  ///< Manifest-local key of the resource, when scoped.
    /// `false` narrows the assignment to `resource` alone. `true` is REFUSED
    /// client-side at `plan()` time (see the note above); omit the field for an
    /// inheritable binding, which is the default both here and on the wire.
    std::optional<bool> inherit;
};

/// One entity a manifest declares must exist.
struct ManifestEntity {
    ManifestKind kind = ManifestKind::Permission;  ///< What sort of object this is.
    std::string key{};          ///< Manifest-local identity, unique within its kind.
    std::string name{};         ///< The name the server knows it by; also the match key.
    std::string description{};  ///< Human-readable description.
    std::string resource_type{};  ///< For a resource: its `resource_type`.
    std::string action{};         ///< For a permission: the action it names.
    bool is_global = false;       ///< For a role: whether it applies tenant-wide.
    /// Key of the entity this one must be applied after, beyond what `kind` already
    /// orders — a parent resource, or a permission a role grants.
    ///
    /// A KEY, never a UUID: a manifest describes a tenant that may not exist yet.
    std::optional<std::string> depends_on = std::nullopt;

    // ---- Contract 1.51, §27.6.1 additions. Appended after depends_on so every
    // existing designated-initializer (positional up to depends_on) and every
    // AXIAM_RESOURCE/AXIAM_ROLE/AXIAM_GROUP macro use still compiles unchanged. ----

    /// §27.6.1 item 1, for a `Resource`: the desired `metadata` object, as JSON text
    /// (this SDK's convention for a free-form JSON member — see management_models.hpp).
    /// Disengaged is silent about the field, per rule 3 — never an assertion that the
    /// server's `metadata` should become `{}`. Drift is JSON VALUE equality of the
    /// whole object (never key-by-key), matching the contract's own rule: a merge
    /// would make `apply` unable to remove a key.
    std::optional<std::string> metadata_json = std::nullopt;

    /// §27.6.1 item 2, for a `Group` or `ServiceAccount`: the roles it must hold.
    /// Reconciled ADDITIVELY (this SDK's documented scope, see README): a declared
    /// binding absent from the subject is assigned; a role the manifest does not name
    /// is left exactly as the tenant already has it, whether or not this subject holds
    /// it. Changing an EXISTING binding's `resource`/`inherit` is not performed by
    /// `apply` — use `roles().unassign_from_group()` / `assign_to_group()` (or the
    /// service-account pair) directly for that.
    std::vector<ManifestRoleBinding> roles{};
};

/// A declarative description of the state a tenant must be in.
struct Manifest {
    std::vector<ManifestEntity> entities;
};

/// One entry in a plan: what would happen to one entity, and why.
struct PlannedChange {
    ManifestEntity entity;                     ///< The declaration this is for.
    ChangeAction action = ChangeAction::Unchanged;  ///< What would be done.
    std::optional<std::string> id;             ///< Server id when it already exists.

    /// CONTRACT.md §27.5 rule 5 (contract 1.51): the ONE-TIME `client_secret` from a
    /// `ServiceAccount` `Create` outcome, `Sensitive<T>` as always. Engaged only when
    /// `entity.kind == ManifestKind::ServiceAccount && action == ChangeAction::Create`
    /// and the create actually succeeded (only path where this field is ever written).
    /// `Update` and `NoChange` never rotate a secret to reconcile, so this stays
    /// disengaged for both -- the only way to see one again is the imperative
    /// `rotate_secret`, which the caller chooses to make.
    ///
    /// Returned here rather than only on `apply()`'s overall result because §27.6 rule 7
    /// already requires every attempted action's outcome, and this is the one place a
    /// declarative `apply` touches a credential that cannot be read back: an `apply`
    /// that stopped at a LATER action still needs this one recoverable from
    /// `ApplyReport::applied`.
    std::optional<Sensitive<std::string>> service_account_secret;

    /// A one-line rendering, e.g. `create permission:read`.
    std::string describe() const;
};

/// What plan() produced: the ordered changes an apply would make.
///
/// Includes the Unchanged entries too, so a reader sees what was considered and not only
/// what moved.
struct Plan {
    std::vector<PlannedChange> changes;

    /// Only the changes that would actually send a request.
    std::vector<PlannedChange> pending() const;

    /// True when the tenant already matches and an apply would send nothing.
    bool converged() const { return pending().empty(); }
};

/// What apply() actually did — including, when it stopped early, what it had already done.
///
/// This is the recovery tool. Fix the cause and re-run: the changes that already landed
/// plan as Unchanged next time, so a resumed apply picks up where this one stopped.
struct ApplyReport {
    std::vector<PlannedChange> applied;    ///< Changes that succeeded, in order.
    std::optional<PlannedChange> failed;   ///< The change that failed, if any.
    std::string failure;                   ///< Why it failed.
    std::vector<PlannedChange> remaining;  ///< Never attempted because of the failure.

    /// True when every planned change landed.
    bool complete() const { return !failed.has_value(); }

    /// A human-readable account of the run, for a log line or a CI summary.
    std::vector<std::string> describe() const;
};

/// Raised when a manifest is rejected BEFORE any request is sent.
///
/// Every use of this type is a refusal to START. A manifest with a dangling reference or
/// a dependency cycle cannot be applied coherently, and discovering that halfway through
/// — with no rollback (§27.7) — is strictly worse than refusing up front.
class ManifestError : public AxiamError {
public:
    explicit ManifestError(const std::string& message) : AxiamError(message) {}
};

/// Plans and applies a §27.6 manifest.
class ManifestApi {
public:
    explicit ManifestApi(std::shared_ptr<Transport> transport, CallScope scope);

    /// Compute what an apply would do. Sends only reads (§27.6).
    ///
    /// Validates the manifest before the first read, so an incoherent one is refused up
    /// front rather than halfway through.
    Plan plan(const Manifest& manifest) const;

    /// Apply a manifest, stopping at the first failure and NOT rolling back (§27.7).
    ///
    /// Re-plans internally rather than taking a Plan, so what is applied is computed
    /// against the tenant's state NOW. A plan from an earlier run describes a tenant that
    /// may have moved since, and applying it would either duplicate work or fail on a
    /// conflict — either way acting on a world that no longer exists.
    ApplyReport apply(const Manifest& manifest) const;

    /// Validate a manifest without contacting the server.
    ///
    /// Every check is one that can be made from the manifest alone: a duplicate key, a
    /// `depends_on` naming an entity nobody declares, or a dependency cycle. Exposed
    /// separately so a caller can check at start-up rather than at apply time.
    static void validate(const Manifest& manifest);

    /// The entities in apply order: by kind, then by dependency, then by key.
    ///
    /// The final tie-break on key is what makes a plan STABLE ACROSS RUNS. Two entities
    /// of the same kind with no dependency between them have no natural order, and
    /// without a deterministic tie-break they would come out in whatever order the caller
    /// happened to declare them — making every plan diff unreadable.
    static std::vector<ManifestEntity> ordered(const Manifest& manifest);

private:
    std::shared_ptr<Transport> transport_;
    CallScope scope_;
};

}  // namespace axiam::management

// ---------------------------------------------------------------------------
// §27.7's C++ declarative form: designated-initializer aggregate specs plus an
// AXIAM_MANIFEST(...) macro.
//
// ManifestEntity is an aggregate whose every member carries a default member
// initializer, which is what makes `.key = "x", .name = "y"` legal without
// naming the members you do not care about — and, less obviously, what keeps
// -Wextra quiet, since -Wmissing-field-initializers fires on an omitted member
// only when that member has no default.
//
// The macros fix `.kind` and nothing else. They are sugar over the aggregate,
// not a second way to build one: each expands to a ManifestEntity value and
// AXIAM_MANIFEST expands to a Manifest holding them, so a manifest written this
// way and one deserialized from configuration are the same value and go through
// the same plan()/apply(). §27.7 requires exactly that — "a declarative form
// that talks to the network itself is a second implementation of §27.6, and the
// two will disagree."
//
// Designated initializers must appear in DECLARATION order, which for
// ManifestEntity is: key, name, description, resource_type, action, is_global,
// depends_on.
//
//   const auto manifest = AXIAM_MANIFEST(
//       AXIAM_PERMISSION(.key = "read", .name = "documents:read", .action = "read"),
//       AXIAM_ROLE(.key = "editor", .name = "editor", .depends_on = "read"),
//       AXIAM_RESOURCE(.key = "root", .name = "documents", .resource_type = "folder"),
//       AXIAM_GROUP(.key = "editors", .name = "editors", .depends_on = "editor"));
//
// Unqualified in the axiam:: namespace on purpose: a macro has no namespace, so
// the expansions below name their types fully instead.
// ---------------------------------------------------------------------------

/// A `ManifestEntity` of kind `Resource`; remaining members in declaration order.
#define AXIAM_RESOURCE(...) \
    ::axiam::management::ManifestEntity { .kind = ::axiam::management::ManifestKind::Resource, __VA_ARGS__ }

/// A `ManifestEntity` of kind `Permission`; remaining members in declaration order.
#define AXIAM_PERMISSION(...) \
    ::axiam::management::ManifestEntity { .kind = ::axiam::management::ManifestKind::Permission, __VA_ARGS__ }

/// A `ManifestEntity` of kind `Role`; remaining members in declaration order.
#define AXIAM_ROLE(...) \
    ::axiam::management::ManifestEntity { .kind = ::axiam::management::ManifestKind::Role, __VA_ARGS__ }

/// A `ManifestEntity` of kind `Group`; remaining members in declaration order.
#define AXIAM_GROUP(...) \
    ::axiam::management::ManifestEntity { .kind = ::axiam::management::ManifestKind::Group, __VA_ARGS__ }

/// A `ManifestEntity` of kind `ServiceAccount` (contract 1.51, §27.6.1 item 3);
/// remaining members in declaration order.
#define AXIAM_SERVICE_ACCOUNT(...) \
    ::axiam::management::ManifestEntity { \
        .kind = ::axiam::management::ManifestKind::ServiceAccount, __VA_ARGS__ \
    }

/// A `Manifest` holding the entity specs given.
///
/// Declaration ORDER here carries no meaning: `ManifestApi::ordered()` derives apply order
/// from kind and `depends_on`, so shuffling the arguments below yields the same plan.
#define AXIAM_MANIFEST(...) \
    ::axiam::management::Manifest { { __VA_ARGS__ } }

#endif  // AXIAM_MANAGEMENT_MANIFEST_HPP
