// management_manifest — the CONTRACT.md §27.6/§27.7 declarative layer.
//
// The imperative surface in management_basics.cpp is fine for one change. It is
// a poor way to describe a TENANT, because re-running it either fails on the
// second run or makes you hand-write "does this exist already?" around every
// object. A manifest is re-runnable by construction: apply it twice and the
// second run sends nothing.
//
// Four properties are worth knowing before pointing this at production:
//
//   * plan() writes nothing. It reads the tenant and reports the difference —
//     safe in CI, safe on a schedule, safe against a live tenant.
//   * apply() stops at the first failure and does NOT roll back (§27.7). The
//     report names what landed, what failed and what was never attempted, so a
//     partial apply is a state you resume from. An automatic rollback would
//     fire a second wave of writes at exactly the moment the server is telling
//     you something is wrong.
//   * Ordering is DERIVED, not declared. By kind, then dependency, then key —
//     so shuffling the entities below changes nothing, and two runs of the same
//     manifest produce the same plan in the same order.
//   * Omission is never deletion. ChangeAction has no Delete member at all, so
//     an incomplete manifest cannot become a destructive one.
//
// The manifest is built here with §27.7's C++ form: designated-initializer
// aggregate specs and the AXIAM_MANIFEST(...) macro. That is sugar over a plain
// value — it lowers to the same Manifest a config file deserializes into, and
// goes through the same plan()/apply(). A declarative form that talked to the
// network itself would be a second implementation of §27.6, and the two would
// disagree.
//
// Runs plan-only unless AXIAM_APPLY=1 is set.

#include <cstdlib>
#include <iostream>
#include <string>

#include "axiam/axiam.hpp"
#include "axiam/management_manifest.hpp"

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v != nullptr && *v != '\0') ? std::string(v) : fallback;
}

// The tenant this program insists must exist. Entities are addressed by a
// manifest-local `key`, never by a server-assigned UUID — that is what lets the
// same manifest mean the same thing against a fresh tenant and an existing one,
// since a UUID does not exist until the first apply.
//
// Note the declaration order: group, then role, then permission, then resource
// — deliberately backwards. ManifestApi::ordered() derives the apply order from
// kind and depends_on, so this comes out resource, permission, role, group.
axiam::management::Manifest documents_tenant() {
    return AXIAM_MANIFEST(
        AXIAM_GROUP(.key = "editors", .name = "editors",
                    .description = "People who may edit documents",
                    .depends_on = "editor"),

        AXIAM_ROLE(.key = "editor", .name = "editor",
                   .description = "Read and write documents",
                   .is_global = false,
                   // A role cannot grant a permission that does not exist yet.
                   // `kind` already orders permissions before roles; this names
                   // WHICH permission, so the resource-level dependency is
                   // explicit rather than incidental.
                   .depends_on = "documents-write"),

        AXIAM_PERMISSION(.key = "documents-read", .name = "documents:read",
                         .description = "Read a document", .action = "read",
                         .depends_on = "root"),

        AXIAM_PERMISSION(.key = "documents-write", .name = "documents:write",
                         .description = "Write a document", .action = "write",
                         .depends_on = "root"),

        AXIAM_RESOURCE(.key = "root", .name = "documents",
                       .description = "The document tree",
                       .resource_type = "folder"));
}

}  // namespace

int main() {
    try {
        auto client =
            axiam::Client::builder()
                .base_url(env_or("AXIAM_BASE_URL", "https://localhost:8443"))
                .tenant_id(env_or("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111"))
                .build();
        client.login(env_or("AXIAM_USERNAME", "admin"), env_or("AXIAM_PASSWORD", "admin"));

        const auto manifest = documents_tenant();
        auto manifests = client.management().manifest();

        // Validation is separable from planning on purpose: a duplicate key, a
        // depends_on naming nothing, or a dependency cycle is decidable from
        // the manifest alone, so a service can check its manifest at start-up
        // rather than discovering it is incoherent at apply time. plan() runs
        // this itself before its first read, so calling it here is belt and
        // braces — cheap belt, no network.
        axiam::management::ManifestApi::validate(manifest);

        // ---- plan: reads only --------------------------------------------
        const auto plan = manifests.plan(manifest);

        std::cout << "plan (" << plan.changes.size() << " entities considered, "
                  << plan.pending().size() << " would change):\n";
        for (const auto& change : plan.changes) {
            std::cout << "  " << change.describe() << "\n";
        }

        if (plan.converged()) {
            std::cout << "\nTenant already matches. An apply would send nothing.\n";
            return 0;
        }

        if (env_or("AXIAM_APPLY", "") != "1") {
            std::cout << "\n(set AXIAM_APPLY=1 to apply this plan)\n";
            return 0;
        }

        // ---- apply: stops at the first failure, does not roll back --------
        //
        // apply() re-plans internally rather than taking the plan above,
        // because what it applies must be computed against the tenant's state
        // NOW. A plan from a minute ago describes a tenant that may have moved,
        // and applying it would either duplicate work or fail on a conflict —
        // either way acting on a world that no longer exists.
        const auto report = manifests.apply(manifest);

        for (const auto& line : report.describe()) {
            std::cout << line << "\n";
        }

        if (!report.complete()) {
            // Not an error to paper over: this is the recovery instruction.
            // Fix the cause and re-run — the changes that already landed plan
            // as Unchanged next time, so a resumed apply picks up exactly where
            // this one stopped.
            std::cerr << "\napply stopped early: " << report.failure << "\n"
                      << report.applied.size() << " applied, " << report.remaining.size()
                      << " never attempted. Re-run after fixing the cause.\n";
            return 1;
        }

        std::cout << "\nConverged. Run this again and it will send nothing.\n";
        return 0;

    } catch (const axiam::management::ManifestError& e) {
        // Refused BEFORE any request went out. Every use of this type is a
        // refusal to START: a manifest with a dangling reference or a cycle
        // cannot be applied coherently, and discovering that halfway through —
        // with no rollback — is strictly worse than refusing up front.
        std::cerr << "manifest rejected: " << e.what() << "\n";
        return 2;
    } catch (const axiam::AxiamError& e) {
        std::cerr << "failed: " << e.what() << "\n";
        return 1;
    }
}
