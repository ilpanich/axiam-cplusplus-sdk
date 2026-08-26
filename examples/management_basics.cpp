// management_basics — the CONTRACT.md §27 management surface.
//
// 146 operations across 24 namespaces, reached through namespace handles hung
// off `client.management()`. Nothing here opens its own connection: §27.8
// requires the generated layer sit on the SDK's existing request path, so every
// call below inherits §5's tenant headers, §6's TLS floor, §9's single-flight
// refresh, §16's retry policy and §19's telemetry by construction.
//
// What this program demonstrates, in order:
//
//   1. Paging that does not lie (§27.4 rule 4) — `total` is the server's count
//      across every page and is NOT the length of the page in your hand.
//   2. Per-call scope (§27.4 rule 3) — `for_tenant()` returns a NEW handle.
//   3. A sparse update (§27.4 rule 5) — only the fields you set are sent.
//   4. The error sub-types (§27.4 rule 7), including the two that sit under
//      AuthzError rather than where you would guess.
//
// It writes nothing unless AXIAM_WRITE=1 is set, so it is safe to point at a
// real tenant to see what is there.

#include <cstdlib>
#include <iostream>
#include <string>

#include "axiam/axiam.hpp"
#include "axiam/management.hpp"

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v != nullptr && *v != '\0') ? std::string(v) : fallback;
}

}  // namespace

int main() {
    try {
        auto client =
            axiam::Client::builder()
                .base_url(env_or("AXIAM_BASE_URL", "https://localhost:8443"))
                .tenant_id(env_or("AXIAM_TENANT_ID", "11111111-1111-1111-1111-111111111111"))
                .build();

        // §27.4 rule 1: no session, no wire call. Every management operation
        // refuses locally when the client is unauthenticated, rather than
        // sending a request the server will reject — an unauthenticated
        // management call is a programming error, not a 401 to handle.
        client.login(env_or("AXIAM_USERNAME", "admin"), env_or("AXIAM_PASSWORD", "admin"));

        auto mgmt = client.management();

        // ---- 1. Paging (§27.4 rule 4) ---------------------------------
        //
        // `page.total` is the SERVER's count across all pages. `page.size()` is
        // how many came back in this one. They are separate members precisely
        // so that a management tool cannot accidentally report "4 roles" after
        // reading the first page of four hundred.
        auto page = mgmt.roles().list();
        std::cout << "roles: " << page.size() << " on this page, " << page.total
                  << " in the tenant\n";
        for (const auto& role : page) {
            std::cout << "  " << role.name << (role.is_global ? "  [global]" : "") << "\n";
        }

        // Auto-paging stops on an EMPTY page, not a short one — a server is
        // free to return fewer rows than asked for and still have more.
        std::int64_t seen = 0;
        for (auto req = axiam::management::PageRequest{}; ; req = req.next()) {
            const auto batch = mgmt.roles().list(req);
            if (batch.empty()) {
                break;  // The stop condition. Not `batch.size() < req.limit`.
            }
            seen += static_cast<std::int64_t>(batch.size());
        }
        std::cout << "walked " << seen << " roles across every page\n";

        // ---- 2. Per-call scope (§27.4 rule 3) -------------------------
        //
        // for_tenant() returns a NEW handle rather than repointing this one. On
        // a management surface, a shared handle that another code path had
        // re-scoped would not merely read the wrong tenant — it would WRITE to
        // it.
        const std::string other = env_or("AXIAM_OTHER_TENANT_ID", "");
        if (!other.empty()) {
            const auto elsewhere = mgmt.roles().for_tenant(other).list();
            std::cout << "tenant " << other << " has " << elsewhere.total << " roles\n";
            // mgmt.roles() is still pointed at the client's own tenant here.
        }

        if (env_or("AXIAM_WRITE", "") != "1") {
            std::cout << "\n(set AXIAM_WRITE=1 to run the write half)\n";
            return 0;
        }

        // ---- 3. Create, then a SPARSE update (§27.4 rule 5) -----------
        axiam::management::CreateRoleRequest create;
        create.name = "example-editor";
        create.description = "Created by the management_basics example";
        create.is_global = false;
        const auto role = mgmt.roles().create(create);
        std::cout << "\ncreated role " << role.id << "\n";

        // Sparse means ABSENT, not null. Only `description` is set below, so
        // only `description` appears in the request body — `name` and
        // `is_global` keep whatever the server holds. A replacement body would
        // require all three; that is a different operation, and the model types
        // are different so you cannot confuse them by accident.
        axiam::management::UpdateRole patch;
        patch.description = "Description changed; name and is_global untouched";
        const auto updated = mgmt.roles().update(role.id, patch);
        std::cout << "updated: name is still " << updated.name << "\n";

        // §27.4 rule 6: deletes are NOT idempotent. Deleting this twice gives a
        // NotFoundError on the second call, and the SDK does not swallow it —
        // "it was already gone" and "I deleted it" are different facts, and a
        // provisioning tool that cannot tell them apart cannot audit itself.
        mgmt.roles().delete_(role.id);
        std::cout << "deleted\n";

        return 0;

        // ---- 4. The §27.4 rule 7 error map ----------------------------
        //
        // Order matters below: NotFoundError and ConflictError both derive from
        // AuthzError, so a `catch (const AuthzError&)` placed first would
        // swallow them.
    } catch (const axiam::management::NotFoundError& e) {
        // 404. Derives from AuthzError, which is the surprising part and the
        // deliberate part: AXIAM answers 404 for an object in another tenant
        // exactly so a probing caller cannot distinguish "does not exist" from
        // "exists, not yours". Classifying it as an authorization outcome keeps
        // the SDK from re-drawing a line the server refused to draw.
        std::cerr << "not found (or not yours): " << e.what() << "\n";
        return 1;
    } catch (const axiam::management::ConflictError& e) {
        // 409. Also under AuthzError — §2 already mapped 409 there and §27.4
        // rule 7 keeps that mapping rather than moving it.
        std::cerr << "conflict: " << e.what() << "\n";
        return 1;
    } catch (const axiam::management::ValidationError& e) {
        // 400/422. Under NetworkError, inherited from §2's 400 row. That has
        // one consequence worth knowing: §16 retries NetworkError, so this type
        // is explicitly excluded from retry — a body the server has already
        // rejected does not get sent three times.
        std::cerr << "rejected: " << e.what() << "\n";
        return 1;
    } catch (const axiam::AxiamError& e) {
        std::cerr << "management call failed: " << e.what() << "\n";
        return 1;
    }
}
