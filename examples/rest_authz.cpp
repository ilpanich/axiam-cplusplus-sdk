// rest_authz.cpp — the REST authorization surface (CONTRACT.md §1, §5.1).
//
// Logs in first (see login_mfa.cpp for the full MFA-aware flow), then exercises
// POST /api/v1/authz/check (check_access / the can() alias) and
// POST /api/v1/authz/check/batch (batch_check, results preserve input order).
//
// The client is built with BOTH tenant and organization context: §5.1 requires
// an org identifier for login (server returns HTTP 400 otherwise), and refresh
// needs the org_id the client recovers from the login response.
//
// This example is illustrative and self-contained: it reads connection details
// from environment variables and compiles without a live AXIAM server.
//
// Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
// Run:    ./build/examples/axiam_example_rest_authz

#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <axiam/axiam.hpp>

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v && *v) ? std::string(v) : fallback;
}

}  // namespace

int main() {
    const std::string base_url    = env_or("AXIAM_BASE_URL", "https://localhost:8443");
    const std::string tenant_slug = env_or("AXIAM_TENANT_SLUG", "acme");
    const std::string org_slug    = env_or("AXIAM_ORG_SLUG", "acme");
    const std::string email       = env_or("AXIAM_EMAIL", "user@example.com");
    const std::string password    = env_or("AXIAM_PASSWORD", "changeme");
    const std::string resource_id =
        env_or("AXIAM_RESOURCE_ID", "00000000-0000-0000-0000-000000000000");

    try {
        // §5 tenant + §5.1 org context are both required to log in.
        axiam::Client client = axiam::Client::builder()
            .base_url(base_url)
            .tenant_slug(tenant_slug)
            .org_slug(org_slug)
            .build();

        axiam::LoginResult login = client.login(email, password);
        if (login.mfa_required) {
            std::cout << "MFA is required for this account — see login_mfa.cpp first.\n";
            return 0;
        }

        // POST /api/v1/authz/check — a single access check.
        axiam::AccessDecision read = client.check_access("resource:read", resource_id);
        std::cout << "check_access(resource:read) -> allowed=" << std::boolalpha
                  << read.allowed;
        if (read.reason) std::cout << " reason=" << *read.reason;
        std::cout << "\n";

        // can() — the UI-facing alias for check_access (same wire call).
        axiam::AccessDecision write = client.can("resource:write", resource_id);
        std::cout << "can(resource:write) -> allowed=" << write.allowed << "\n";

        // POST /api/v1/authz/check/batch — ordered batch; results match input order.
        std::vector<axiam::AccessCheck> checks = {
            {"resource:read", resource_id, std::nullopt, std::nullopt},
            {"resource:delete", resource_id, std::optional<std::string>("admin"), std::nullopt},
        };
        std::vector<axiam::AccessDecision> results = client.batch_check(checks);
        for (std::size_t i = 0; i < results.size(); ++i) {
            std::cout << "batch_check[" << i << "] -> allowed=" << results[i].allowed << "\n";
        }

        client.logout();
        return 0;
    } catch (const axiam::AuthError& e) {
        std::cerr << "authentication failed: " << e.what() << "\n";
    } catch (const axiam::AuthzError& e) {
        std::cerr << "authorization denied: " << e.what() << "\n";
    } catch (const axiam::NetworkError& e) {
        std::cerr << "transport error: " << e.what() << " (cause: " << e.cause() << ")\n";
    } catch (const axiam::AxiamError& e) {
        std::cerr << "axiam error: " << e.what() << "\n";
    }
    return 1;
}
