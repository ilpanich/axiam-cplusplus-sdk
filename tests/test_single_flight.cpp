#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::json_response;

// §9: N concurrent 401-triggering requests must produce exactly ONE refresh call,
// whose outcome is shared; all waiters then succeed on retry.
AXIAM_TEST("single-flight refresh: 5 concurrent 401s -> exactly 1 refresh") {
    auto st = std::make_shared<FakeState>();
    auto refreshed = std::make_shared<std::atomic<bool>>(false);

    st->router = [refreshed](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            auto r = json_response(200,
                                   R"({"session_id":"s","expires_in":900,)"
                                   R"("user":{"id":"u","username":"a","email":"a@x","tenant_id":"t"}})");
            r.headers["X-CSRF-Token"] = "tok";
            return r;
        }
        if (req.url.find("/auth/refresh") != std::string::npos) {
            // Hold the refresh open briefly so all waiters coalesce onto it.
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            refreshed->store(true);
            return json_response(200, R"({"expires_in":900})");
        }
        // authz/check: 401 until the (single) refresh has completed.
        if (!refreshed->load()) return json_response(401, "{}");
        return json_response(200, R"({"allowed":true})");
    };

    Client c = Client::builder()
                   .base_url("https://api.example.test")
                   .tenant_slug("acme")
                   .org_id("org-1")
                   .transport(axtest::make_fake(st))
                   .build();
    c.login("a", "b");

    constexpr int N = 5;
    std::vector<std::thread> threads;
    std::atomic<int> allowed_count{0};
    std::atomic<int> error_count{0};
    for (int i = 0; i < N; ++i) {
        threads.emplace_back([&c, &allowed_count, &error_count] {
            try {
                if (c.check_access("read", "r").allowed) allowed_count.fetch_add(1);
            } catch (...) {
                error_count.fetch_add(1);
            }
        });
    }
    for (auto& t : threads) t.join();

    AXIAM_CHECK(error_count.load() == 0);
    AXIAM_CHECK(allowed_count.load() == N);
    // The key assertion: exactly one network refresh despite N concurrent 401s.
    AXIAM_CHECK(c.refresh_call_count() == 1);
    AXIAM_CHECK(st->count_path("/auth/refresh") == 1);
}

AXIAM_TEST("failed refresh raises AuthError and does not retry-loop (§9.3)") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            auto r = json_response(200,
                                   R"({"session_id":"s","expires_in":900,)"
                                   R"("user":{"id":"u","username":"a","email":"a@x","tenant_id":"t"}})");
            r.headers["X-CSRF-Token"] = "tok";
            return r;
        }
        if (req.url.find("/auth/refresh") != std::string::npos) {
            return json_response(401, "{}");  // refresh itself rejected
        }
        return json_response(401, "{}");  // check always unauthenticated
    };
    Client c = Client::builder()
                   .base_url("https://api.example.test")
                   .tenant_slug("acme")
                   .org_id("org-1")
                   .transport(axtest::make_fake(st))
                   .build();
    c.login("a", "b");
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r"), AuthError);
    // Exactly one refresh attempt; no retry loop.
    AXIAM_CHECK(c.refresh_call_count() == 1);
}
