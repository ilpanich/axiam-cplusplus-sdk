#include <atomic>
#include <memory>
#include <string>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "fake_transport.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::json_response;

static Client make_client(std::shared_ptr<FakeState> st, const std::string& tenant = "acme") {
    return Client::builder()
        .base_url("https://api.example.test")
        .tenant_slug(tenant)
        .org_slug("globex")
        .transport(axtest::make_fake(st))
        .build();
}

AXIAM_TEST("login success parses user + sets session, injects tenant header") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        auto r = json_response(200,
                               R"({"session_id":"sess-1","expires_in":900,)"
                               R"("user":{"id":"u-1","username":"alice","email":"a@x.io",)"
                               R"("tenant_id":"t-1","tenant_slug":"acme"}})");
        r.headers["X-CSRF-Token"] = "csrf-abc";
        return r;
    };
    Client c = make_client(st);
    LoginResult res = c.login("alice", "pw");
    AXIAM_CHECK_FALSE(res.mfa_required);
    AXIAM_REQUIRE(res.user.has_value());
    AXIAM_CHECK(res.user->id == "u-1");
    AXIAM_CHECK(res.expires_in == 900);
    AXIAM_CHECK(c.has_session());
    // §5: X-Tenant-ID present on the login request.
    AXIAM_CHECK(st->last().headers.count("X-Tenant-ID") == 1);
    AXIAM_CHECK(st->last().headers.at("X-Tenant-ID") == "acme");
    // §3: CSRF token captured from response header.
    AXIAM_REQUIRE(c.csrf_token().has_value());
    AXIAM_CHECK(*c.csrf_token() == "csrf-abc");
}

AXIAM_TEST("login MFA-required (202) returns challenge branch") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(202,
                             R"({"mfa_required":true,"challenge_token":"chal-9",)"
                             R"("available_methods":["totp"]})");
    };
    Client c = make_client(st);
    LoginResult res = c.login("alice", "pw");
    AXIAM_CHECK(res.mfa_required);
    AXIAM_CHECK(res.challenge_token == "chal-9");
    AXIAM_REQUIRE(res.available_methods.size() == 1);
    AXIAM_CHECK(res.available_methods[0] == "totp");
    AXIAM_CHECK_FALSE(c.has_session());
}

AXIAM_TEST("verify_mfa success establishes session") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200,
                             R"({"session_id":"s","expires_in":900,)"
                             R"("user":{"id":"u-1","username":"a","email":"a@x","tenant_id":"t-1"}})");
    };
    Client c = make_client(st);
    LoginResult res = c.verify_mfa("chal-9", "123456");
    AXIAM_CHECK(c.has_session());
    AXIAM_REQUIRE(res.user.has_value());
    AXIAM_CHECK(res.user->tenant_id == "t-1");
}

AXIAM_TEST("check_access sends action+resource, parses decision") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) {
        AXIAM_CHECK(req.url.find("/api/v1/authz/check") != std::string::npos);
        AXIAM_CHECK(req.body.find("\"action\":\"read\"") != std::string::npos);
        AXIAM_CHECK(req.body.find("\"resource_id\":\"res-7\"") != std::string::npos);
        return json_response(200, R"({"allowed":true,"reason":"granted"})");
    };
    Client c = make_client(st);
    AccessDecision d = c.check_access("read", "res-7");
    AXIAM_CHECK(d.allowed);
    AXIAM_REQUIRE(d.reason.has_value());
    AXIAM_CHECK(*d.reason == "granted");
}

AXIAM_TEST("can is an alias for check_access and passes scope/subject") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) {
        AXIAM_CHECK(req.body.find("\"scope\":\"col-a\"") != std::string::npos);
        AXIAM_CHECK(req.body.find("\"subject_id\":\"end-user\"") != std::string::npos);
        return json_response(200, R"({"allowed":false})");
    };
    Client c = make_client(st);
    AccessDecision d = c.can("write", "res-7", std::string("col-a"), std::string("end-user"));
    AXIAM_CHECK_FALSE(d.allowed);
}

AXIAM_TEST("batch_check preserves order") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) {
        AXIAM_CHECK(req.url.find("/authz/check/batch") != std::string::npos);
        return json_response(200,
                             R"({"results":[{"allowed":true},{"allowed":false},{"allowed":true}]})");
    };
    Client c = make_client(st);
    std::vector<AccessCheck> checks = {
        {"read", "r1", std::nullopt, std::nullopt},
        {"write", "r2", std::nullopt, std::nullopt},
        {"delete", "r3", std::nullopt, std::nullopt},
    };
    auto results = c.batch_check(checks);
    AXIAM_REQUIRE(results.size() == 3);
    AXIAM_CHECK(results[0].allowed);
    AXIAM_CHECK_FALSE(results[1].allowed);
    AXIAM_CHECK(results[2].allowed);
}

AXIAM_TEST("CSRF token echoed on state-changing request after capture") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState& state) {
        // First call (login) sets the CSRF cookie/token; later calls must echo it.
        if (state.requests.size() == 1) {
            auto r = json_response(200,
                                   R"({"session_id":"s","expires_in":900,)"
                                   R"("user":{"id":"u","username":"a","email":"a@x","tenant_id":"t"}})");
            r.headers["X-CSRF-Token"] = "tok-77";
            return r;
        }
        return json_response(200, R"({"allowed":true})");
    };
    Client c = make_client(st);
    c.login("a", "b");
    c.check_access("read", "r1");
    auto last = st->last();
    AXIAM_REQUIRE(last.headers.count("X-CSRF-Token") == 1);
    AXIAM_CHECK(last.headers.at("X-CSRF-Token") == "tok-77");
}

AXIAM_TEST("status mapping: 400 -> NetworkError") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(400, "{}"); };
    Client c = make_client(st);
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r"), NetworkError);
}

AXIAM_TEST("status mapping: 401 (no session) -> AuthError") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(401, "{}"); };
    Client c = make_client(st);
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r"), AuthError);
}

AXIAM_TEST("status mapping: 403 -> AuthzError with detail") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(403, R"({"message":"nope","action":"read","resource_id":"r9"})");
    };
    Client c = make_client(st);
    bool caught = false;
    try {
        c.check_access("read", "r9");
    } catch (const AuthzError& e) {
        caught = true;
        AXIAM_REQUIRE(e.action().has_value());
        AXIAM_CHECK(*e.action() == "read");
        AXIAM_REQUIRE(e.resource_id().has_value());
        AXIAM_CHECK(*e.resource_id() == "r9");
    }
    AXIAM_CHECK(caught);
}

AXIAM_TEST("status mapping: 409 -> AuthzError, 429 -> NetworkError, 503 -> NetworkError") {
    auto st = std::make_shared<FakeState>();
    long code = 0;
    st->router = [&code](const HttpRequest&, FakeState&) { return json_response(code, "{}"); };
    Client c = make_client(st);
    code = 409;
    AXIAM_REQUIRE_THROWS_AS(c.check_access("a", "r"), AuthzError);
    code = 429;
    AXIAM_REQUIRE_THROWS_AS(c.check_access("a", "r"), NetworkError);
    code = 503;
    AXIAM_REQUIRE_THROWS_AS(c.check_access("a", "r"), NetworkError);
}

AXIAM_TEST("transport failure surfaces as NetworkError with cause") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        HttpResponse r;
        r.transport_error = "Could not resolve host";
        return r;
    };
    Client c = make_client(st);
    bool caught = false;
    try {
        c.check_access("a", "r");
    } catch (const NetworkError& e) {
        caught = true;
        AXIAM_CHECK(e.cause() == "Could not resolve host");
    }
    AXIAM_CHECK(caught);
}

AXIAM_TEST("logout clears session and CSRF even if server errors") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState& state) {
        if (req.url.find("/auth/login") != std::string::npos) {
            auto r = json_response(200,
                                   R"({"session_id":"s","expires_in":900,)"
                                   R"("user":{"id":"u","username":"a","email":"a@x","tenant_id":"t"}})");
            r.headers["X-CSRF-Token"] = "tok";
            (void)state;
            return r;
        }
        return json_response(500, "{}");  // logout fails server-side
    };
    Client c = make_client(st);
    c.login("a", "b");
    AXIAM_CHECK(c.has_session());
    c.logout();
    AXIAM_CHECK_FALSE(c.has_session());
    AXIAM_CHECK_FALSE(c.csrf_token().has_value());
}

AXIAM_TEST("refresh sends org_id decoded from the access-token cookie (D-14)") {
    // A JWT whose payload carries {"tenant_id":"tenant-uuid-abc","org_id":"org-uuid-xyz"}.
    const std::string access_jwt =
        "eyJhbGciOiAiRWREU0EiLCAidHlwIjogIkpXVCJ9."
        "eyJ0ZW5hbnRfaWQiOiAidGVuYW50LXV1aWQtYWJjIiwgIm9yZ19pZCI6ICJvcmctdXVpZC14eXoiLCAiZXhwIjogOTk5OTk5OTk5OX0."
        "sig";
    auto st = std::make_shared<FakeState>();
    auto refreshed = std::make_shared<std::atomic<bool>>(false);
    st->router = [access_jwt, refreshed](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            auto r = json_response(200,
                                   R"({"session_id":"s","expires_in":900,)"
                                   R"("user":{"id":"u","username":"a","email":"a@x","tenant_id":"tenant-uuid-abc"}})");
            r.headers["X-CSRF-Token"] = "tok";
            r.set_cookies.push_back("axiam_access=" + access_jwt + "; Path=/; HttpOnly");
            return r;
        }
        if (req.url.find("/auth/refresh") != std::string::npos) {
            refreshed->store(true);
            return json_response(200, R"({"expires_in":900})");
        }
        // authz/check: 401 until the (single) refresh has completed, then allow.
        if (!refreshed->load()) return json_response(401, "{}");
        return json_response(200, R"({"allowed":true})");
    };

    // Client configured with org SLUG only — org_id must come from the token.
    Client c = make_client(st);
    c.login("a", "b");
    AXIAM_CHECK(c.check_access("read", "res-1").allowed);

    // Locate the refresh request and assert it echoed the decoded org_id UUID,
    // not the configured slug.
    std::string refresh_body;
    {
        std::lock_guard<std::mutex> lock(st->mtx);
        for (const auto& r : st->requests) {
            if (r.url.find("/auth/refresh") != std::string::npos) refresh_body = r.body;
        }
    }
    AXIAM_CHECK(refresh_body.find("\"org_id\":\"org-uuid-xyz\"") != std::string::npos);
    AXIAM_CHECK(refresh_body.find("\"tenant_id\":\"tenant-uuid-abc\"") != std::string::npos);
    AXIAM_CHECK(refresh_body.find("globex") == std::string::npos);
}

AXIAM_TEST("authenticate_device parses response and wraps token in Sensitive") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200,
                             R"({"access_token":"device-token-xyz","token_type":"Bearer","expires_in":3600})");
    };
    Client c = make_client(st);
    DeviceAuth da = c.authenticate_device();
    AXIAM_CHECK(da.token_type == "Bearer");
    AXIAM_CHECK(da.expires_in == 3600);
    AXIAM_CHECK(da.access_token.to_string() == "[SENSITIVE]");
    AXIAM_CHECK(axiam::detail::reveal(da.access_token) == "device-token-xyz");
}

AXIAM_TEST("async check_access returns a future resolving to the decision") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"allowed":true})");
    };
    Client c = make_client(st);
    auto fut = c.check_access_async("read", "r1");
    AXIAM_CHECK(fut.get().allowed);
}

AXIAM_TEST("login parses org_slug on the user object") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200,
                             R"({"session_id":"s","expires_in":900,"user":{"id":"u",)"
                             R"("username":"a","email":"a@x","tenant_id":"t","org_slug":"globex"}})");
    };
    Client c = make_client(st);
    LoginResult res = c.login("a", "b");
    AXIAM_REQUIRE(res.user.has_value());
    AXIAM_REQUIRE(res.user->org_slug.has_value());
    AXIAM_CHECK(*res.user->org_slug == "globex");
}

AXIAM_TEST("unexpected HTTP status (302) maps to NetworkError") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(302, "{}"); };
    Client c = make_client(st);
    AXIAM_REQUIRE_THROWS_AS(c.check_access("a", "r"), NetworkError);
}

AXIAM_TEST("public refresh() drives a single refresh call and returns expiry") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"expires_in":900})");
    };
    Client c = make_client(st);
    TokenPair tp = c.refresh();
    AXIAM_CHECK(tp.expires_in == 900);
    AXIAM_CHECK(c.refresh_call_count() == 1);
}

AXIAM_TEST("401 -> refresh succeeds but retry still 401 -> AuthError (no loop)") {
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
            return json_response(200, R"({"expires_in":900})");  // refresh OK
        }
        return json_response(401, "{}");  // check still unauthenticated after refresh
    };
    Client c = make_client(st);
    c.login("a", "b");
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r"), AuthError);
    AXIAM_CHECK(c.refresh_call_count() == 1);
}

AXIAM_TEST("async login and batch_check futures resolve") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(200,
                                 R"({"session_id":"s","expires_in":900,)"
                                 R"("user":{"id":"u","username":"a","email":"a@x","tenant_id":"t"}})");
        }
        return json_response(200, R"({"results":[{"allowed":true}]})");
    };
    Client c = make_client(st);
    auto lf = c.login_async("a", "b");
    AXIAM_CHECK(lf.get().user.has_value());
    std::vector<AccessCheck> checks = {{"read", "r1", std::nullopt, std::nullopt}};
    auto bf = c.batch_check_async(checks);
    AXIAM_REQUIRE(bf.get().size() == 1);
}

AXIAM_TEST("refresh_async future resolves to a TokenPair") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"expires_in":123})");
    };
    Client c = make_client(st);
    auto f = c.refresh_async();
    AXIAM_CHECK(f.get().expires_in == 123);
}
