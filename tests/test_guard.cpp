#include <memory>
#include <optional>
#include <string>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/guard.hpp"
#include "fake_transport.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::json_response;

static Client guard_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://api.example.test")
        .tenant_slug("acme")
        .transport(axtest::make_fake(st))
        .build();
}

AXIAM_TEST("require_auth throws AuthError when unauthenticated (401)") {
    std::optional<AxiamUser> none;
    AXIAM_REQUIRE_THROWS_AS(require_auth(none), AuthError);
}

AXIAM_TEST("require_auth returns user when present") {
    std::optional<AxiamUser> u = AxiamUser{"u-1", "t-1", {"admin"}};
    AXIAM_REQUIRE_NOTHROW(require_auth(u));
    AXIAM_CHECK(require_auth(u).user_id == "u-1");
}

AXIAM_TEST("require_role passes with a matching role, fails otherwise (403)") {
    std::optional<AxiamUser> u = AxiamUser{"u-1", "t-1", {"editor"}};
    AXIAM_REQUIRE_NOTHROW(require_role(u, {"editor", "admin"}));
    AXIAM_REQUIRE_THROWS_AS(require_role(u, {"admin"}), AuthzError);
}

AXIAM_TEST("require_role on unauthenticated user is AuthError (401)") {
    std::optional<AxiamUser> none;
    AXIAM_REQUIRE_THROWS_AS(require_role(none, {"admin"}), AuthError);
}

AXIAM_TEST("require_role fails closed for an identity whose roles claim was absent") {
    AxiamUser absent{"u-1", "t-1", {"admin"}};
    absent.roles_claim_present = false;  // what TokenAuthenticator sets for an absent claim
    std::optional<AxiamUser> u = absent;
    AXIAM_REQUIRE_THROWS_AS(require_role(u, {"admin"}), AuthzError);
}

AXIAM_TEST("require_scope: 401 unauthenticated, 403 on a miss, pass on a whole-entry match") {
    std::optional<AxiamUser> none;
    AXIAM_REQUIRE_THROWS_AS(require_scope(none, {"admin"}), AuthError);

    AxiamUser with_scope{"u-1", "t-1", {}};
    with_scope.scope = "openid admin";
    std::optional<AxiamUser> u = with_scope;
    AXIAM_REQUIRE_NOTHROW(require_scope(u, {"admin"}));
    AXIAM_REQUIRE_NOTHROW(require_scope(u, {"missing", "openid"}));
    AXIAM_REQUIRE_THROWS_AS(require_scope(u, {"adm"}), AuthzError);

    // `roles` never stands in for `scope`.
    std::optional<AxiamUser> roles_only = AxiamUser{"u-1", "t-1", {"admin"}};
    AXIAM_REQUIRE_THROWS_AS(require_scope(roles_only, {"admin"}), AuthzError);
}

AXIAM_TEST("require_access propagates subject_id = authenticated user and allows") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) {
        // §11.2 subject propagation: the end user's id, not the SDK session.
        AXIAM_CHECK(req.body.find("\"subject_id\":\"end-user-42\"") != std::string::npos);
        return json_response(200, R"({"allowed":true})");
    };
    Client c = guard_client(st);
    std::optional<AxiamUser> u = AxiamUser{"end-user-42", "t-1", {}};
    AXIAM_REQUIRE_NOTHROW(require_access(c, u, "read", "res-1"));
}

AXIAM_TEST("require_access denies (allowed=false) -> AuthzError (403)") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(200, R"({"allowed":false})"); };
    Client c = guard_client(st);
    std::optional<AxiamUser> u = AxiamUser{"u-1", "t-1", {}};
    AXIAM_REQUIRE_THROWS_AS(require_access(c, u, "read", "res-1"), AuthzError);
}

AXIAM_TEST("require_access unauthenticated -> AuthError (401)") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(200, R"({"allowed":true})"); };
    Client c = guard_client(st);
    std::optional<AxiamUser> none;
    AXIAM_REQUIRE_THROWS_AS(require_access(c, none, "read", "res-1"), AuthError);
}

AXIAM_TEST("require_access empty resource id -> invalid_argument (400)") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(200, R"({"allowed":true})"); };
    Client c = guard_client(st);
    std::optional<AxiamUser> u = AxiamUser{"u-1", "t-1", {}};
    AXIAM_REQUIRE_THROWS_AS(require_access(c, u, "read", ""), std::invalid_argument);
}

AXIAM_TEST("require_access fails closed on NetworkError -> AuthzError (§11.5)") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        HttpResponse r;
        r.transport_error = "connection refused";
        return r;
    };
    Client c = guard_client(st);
    std::optional<AxiamUser> u = AxiamUser{"u-1", "t-1", {}};
    AXIAM_REQUIRE_THROWS_AS(require_access(c, u, "read", "res-1"), AuthzError);
}

AXIAM_TEST("AXIAM_REQUIRE_ACCESS macro composes over the guard") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(200, R"({"allowed":true})"); };
    Client c = guard_client(st);
    std::optional<AxiamUser> u = AxiamUser{"u-1", "t-1", {}};
    AXIAM_REQUIRE_NOTHROW(AXIAM_REQUIRE_ACCESS(c, u, "read", "res-1"));
}

AXIAM_TEST("resolver overload resolves resource id from a request object") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) {
        AXIAM_CHECK(req.body.find("\"resource_id\":\"from-resolver\"") != std::string::npos);
        return json_response(200, R"({"allowed":true})");
    };
    Client c = guard_client(st);
    std::optional<AxiamUser> u = AxiamUser{"u-1", "t-1", {}};
    struct Req { std::string id; };
    Req request{"from-resolver"};
    std::function<std::string(const Req&)> resolver = [](const Req& r) { return r.id; };
    AXIAM_REQUIRE_NOTHROW(require_access<Req>(c, u, "read", resolver, request));
}

AXIAM_TEST("AxiamGuard functor yields user or throws") {
    AxiamGuard<std::string> guard(
        [](const std::string& token) -> std::optional<AxiamUser> {
            if (token == "good") return AxiamUser{"u-1", "t-1", {"admin"}};
            return std::nullopt;
        });
    AXIAM_CHECK(guard(std::string("good")).user_id == "u-1");
    AXIAM_REQUIRE_THROWS_AS(guard(std::string("bad")), AuthError);
}
