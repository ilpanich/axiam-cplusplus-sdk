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

// §11.5's other arm. The guard has two catch clauses and they must NOT collapse
// into one: a NetworkError is translated to `authz_unavailable` (fail closed on
// something the server never decided), while an AuthzError the server actually
// returned is rethrown UNCHANGED. Rewriting the server's 403 into
// `authz_unavailable` would tell an operator their authorization service is
// down when it is up and deliberately saying no — and it would hide a real
// policy denial behind a transient-looking code that callers retry.
AXIAM_TEST("require_access rethrows a server AuthzError unchanged, not as authz_unavailable") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        // §2 maps 403 to AuthzError, with the server's detail attached.
        return json_response(403, R"({"action":"read","resource":"res-1"})");
    };
    Client c = guard_client(st);
    std::optional<AxiamUser> u = AxiamUser{"u-1", "t-1", {}};
    try {
        require_access(c, u, "read", "res-1");
        AXIAM_REQUIRE(false);
    } catch (const AuthzError& e) {
        // The fail-closed branch's marker must be absent: this denial came from
        // the server, and the distinction is the whole point of the two arms.
        AXIAM_REQUIRE(std::string(e.what()).find("authz_unavailable") == std::string::npos);
    }
}
