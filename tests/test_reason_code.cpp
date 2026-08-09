// Decision reason codes — CONTRACT.md §11 rule 9 (B1 deny-override).
//
// The rule exists because the two refusals mean opposite things to the person
// on the other end: `no_grant` says *ask an admin for access*, `denied_by_rule`
// says *an admin has already decided*. An application that cannot tell them
// apart sends users to raise tickets that will be refused.
//
// The second half of the file asserts the other side of the clause: reporting
// changed, enforcement did not.

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/guard.hpp"
#include "axiam/types.hpp"
#include "fake_transport.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::json_response;

namespace {

Client make_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://api.example.test")
        .tenant_slug("acme")
        .transport(axtest::make_fake(st))
        .build();
}

/// Run one check against a canned response body and return the decision.
AccessDecision check_with(const std::string& body) {
    auto st = std::make_shared<FakeState>();
    st->router = [body](const HttpRequest&, FakeState&) { return json_response(200, body); };
    Client c = make_client(st);
    return c.check_access("read", "res-7");
}

}  // namespace

// ---------------------------------------------------------------------------
// check_access
// ---------------------------------------------------------------------------

AXIAM_TEST("an allow carries the `allowed` reason code") {
    AccessDecision d = check_with(R"({"allowed":true,"reason_code":"allowed"})");
    AXIAM_CHECK(d.allowed);
    AXIAM_REQUIRE(d.reason_code.has_value());
    AXIAM_CHECK(*d.reason_code == ReasonCode::kAllowed);
}

AXIAM_TEST("no_grant and denied_by_rule are not collapsed into a bare false") {
    AccessDecision no_grant = check_with(R"({"allowed":false,"reason_code":"no_grant"})");
    AccessDecision by_rule = check_with(R"({"allowed":false,"reason_code":"denied_by_rule"})");

    // Both are refusals…
    AXIAM_CHECK_FALSE(no_grant.allowed);
    AXIAM_CHECK_FALSE(by_rule.allowed);
    // …and the SDK must not reduce them to that shared `false`.
    AXIAM_REQUIRE(no_grant.reason_code.has_value());
    AXIAM_REQUIRE(by_rule.reason_code.has_value());
    AXIAM_CHECK(*no_grant.reason_code == ReasonCode::kNoGrant);
    AXIAM_CHECK(*by_rule.reason_code == ReasonCode::kDeniedByRule);
    AXIAM_CHECK(*no_grant.reason_code != *by_rule.reason_code);
}

AXIAM_TEST("an unrecognised reason code is surfaced verbatim and changes nothing") {
    // This is what lets the server add a fourth code without breaking every
    // deployed SDK: the outcome is carried by `allowed` alone.
    AccessDecision denied =
        check_with(R"({"allowed":false,"reason_code":"denied_by_some_future_thing"})");
    AXIAM_CHECK_FALSE(denied.allowed);
    AXIAM_REQUIRE(denied.reason_code.has_value());
    AXIAM_CHECK(*denied.reason_code == "denied_by_some_future_thing");

    // And it must not flip an allow either.
    AccessDecision allowed =
        check_with(R"({"allowed":true,"reason_code":"something-unrecognised"})");
    AXIAM_CHECK(allowed.allowed);
    AXIAM_CHECK(*allowed.reason_code == "something-unrecognised");
}

AXIAM_TEST("a server omitting reason_code reads as absent, not as an error") {
    AccessDecision denied = check_with(R"({"allowed":false})");
    AXIAM_CHECK_FALSE(denied.allowed);
    AXIAM_CHECK_FALSE(denied.reason_code.has_value());

    // A JSON null is the same thing as absent, not a decode failure.
    AccessDecision allowed =
        check_with(R"({"allowed":true,"reason":"role grants it","reason_code":null})");
    AXIAM_CHECK(allowed.allowed);
    AXIAM_CHECK_FALSE(allowed.reason_code.has_value());
    AXIAM_REQUIRE(allowed.reason.has_value());
    AXIAM_CHECK(*allowed.reason == "role grants it");
}

AXIAM_TEST("a non-string reason_code is ignored rather than throwing") {
    // A malformed field must not take down a decision the caller can otherwise
    // act on — `allowed` is still authoritative.
    AccessDecision d = check_with(R"({"allowed":false,"reason_code":42})");
    AXIAM_CHECK_FALSE(d.allowed);
    AXIAM_CHECK_FALSE(d.reason_code.has_value());
}

AXIAM_TEST("reason and reason_code are independent") {
    // `reason` is prose for a human, `reason_code` is for a branch in code.
    // Neither is derived from the other.
    AccessDecision d = check_with(
        R"({"allowed":false,"reason":"no grant on /docs/42","reason_code":"no_grant"})");
    AXIAM_REQUIRE(d.reason.has_value());
    AXIAM_REQUIRE(d.reason_code.has_value());
    AXIAM_CHECK(*d.reason == "no grant on /docs/42");
    AXIAM_CHECK(*d.reason_code == ReasonCode::kNoGrant);
}

AXIAM_TEST("can() surfaces the reason code too") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"allowed":false,"reason_code":"denied_by_rule"})");
    };
    Client c = make_client(st);
    AccessDecision d = c.can("write", "res-7");
    AXIAM_CHECK_FALSE(d.allowed);
    AXIAM_REQUIRE(d.reason_code.has_value());
    AXIAM_CHECK(*d.reason_code == ReasonCode::kDeniedByRule);
}

// ---------------------------------------------------------------------------
// batch_check
// ---------------------------------------------------------------------------

AXIAM_TEST("batch_check surfaces a reason code per decision, in order") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"results":[
            {"allowed":true,"reason_code":"allowed"},
            {"allowed":false,"reason_code":"no_grant"},
            {"allowed":false,"reason_code":"denied_by_rule"}]})");
    };
    Client c = make_client(st);
    std::vector<AccessCheck> checks = {
        {"read", "r1", std::nullopt, std::nullopt},
        {"write", "r1", std::nullopt, std::nullopt},
        {"delete", "r1", std::nullopt, std::nullopt},
    };

    auto results = c.batch_check(checks);

    AXIAM_REQUIRE(results.size() == 3);
    AXIAM_CHECK(*results[0].reason_code == ReasonCode::kAllowed);
    AXIAM_CHECK(*results[1].reason_code == ReasonCode::kNoGrant);
    AXIAM_CHECK(*results[2].reason_code == ReasonCode::kDeniedByRule);
}

AXIAM_TEST("batch_check tolerates a server that sends no reason codes") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"results":[{"allowed":true},{"allowed":false}]})");
    };
    Client c = make_client(st);
    std::vector<AccessCheck> checks = {
        {"read", "r1", std::nullopt, std::nullopt},
        {"write", "r2", std::nullopt, std::nullopt},
    };

    auto results = c.batch_check(checks);

    AXIAM_REQUIRE(results.size() == 2);
    AXIAM_CHECK_FALSE(results[0].reason_code.has_value());
    AXIAM_CHECK_FALSE(results[1].reason_code.has_value());
}

// ---------------------------------------------------------------------------
// Enforcement is unchanged (§11 rule 9)
// ---------------------------------------------------------------------------

AXIAM_TEST("require_access throws AuthzError for both refusals alike") {
    // "This clause is about *reporting*, not enforcement, and an SDK MUST NOT
    // vary its guard behaviour on reason_code." Both refusals stop the request
    // identically; only the reporting differs.
    for (const char* code : {ReasonCode::kNoGrant, ReasonCode::kDeniedByRule}) {
        auto st = std::make_shared<FakeState>();
        std::string body = std::string(R"({"allowed":false,"reason_code":")") + code + R"("})";
        st->router = [body](const HttpRequest&, FakeState&) { return json_response(200, body); };
        Client c = make_client(st);
        std::optional<AxiamUser> u = AxiamUser{"end-user-42", "t-1", {}};

        AXIAM_REQUIRE_THROWS_AS(require_access(c, u, "read", "res-1"), AuthzError);
    }
}

AXIAM_TEST("require_access still allows when the code is one it has never seen") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"allowed":true,"reason_code":"allowed_by_future_thing"})");
    };
    Client c = make_client(st);
    std::optional<AxiamUser> u = AxiamUser{"end-user-42", "t-1", {}};

    AXIAM_REQUIRE_NOTHROW(require_access(c, u, "read", "res-1"));
}
