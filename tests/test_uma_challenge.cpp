// The §20.3 emit half, wired into the §11 require_access guard.
//
// Everything asserted here is about the DENY path, because that is the only
// path that mints anything:
//
//   1. A denial with a challenger mints exactly one ticket and carries it.
//   2. An allow mints nothing — a guard that minted on the happy path would put
//      a Protection API call in front of every authorized request.
//   3. A minting failure still denies, without a challenge. An outage must not
//      turn a deny into a 503, and must never turn it into an allow.
#include <memory>
#include <optional>
#include <string>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/guard.hpp"
#include "axiam/uma.hpp"
#include "fake_transport.hpp"

using namespace axiam;
using axtest::FakeState;

namespace {

const char* kResourceId = "44444444-4444-4444-4444-444444444444";
const char* kTicket = "ticket-value";

const char* kDiscovery = R"({
  "issuer":"https://iam.example.com",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "permission_endpoint":"https://iam.example.com/uma2/perm",
  "resource_registration_endpoint":"https://iam.example.com/uma2/rreg/resource_set",
  "permission_ticket_lifetime":60
})";

/// Counts what reached the Protection API, and what the check answered.
struct Scenario {
    bool allowed = false;
    long perm_status = 201;
    std::string perm_body = std::string("{\"ticket\":\"") + kTicket + "\"}";
    int perm_calls = 0;
    std::string last_perm_body;
};

Client make_client(std::shared_ptr<FakeState> st, std::shared_ptr<Scenario> s) {
    st->router = [s](const HttpRequest& req, FakeState&) {
        HttpResponse resp;
        resp.status = 404;
        resp.body = "{}";
        const std::string& url = req.url;

        if (url.find("uma2-configuration") != std::string::npos) {
            resp.status = 200;
            resp.body = kDiscovery;
        } else if (url.find("/uma2/perm") != std::string::npos) {
            s->perm_calls++;
            s->last_perm_body = req.body;
            resp.status = s->perm_status;
            resp.body = s->perm_body;
        } else if (url.find("/authz/check") != std::string::npos) {
            resp.status = 200;
            resp.body = s->allowed ? R"({"allowed":true})" : R"({"allowed":false})";
        }
        return resp;
    };
    return Client::builder()
        .base_url("https://iam.example.com")
        .tenant_slug("acme")
        .transport(axtest::make_fake(std::move(st)))
        .build();
}

std::optional<AxiamUser> caller() { return AxiamUser{"end-user-42", "acme", {"reader"}}; }

UmaChallenger challenger() {
    return UmaChallenger{"invoices", "https://id.example",
                         Sensitive<std::string>("pat-token-value")};
}

}  // namespace

AXIAM_TEST("a denial mints one ticket and carries the challenge") {
    auto st = std::make_shared<FakeState>();
    auto s = std::make_shared<Scenario>();
    auto client = make_client(st, s);

    bool threw = false;
    try {
        require_access(client, caller(), "invoices:read", kResourceId, challenger());
    } catch (const AuthzChallengeError& denial) {
        threw = true;
        AXIAM_CHECK(s->perm_calls == 1);  // one ticket, not two

        // The emitted header is the one this SDK's own parser consumes — the
        // round trip is the point of shipping both halves.
        auto parsed = uma_parse_challenge(denial.challenge());
        AXIAM_REQUIRE(parsed.has_value());
        AXIAM_CHECK(parsed->realm.value_or("") == "invoices");
        AXIAM_CHECK(parsed->as_uri.value_or("") == "https://id.example");
        AXIAM_REQUIRE(parsed->ticket.has_value());
        AXIAM_CHECK(axiam::detail::reveal(*parsed->ticket) == kTicket);

        // §20.6: the ticket must not be reachable through what(), which is what
        // ends up in a log line.
        AXIAM_CHECK(std::string(denial.what()).find(kTicket) == std::string::npos);
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("an adapter that knows nothing about UMA still catches the denial") {
    // AuthzChallengeError IS an AuthzError, so the addition can never turn a
    // denial into a different outcome for an existing handler.
    auto st = std::make_shared<FakeState>();
    auto s = std::make_shared<Scenario>();
    auto client = make_client(st, s);

    AXIAM_REQUIRE_THROWS_AS(
        require_access(client, caller(), "invoices:read", kResourceId, challenger()),
        AuthzError);
}

AXIAM_TEST("the ticket asks for the action that was refused") {
    auto st = std::make_shared<FakeState>();
    auto s = std::make_shared<Scenario>();
    auto client = make_client(st, s);

    try {
        require_access(client, caller(), "invoices:approve", kResourceId, challenger());
    } catch (const AuthzError&) {
    }

    // §20.2: the UMA scope is the AXIAM *action*. Asking for anything else would
    // mint a ticket for authority other than the one just refused — and would
    // step outside the grants the engine evaluated, deny rules included.
    AXIAM_CHECK(s->last_perm_body.find(std::string("\"resource_id\":\"") + kResourceId + "\"")
                != std::string::npos);
    AXIAM_CHECK(s->last_perm_body.find("\"invoices:approve\"") != std::string::npos);
}

AXIAM_TEST("an allow mints nothing") {
    auto st = std::make_shared<FakeState>();
    auto s = std::make_shared<Scenario>();
    s->allowed = true;
    auto client = make_client(st, s);

    AXIAM_REQUIRE_NOTHROW(
        require_access(client, caller(), "invoices:read", kResourceId, challenger()));
    // Minting on the happy path would put a Protection API call — and a live
    // credential — in front of every authorized request.
    AXIAM_CHECK(s->perm_calls == 0);
}

AXIAM_TEST("a minting failure still denies, and denies with the original error") {
    auto st = std::make_shared<FakeState>();
    auto s = std::make_shared<Scenario>();
    s->perm_status = 500;
    s->perm_body = R"({"error":"server_error"})";
    auto client = make_client(st, s);

    bool threw = false;
    try {
        require_access(client, caller(), "invoices:read", kResourceId, challenger());
    } catch (const AuthzChallengeError&) {
        AXIAM_CHECK(false && "a failed mint must not produce a challenge");
    } catch (const AuthzError&) {
        // Failure is not escalation: the caller was going to be refused, and a
        // Protection API outage must not turn that into a 503 (a NetworkError
        // escaping here) — nor, far worse, into an allow.
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(s->perm_calls >= 1);
}

AXIAM_TEST("without a challenger a denial mints nothing") {
    auto st = std::make_shared<FakeState>();
    auto s = std::make_shared<Scenario>();
    auto client = make_client(st, s);

    // Opt-in means opt-in: the existing overload is untouched, so an application
    // that never asked for UMA semantics gets no Protection API traffic.
    AXIAM_REQUIRE_THROWS_AS(require_access(client, caller(), "invoices:read", kResourceId),
                            AuthzError);
    AXIAM_CHECK(s->perm_calls == 0);
}

AXIAM_TEST("an unauthenticated request mints nothing") {
    // Only a resource denial is answerable with a ticket: an unauthenticated
    // request has no subject to mint for, and offering one would be inventing an
    // answer the engine never gave.
    auto st = std::make_shared<FakeState>();
    auto s = std::make_shared<Scenario>();
    auto client = make_client(st, s);

    std::optional<AxiamUser> none;
    AXIAM_REQUIRE_THROWS_AS(
        require_access(client, none, "invoices:read", kResourceId, challenger()), AuthError);
    AXIAM_CHECK(s->perm_calls == 0);
}
