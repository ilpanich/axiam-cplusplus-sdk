// UMA 2.0 — CONTRACT.md §20.7 required assertions.
//
// Most of §20 is a list of things an SDK must NOT helpfully do, so most of these
// tests assert an absence. The centrepiece is §20.2 rule 6: a permission ticket
// is never retried.
//
// That rule is the one documented exception to §16, and the only way to assert
// it is to count requests. A ticket is consumed BEFORE the exchange is
// evaluated, so a failed exchange has already spent it — and under concurrency a
// retry is precisely the concurrent redemption a server whose storage engine
// this SDK cannot attest may admit twice (ilpanich/axiam#302). "Exactly one
// request" is a security assertion here, not a performance one.

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"

namespace {

const char* kPat = "pat-token-value";
const char* kTicket = "ticket-value";
const char* kClaimToken = "claim-token-value";
const char* kRpt = "rpt-token-value";
const char* kResourceId = "99999999-8888-7777-6666-555555555555";
const char* kTenantUuid = "22222222-2222-2222-2222-222222222222";

const char* kDiscovery = R"({
  "issuer":"https://iam.example.com",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "introspection_endpoint":"https://iam.example.com/oauth2/introspect",
  "permission_endpoint":"https://iam.example.com/uma2/perm",
  "resource_registration_endpoint":"https://iam.example.com/uma2/rreg/resource_set",
  "jwks_uri":"https://iam.example.com/.well-known/jwks.json",
  "grant_types_supported":["urn:ietf:params:oauth:grant-type:uma-ticket"],
  "uma_profiles_supported":[],
  "permission_ticket_lifetime":60
})";

/// Per-endpoint canned replies. A `status` of 0 means the request never
/// completed — the transport-failure case §20.2 rule 6 names explicitly.
struct Replies {
    long rreg_status = 200;
    std::string rreg_body = "{}";
    long perm_status = 201;
    std::string perm_body = "{}";
    long token_status = 200;
    std::string token_body = "{}";
};

axiam::Transport routed(std::shared_ptr<axtest::FakeState> st, std::shared_ptr<Replies> r) {
    st->router = [r](const axiam::HttpRequest& req, axtest::FakeState&) -> axiam::HttpResponse {
        const std::string& url = req.url;
        auto reply = [](long status, const std::string& body) {
            axiam::HttpResponse resp;
            if (status == 0) {
                resp.transport_error = "connection refused";
                return resp;
            }
            resp.status = status;
            resp.body = body;
            return resp;
        };
        if (url.find("uma2-configuration") != std::string::npos) return reply(200, kDiscovery);
        if (url.find("/oauth2/token") != std::string::npos) {
            return reply(r->token_status, r->token_body);
        }
        if (url.find("/uma2/perm") != std::string::npos) {
            return reply(r->perm_status, r->perm_body);
        }
        if (url.find("/uma2/rreg/resource_set") != std::string::npos) {
            return reply(r->rreg_status, r->rreg_body);
        }
        return reply(404, "{}");
    };
    return axtest::make_fake(std::move(st));
}

axiam::Client make_client(std::shared_ptr<axtest::FakeState> st, std::shared_ptr<Replies> r,
                          bool with_tenant_uuid = true) {
    auto builder = axiam::Client::builder()
                       .base_url("https://iam.example.com")
                       .tenant_slug("acme")
                       .transport(routed(std::move(st), std::move(r)));
    if (with_tenant_uuid) builder.tenant_id(kTenantUuid);
    return builder.build();
}

axiam::UmaClientCredentials credentials() {
    return {"orders-resource-server", axiam::Sensitive<std::string>("resource-server-secret")};
}

axiam::UmaExchangeTicketParams exchange_params() {
    axiam::UmaExchangeTicketParams p;
    p.ticket = axiam::Sensitive<std::string>(kTicket);
    p.claim_token = axiam::Sensitive<std::string>(kClaimToken);
    p.credentials = credentials();
    return p;
}

std::string form_value(const std::string& form, const std::string& key) {
    const std::string needle = key + "=";
    std::size_t at = 0;
    while (at < form.size()) {
        const std::size_t amp = form.find('&', at);
        const std::string part = form.substr(at, amp == std::string::npos ? std::string::npos : amp - at);
        if (part.rfind(needle, 0) == 0) return part.substr(needle.size());
        if (amp == std::string::npos) break;
        at = amp + 1;
    }
    return {};
}

}  // namespace

// ---------------------------------------------------------------------------
// §20.1 the Protection API
// ---------------------------------------------------------------------------

AXIAM_TEST("uma: registration round-trips and the id is usable as a ticket resource id") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->rreg_status = 201;
    r->rreg_body =
        R"({"_id":"99999999-8888-7777-6666-555555555555","name":"invoice-7","type":"document","resource_scopes":["view"]})";
    r->perm_body = R"({"ticket":"ticket-value"})";
    auto client = make_client(st, r);

    const auto registered = client.uma_register_resource(axiam::Sensitive<std::string>(kPat),
                                                         "invoice-7", "document", {"view"});
    AXIAM_REQUIRE(registered.id.has_value());
    AXIAM_REQUIRE(*registered.id == kResourceId);
    AXIAM_REQUIRE(registered.resource_scopes.size() == 1);

    // §20.1: `_id` IS the AXIAM resource id, not a parallel identifier — it goes
    // straight back out as a requested permission with no translation step.
    const auto ticket = client.uma_request_ticket(axiam::Sensitive<std::string>(kPat),
                                                  {{*registered.id, {"view"}}});
    AXIAM_REQUIRE(axiam::detail::reveal(ticket) == kTicket);
    AXIAM_REQUIRE(st->last().body.find(kResourceId) != std::string::npos);
}

AXIAM_TEST("uma: an omitted type is left out rather than sent empty") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->rreg_status = 201;
    r->rreg_body = R"({"_id":"99999999-8888-7777-6666-555555555555","name":"invoice-7"})";
    auto client = make_client(st, r);

    client.uma_register_resource(axiam::Sensitive<std::string>(kPat), "invoice-7", std::nullopt,
                                 {"view"});

    // §12.1: an absent optional field is omitted, never sent empty — here so the
    // server applies its own `uma_resource` default rather than storing "".
    AXIAM_REQUIRE(st->last().body.find("\"type\"") == std::string::npos);
}

AXIAM_TEST("uma: an update sends exactly the scopes given, with no read first") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->rreg_body =
        R"({"_id":"99999999-8888-7777-6666-555555555555","name":"invoice-7","type":"document","resource_scopes":["view"]})";
    auto client = make_client(st, r);

    const auto updated = client.uma_update_resource(axiam::Sensitive<std::string>(kPat),
                                                    kResourceId, "invoice-7", "document", {"view"});

    // §20.2 rule 8: the update replaces the scope list. A read-modify-write
    // would show up here as a second rreg call, and would silently make removing
    // a scope impossible through the SDK.
    AXIAM_REQUIRE(st->count_path("/uma2/rreg/resource_set") == 1);
    AXIAM_REQUIRE(st->last().method == "PUT");
    AXIAM_REQUIRE(st->last().body.find(R"("resource_scopes":["view"])") != std::string::npos);
    AXIAM_REQUIRE(updated.resource_scopes.size() == 1);
}

AXIAM_TEST("uma: an undeclared scope surfaces the 400 unchanged") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->perm_status = 400;
    r->perm_body = R"({"message":"scope not declared on resource"})";
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(
        client.uma_request_ticket(axiam::Sensitive<std::string>(kPat), {{kResourceId, {"delete"}}}),
        axiam::NetworkError);
    AXIAM_REQUIRE(st->count_path("/uma2/perm") == 1);
}

AXIAM_TEST("uma: a token that is not a PAT surfaces the server's 403") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->perm_status = 403;
    r->perm_body =
        R"({"error":"authorization_denied","message":"the protection API requires the 'uma_protection' scope"})";
    auto client = make_client(st, r);

    // §20.2 rule 1: a user access token is not a PAT. The SDK does not pre-judge
    // the token's subject kind — it lets the server's refusal through as the §2
    // mapping for a 403, rather than an OAuth2 protocol error (those rows belong
    // to the token endpoint, §20.4).
    AXIAM_REQUIRE_THROWS_AS(client.uma_request_ticket(axiam::Sensitive<std::string>("a-user-token"),
                                                      {{kResourceId, {"view"}}}),
                            axiam::AuthzError);
}

AXIAM_TEST("uma: the Protection API carries the PAT and no session credential") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->rreg_body = R"(["99999999-8888-7777-6666-555555555555"])";
    auto client = make_client(st, r);

    const auto ids = client.uma_list_resources(axiam::Sensitive<std::string>(kPat));
    AXIAM_REQUIRE(ids.size() == 1);
    AXIAM_REQUIRE(ids[0] == kResourceId);

    // §20.2 rule 1: a minted ticket is bound to the client_id that minted it, so
    // the Protection API credential is the caller's explicit PAT.
    const auto headers = st->last().headers;
    AXIAM_REQUIRE(headers.at("Authorization") == std::string("Bearer ") + kPat);
}

AXIAM_TEST("uma: an empty PAT is refused client-side with no wire call") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    // An omitted PAT must not become a request with an empty bearer, nor one
    // carrying whatever credential is lying around.
    AXIAM_REQUIRE_THROWS_AS(client.uma_delete_resource(axiam::Sensitive<std::string>(""), kResourceId),
                            axiam::AuthError);
    AXIAM_REQUIRE(st->count_path("/uma2/rreg/resource_set") == 0);
}

AXIAM_TEST("uma: read and delete use their own methods and paths") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->rreg_body =
        R"({"_id":"99999999-8888-7777-6666-555555555555","name":"invoice-7","type":"document","resource_scopes":["view","edit"]})";
    auto client = make_client(st, r);

    const auto resource = client.uma_read_resource(axiam::Sensitive<std::string>(kPat), kResourceId);
    // §20.6: scopes and the resource id are NOT sensitive and must stay readable
    // — an application cannot act on a resource it may not inspect.
    AXIAM_REQUIRE(resource.resource_scopes.size() == 2);
    AXIAM_REQUIRE(st->last().method == "GET");
    AXIAM_REQUIRE(st->last().url.find(kResourceId) != std::string::npos);

    r->rreg_status = 204;
    r->rreg_body = "";
    client.uma_delete_resource(axiam::Sensitive<std::string>(kPat), kResourceId);
    AXIAM_REQUIRE(st->last().method == "DELETE");
}

AXIAM_TEST("uma: discovery is fetched once and cached") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->rreg_body = "[]";
    auto client = make_client(st, r);

    client.uma_list_resources(axiam::Sensitive<std::string>(kPat));
    client.uma_list_resources(axiam::Sensitive<std::string>(kPat));

    // An endpoint map is not a credential; re-fetching it on every guarded
    // request is a self-inflicted round trip.
    AXIAM_REQUIRE(st->count_path("uma2-configuration") == 1);
}

AXIAM_TEST("uma: an incomplete discovery document is refused") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    st->router = [](const axiam::HttpRequest&, axtest::FakeState&) {
        return axtest::json_response(200, R"({"issuer":"https://iam.example.com"})");
    };
    auto client = axiam::Client::builder()
                      .base_url("https://iam.example.com")
                      .tenant_slug("acme")
                      .tenant_id(kTenantUuid)
                      .transport(axtest::make_fake(st))
                      .build();

    // Endpoints are read from the document, never hardcoded — so a document
    // missing one does not become a request aimed at a guessed path.
    AXIAM_REQUIRE_THROWS_AS(client.uma_discover(), axiam::NetworkError);
}

// ---------------------------------------------------------------------------
// §20.2 rule 6 — the ticket grant is never retried
// ---------------------------------------------------------------------------

AXIAM_TEST("uma: the ticket grant is not retried on a 5xx") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->token_status = 500;
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.uma_exchange_ticket(exchange_params()), axiam::NetworkError);
    // Retrying a spent ticket is the concurrent redemption ilpanich/axiam#302
    // describes.
    AXIAM_REQUIRE(st->count_path("/oauth2/token") == 1);
}

AXIAM_TEST("uma: the ticket grant is not retried on a transport failure") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->token_status = 0;  // the request never completed
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.uma_exchange_ticket(exchange_params()), axiam::NetworkError);
    // §20.2 rule 6 names the timeout explicitly: a request that never answered
    // may well have reached the server and spent the ticket. Silence is not
    // evidence it did not.
    AXIAM_REQUIRE(st->count_path("/oauth2/token") == 1);
}

AXIAM_TEST("uma: the ticket grant is not retried on invalid_grant") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->token_status = 400;
    r->token_body = R"({"error":"invalid_grant","error_description":"already used"})";
    auto client = make_client(st, r);

    bool seen = false;
    try {
        client.uma_exchange_ticket(exchange_params());
    } catch (const axiam::OAuthProtocolError& e) {
        // §20.4: unknown, expired, already-used and wrong-client all collapse
        // into this one code, and the SDK must not re-derive which — the server
        // withheld the distinction because it lets a caller probe for live
        // ticket handles.
        AXIAM_REQUIRE(e.error_code() == "invalid_grant");
        seen = true;
    }
    AXIAM_REQUIRE(seen);
    AXIAM_REQUIRE(st->count_path("/oauth2/token") == 1);
}

AXIAM_TEST("uma: a 403 access_denied is surfaced as itself and not auto-narrowed") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->token_status = 403;
    r->token_body =
        R"({"error":"access_denied","error_description":"not authorized for every requested permission"})";
    auto client = make_client(st, r);

    bool seen = false;
    try {
        client.uma_exchange_ticket(exchange_params());
    } catch (const axiam::OAuthProtocolError& e) {
        // §20.4: access_denied answers HTTP 403 here where RFC 8628's answers
        // 400. Dispatching on the `error` field rather than the status is what
        // keeps this correct — the plain §2 mapping would have produced an
        // AuthzError with no code to read.
        AXIAM_REQUIRE(e.error_code() == "access_denied");
        seen = true;
    }
    AXIAM_REQUIRE(seen);
    // §20.2 rule 3: a partial grant is refused whole. Whether two-of-three
    // permissions is useful is the application's judgement, not this SDK's.
    AXIAM_REQUIRE(st->count_path("/oauth2/token") == 1);
}

AXIAM_TEST("uma: an OAuthProtocolError is still an AuthError") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->token_status = 401;
    r->token_body = R"({"error":"invalid_client"})";
    auto client = make_client(st, r);

    // The contract models the protocol error as a SUB-TYPE of the authentication
    // error precisely so a caller that only knows about the §2 taxonomy still
    // catches it.
    AXIAM_REQUIRE_THROWS_AS(client.uma_exchange_ticket(exchange_params()), axiam::AuthError);
}

AXIAM_TEST("uma: a non-OAuth2 error body still gets the status mapping") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->token_status = 502;
    r->token_body = "<html>gateway</html>";
    auto client = make_client(st, r);

    // The widened `error`-field dispatch must not turn a proxy's HTML 502 into a
    // protocol error with an empty code.
    bool protocol_error = false;
    try {
        client.uma_exchange_ticket(exchange_params());
    } catch (const axiam::OAuthProtocolError&) {
        protocol_error = true;
    } catch (const axiam::NetworkError&) {
    }
    AXIAM_REQUIRE_FALSE(protocol_error);
}

// ---------------------------------------------------------------------------
// §20.1/§20.2 — what the grant sends, and what the result is not
// ---------------------------------------------------------------------------

AXIAM_TEST("uma: the ticket grant sends the required claim_token and its format") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->token_body = R"({"access_token":"rpt-token-value","token_type":"Bearer","expires_in":300})";
    auto client = make_client(st, r);

    const auto rpt = client.uma_exchange_ticket(exchange_params());

    // Bound once: st->last() returns by value, so calling it twice would compare
    // iterators from two different containers.
    const auto sent = st->last();
    const auto form = sent.body;
    AXIAM_REQUIRE(form_value(form, "grant_type") ==
                  "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Auma-ticket");
    AXIAM_REQUIRE(form_value(form, "ticket") == kTicket);
    // §20.2 rule 2: required, never defaulted — it is the only channel that
    // names the requesting party, and defaulting it to the resource server's own
    // PAT would mint an RPT for the resource server instead of the user.
    AXIAM_REQUIRE(form_value(form, "claim_token") == kClaimToken);
    AXIAM_REQUIRE(!form_value(form, "claim_token_format").empty());
    // A token-endpoint grant: the client authenticates through the body, and the
    // request carries no Authorization header.
    AXIAM_REQUIRE(form_value(form, "client_secret") == "resource-server-secret");
    AXIAM_REQUIRE(sent.headers.count("Authorization") == 0);
    // §12.1 note 2, which §20.1 applies to this grant unchanged.
    AXIAM_REQUIRE(sent.url.find(std::string("tenant_id=") + kTenantUuid) != std::string::npos);

    AXIAM_REQUIRE(axiam::detail::reveal(rpt.access_token) == kRpt);
    AXIAM_REQUIRE(rpt.expires_in == 300);
}

AXIAM_TEST("uma: an absent ticket or claim_token is refused client-side with no wire call") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    auto no_claim = exchange_params();
    no_claim.claim_token = axiam::Sensitive<std::string>("");
    AXIAM_REQUIRE_THROWS_AS(client.uma_exchange_ticket(no_claim), axiam::AuthError);

    auto no_ticket = exchange_params();
    no_ticket.ticket = axiam::Sensitive<std::string>("");
    AXIAM_REQUIRE_THROWS_AS(client.uma_exchange_ticket(no_ticket), axiam::AuthError);

    auto no_secret = exchange_params();
    no_secret.credentials.client_secret = axiam::Sensitive<std::string>("");
    AXIAM_REQUIRE_THROWS_AS(client.uma_exchange_ticket(no_secret), axiam::AuthError);

    // Refusing client-side keeps the ticket unspent for a request that could not
    // have succeeded (§20.2 rules 2 and 6 together).
    AXIAM_REQUIRE(st->count_path("/oauth2/token") == 0);
}

AXIAM_TEST("uma: a tenant slug cannot be substituted for the tenant UUID") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r, /*with_tenant_uuid=*/false);

    // §12.3 rule 4: the query parameter is a UUID and a slug is not one. Failing
    // here rather than on the wire is what keeps the ticket unspent.
    AXIAM_REQUIRE_THROWS_AS(client.uma_exchange_ticket(exchange_params()), axiam::AuthError);
    AXIAM_REQUIRE(st->count_path("/oauth2/token") == 0);
}

AXIAM_TEST("uma: a server-sent refresh token is not surfaced") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    // Deliberately hostile fixture: the grant issues no refresh token, so the
    // result type has no member for one and there is nothing to synthesise.
    r->token_body =
        R"({"access_token":"rpt-token-value","token_type":"Bearer","expires_in":300,"refresh_token":"should-not-exist"})";
    auto client = make_client(st, r);

    const auto rpt = client.uma_exchange_ticket(exchange_params());
    AXIAM_REQUIRE(rpt.token_type == "Bearer");
    // The struct has exactly three members; a fourth would change its size.
    AXIAM_REQUIRE(sizeof(axiam::RequestingPartyToken) ==
                  sizeof(axiam::Sensitive<std::string>) + sizeof(std::string) + sizeof(long));
}

AXIAM_TEST("uma: a malformed token response is refused") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->token_body = R"({"token_type":"Bearer"})";
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.uma_exchange_ticket(exchange_params()), axiam::NetworkError);
}

// ---------------------------------------------------------------------------
// §20.3 the challenge helpers
// ---------------------------------------------------------------------------

AXIAM_TEST("uma: parses a well-formed challenge") {
    const auto challenge = axiam::uma_parse_challenge(
        R"(UMA realm="example", as_uri="https://id.example", ticket="ticket-value")");

    AXIAM_REQUIRE(challenge.has_value());
    AXIAM_REQUIRE(challenge->realm.value_or("") == "example");
    AXIAM_REQUIRE(challenge->as_uri.value_or("") == "https://id.example");
    AXIAM_REQUIRE(challenge->ticket.has_value());
    AXIAM_REQUIRE(axiam::detail::reveal(*challenge->ticket) == kTicket);
}

AXIAM_TEST("uma: rejects a scheme that merely starts with UMA") {
    AXIAM_REQUIRE_FALSE(axiam::uma_parse_challenge(R"(Bearer realm="example")").has_value());
    AXIAM_REQUIRE_FALSE(axiam::uma_parse_challenge(R"(UMAX realm="example")").has_value());
    // "UMA" alone is a valid, if useless, challenge: the scheme is present and
    // simply names no parameters.
    AXIAM_REQUIRE(axiam::uma_parse_challenge("UMA").has_value());
}

AXIAM_TEST("uma: parsing performs no exchange") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto challenge = axiam::uma_parse_challenge(
        R"(UMA realm="example", as_uri="https://iam.example.com", ticket="ticket-value")");

    AXIAM_REQUIRE(challenge.has_value());
    // §20.3: the as_uri names an authorization server this client has not chosen
    // to trust. Auto-exchanging would send the requesting party's claim_token to
    // whatever host answered the 401.
    AXIAM_REQUIRE(st->count() == 0);
}

AXIAM_TEST("uma: an unknown challenge parameter is ignored, not rejected") {
    // UMA 2.0 permits a server to add its own parameters, and refusing the whole
    // challenge over one would lose the ticket with it.
    const auto challenge = axiam::uma_parse_challenge(
        R"(UMA realm="example", unknown="x", ticket="ticket-value")");

    AXIAM_REQUIRE(challenge.has_value());
    AXIAM_REQUIRE(challenge->ticket.has_value());
    AXIAM_REQUIRE(axiam::detail::reveal(*challenge->ticket) == kTicket);
}

AXIAM_TEST("uma: the challenge round-trips through the emit half") {
    const auto header = axiam::uma_challenge_header("example", "https://id.example",
                                                    axiam::Sensitive<std::string>(kTicket));
    const auto challenge = axiam::uma_parse_challenge(header);

    AXIAM_REQUIRE(challenge.has_value());
    AXIAM_REQUIRE(challenge->as_uri.value_or("") == "https://id.example");
    AXIAM_REQUIRE(axiam::detail::reveal(*challenge->ticket) == kTicket);
}

// ---------------------------------------------------------------------------
// §20.6 redaction
// ---------------------------------------------------------------------------

AXIAM_TEST("uma: no ticket or RPT renders through any display path") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->perm_body = R"({"ticket":"ticket-value"})";
    r->token_body = R"({"access_token":"rpt-token-value","token_type":"Bearer","expires_in":300})";
    auto client = make_client(st, r);

    const auto ticket =
        client.uma_request_ticket(axiam::Sensitive<std::string>(kPat), {{kResourceId, {"view"}}});
    const auto rpt = client.uma_exchange_ticket(exchange_params());
    const auto challenge = axiam::uma_parse_challenge(R"(UMA ticket="ticket-value")");

    // §20.6: the ticket's 60-second lifetime is exactly what invites treating it
    // as harmless. For those 60 seconds it is the credential that converts into
    // an RPT.
    std::ostringstream os;
    os << ticket << rpt.access_token << *challenge->ticket;
    AXIAM_REQUIRE(os.str().find(kTicket) == std::string::npos);
    AXIAM_REQUIRE(os.str().find(kRpt) == std::string::npos);
    AXIAM_REQUIRE(ticket.to_string() == "[SENSITIVE]");
    AXIAM_REQUIRE(rpt.access_token.to_string() == "[SENSITIVE]");
}

AXIAM_TEST("uma: a failed exchange never echoes the ticket or claim token") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->token_status = 400;
    // The server's description contains the ticket — the case where a naive
    // implementation copies free text into its own message.
    r->token_body = R"({"error":"invalid_grant","error_description":"ticket-value is spent"})";
    auto client = make_client(st, r);

    bool seen = false;
    try {
        client.uma_exchange_ticket(exchange_params());
    } catch (const axiam::OAuthProtocolError& e) {
        const std::string message = e.what();
        AXIAM_REQUIRE(message.find(kTicket) == std::string::npos);
        AXIAM_REQUIRE(message.find(kClaimToken) == std::string::npos);
        // The description is surfaced deliberately and separately, so a caller
        // that wants it opts in rather than finding it in a log line.
        AXIAM_REQUIRE(e.error_description().has_value());
        seen = true;
    }
    AXIAM_REQUIRE(seen);
}
