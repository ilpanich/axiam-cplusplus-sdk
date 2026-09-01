// CONTRACT.md §12.1 — the four public login-provider operations added at
// contract 1.37, with rule 12a as it stands at 1.38: sso_providers(),
// sso_start_oauth2(), sso_complete_oauth2() and sso_complete_handoff().
//
// The assertions are about WHAT WENT ON THE WIRE and HOW MANY TIMES, for the
// same reason the rest of the §12 suite is: every rule these operations carry
// is a claim about requests. Note 9 is "the empty list is the success" — a
// claim that the call REACHED the wire and came back 200, not that a helper
// returned an empty vector. Note 12 is "a failed redemption is never retried" —
// a count. Rule 12a is "a 400 is a configuration error, distinct from the 401"
// — a mapping, asserted against both statuses so it cannot quietly collapse.

#include <memory>
#include <string>
#include <vector>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"

namespace {

const char* kTenantUuid = "22222222-2222-2222-2222-222222222222";
const char* kOrgUuid = "33333333-3333-3333-3333-333333333333";
const char* kConfigId = "44444444-4444-4444-4444-444444444444";
const char* kRedirectUri = "https://app.test/callback";

const char* kProvidersTwo = R"({"providers":[
  {"id":"11111111-1111-1111-1111-111111111111","provider_kind":"google",
   "display_name":"Google","protocol":"OidcConnect","has_bundled_mark":true,
   "button_icon":null,"inherited":true},
  {"id":"22222222-2222-2222-2222-222222222222","provider_kind":"generic_oauth2",
   "display_name":"Acme SSO","protocol":"OAuth2","has_bundled_mark":false,
   "button_icon":"data:image/png;base64,iVBORw0KGgo=","inherited":false}]})";

// The third entry's provider_kind is DELIBERATELY "google" while its protocol
// is Saml: an SDK that dispatched on the kind would send it to sso_start, which
// the server refuses with 400 (§12.1 note 10).
const char* kProvidersThreeProtocols = R"({"providers":[
  {"id":"aaaa","provider_kind":"google","display_name":"G",
   "protocol":"OidcConnect","has_bundled_mark":true,"inherited":false},
  {"id":"bbbb","provider_kind":"github","display_name":"GH",
   "protocol":"OAuth2","has_bundled_mark":true,"inherited":false},
  {"id":"cccc","provider_kind":"google","display_name":"GW",
   "protocol":"Saml","has_bundled_mark":true,"inherited":false}]})";

const char* kOauth2StartOk =
    R"({"authorize_url":"https://github.com/login/oauth/authorize?state=s",
        "state":"the-state","expires_in_secs":300})";

const char* kSessionOk =
    R"({"user_id":"66666666-6666-6666-6666-666666666666",
        "session_id":"77777777-7777-7777-7777-777777777777",
        "expires_in":3600,"redirect_uri":"https://app.test/dashboard"})";

/// Per-endpoint canned answers and call counters — the assertions here are
/// counts, so each of the four endpoints gets its own.
struct Replies {
    long providers_status = 200;
    std::string providers_body = R"({"providers":[]})";
    std::size_t providers_calls = 0;

    long start_status = 200;
    std::string start_body = "{}";
    std::size_t start_calls = 0;

    long callback_status = 200;
    std::string callback_body = "{}";
    std::size_t callback_calls = 0;

    long handoff_status = 200;
    std::string handoff_body = "{}";
    std::size_t handoff_calls = 0;
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
        if (url.find("/federation/providers") != std::string::npos) {
            ++r->providers_calls;
            return reply(r->providers_status, r->providers_body);
        }
        if (url.find("/federation/oauth2/start") != std::string::npos) {
            ++r->start_calls;
            return reply(r->start_status, r->start_body);
        }
        if (url.find("/federation/oauth2/callback") != std::string::npos) {
            ++r->callback_calls;
            return reply(r->callback_status, r->callback_body);
        }
        if (url.find("/federation/handoff") != std::string::npos) {
            ++r->handoff_calls;
            return reply(r->handoff_status, r->handoff_body);
        }
        return reply(404, "{}");
    };
    return axtest::make_fake(std::move(st));
}

struct Fixture {
    std::shared_ptr<axtest::FakeState> st = std::make_shared<axtest::FakeState>();
    std::shared_ptr<Replies> replies = std::make_shared<Replies>();
};

/// A client whose workspace is configured the way a real login page's would be.
axiam::Client make_client(Fixture& f, bool tenant_uuid = true, const char* org_id = nullptr,
                          const char* org_slug = "acme") {
    auto builder = axiam::Client::builder()
                       .base_url("https://iam.example.com")
                       .tenant_slug("acme")
                       .transport(routed(f.st, f.replies));
    if (tenant_uuid) builder.tenant_id(kTenantUuid);
    if (org_id != nullptr) builder.org_id(org_id);
    if (org_slug != nullptr) builder.org_slug(org_slug);
    return builder.build();
}

std::string last_url(axtest::FakeState& st, const std::string& needle) {
    std::lock_guard<std::mutex> lock(st.mtx);
    for (auto it = st.requests.rbegin(); it != st.requests.rend(); ++it) {
        if (it->url.find(needle) != std::string::npos) return it->url;
    }
    return {};
}

axtest::RecordedReq last_request(axtest::FakeState& st, const std::string& needle) {
    std::lock_guard<std::mutex> lock(st.mtx);
    for (auto it = st.requests.rbegin(); it != st.requests.rend(); ++it) {
        if (it->url.find(needle) != std::string::npos) return *it;
    }
    return {};
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

// ---------------------------------------------------------------------------
// sso_providers — the wire shape
// ---------------------------------------------------------------------------

AXIAM_TEST("§12.1 sso_providers is a GET carrying the identifiers as query parameters") {
    Fixture f;
    f.replies->providers_body = kProvidersTwo;
    auto client = make_client(f);
    const auto providers = client.sso_providers();

    const auto req = last_request(*f.st, "/federation/providers");
    AXIAM_REQUIRE(req.method == "GET");
    // No body, and therefore no Content-Type: this is the one GET in §12.
    AXIAM_REQUIRE(req.body.empty());
    AXIAM_REQUIRE(req.headers.find("Content-Type") == req.headers.end());
    // The identifiers are QUERY parameters, not a body.
    AXIAM_REQUIRE(contains(req.url, "org_slug=acme"));
    AXIAM_REQUIRE(contains(req.url, std::string("tenant_id=") + kTenantUuid));
    AXIAM_REQUIRE(providers.size() == 2);
}

AXIAM_TEST("§5.1 sso_providers prefers the UUID form over the slug form") {
    Fixture f;
    auto client = make_client(f, /*tenant_uuid=*/true, kOrgUuid, /*org_slug=*/nullptr);
    (void)client.sso_providers();

    const auto url = last_url(*f.st, "/federation/providers");
    AXIAM_REQUIRE(contains(url, std::string("org_id=") + kOrgUuid));
    AXIAM_REQUIRE_FALSE(contains(url, "org_slug"));
    AXIAM_REQUIRE(contains(url, std::string("tenant_id=") + kTenantUuid));
    AXIAM_REQUIRE_FALSE(contains(url, "tenant_slug"));
}

AXIAM_TEST("§12.1 sso_providers arguments override the configured workspace") {
    Fixture f;
    auto client = make_client(f, /*tenant_uuid=*/false, nullptr, "acme");
    // A login page resolves the org from what the user typed, not from how the
    // client was built.
    (void)client.sso_providers(std::nullopt, std::string("typed by the user"),
                               std::nullopt, std::string("engineering"));

    const auto url = last_url(*f.st, "/federation/providers");
    // And the value is percent-encoded rather than pasted in raw.
    AXIAM_REQUIRE(contains(url, "org_slug=typed%20by%20the%20user"));
    AXIAM_REQUIRE(contains(url, "tenant_slug=engineering"));
    AXIAM_REQUIRE_FALSE(contains(url, "acme"));
}

AXIAM_TEST("§12.1 sso_providers decodes every field including the nullable button_icon") {
    Fixture f;
    f.replies->providers_body = kProvidersTwo;
    auto client = make_client(f);
    const auto p = client.sso_providers();
    AXIAM_REQUIRE(p.size() == 2);

    AXIAM_REQUIRE(p[0].id == "11111111-1111-1111-1111-111111111111");
    AXIAM_REQUIRE(p[0].provider_kind == "google");
    AXIAM_REQUIRE(p[0].display_name == "Google");
    AXIAM_REQUIRE(p[0].protocol == axiam::kFederationProtocolOidcConnect);
    AXIAM_REQUIRE(p[0].has_bundled_mark);
    AXIAM_REQUIRE_FALSE(p[0].button_icon.has_value());  // absent for most providers
    AXIAM_REQUIRE(p[0].inherited);                      // note 13, resolved server-side

    AXIAM_REQUIRE(p[1].protocol == axiam::kFederationProtocolOAuth2);
    AXIAM_REQUIRE_FALSE(p[1].has_bundled_mark);
    AXIAM_REQUIRE(p[1].button_icon.has_value());
    AXIAM_REQUIRE(*p[1].button_icon == "data:image/png;base64,iVBORw0KGgo=");
    AXIAM_REQUIRE_FALSE(p[1].inherited);
}

AXIAM_TEST("§12.1 note 10 an unknown protocol does not fail the parse of the whole list") {
    Fixture f;
    f.replies->providers_body = R"({"providers":[
      {"id":"a","provider_kind":"google","display_name":"G","protocol":"OidcConnect",
       "has_bundled_mark":true,"inherited":false},
      {"id":"b","provider_kind":"future_kind","display_name":"L","protocol":"SomethingNewer",
       "has_bundled_mark":false,"inherited":false}]})";
    auto client = make_client(f);
    const auto p = client.sso_providers();
    // `protocol` is the wire string, not an enum, precisely so this holds.
    AXIAM_REQUIRE(p.size() == 2);
    AXIAM_REQUIRE(p[1].protocol == "SomethingNewer");
}

AXIAM_TEST("§12.1 an entry that could not start a login is dropped, not fatal") {
    Fixture f;
    f.replies->providers_body = R"({"providers":[
      {"provider_kind":"google","display_name":"no id","protocol":"OidcConnect"},
      {"id":"b","provider_kind":"github","display_name":"no protocol"},
      7,
      {"id":"c","provider_kind":"github","display_name":"GH","protocol":"OAuth2",
       "has_bundled_mark":true,"inherited":false}]})";
    auto client = make_client(f);
    const auto p = client.sso_providers();
    // The buttons that ARE usable must still render.
    AXIAM_REQUIRE(p.size() == 1);
    AXIAM_REQUIRE(p[0].id == "c");
}

// ---------------------------------------------------------------------------
// §12.1 note 9 — the empty list is a success, and the only success
// ---------------------------------------------------------------------------

AXIAM_TEST("§12.1 note 9 an unknown organization answers an empty list, not an error") {
    Fixture f;
    auto client = make_client(f, /*tenant_uuid=*/true, nullptr, "no-such-org");
    std::vector<axiam::FederationProvider> p;
    AXIAM_REQUIRE_NOTHROW(p = client.sso_providers());
    AXIAM_REQUIRE(p.empty());
    AXIAM_REQUIRE(f.replies->providers_calls == 1);
}

AXIAM_TEST("§12.1 note 9 a known organization with no providers answers the same way") {
    Fixture f;
    auto client = make_client(f);
    std::vector<axiam::FederationProvider> p;
    AXIAM_REQUIRE_NOTHROW(p = client.sso_providers());
    AXIAM_REQUIRE(p.empty());
}

AXIAM_TEST("§12.1 note 9 naming no organization at all still reaches the wire and succeeds") {
    // The arm an SDK is most tempted to get wrong: a request naming no
    // organization is still a request, still reaches the wire, and still
    // answers 200 with an empty list. A client-side refusal would restore
    // exactly the two-valued organization-slug oracle note 9 removes.
    Fixture f;
    auto client = make_client(f, /*tenant_uuid=*/true, nullptr, /*org_slug=*/nullptr);
    std::vector<axiam::FederationProvider> p;
    AXIAM_REQUIRE_NOTHROW(p = client.sso_providers());
    AXIAM_REQUIRE(p.empty());
    AXIAM_REQUIRE(f.replies->providers_calls == 1);

    // Nothing is invented for an organization the caller did not name.
    const auto url = last_url(*f.st, "/federation/providers");
    AXIAM_REQUIRE_FALSE(contains(url, "org_"));
}

AXIAM_TEST("§12.1 note 9 makes the empty list a success, not every answer") {
    Fixture f;
    f.replies->providers_status = 503;
    auto client = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(client.sso_providers(), axiam::NetworkError);

    Fixture g;
    g.replies->providers_body = R"({"providers":"not-a-list"})";
    auto c2 = make_client(g);
    AXIAM_REQUIRE_THROWS_AS(c2.sso_providers(), axiam::NetworkError);

    Fixture h;
    h.replies->providers_status = 0;  // transport failure, no HTTP response
    auto c3 = make_client(h);
    AXIAM_REQUIRE_THROWS_AS(c3.sso_providers(), axiam::NetworkError);
}

// ---------------------------------------------------------------------------
// §12.1 note 10 — `protocol` selects the start operation
// ---------------------------------------------------------------------------

AXIAM_TEST("§12.1 note 10 protocol selects the start operation and provider_kind never does") {
    Fixture f;
    f.replies->providers_body = kProvidersThreeProtocols;
    auto client = make_client(f);
    const auto p = client.sso_providers();
    AXIAM_REQUIRE(p.size() == 3);

    // The dispatch a login page performs, written out so all three arms run.
    std::vector<std::string> routed_to;
    for (const auto& provider : p) {
        if (provider.protocol == axiam::kFederationProtocolOidcConnect)
            routed_to.emplace_back("sso_start");
        else if (provider.protocol == axiam::kFederationProtocolOAuth2)
            routed_to.emplace_back("sso_start_oauth2");
        else if (provider.protocol == axiam::kFederationProtocolSaml)
            routed_to.emplace_back("saml_login");
        else
            routed_to.emplace_back("unsupported");
    }
    AXIAM_REQUIRE(routed_to[0] == "sso_start");
    AXIAM_REQUIRE(routed_to[1] == "sso_start_oauth2");
    AXIAM_REQUIRE(routed_to[2] == "saml_login");

    // The third entry's KIND is "google"; only its protocol says SAML.
    AXIAM_REQUIRE(p[2].provider_kind == "google");
    AXIAM_REQUIRE(p[2].protocol == axiam::kFederationProtocolSaml);
}

AXIAM_TEST("§12.1 the protocol and handoff constants are the contract values") {
    AXIAM_REQUIRE(std::string(axiam::kFederationProtocolOidcConnect) == "OidcConnect");
    AXIAM_REQUIRE(std::string(axiam::kFederationProtocolOAuth2) == "OAuth2");
    AXIAM_REQUIRE(std::string(axiam::kFederationProtocolSaml) == "Saml");
    AXIAM_REQUIRE(std::string(axiam::kHandoffQueryParam) == "axiam_handoff");
    AXIAM_REQUIRE(axiam::kHandoffCodeTtlSeconds == 60);
}

// ---------------------------------------------------------------------------
// sso_start_oauth2
// ---------------------------------------------------------------------------

AXIAM_TEST("§12.1 sso_start_oauth2 posts JSON to its own path and carries no PKCE") {
    Fixture f;
    f.replies->start_body = kOauth2StartOk;
    auto client = make_client(f);
    const auto r = client.sso_start_oauth2(kConfigId, kRedirectUri);
    AXIAM_REQUIRE(r.state == "the-state");
    AXIAM_REQUIRE(r.expires_in_secs == 300);
    AXIAM_REQUIRE(contains(r.authorize_url, "https://github.com/"));

    const auto req = last_request(*f.st, "/federation/oauth2/start");
    AXIAM_REQUIRE(req.method == "POST");
    AXIAM_REQUIRE(req.headers.at("Content-Type") == "application/json");
    AXIAM_REQUIRE(contains(req.body, std::string("\"federation_config_id\":\"") + kConfigId));
    AXIAM_REQUIRE(contains(req.body, std::string("\"redirect_uri\":\"") + kRedirectUri));
    // §5.1: the workspace is in the BODY here, unlike sso_providers.
    AXIAM_REQUIRE(contains(req.body, std::string("\"tenant_id\":\"") + kTenantUuid));
    AXIAM_REQUIRE(contains(req.body, "\"org_slug\":\"acme\""));
    // §12.1 note 11: PKCE is generated and held server-side. Nothing is sent.
    AXIAM_REQUIRE_FALSE(contains(req.body, "code_verifier"));
    AXIAM_REQUIRE_FALSE(contains(req.body, "code_challenge"));
    // §12.1 note 8: unauthenticated, so no CSRF header is invented.
    AXIAM_REQUIRE(req.headers.find("X-CSRF-Token") == req.headers.end());
}

AXIAM_TEST("§12.1 rule 12a a 400 is the configuration error and is not retried") {
    // A 400 means the deployment does not accept this redirect_uri's ORIGIN.
    // §2 puts that on the NetworkError row — the taxonomy's
    // configuration/programming-error member — and it is not retried.
    Fixture f;
    f.replies->start_status = 400;
    f.replies->start_body = R"({"error":"redirect_uri origin is not permitted"})";
    auto client = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(client.sso_start_oauth2(kConfigId, "https://attacker.test/cb"),
                            axiam::NetworkError);
    AXIAM_REQUIRE(f.replies->start_calls == 1);

    // The companion, so rule 12a's distinction cannot collapse into "any
    // federation failure": a 401 is an AuthError, not a configuration error.
    Fixture g;
    g.replies->start_status = 401;
    auto c2 = make_client(g);
    AXIAM_REQUIRE_THROWS_AS(c2.sso_start_oauth2(kConfigId, kRedirectUri), axiam::AuthError);
    AXIAM_REQUIRE(g.replies->start_calls == 1);
}

AXIAM_TEST("§12.1 sso_start_oauth2 refuses a malformed OAuth2StartResponse") {
    Fixture f;
    f.replies->start_body = R"({"state":"s"})";
    auto client = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(client.sso_start_oauth2(kConfigId, kRedirectUri),
                            axiam::NetworkError);

    Fixture g;
    g.replies->start_body = "not json at all";
    auto c2 = make_client(g);
    AXIAM_REQUIRE_THROWS_AS(c2.sso_start_oauth2(kConfigId, kRedirectUri), axiam::NetworkError);
}

AXIAM_TEST("§5.1 sso_start_oauth2 sends the slug forms when that is what the client has") {
    Fixture f;
    f.replies->start_body = kOauth2StartOk;
    auto client = make_client(f, /*tenant_uuid=*/false, nullptr, "acme");
    (void)client.sso_start_oauth2(kConfigId, kRedirectUri);
    const auto req = last_request(*f.st, "/federation/oauth2/start");
    AXIAM_REQUIRE(contains(req.body, "\"tenant_slug\":\"acme\""));
    AXIAM_REQUIRE(contains(req.body, "\"org_slug\":\"acme\""));

    Fixture g;
    g.replies->start_body = kOauth2StartOk;
    auto c2 = make_client(g, /*tenant_uuid=*/true, kOrgUuid, /*org_slug=*/nullptr);
    (void)c2.sso_start_oauth2(kConfigId, kRedirectUri);
    const auto req2 = last_request(*g.st, "/federation/oauth2/start");
    AXIAM_REQUIRE(contains(req2.body, std::string("\"org_id\":\"") + kOrgUuid));
    AXIAM_REQUIRE_FALSE(contains(req2.body, "org_slug"));
}

// ---------------------------------------------------------------------------
// sso_complete_oauth2
// ---------------------------------------------------------------------------

AXIAM_TEST("§12.1 sso_complete_oauth2 posts state and code and returns no token material") {
    Fixture f;
    f.replies->callback_body = kSessionOk;
    auto client = make_client(f);
    const auto r = client.sso_complete_oauth2("the-code", "the-state");
    AXIAM_REQUIRE(r.user_id == "66666666-6666-6666-6666-666666666666");
    AXIAM_REQUIRE(r.session_id == "77777777-7777-7777-7777-777777777777");
    AXIAM_REQUIRE(r.expires_in == 3600);
    AXIAM_REQUIRE(r.redirect_uri.has_value());
    AXIAM_REQUIRE(*r.redirect_uri == "https://app.test/dashboard");

    const auto req = last_request(*f.st, "/federation/oauth2/callback");
    AXIAM_REQUIRE(req.method == "POST");
    AXIAM_REQUIRE(req.headers.at("Content-Type") == "application/json");
    AXIAM_REQUIRE(contains(req.body, "\"state\":\"the-state\""));
    AXIAM_REQUIRE(contains(req.body, "\"code\":\"the-code\""));
    // §12.1 note 6: SsoCompleteResult has nowhere to put token material, which
    // is the assertion — the session is a Set-Cookie the §4 jar keeps.
}

AXIAM_TEST("§12.1 sso_complete_oauth2 maps a 401 to an AuthError and refuses a partial body") {
    Fixture f;
    f.replies->callback_status = 401;
    auto client = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(client.sso_complete_oauth2("c", "s"), axiam::AuthError);
    AXIAM_REQUIRE(f.replies->callback_calls == 1);

    Fixture g;
    g.replies->callback_body = R"({"user_id":"u"})";
    auto c2 = make_client(g);
    AXIAM_REQUIRE_THROWS_AS(c2.sso_complete_oauth2("c", "s"), axiam::NetworkError);
}

// ---------------------------------------------------------------------------
// sso_complete_handoff — §12.1 note 12
// ---------------------------------------------------------------------------

AXIAM_TEST("§12.1 sso_complete_handoff posts only the code") {
    Fixture f;
    f.replies->handoff_body = kSessionOk;
    auto client = make_client(f);
    const auto r = client.sso_complete_handoff("the-handoff-code");
    AXIAM_REQUIRE(r.session_id == "77777777-7777-7777-7777-777777777777");

    const auto req = last_request(*f.st, "/federation/handoff");
    AXIAM_REQUIRE(req.method == "POST");
    AXIAM_REQUIRE(contains(req.body, "\"code\":\"the-handoff-code\""));
    // The code is the whole request: no state, no workspace.
    AXIAM_REQUIRE_FALSE(contains(req.body, "state"));
    AXIAM_REQUIRE_FALSE(contains(req.body, "tenant"));
}

AXIAM_TEST("§12.1 note 12 a handoff 401 is terminal and the redemption is never retried") {
    // Unknown, expired and already-redeemed all answer the same 401,
    // deliberately, and the code is gone either way.
    Fixture f;
    f.replies->handoff_status = 401;
    auto client = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(client.sso_complete_handoff("spent-code"), axiam::AuthError);
    AXIAM_REQUIRE(f.replies->handoff_calls == 1);
}

AXIAM_TEST("§12.1 sso_complete_handoff surfaces transport and body failures as NetworkError") {
    Fixture f;
    f.replies->handoff_status = 0;  // transport failure, no HTTP response
    auto client = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(client.sso_complete_handoff("code"), axiam::NetworkError);

    Fixture g;
    g.replies->handoff_body = R"({"session_id":"s"})";
    auto c2 = make_client(g);
    AXIAM_REQUIRE_THROWS_AS(c2.sso_complete_handoff("code"), axiam::NetworkError);
}

// ---------------------------------------------------------------------------
// §12.3 cross-cutting rules
// ---------------------------------------------------------------------------

AXIAM_TEST("§18.1 rule 4 all four login-provider operations refuse on a closed client") {
    Fixture f;
    auto client = make_client(f);
    client.close();

    AXIAM_REQUIRE_THROWS_AS(client.sso_providers(), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.sso_start_oauth2(kConfigId, kRedirectUri),
                            axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.sso_complete_oauth2("c", "s"), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.sso_complete_handoff("c"), axiam::NetworkError);
    // Nothing reached the wire.
    AXIAM_REQUIRE(f.st->count() == 0);
}

AXIAM_TEST("§12.3 rule 1 the provider listing is not cached") {
    // Two calls are two requests, so a workspace switch can never be answered
    // from a stale list.
    Fixture f;
    auto client = make_client(f);
    (void)client.sso_providers();
    (void)client.sso_providers();
    AXIAM_REQUIRE(f.replies->providers_calls == 2);
}
