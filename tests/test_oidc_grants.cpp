// CONTRACT.md §12.7 (logout), §14 (RFC 8628 device grant), §15 (RFC 8693 token
// exchange), and §12.1's §9-conformant single-flight for `oidc_refresh`.
//
// §14.2 is titled "the part implementations get wrong", and its four rules are
// all about the SHAPE OF THE POLLING LOOP rather than about parsing: whether
// `slow_down` sticks, where the initial interval comes from, whether the two
// refusals stay distinguishable, and whether the deadline is honoured. None of
// that is observable from a return value, so the assertions here read the
// recorded sleeps and count requests.
//
// §15 is a list of things an SDK must NOT helpfully do, so every one of its
// tests asserts an ABSENCE: no retry, no rewritten request, no auto-narrowed
// scope, no refresh token, no adopted session.
//
// §12.7's two halves sit on opposite sides of the flow. `logout_url` is a URL
// builder whose tests are about what it refuses to invent. `verify_logout_token`
// is the half carrying security weight: its input arrives unsolicited, from the
// network, and instructs the RP to terminate a session — so the two tests that
// matter most are the two an implementer is most likely to skip.

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"
#include "test_key.hpp"

namespace {

const char* kTenantUuid = "22222222-2222-2222-2222-222222222222";
const char* kClientId = "example-rp";
const char* kClientSecret = "example-secret";
const char* kIssuer = "https://issuer.test";

const char* kDiscovery = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "end_session_endpoint":"https://iam.example.com/oauth2/end_session",
  "device_authorization_endpoint":"https://iam.example.com/oauth2/device_authorization"
})";

struct Replies {
    std::vector<std::pair<long, std::string>> token_script;
    std::size_t token_calls = 0;
    std::size_t device_calls = 0;
    long device_status = 200;
    std::string device_body = "{}";
    std::string jwks_body = R"({"keys":[]})";
    // Widen the coalescing window for the §9 single-flight test, exactly as the
    // §9 cookie-refresh test does — without it the leader can finish before a
    // follower arrives and the test would pass for the wrong reason.
    std::chrono::milliseconds token_delay{0};
    std::mutex mtx;
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
        if (url.find("openid-configuration") != std::string::npos) return reply(200, kDiscovery);
        if (url.find("/oauth2/jwks") != std::string::npos) return reply(200, r->jwks_body);
        if (url.find("/oauth2/device_authorization") != std::string::npos) {
            std::lock_guard<std::mutex> lock(r->mtx);
            ++r->device_calls;
            return reply(r->device_status, r->device_body);
        }
        if (url.find("/oauth2/token") != std::string::npos) {
            std::size_t i;
            std::chrono::milliseconds delay;
            {
                std::lock_guard<std::mutex> lock(r->mtx);
                i = r->token_calls++;
                delay = r->token_delay;
            }
            if (delay.count() > 0) std::this_thread::sleep_for(delay);
            std::lock_guard<std::mutex> lock(r->mtx);
            if (r->token_script.empty()) return reply(200, "{}");
            const auto& answer = r->token_script[std::min(i, r->token_script.size() - 1)];
            return reply(answer.first, answer.second);
        }
        return reply(404, "{}");
    };
    return axtest::make_fake(std::move(st));
}

struct Fixture {
    std::shared_ptr<axtest::FakeState> st = std::make_shared<axtest::FakeState>();
    std::shared_ptr<Replies> replies = std::make_shared<Replies>();
    /// Recorded waits, so §14.2's intervals become assertable and a 600-second
    /// grant runs in microseconds.
    std::shared_ptr<std::vector<std::chrono::milliseconds>> sleeps =
        std::make_shared<std::vector<std::chrono::milliseconds>>();
};

axiam::Client make_client(Fixture& f, const char* secret = kClientSecret,
                          bool tenant_uuid = true) {
    auto builder = axiam::Client::builder()
                       .base_url("https://iam.example.com")
                       .tenant_slug("acme")
                       .oidc_client_id(kClientId)
                       .transport(routed(f.st, f.replies));
    if (tenant_uuid) builder.tenant_id(kTenantUuid);
    if (secret != nullptr) builder.oidc_client_secret(secret);
    auto client = builder.build();
    auto sleeps = f.sleeps;
    client._set_retry_test_seams([] { return 0.5; },
                                 [sleeps](std::chrono::milliseconds d) { sleeps->push_back(d); });
    return client;
}

axtest::RecordedReq last_request(axtest::FakeState& st, const std::string& needle) {
    std::lock_guard<std::mutex> lock(st.mtx);
    for (auto it = st.requests.rbegin(); it != st.requests.rend(); ++it) {
        if (it->url.find(needle) != std::string::npos) return *it;
    }
    return {};
}

bool body_has_field(axtest::FakeState& st, const std::string& needle, const std::string& field) {
    const auto req = last_request(st, needle);
    const std::string prefix = field + "=";
    if (req.body.rfind(prefix, 0) == 0) return true;
    return req.body.find("&" + prefix) != std::string::npos;
}

std::int64_t now() { return static_cast<std::int64_t>(std::time(nullptr)); }

std::string device_body(const std::string& interval_json, int expires) {
    return R"({"device_code":"the-device-code","user_code":"WDJB-MJHT",)"
           R"("verification_uri":"https://id.test/device","expires_in":)" +
           std::to_string(expires) + interval_json + "}";
}

const char* kSuccessTokens =
    R"({"access_token":"the-access-token","token_type":"Bearer","expires_in":900})";

}  // namespace

// ---------------------------------------------------------------------------
// §14.1 device_authorize
// ---------------------------------------------------------------------------

AXIAM_TEST("§14.1 device_authorize sends no secret, and works without one") {
    Fixture f;
    f.replies->device_body = device_body(R"(,"interval":3)", 600);
    // A PUBLIC client. §14.1 forbids refusing to call this from one, because a
    // device that cannot show a browser also cannot hold a secret.
    auto client = make_client(f, /*secret=*/nullptr);
    const auto a = client.device_authorize();

    AXIAM_REQUIRE(a.user_code == "WDJB-MJHT");
    AXIAM_REQUIRE(a.interval == 3);
    AXIAM_REQUIRE_FALSE(body_has_field(*f.st, "/oauth2/device_authorization", "client_secret"));
    AXIAM_REQUIRE(body_has_field(*f.st, "/oauth2/device_authorization", "client_id"));
    // §14.3: surfaced when present, and NOT concatenated when absent — its
    // format is the server's to choose.
    AXIAM_REQUIRE_FALSE(a.verification_uri_complete.has_value());
}

AXIAM_TEST("§14.1 device_authorize never sends a secret even when one is configured") {
    // The other half of the rule: "SDKs MUST NOT send client_secret on it". A
    // confidential client calling this must still not leak its secret to an
    // unauthenticated endpoint.
    Fixture f;
    f.replies->device_body = device_body(R"(,"interval":3)", 600);
    auto client = make_client(f);
    client.device_authorize();
    AXIAM_REQUIRE_FALSE(body_has_field(*f.st, "/oauth2/device_authorization", "client_secret"));
    AXIAM_REQUIRE(last_request(*f.st, "/oauth2/device_authorization").body.find(kClientSecret) ==
                  std::string::npos);
}

AXIAM_TEST("§14.2 rule 2 an omitted interval defaults to five seconds") {
    // The initial interval comes from the RESPONSE, and RFC 8628 §3.2's default
    // is 5 s. No SDK may hard-code a faster floor.
    Fixture f;
    f.replies->device_body = device_body("", 600);
    auto client = make_client(f);
    AXIAM_REQUIRE(client.device_authorize().interval == axiam::kDeviceDefaultIntervalSeconds);
}

// ---------------------------------------------------------------------------
// §14.2 polling
// ---------------------------------------------------------------------------

AXIAM_TEST("§14.2 rule 3 the two refusals stay distinct") {
    // `access_denied` means a human said no; `expired_token` means nobody
    // answered. Collapsing them loses the only information the device can act on
    // — retry versus stop asking.
    for (const char* code : {"access_denied", "expired_token", "invalid_grant"}) {
        Fixture f;
        f.replies->token_script = {{400, std::string(R"({"error":")") + code + "\"}"}};
        auto client = make_client(f);
        try {
            client.device_poll(axiam::Sensitive<std::string>("dc"));
            AXIAM_REQUIRE(false);
        } catch (const axiam::OAuthProtocolError& e) {
            // §14.2 rule 5: all five arrive as 400, which §2 would map to a
            // generic error. Dispatch is on the `error` field, and it survives.
            AXIAM_REQUIRE(e.error_code() == code);
        }
    }
}

AXIAM_TEST("§14.3 rule 2 device_login surfaces the codes before the first poll") {
    Fixture f;
    f.replies->device_body = device_body(R"(,"interval":1)", 600);
    f.replies->token_script = {{400, R"({"error":"authorization_pending"})"},
                               {200, kSuccessTokens}};
    auto client = make_client(f);

    std::string seen_code;
    std::size_t polls_when_called = 999;
    int display_calls = 0;
    const auto set = client.device_login([&](const axiam::DeviceAuthorization& a) {
        ++display_calls;
        seen_code = a.user_code;
        std::lock_guard<std::mutex> lock(f.replies->mtx);
        polls_when_called = f.replies->token_calls;
    });

    // Ordering, not just presence. A device must be able to display the codes,
    // and the SDK must not begin polling before the caller has had the chance.
    AXIAM_REQUIRE(display_calls == 1);
    AXIAM_REQUIRE(polls_when_called == 0);
    AXIAM_REQUIRE(seen_code == "WDJB-MJHT");
    // `authorization_pending` LOOPS rather than raising.
    AXIAM_REQUIRE(f.replies->token_calls == 2);
    AXIAM_REQUIRE(axiam::detail::reveal(set.access_token) == "the-access-token");
    // §14.3 rule 4: the token set is returned, NOT adopted.
    AXIAM_REQUIRE_FALSE(client.has_session());
}

AXIAM_TEST("§14.2 rule 1 slow_down raises the interval permanently") {
    // The interval starts at 1 s; the first poll is told to slow down, which
    // must take it to 6 s and KEEP it there. An SDK that backed off for one
    // round and returned to 1 s would show a 1000 ms third sleep here — and in
    // production would be told to slow down again, forever.
    Fixture f;
    f.replies->device_body = device_body(R"(,"interval":1)", 600);
    f.replies->token_script = {{400, R"({"error":"slow_down"})"},
                               {400, R"({"error":"authorization_pending"})"},
                               {200, kSuccessTokens}};
    auto client = make_client(f);
    client.device_login(nullptr);

    AXIAM_REQUIRE(f.sleeps->size() == 3);
    AXIAM_REQUIRE((*f.sleeps)[0] == std::chrono::milliseconds(1000));
    // +5 s, cumulative, applied to the CURRENT interval...
    AXIAM_REQUIRE((*f.sleeps)[1] == std::chrono::milliseconds(6000));
    // ...and it persists across the subsequent poll — never reset.
    AXIAM_REQUIRE((*f.sleeps)[2] == std::chrono::milliseconds(6000));
}

AXIAM_TEST("§14.2 rule 4 polling stops at expires_in even with no expired_token answer") {
    // The deadline is authoritative. This server never says `expired_token` — it
    // answers `authorization_pending` forever — and the loop must stop anyway,
    // because the extra requests are pure load.
    //
    // The recorded sleeps do not advance the real clock, so the deadline here is
    // wall-clock: a 0-second grant means the very first attempt already falls
    // outside it, which is the branch this asserts. The persistence of the
    // raised interval is covered above.
    Fixture f;
    f.replies->device_body = device_body(R"(,"interval":3)", 0);
    f.replies->token_script = {{400, R"({"error":"authorization_pending"})"}};
    auto client = make_client(f);
    try {
        client.device_login(nullptr);
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        // The SDK reports the grant's own expiry even though the server never
        // did.
        AXIAM_REQUIRE(e.error_code() == "expired_token");
    }
    // Not one poll: it is the NEXT ATTEMPT that must fall inside the deadline,
    // and it does not. A `now < deadline` check before sleeping would have let
    // this request through.
    AXIAM_REQUIRE(f.replies->token_calls == 0);
}

AXIAM_TEST("§14.2 rule 6 a 500 mid-poll is retried rather than treated as terminal") {
    // §16.2's one token-endpoint exception. A server restart mid-flow must not
    // lose a grant the user has already approved. The §16 budget is PER POLL
    // ATTEMPT: one poll that hits a 500 makes up to three requests and then the
    // loop continues — it does not consume the grant's own `expires_in` window.
    Fixture f;
    f.replies->device_body = device_body(R"(,"interval":1)", 600);
    f.replies->token_script = {{503, ""}, {503, ""}, {503, ""}, {200, kSuccessTokens}};
    auto client = make_client(f);
    client.device_login(nullptr);
    // Three attempts inside the first poll (§16.1's 1 + 2), then the loop's own
    // second poll succeeds. A terminal treatment would have stopped at one.
    AXIAM_REQUIRE(f.replies->token_calls == 4);
}

// ---------------------------------------------------------------------------
// §15 token exchange
// ---------------------------------------------------------------------------

namespace {

axiam::TokenExchangeParams exchange(const char* actor = nullptr,
                                    std::vector<std::string> scopes = {}) {
    axiam::TokenExchangeParams p;
    p.subject_token = axiam::Sensitive<std::string>("subject-token");
    if (actor != nullptr) p.actor_token = axiam::Sensitive<std::string>(actor);
    p.scopes = std::move(scopes);
    return p;
}

}  // namespace

AXIAM_TEST("§15.2 a delegation narrows scopes and reports what was granted") {
    Fixture f;
    f.replies->token_script = {
        {200,
         R"({"access_token":"narrow","issued_token_type":"urn:ietf:params:oauth:token-type:access_token",)"
         R"("token_type":"Bearer","expires_in":300,"scope":"invoices:read"})"}};
    auto client = make_client(f);
    const auto t = client.token_exchange(exchange("actor-token", {"invoices:read", "invoices:write"}));

    const auto req = last_request(*f.st, "/oauth2/token");
    AXIAM_REQUIRE(req.body.find("actor_token=") != std::string::npos);
    AXIAM_REQUIRE(req.body.find("actor_token_type=") != std::string::npos);
    AXIAM_REQUIRE(req.body.find("scope=invoices%3Aread%20invoices%3Awrite") != std::string::npos);
    // §15.2 rule 7: the response's scope is the GRANTED set, which may be
    // narrower than what was asked for even on success.
    AXIAM_REQUIRE(t.scope.value_or("") == "invoices:read");
    // Rule 6: surfaced, never dropped.
    AXIAM_REQUIRE(t.issued_token_type == axiam::kAccessTokenType);
}

AXIAM_TEST("§15.2 rule 1 omitting the actor token asks for impersonation") {
    Fixture f;
    f.replies->token_script = {
        {200,
         R"({"access_token":"inherited","token_type":"Bearer","expires_in":300,"scope":"a b"})"}};
    auto client = make_client(f);
    const auto t = client.token_exchange(exchange());

    // Omitted, not sent empty.
    AXIAM_REQUIRE_FALSE(body_has_field(*f.st, "/oauth2/token", "scope"));
    // The ABSENCE of an actor token is what selects impersonation. This SDK
    // supplies no default and never substitutes the client's own session — the
    // assertion is that nothing named `actor_token` went out.
    AXIAM_REQUIRE_FALSE(body_has_field(*f.st, "/oauth2/token", "actor_token"));
    AXIAM_REQUIRE(t.scope.value_or("") == "a b");
}

AXIAM_TEST("§15.2 rule 2 unauthorized_client is surfaced verbatim, with no retry or rewrite") {
    Fixture f;
    f.replies->token_script = {
        {400, R"({"error":"unauthorized_client","error_description":"impersonation not granted"})"}};
    auto client = make_client(f);
    try {
        client.token_exchange(exchange());
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        AXIAM_REQUIRE(e.error_code() == "unauthorized_client");
    }
    // It means either "this client may not exchange at all" or "this client may
    // not impersonate". Both are registration facts an operator must fix. An SDK
    // that retried, downgraded, or reworked the request into a delegation would
    // be sending a request the caller did not write — so: exactly one request,
    // and it still carries no actor_token.
    AXIAM_REQUIRE(f.replies->token_calls == 1);
    AXIAM_REQUIRE_FALSE(body_has_field(*f.st, "/oauth2/token", "actor_token"));
}

AXIAM_TEST("§15.2 rule 3 invalid_scope is not auto-narrowed and re-sent") {
    Fixture f;
    f.replies->token_script = {{400, R"({"error":"invalid_scope"})"}};
    auto client = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(client.token_exchange(exchange(nullptr, {"a", "b", "c"})),
                            axiam::OAuthProtocolError);
    // The server refuses rather than silently narrowing precisely so the caller
    // finds out here. One request — no second attempt with fewer scopes.
    AXIAM_REQUIRE(f.replies->token_calls == 1);
}

AXIAM_TEST("§15.3 a cross-tenant subject token answers invalid_grant, unrefined") {
    Fixture f;
    f.replies->token_script = {{400, R"({"error":"invalid_grant"})"}};
    auto client = make_client(f);
    try {
        client.token_exchange(exchange());
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        // The server collapses "wrong tenant" into "bad token" because telling
        // them apart is a tenant-enumeration signal. The SDK reports what it was
        // told and adds no guess — the message must not speculate about tenancy.
        AXIAM_REQUIRE(e.error_code() == "invalid_grant");
        AXIAM_REQUIRE(std::string(e.what()).find("tenant") == std::string::npos);
    }
}

AXIAM_TEST("§15.2 rules 4 and 5 the exchanged token carries no refresh token and is not adopted") {
    // The server sends a refresh_token it should not; there is nowhere to put
    // it, so it is dropped rather than synthesised into the result — an exchange
    // only ever narrows, and a refresh token would let the holder re-widen
    // later. And the client's own session is untouched: this is a MUST NOT where
    // adoption elsewhere is a MAY.
    Fixture f;
    f.replies->token_script = {
        {200,
         R"({"access_token":"narrow","token_type":"Bearer","expires_in":300,"refresh_token":"nope"})"}};
    auto client = make_client(f);
    const auto t = client.token_exchange(exchange());
    AXIAM_REQUIRE_FALSE(client.has_session());
    AXIAM_REQUIRE(client.refresh_call_count() == 0);
    AXIAM_REQUIRE(axiam::detail::reveal(t.access_token) == "narrow");
}

AXIAM_TEST("§15.1 token_exchange refuses a public client with no wire call") {
    Fixture f;
    auto client = make_client(f, /*secret=*/nullptr);
    AXIAM_REQUIRE_THROWS_AS(client.token_exchange(exchange()), axiam::AuthError);
    AXIAM_REQUIRE(f.st->count() == 0);
}

// ---------------------------------------------------------------------------
// §15.7 external-IdP subject tokens (X4)
//
// No new operation: the same token_exchange carries a partner IdP's token. What
// changes is which subject tokens the server accepts and what its refusals
// mean, so these tests are about not getting in the way of either.
// ---------------------------------------------------------------------------

namespace {

/// A token minted by a partner's IdP. Opaque to the SDK — deliberately not a
/// well-formed JWT, because nothing here may decode it.
constexpr const char* kExternalSubjectToken = "partner-idp-subject-token";

/// The one normative `error_description` (§15.7). It means "fix the AXIAM trust
/// configuration", not "fix your token".
constexpr const char* kIssuerNotConfigured =
    "the subject token's issuer is not configured for token exchange";

/// Percent-encoded as `Form::pct` emits them — every URN colon becomes %3A.
constexpr const char* kEncJwtType = "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt";
constexpr const char* kEncAccessType =
    "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token";

/// `exchange()`, plus the §15.7 subject_token_type and an explicit subject.
axiam::TokenExchangeParams external_exchange(const char* subject_token_type,
                                             const char* actor = nullptr,
                                             const char* subject = kExternalSubjectToken) {
    axiam::TokenExchangeParams p;
    p.subject_token = axiam::Sensitive<std::string>(subject);
    if (subject_token_type != nullptr) p.subject_token_type = std::string(subject_token_type);
    if (actor != nullptr) p.actor_token = axiam::Sensitive<std::string>(actor);
    return p;
}

}  // namespace

AXIAM_TEST("§15.7 an external subject_token_type is sent verbatim and the result surfaces unchanged") {
    Fixture f;
    f.replies->token_script = {
        {200,
         R"({"access_token":"narrow","issued_token_type":"urn:ietf:params:oauth:token-type:access_token",)"
         R"("token_type":"Bearer","expires_in":300,"scope":"read:orders"})"}};
    auto client = make_client(f);
    const auto t = client.token_exchange(external_exchange(axiam::kJwtTokenType));

    const auto req = last_request(*f.st, "/oauth2/token");
    // The caller named …:jwt, so …:jwt goes on the wire. §15.7: the SDK must not
    // inspect the subject token to pick this, and must not override it.
    AXIAM_REQUIRE(req.body.find(std::string("subject_token_type=") + kEncJwtType) !=
                  std::string::npos);
    AXIAM_REQUIRE(req.body.find(std::string("subject_token=") + kExternalSubjectToken) !=
                  std::string::npos);
    // Delegation across a trust boundary is unsupported; nothing may add one.
    AXIAM_REQUIRE_FALSE(body_has_field(*f.st, "/oauth2/token", "actor_token"));

    // The cross-domain path is not a different result shape, and §15.2
    // rules 6-7 still hold.
    AXIAM_REQUIRE(axiam::detail::reveal(t.access_token) == "narrow");
    AXIAM_REQUIRE(t.issued_token_type == axiam::kAccessTokenType);
    AXIAM_REQUIRE(t.scope.value_or("") == "read:orders");
}

AXIAM_TEST("§15.7 subject_token_type is never inferred from the token itself") {
    Fixture f;
    f.replies->token_script = {
        {200, R"({"access_token":"narrow","token_type":"Bearer","expires_in":300})"}};
    auto client = make_client(f);
    // A subject token that *looks* exactly like a JWT. An SDK that sniffed the
    // token would send …:jwt here; §15.7 says it must not look, so the caller's
    // silence still means the §15.1 same-domain default.
    client.token_exchange(external_exchange(
        nullptr, nullptr,
        "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL3BhcnRuZXIuZXhhbXBsZS8ifQ.sig"));

    const auto req = last_request(*f.st, "/oauth2/token");
    AXIAM_REQUIRE(req.body.find(std::string("subject_token_type=") + kEncAccessType) !=
                  std::string::npos);
}

AXIAM_TEST("§15.7 an actor token with an external subject token is refused without retry") {
    Fixture f;
    f.replies->token_script = {
        {400,
         R"({"error":"invalid_request","error_description":"actor_token is not supported for an external subject token"})"}};
    auto client = make_client(f);
    try {
        client.token_exchange(external_exchange(axiam::kJwtTokenType, "actor-token"));
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        AXIAM_REQUIRE(e.error_code() == "invalid_request");
    }

    // §15.7: no retry, and no rewriting. Dropping the actor token and re-sending
    // would turn a delegation the caller asked for into an impersonation they
    // did not.
    AXIAM_REQUIRE(f.replies->token_calls == 1);
    const auto req = last_request(*f.st, "/oauth2/token");
    AXIAM_REQUIRE(req.body.find("actor_token=actor-token") != std::string::npos);
    AXIAM_REQUIRE(req.body.find(std::string("subject_token_type=") + kEncJwtType) !=
                  std::string::npos);
}

AXIAM_TEST("§15.7 a refused subject_token_type is never retried as another") {
    // A refresh token is a re-authentication credential and an ID token is an
    // assertion to a client about a login; neither is a bearer credential for an
    // API, so both are refused BY NAME. Retrying as …:jwt would present one as
    // if it were.
    const std::vector<std::pair<const char*, const char*>> cases = {
        {"urn:ietf:params:oauth:token-type:refresh_token",
         "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Arefresh_token"},
        {"urn:ietf:params:oauth:token-type:id_token",
         "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token"},
    };
    for (const auto& [refused, encoded] : cases) {
        Fixture f;
        f.replies->token_script = {
            {400,
             R"({"error":"invalid_request","error_description":"unsupported subject_token_type"})"}};
        auto client = make_client(f);
        AXIAM_REQUIRE_THROWS_AS(client.token_exchange(external_exchange(refused)),
                                axiam::OAuthProtocolError);

        AXIAM_REQUIRE(f.replies->token_calls == 1);
        const auto req = last_request(*f.st, "/oauth2/token");
        AXIAM_REQUIRE(req.body.find(std::string("subject_token_type=") + encoded) !=
                      std::string::npos);
    }
}

AXIAM_TEST("§15.7 the issuer-not-configured description reaches the caller intact") {
    Fixture f;
    f.replies->token_script = {
        {400,
         std::string(R"({"error":"invalid_grant","error_description":")") + kIssuerNotConfigured +
             R"("})"}};
    auto client = make_client(f);
    try {
        client.token_exchange(external_exchange(axiam::kJwtTokenType));
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        AXIAM_REQUIRE(e.error_code() == "invalid_grant");
        // This is the ONLY distinguishable external failure, and the whole point
        // of it is that an integrator can tell "fix the AXIAM trust config" from
        // "fix your token". Truncating or rewording it destroys that.
        AXIAM_REQUIRE(e.error_description().value_or("") == kIssuerNotConfigured);
    }
}

AXIAM_TEST("§15.7 no helper re-exchanges an externally exchanged token") {
    // Tokens minted from an external subject token carry ext_exchange, and BOTH
    // exchange paths refuse a subject token bearing it: exchanges do not
    // compose. The SDK's part is to never feed a result back in by itself.
    Fixture f;
    f.replies->token_script = {
        {200,
         R"({"access_token":"narrow","token_type":"Bearer","expires_in":300,"scope":"read:orders"})"}};
    auto client = make_client(f);
    const auto t = client.token_exchange(external_exchange(axiam::kJwtTokenType));

    // Exactly one exchange happened: nothing looped the result back in.
    AXIAM_REQUIRE(f.replies->token_calls == 1);
    // §15.2 rule 5 restated for the cross-domain path: had the result been
    // adopted, the next exchange would carry it as a *subject* token, which is
    // exactly the re-exchange §15.7 forbids, arrived at by accident.
    AXIAM_REQUIRE_FALSE(client.has_session());
    AXIAM_REQUIRE(axiam::detail::reveal(t.access_token) == "narrow");
}

// ---------------------------------------------------------------------------
// §12.1 / §9 rule 2 — oidc_refresh is single-flighted
// ---------------------------------------------------------------------------

AXIAM_TEST("§9 rule 2 concurrent refreshes of one token make exactly one wire call") {
    // §12.1: `oidc_refresh` MUST be governed by a §9-conformant guard, including
    // rule 2's observable requirement — one wire call per burst, that one
    // outcome shared with every concurrent caller. That observable is a COUNT.
    //
    // Why it matters even though the caller supplies the token: AXIAM rotates
    // refresh tokens. Two threads redeeming the same one concurrently produce
    // one winner and one `invalid_grant` — for a token that was good a
    // millisecond earlier, and which the loser cannot distinguish from a
    // genuinely revoked session.
    Fixture f;
    f.replies->token_script = {
        {200,
         R"({"access_token":"rotated-access","token_type":"Bearer","expires_in":900,)"
         R"("refresh_token":"rotated-refresh"})"}};
    f.replies->token_delay = std::chrono::milliseconds(60);
    auto client = make_client(f);
    client.oidc_discover();  // warm the cache so the count is about the grant

    std::vector<std::thread> threads;
    std::atomic<int> ok{0};
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&] {
            const auto set = client.oidc_refresh(axiam::Sensitive<std::string>("one-token"));
            if (axiam::detail::reveal(set.access_token) == "rotated-access" &&
                set.refresh_token.has_value()) {
                ok.fetch_add(1);
            }
        });
    }
    for (auto& t : threads) t.join();

    AXIAM_REQUIRE(f.replies->token_calls == 1);
    // ...and every worker got that one outcome, whole.
    AXIAM_REQUIRE(ok.load() == 8);
}

AXIAM_TEST("§9 rule 2 distinct refresh tokens do not contend, and a burst is not a cache") {
    // The guard is keyed on the TOKEN, not on the client: coalescing unrelated
    // tokens would be worse than not coalescing at all, because one caller would
    // be handed another caller's freshly-rotated credential.
    Fixture f;
    f.replies->token_script = {
        {200, R"({"access_token":"rotated","token_type":"Bearer","expires_in":900})"}};
    f.replies->token_delay = std::chrono::milliseconds(40);
    auto client = make_client(f);
    client.oidc_discover();

    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&, i] {
            client.oidc_refresh(axiam::Sensitive<std::string>("token-" + std::to_string(i)));
        });
    }
    for (auto& t : threads) t.join();
    AXIAM_REQUIRE(f.replies->token_calls == 4);

    // A coalesce, not a cache. The flight is unlinked before its outcome is
    // published, so a caller arriving after it completed starts a fresh one —
    // anything else would hand out a token whose refresh token has already been
    // spent, with no TTL and no invalidation.
    f.replies->token_delay = std::chrono::milliseconds(0);
    const std::size_t before = f.replies->token_calls;
    client.oidc_refresh(axiam::Sensitive<std::string>("token-0"));
    client.oidc_refresh(axiam::Sensitive<std::string>("token-0"));
    AXIAM_REQUIRE(f.replies->token_calls == before + 2);
}

AXIAM_TEST("§9 rule 2 a failing flight shares its failure with every waiter") {
    // The other half of the rule: "that ONE OUTCOME shared with every concurrent
    // caller" — outcome, not success. Eight threads redeem one already-spent
    // token; one request goes out and all eight see the same `invalid_grant`. A
    // guard that only shared successes would leave the followers to make their
    // own requests and collect a second, differently-worded refusal each.
    Fixture f;
    f.replies->token_script = {{400, R"({"error":"invalid_grant"})"}};
    f.replies->token_delay = std::chrono::milliseconds(60);
    auto client = make_client(f);
    client.oidc_discover();

    std::vector<std::thread> threads;
    std::atomic<int> refused{0};
    for (int i = 0; i < 8; ++i) {
        threads.emplace_back([&] {
            try {
                client.oidc_refresh(axiam::Sensitive<std::string>("spent-token"));
            } catch (const axiam::OAuthProtocolError& e) {
                if (e.error_code() == "invalid_grant") refused.fetch_add(1);
            }
        });
    }
    for (auto& t : threads) t.join();

    AXIAM_REQUIRE(f.replies->token_calls == 1);
    AXIAM_REQUIRE(refused.load() == 8);
}

// ---------------------------------------------------------------------------
// §12.7 logout
// ---------------------------------------------------------------------------

AXIAM_TEST("§12.7.2 logout_url uses the discovered endpoint, not concatenation") {
    Fixture f;
    auto client = make_client(f);
    const auto cfg = client.oidc_discover();
    const auto url = axiam::logout_url(cfg, "the-id-token", "https://app.test/bye", "st-1");
    AXIAM_REQUIRE(url.has_value());

    // Rule 1. The fixture's issuer is https://issuer.test while the
    // end_session_endpoint is on https://iam.example.com, so an implementation
    // that built "{issuer}/oauth2/end_session" would produce a different host —
    // the exact failure that works against AXIAM and breaks against every other
    // OP the same code is pointed at.
    AXIAM_REQUIRE(url->rfind("https://iam.example.com/oauth2/end_session?", 0) == 0);
    AXIAM_REQUIRE(url->find(kIssuer) == std::string::npos);
    AXIAM_REQUIRE(url->find("id_token_hint=the-id-token") != std::string::npos);
    AXIAM_REQUIRE(url->find("post_logout_redirect_uri=https%3A%2F%2Fapp.test%2Fbye") !=
                  std::string::npos);
    // Rule 2: passed through unmodified.
    AXIAM_REQUIRE(url->find("state=st-1") != std::string::npos);

    // Omitted when not supplied — and the SDK never INVENTS a state, because the
    // value only means something to the application that receives it back.
    const auto bare = axiam::logout_url(cfg, "the-id-token");
    AXIAM_REQUIRE(bare->find("state=") == std::string::npos);
    AXIAM_REQUIRE(bare->find("post_logout_redirect_uri=") == std::string::npos);

    // Rule 3: NOT pre-validated against a local list. The allow-list lives in
    // the client's server-side registration; a client-side copy would drift and
    // would reject a URI an operator had just registered.
    AXIAM_REQUIRE(axiam::logout_url(cfg, "tok", "https://somewhere-else.example/bye")
                      ->find("somewhere-else.example") != std::string::npos);

    // §12.7.1: there is no hint-less mode — no parameter on the wire names the
    // user another way, and inventing one would encourage exactly the request
    // the server refuses to act on.
    AXIAM_REQUIRE_FALSE(axiam::logout_url(cfg, "").has_value());

    // §12.7.2 rule 1 leaves no fallback: a document advertising no endpoint gets
    // nullopt rather than a guess.
    axiam::OidcConfiguration bare_cfg = cfg;
    bare_cfg.end_session_endpoint.reset();
    AXIAM_REQUIRE_FALSE(axiam::logout_url(bare_cfg, "tok").has_value());
}

namespace {

std::string logout_claims(const std::string& overrides = "") {
    return std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":\"" + kClientId +
           "\",\"sid\":\"session-1\",\"sub\":\"user-1\",\"jti\":\"jti-1\",\"iat\":" +
           std::to_string(now() - 5) + ",\"exp\":" + std::to_string(now() + 120) +
           ",\"events\":{\"" + axiam::kBackchannelLogoutEvent + "\":{}}" + overrides + "}";
}

}  // namespace

AXIAM_TEST("§12.7.3 a valid logout token surfaces sid, sub and jti — and verifies twice") {
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    auto client = make_client(f);
    const std::string token = key.make_jwt("EdDSA", logout_claims());

    const auto t = client.verify_logout_token(token);
    // NEVER a bare boolean: the RP has to know WHICH session to end, and when
    // `sid` is present it must end that one only.
    AXIAM_REQUIRE(t.sid.value_or("") == "session-1");
    AXIAM_REQUIRE(t.subject.value_or("") == "user-1");
    AXIAM_REQUIRE(t.jwt_id.value_or("") == "jti-1");

    // Rule 7 / §12.7.6: delivery is at-least-once with retry, so a valid token
    // legitimately arrives twice. This SDK deliberately does NOT dedup
    // internally — it has no durable store and would silently drop a real second
    // logout after a restart — so `jti` is surfaced and dedup is the RP's job.
    // An SDK that failed the second delivery would break a legitimate retry.
    AXIAM_REQUIRE_NOTHROW(client.verify_logout_token(token));
}

AXIAM_TEST("§12.7.3 rule 3 a missing events member is rejected") {
    // This is what distinguishes a logout token from an ID token. An SDK that
    // skips it will accept a replayed ID token as a logout instruction.
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    auto client = make_client(f);
    const std::string payload = std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":\"" +
                                kClientId + "\",\"sid\":\"s\",\"jti\":\"j\",\"iat\":" +
                                std::to_string(now() - 5) + ",\"exp\":" +
                                std::to_string(now() + 120) + "}";
    const std::string token = key.make_jwt("EdDSA", payload);
    try {
        client.verify_logout_token(token);
        AXIAM_REQUIRE(false);
    } catch (const axiam::AuthError& e) {
        AXIAM_REQUIRE(std::string(e.what()).find("events") != std::string::npos);
        // Rule 8: the error must not echo the token.
        AXIAM_REQUIRE(std::string(e.what()).find(token) == std::string::npos);
    }
}

AXIAM_TEST("§12.7.3 rule 4 a replayed ID token is rejected for carrying a nonce") {
    // §12.7.6 names this test and says to assert it with an OTHERWISE-VALID ID
    // token, because that is the actual attack: an attacker who captures an ID
    // token and POSTs it to the RP's back-channel endpoint. Back-Channel Logout
    // 1.0 §2.4 forbids a `nonce`, and its presence is the documented signature
    // of the replay — so this rejects rather than ignoring.
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    auto client = make_client(f);
    try {
        client.verify_logout_token(key.make_jwt("EdDSA", logout_claims(R"(,"nonce":"n-1")")));
        AXIAM_REQUIRE(false);
    } catch (const axiam::AuthError& e) {
        AXIAM_REQUIRE(std::string(e.what()).find("nonce") != std::string::npos);
    }
}

AXIAM_TEST("§12.7.3 the remaining rules all reject") {
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    auto client = make_client(f);
    const std::string events =
        std::string(",\"events\":{\"") + axiam::kBackchannelLogoutEvent + "\":{}}";

    // Rule 5: a token naming neither sid nor sub identifies nothing.
    AXIAM_REQUIRE_THROWS_AS(
        client.verify_logout_token(key.make_jwt(
            "EdDSA", std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":\"" + kClientId +
                         "\",\"exp\":" + std::to_string(now() + 120) + events)),
        axiam::AuthError);

    // Rule 2: a token minted for another RP must not be accepted here.
    AXIAM_REQUIRE_THROWS_AS(
        client.verify_logout_token(key.make_jwt(
            "EdDSA", std::string("{\"iss\":\"") + kIssuer +
                         "\",\"aud\":\"other-rp\",\"sid\":\"s\",\"exp\":" +
                         std::to_string(now() + 120) + events)),
        axiam::AuthError);

    // ...and one minted by another OP.
    AXIAM_REQUIRE_THROWS_AS(
        client.verify_logout_token(key.make_jwt(
            "EdDSA", std::string("{\"iss\":\"https://evil.test\",\"aud\":\"") + kClientId +
                         "\",\"sid\":\"s\",\"exp\":" + std::to_string(now() + 120) + events)),
        axiam::AuthError);

    // Rule 6: AXIAM issues a 120 s lifetime, and a stale one is a replay
    // candidate rather than a late delivery.
    AXIAM_REQUIRE_THROWS_AS(
        client.verify_logout_token(key.make_jwt(
            "EdDSA", std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":\"" + kClientId +
                         "\",\"sid\":\"s\",\"exp\":" + std::to_string(now() - 1800) + events)),
        axiam::AuthError);
}

AXIAM_TEST("§12.7.3 rule 1 a bad signature is rejected through the same §12.4 verifier") {
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    auto client = make_client(f);
    std::string token = key.make_jwt("EdDSA", logout_claims());
    const auto dot = token.find('.');
    token[dot + 3] = (token[dot + 3] == 'a') ? 'b' : 'a';
    try {
        client.verify_logout_token(token);
        AXIAM_REQUIRE(false);
    } catch (const axiam::OidcValidationError& e) {
        // No second key-fetching path, so it fails the same way an ID token
        // would.
        AXIAM_REQUIRE(e.reason() == axiam::OidcValidationReason::kInvalidSignature);
    }
}
