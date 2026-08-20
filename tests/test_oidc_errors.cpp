// CONTRACT.md §12 / §12.7 / §14 — the REFUSAL paths.
//
// tests/test_oidc.cpp pins what a successful operation puts on the wire. This
// file pins the other half: what happens when the server answers with something
// the SDK must not accept, and when the caller asks for something that cannot
// work. Those arms are where an SDK fails open — a malformed discovery document
// silently yielding a client that "works" until the first token call, a token
// response with no access_token surfacing as an empty string, a logout token
// minted for another RP being honoured — so each case below asserts that a
// SPECIFIC exception type comes out, not merely that something was thrown.
//
// The discovery document is configurable here, which is what test_oidc.cpp's
// fixed one cannot express: several §12.3 and §14.1 refusals are ABOUT the
// document's contents.

#include <memory>
#include <string>
#include <vector>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"
#include "test_key.hpp"

namespace {

const char* kTenantUuid = "22222222-2222-2222-2222-222222222222";
const char* kClientId = "example-rp";
const char* kClientSecret = "example-secret";
const char* kRedirectUri = "https://app.test/callback";
const char* kIssuer = "https://issuer.test";

const char* kFullDiscovery = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "introspection_endpoint":"https://iam.example.com/oauth2/introspect",
  "revocation_endpoint":"https://iam.example.com/oauth2/revoke",
  "end_session_endpoint":"https://iam.example.com/oauth2/end_session",
  "device_authorization_endpoint":"https://iam.example.com/oauth2/device_authorization",
  "scopes_supported":["openid","profile"],
  "response_types_supported":["code"],
  "id_token_signing_alg_values_supported":["EdDSA"]
})";

// The same document with no device_authorization_endpoint — §14.1's refusal is
// about the DOCUMENT, so it needs one that legitimately lacks the endpoint.
const char* kNoDeviceDiscovery = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks"
})";

struct Replies {
    long discovery_status = 200;
    std::string discovery_body = kFullDiscovery;

    std::vector<std::pair<long, std::string>> token_script;
    std::size_t token_calls = 0;

    long introspect_status = 200;
    std::string introspect_body = R"({"active":true})";
    std::size_t introspect_calls = 0;

    long sso_status = 200;
    std::string sso_body = "{}";

    long device_status = 200;
    std::string device_body = "{}";

    std::string jwks_body = R"({"keys":[]})";
};

axiam::Transport routed(std::shared_ptr<axtest::FakeState> st, std::shared_ptr<Replies> r) {
    st->router = [r](const axiam::HttpRequest& req, axtest::FakeState&) -> axiam::HttpResponse {
        const std::string& url = req.url;
        // status 0 means "the transport itself failed", which §2 maps to a
        // NetworkError carrying the transport's own message rather than a
        // status code.
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
        if (url.find("openid-configuration") != std::string::npos) {
            return reply(r->discovery_status, r->discovery_body);
        }
        if (url.find("/oauth2/jwks") != std::string::npos) return reply(200, r->jwks_body);
        if (url.find("/oauth2/device_authorization") != std::string::npos) {
            return reply(r->device_status, r->device_body);
        }
        if (url.find("/oauth2/introspect") != std::string::npos) {
            ++r->introspect_calls;
            return reply(r->introspect_status, r->introspect_body);
        }
        if (url.find("/oauth2/revoke") != std::string::npos) return reply(200, "");
        if (url.find("/oauth2/token") != std::string::npos) {
            const std::size_t i = r->token_calls++;
            if (r->token_script.empty()) return reply(200, "{}");
            const auto& a = r->token_script[std::min(i, r->token_script.size() - 1)];
            return reply(a.first, a.second);
        }
        if (url.find("/federation/oidc/") != std::string::npos) {
            return reply(r->sso_status, r->sso_body);
        }
        return reply(404, "{}");
    };
    return axtest::make_fake(std::move(st));
}

struct Fixture {
    std::shared_ptr<axtest::FakeState> st = std::make_shared<axtest::FakeState>();
    std::shared_ptr<Replies> replies = std::make_shared<Replies>();
};

axiam::Client make_client(Fixture& f, const char* client_id = kClientId,
                          const char* secret = kClientSecret) {
    auto builder = axiam::Client::builder()
                       .base_url("https://iam.example.com")
                       .tenant_slug("acme")
                       .tenant_id(kTenantUuid)
                       .transport(routed(f.st, f.replies));
    if (client_id != nullptr) builder.oidc_client_id(client_id);
    if (secret != nullptr) builder.oidc_client_secret(secret);
    return builder.build();
}

}  // namespace

// ---------------------------------------------------------------------------
// §12.3 — discovery
// ---------------------------------------------------------------------------

AXIAM_TEST("discovery: a non-2xx answer is a NetworkError naming the status") {
    Fixture f;
    f.replies->discovery_status = 503;
    f.replies->discovery_body = "upstream unavailable";
    axiam::Client c = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(c.oidc_discover(), axiam::NetworkError);
}

AXIAM_TEST("discovery: a document missing a REQUIRED endpoint is refused") {
    // §12.3: issuer / authorization_endpoint / token_endpoint / jwks_uri are the
    // four every other operation depends on. Accepting a document without them
    // defers the failure to a later call that cannot explain itself, so each
    // omission is refused at discovery.
    const char* kOmissions[] = {
        R"({"authorization_endpoint":"a","token_endpoint":"t","jwks_uri":"j"})",
        R"({"issuer":"https://issuer.test","token_endpoint":"t","jwks_uri":"j"})",
        R"({"issuer":"https://issuer.test","authorization_endpoint":"a","jwks_uri":"j"})",
        R"({"issuer":"https://issuer.test","authorization_endpoint":"a","token_endpoint":"t"})",
    };
    for (const char* body : kOmissions) {
        Fixture f;
        f.replies->discovery_body = body;
        axiam::Client c = make_client(f);
        AXIAM_REQUIRE_THROWS_AS(c.oidc_discover(), axiam::NetworkError);
    }
}

AXIAM_TEST("discovery: an OPTIONAL endpoint's absence is NOT a discovery failure") {
    // The other half of the rule above, and the one a stricter implementation
    // gets wrong: a server without an end_session_endpoint must still discover
    // successfully and fail later, at logout_url(), where the caller can act on
    // it. Failing here would break every other operation over an unused one.
    Fixture f;
    f.replies->discovery_body = kNoDeviceDiscovery;
    axiam::Client c = make_client(f);
    const axiam::OidcConfiguration cfg = c.oidc_discover();
    AXIAM_CHECK(cfg.issuer == kIssuer);
    AXIAM_CHECK(!cfg.end_session_endpoint.has_value());
    AXIAM_CHECK(!cfg.device_authorization_endpoint.has_value());
}

// ---------------------------------------------------------------------------
// §12.1 — oidc_begin's client-side refusals (no network I/O either way)
// ---------------------------------------------------------------------------

AXIAM_TEST("oidc_begin: an empty redirect_uri is refused before any request") {
    Fixture f;
    axiam::Client c = make_client(f);
    const axiam::OidcConfiguration cfg = c.oidc_discover();
    const std::size_t before = f.st->count();
    AXIAM_REQUIRE_THROWS_AS(c.oidc_begin(cfg, ""), axiam::NetworkError);
    AXIAM_CHECK(f.st->count() == before);
}

AXIAM_TEST("oidc_begin: a document with no authorization_endpoint is refused") {
    Fixture f;
    axiam::Client c = make_client(f);
    axiam::OidcConfiguration cfg = c.oidc_discover();
    cfg.authorization_endpoint.clear();
    AXIAM_REQUIRE_THROWS_AS(c.oidc_begin(cfg, kRedirectUri), axiam::NetworkError);
}

// ---------------------------------------------------------------------------
// §12.1 / §12.4 — oidc_exchange
// ---------------------------------------------------------------------------

AXIAM_TEST("oidc_exchange: the three required inputs are checked client-side") {
    // Each of these would produce a request the server can only reject, and the
    // code is single-use — so a request that could not have succeeded must
    // never be sent, or it spends the code for nothing.
    Fixture f;
    axiam::Client c = make_client(f);
    const std::size_t before = f.st->count();

    axiam::OidcExchangeParams no_code;
    no_code.redirect_uri = kRedirectUri;
    no_code.code_verifier = axiam::Sensitive<std::string>("the-verifier");
    no_code.nonce = "the-nonce";
    AXIAM_REQUIRE_THROWS_AS(c.oidc_exchange(no_code), axiam::AuthError);

    axiam::OidcExchangeParams no_redirect;
    no_redirect.code = "the-code";
    no_redirect.code_verifier = axiam::Sensitive<std::string>("the-verifier");
    no_redirect.nonce = "the-nonce";
    AXIAM_REQUIRE_THROWS_AS(c.oidc_exchange(no_redirect), axiam::AuthError);

    axiam::OidcExchangeParams no_verifier;
    no_verifier.code = "the-code";
    no_verifier.redirect_uri = kRedirectUri;
    no_verifier.nonce = "the-nonce";
    AXIAM_REQUIRE_THROWS_AS(c.oidc_exchange(no_verifier), axiam::AuthError);

    // §12.4 rule 6: the nonce is mandatory for this operation specifically.
    axiam::OidcExchangeParams no_nonce;
    no_nonce.code = "the-code";
    no_nonce.redirect_uri = kRedirectUri;
    no_nonce.code_verifier = axiam::Sensitive<std::string>("the-verifier");
    AXIAM_REQUIRE_THROWS_AS(c.oidc_exchange(no_nonce), axiam::AuthError);

    AXIAM_CHECK(f.st->count() == before);
}

AXIAM_TEST("oidc_exchange: a TokenResponse with no access_token is malformed, not empty") {
    // The failure an SDK is most likely to paper over: `access_token` absent
    // yields an empty string, and the caller sends `Authorization: Bearer ` to
    // the resource server instead of learning the exchange failed.
    Fixture f;
    f.replies->token_script = {{200, R"({"token_type":"Bearer","expires_in":900})"}};
    axiam::Client c = make_client(f);

    axiam::OidcExchangeParams p;
    p.code = "the-code";
    p.redirect_uri = kRedirectUri;
    p.code_verifier = axiam::Sensitive<std::string>("the-verifier");
    p.nonce = "the-nonce";
    AXIAM_REQUIRE_THROWS_AS(c.oidc_exchange(p), axiam::NetworkError);
}

AXIAM_TEST("oidc_exchange: a transport failure surfaces as NetworkError, unretried") {
    // §16.2: the authorization code is consumed by the attempt, so this is one
    // request and exactly one — a retry would replay a spent credential.
    Fixture f;
    f.replies->token_script = {{0, ""}};
    axiam::Client c = make_client(f);

    axiam::OidcExchangeParams p;
    p.code = "the-code";
    p.redirect_uri = kRedirectUri;
    p.code_verifier = axiam::Sensitive<std::string>("the-verifier");
    p.nonce = "the-nonce";
    AXIAM_REQUIRE_THROWS_AS(c.oidc_exchange(p), axiam::NetworkError);
    AXIAM_CHECK(f.replies->token_calls == 1);
}

// ---------------------------------------------------------------------------
// §12.1 — introspect / revoke
// ---------------------------------------------------------------------------

// Both operations resolve the discovery document before inspecting the token,
// so the assertion is that the OPERATION's OWN endpoint is never reached — not
// that nothing at all went out. Discovery is a cached, idempotent read that
// mints nothing; the introspection and revocation endpoints are where a request
// that cannot succeed would actually cost something.
AXIAM_TEST("introspect: an empty token never reaches the introspection endpoint") {
    Fixture f;
    axiam::Client c = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(c.introspect(axiam::Sensitive<std::string>("")), axiam::AuthError);
    AXIAM_CHECK(f.st->count_path("/oauth2/introspect") == 0);
    AXIAM_CHECK(f.replies->introspect_calls == 0);
}

AXIAM_TEST("revoke: an empty token never reaches the revocation endpoint") {
    Fixture f;
    axiam::Client c = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(c.revoke(axiam::Sensitive<std::string>("")), axiam::AuthError);
    AXIAM_CHECK(f.st->count_path("/oauth2/revoke") == 0);
}

AXIAM_TEST("introspect: a 5xx is retried and the eventual success is returned") {
    // §16.2 lists introspection as retry-eligible: it is a read ABOUT a token
    // and mints nothing, so replaying it is safe. This is the arm that proves
    // the retry loop actually runs rather than being dead code.
    Fixture f;
    f.replies->introspect_status = 503;
    axiam::Client c = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(c.introspect(axiam::Sensitive<std::string>("a-token")),
                            axiam::NetworkError);
    // More than one attempt was made — the retry budget was actually spent.
    AXIAM_CHECK(f.replies->introspect_calls > 1);
}

// ---------------------------------------------------------------------------
// §12.1 — federation SSO
// ---------------------------------------------------------------------------

AXIAM_TEST("sso_start: a response missing authorize_url or state is malformed") {
    Fixture f;
    f.replies->sso_body = R"({"state":"s"})";  // no authorize_url
    axiam::Client c = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(c.sso_start("fed-1", kRedirectUri), axiam::NetworkError);

    Fixture g;
    g.replies->sso_body = R"({"authorize_url":"https://idp.test/a"})";  // no state
    axiam::Client c2 = make_client(g);
    AXIAM_REQUIRE_THROWS_AS(c2.sso_start("fed-1", kRedirectUri), axiam::NetworkError);
}

AXIAM_TEST("sso_complete: a response missing user_id or session_id is malformed") {
    Fixture f;
    f.replies->sso_body = R"({"session_id":"s"})";
    axiam::Client c = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(c.sso_complete("code", "state"), axiam::NetworkError);

    Fixture g;
    g.replies->sso_body = R"({"user_id":"u"})";
    axiam::Client c2 = make_client(g);
    AXIAM_REQUIRE_THROWS_AS(c2.sso_complete("code", "state"), axiam::NetworkError);
}

// ---------------------------------------------------------------------------
// §14.1 — device authorization
// ---------------------------------------------------------------------------

AXIAM_TEST("device_authorize: a document advertising no endpoint is refused") {
    // §14.1 gives no fallback path for this endpoint, so a document without it
    // means the deployment does not support the grant — which is a refusal the
    // caller can act on, not a URL for the SDK to guess.
    Fixture f;
    f.replies->discovery_body = kNoDeviceDiscovery;
    axiam::Client c = make_client(f, kClientId, nullptr);
    AXIAM_REQUIRE_THROWS_AS(c.device_authorize(), axiam::NetworkError);
}

// ---------------------------------------------------------------------------
// §14.1 — device authorization's failure arms.
//
// The grant that starts here is the one a user finishes on a different device,
// so a failure that surfaces as a half-built DeviceAuthorization is a failure
// nobody sees until a human has already been told to visit a URL that does not
// exist. Every arm below therefore refuses at the boundary.
// ---------------------------------------------------------------------------

AXIAM_TEST("device_authorize: a transport failure is a NetworkError carrying the cause") {
    Fixture f;
    f.replies->device_status = 0;  // the request never completed
    axiam::Client c = make_client(f, kClientId, nullptr);
    try {
        c.device_authorize();
        AXIAM_REQUIRE(false);
    } catch (const axiam::NetworkError& e) {
        // The transport's own message is preserved rather than replaced with a
        // generic one: "connection refused" and "TLS handshake failed" call for
        // different operator action.
        AXIAM_REQUIRE(std::string(e.what()).find("connection refused") != std::string::npos);
    }
}

AXIAM_TEST("device_authorize: a non-2xx goes through the OAuth2 error mapping") {
    // Not a bare status map: §14 answers arrive as an OAuth2 error object, and
    // the code in it is the part a caller can act on.
    Fixture f;
    f.replies->device_status = 400;
    f.replies->device_body = R"({"error":"invalid_client","error_description":"unknown client"})";
    axiam::Client c = make_client(f, kClientId, nullptr);
    try {
        c.device_authorize();
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        AXIAM_REQUIRE(e.error_code() == "invalid_client");
    }
}

AXIAM_TEST("device_authorize: a 2xx missing any required member is malformed, not partial") {
    // RFC 8628 §3.2 makes device_code, user_code and verification_uri all
    // REQUIRED. Returning a DeviceAuthorization with any of them empty would
    // send a human to "" or leave the poll loop with nothing to poll — so each
    // omission is refused rather than defaulted.
    const char* kIncomplete[] = {
        R"({"user_code":"WDJB-MJHT","verification_uri":"https://v.test"})",       // no device_code
        R"({"device_code":"dc","verification_uri":"https://v.test"})",            // no user_code
        R"({"device_code":"dc","user_code":"WDJB-MJHT"})",                        // no verification_uri
        R"({})",                                                                  // none at all
    };
    for (const char* body : kIncomplete) {
        Fixture f;
        f.replies->device_status = 200;
        f.replies->device_body = body;
        axiam::Client c = make_client(f, kClientId, nullptr);
        AXIAM_REQUIRE_THROWS_AS(c.device_authorize(), axiam::NetworkError);
    }
}

// ---------------------------------------------------------------------------
// §15 — token exchange's malformed-response arm
// ---------------------------------------------------------------------------

AXIAM_TEST("token_exchange: a 2xx with no access_token is malformed, not an empty token") {
    // The whole point of the call is the token. A response without one that
    // still returned an ExchangedToken would hand the caller an empty string to
    // put in an Authorization header, and the 401 that follows would be blamed
    // on the wrong hop.
    Fixture f;
    f.replies->token_script = {{200, R"({"token_type":"Bearer","expires_in":300})"}};
    axiam::Client c = make_client(f);
    axiam::TokenExchangeParams p;
    p.subject_token = axiam::Sensitive<std::string>("subject-token");
    p.subject_token_type = axiam::kAccessTokenType;
    AXIAM_REQUIRE_THROWS_AS(c.token_exchange(p), axiam::NetworkError);
}

// ---------------------------------------------------------------------------
// §12.1 rule 4 — `openid` is added by whole-token match, never by substring
// ---------------------------------------------------------------------------

AXIAM_TEST("oidc_begin: openid is added when absent and never duplicated when present") {
    Fixture f;
    axiam::Client c = make_client(f);
    const axiam::OidcConfiguration cfg = c.oidc_discover();

    const auto scope_of = [&](std::optional<std::string> requested) {
        const auto begun = c.oidc_begin(cfg, kRedirectUri, std::move(requested));
        const std::string& url = begun.url;
        const auto at = url.find("scope=");
        AXIAM_REQUIRE(at != std::string::npos);
        const auto end = url.find('&', at);
        return url.substr(at + 6, end == std::string::npos ? std::string::npos : end - (at + 6));
    };

    // Absent entirely -> exactly "openid".
    AXIAM_REQUIRE(scope_of(std::nullopt) == "openid");

    // Present, but NOT first: the scan has to walk past a space-separated
    // element before it finds it. A loop that only ever examined the first
    // element would prepend a second `openid` here.
    AXIAM_REQUIRE(scope_of(std::string("profile openid email")).find("openid") !=
                  std::string::npos);
    AXIAM_REQUIRE(scope_of(std::string("profile openid email")).find("openid%20openid") ==
                  std::string::npos);

    // Present as the LAST element — the arm where the terminating
    // `find(' ') == npos` decides between "found it" and "give up".
    const std::string last = scope_of(std::string("profile openid"));
    AXIAM_REQUIRE(last.find("openid") != std::string::npos);

    // Absent, multi-element, and containing a scope that has `openid` as a
    // PREFIX. A substring test would see `openid` inside `openid_admin` and skip
    // the addition, producing a plain-OAuth2 request with no ID token and so no
    // §12.4 validation at all — silent until something downstream reads
    // id_claims and finds nothing.
    const std::string prefixed = scope_of(std::string("profile openid_admin"));
    AXIAM_REQUIRE(prefixed.rfind("openid", 0) == 0);
    AXIAM_REQUIRE(prefixed.find("openid_admin") != std::string::npos);
}

// §12.4 — an id_token that SIGNS correctly but whose payload is not a JSON
// object.
//
// The signature check and the claims check are separate stages, and the gap
// between them is where a well-signed non-object slips through: every claim
// lookup on a JSON array or string answers "absent", so an implementation that
// went straight to the claims would report a missing `iss` on a token that has
// no claims at all — or, worse, treat "no aud" and "no nonce" as nothing to
// check and accept it. The token is refused as its own case, and as a
// VALIDATION failure (it reached the verifier), not a malformed-body one.
AXIAM_TEST("oidc_exchange: a well-signed id_token whose payload is not an object is refused") {
    for (const char* payload : {"[1,2,3]", R"("a-string")", "42", "null"}) {
        Fixture f;
        axtest::TestKey key;
        f.replies->jwks_body = key.jwks_json();
        const std::string id_token = key.make_jwt("EdDSA", payload);
        f.replies->token_script = {
            {200, std::string(R"({"access_token":"at","token_type":"Bearer","expires_in":900,)"
                              R"("id_token":")") +
                      id_token + R"("})"}};
        axiam::Client c = make_client(f);

        axiam::OidcExchangeParams p;
        p.code = "the-code";
        p.redirect_uri = kRedirectUri;
        p.code_verifier = axiam::Sensitive<std::string>("the-verifier");
        p.nonce = "the-nonce";
        AXIAM_REQUIRE_THROWS_AS(c.oidc_exchange(p), axiam::OidcValidationError);
    }
}
