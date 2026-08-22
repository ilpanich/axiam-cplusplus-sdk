// Pushed Authorization Requests, RFC 9126 — CONTRACT.md §26.
//
// PAR moves the authorization request off the browser: instead of putting
// `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the user
// agent carries, the client POSTs them straight to AXIAM and puts an opaque
// handle in the redirect. What travels through the browser is then a random
// string that cannot be edited into meaning something else.
//
// TWO OF THESE TESTS ARE THE ONES THAT CATCH REAL BUGS.
//
//  - The 201 test. RFC 9126 §2.2 answers Created, and a success predicate
//    written `== 200` treats every successful push as a failure while passing
//    every other assertion in this file.
//  - The "exactly two parameters" test. The server REFUSES a request mixing a
//    request_uri with inline authorization parameters rather than merging them,
//    because merging is where parameter confusion lives — so an SDK that re-adds
//    `scope` "for compatibility" has restored the attack.

#include <memory>
#include <sstream>
#include <string>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"

namespace {

const char* kTenantUuid = "22222222-2222-2222-2222-222222222222";
const char* kClientId = "example-rp";
const char* kClientSecret = "example-secret";
const char* kRedirectUri = "https://app.example.com/callback";
const char* kRequestUri = "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c";

/// A document that advertises PAR.
const char* kDiscoveryWithPar = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "pushed_authorization_request_endpoint":"https://iam.example.com/oauth2/par"
})";

/// The same, without it: §26.1 refuses client-side rather than synthesising the
/// endpoint from the issuer.
const char* kDiscoveryWithoutPar = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks"
})";

/// A deployment behind a router: the authorization endpoint already carries a
/// query, which §26.2 rule 2 says is DROPPED rather than merged.
const char* kDiscoveryWithQuery = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize?ui_locales=en&prompt=login",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "pushed_authorization_request_endpoint":"https://iam.example.com/oauth2/par"
})";

struct Replies {
    std::string discovery = kDiscoveryWithPar;
    long par_status = 201;
    std::string par_body = R"({"request_uri":"urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c","expires_in":90})";
    std::size_t par_calls = 0;
    bool par_transport_fails = false;
};

axiam::Transport routed(std::shared_ptr<axtest::FakeState> st, std::shared_ptr<Replies> r) {
    st->router = [r](const axiam::HttpRequest& req, axtest::FakeState&) -> axiam::HttpResponse {
        const std::string& url = req.url;
        axiam::HttpResponse resp;
        if (url.find("openid-configuration") != std::string::npos) {
            resp.status = 200;
            resp.body = r->discovery;
            return resp;
        }
        if (url.find("/oauth2/par") != std::string::npos) {
            ++r->par_calls;
            if (r->par_transport_fails) {
                resp.transport_error = "connection refused";
                return resp;
            }
            resp.status = r->par_status;
            resp.body = r->par_body;
            return resp;
        }
        resp.status = 404;
        resp.body = "{}";
        return resp;
    };
    return axtest::make_fake(std::move(st));
}

axiam::Client make_client(std::shared_ptr<axtest::FakeState> st, std::shared_ptr<Replies> r,
                          bool confidential = true, bool with_tenant_uuid = true) {
    auto builder = axiam::Client::builder()
                       .base_url("https://iam.example.com")
                       .tenant_slug("acme")
                       .oidc_client_id(kClientId)
                       .transport(routed(std::move(st), std::move(r)));
    if (confidential) builder.oidc_client_secret(kClientSecret);
    if (with_tenant_uuid) builder.tenant_id(kTenantUuid);
    return builder.build();
}

std::string last_par_body(axtest::FakeState& st) {
    std::lock_guard<std::mutex> lock(st.mtx);
    for (auto it = st.requests.rbegin(); it != st.requests.rend(); ++it) {
        if (it->url.find("/oauth2/par") != std::string::npos) return it->body;
    }
    return {};
}

std::string last_par_url(axtest::FakeState& st) {
    std::lock_guard<std::mutex> lock(st.mtx);
    for (auto it = st.requests.rbegin(); it != st.requests.rend(); ++it) {
        if (it->url.find("/oauth2/par") != std::string::npos) return it->url;
    }
    return {};
}

std::string form_value(const std::string& form, const std::string& key) {
    const std::string needle = key + "=";
    std::size_t at = 0;
    while (at < form.size()) {
        const std::size_t amp = form.find('&', at);
        const std::string part =
            form.substr(at, amp == std::string::npos ? std::string::npos : amp - at);
        if (part.rfind(needle, 0) == 0) return part.substr(needle.size());
        if (amp == std::string::npos) break;
        at = amp + 1;
    }
    return {};
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

// ---------------------------------------------------------------------------
// §26.1 discovery and the push
// ---------------------------------------------------------------------------

AXIAM_TEST("par: a successful push answers 201, not 200") {
    // RFC 9126 §2.2. This is the single most likely way to get §26 wrong: every
    // other assertion in this file passes for an implementation whose success
    // predicate is `== 200`, and every real push fails.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid profile");
    const auto pushed = client.oidc_par(doc, request, kRedirectUri, "openid profile");

    AXIAM_REQUIRE(axiam::detail::reveal(pushed.request_uri) == kRequestUri);
    AXIAM_REQUIRE(pushed.expires_in == 90);
    AXIAM_REQUIRE(r->par_calls == 1);
}

AXIAM_TEST("par: a 200 is also accepted") {
    // The check is on the 2xx RANGE, not on one status: a deployment behind a
    // gateway that normalises to 200 is not a failure.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->par_status = 200;
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    AXIAM_REQUIRE_NOTHROW(client.oidc_par(doc, request, kRedirectUri, "openid"));
}

AXIAM_TEST("par: a server without a PAR endpoint is refused with no wire call") {
    // §12.7.2 rule 1's discipline, applied to §26.1: never synthesise the URL
    // from the issuer. A server that does not advertise the endpoint does not
    // have it, and guessing `/oauth2/par` produces a 404 that reads like a
    // broken request.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->discovery = kDiscoveryWithoutPar;
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    AXIAM_REQUIRE_FALSE(doc.pushed_authorization_request_endpoint.has_value());
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");

    AXIAM_REQUIRE_THROWS_AS(client.oidc_par(doc, request, kRedirectUri, "openid"),
                            axiam::AuthError);
    AXIAM_REQUIRE(r->par_calls == 0);
}

AXIAM_TEST("par: the push carries the tenant as a query parameter and a form body") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    client.oidc_par(doc, request, kRedirectUri, "openid");

    // §12.1 rule 2: the /oauth2 family takes the tenant as a query parameter, in
    // UUID form.
    AXIAM_REQUIRE(contains(last_par_url(*st), std::string("tenant_id=") + kTenantUuid));
    std::lock_guard<std::mutex> lock(st->mtx);
    const auto& last = st->requests.back();
    AXIAM_REQUIRE(last.method == "POST");
    AXIAM_REQUIRE(last.headers.at("Content-Type") == "application/x-www-form-urlencoded");
}

AXIAM_TEST("par: a slug-only client is refused client-side") {
    // §12.3 rule 4: a slug is never a substitute for the tenant UUID on the
    // /oauth2 family. Refused before the wire, because the 400 the server would
    // answer names a field the caller never set.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r, /*confidential=*/true, /*with_tenant_uuid=*/false);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    AXIAM_REQUIRE_THROWS_AS(client.oidc_par(doc, request, kRedirectUri, "openid"),
                            axiam::AuthError);
    AXIAM_REQUIRE(r->par_calls == 0);
}

// ---------------------------------------------------------------------------
// §26.2 rule 1 — one generator, not two
// ---------------------------------------------------------------------------

AXIAM_TEST("par: the push reuses oidc_begin's state, nonce and PKCE pair") {
    // Two sources for `state` or the PKCE pair are two things that can disagree,
    // and when they do the failure surfaces at the exchange as an opaque
    // `invalid_grant` — a long way from the code that caused it.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    const auto pushed = client.oidc_par(doc, request, kRedirectUri, "openid");

    const std::string form = last_par_body(*st);
    AXIAM_REQUIRE(form_value(form, "state") == request.state);
    AXIAM_REQUIRE(form_value(form, "nonce") == request.nonce);
    AXIAM_REQUIRE(form_value(form, "code_challenge_method") == "S256");

    // And they come BACK OUT, so the caller has one object to persist rather
    // than two to keep in step.
    AXIAM_REQUIRE(pushed.state == request.state);
    AXIAM_REQUIRE(pushed.nonce == request.nonce);
    AXIAM_REQUIRE(axiam::detail::reveal(pushed.code_verifier) ==
                  axiam::detail::reveal(request.code_verifier));
}

AXIAM_TEST("par: the verifier itself never goes on the wire") {
    // PKCE's whole point: the push carries the CHALLENGE, and the verifier stays
    // with the client until the exchange.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    client.oidc_par(doc, request, kRedirectUri, "openid");

    const std::string form = last_par_body(*st);
    AXIAM_REQUIRE_FALSE(contains(form, axiam::detail::reveal(request.code_verifier)));
    AXIAM_REQUIRE_FALSE(form_value(form, "code_challenge").empty());
}

AXIAM_TEST("par: openid is added to the pushed scope when absent") {
    // §12.1 rule 4, applied to the push exactly as oidc_begin applies it —
    // otherwise the two halves of one authorization request ask for different
    // scopes.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "profile email");
    client.oidc_par(doc, request, kRedirectUri, std::string("profile email"));

    AXIAM_REQUIRE(contains(form_value(last_par_body(*st), "scope"), "openid"));
}

AXIAM_TEST("par: a scope that merely CONTAINS openid still gets the token added") {
    // Whole-token matching: "openid_extra" is not `openid`, and a substring
    // check would silently drop the one scope that makes this OIDC.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    client.oidc_par(doc, request, kRedirectUri, std::string("openid_extra"));

    AXIAM_REQUIRE(form_value(last_par_body(*st), "scope") == "openid%20openid_extra");
}

AXIAM_TEST("par: no scope at all still asks for openid") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri);
    client.oidc_par(doc, request, kRedirectUri);

    AXIAM_REQUIRE(form_value(last_par_body(*st), "scope") == "openid");
}

AXIAM_TEST("par: a public client pushes without a secret") {
    // A native app is a public client. It has no secret to send, and an SDK that
    // required one would put PAR — and therefore FAPI 2.0 — out of reach of the
    // clients that most need the request off the browser.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r, /*confidential=*/false);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    client.oidc_par(doc, request, kRedirectUri, "openid");

    AXIAM_REQUIRE_FALSE(contains(last_par_body(*st), "client_secret"));
    AXIAM_REQUIRE(form_value(last_par_body(*st), "client_id") == kClientId);
}

// ---------------------------------------------------------------------------
// §26.2 rule 2 — the redirect carries exactly two parameters
// ---------------------------------------------------------------------------

AXIAM_TEST("par: the redirect URL carries exactly client_id and request_uri") {
    // THE SECURITY ASSERTION OF §26. The server refuses a request that mixes a
    // request_uri with inline authorization parameters rather than merging them:
    // merging is where parameter confusion lives — an attacker supplies the
    // inline value they want and lets the pushed copy satisfy whichever check
    // reads the other one.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid profile");
    const auto pushed = client.oidc_par(doc, request, kRedirectUri, "openid profile");

    const std::size_t q = pushed.url.find('?');
    AXIAM_REQUIRE(q != std::string::npos);
    std::size_t amps = 0;
    for (std::size_t i = q; i < pushed.url.size(); ++i) {
        if (pushed.url[i] == '&') ++amps;
    }
    AXIAM_REQUIRE(amps == 1);  // exactly two parameters
    AXIAM_REQUIRE(contains(pushed.url, std::string("client_id=") + kClientId));
    AXIAM_REQUIRE(contains(pushed.url, "request_uri="));

    // None of the pushed parameters is re-added "for compatibility".
    AXIAM_REQUIRE_FALSE(contains(pushed.url, "scope="));
    AXIAM_REQUIRE_FALSE(contains(pushed.url, "redirect_uri="));
    AXIAM_REQUIRE_FALSE(contains(pushed.url, "state="));
    AXIAM_REQUIRE_FALSE(contains(pushed.url, "nonce="));
    AXIAM_REQUIRE_FALSE(contains(pushed.url, "code_challenge="));
    AXIAM_REQUIRE_FALSE(contains(pushed.url, "response_type="));
}

AXIAM_TEST("par: a pre-existing query on the authorization endpoint is dropped") {
    // The same rule from the other direction: a deployment whose discovered
    // authorization endpoint already carries a query does not get those
    // parameters smuggled into a PAR redirect.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->discovery = kDiscoveryWithQuery;
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    const auto pushed = client.oidc_par(doc, request, kRedirectUri, "openid");

    AXIAM_REQUIRE_FALSE(contains(pushed.url, "ui_locales"));
    AXIAM_REQUIRE_FALSE(contains(pushed.url, "prompt="));
    AXIAM_REQUIRE(contains(pushed.url, "/oauth2/authorize?client_id="));
}

AXIAM_TEST("par: the request_uri is percent-encoded in the redirect") {
    // A `urn:` contains colons; unencoded it is a URL a strict parser rejects
    // and a lenient one truncates.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    const auto pushed = client.oidc_par(doc, request, kRedirectUri, "openid");

    AXIAM_REQUIRE(contains(pushed.url, "request_uri=urn%3Aietf%3A"));
    AXIAM_REQUIRE_FALSE(contains(pushed.url, "request_uri=urn:"));
}

// ---------------------------------------------------------------------------
// §26.2 rule 4 — never retried
// ---------------------------------------------------------------------------

AXIAM_TEST("par: the push is not retried on a 5xx") {
    // A POST that creates server state falls outside §16.2's read-only
    // eligibility exactly as oidc_exchange does. The safe recovery is a FRESH
    // push, which costs one round trip and cannot double-consume anything.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->par_status = 503;
    r->par_body = R"({"error":"server_error"})";
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    AXIAM_REQUIRE_THROWS_AS(client.oidc_par(doc, request, kRedirectUri, "openid"),
                            axiam::AxiamError);
    AXIAM_REQUIRE(r->par_calls == 1);
}

AXIAM_TEST("par: the push is not retried on a transport failure") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->par_transport_fails = true;
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    AXIAM_REQUIRE_THROWS_AS(client.oidc_par(doc, request, kRedirectUri, "openid"),
                            axiam::NetworkError);
    AXIAM_REQUIRE(r->par_calls == 1);
}

AXIAM_TEST("par: an OAuth2 error body is surfaced with its code") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->par_status = 400;
    r->par_body =
        R"({"error":"invalid_request","error_description":"redirect_uri not registered"})";
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    try {
        client.oidc_par(doc, request, kRedirectUri, "openid");
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        AXIAM_REQUIRE(e.error_code() == "invalid_request");
        AXIAM_REQUIRE(contains(e.what(), "redirect_uri not registered"));
    }
}

AXIAM_TEST("par: a response without a request_uri is a failure") {
    // A 201 with no handle is not a successful push with a missing field; there
    // is nothing to redirect with, and returning normally would hand the caller
    // a URL naming an empty request_uri.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->par_body = R"({"expires_in":90})";
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    AXIAM_REQUIRE_THROWS_AS(client.oidc_par(doc, request, kRedirectUri, "openid"),
                            axiam::NetworkError);
}

// ---------------------------------------------------------------------------
// §26.5 / §7 — the handle is a secret for the length of the window
// ---------------------------------------------------------------------------

AXIAM_TEST("par: the request_uri and the verifier do not render") {
    // Between the push and the redirect the handle is a bearer handle to a
    // fully-formed authorization request, and a log line is the wrong place for
    // it to sit for the length of that window.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    const auto pushed = client.oidc_par(doc, request, kRedirectUri, "openid");

    std::ostringstream os;
    os << pushed.request_uri << " " << pushed.code_verifier;
    AXIAM_REQUIRE(os.str() == "[SENSITIVE] [SENSITIVE]");
    // `state` and `nonce` stay readable — the caller has to compare them on
    // return, so wrapping them would make §12.4 rule 6 unimplementable.
    AXIAM_REQUIRE_FALSE(pushed.state.empty());
    AXIAM_REQUIRE_FALSE(pushed.nonce.empty());
}

AXIAM_TEST("par: a failed push never echoes the verifier") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->par_status = 400;
    r->par_body = R"({"error":"invalid_request"})";
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    try {
        client.oidc_par(doc, request, kRedirectUri, "openid");
        AXIAM_REQUIRE(false);
    } catch (const axiam::AxiamError& e) {
        AXIAM_REQUIRE_FALSE(contains(e.what(), axiam::detail::reveal(request.code_verifier)));
    }
}

// ---------------------------------------------------------------------------
// Housekeeping
// ---------------------------------------------------------------------------

AXIAM_TEST("par: an empty redirect_uri is refused with no wire call") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    AXIAM_REQUIRE_THROWS_AS(client.oidc_par(doc, request, "", "openid"), axiam::AuthError);
    AXIAM_REQUIRE(r->par_calls == 0);
}

AXIAM_TEST("par: a closed client refuses the push") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    const auto request = client.oidc_begin(doc, kRedirectUri, "openid");
    client.close();

    AXIAM_REQUIRE_THROWS_AS(client.oidc_par(doc, request, kRedirectUri, "openid"),
                            axiam::NetworkError);
    AXIAM_REQUIRE(r->par_calls == 0);
}

AXIAM_TEST("par: an authorization request with no code_verifier is refused") {
    // PKCE is not optional on this path: without a verifier there is no
    // challenge to push, and a push that omitted it would produce an
    // authorization request the exchange can never complete.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto doc = client.oidc_discover();
    axiam::AuthorizationRequest empty;  // default-constructed: no verifier
    empty.state = "state";
    empty.nonce = "nonce";
    AXIAM_REQUIRE_THROWS_AS(client.oidc_par(doc, empty, kRedirectUri, "openid"),
                            axiam::AuthError);
    AXIAM_REQUIRE(r->par_calls == 0);
}
