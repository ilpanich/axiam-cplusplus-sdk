// RFC 8705 §5 `mtls_endpoint_aliases` — CONTRACT.md §21.3 rule 2 (contract 1.40).
//
// The rule has one sentence and three named ways to get it wrong, and this file
// is organised around them rather than around the SDK's method list:
//
//   - a call going over mTLS prefers the alias;
//   - a call NOT going over mTLS keeps the top-level entry;
//   - an ABSENT member means "no separate mTLS host", never "unsupported";
//   - only the six listed endpoints are ever aliased — not
//     `authorization_endpoint`, `end_session_endpoint` or `jwks_uri`;
//   - `issuer` is not an endpoint, does not move, and still governs `iss`
//     validation by exact string.
//
// The fake transport routes by path and RECORDS THE FULL URL, so choosing the
// wrong host is a recorded call the assertion can name. The §6.1 identity is a
// PEM-shaped pair on the builder: no handshake ever runs against it, and none
// needs to — what is under test is WHICH URL the SDK builds, which the
// configured identity and the document decide, not the socket.

#include <memory>
#include <mutex>
#include <string>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"

namespace {

const char* kTenantUuid = "22222222-2222-2222-2222-222222222222";
const char* kClientId = "example-rp";
const char* kClientSecret = "example-secret";
const char* kIssuer = "https://issuer.test";
const char* kBase = "https://iam.example.com";
const char* kMtlsBase = "https://mtls.iam.example.com";

// A PEM-shaped placeholder pair. `with_client_cert` checks the shape and stores
// the bytes; the fake transport never opens a socket, so no real key material is
// needed — and deliberately none is present.
const char* kCertPem =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBkTCB+wIJAKZ0000000000MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n"
    "-----END CERTIFICATE-----\n";
const char* kKeyPem =
    "-----BEGIN AXIAM TEST PLACEHOLDER-----\n"
    "bm90LWtleS1tYXRlcmlhbA==\n"
    "-----END AXIAM TEST PLACEHOLDER-----\n";

// The conventional document, plus all six aliases on the mTLS host.
const char* kDiscoveryWithAliases = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "introspection_endpoint":"https://iam.example.com/oauth2/introspect",
  "revocation_endpoint":"https://iam.example.com/oauth2/revoke",
  "end_session_endpoint":"https://iam.example.com/oauth2/end_session",
  "device_authorization_endpoint":"https://iam.example.com/oauth2/device_authorization",
  "pushed_authorization_request_endpoint":"https://iam.example.com/oauth2/par",
  "mtls_endpoint_aliases":{
    "token_endpoint":"https://mtls.iam.example.com/oauth2/token",
    "userinfo_endpoint":"https://mtls.iam.example.com/oauth2/userinfo",
    "revocation_endpoint":"https://mtls.iam.example.com/oauth2/revoke",
    "introspection_endpoint":"https://mtls.iam.example.com/oauth2/introspect",
    "device_authorization_endpoint":"https://mtls.iam.example.com/oauth2/device_authorization",
    "pushed_authorization_request_endpoint":"https://mtls.iam.example.com/oauth2/par"
  }
})";

// The same document with no aliases at all — the shape a single-listener
// deployment (including `client_auth = optional`) correctly publishes.
const char* kDiscoveryWithoutAliases = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "introspection_endpoint":"https://iam.example.com/oauth2/introspect",
  "revocation_endpoint":"https://iam.example.com/oauth2/revoke",
  "end_session_endpoint":"https://iam.example.com/oauth2/end_session",
  "device_authorization_endpoint":"https://iam.example.com/oauth2/device_authorization",
  "pushed_authorization_request_endpoint":"https://iam.example.com/oauth2/par"
})";

// An object naming ONLY token_endpoint — which RFC 8705 §5 permits.
const char* kDiscoveryPartialAliases = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "introspection_endpoint":"https://iam.example.com/oauth2/introspect",
  "revocation_endpoint":"https://iam.example.com/oauth2/revoke",
  "mtls_endpoint_aliases":{
    "token_endpoint":"https://mtls.iam.example.com/oauth2/token"
  }
})";

// Aliases published, but NEITHER level names the device endpoint.
const char* kDiscoveryNoDeviceEndpoint = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "mtls_endpoint_aliases":{
    "token_endpoint":"https://mtls.iam.example.com/oauth2/token"
  }
})";

// A relative alias — vector C's first defect.
const char* kDiscoveryRelativeAlias = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "mtls_endpoint_aliases":{
    "token_endpoint":"/oauth2/token"
  }
})";

// An http alias standing in for an https endpoint — vector C's second defect.
// Every other fixture in this file pairs https with https, so this pair plus
// the http/http one below are what separate "must be https" from "must not be
// weaker than what it replaces".
const char* kDiscoveryDowngradeAlias = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "mtls_endpoint_aliases":{
    "token_endpoint":"http://mtls.iam.example.com/oauth2/token"
  }
})";

// A development deployment: http alias for an http endpoint, which AXIAM's own
// build_mtls_aliases supports and which must keep working.
const char* kDiscoveryHttpForHttp = R"({
  "issuer":"http://issuer.test",
  "authorization_endpoint":"http://iam.example.com/oauth2/authorize",
  "token_endpoint":"http://iam.example.com/oauth2/token",
  "jwks_uri":"http://iam.example.com/oauth2/jwks",
  "mtls_endpoint_aliases":{
    "token_endpoint":"http://mtls.iam.example.com/oauth2/token"
  }
})";

// One malformed alias among well-formed ones: the refusal must be per endpoint.
const char* kDiscoveryOneBadAlias = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "introspection_endpoint":"https://iam.example.com/oauth2/introspect",
  "mtls_endpoint_aliases":{
    "token_endpoint":"https://mtls.iam.example.com/oauth2/token",
    "introspection_endpoint":"not-a-url-at-all"
  }
})";

struct Fixture {
    std::shared_ptr<axtest::FakeState> st = std::make_shared<axtest::FakeState>();
    const char* discovery = kDiscoveryWithAliases;
};

axiam::Transport routed(Fixture& f) {
    const char* discovery = f.discovery;
    f.st->router = [discovery](const axiam::HttpRequest& req,
                               axtest::FakeState&) -> axiam::HttpResponse {
        const std::string& url = req.url;
        axiam::HttpResponse resp;
        resp.status = 200;
        if (url.find("openid-configuration") != std::string::npos) {
            resp.body = discovery;
        } else if (url.find("/oauth2/jwks") != std::string::npos) {
            resp.body = R"({"keys":[]})";
        } else if (url.find("/oauth2/device_authorization") != std::string::npos) {
            resp.body =
                R"({"device_code":"d","user_code":"WDJB-MJHT",)"
                R"("verification_uri":"https://id.test/device","expires_in":30,"interval":1})";
        } else if (url.find("/oauth2/par") != std::string::npos) {
            // RFC 9126 §2.2 answers Created, and the SDK asserts exactly that.
            resp.status = 201;
            resp.body = R"({"request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":60})";
        } else if (url.find("/oauth2/introspect") != std::string::npos) {
            resp.body = R"({"active":true})";
        } else if (url.find("/oauth2/revoke") != std::string::npos) {
            resp.body = "{}";
        } else if (url.find("/oauth2/token") != std::string::npos) {
            resp.body = R"({"access_token":"a","token_type":"Bearer","expires_in":900})";
        } else {
            resp.status = 404;
            resp.body = "{}";
        }
        return resp;
    };
    return axtest::make_fake(f.st);
}

axiam::Client make_client(Fixture& f, bool mtls) {
    auto builder = axiam::Client::builder()
                       .base_url(kBase)
                       .tenant_slug("acme")
                       .tenant_id(kTenantUuid)
                       .oidc_client_id(kClientId)
                       .oidc_client_secret(kClientSecret)
                       .transport(routed(f));
    if (mtls) builder.with_client_cert(kCertPem, kKeyPem);
    return builder.build();
}

/// The host of the most recent request whose URL contains `needle`.
std::string host_of_last_call(axtest::FakeState& st, const std::string& needle) {
    std::lock_guard<std::mutex> lock(st.mtx);
    for (auto it = st.requests.rbegin(); it != st.requests.rend(); ++it) {
        if (it->url.find(needle) == std::string::npos) continue;
        return it->url.rfind(kMtlsBase, 0) == 0 ? kMtlsBase : kBase;
    }
    return {};
}

}  // namespace

// ── The document round-trips the member ────────────────────────────────────

AXIAM_TEST("§21.3 rule 2 discovery exposes the member when the server publishes it") {
    Fixture f;
    auto client = make_client(f, /*mtls=*/false);

    const auto config = client.oidc_discover();

    AXIAM_REQUIRE(config.mtls_endpoint_aliases.has_value());
    AXIAM_REQUIRE(config.mtls_endpoint_aliases->token_endpoint ==
                  std::string(kMtlsBase) + "/oauth2/token");
    // Alongside, never instead of: the conventional entry is untouched.
    AXIAM_REQUIRE(config.token_endpoint == std::string(kBase) + "/oauth2/token");
}

AXIAM_TEST("§21.3 rule 2 an absent member parses to nullopt rather than failing") {
    Fixture f;
    f.discovery = kDiscoveryWithoutAliases;
    auto client = make_client(f, /*mtls=*/true);

    const auto config = client.oidc_discover();

    AXIAM_REQUIRE(!config.mtls_endpoint_aliases.has_value());
}

// ── A call over mTLS prefers the alias ─────────────────────────────────────

AXIAM_TEST("§21.3 rule 2 every aliasable endpoint goes to the alias host") {
    Fixture f;
    auto client = make_client(f, /*mtls=*/true);

    client.login_client_credentials();
    client.introspect(axiam::Sensitive<std::string>("t"));
    client.revoke(axiam::Sensitive<std::string>("t"));
    client.device_authorize();
    const auto config = client.oidc_discover();
    const auto request = client.oidc_begin(config, "https://app.example.com/cb");
    client.oidc_par(config, request, "https://app.example.com/cb");

    for (const char* path : {"/oauth2/token", "/oauth2/introspect", "/oauth2/revoke",
                             "/oauth2/device_authorization", "/oauth2/par"}) {
        AXIAM_REQUIRE(host_of_last_call(*f.st, path) == kMtlsBase);
    }
}

// ── Consequence 1: absence means "no separate host" ────────────────────────

AXIAM_TEST("§21.3 rule 2 an mTLS client with no aliases keeps the top-level endpoints") {
    Fixture f;
    f.discovery = kDiscoveryWithoutAliases;
    auto client = make_client(f, /*mtls=*/true);

    // Not an error, and not the alias origin: a deployment running
    // `client_auth = optional` on one listener serves both populations at the
    // conventional endpoints and correctly publishes nothing.
    client.introspect(axiam::Sensitive<std::string>("t"));

    AXIAM_REQUIRE(host_of_last_call(*f.st, "/oauth2/introspect") == kBase);
}

AXIAM_TEST("§21.3 rule 2 a client not doing mTLS keeps the top-level endpoints") {
    Fixture f;
    auto client = make_client(f, /*mtls=*/false);

    client.revoke(axiam::Sensitive<std::string>("t"));

    AXIAM_REQUIRE(host_of_last_call(*f.st, "/oauth2/revoke") == kBase);
}

AXIAM_TEST("§21.3 rule 2 a partial alias object falls back per endpoint") {
    // RFC 8705 §5 does not require an OP to alias all six, and the shape of this
    // member must never be why a client stops working: an object naming only
    // token_endpoint is a valid document, and every endpoint it does not name
    // falls back to the top-level entry.
    Fixture f;
    f.discovery = kDiscoveryPartialAliases;
    auto client = make_client(f, /*mtls=*/true);

    client.login_client_credentials();
    client.introspect(axiam::Sensitive<std::string>("t"));

    AXIAM_REQUIRE(host_of_last_call(*f.st, "/oauth2/token") == kMtlsBase);
    AXIAM_REQUIRE(host_of_last_call(*f.st, "/oauth2/introspect") == kBase);
}

AXIAM_TEST("§21.3 rule 2 an unsupported grant is still reported when neither level names it") {
    Fixture f;
    f.discovery = kDiscoveryNoDeviceEndpoint;
    auto client = make_client(f, /*mtls=*/true);

    // Neither level names the endpoint, so the answer is still "this server does
    // not support the device grant" — never a URL built by concatenation.
    AXIAM_REQUIRE_THROWS_AS(client.device_authorize(), axiam::NetworkError);
    AXIAM_REQUIRE(host_of_last_call(*f.st, "/oauth2/device_authorization").empty());
}

// ── Consequence 2: no alias is ever synthesised ────────────────────────────

AXIAM_TEST("§21.3 rule 2 the front-channel and jwks endpoints are never aliased") {
    Fixture f;
    auto client = make_client(f, /*mtls=*/true);
    const auto config = client.oidc_discover();

    // A browser sent to an mTLS host raises a native certificate-chooser dialog
    // most users cannot answer, and jwks_uri is public key material that gains
    // nothing from a handshake.
    const auto request = client.oidc_begin(config, "https://app.example.com/cb");
    AXIAM_REQUIRE(request.url.rfind(std::string(kBase) + "/oauth2/authorize", 0) == 0);

    const auto logout = axiam::logout_url(config, "not-a-real-token");
    AXIAM_REQUIRE(logout.has_value());
    AXIAM_REQUIRE(logout->rfind(std::string(kBase) + "/oauth2/end_session", 0) == 0);

    AXIAM_REQUIRE(config.jwks_uri == std::string(kBase) + "/oauth2/jwks");
}

// ── Consequence 3: issuer is never aliased ─────────────────────────────────

AXIAM_TEST("§21.3 rule 2 the issuer does not move with the endpoints") {
    Fixture f;
    auto client = make_client(f, /*mtls=*/true);

    const auto config = client.oidc_discover();

    // §12.4 rule 3 compares `iss` against THIS value by exact string, for every
    // token — including one minted at an alias endpoint. An SDK that derived an
    // expected issuer from the host it called would reject every token it
    // obtains over mTLS.
    AXIAM_REQUIRE(config.issuer == kIssuer);
    AXIAM_REQUIRE(config.issuer != std::string(kMtlsBase));
}


// ── Vector C: a malformed alias is refused, never fallen back from ─────────
//
// CONTRACT.md §21.3.1 vector C, contract 1.43. Rule 2 had been normative since
// 1.40 and, until the 2026-09-12 pass, said nothing about an alias that is
// PRESENT and unusable — every SDK that read the member fell back to the
// top-level endpoint. Falling back looks like the safe answer and is the
// dangerous one: the caller asked to authenticate with a certificate, the
// operator published something unusable, and sending the certificate to the
// front-channel host authenticates nothing while appearing to work.

AXIAM_TEST("§21.3.1 vector C a relative alias is refused rather than resolved") {
    // A relative alias resolves against nothing the client holds, and the base
    // that might seem obvious — the issuer's host — is precisely the host the
    // alias exists to name a different one from.
    Fixture f;
    f.discovery = kDiscoveryRelativeAlias;
    auto client = make_client(f, /*mtls=*/true);

    // AuthError, not NetworkError: §16.3 retries NetworkError and only
    // NetworkError, so the other choice would have attempted a permanent,
    // deterministic misconfiguration three times.
    AXIAM_REQUIRE_THROWS_AS(client.login_client_credentials(), axiam::AuthError);

    // And the certificate never reached the conventional host, which is the
    // whole point of refusing rather than falling back.
    AXIAM_REQUIRE(host_of_last_call(*f.st, "/oauth2/token").empty());
}

AXIAM_TEST("§21.3.1 vector C a scheme downgrade is refused") {
    // The comparison is like with like: the alias substitutes for exactly one
    // top-level endpoint, and that endpoint's scheme is what a downgrade is
    // measured against.
    Fixture f;
    f.discovery = kDiscoveryDowngradeAlias;
    auto client = make_client(f, /*mtls=*/true);

    AXIAM_REQUIRE_THROWS_AS(client.login_client_credentials(), axiam::AuthError);
}

AXIAM_TEST("§21.3.1 vector C an http alias for an http endpoint is accepted") {
    // The I4 twin of the downgrade refusal, and the reason the rule compares
    // like with like rather than demanding https outright: this is a
    // development deployment, which AXIAM's own build_mtls_aliases supports. A
    // rule written as "the scheme must be https" would have refused it.
    Fixture f;
    f.discovery = kDiscoveryHttpForHttp;
    auto client = make_client(f, /*mtls=*/true);

    client.login_client_credentials();

    // Asserted on the URL rather than through host_of_last_call, which knows
    // only the two https origins the rest of this file uses: the whole point
    // here is that the origin is the http one.
    std::lock_guard<std::mutex> lock(f.st->mtx);
    bool reached_the_alias = false;
    for (const auto& request : f.st->requests) {
        if (request.url.rfind("http://mtls.iam.example.com/oauth2/token", 0) == 0) {
            reached_the_alias = true;
        }
    }
    AXIAM_REQUIRE(reached_the_alias);
}

AXIAM_TEST("§21.3.1 vector C a malformed alias cannot break a client not doing mTLS") {
    // The second I4 twin, and the more important one: a client with no
    // certificate never reads the member at all, not even to validate it. A
    // deployment whose aliases are malformed cannot break the clients that
    // never use them.
    Fixture f;
    f.discovery = kDiscoveryRelativeAlias;
    auto client = make_client(f, /*mtls=*/false);

    client.login_client_credentials();

    AXIAM_REQUIRE(host_of_last_call(*f.st, "/oauth2/token") == kBase);
}

AXIAM_TEST("§21.3.1 vector C one malformed alias does not poison the others") {
    // Per endpoint, like the fallback itself: one malformed alias stops the
    // calls that would have used it and leaves every other endpoint working.
    Fixture f;
    f.discovery = kDiscoveryOneBadAlias;
    auto client = make_client(f, /*mtls=*/true);

    client.login_client_credentials();
    AXIAM_REQUIRE(host_of_last_call(*f.st, "/oauth2/token") == kMtlsBase);

    AXIAM_REQUIRE_THROWS_AS(client.introspect(axiam::Sensitive<std::string>("t")),
                            axiam::AuthError);
}
