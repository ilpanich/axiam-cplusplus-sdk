// CONTRACT.md §28.9's five required tests, plus the regression that matters
// more than all five: with resource_metadata_url unset, nothing changes.
//
// Ported from the TypeScript reference implementation
// (axiam-typescript-sdk@claude/t21-9b-mcp-helpers, test/middleware/mcp.*.test.ts)
// against the SAME fixture §28.9 names, so a divergence between the two SDKs
// shows up as a different expected value rather than as a different test.
//
// C++ has no router and no middleware (§28.3, §28.7): there is no HTTP
// pipeline to drive a real request through, so tests 3-5 exercise the
// operations that would sit behind one directly — AxiamGuard's operator()
// for the 401 path and require_access() for the 403 path — exactly the way
// test_guard.cpp and test_uma_challenge.cpp already test those functions,
// with no real socket anywhere in this suite.
//
//   1. document shape + validation negatives .......... here
//   2. challenge quoting + refusals ..................... here
//   3. 401 with the challenge ........................... here (AxiamGuard)
//   4. 403 insufficient_scope ........................... here (require_access)
//   5. a token whose aud is not the resource ............ here (TokenAuthenticator + AxiamGuard)
//   + the regression that matters more than all five .... here
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>

#include "assert.hpp"
#include "axiam/authenticator.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "axiam/guard.hpp"
#include "axiam/mcp.hpp"
#include "fake_transport.hpp"
#include "test_key.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::json_response;
using axtest::jwks_transport;
using axtest::TestKey;
using json = nlohmann::json;

namespace {

// ---------------------------------------------------------------------------
// §28.9's fixture, quoted verbatim.
// ---------------------------------------------------------------------------

ProtectedResourceMetadataOptions fixture() {
    return ProtectedResourceMetadataOptions{
        "https://mcp.example.com/mcp",
        {"https://axiam.example.com"},
        {"mcp:read", "mcp:tools"},
        {"header"},
        std::string("https://mcp.example.com/docs"),
    };
}

const char* kMetadataPath = "/.well-known/oauth-protected-resource/mcp";
const char* kMetadataUrl = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";
const char* kExpectedAudience = "https://mcp.example.com/mcp";

const std::string kNoCredentialVector =
    std::string("Bearer resource_metadata=\"") + kMetadataUrl + "\"";
const std::string kInvalidTokenVector =
    std::string("Bearer error=\"invalid_token\", resource_metadata=\"") + kMetadataUrl + "\"";
const std::string kInsufficientScopeVector =
    std::string("Bearer error=\"insufficient_scope\", scope=\"mcp:tools\", resource_metadata=\"") +
    kMetadataUrl + "\"";
const std::string kAllFourVector =
    std::string("Bearer error=\"invalid_request\", error_description=\"The access token is "
               "malformed\", scope=\"mcp:read mcp:tools\", resource_metadata=\"") +
    kMetadataUrl + "\"";

template <typename Fn>
bool refuses(Fn&& fn) {
    try {
        fn();
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// §28.9 test 1 — document shape, and the validation negatives
// ---------------------------------------------------------------------------

AXIAM_TEST("mcp: fixture produces the exact §28.2 JSON, parsed") {
    auto metadata = protected_resource_metadata(fixture());

    json parsed = json::parse(metadata.document.to_json());
    json expected = {
        {"resource", "https://mcp.example.com/mcp"},
        {"authorization_servers", json::array({"https://axiam.example.com"})},
        {"scopes_supported", json::array({"mcp:read", "mcp:tools"})},
        {"bearer_methods_supported", json::array({"header"})},
        {"resource_documentation", "https://mcp.example.com/docs"},
    };
    AXIAM_CHECK(parsed == expected);
    AXIAM_CHECK(metadata.metadata_path == kMetadataPath);
    AXIAM_CHECK(metadata.metadata_url == kMetadataUrl);
}

AXIAM_TEST("mcp: derives every metadata_path in §28.3's table") {
    struct Case { const char* resource; const char* path; };
    const Case cases[] = {
        {"https://mcp.example.com", "/.well-known/oauth-protected-resource"},
        {"https://mcp.example.com/", "/.well-known/oauth-protected-resource"},
        {"https://mcp.example.com/mcp", "/.well-known/oauth-protected-resource/mcp"},
        {"https://mcp.example.com/mcp/", "/.well-known/oauth-protected-resource/mcp/"},
        {"https://mcp.example.com/a/b", "/.well-known/oauth-protected-resource/a/b"},
    };
    for (const auto& c : cases) {
        auto options = fixture();
        options.resource = c.resource;
        auto metadata = protected_resource_metadata(options);
        AXIAM_CHECK(metadata.metadata_path == c.path);
        AXIAM_CHECK(metadata.metadata_url == std::string("https://mcp.example.com") + c.path);
        // Nothing is normalised: the fourth row's trailing slash survives.
        AXIAM_CHECK(metadata.document.resource == c.resource);
    }
}

AXIAM_TEST("mcp: refuses a resource that is relative, or carries a fragment or a query") {
    auto relative = fixture(); relative.resource = "/mcp";
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(relative); }));

    auto no_scheme = fixture(); no_scheme.resource = "mcp.example.com/mcp";
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(no_scheme); }));

    auto fragment = fixture(); fragment.resource = "https://mcp.example.com/mcp#tools";
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(fragment); }));

    // §28.3 derives the document's own URL from this value and a query makes
    // that derivation ambiguous — §28 forbids what RFC 8707 permits.
    auto query = fixture(); query.resource = "https://mcp.example.com/mcp?tenant_id=acme";
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(query); }));

    auto empty = fixture(); empty.resource = "";
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(empty); }));
}

AXIAM_TEST("mcp: refuses http on a routable host and accepts it on loopback hosts") {
    auto routable = fixture(); routable.resource = "http://mcp.example.com/mcp";
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(routable); }));

    auto loopback = fixture();
    loopback.resource = "http://127.0.0.1:8080/mcp";
    loopback.authorization_servers = {"http://localhost:9000"};
    auto lb = protected_resource_metadata(loopback);
    AXIAM_CHECK(lb.document.resource == "http://127.0.0.1:8080/mcp");
    AXIAM_CHECK(lb.metadata_url == "http://127.0.0.1:8080/.well-known/oauth-protected-resource/mcp");

    // The carve-out is the HOST, not a substring of it: userinfo merely
    // reading "localhost" resolves to a routable host.
    auto userinfo_trick = fixture();
    userinfo_trick.resource = "http://localhost@evil.example.com/mcp";
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(userinfo_trick); }));

    // [::1] is the third named host, brackets included.
    auto v6 = fixture();
    v6.resource = "http://[::1]:8080/mcp";
    v6.authorization_servers = {"http://[::1]:9000"};
    auto v6r = protected_resource_metadata(v6);
    AXIAM_CHECK(v6r.metadata_url == "http://[::1]:8080/.well-known/oauth-protected-resource/mcp");

    auto other_v6 = fixture();
    other_v6.resource = "http://[2001:db8::1]:8080/mcp";
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(other_v6); }));
}

AXIAM_TEST("mcp: refuses empty authorization_servers, and an entry with a query, fragment or duplicate") {
    auto empty = fixture(); empty.authorization_servers = {};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(empty); }));

    // §28.2 rule 4: the tenant travels as ?tenant_id= on individual endpoints,
    // never on the issuer.
    auto query = fixture(); query.authorization_servers = {"https://axiam.example.com?tenant_id=a"};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(query); }));

    auto frag = fixture(); frag.authorization_servers = {"https://axiam.example.com#frag"};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(frag); }));

    auto dup = fixture();
    dup.authorization_servers = {"https://axiam.example.com", "https://axiam.example.com"};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(dup); }));
}

AXIAM_TEST("mcp: refuses a duplicate scope and a scope outside NQCHAR, preserves caller's order") {
    auto dup = fixture(); dup.scopes_supported = {"mcp:read", "mcp:read"};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(dup); }));

    auto space = fixture(); space.scopes_supported = {"mcp read"};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(space); }));

    auto quote = fixture(); quote.scopes_supported = {"mcp:\"read\""};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(quote); }));

    auto empty_token = fixture(); empty_token.scopes_supported = {""};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(empty_token); }));

    auto reordered = fixture();
    reordered.scopes_supported = {"mcp:tools", "mcp:read"};
    auto r = protected_resource_metadata(reordered);
    AXIAM_REQUIRE(r.document.scopes_supported.size() == 2);
    AXIAM_CHECK(r.document.scopes_supported[0] == "mcp:tools");
    AXIAM_CHECK(r.document.scopes_supported[1] == "mcp:read");
}

AXIAM_TEST("mcp: refuses any bearer_methods_supported that is not exactly [\"header\"]") {
    auto query_method = fixture(); query_method.bearer_methods_supported = {"query"};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(query_method); }));

    auto two = fixture(); two.bearer_methods_supported = {"header", "body"};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(two); }));

    auto none = fixture(); none.bearer_methods_supported = {};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(none); }));

    auto dup = fixture(); dup.bearer_methods_supported = {"header", "header"};
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(dup); }));
}

AXIAM_TEST("mcp: omits scopes_supported when empty, and resource_documentation when absent — never null") {
    ProtectedResourceMetadataOptions bare;
    bare.resource = "https://mcp.example.com/mcp";
    bare.authorization_servers = {"https://axiam.example.com"};
    bare.scopes_supported = {};

    auto metadata = protected_resource_metadata(bare);
    const std::string body = metadata.document.to_json();
    json parsed = json::parse(body);
    json expected = {
        {"resource", "https://mcp.example.com/mcp"},
        {"authorization_servers", json::array({"https://axiam.example.com"})},
        {"bearer_methods_supported", json::array({"header"})},
    };
    AXIAM_CHECK(parsed == expected);
    AXIAM_CHECK_FALSE(parsed.contains("scopes_supported"));
    AXIAM_CHECK_FALSE(parsed.contains("resource_documentation"));
    AXIAM_CHECK(body.find("null") == std::string::npos);
}

AXIAM_TEST("mcp: accepts resource_documentation with a query and a fragment — it is a page, not an identifier") {
    auto with_doc = fixture();
    with_doc.resource_documentation = "https://mcp.example.com/docs?v=2#tools";
    auto metadata = protected_resource_metadata(with_doc);
    AXIAM_REQUIRE(metadata.document.resource_documentation.has_value());
    AXIAM_CHECK(*metadata.document.resource_documentation == "https://mcp.example.com/docs?v=2#tools");

    auto insecure_doc = fixture();
    insecure_doc.resource_documentation = "http://docs.example.com/mcp";
    AXIAM_CHECK(refuses([&] { protected_resource_metadata(insecure_doc); }));
}

// ---------------------------------------------------------------------------
// §28.9 test 2 — the challenge and its quoting
// ---------------------------------------------------------------------------

AXIAM_TEST("mcp: produces §28.4's four vectors as exact strings") {
    AXIAM_CHECK(bearer_challenge({kMetadataUrl, std::nullopt, std::nullopt, std::nullopt}) ==
               kNoCredentialVector);

    AXIAM_CHECK(bearer_challenge({kMetadataUrl, BearerChallengeError::kInvalidToken, std::nullopt,
                                 std::nullopt}) == kInvalidTokenVector);

    AXIAM_CHECK(bearer_challenge({kMetadataUrl, BearerChallengeError::kInsufficientScope,
                                 std::nullopt, std::string("mcp:tools")}) ==
               kInsufficientScopeVector);

    // Fixed order — error, error_description, scope, resource_metadata — and
    // exactly ", " between parameters.
    AXIAM_CHECK(bearer_challenge({kMetadataUrl, BearerChallengeError::kInvalidRequest,
                                 std::string("The access token is malformed"),
                                 std::string("mcp:read mcp:tools")}) == kAllFourVector);
}

// Note: there is no test here for "an error code RFC 6750 §3.1 does not
// define" (T9b's mcp.contract.test.ts asserts `bearerChallenge` refuses
// "invalid_grant" at runtime). In this SDK `error` is `BearerChallengeError`,
// a scoped enum with exactly RFC 6750 §3.1's three values — the type system
// makes an undefined error code impossible to express at all, which is
// stronger than refusing it at runtime. See the PR description.

AXIAM_TEST("mcp: refuses rather than escapes an error_description outside NQSCHAR") {
    // "a control" carries a literal embedded NUL between "a" and "control"
    // (matching the TS reference suite's `'a\0control'`, which a plain-text
    // read renders invisibly) — the explicit-length constructor is what keeps
    // it from being truncated at the NUL the way a `const char*` conversion
    // would.
    const std::string bad_descriptions[] = {
        "he said \"no\"", "a back\\slash", "two\nlines", std::string("a\0control", 9),
        "non-ASCII: caf\xC3\xA9", "",
    };
    for (const auto& description : bad_descriptions) {
        bool threw = false;
        try {
            bearer_challenge({kMetadataUrl, BearerChallengeError::kInvalidRequest, description,
                             std::nullopt});
        } catch (const std::invalid_argument& e) {
            threw = true;
            // No escaping occurred: the refusal is an exception, never a
            // challenge carrying \".
            AXIAM_CHECK(std::string(e.what()).find("\\\"") == std::string::npos);
        }
        AXIAM_CHECK(threw);
    }
}

AXIAM_TEST("mcp: refuses a scope with a leading, trailing or doubled space, or an empty one") {
    const std::string bad_scopes[] = {" mcp:read", "mcp:read ", "mcp:read  mcp:tools", "", " ",
                                      "mcp:\"read\""};
    for (const auto& scope : bad_scopes) {
        AXIAM_CHECK(refuses([&] {
            bearer_challenge(
                {kMetadataUrl, BearerChallengeError::kInsufficientScope, std::nullopt, scope});
        }));
    }
}

AXIAM_TEST("mcp: refuses a resource_metadata that is not an encoded absolute URL") {
    const std::string bad_urls[] = {
        "https://mcp.example.com/.well-known/oauth protected resource",
        "https://mcp.example.com/\"quoted\"",
        "https://mcp.example.com/back\\slash",
        "/.well-known/oauth-protected-resource/mcp",
        "http://mcp.example.com/.well-known/oauth-protected-resource/mcp",
    };
    for (const auto& url : bad_urls) {
        AXIAM_CHECK(refuses([&] { bearer_challenge({url, std::nullopt, std::nullopt, std::nullopt}); }));
    }

    // MAY carry a query and a fragment, unlike the resource identifier.
    const std::string with_query = std::string(kMetadataUrl) + "?v=2#x";
    AXIAM_CHECK(bearer_challenge({with_query, std::nullopt, std::nullopt, std::nullopt}) ==
               "Bearer resource_metadata=\"" + with_query + "\"");
}

// ---------------------------------------------------------------------------
// §28.9 test 3 — 401 with the challenge (AxiamGuard; no HTTP pipeline exists
// to drive in this SDK, so the guard's own operator() is what is asserted —
// see the file header)
// ---------------------------------------------------------------------------

namespace {

/// A minimal framework-agnostic "request": just the bearer credential a real
/// adapter would have already pulled out of the Authorization header.
struct FakeRequest {
    std::optional<std::string> bearer;
};

constexpr std::int64_t kNow = 1785700000;
const char* kTenant = "11111111-1111-1111-1111-111111111111";

AuthenticatorOptions mcp_options(std::int64_t now = kNow) {
    AuthenticatorOptions opts;
    opts.now = [now] { return now; };
    opts.expected_audience = kExpectedAudience;
    opts.resource_metadata_url = kMetadataUrl;
    return opts;
}

std::string claims(const std::string& extra) {
    return std::string("{\"sub\":\"user-1\",\"tenant_id\":\"") + kTenant + "\"," + extra + "}";
}

using FakeGuard = AxiamGuard<FakeRequest>;

FakeGuard::Authenticator extractor(const TokenAuthenticator& auth) {
    return auth.guard_authenticator<FakeRequest>(
        [](const FakeRequest& r) { return r.bearer; });
}

FakeGuard::CredentialProbe probe() {
    return [](const FakeRequest& r) { return r.bearer.has_value(); };
}

}  // namespace

AXIAM_TEST("mcp: a request with no credential answers vector 1") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, mcp_options());

    FakeGuard guard(extractor(auth), auth.mcp_challenges(), probe());

    bool threw = false;
    try {
        guard(FakeRequest{std::nullopt});
    } catch (const AuthChallengeError& e) {
        threw = true;
        AXIAM_CHECK(e.challenge() == kNoCredentialVector);
        // No error= parameter: no credential is not a bad credential.
        AXIAM_CHECK(e.challenge().find("error=") == std::string::npos);
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("mcp: a rejected credential (expired) answers vector 2, and says nothing else about why") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, mcp_options());
    FakeGuard guard(extractor(auth), auth.mcp_challenges(), probe());

    const std::string expired = key.make_jwt(
        "EdDSA", claims("\"exp\":" + std::to_string(kNow - 3600) + ",\"aud\":\"" +
                        kExpectedAudience + "\""));

    bool threw = false;
    try {
        guard(FakeRequest{expired});
    } catch (const AuthChallengeError& e) {
        threw = true;
        AXIAM_CHECK(e.challenge() == kInvalidTokenVector);
        AXIAM_CHECK(e.challenge().find("error_description") == std::string::npos);
        AXIAM_CHECK(e.challenge().find("expired") == std::string::npos);
        AXIAM_CHECK(std::string(e.what()).find(expired) == std::string::npos);
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("mcp: admits a valid, correctly-audienced credential") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, mcp_options());
    FakeGuard guard(extractor(auth), auth.mcp_challenges(), probe());

    const std::string token = key.make_jwt(
        "EdDSA", claims("\"exp\":" + std::to_string(kNow + 900) + ",\"aud\":\"" +
                        kExpectedAudience + "\""));

    AxiamUser user = guard(FakeRequest{token});
    AXIAM_CHECK(user.user_id == "user-1");
}

AXIAM_TEST("mcp: is_metadata_document_request exempts exactly the derived path, GET and HEAD only") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, mcp_options());

    AXIAM_CHECK(is_metadata_document_request(auth.mcp_challenges(), "GET", kMetadataPath));
    AXIAM_CHECK(is_metadata_document_request(auth.mcp_challenges(), "HEAD", kMetadataPath));
    AXIAM_CHECK(is_metadata_document_request(auth.mcp_challenges(), "GET",
                                             std::string(kMetadataPath) + "?x=1"));
    AXIAM_CHECK_FALSE(is_metadata_document_request(auth.mcp_challenges(), "POST", kMetadataPath));
    AXIAM_CHECK_FALSE(is_metadata_document_request(auth.mcp_challenges(), "GET", "/mcp"));
}

// ---------------------------------------------------------------------------
// §28.9 test 4 — 403 insufficient_scope (require_access)
// ---------------------------------------------------------------------------

namespace {

Client denial_client(std::shared_ptr<FakeState> st, const std::string& decision_json) {
    st->router = [decision_json](const HttpRequest&, FakeState&) {
        return json_response(200, decision_json);
    };
    return Client::builder()
        .base_url("https://api.example.test")
        .tenant_slug("acme")
        .transport(axtest::make_fake(std::move(st)))
        .build();
}

std::optional<McpChallenges> fixture_challenges() {
    return mcp_challenges(kMetadataUrl, kExpectedAudience);
}

}  // namespace

AXIAM_TEST("mcp: a no_grant denial with a scope answers vector 3, message unchanged") {
    auto st = std::make_shared<FakeState>();
    auto client = denial_client(st, R"({"allowed":false,"reason_code":"no_grant"})");
    std::optional<AxiamUser> user = AxiamUser{"u-1", "acme", {}};

    bool threw = false;
    try {
        require_access(client, user, "mcp:invoke", "tool-1", fixture_challenges(),
                       std::string("mcp:tools"));
    } catch (const AuthzChallengeError& e) {
        threw = true;
        AXIAM_CHECK(e.challenge() == kInsufficientScopeVector);
        // The message/body taxonomy does not change: insufficient_scope
        // appears ONLY inside the challenge value.
        AXIAM_CHECK(std::string(e.what()) == "authorization_denied");
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("mcp: names the scope the route asked for, verbatim") {
    auto st = std::make_shared<FakeState>();
    auto client = denial_client(st, R"({"allowed":false,"reason_code":"no_grant"})");
    std::optional<AxiamUser> user = AxiamUser{"u-1", "acme", {}};

    try {
        require_access(client, user, "mcp:invoke", "tool-1", fixture_challenges(),
                       std::string("urn:example:tools.invoke"));
    } catch (const AuthzChallengeError& e) {
        AXIAM_CHECK(e.challenge() ==
                   std::string("Bearer error=\"insufficient_scope\", "
                               "scope=\"urn:example:tools.invoke\", resource_metadata=\"") +
                       kMetadataUrl + "\"");
        return;
    }
    AXIAM_CHECK(false && "expected AuthzChallengeError");
}

AXIAM_TEST("mcp: carries no challenge on denied_by_rule, an absent/unrecognised reason_code, or no scope") {
    auto by_rule_client = [] {
        auto st = std::make_shared<FakeState>();
        return denial_client(st, R"({"allowed":false,"reason_code":"denied_by_rule"})");
    }();
    std::optional<AxiamUser> user = AxiamUser{"u-1", "acme", {}};

    auto assert_plain = [&](Client& c, std::optional<std::string> scope) {
        try {
            require_access(c, user, "mcp:invoke", "tool-1", fixture_challenges(), std::move(scope));
        } catch (const AuthzChallengeError&) {
            AXIAM_CHECK(false && "denied_by_rule/absent/unknown reason_code must not challenge");
            return;
        } catch (const AuthzError&) {
            return;  // expected: plain AuthzError
        }
        AXIAM_CHECK(false && "expected AuthzError");
    };

    assert_plain(by_rule_client, std::string("mcp:tools"));

    auto no_code_client_st = std::make_shared<FakeState>();
    auto no_code_client = denial_client(no_code_client_st, R"({"allowed":false})");
    assert_plain(no_code_client, std::string("mcp:tools"));

    auto unknown_client_st = std::make_shared<FakeState>();
    auto unknown_client =
        denial_client(unknown_client_st, R"({"allowed":false,"reason_code":"quota_exhausted"})");
    assert_plain(unknown_client, std::string("mcp:tools"));

    auto no_grant_st = std::make_shared<FakeState>();
    auto no_grant_client = denial_client(no_grant_st, R"({"allowed":false,"reason_code":"no_grant"})");
    assert_plain(no_grant_client, std::nullopt);  // no scope argument: nothing to name
}

AXIAM_TEST("mcp: touches no other response — an allow gains nothing") {
    auto st = std::make_shared<FakeState>();
    auto client = denial_client(st, R"({"allowed":true,"reason_code":"allowed"})");
    std::optional<AxiamUser> user = AxiamUser{"u-1", "acme", {}};

    AXIAM_REQUIRE_NOTHROW(require_access(client, user, "mcp:invoke", "tool-1", fixture_challenges(),
                                        std::string("mcp:tools")));
}

// ---------------------------------------------------------------------------
// §28.9 test 5 — a token whose aud is not the resource is refused
// ---------------------------------------------------------------------------

AXIAM_TEST("mcp: refuses a token minted for another resource server, identically to axiam:user") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, mcp_options());
    FakeGuard guard(extractor(auth), auth.mcp_challenges(), probe());

    const std::string other_resource = key.make_jwt(
        "EdDSA",
        claims("\"exp\":" + std::to_string(kNow + 900) + ",\"aud\":\"https://other.example.com/mcp\""));
    const std::string generic_user = key.make_jwt(
        "EdDSA", claims("\"exp\":" + std::to_string(kNow + 900) + ",\"aud\":\"axiam:user\""));

    for (const auto& token : {other_resource, generic_user}) {
        bool threw = false;
        try {
            guard(FakeRequest{token});
        } catch (const AuthChallengeError& e) {
            threw = true;
            // Indistinguishable from any other rejected credential — that is
            // the point: an implementation that told them apart would leak
            // whether a foreign-but-valid AXIAM token exists.
            AXIAM_CHECK(e.challenge() == kInvalidTokenVector);
        }
        AXIAM_CHECK(threw);
    }
}

AXIAM_TEST("mcp: refuses at construction when resource_metadata_url is set with no expected_audience") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");

    AuthenticatorOptions half_configured;
    half_configured.resource_metadata_url = kMetadataUrl;
    // expected_audience left unset — the impossible configuration §28.5
    // rule 2 names.

    bool threw = false;
    try {
        TokenAuthenticator broken(v, kTenant, half_configured);
    } catch (const std::invalid_argument& e) {
        threw = true;
        const std::string message = e.what();
        AXIAM_CHECK(message.find("resource_metadata_url") != std::string::npos);
        AXIAM_CHECK(message.find("expected_audience") != std::string::npos);
    }
    AXIAM_CHECK(threw);
}

// ---------------------------------------------------------------------------
// The regression that matters more than all five: §28 off is byte-for-byte
// unchanged.
// ---------------------------------------------------------------------------

AXIAM_TEST("mcp off: AxiamGuard's single-argument constructor never carries a challenge") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    AuthenticatorOptions plain;
    plain.now = [] { return kNow; };
    TokenAuthenticator auth(v, kTenant, plain);

    AXIAM_CHECK_FALSE(auth.mcp_challenges().has_value());

    FakeGuard guard(extractor(auth));  // the pre-existing, single-argument constructor

    bool threw = false;
    try {
        guard(FakeRequest{std::nullopt});
    } catch (const AuthError& e) {
        threw = true;
        // Plain AuthError, not the §28 subtype — the exact exception this
        // guard threw before §28 existed.
        AXIAM_CHECK(dynamic_cast<const AuthChallengeError*>(&e) == nullptr);
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("mcp off: the §28 constructor with std::nullopt challenges behaves identically") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    AuthenticatorOptions plain;
    plain.now = [] { return kNow; };
    TokenAuthenticator auth(v, kTenant, plain);

    FakeGuard guard(extractor(auth), auth.mcp_challenges(), probe());  // challenges is nullopt here

    bool threw = false;
    try {
        guard(FakeRequest{std::nullopt});
    } catch (const AuthError& e) {
        threw = true;
        AXIAM_CHECK(dynamic_cast<const AuthChallengeError*>(&e) == nullptr);
    }
    AXIAM_CHECK(threw);
    // §28 off exempts no path.
    AXIAM_CHECK_FALSE(is_metadata_document_request(guard.mcp_challenges(), "GET", kMetadataPath));
}

AXIAM_TEST("mcp off: require_access's plain overload is untouched by the §28 overload's existence") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"allowed":false,"reason_code":"no_grant"})");
    };
    Client c = Client::builder()
                  .base_url("https://api.example.test")
                  .tenant_slug("acme")
                  .transport(axtest::make_fake(st))
                  .build();
    std::optional<AxiamUser> user = AxiamUser{"u-1", "acme", {}};

    // The two-argument-scope overload from BEFORE §28 existed: no way to
    // reach a challenge at all.
    AXIAM_REQUIRE_THROWS_AS(
        require_access(c, user, "mcp:invoke", "tool-1", std::string("mcp:tools")), AuthzError);
}

// ---------------------------------------------------------------------------
// §28.5 rule 3 — the cross-check between a guard's configuration and the
// document it should describe, for a deployment where an adapter can see
// both (documented for the Crow/Pistache adapters in README.md).
// ---------------------------------------------------------------------------

AXIAM_TEST("mcp: check_mcp_configuration_matches refuses a mismatched resource_metadata_url or expected_audience") {
    auto metadata = protected_resource_metadata(fixture());

    auto wrong_url = mcp_challenges(std::string(kMetadataUrl) + "/", kExpectedAudience);
    AXIAM_CHECK(refuses([&] {
        check_mcp_configuration_matches(std::optional<McpChallenges>(wrong_url), metadata);
    }));

    // These are DIFFERENT strings — the resource vs. the metadata URL — and
    // each must be compared against its own counterpart.
    auto wrong_audience = mcp_challenges(kMetadataUrl, std::string(kExpectedAudience) + "/");
    AXIAM_CHECK(refuses([&] {
        check_mcp_configuration_matches(std::optional<McpChallenges>(wrong_audience), metadata);
    }));

    auto matching = mcp_challenges(kMetadataUrl, kExpectedAudience);
    AXIAM_REQUIRE_NOTHROW(
        check_mcp_configuration_matches(std::optional<McpChallenges>(matching), metadata));

    // §28 off: nothing to cross-check, never throws.
    AXIAM_REQUIRE_NOTHROW(check_mcp_configuration_matches(std::nullopt, metadata));
}
