// CONTRACT.md §37 (contract 1.65) — native sign-in with a provider ID token, the
// optional `idp_hint` of §12.1 / §26.2 rule 8, and the §9 refresh-reuse confirmation.
//
// §37 is a list of things the helper must NOT do, so most of these assert an absence from the
// wire: no hash where the raw nonce belongs, no `openid` the caller did not name, no second
// request after a refusal, no provider lookup, no secret in an error. The tests therefore read
// the RECORDED requests rather than the return value, and assert on the FULL key set of a form
// rather than on the presence of the keys the test expects.
//
// Test names are §37.9's, so the eleven SDKs' suites can be compared. The discovery document is
// fetched once before each count (`client.oidc_discover()`): the helper reads the token endpoint
// from the cached document exactly as oidc_exchange does, and every count below is a count of the
// requests the HELPER made.

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <ctime>
#include <functional>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <openssl/evp.h>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"
#include "test_key.hpp"

namespace {

const char* kTenantUuid = "22222222-2222-2222-2222-222222222222";
const char* kClientId = "example-app";
const char* kClientSecret = "example-secret";
const char* kIssuer = "https://issuer.test";
const char* kRedirectUri = "https://app.test/callback";

// §37.4's fixed vector: SHA-256 of the ASCII string below.
const char* kVectorRaw = "n-0S6_WzA2Mj";
const char* kVectorHash = "0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19";

// Fixture values that must never appear in an error, a rendering or a telemetry event.
const char* kProviderToken = "PROVIDER-ID-TOKEN-fixture-8f3a1c";
const char* kRawNonce = "RAW-NONCE-fixture-77d2e0";

const char* kDiscovery = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "pushed_authorization_request_endpoint":"https://iam.example.com/oauth2/par",
  "grant_types_supported":["authorization_code","urn:axiam:params:oauth:grant-type:provider-id-token"],
  "token_endpoint_auth_methods_supported":["none","client_secret_post"]
})";

const char* kDiscoveryBasic = R"({
  "issuer":"https://issuer.test",
  "authorization_endpoint":"https://iam.example.com/oauth2/authorize",
  "token_endpoint":"https://iam.example.com/oauth2/token",
  "jwks_uri":"https://iam.example.com/oauth2/jwks",
  "token_endpoint_auth_methods_supported":["client_secret_basic"]
})";

struct Reply {
    long status = 200;
    std::string body = "{}";
    axiam::HeaderMap headers;
};

struct Replies {
    std::string discovery = kDiscovery;
    std::vector<Reply> token_script;
    std::size_t token_calls = 0;
    std::size_t par_calls = 0;
    std::string jwks_body = R"({"keys":[]})";
    std::chrono::milliseconds token_delay{0};
    std::atomic<int> gate_arrived{0};
    int gate_expect = 0;
    std::mutex mtx;
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
        if (url.find("/oauth2/jwks") != std::string::npos) {
            resp.status = 200;
            resp.body = r->jwks_body;
            return resp;
        }
        if (url.find("/oauth2/par") != std::string::npos) {
            {
                std::lock_guard<std::mutex> lock(r->mtx);
                ++r->par_calls;
            }
            resp.status = 201;
            resp.body = R"({"request_uri":"urn:ietf:params:oauth:request_uri:abc123","expires_in":90})";
            return resp;
        }
        if (url.find("/oauth2/token") != std::string::npos) {
            std::size_t i;
            std::chrono::milliseconds delay;
            int expect;
            {
                std::lock_guard<std::mutex> lock(r->mtx);
                i = r->token_calls++;
                delay = r->token_delay;
                expect = r->gate_expect;
            }
            if (expect > 0) {
                // Bounded, so a regression fails an assertion instead of hanging the suite.
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
                while (r->gate_arrived.load(std::memory_order_acquire) < expect &&
                       std::chrono::steady_clock::now() < deadline) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            }
            if (delay.count() > 0) std::this_thread::sleep_for(delay);
            std::lock_guard<std::mutex> lock(r->mtx);
            if (r->token_script.empty()) {
                resp.status = 200;
                resp.body = "{}";
                return resp;
            }
            const Reply& a = r->token_script[std::min(i, r->token_script.size() - 1)];
            if (a.status == 0) {
                resp.transport_error = "connection reset";
                return resp;
            }
            resp.status = a.status;
            resp.body = a.body;
            resp.headers = a.headers;
            return resp;
        }
        resp.status = 404;
        resp.body = "{}";
        return resp;
    };
    return axtest::make_fake(std::move(st));
}

struct Fixture {
    std::shared_ptr<axtest::FakeState> st = std::make_shared<axtest::FakeState>();
    std::shared_ptr<Replies> replies = std::make_shared<Replies>();
    std::shared_ptr<std::vector<std::string>> telemetry = std::make_shared<std::vector<std::string>>();
};

/// `secret == nullptr` builds the PUBLIC client — the mobile-app persona §37.7 names first.
axiam::Client make_client(Fixture& f, const char* secret = nullptr, bool tenant_uuid = true) {
    auto tel = f.telemetry;
    auto builder = axiam::Client::builder()
                       .base_url("https://iam.example.com")
                       .tenant_slug("acme")
                       .oidc_client_id(kClientId)
                       .transport(routed(f.st, f.replies))
                       .telemetry_hook([tel](const axiam::TelemetryEvent& ev) {
                           // Every string field of every event, so test 12 can scan them.
                           std::string s;
                           if (const auto* e = std::get_if<axiam::RequestStartEvent>(&ev)) {
                               s = e->operation + "|" + e->method + "|" + e->path_template;
                           } else if (const auto* e2 = std::get_if<axiam::RequestEndEvent>(&ev)) {
                               s = e2->operation + "|" + e2->method + "|" + e2->path_template;
                           } else if (const auto* e3 = std::get_if<axiam::RetryEvent>(&ev)) {
                               s = e3->operation + "|" + e3->reason;
                           } else {
                               s = "other";
                           }
                           tel->push_back(s);
                       });
    if (tenant_uuid) builder.tenant_id(kTenantUuid);
    if (secret != nullptr) builder.oidc_client_secret(secret);
    auto client = builder.build();
    client._set_retry_test_seams([] { return 0.5; }, [](std::chrono::milliseconds) {});
    return client;
}

std::string pct_decode(const std::string& s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            out.push_back(static_cast<char>(std::stoi(s.substr(i + 1, 2), nullptr, 16)));
            i += 2;
        } else if (s[i] == '+') {
            out.push_back(' ');
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

using Params = std::vector<std::pair<std::string, std::string>>;

/// A form body or query string as an ordered parameter list, percent-decoded.
Params parse_params(const std::string& q) {
    Params out;
    std::size_t at = 0;
    while (at <= q.size() && !q.empty()) {
        const auto amp = q.find('&', at);
        const std::string pair = q.substr(at, amp == std::string::npos ? std::string::npos : amp - at);
        const auto eq = pair.find('=');
        if (eq == std::string::npos) {
            out.emplace_back(pct_decode(pair), "");
        } else {
            out.emplace_back(pct_decode(pair.substr(0, eq)), pct_decode(pair.substr(eq + 1)));
        }
        if (amp == std::string::npos) break;
        at = amp + 1;
    }
    return out;
}

Params query_of(const std::string& url) {
    const auto q = url.find('?');
    return q == std::string::npos ? Params{} : parse_params(url.substr(q + 1));
}

std::vector<std::string> keys_of(const Params& p) {
    std::vector<std::string> k;
    for (const auto& kv : p) k.push_back(kv.first);
    std::sort(k.begin(), k.end());
    return k;
}

std::size_t count_of(const Params& p, const std::string& key) {
    return static_cast<std::size_t>(
        std::count_if(p.begin(), p.end(), [&](const auto& kv) { return kv.first == key; }));
}

std::string value_of(const Params& p, const std::string& key) {
    for (const auto& kv : p) {
        if (kv.first == key) return kv.second;
    }
    return {};
}

std::vector<axtest::RecordedReq> token_requests(axtest::FakeState& st) {
    std::lock_guard<std::mutex> lock(st.mtx);
    std::vector<axtest::RecordedReq> out;
    for (const auto& r : st.requests) {
        if (r.url.find("/oauth2/token") != std::string::npos) out.push_back(r);
    }
    return out;
}

bool has_header(const axtest::RecordedReq& req, const std::string& name) {
    for (const auto& h : req.headers) {
        std::string lower = h.first;
        for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lower == name) return true;
    }
    return false;
}

std::int64_t now() { return static_cast<std::int64_t>(std::time(nullptr)); }

axiam::Sensitive<std::string> S(const char* v) { return axiam::Sensitive<std::string>(v); }

const char* kPlainTokens =
    R"({"access_token":"the-access-token","token_type":"Bearer","expires_in":900})";

std::string error_body(const std::string& code, const std::string& description = "") {
    std::string b = "{\"error\":\"" + code + "\"";
    if (!description.empty()) b += ",\"error_description\":\"" + description + "\"";
    return b + "}";
}

/// Run one native sign-in with the fixture token and raw nonce; the common shape of the failure tests.
axiam::OidcTokenSet sign_in(axiam::Client& c, const std::string& provider = "Corp-Okta") {
    return c.login_with_provider_id_token(provider, S(kProviderToken), S(kRawNonce));
}

}  // namespace

// ---------------------------------------------------------------------------
// §37.9 test 1
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 request_body_exact") {
    Fixture f;
    f.replies->token_script = {{200, kPlainTokens, {}}, {200, kPlainTokens, {}}};
    auto client = make_client(f);
    client.oidc_discover();
    const std::size_t before = f.st->count();

    client.login_with_provider_id_token("Corp-Okta", S("the-provider-token"), S(kVectorRaw),
                                        {"openid", "profile"}, std::string("https://api.test/"));

    AXIAM_REQUIRE(f.st->count() == before + 1);  // one POST, nothing else
    auto reqs = token_requests(*f.st);
    AXIAM_REQUIRE(reqs.size() == 1);
    const auto& r = reqs[0];
    AXIAM_REQUIRE(r.method == "POST");
    // `tenant_id` in the QUERY, and absent from the body.
    const Params q = query_of(r.url);
    AXIAM_REQUIRE(value_of(q, "tenant_id") == kTenantUuid);
    AXIAM_REQUIRE(r.url.find("https://iam.example.com/oauth2/token?") == 0);
    const Params body = parse_params(r.body);
    AXIAM_REQUIRE(count_of(body, "tenant_id") == 0);
    AXIAM_REQUIRE(r.headers.at("Content-Type") == "application/x-www-form-urlencoded");
    // The FULL key set: exactly these, a public client sending no credential.
    const std::vector<std::string> expected = {"client_id", "grant_type", "id_token", "nonce",
                                               "provider", "resource",   "scope"};
    AXIAM_REQUIRE(keys_of(body) == expected);
    AXIAM_REQUIRE(value_of(body, "grant_type") ==
                  "urn:axiam:params:oauth:grant-type:provider-id-token");
    AXIAM_REQUIRE(value_of(body, "client_id") == kClientId);
    AXIAM_REQUIRE(value_of(body, "provider") == "Corp-Okta");
    AXIAM_REQUIRE(value_of(body, "id_token") == "the-provider-token");
    AXIAM_REQUIRE(value_of(body, "nonce") == kVectorRaw);
    AXIAM_REQUIRE(value_of(body, "scope") == "openid profile");  // the space-joined list
    AXIAM_REQUIRE(value_of(body, "resource") == "https://api.test/");
    AXIAM_REQUIRE_FALSE(has_header(r, "authorization"));
    AXIAM_REQUIRE_FALSE(has_header(r, "cookie"));
    AXIAM_REQUIRE_FALSE(has_header(r, "x-csrf-token"));
    AXIAM_REQUIRE(r.sessionless);

    // No scopes and no resource: neither key is sent, and `openid` is NOT added.
    client.login_with_provider_id_token("Corp-Okta", S("the-provider-token"), S(kVectorRaw));
    reqs = token_requests(*f.st);
    AXIAM_REQUIRE(reqs.size() == 2);
    const Params bare = parse_params(reqs[1].body);
    const std::vector<std::string> bare_keys = {"client_id", "grant_type", "id_token", "nonce",
                                                "provider"};
    AXIAM_REQUIRE(keys_of(bare) == bare_keys);
    AXIAM_REQUIRE(reqs[1].body.find("openid") == std::string::npos);
    AXIAM_REQUIRE(reqs[1].body.find("scope") == std::string::npos);
}

// ---------------------------------------------------------------------------
// §37.9 test 2
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 raw_nonce_sent_not_hash") {
    Fixture f;
    f.replies->token_script = {{200, kPlainTokens, {}}};
    auto client = make_client(f);
    client.oidc_discover();

    // A token whose payload carries the HASH, as the provider's token does.
    const std::string token = "eyJhbGciOiJSUzI1NiJ9." +
                              axtest::b64url_encode(std::string("{\"nonce\":\"") + kVectorHash +
                                                    "\"}") +
                              ".sig";
    client.login_with_provider_id_token("p", axiam::Sensitive<std::string>(token), S(kVectorRaw));

    const auto reqs = token_requests(*f.st);
    AXIAM_REQUIRE(reqs.size() == 1);
    const Params body = parse_params(reqs[0].body);
    AXIAM_REQUIRE(value_of(body, "nonce") == kVectorRaw);  // byte for byte
    AXIAM_REQUIRE(reqs[0].body.find(kVectorHash) == std::string::npos);
    AXIAM_REQUIRE(reqs[0].body.find("0823a09b") == std::string::npos);
    // ...nor the token's own `nonce` claim, sent as a field of its own: the only place the
    // hash may appear is INSIDE the opaque id_token value, and not even there as a hex string.
    AXIAM_REQUIRE(count_of(body, "nonce") == 1);
}

// ---------------------------------------------------------------------------
// §37.9 test 3
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 provider_sent_verbatim") {
    Fixture f;
    f.replies->token_script = {{200, kPlainTokens, {}}};
    auto client = make_client(f);
    client.oidc_discover();
    const std::size_t before = f.st->count();

    const std::vector<std::string> providers = {
        "9f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f",  // a UUID
        "Corp-Okta",                              // a slug, mixed case: not folded
        "google",                                 // a kind name: not translated
    };
    for (const auto& p : providers) {
        client.login_with_provider_id_token(p, S("t"), S("n"));
    }

    // One request per call and no other: no `sso_providers` lookup, no discovery fetch.
    AXIAM_REQUIRE(f.st->count() == before + providers.size());
    AXIAM_REQUIRE(f.st->count_path("/federation/providers") == 0);
    AXIAM_REQUIRE(f.st->count_path("openid-configuration") == 1);  // the warm-up alone
    const auto reqs = token_requests(*f.st);
    AXIAM_REQUIRE(reqs.size() == providers.size());
    for (std::size_t i = 0; i < providers.size(); ++i) {
        AXIAM_REQUIRE(value_of(parse_params(reqs[i].body), "provider") == providers[i]);
    }

    // The one-request claim, stated for a single call too.
    Fixture g;
    g.replies->token_script = {{200, kPlainTokens, {}}};
    auto c2 = make_client(g);
    c2.oidc_discover();
    const std::size_t b2 = g.st->count();
    c2.login_with_provider_id_token("Corp-Okta", S("t"), S("n"));
    AXIAM_REQUIRE(g.st->count() == b2 + 1);
}

// ---------------------------------------------------------------------------
// §37.9 test 4
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 public_client_sends_client_id_only") {
    Fixture f;
    f.replies->token_script = {{200, kPlainTokens, {}}};
    auto client = make_client(f, /*secret=*/nullptr);  // no secret configured
    // Not refused client-side for lacking one (§14.1 rule 1's rule, applied here).
    AXIAM_REQUIRE_NOTHROW(client.login_with_provider_id_token("p", S("t"), S("n")));

    const auto reqs = token_requests(*f.st);
    AXIAM_REQUIRE(reqs.size() == 1);
    const Params body = parse_params(reqs[0].body);
    AXIAM_REQUIRE(value_of(body, "client_id") == kClientId);
    AXIAM_REQUIRE(count_of(body, "client_secret") == 0);
    AXIAM_REQUIRE(count_of(body, "client_assertion") == 0);
    AXIAM_REQUIRE_FALSE(has_header(reqs[0], "authorization"));
}

AXIAM_TEST("§37.9 confidential_client_sends_its_credential") {
    // Whichever of client_secret_post and client_secret_basic the discovery names: this SDK
    // has one request shape (§12.1 rule 3) and the secret is in the body, never a Basic header.
    for (const char* doc : {kDiscovery, kDiscoveryBasic}) {
        Fixture f;
        f.replies->discovery = doc;
        f.replies->token_script = {{200, kPlainTokens, {}}};
        auto client = make_client(f, kClientSecret);
        client.login_with_provider_id_token("p", S("t"), S("n"));

        const auto reqs = token_requests(*f.st);
        AXIAM_REQUIRE(reqs.size() == 1);
        const Params body = parse_params(reqs[0].body);
        AXIAM_REQUIRE(value_of(body, "client_secret") == kClientSecret);
        AXIAM_REQUIRE(value_of(body, "client_id") == kClientId);
        AXIAM_REQUIRE_FALSE(has_header(reqs[0], "authorization"));
    }
}

// ---------------------------------------------------------------------------
// §37.9 test 5
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 empty_inputs_refused_locally") {
    Fixture f;
    f.replies->token_script = {{200, kPlainTokens, {}}};
    auto client = make_client(f);
    client.oidc_discover();
    const std::size_t before = f.st->count();

    // The SDK's local validation error (std::invalid_argument, §28.7's C++ mapping).
    AXIAM_REQUIRE_THROWS_AS(client.login_with_provider_id_token("", S("t"), S("n")),
                            std::invalid_argument);
    AXIAM_REQUIRE_THROWS_AS(client.login_with_provider_id_token("p", S(""), S("n")),
                            std::invalid_argument);
    AXIAM_REQUIRE_THROWS_AS(client.login_with_provider_id_token("p", S("t"), S("")),
                            std::invalid_argument);
    AXIAM_REQUIRE_THROWS_AS(client.login_with_provider_id_token("p", axiam::Sensitive<std::string>(),
                                                                S("n")),
                            std::invalid_argument);
    AXIAM_REQUIRE(f.st->count() == before);  // zero requests

    // A slug-only client (§12.3 rule 4) raises its taxonomy error, also with zero requests.
    Fixture g;
    auto slug_only = make_client(g, nullptr, /*tenant_uuid=*/false);
    AXIAM_REQUIRE_THROWS_AS(slug_only.login_with_provider_id_token("p", S("t"), S("n")),
                            axiam::AuthError);
    AXIAM_REQUIRE(g.st->count() == 0);

    // The nonce is not required to be anything else locally: a long one is the server's to
    // refuse (400 invalid_request), so it is sent, not rejected.
    f.replies->token_script = {{400, error_body("invalid_request"), {}}};
    AXIAM_REQUIRE_THROWS_AS(
        client.login_with_provider_id_token("p", S("t"), axiam::Sensitive<std::string>(std::string(513, 'n'))),
        axiam::OAuthProtocolError);
}

// ---------------------------------------------------------------------------
// §37.9 test 6
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 generic_invalid_grant_mapped") {
    Fixture f;
    f.replies->token_script = {
        {400, error_body("invalid_grant", "the provider ID token is not acceptable"), {}}};
    auto client = make_client(f);
    client.oidc_discover();
    const std::size_t before = f.st->count();

    try {
        sign_in(client);
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        AXIAM_REQUIRE(e.error_code() == "invalid_grant");
        AXIAM_REQUIRE(e.error_description() ==
                      std::optional<std::string>("the provider ID token is not acceptable"));
        AXIAM_REQUIRE(std::string(e.what()) ==
                      "invalid_grant: the provider ID token is not acceptable");
    }
    // Exactly one request: no retry, no regenerated nonce.
    AXIAM_REQUIRE(f.st->count() == before + 1);
    AXIAM_REQUIRE(f.replies->token_calls == 1);
    // The §9 guard is not entered.
    AXIAM_REQUIRE(client.refresh_call_count() == 0);
}

// ---------------------------------------------------------------------------
// §37.9 test 7
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 consent_required_mapped") {
    Fixture f;
    f.replies->token_script = {{400, error_body("consent_required", "consent is needed"), {}}};
    auto client = make_client(f);
    client.oidc_discover();
    const std::size_t before = f.st->count();

    try {
        sign_in(client);
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        AXIAM_REQUIRE(e.error_code() == "consent_required");
    }
    // One request, and no fallback to another grant or a browser flow.
    AXIAM_REQUIRE(f.st->count() == before + 1);
    const auto reqs = token_requests(*f.st);
    AXIAM_REQUIRE(reqs.size() == 1);
    AXIAM_REQUIRE(reqs[0].body.find("provider-id-token") != std::string::npos);
    AXIAM_REQUIRE(f.st->count_path("/oauth2/par") == 0);
}

// ---------------------------------------------------------------------------
// §37.9 test 8
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 client_and_scope_refusals_surfaced") {
    struct Case {
        long status;
        const char* code;
        axiam::HeaderMap headers;
    };
    const std::vector<Case> cases = {
        {400, "unauthorized_client", {}},
        {401, "invalid_client", {{"WWW-Authenticate", "Basic realm=\"axiam\""}}},
        {400, "invalid_scope", {}},
        {400, "invalid_target", {}},
    };
    for (const auto& c : cases) {
        Fixture f;
        f.replies->token_script = {{c.status, error_body(c.code, "refused"), c.headers}};
        auto client = make_client(f);
        client.oidc_discover();
        const std::size_t before = f.st->count();

        try {
            client.login_with_provider_id_token("p", S("t"), S("n"), {"openid", "phone"});
            AXIAM_REQUIRE(false);
        } catch (const axiam::OAuthProtocolError& e) {
            AXIAM_REQUIRE(e.error_code() == c.code);
        }
        // One request each; invalid_scope is not narrowed and re-sent.
        AXIAM_REQUIRE(f.st->count() == before + 1);
        AXIAM_REQUIRE(f.replies->token_calls == 1);
        // The 401 does not enter the §9 guard: no refresh of any kind.
        AXIAM_REQUIRE(client.refresh_call_count() == 0);
        AXIAM_REQUIRE(f.st->count_path("/api/v1/auth/refresh") == 0);
    }
}

// ---------------------------------------------------------------------------
// §37.9 test 9
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 rate_limit_with_retry_after_mapped") {
    Fixture f;
    f.replies->token_script = {{429, error_body("rate_limit_exceeded"), {{"Retry-After", "7"}}}};
    auto client = make_client(f);
    client.oidc_discover();
    const std::size_t before = f.st->count();

    try {
        sign_in(client);
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        AXIAM_REQUIRE(e.error_code() == "rate_limit_exceeded");
        AXIAM_REQUIRE(e.retry_after().has_value());
        AXIAM_REQUIRE(*e.retry_after() == std::chrono::milliseconds(7000));
    }
    AXIAM_REQUIRE(f.st->count() == before + 1);  // exactly one request, retry enabled or not
}

// ---------------------------------------------------------------------------
// §37.9 test 10
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 server_error_not_retried") {
    {
        Fixture f;
        f.replies->token_script = {{500, error_body("server_error", "datastore unavailable"), {}}};
        auto client = make_client(f);
        client.oidc_discover();
        try {
            sign_in(client);
            AXIAM_REQUIRE(false);
        } catch (const axiam::OAuthProtocolError& e) {
            AXIAM_REQUIRE(e.error_code() == "server_error");
        }
        AXIAM_REQUIRE(f.replies->token_calls == 1);
    }
    {
        // A 5xx with no body is a NetworkError, one request.
        Fixture f;
        f.replies->token_script = {{500, "", {}}};
        auto client = make_client(f);
        client.oidc_discover();
        AXIAM_REQUIRE_THROWS_AS(sign_in(client), axiam::NetworkError);
        AXIAM_REQUIRE(f.replies->token_calls == 1);
    }
    {
        // A transport failure after the request was sent: NetworkError, one request.
        Fixture f;
        f.replies->token_script = {{0, "", {}}};
        auto client = make_client(f);
        client.oidc_discover();
        AXIAM_REQUIRE_THROWS_AS(sign_in(client), axiam::NetworkError);
        AXIAM_REQUIRE(f.replies->token_calls == 1);
    }
}

// ---------------------------------------------------------------------------
// §37.9 test 11
// ---------------------------------------------------------------------------

namespace {

std::string native_id_token(const axtest::TestKey& key, const std::string& nonce_claim) {
    const std::string payload = std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":\"" + kClientId +
                                "\",\"sub\":\"user-1\",\"exp\":" + std::to_string(now() + 900) +
                                ",\"iat\":" + std::to_string(now() - 5) + ",\"nonce\":\"" +
                                nonce_claim + "\"}";
    return key.make_jwt("EdDSA", payload);
}

}  // namespace

AXIAM_TEST("§37.9 result_is_the_ordinary_token_set") {
    axtest::TestKey key;
    {
        Fixture f;
        f.replies->jwks_body = key.jwks_json();
        // The AXIAM ID token carries the RAW nonce, not the hash.
        f.replies->token_script = {
            {200,
             std::string(R"({"access_token":"the-access-token","token_type":"DPoP","expires_in":900,)"
                         R"("refresh_token":"the-refresh-token","scope":"openid profile",)"
                         R"("id_token":")") +
                 native_id_token(key, kVectorRaw) + "\"}",
             {}}};
        auto client = make_client(f);
        const auto set = client.login_with_provider_id_token("p", S("t"), S(kVectorRaw), {"openid"});

        AXIAM_REQUIRE(set.token_type == "DPoP");  // read, not assumed to be Bearer
        AXIAM_REQUIRE(set.scope == std::optional<std::string>("openid profile"));
        AXIAM_REQUIRE(axiam::detail::reveal(set.access_token) == "the-access-token");
        AXIAM_REQUIRE(set.refresh_token.has_value());
        AXIAM_REQUIRE(set.id_token.has_value());
        AXIAM_REQUIRE(set.id_claims.has_value());
        AXIAM_REQUIRE(set.id_claims->nonce == std::optional<std::string>(kVectorRaw));
        // Wrapped, per §37.6.
        AXIAM_REQUIRE(set.access_token.to_string() == "[SENSITIVE]");
        // Adoption posture (rule 9): this SDK adopts nothing, as login_client_credentials().
        AXIAM_REQUIRE_FALSE(client.has_session());
    }
    {
        // A mismatching nonce claim is the nonce_mismatch AuthError, and the set is discarded.
        Fixture f;
        f.replies->jwks_body = key.jwks_json();
        f.replies->token_script = {
            {200,
             std::string(R"({"access_token":"a","token_type":"Bearer","expires_in":900,"id_token":")") +
                 native_id_token(key, kVectorHash) + "\"}",
             {}}};
        auto client = make_client(f);
        try {
            client.login_with_provider_id_token("p", S("t"), S(kVectorRaw), {"openid"});
            AXIAM_REQUIRE(false);
        } catch (const axiam::OidcValidationError& e) {
            AXIAM_REQUIRE(e.reason() == axiam::OidcValidationReason::kNonceMismatch);
        }
    }
    {
        // A 200 without refresh_token and id_token decodes with both absent.
        Fixture f;
        f.replies->token_script = {{200, kPlainTokens, {}}};
        auto client = make_client(f);
        const auto set = sign_in(client);
        AXIAM_REQUIRE_FALSE(set.refresh_token.has_value());
        AXIAM_REQUIRE_FALSE(set.id_token.has_value());
        AXIAM_REQUIRE_FALSE(set.id_claims.has_value());
        AXIAM_REQUIRE(set.token_type == "Bearer");
        AXIAM_REQUIRE_FALSE(client.has_session());
    }
}

// ---------------------------------------------------------------------------
// §37.9 test 12
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 no_secret_in_logs_or_errors") {
    // This SDK has no logger: the surfaces a secret could reach are the error (message, code,
    // description), the Sensitive renderings, and the §19 telemetry events. All are scanned.
    auto leaks = [](const std::string& text) {
        return text.find(kProviderToken) != std::string::npos ||
               text.find(kRawNonce) != std::string::npos;
    };

    struct Failure {
        long status;
        std::string body;
        axiam::HeaderMap headers;
    };
    const std::vector<Failure> failures = {
        {400, error_body("invalid_grant", "the provider ID token is not acceptable"), {}},
        {400, error_body("consent_required", "consent"), {}},
        {400, error_body("unauthorized_client", "no grant"), {}},
        {401, error_body("invalid_client", "bad client"), {{"WWW-Authenticate", "Basic"}}},
        {400, error_body("invalid_scope", "scope"), {}},
        {400, error_body("invalid_target", "target"), {}},
        {429, error_body("rate_limit_exceeded"), {{"Retry-After", "7"}}},
        {500, error_body("server_error", "boom"), {}},
        {500, "", {}},
        {0, "", {}},
        {400, "not json at all", {}},
    };
    for (const auto& fail : failures) {
        Fixture f;
        f.replies->token_script = {{fail.status, fail.body, fail.headers}};
        auto client = make_client(f);
        try {
            sign_in(client);
            AXIAM_REQUIRE(false);
        } catch (const axiam::OAuthProtocolError& e) {
            AXIAM_REQUIRE_FALSE(leaks(e.what()));
            AXIAM_REQUIRE_FALSE(leaks(e.error_code()));
            AXIAM_REQUIRE_FALSE(leaks(e.error_description().value_or("")));
        } catch (const std::exception& e) {
            AXIAM_REQUIRE_FALSE(leaks(e.what()));
        }
        for (const auto& line : *f.telemetry) AXIAM_REQUIRE_FALSE(leaks(line));
    }

    // The local refusals (test 5) and the nonce_mismatch of test 11.
    {
        Fixture f;
        auto client = make_client(f);
        const std::vector<std::function<void()>> refusals = {
            [&] { client.login_with_provider_id_token("", S(kProviderToken), S(kRawNonce)); },
            [&] { client.login_with_provider_id_token("p", S(""), S(kRawNonce)); },
            [&] { client.login_with_provider_id_token("p", S(kProviderToken), S("")); },
        };
        for (const auto& go : refusals) {
            try {
                go();
                AXIAM_REQUIRE(false);
            } catch (const std::exception& e) {
                AXIAM_REQUIRE_FALSE(leaks(e.what()));
            }
        }
        Fixture g;
        auto slug_only = make_client(g, nullptr, false);
        try {
            sign_in(slug_only);
            AXIAM_REQUIRE(false);
        } catch (const std::exception& e) {
            AXIAM_REQUIRE_FALSE(leaks(e.what()));
        }
    }
    {
        axtest::TestKey key;
        Fixture f;
        f.replies->jwks_body = key.jwks_json();
        f.replies->token_script = {
            {200,
             std::string(R"({"access_token":"a","token_type":"Bearer","expires_in":900,"id_token":")") +
                 native_id_token(key, "some-other-nonce") + "\"}",
             {}}};
        auto client = make_client(f);
        try {
            client.login_with_provider_id_token("p", S(kProviderToken), S(kRawNonce), {"openid"});
            AXIAM_REQUIRE(false);
        } catch (const axiam::OidcValidationError& e) {
            AXIAM_REQUIRE_FALSE(leaks(e.what()));
            AXIAM_REQUIRE_FALSE(leaks(e.reason()));
        }
        for (const auto& line : *f.telemetry) AXIAM_REQUIRE_FALSE(leaks(line));
    }

    // The success path's telemetry, and the renderings of the wrapped values.
    {
        Fixture f;
        f.replies->token_script = {{200, kPlainTokens, {}}};
        auto client = make_client(f);
        sign_in(client);
        for (const auto& line : *f.telemetry) AXIAM_REQUIRE_FALSE(leaks(line));
        std::ostringstream os;
        os << S(kProviderToken) << S(kRawNonce);
        AXIAM_REQUIRE_FALSE(leaks(os.str()));
        AXIAM_REQUIRE(os.str() == "[SENSITIVE][SENSITIVE]");
    }
    // ProviderNonce.raw's rendering (§37.4).
    {
        const auto pair = axiam::native_nonce();
        std::ostringstream os;
        os << pair.raw;
        AXIAM_REQUIRE(os.str() == "[SENSITIVE]");
        AXIAM_REQUIRE(pair.raw.to_string() == "[SENSITIVE]");
        AXIAM_REQUIRE(os.str().find(pair.raw.expose()) == std::string::npos);
    }
}

// ---------------------------------------------------------------------------
// §37.9 test 13 (§37.4)
// ---------------------------------------------------------------------------

AXIAM_TEST("§37.9 native_nonce_pair") {
    const auto a = axiam::native_nonce();
    const auto b = axiam::native_nonce();
    const std::string& raw = a.raw.expose();

    // base64url without padding, and at least 32 bytes once decoded: 43 characters for 32.
    AXIAM_REQUIRE(raw.size() >= 43);
    AXIAM_REQUIRE(raw.size() <= 512);
    for (const char c : raw) {
        AXIAM_REQUIRE(std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '_');
    }
    AXIAM_REQUIRE(raw.find('=') == std::string::npos);
    AXIAM_REQUIRE((raw.size() * 6) / 8 >= 32);

    // `hashed` is 64 lower-case hex characters and equals SHA-256(raw): checked against the
    // contract's fixed vector for the hashing step, and for the pair against the value the
    // server would compute (the same primitive, applied to what native_nonce returned).
    AXIAM_REQUIRE(a.hashed.size() == 64);
    for (const char c : a.hashed) {
        AXIAM_REQUIRE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
    }
    AXIAM_REQUIRE(a.hashed != raw);

    // Two calls, two different pairs.
    AXIAM_REQUIRE(a.raw.expose() != b.raw.expose());
    AXIAM_REQUIRE(a.hashed != b.hashed);

    // `raw` is wrapped, `hashed` is a plain string.
    AXIAM_REQUIRE(a.raw.to_string() == "[SENSITIVE]");
    static_assert(std::is_same<decltype(a.hashed), std::string>::value,
                  "hashed is a plain string");
    static_assert(std::is_same<decltype(a.raw), axiam::Sensitive<std::string>>::value,
                  "raw is Sensitive");
}

AXIAM_TEST("§37.9 native_nonce_pair: the hash is SHA-256 of the raw bytes (the §37.4 vector)") {
    // The hashing step, driven through the helper's own pipeline: a pair is generated, then the
    // hash recomputed independently with OpenSSL and compared; and the fixed vector is checked
    // the same way so the independent computation is itself pinned to the contract's number.
    auto sha256_hex = [](const std::string& s) {
        unsigned char d[EVP_MAX_MD_SIZE];
        unsigned int n = 0;
        EVP_Digest(s.data(), s.size(), d, &n, EVP_sha256(), nullptr);
        static const char* h = "0123456789abcdef";
        std::string out;
        for (unsigned i = 0; i < n; ++i) {
            out.push_back(h[d[i] >> 4]);
            out.push_back(h[d[i] & 0xF]);
        }
        return out;
    };
    AXIAM_REQUIRE(sha256_hex(kVectorRaw) == kVectorHash);
    for (int i = 0; i < 5; ++i) {
        const auto p = axiam::native_nonce();
        AXIAM_REQUIRE(p.hashed == sha256_hex(p.raw.expose()));
    }
}

AXIAM_TEST("§37.4 the pair feeds the helper: raw goes to the server, hashed is for the provider") {
    Fixture f;
    f.replies->token_script = {{200, kPlainTokens, {}}};
    auto client = make_client(f);
    const auto pair = axiam::native_nonce();
    client.login_with_provider_id_token("p", S("t"), pair.raw);
    const auto reqs = token_requests(*f.st);
    AXIAM_REQUIRE(reqs.size() == 1);
    AXIAM_REQUIRE(value_of(parse_params(reqs[0].body), "nonce") == pair.raw.expose());
    AXIAM_REQUIRE(reqs[0].body.find(pair.hashed) == std::string::npos);
}

// ---------------------------------------------------------------------------
// §12.1 idp_hint on oidc_begin
// ---------------------------------------------------------------------------

namespace {

axiam::AuthorizationRequest begin_with(axiam::Client& client, std::optional<std::string> hint) {
    const auto cfg = client.oidc_discover();
    return client.oidc_begin(cfg, kRedirectUri, std::nullopt, std::move(hint));
}

const std::vector<std::string> kEightParams = {"client_id",    "code_challenge", "code_challenge_method",
                                               "nonce",        "redirect_uri",   "response_type",
                                               "scope",        "state"};

}  // namespace

AXIAM_TEST("§12.1 idp_hint_emitted_once") {
    Fixture f;
    auto client = make_client(f);
    for (const std::string hint : {"corp-okta", "9f1c2d3e-4a5b-4c6d-8e7f-0a1b2c3d4e5f", "Google"}) {
        const auto req = begin_with(client, hint);
        const Params q = query_of(req.url);
        // Asserted on the parsed parameter list, not a substring.
        AXIAM_REQUIRE(count_of(q, "axiam_idp_hint") == 1);
        AXIAM_REQUIRE(value_of(q, "axiam_idp_hint") == hint);  // `Google` is not folded
        // ...beside the other eight, unchanged.
        std::vector<std::string> expected = kEightParams;
        expected.push_back("axiam_idp_hint");
        std::sort(expected.begin(), expected.end());
        AXIAM_REQUIRE(keys_of(q) == expected);
        AXIAM_REQUIRE(value_of(q, "state") == req.state);
        AXIAM_REQUIRE(value_of(q, "scope") == "openid");
    }
    // A hint that needs percent-encoding round-trips through the parsed query intact.
    const std::string awkward = "corp okta&x=1/é+ü#?";
    const auto req = begin_with(client, awkward);
    const Params q = query_of(req.url);
    AXIAM_REQUIRE(count_of(q, "axiam_idp_hint") == 1);
    AXIAM_REQUIRE(value_of(q, "axiam_idp_hint") == awkward);
    AXIAM_REQUIRE(count_of(q, "x") == 0);
}

AXIAM_TEST("§12.1 idp_hint_omitted_when_unset") {
    Fixture f;
    auto client = make_client(f);
    const auto cfg = client.oidc_discover();
    for (int via : {0, 1}) {
        // The established overload, and the new one with a disengaged hint.
        const auto req = via == 0 ? client.oidc_begin(cfg, kRedirectUri)
                                  : client.oidc_begin(cfg, kRedirectUri, std::nullopt, std::nullopt);
        const Params q = query_of(req.url);
        AXIAM_REQUIRE(keys_of(q) == kEightParams);  // exactly the eight of rule 5
        AXIAM_REQUIRE(count_of(q, "axiam_idp_hint") == 0);
        AXIAM_REQUIRE(count_of(q, "kc_idp_hint") == 0);
        AXIAM_REQUIRE(req.url.find("idp_hint") == std::string::npos);
    }
}

AXIAM_TEST("§12.1 idp_hint_not_duplicated") {
    // oidc_begin accepts no additional caller-supplied query parameter in this SDK (rule 5's
    // "MAY accept"), so a second `axiam_idp_hint` cannot be supplied. What is checkable is the
    // other half of the rule: the option is the SINGLE source, and the name is emitted once,
    // with the option's value, even when the value itself looks like a parameter. And there is
    // no `kc_idp_hint` alias (rule 4).
    Fixture f;
    auto client = make_client(f);
    const auto req = begin_with(client, std::string("axiam_idp_hint=other"));
    const Params q = query_of(req.url);
    AXIAM_REQUIRE(count_of(q, "axiam_idp_hint") == 1);
    AXIAM_REQUIRE(value_of(q, "axiam_idp_hint") == "axiam_idp_hint=other");
    AXIAM_REQUIRE(count_of(q, "kc_idp_hint") == 0);
}

AXIAM_TEST("§12.1 idp_hint_bounds") {
    Fixture f;
    auto client = make_client(f);
    const auto cfg = client.oidc_discover();
    const std::size_t before = f.st->count();

    // Empty and 257 bytes: refused with no URL built and no request.
    AXIAM_REQUIRE_THROWS_AS(client.oidc_begin(cfg, kRedirectUri, std::nullopt, std::string("")),
                            std::invalid_argument);
    AXIAM_REQUIRE_THROWS_AS(
        client.oidc_begin(cfg, kRedirectUri, std::nullopt, std::string(257, 'a')),
        std::invalid_argument);
    // Bytes, not characters: 129 two-byte characters are 258 bytes.
    std::string wide;
    for (int i = 0; i < 129; ++i) wide += "\xC3\xA9";
    AXIAM_REQUIRE_THROWS_AS(client.oidc_begin(cfg, kRedirectUri, std::nullopt, wide),
                            std::invalid_argument);
    AXIAM_REQUIRE(f.st->count() == before);

    // 256 bytes: accepted, unchanged.
    const std::string max(256, 'a');
    const auto req = client.oidc_begin(cfg, kRedirectUri, std::nullopt, max);
    AXIAM_REQUIRE(value_of(query_of(req.url), "axiam_idp_hint") == max);

    // The value is not otherwise judged: not trimmed, folded, UUID-checked or looked up.
    const auto odd = client.oidc_begin(cfg, kRedirectUri, std::nullopt, std::string("  Not-A-Provider  "));
    AXIAM_REQUIRE(value_of(query_of(odd.url), "axiam_idp_hint") == "  Not-A-Provider  ");
    AXIAM_REQUIRE(f.st->count_path("/federation/providers") == 0);

    // The same bounds on oidc_par, refused before any push.
    AXIAM_REQUIRE_THROWS_AS(
        client.oidc_par(cfg, req, kRedirectUri, std::nullopt, std::nullopt, std::nullopt, std::string("")),
        std::invalid_argument);
    AXIAM_REQUIRE_THROWS_AS(client.oidc_par(cfg, req, kRedirectUri, std::nullopt, std::nullopt,
                                            std::nullopt, std::string(257, 'a')),
                            std::invalid_argument);
    AXIAM_REQUIRE(f.replies->par_calls == 0);
}

// ---------------------------------------------------------------------------
// §26.2 rule 8
// ---------------------------------------------------------------------------

AXIAM_TEST("§26.2 par_idp_hint_in_pushed_body") {
    Fixture f;
    auto client = make_client(f);
    const auto cfg = client.oidc_discover();
    const auto begun = client.oidc_begin(cfg, kRedirectUri);

    auto pushed_body = [&]() {
        std::lock_guard<std::mutex> lock(f.st->mtx);
        for (auto it = f.st->requests.rbegin(); it != f.st->requests.rend(); ++it) {
            if (it->url.find("/oauth2/par") != std::string::npos) return it->body;
        }
        return std::string();
    };
    auto redirect_params = [](const std::string& url) { return keys_of(query_of(url)); };
    const std::vector<std::string> redirect_expected = {"client_id", "request_uri", "tenant_id"};

    // With a hint: the pushed form carries it exactly once.
    const auto with_hint = client.oidc_par(cfg, begun, kRedirectUri, std::nullopt, std::nullopt,
                                           std::nullopt, std::string("corp-okta"));
    const Params body = parse_params(pushed_body());
    AXIAM_REQUIRE(count_of(body, "axiam_idp_hint") == 1);
    AXIAM_REQUIRE(value_of(body, "axiam_idp_hint") == "corp-okta");
    AXIAM_REQUIRE(count_of(body, "kc_idp_hint") == 0);
    // ...and the redirect carries ONLY client_id and request_uri (plus the routing tenant_id,
    // §26.2 rule 2 / contract 1.42): the hint cannot leak into it.
    AXIAM_REQUIRE(redirect_params(with_hint.url) == redirect_expected);
    AXIAM_REQUIRE(with_hint.url.find("idp_hint") == std::string::npos);

    // Without one, in both overloads: the field is absent, and the redirect is unchanged.
    const auto without = client.oidc_par(cfg, begun, kRedirectUri);
    AXIAM_REQUIRE(count_of(parse_params(pushed_body()), "axiam_idp_hint") == 0);
    AXIAM_REQUIRE(redirect_params(without.url) == redirect_expected);
    const auto none = client.oidc_par(cfg, begun, kRedirectUri, std::nullopt, std::nullopt,
                                      std::nullopt, std::nullopt);
    AXIAM_REQUIRE(count_of(parse_params(pushed_body()), "axiam_idp_hint") == 0);
    AXIAM_REQUIRE(redirect_params(none.url) == redirect_expected);
    AXIAM_REQUIRE(f.replies->par_calls == 3);
}

// ---------------------------------------------------------------------------
// §9 (contract 1.65): refresh-reuse confirmation
// ---------------------------------------------------------------------------

AXIAM_TEST("§9 invalid_grant on oidc_refresh: one wire call, one outcome for all N waiters, the spent token never again") {
    constexpr int kWaiters = 6;  // N >= 5
    Fixture f;
    f.replies->token_script = {{400, error_body("invalid_grant"), {}}};
    f.replies->token_delay = std::chrono::milliseconds(60);
    auto client = make_client(f);
    client.oidc_discover();  // warm the cache so the count is about the grant
    f.replies->gate_expect = kWaiters;

    std::atomic<int> refused{0};
    std::atomic<int> other{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < kWaiters; ++i) {
        threads.emplace_back([&] {
            f.replies->gate_arrived.fetch_add(1, std::memory_order_release);
            try {
                client.oidc_refresh(S("spent-refresh-token"));
                other.fetch_add(1);
            } catch (const axiam::OAuthProtocolError& e) {
                if (e.error_code() == "invalid_grant") refused.fetch_add(1);
                else other.fetch_add(1);
            } catch (...) {
                other.fetch_add(1);
            }
        });
    }
    for (auto& t : threads) t.join();

    // Exactly one wire call, and every waiter got that one OAuthProtocolError.
    AXIAM_REQUIRE(f.replies->token_calls == 1);
    AXIAM_REQUIRE(refused.load() == kWaiters);
    AXIAM_REQUIRE(other.load() == 0);

    // The SDK never presents the spent token again by itself: nothing it does afterwards
    // (re-reading discovery, building a request, an unrelated operation) sends it.
    f.replies->gate_expect = 0;
    client.oidc_discover();
    const auto cfg = client.oidc_discover();
    client.oidc_begin(cfg, kRedirectUri);
    std::size_t spent = 0;
    for (const auto& r : token_requests(*f.st)) {
        if (parse_params(r.body).size() > 0 && value_of(parse_params(r.body), "refresh_token") == "spent-refresh-token") ++spent;
    }
    AXIAM_REQUIRE(spent == 1);
    AXIAM_REQUIRE(f.replies->token_calls == 1);
}
