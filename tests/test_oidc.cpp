// CONTRACT.md §12 — the nine OIDC relying-party operations, plus §12.7, §14 and
// §15.
//
// These are the assertions those sections make hard requirements of, and most
// are about REQUESTS rather than return values: what encoding went out, which
// parameter carried the tenant, whether a secret was sent, and — repeatedly —
// whether a request was made at all. The failure modes here are things an SDK
// does too eagerly (retrying a single-use code, sending a slug the server will
// reject, storing correlation values the caller owns), so the tests that catch
// them count wire calls.

#include <chrono>
#include <memory>
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
const char* kRedirectUri = "https://app.test/callback";

// The issuer deliberately differs from the base URL. §12.3 rule 6 forbids
// rejecting a document over an issuer/base-URL mismatch — behind a proxy the two
// legitimately differ — and §12.4 rule 3 compares an ID token's `iss` against the
// DOCUMENT's value. Making them differ here is what keeps a "compare against the
// base URL" regression from passing.
const char* kIssuer = "https://issuer.test";

const char* kDiscovery = R"({
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

struct Replies {
    // One scripted answer per /oauth2/token call, consumed in order; the last
    // repeats, so a "forever pending" server needs one entry.
    std::vector<std::pair<long, std::string>> token_script;
    std::size_t token_calls = 0;
    std::size_t discovery_calls = 0;
    std::size_t jwks_calls = 0;
    std::size_t introspect_calls = 0;
    std::size_t revoke_calls = 0;
    std::size_t device_calls = 0;
    long introspect_status = 200;
    std::string introspect_body = R"({"active":false})";
    long revoke_status = 200;
    std::string revoke_body;
    long device_status = 200;
    std::string device_body = "{}";
    long sso_status = 200;
    std::string sso_body = "{}";
    std::string jwks_body = R"({"keys":[]})";
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
        if (url.find("openid-configuration") != std::string::npos) {
            ++r->discovery_calls;
            return reply(200, kDiscovery);
        }
        if (url.find("/oauth2/jwks") != std::string::npos) {
            ++r->jwks_calls;
            return reply(200, r->jwks_body);
        }
        if (url.find("/oauth2/device_authorization") != std::string::npos) {
            ++r->device_calls;
            return reply(r->device_status, r->device_body);
        }
        if (url.find("/oauth2/introspect") != std::string::npos) {
            ++r->introspect_calls;
            return reply(r->introspect_status, r->introspect_body);
        }
        if (url.find("/oauth2/revoke") != std::string::npos) {
            ++r->revoke_calls;
            return reply(r->revoke_status, r->revoke_body);
        }
        if (url.find("/oauth2/token") != std::string::npos) {
            const std::size_t i = r->token_calls++;
            if (r->token_script.empty()) return reply(200, "{}");
            const auto& answer = r->token_script[std::min(i, r->token_script.size() - 1)];
            return reply(answer.first, answer.second);
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

/// `secret == nullptr` builds a PUBLIC client — the shape §14.1 requires a
/// device to work with, and the shape §12.1 rule 4 makes introspect/revoke
/// refuse.
axiam::Client make_client(Fixture& f, const char* client_id = kClientId,
                          const char* secret = kClientSecret, bool tenant_uuid = true) {
    auto builder = axiam::Client::builder()
                       .base_url("https://iam.example.com")
                       .tenant_slug("acme")
                       .transport(routed(f.st, f.replies));
    if (tenant_uuid) builder.tenant_id(kTenantUuid);
    if (client_id != nullptr) builder.oidc_client_id(client_id);
    if (secret != nullptr) builder.oidc_client_secret(secret);
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

/// True when the last request to `needle` carried `field=` as a whole form key.
bool body_has_field(axtest::FakeState& st, const std::string& needle, const std::string& field) {
    const auto req = last_request(st, needle);
    const std::string prefix = field + "=";
    if (req.body.rfind(prefix, 0) == 0) return true;
    return req.body.find("&" + prefix) != std::string::npos;
}

std::int64_t now() { return static_cast<std::int64_t>(std::time(nullptr)); }

std::string good_claims(const std::string& extra = "") {
    return std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":\"" + kClientId +
           "\",\"sub\":\"user-1\",\"exp\":" + std::to_string(now() + 900) +
           ",\"iat\":" + std::to_string(now() - 5) + ",\"nonce\":\"the-nonce\"" + extra + "}";
}

std::string token_body_with_id(const std::string& id_token) {
    return R"({"access_token":"the-access-token","token_type":"Bearer","expires_in":900,)"
           R"("refresh_token":"the-refresh-token","id_token":")" + id_token + "\"}";
}

axiam::OidcExchangeParams exchange_params(const char* nonce = "the-nonce") {
    axiam::OidcExchangeParams p;
    p.code = "the-code";
    p.code_verifier = axiam::Sensitive<std::string>("the-verifier");
    p.redirect_uri = kRedirectUri;
    p.nonce = nonce;
    return p;
}

}  // namespace

// ---------------------------------------------------------------------------
// §12.1 / §12.3 rule 6 — discovery
// ---------------------------------------------------------------------------

AXIAM_TEST("§12.1 discovery reads every endpoint from the document") {
    Fixture f;
    auto client = make_client(f);
    const auto cfg = client.oidc_discover();

    // §12.3 rule 6: the document's own `issuer` is authoritative, and it
    // legitimately differs from the base URL behind a proxy.
    AXIAM_REQUIRE(cfg.issuer == kIssuer);
    AXIAM_REQUIRE(cfg.token_endpoint == "https://iam.example.com/oauth2/token");
    // Read from the document rather than hardcoded to /oauth2/jwks.
    AXIAM_REQUIRE(cfg.jwks_uri == "https://iam.example.com/oauth2/jwks");
    AXIAM_REQUIRE(cfg.end_session_endpoint.has_value());
    AXIAM_REQUIRE(cfg.device_authorization_endpoint.has_value());
}

AXIAM_TEST("§12.3 rule 6 discovery is cached so a second call makes no request") {
    Fixture f;
    auto client = make_client(f);
    client.oidc_discover();
    client.oidc_discover();
    AXIAM_REQUIRE(f.replies->discovery_calls == 1);
}

AXIAM_TEST("§12.3 rule 6 a configured TTL below the floor is raised") {
    // 5 minutes is a MINIMUM. An SDK that honoured 1 second would turn the cache
    // into a per-request fetch.
    Fixture f;
    auto client = axiam::Client::builder()
                      .base_url("https://iam.example.com")
                      .tenant_id(kTenantUuid)
                      .oidc_client_id(kClientId)
                      .oidc_discovery_ttl(std::chrono::seconds(1))
                      .transport(routed(f.st, f.replies))
                      .build();
    client.oidc_discover();
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    client.oidc_discover();
    AXIAM_REQUIRE(f.replies->discovery_calls == 1);
}

// ---------------------------------------------------------------------------
// §12.1 oidc_begin
// ---------------------------------------------------------------------------

AXIAM_TEST("§12.1 rule 3 the RFC 7636 Appendix B PKCE vector") {
    // §12.1 rule 3 requires this vector by name. It is the one part of PKCE
    // where a plausible-looking implementation (base64 with padding, or hex, or
    // SHA-256 of the base64 rather than of the ASCII) produces a challenge the
    // server silently rejects at exchange time with `invalid_grant`.
    //
    // Asserted end-to-end through the URL, because that is where it has to be
    // right: build a request, take the verifier back out, and check that the
    // challenge in the URL is the SHA-256 the RFC specifies for it.
    Fixture f;
    auto client = make_client(f);
    const auto cfg = client.oidc_discover();
    const auto req = client.oidc_begin(cfg, kRedirectUri);

    // The published vector, computed independently of the SDK.
    const std::string vector_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const std::string vector_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, vector_verifier.data(), vector_verifier.size());
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);
    AXIAM_REQUIRE(axtest::b64url_encode(digest, len) == vector_challenge);

    // ...and the SDK's own verifier hashes to the challenge it published.
    const std::string produced = axiam::detail::reveal(req.code_verifier);
    EVP_MD_CTX* ctx2 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx2, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx2, produced.data(), produced.size());
    EVP_DigestFinal_ex(ctx2, digest, &len);
    EVP_MD_CTX_free(ctx2);
    AXIAM_REQUIRE(req.url.find("code_challenge=" + axtest::b64url_encode(digest, len)) !=
                  std::string::npos);
}

AXIAM_TEST("§12.1 oidc_begin performs no network I/O and builds the eight parameters") {
    Fixture f;
    auto client = make_client(f);
    const auto cfg = client.oidc_discover();
    const std::size_t before = f.st->count();

    const auto req = client.oidc_begin(cfg, kRedirectUri, "profile");

    // §12.1: PURE LOCAL COMPUTATION. Not one request.
    AXIAM_REQUIRE(f.st->count() == before);
    AXIAM_REQUIRE(req.url.rfind("https://iam.example.com/oauth2/authorize?", 0) == 0);
    AXIAM_REQUIRE(req.url.find("response_type=code") != std::string::npos);
    AXIAM_REQUIRE(req.url.find(std::string("client_id=") + kClientId) != std::string::npos);
    AXIAM_REQUIRE(req.url.find("code_challenge_method=S256") != std::string::npos);
    // §12.1 rule 4: `openid` is added when the caller omits it.
    AXIAM_REQUIRE(req.url.find("scope=openid%20profile") != std::string::npos);
    // Rule 5 permits no parameters of the SDK's own beyond the eight.
    AXIAM_REQUIRE(req.url.find("prompt=") == std::string::npos);
    // The URL carries the CHALLENGE; the verifier never appears in it.
    AXIAM_REQUIRE(req.url.find(axiam::detail::reveal(req.code_verifier)) == std::string::npos);
}

AXIAM_TEST("§12.3 rule 1 oidc_begin is stateless and draws fresh values each call") {
    Fixture f;
    auto client = make_client(f);
    const auto cfg = client.oidc_discover();
    const auto a = client.oidc_begin(cfg, kRedirectUri);
    const auto b = client.oidc_begin(cfg, kRedirectUri);

    AXIAM_REQUIRE(a.state != b.state);
    AXIAM_REQUIRE(a.nonce != b.nonce);
    AXIAM_REQUIRE(axiam::detail::reveal(a.code_verifier) !=
                  axiam::detail::reveal(b.code_verifier));
    // §12.1 rule 1: at least 16 bytes of entropy, base64url WITHOUT padding.
    AXIAM_REQUIRE(a.state.size() >= 22);
    AXIAM_REQUIRE(a.state.find('=') == std::string::npos);
    // Rule 2: 43-128 characters from the RFC 7636 unreserved set.
    AXIAM_REQUIRE(axiam::detail::reveal(a.code_verifier).size() >= 43);
    AXIAM_REQUIRE(axiam::detail::reveal(a.code_verifier).size() <= 128);
    // §12.5: the verifier is secret for its whole lifetime, including here.
    AXIAM_REQUIRE(a.code_verifier.to_string() == "[SENSITIVE]");
}

AXIAM_TEST("§12.1 oidc_begin without a client_id fails fast with no wire call") {
    Fixture f;
    auto client = make_client(f, /*client_id=*/nullptr, /*secret=*/nullptr);
    const auto cfg = client.oidc_discover();
    const std::size_t before = f.st->count();
    AXIAM_REQUIRE_THROWS_AS(client.oidc_begin(cfg, kRedirectUri), axiam::AuthError);
    AXIAM_REQUIRE(f.st->count() == before);
}

AXIAM_TEST("§12.1 rule 4 the openid scope check matches whole tokens only") {
    // A substring test would see `openid` inside `openid_connect_admin` and skip
    // the addition, producing an authorization request the OP treats as plain
    // OAuth2 — no ID token, and therefore no §12.4 validation at all. The
    // failure is silent until something downstream reads id_claims.
    Fixture f;
    auto client = make_client(f);
    const auto cfg = client.oidc_discover();
    AXIAM_REQUIRE(client.oidc_begin(cfg, kRedirectUri).url.find("scope=openid") !=
                  std::string::npos);
    AXIAM_REQUIRE(client.oidc_begin(cfg, kRedirectUri, "openid").url.find("scope=openid&") !=
                  std::string::npos);
    AXIAM_REQUIRE(client.oidc_begin(cfg, kRedirectUri, "openid_connect_admin")
                      .url.find("scope=openid%20openid_connect_admin") != std::string::npos);
    AXIAM_REQUIRE(client.oidc_begin(cfg, kRedirectUri, "emails")
                      .url.find("scope=openid%20emails") != std::string::npos);
}

// ---------------------------------------------------------------------------
// §12.1 oidc_exchange
// ---------------------------------------------------------------------------

AXIAM_TEST("§12.1 exchange is form-encoded with the tenant in the query") {
    Fixture f;
    f.replies->token_script = {
        {200, R"({"access_token":"at","token_type":"Bearer","expires_in":900})"}};
    auto client = make_client(f);
    const auto set = client.oidc_exchange(exchange_params());

    const auto req = last_request(*f.st, "/oauth2/token");
    // §12.1 rule 1: form-encoded, not JSON. An SDK that posts JSON here is
    // non-conformant.
    AXIAM_REQUIRE(req.headers.at("Content-Type") == "application/x-www-form-urlencoded");
    // Rule 2: tenant_id is a QUERY parameter and never a body field...
    AXIAM_REQUIRE(req.url.find(std::string("?tenant_id=") + kTenantUuid) != std::string::npos);
    AXIAM_REQUIRE_FALSE(body_has_field(*f.st, "/oauth2/token", "tenant_id"));
    // ...and §5 rule 2 still emits the header alongside it, unconditionally.
    // The two legitimately disagree in FORM: this client was built with a slug
    // AND a uuid, and the header carries whichever it was constructed with.
    AXIAM_REQUIRE(req.headers.count("X-Tenant-ID") == 1);
    // Rule 3: client_secret_post. No Authorization: Basic.
    AXIAM_REQUIRE(req.headers.count("Authorization") == 0);
    AXIAM_REQUIRE(body_has_field(*f.st, "/oauth2/token", "client_secret"));
    AXIAM_REQUIRE(body_has_field(*f.st, "/oauth2/token", "code_verifier"));
    AXIAM_REQUIRE(req.body.find("grant_type=authorization_code") != std::string::npos);
    AXIAM_REQUIRE(axiam::detail::reveal(set.access_token) == "at");
}

AXIAM_TEST("§12.3 rule 4 a slug-only client is refused client-side with no wire call") {
    Fixture f;
    auto client = make_client(f, kClientId, kClientSecret, /*tenant_uuid=*/false);
    // Five of the nine operations need a tenant UUID, and a slug is never a
    // substitute. The SDK MUST raise its taxonomy error CLIENT-SIDE — not even
    // the discovery fetch happens, because the request could not have succeeded.
    AXIAM_REQUIRE_THROWS_AS(client.oidc_exchange(exchange_params()), axiam::AuthError);
    AXIAM_REQUIRE(f.st->count() == 0);
}

AXIAM_TEST("§12.4 rule 6 exchange requires the nonce, because the rule is mandatory here") {
    Fixture f;
    auto client = make_client(f);
    // The helper always requests `openid`, so the server always issues a nonce,
    // and a caller with nothing to compare against has silently lost replay
    // protection. Refusing is louder than skipping the check.
    AXIAM_REQUIRE_THROWS_AS(client.oidc_exchange(exchange_params("")), axiam::AuthError);
    AXIAM_REQUIRE(f.st->count() == 0);
}

AXIAM_TEST("§12.3 rule 3 an OAuth2 error body surfaces its code, not the generic 400") {
    Fixture f;
    f.replies->token_script = {
        {400, R"({"error":"invalid_grant","error_description":"code already used"})"}};
    auto client = make_client(f);
    try {
        client.oidc_exchange(exchange_params());
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        // A 400 from /oauth2/token MUST NOT surface as the generic §2 400 row
        // (NetworkError). The code is what §14.2 rule 5 and §15.3 tell callers
        // to dispatch on.
        AXIAM_REQUIRE(e.error_code() == "invalid_grant");
        AXIAM_REQUIRE(std::string(e.what()) == "invalid_grant: code already used");
    }
}

AXIAM_TEST("§16.2 exchange is never retried, because the code is single-use") {
    Fixture f;
    f.replies->token_script = {{503, "{}"}};
    auto client = make_client(f);
    AXIAM_REQUIRE_THROWS_AS(client.oidc_exchange(exchange_params()), axiam::NetworkError);
    // Retrying replays a spent authorization code and turns a recoverable 503
    // into a hard `invalid_grant` the caller cannot interpret. EXACTLY ONE
    // request, on every outcome.
    AXIAM_REQUIRE(f.replies->token_calls == 1);
}

// ---------------------------------------------------------------------------
// §12.4 — one failing test per rule
// ---------------------------------------------------------------------------

namespace {

/// Assert that a token minted from `payload` is rejected with `reason`, and that
/// §12.4 rule 7 discarded the whole set with it.
void assert_id_token_rejected(const std::string& payload, const char* reason,
                              const char* nonce = "the-nonce") {
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    f.replies->token_script = {{200, token_body_with_id(key.make_jwt("EdDSA", payload))}};
    auto client = make_client(f);
    try {
        client.oidc_exchange(exchange_params(nonce));
        AXIAM_REQUIRE(false);
    } catch (const axiam::OidcValidationError& e) {
        AXIAM_REQUIRE(e.reason() == reason);
        // Rule 8 / §2: the message never carries the token.
        AXIAM_REQUIRE(std::string(e.what()).find("eyJ") == std::string::npos);
    }
    // Rule 7, every time: no partial success. The exception is the only outcome,
    // so the access and refresh tokens from the same response never reach the
    // caller — there is no object for them to be attached to.
}

}  // namespace

AXIAM_TEST("§12.4 a valid ID token yields claims and preserves unknown ones") {
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    // `department` is not in openapi.json — the ID token's claim set is not
    // enumerated there, so §12.1 forbids rejecting what an SDK does not
    // recognise and requires preserving it.
    const std::string payload =
        good_claims(R"(,"email":"a@b.test","roles":["admin"],"department":"ops")");
    f.replies->token_script = {{200, token_body_with_id(key.make_jwt("EdDSA", payload))}};

    auto client = make_client(f);
    const auto set = client.oidc_exchange(exchange_params());

    AXIAM_REQUIRE(set.id_claims.has_value());
    AXIAM_REQUIRE(set.id_claims->subject == "user-1");
    AXIAM_REQUIRE(set.id_claims->issuer == kIssuer);
    AXIAM_REQUIRE(set.id_claims->audience.size() == 1);
    AXIAM_REQUIRE(set.id_claims->email.value_or("") == "a@b.test");
    AXIAM_REQUIRE(set.id_claims->roles.size() == 1);
    AXIAM_REQUIRE(set.id_claims->raw_claims_json.find("\"department\":\"ops\"") !=
                  std::string::npos);
    // The whole set survives together — the other half of rule 7.
    AXIAM_REQUIRE(axiam::detail::reveal(set.access_token) == "the-access-token");
    AXIAM_REQUIRE(set.refresh_token.has_value());
}

AXIAM_TEST("§12.4 rule 1 alg:none is rejected before any key is consulted") {
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    f.replies->token_script = {{200, token_body_with_id(key.make_alg_none_jwt(good_claims()))}};
    auto client = make_client(f);
    try {
        client.oidc_exchange(exchange_params());
        AXIAM_REQUIRE(false);
    } catch (const axiam::OidcValidationError& e) {
        AXIAM_REQUIRE(e.reason() == axiam::OidcValidationReason::kInvalidAlg);
    }
    // No key was fetched, because the algorithm was refused first: §12.4 rule 1
    // requires `alg` read from the header and checked BEFORE any signature work.
    AXIAM_REQUIRE(f.replies->jwks_calls == 0);
}

AXIAM_TEST("§12.4 rule 1 the HS/EdDSA confusion is rejected") {
    // The classic confusion: the attacker's "secret" is the published
    // verification key. An implementation that trusted the header would compute
    // the same MAC and accept the token.
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    f.replies->token_script = {
        {200, token_body_with_id(key.make_hs256_confused_jwt(good_claims()))}};
    auto client = make_client(f);
    try {
        client.oidc_exchange(exchange_params());
        AXIAM_REQUIRE(false);
    } catch (const axiam::OidcValidationError& e) {
        AXIAM_REQUIRE(e.reason() == axiam::OidcValidationReason::kInvalidAlg);
    }
    AXIAM_REQUIRE(f.replies->jwks_calls == 0);
}

AXIAM_TEST("§12.4 rule 2 an unknown kid re-fetches once per cooldown window") {
    // As contract 1.5 corrected it: "one re-fetch then fail" is per WINDOW, not
    // per token. Taken literally against a warm cache it is unimplementable
    // without handing an attacker one JWKS fetch per forged `kid` — the
    // amplification the rule exists to prevent.
    //
    // Asserted the only way it can be: by counting JWKS fetches across two
    // verifications with unknown kids. The first opens the window and costs one
    // extra fetch; the second re-consults the cached set with none.
    Fixture f;
    axtest::TestKey served;
    axtest::TestKey rotated_away;
    rotated_away.kid = "rotated-away";
    f.replies->jwks_body = served.jwks_json();

    auto client = make_client(f);
    const std::string token = rotated_away.make_jwt("EdDSA", good_claims());

    f.replies->token_script = {{200, token_body_with_id(token)}};
    AXIAM_REQUIRE_THROWS_AS(client.oidc_exchange(exchange_params()),
                            axiam::OidcValidationError);
    // The initial cache fill plus exactly one re-fetch.
    const std::size_t after_first = f.replies->jwks_calls;
    AXIAM_REQUIRE(after_first == 2);

    f.replies->token_script = {{200, token_body_with_id(token)}};
    AXIAM_REQUIRE_THROWS_AS(client.oidc_exchange(exchange_params()),
                            axiam::OidcValidationError);
    // Inside the window: no network call at all. Not "never re-fetch" (key
    // rotation would break) and not "always re-fetch" (the amplifier).
    AXIAM_REQUIRE(f.replies->jwks_calls == after_first);
}

AXIAM_TEST("§12.4 rule 3 a foreign issuer, and a trailing slash, are rejected") {
    // EXACT string comparison: no normalization, no trailing-slash tolerance,
    // no prefix matching. Each of those has been an OP-confusion CVE.
    assert_id_token_rejected(
        std::string("{\"iss\":\"https://evil.test\",\"aud\":\"") + kClientId +
            "\",\"sub\":\"u\",\"exp\":" + std::to_string(now() + 900) +
            ",\"iat\":" + std::to_string(now() - 5) + ",\"nonce\":\"the-nonce\"}",
        axiam::OidcValidationReason::kInvalidIssuer);
    assert_id_token_rejected(
        std::string("{\"iss\":\"") + kIssuer + "/\",\"aud\":\"" + kClientId +
            "\",\"sub\":\"u\",\"exp\":" + std::to_string(now() + 900) +
            ",\"iat\":" + std::to_string(now() - 5) + ",\"nonce\":\"the-nonce\"}",
        axiam::OidcValidationReason::kInvalidIssuer);
}

AXIAM_TEST("§12.4 rule 4 another RP's token, and a multi-aud token with no azp, are rejected") {
    assert_id_token_rejected(
        std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":\"some-other-rp\",\"sub\":\"u\",\"exp\":" +
            std::to_string(now() + 900) + ",\"iat\":" + std::to_string(now() - 5) +
            ",\"nonce\":\"the-nonce\"}",
        axiam::OidcValidationReason::kInvalidAudience);
    // `aud` names this client, but with more than one audience rule 4
    // additionally requires `azp` — and it is absent.
    assert_id_token_rejected(
        std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":[\"" + kClientId +
            "\",\"other\"],\"sub\":\"u\",\"exp\":" + std::to_string(now() + 900) +
            ",\"iat\":" + std::to_string(now() - 5) + ",\"nonce\":\"the-nonce\"}",
        axiam::OidcValidationReason::kInvalidAudience);
}

AXIAM_TEST("§12.4 rule 4 multiple audiences with a correct azp are accepted") {
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    const std::string payload =
        std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":[\"" + kClientId +
        "\",\"other\"],\"azp\":\"" + kClientId + "\",\"sub\":\"u\",\"exp\":" +
        std::to_string(now() + 900) + ",\"iat\":" + std::to_string(now() - 5) +
        ",\"nonce\":\"the-nonce\"}";
    f.replies->token_script = {{200, token_body_with_id(key.make_jwt("EdDSA", payload))}};
    auto client = make_client(f);
    const auto set = client.oidc_exchange(exchange_params());
    AXIAM_REQUIRE(set.id_claims->authorized_party.value_or("") == kClientId);
}

AXIAM_TEST("§12.4 rule 5 every time failure reports the single code token_expired") {
    // The closed-vocabulary consequence, spelled out in §12.3 rule 3: a past
    // `exp`, an ABSENT `exp`, an absent or future `iat`, and a future `nbf` all
    // report the SAME code. There is no `token_not_yet_valid`, no
    // `iat_in_future` and no `missing_exp`.
    const std::string iss_aud = std::string("\"iss\":\"") + kIssuer + "\",\"aud\":\"" + kClientId +
                                "\",\"sub\":\"u\",\"nonce\":\"the-nonce\"";
    assert_id_token_rejected("{" + iss_aud + ",\"exp\":" + std::to_string(now() - 3600) +
                                 ",\"iat\":" + std::to_string(now() - 4000) + "}",
                             axiam::OidcValidationReason::kTokenExpired);
    assert_id_token_rejected("{" + iss_aud + ",\"iat\":" + std::to_string(now() - 5) + "}",
                             axiam::OidcValidationReason::kTokenExpired);
    assert_id_token_rejected("{" + iss_aud + ",\"exp\":" + std::to_string(now() + 900) + "}",
                             axiam::OidcValidationReason::kTokenExpired);
    assert_id_token_rejected("{" + iss_aud + ",\"exp\":" + std::to_string(now() + 900) +
                                 ",\"iat\":" + std::to_string(now() + 600) + "}",
                             axiam::OidcValidationReason::kTokenExpired);
    assert_id_token_rejected("{" + iss_aud + ",\"exp\":" + std::to_string(now() + 900) +
                                 ",\"iat\":" + std::to_string(now() - 5) +
                                 ",\"nbf\":" + std::to_string(now() + 600) + "}",
                             axiam::OidcValidationReason::kTokenExpired);
}

AXIAM_TEST("§12.4 rule 5 the clock-skew ceiling is clamped down, not rejected") {
    // At most 60 seconds, and a larger configured value is CLAMPED rather than
    // refused — an operator who asked for five minutes gets a working client
    // with a conformant window, not a construction failure they will route
    // around by disabling something.
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    // Expired 300 s ago: inside a (refused) 3600 s window, outside the 60 s cap.
    const std::string payload =
        std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":\"" + kClientId +
        "\",\"sub\":\"u\",\"exp\":" + std::to_string(now() - 300) +
        ",\"iat\":" + std::to_string(now() - 900) + ",\"nonce\":\"the-nonce\"}";
    f.replies->token_script = {{200, token_body_with_id(key.make_jwt("EdDSA", payload))}};

    auto client = axiam::Client::builder()
                      .base_url("https://iam.example.com")
                      .tenant_id(kTenantUuid)
                      .oidc_client_id(kClientId)
                      .oidc_clock_skew(std::chrono::seconds(3600))
                      .transport(routed(f.st, f.replies))
                      .build();
    AXIAM_REQUIRE_THROWS_AS(client.oidc_exchange(exchange_params()),
                            axiam::OidcValidationError);
}

AXIAM_TEST("§12.4 rule 6 a mismatched or absent nonce is rejected") {
    assert_id_token_rejected(good_claims(), axiam::OidcValidationReason::kNonceMismatch,
                             "a-different-nonce");
    assert_id_token_rejected(
        std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":\"" + kClientId +
            "\",\"sub\":\"u\",\"exp\":" + std::to_string(now() + 900) +
            ",\"iat\":" + std::to_string(now() - 5) + "}",
        axiam::OidcValidationReason::kNonceMismatch);
}

AXIAM_TEST("§12.4 rule 6 is skipped for a refresh-issued ID token") {
    // OIDC Core §12.2 does not require a nonce in a refresh-issued ID token, and
    // `login_client_credentials` had no authorization request to carry one.
    // Rules 1-5 and 7 still apply.
    Fixture f;
    axtest::TestKey key;
    f.replies->jwks_body = key.jwks_json();
    const std::string payload = std::string("{\"iss\":\"") + kIssuer + "\",\"aud\":\"" +
                                kClientId + "\",\"sub\":\"u\",\"exp\":" +
                                std::to_string(now() + 900) + ",\"iat\":" +
                                std::to_string(now() - 5) + "}";
    f.replies->token_script = {
        {200, R"({"access_token":"at","token_type":"Bearer","expires_in":900,"id_token":")" +
                  key.make_jwt("EdDSA", payload) + "\"}"}};
    auto client = make_client(f);
    const auto set = client.login_client_credentials();
    AXIAM_REQUIRE(set.id_claims.has_value());
    AXIAM_REQUIRE_FALSE(set.id_claims->nonce.has_value());
}

// ---------------------------------------------------------------------------
// §12.1 login_client_credentials / introspect / revoke / sso
// ---------------------------------------------------------------------------

AXIAM_TEST("§12.1 client credentials omits an absent scope and adopts nothing") {
    Fixture f;
    f.replies->token_script = {
        {200, R"({"access_token":"m2m","token_type":"Bearer","expires_in":900})"}};
    auto client = make_client(f);
    const auto set = client.login_client_credentials();

    AXIAM_REQUIRE(last_request(*f.st, "/oauth2/token").body.find("grant_type=client_credentials") !=
                  std::string::npos);
    // §12.1: an optional field the caller did not supply is OMITTED, never sent
    // empty. A SERVICE ACCOUNT registers no scopes at all, so `scope=` would
    // answer `invalid_scope`.
    AXIAM_REQUIRE_FALSE(body_has_field(*f.st, "/oauth2/token", "scope"));
    // §12.1's adoption MAY: this SDK declines, so no session is installed.
    AXIAM_REQUIRE_FALSE(client.has_session());
    AXIAM_REQUIRE(axiam::detail::reveal(set.access_token) == "m2m");
}

AXIAM_TEST("§12.1 rule 4 introspect refuses a public client with no wire call") {
    Fixture f;
    auto client = make_client(f, kClientId, /*secret=*/nullptr);
    // IntrospectRequest marks client_id AND client_secret required, so a public
    // client cannot call this. Refusing beats sending a request that cannot
    // succeed.
    AXIAM_REQUIRE_THROWS_AS(client.introspect(axiam::Sensitive<std::string>("t")),
                            axiam::AuthError);
    AXIAM_REQUIRE(f.replies->introspect_calls == 0);
}

AXIAM_TEST("§12.1 introspect surfaces the full result, and inactive is a success") {
    Fixture f;
    f.replies->introspect_body =
        R"({"active":true,"sub":"user-1","scope":"openid profile","jti":"jti-1","exp":1893456000})";
    auto client = make_client(f);
    const auto r = client.introspect(axiam::Sensitive<std::string>("t"), "access_token");
    AXIAM_REQUIRE(r.active);
    AXIAM_REQUIRE(r.subject.value_or("") == "user-1");
    AXIAM_REQUIRE(r.jwt_id.value_or("") == "jti-1");
    AXIAM_REQUIRE(body_has_field(*f.st, "/oauth2/introspect", "token_type_hint"));

    // `active` is the only guaranteed field, and false is the endpoint doing its
    // job — not a failure.
    Fixture g;
    g.replies->introspect_body = R"({"active":false})";
    auto c2 = make_client(g);
    AXIAM_REQUIRE_FALSE(c2.introspect(axiam::Sensitive<std::string>("stale")).active);
}

AXIAM_TEST("§12.3 rule 3 a 401 from introspect does not enter the refresh guard") {
    Fixture f;
    f.replies->introspect_status = 401;
    f.replies->introspect_body = R"({"error":"invalid_client"})";
    auto client = make_client(f);
    try {
        client.introspect(axiam::Sensitive<std::string>("t"));
        AXIAM_REQUIRE(false);
    } catch (const axiam::OAuthProtocolError& e) {
        AXIAM_REQUIRE(e.error_code() == "invalid_client");
    }
    // Client-credential failure is not a session expiry, and refreshing cannot
    // fix a wrong client secret. Asserted as a count, because "did not refresh"
    // is only observable on the wire.
    AXIAM_REQUIRE(client.refresh_call_count() == 0);
}

AXIAM_TEST("§12.1 rule 5 revoke is idempotent, and a 5xx is still a failure") {
    // RFC 7009 answers 200 for unknown, expired and already-revoked tokens, and
    // that idempotence is the point of the endpoint. Every implementing SDK MUST
    // carry this test.
    Fixture f;
    auto client = make_client(f);
    AXIAM_REQUIRE_NOTHROW(client.revoke(axiam::Sensitive<std::string>("never-issued")));
    AXIAM_REQUIRE_NOTHROW(client.revoke(axiam::Sensitive<std::string>("never-issued")));
    AXIAM_REQUIRE(f.replies->revoke_calls == 2);

    // The correction contract 1.5 made to 1.4: returning void does not turn a
    // server error into a silent success.
    Fixture g;
    g.replies->revoke_status = 503;
    g.replies->revoke_body = "upstream down";
    auto c2 = make_client(g);
    AXIAM_REQUIRE_THROWS_AS(c2.revoke(axiam::Sensitive<std::string>("t")), axiam::NetworkError);
    // And it is not retried — §16.2 names `oidc_revoke` ineligible.
    AXIAM_REQUIRE(g.replies->revoke_calls == 1);
}

AXIAM_TEST("§12.1 sso_start carries slug context in a JSON body and round-trips state") {
    Fixture f;
    f.replies->sso_body =
        R"({"authorize_url":"https://idp.test/a","state":"st-1","expires_in_secs":600})";
    // A slug-only client CAN call this pair — §12.1 note 2's five-operation
    // restriction covers only the /oauth2 endpoints.
    auto client = make_client(f, kClientId, kClientSecret, /*tenant_uuid=*/false);
    const auto r = client.sso_start("fed-1", kRedirectUri);

    const auto req = last_request(*f.st, "/federation/oidc/start");
    AXIAM_REQUIRE(req.headers.at("Content-Type") == "application/json");
    AXIAM_REQUIRE(req.body.find("\"tenant_slug\":\"acme\"") != std::string::npos);
    AXIAM_REQUIRE(req.body.find("\"federation_config_id\":\"fed-1\"") != std::string::npos);
    AXIAM_REQUIRE(r.state == "st-1");
    // §12.1 note 7: no nonce comes back and the SDK must not synthesise one.

    Fixture g;
    g.replies->sso_body =
        R"({"user_id":"u-1","session_id":"s-1","expires_in":900,"redirect_uri":"https://app.test/home"})";
    auto c2 = make_client(g);
    const auto done = c2.sso_complete("the-code", "st-1");
    AXIAM_REQUIRE(last_request(*g.st, "/federation/oidc/callback").body.find("\"state\":\"st-1\"") !=
                  std::string::npos);
    AXIAM_REQUIRE(done.user_id == "u-1");
    // §12.1 note 6: SsoLoginSuccessResponse carries NO token material — the
    // session is a Set-Cookie the §4 jar keeps. The struct has nowhere to put
    // one, which is the assertion.
}

AXIAM_TEST("§12.3 rule 5 no operation calls the userinfo endpoint") {
    // §12 adds no userinfo operation, and SDKs MUST NOT call
    // GET /oauth2/userinfo or substitute it for anything: a relying party's
    // claims come from the validated ID token. The discovery document
    // advertises the endpoint; nothing here may follow it.
    Fixture f;
    f.replies->token_script = {
        {200, R"({"access_token":"at","token_type":"Bearer","expires_in":900})"}};
    auto client = make_client(f);
    client.login_client_credentials();
    AXIAM_REQUIRE(f.st->count_path("/oauth2/userinfo") == 0);
}
