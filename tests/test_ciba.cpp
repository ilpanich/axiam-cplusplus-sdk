// CONTRACT.md §33 (contract 1.58) — CIBA: §33.8's sixteen required tests
// (t01–t16, in the Rust reference's order), plus the edges of the C++ port.
//
// No credential, key or token literal: the client secret, the auth_req_id, the
// notification token and every signing key are generated at run time. The
// signing keys are generated with OpenSSL and handed to the SDK as PEM it
// writes — so no private-key PEM header appears in this file either.

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <chrono>
#include <fstream>
#include <iterator>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"
#include "secret_util.hpp"
#include "test_key.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::json_response;
using nlohmann::json;

namespace {

const char* kBase = "https://iam.example.com";
const char* kIssuer = "https://iam.example.com";
const char* kTenant = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b";
const char* kClientId = "ciba-client";

std::string discovery(bool with_ciba = true, bool with_alias = false) {
    json doc = {{"issuer", kIssuer},
                {"authorization_endpoint", std::string(kBase) + "/oauth2/authorize"},
                {"token_endpoint", std::string(kBase) + "/oauth2/token?tenant_id=" + kTenant},
                {"jwks_uri", std::string(kBase) + "/oauth2/jwks"}};
    if (with_ciba) {
        doc["backchannel_authentication_endpoint"] =
            std::string(kBase) + "/oauth2/bc-authorize?tenant_id=" + kTenant;
        doc["backchannel_token_delivery_modes_supported"] = {"poll", "ping"};
        doc["backchannel_authentication_request_signing_alg_values_supported"] = {"PS256", "ES256",
                                                                                 "EdDSA"};
        doc["backchannel_user_code_parameter_supported"] = false;
    }
    if (with_alias) {
        doc["mtls_endpoint_aliases"] = {
            {"token_endpoint", "https://mtls.iam.example.com/oauth2/token"},
            {"backchannel_authentication_endpoint",
             "https://mtls.iam.example.com/oauth2/bc-authorize"}};
    }
    return doc.dump();
}

/// Parse a form body into its members.
std::map<std::string, std::string> form_of(const std::string& body) {
    std::map<std::string, std::string> out;
    std::size_t at = 0;
    while (at < body.size()) {
        const auto amp = body.find('&', at);
        const std::string pair = body.substr(at, amp == std::string::npos ? std::string::npos : amp - at);
        const auto eq = pair.find('=');
        std::string value = pair.substr(eq + 1), decoded;
        for (std::size_t i = 0; i < value.size(); ++i) {
            if (value[i] == '%' && i + 2 < value.size()) {
                decoded.push_back(static_cast<char>(std::stoi(value.substr(i + 1, 2), nullptr, 16)));
                i += 2;
            } else {
                decoded.push_back(value[i]);
            }
        }
        out[pair.substr(0, eq)] = decoded;
        if (amp == std::string::npos) break;
        at = amp + 1;
    }
    return out;
}

std::string query_of(const std::string& url) {
    const auto q = url.find('?');
    return q == std::string::npos ? std::string{} : url.substr(q + 1);
}

struct Rig {
    std::shared_ptr<FakeState> st = std::make_shared<FakeState>();
    axtest::TestKey key;
    std::string discovery_doc = discovery();
    std::string secret = axtest::random_secret("cs-");
    std::string auth_req_id = axtest::random_secret("arid-");
    std::function<HttpResponse(const HttpRequest&)> initiate = [this](const HttpRequest&) {
        return json_response(
            200, json{{"auth_req_id", auth_req_id}, {"expires_in", 120}, {"interval", 7}}.dump());
    };
    std::vector<std::pair<long, std::string>> token_script;  // answered in order, last repeats
    std::size_t token_calls = 0;

    std::string id_token() const {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
        return key.make_jwt("EdDSA", json{{"iss", kIssuer},
                                          {"aud", kClientId},
                                          {"sub", "user-1"},
                                          {"iat", now},
                                          {"exp", now + 300}}
                                         .dump());
    }
    std::string tokens() const {
        return json{{"access_token", axtest::random_secret("at-")},
                    {"token_type", "Bearer"},
                    {"expires_in", 900},
                    {"id_token", id_token()}}
            .dump();
    }

    Client client(bool with_secret = true, bool mtls = false) {
        st->router = [this](const HttpRequest& req, FakeState&) -> HttpResponse {
            if (req.url.find("openid-configuration") != std::string::npos) {
                return json_response(200, discovery_doc);
            }
            if (req.url.find("/oauth2/jwks") != std::string::npos) {
                return json_response(200, key.jwks_json());
            }
            if (req.url.find("/oauth2/bc-authorize") != std::string::npos) return initiate(req);
            if (req.url.find("/oauth2/token") != std::string::npos) {
                const auto& a = token_script.at(std::min(token_calls++, token_script.size() - 1));
                if (a.first == 0) {
                    HttpResponse r;
                    r.transport_error = "connection reset";
                    return r;
                }
                return json_response(a.first, a.second);
            }
            return json_response(404, "");
        };
        auto b = Client::builder()
                     .base_url(kBase)
                     .tenant_id(kTenant)
                     .oidc_client_id(kClientId)
                     .transport(axtest::make_fake(st));
        if (with_secret) b.oidc_client_secret(secret);
        if (mtls) {
            b.with_client_cert("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                               "-----BEGIN AXIAM TEST PLACEHOLDER-----\nMIIB\n"
                               "-----END AXIAM TEST PLACEHOLDER-----\n");
        }
        auto c = b.build();
        c._set_retry_test_seams([] { return 0.0; }, [](std::chrono::milliseconds) {});
        return c;
    }

    std::size_t calls(const char* path) { return st->count_path(path); }

    /// The most recent request whose URL contains `path` (an ID-token check may
    /// fetch the JWKS after it).
    axtest::RecordedReq last_to(const char* path) {
        std::lock_guard<std::mutex> lock(st->mtx);
        for (auto it = st->requests.rbegin(); it != st->requests.rend(); ++it) {
            if (it->url.find(path) != std::string::npos) return *it;
        }
        return {};
    }
};

/// A clock that only moves when the loop sleeps, recording every sleep.
struct FakeClock {
    std::shared_ptr<std::chrono::steady_clock::time_point> t =
        std::make_shared<std::chrono::steady_clock::time_point>(std::chrono::steady_clock::now());
    std::shared_ptr<std::vector<long>> sleeps = std::make_shared<std::vector<long>>();

    CibaClock clock() const {
        CibaClock c;
        auto now = t;
        auto log = sleeps;
        c.now = [now] { return *now; };
        c.sleep = [now, log](std::chrono::seconds d) {
            log->push_back(static_cast<long>(d.count()));
            *now += d;
        };
        return c;
    }
    CibaInitiateResponse initiated(std::int64_t expires_in, std::int64_t interval) const {
        CibaInitiateResponse r;
        r.auth_req_id = Sensitive<std::string>(axtest::random_secret("arid-"));
        r.expires_in = expires_in;
        r.interval = interval;
        r.received_at = *t;
        return r;
    }
};

std::string error_body(const char* code) { return json{{"error", code}}.dump(); }

template <typename F>
std::string oauth_code(F&& f) {
    try {
        f();
    } catch (const OAuthProtocolError& e) {
        return e.error_code();
    }
    return {};
}

// ---- keys -----------------------------------------------------------------

struct GeneratedKey {
    EVP_PKEY* pkey = nullptr;
    explicit GeneratedKey(CibaSigningAlg alg) {
        if (alg == CibaSigningAlg::kEdDSA) pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
        if (alg == CibaSigningAlg::kES256) pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
        if (alg == CibaSigningAlg::kPS256) {
            pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<size_t>(2048));
        }
    }
    ~GeneratedKey() { EVP_PKEY_free(pkey); }
    GeneratedKey(const GeneratedKey&) = delete;
    GeneratedKey& operator=(const GeneratedKey&) = delete;

    std::string pem() const {
        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        char* data = nullptr;
        const long len = BIO_get_mem_data(bio, &data);
        std::string out(data, static_cast<std::size_t>(len));
        BIO_free(bio);
        return out;
    }

    /// Verify a JOSE signature over `input` with this key's public half.
    bool verifies(CibaSigningAlg alg, const std::string& input, const std::string& sig) const {
        std::string der = sig;
        if (alg == CibaSigningAlg::kES256) {
            if (sig.size() != 64) return false;
            ECDSA_SIG* s = ECDSA_SIG_new();
            ECDSA_SIG_set0(s, BN_bin2bn(reinterpret_cast<const unsigned char*>(sig.data()), 32, nullptr),
                           BN_bin2bn(reinterpret_cast<const unsigned char*>(sig.data()) + 32, 32, nullptr));
            unsigned char* buf = nullptr;
            const int len = i2d_ECDSA_SIG(s, &buf);
            der.assign(reinterpret_cast<char*>(buf), static_cast<std::size_t>(len));
            OPENSSL_free(buf);
            ECDSA_SIG_free(s);
        }
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_PKEY_CTX* pctx = nullptr;
        bool ok = EVP_DigestVerifyInit(ctx, &pctx, alg == CibaSigningAlg::kEdDSA ? nullptr : EVP_sha256(),
                                       nullptr, pkey) == 1;
        if (ok && alg == CibaSigningAlg::kPS256) {
            ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
                 EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) == 1;
        }
        ok = ok && EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char*>(der.data()), der.size(),
                                    reinterpret_cast<const unsigned char*>(input.data()),
                                    input.size()) == 1;
        EVP_MD_CTX_free(ctx);
        return ok;
    }
};

std::string b64_json(const std::string& part) {
    return *axiam::base64url_decode(part);
}

CibaInitiateParams params(CibaUserHint hint = CibaUserHint::login_hint("alice")) {
    return CibaInitiateParams{"openid", std::move(hint)};
}

// ── t01 Redaction ───────────────────────────────────────────────────────────

AXIAM_TEST("§33.8 t01: the notification token and the auth_req_id reach the wire and no rendering") {
    Rig rig;
    rig.initiate = [&rig](const HttpRequest&) {
        return json_response(400, json{{"error", "invalid_request"},
                                       {"error_description", "bad hint"}}.dump());
    };
    auto client = rig.client();
    const std::string notification = axtest::random_secret("cnt-");
    auto p = params();
    p.delivery = CibaDelivery::ping(Sensitive<std::string>(notification));

    std::string rendered;
    try {
        client.ciba_initiate(p);
    } catch (const std::exception& e) {
        rendered += e.what();
    }
    AXIAM_CHECK(!rendered.empty());
    AXIAM_CHECK(form_of(rig.st->last().body).at("client_notification_token") == notification);

    rig.initiate = [&rig](const HttpRequest&) {
        return json_response(200, json{{"auth_req_id", rig.auth_req_id}, {"expires_in", 60}}.dump());
    };
    const auto initiated = client.ciba_initiate(p);
    AXIAM_CHECK(detail::reveal(initiated.auth_req_id) == rig.auth_req_id);  // on the wire
    std::ostringstream os;
    os << initiated.auth_req_id << p.delivery.client_notification_token();
    rendered += os.str();
    AXIAM_CHECK(axtest::no_fragment(rendered, notification));
    AXIAM_CHECK(axtest::no_fragment(rendered, rig.auth_req_id));
}

// ── t02 Client authentication is mandatory ─────────────────────────────────

AXIAM_TEST("§33.8 t02: no credential is a local AuthError; with one it is sent, tenant in the query") {
    Rig rig;
    auto anonymous = rig.client(/*with_secret=*/false);
    AXIAM_REQUIRE_THROWS_AS(anonymous.ciba_initiate(params()), AuthError);
    AXIAM_REQUIRE_THROWS_AS(anonymous.ciba_poll(Sensitive<std::string>(rig.auth_req_id)), AuthError);
    FakeClock fc;
    AXIAM_REQUIRE_THROWS_AS(anonymous.ciba_await(fc.initiated(60, 5)), AuthError);
    AXIAM_CHECK(rig.st->count() == 0);

    Rig with;
    with.token_script = {{200, with.tokens()}};
    auto client = with.client();
    client.ciba_initiate(params());
    auto sent = with.st->last();
    AXIAM_CHECK(form_of(sent.body).at("client_id") == kClientId);
    AXIAM_CHECK(form_of(sent.body).at("client_secret") == with.secret);
    AXIAM_CHECK(form_of(sent.body).count("tenant_id") == 0);
    AXIAM_CHECK(query_of(sent.url) == std::string("tenant_id=") + kTenant);
    AXIAM_CHECK(sent.headers.at("X-Tenant-ID") == kTenant);

    client.ciba_poll(Sensitive<std::string>(with.auth_req_id));
    sent = with.last_to("/oauth2/token");
    const auto form = form_of(sent.body);
    AXIAM_CHECK(form.at("grant_type") == kCibaGrantType);
    AXIAM_CHECK(form.at("auth_req_id") == with.auth_req_id);
    AXIAM_CHECK(form.at("client_secret") == with.secret);
    AXIAM_CHECK(form.count("tenant_id") == 0);
    AXIAM_CHECK(query_of(sent.url) == std::string("tenant_id=") + kTenant);
}

AXIAM_TEST("§33.1: an mTLS-only client sends client_id alone, at the seventh alias") {
    Rig rig;
    rig.discovery_doc = discovery(true, /*with_alias=*/true);
    rig.token_script = {{200, rig.tokens()}};
    auto client = rig.client(/*with_secret=*/false, /*mtls=*/true);
    client.ciba_initiate(params());
    auto sent = rig.st->last();
    AXIAM_CHECK(sent.url.rfind("https://mtls.iam.example.com/oauth2/bc-authorize?", 0) == 0);
    auto form = form_of(sent.body);
    AXIAM_CHECK(form.at("client_id") == kClientId && form.count("client_secret") == 0);

    client.ciba_poll(Sensitive<std::string>(rig.auth_req_id));
    sent = rig.last_to("/oauth2/token");
    AXIAM_CHECK(sent.url.rfind("https://mtls.iam.example.com/oauth2/token?", 0) == 0);
    form = form_of(sent.body);
    AXIAM_CHECK(form.at("client_id") == kClientId && form.count("client_secret") == 0);
}

AXIAM_TEST("§33.1: a server whose discovery has no CIBA endpoint is refused before any request to it") {
    Rig rig;
    rig.discovery_doc = discovery(false);
    auto client = rig.client();
    AXIAM_REQUIRE_THROWS_AS(client.ciba_initiate(params()), AuthError);
    AXIAM_CHECK(rig.calls("/oauth2/bc-authorize") == 0);
}

AXIAM_TEST("§21.5: the four CIBA discovery members are read") {
    Rig rig;
    auto client = rig.client();
    const auto cfg = client.oidc_discover();
    AXIAM_CHECK(cfg.backchannel_authentication_endpoint ==
                std::string(kBase) + "/oauth2/bc-authorize?tenant_id=" + kTenant);
    AXIAM_CHECK(cfg.backchannel_token_delivery_modes_supported ==
                std::vector<std::string>({"poll", "ping"}));
    AXIAM_CHECK(cfg.backchannel_authentication_request_signing_alg_values_supported.size() == 3);
    AXIAM_CHECK(cfg.backchannel_user_code_parameter_supported == std::optional<bool>(false));
}

// ── t03 The initiate request ───────────────────────────────────────────────

AXIAM_TEST("§33.8 t03: exactly the members the caller set are sent, form-encoded") {
    Rig rig;
    auto client = rig.client();
    client.ciba_initiate(params());
    auto form = form_of(rig.st->last().body);
    AXIAM_CHECK(form == (std::map<std::string, std::string>{
                            {"client_id", kClientId}, {"client_secret", rig.secret},
                            {"scope", "openid"}, {"login_hint", "alice"}}));
    AXIAM_CHECK(rig.st->last().headers.at("Content-Type") == "application/x-www-form-urlencoded");

    auto p = params(CibaUserHint::id_token_hint("eyJ.hint.sig"));
    p.binding_message = "W4SCT";
    p.requested_expiry = 300;
    p.acr_values = "urn:axiam:acr:mfa";
    p.resource = "https://api.example.com";
    const std::string notification = axtest::random_secret("cnt-");
    p.delivery = CibaDelivery::ping(Sensitive<std::string>(notification));
    client.ciba_initiate(p);
    form = form_of(rig.st->last().body);
    AXIAM_CHECK(form == (std::map<std::string, std::string>{
                            {"client_id", kClientId}, {"client_secret", rig.secret},
                            {"scope", "openid"}, {"id_token_hint", "eyJ.hint.sig"},
                            {"binding_message", "W4SCT"}, {"requested_expiry", "300"},
                            {"acr_values", "urn:axiam:acr:mfa"},
                            {"resource", "https://api.example.com"},
                            {"client_notification_token", notification}}));
    // The hint is one of two factories, so "both" and "neither" cannot be built,
    // and there is no member for login_hint_token, user_code or request_uri.
    AXIAM_CHECK(p.hint.kind() == CibaUserHint::Kind::kIdTokenHint);
}

AXIAM_TEST("§33.8 t03: a ping-mode request without a notification token is refused locally") {
    Rig rig;
    auto client = rig.client();
    auto p = params();
    p.delivery = CibaDelivery::ping(Sensitive<std::string>(""));
    AXIAM_REQUIRE_THROWS_AS(client.ciba_initiate(p), std::invalid_argument);
    AXIAM_CHECK(rig.st->count() == 0);
}

AXIAM_TEST("§33.2: the initiate response's interval defaults to 5, and a malformed one is refused") {
    Rig rig;
    rig.initiate = [&rig](const HttpRequest&) {
        return json_response(200, json{{"auth_req_id", rig.auth_req_id}, {"expires_in", 60},
                                       {"interval", 0}}.dump());
    };
    auto client = rig.client();
    const auto before = std::chrono::steady_clock::now();
    const auto r = client.ciba_initiate(params());
    AXIAM_CHECK(r.interval == kCibaDefaultIntervalSeconds && r.expires_in == 60);
    AXIAM_CHECK(r.received_at >= before);
    rig.initiate = [](const HttpRequest&) { return json_response(200, R"({"expires_in":60})"); };
    AXIAM_REQUIRE_THROWS_AS(client.ciba_initiate(params()), NetworkError);
}

// ── t04 No retry on initiate ───────────────────────────────────────────────

AXIAM_TEST("§33.8 t04: initiate is sent once on a 503, a 429 and a dropped connection") {
    Rig rig;
    auto client = rig.client();  // retry ENABLED
    rig.initiate = [](const HttpRequest&) { return json_response(503, ""); };
    AXIAM_REQUIRE_THROWS_AS(client.ciba_initiate(params()), NetworkError);
    AXIAM_CHECK(rig.calls("/oauth2/bc-authorize") == 1);

    rig.initiate = [](const HttpRequest&) { return json_response(429, error_body("rate_limit_exceeded")); };
    AXIAM_CHECK(oauth_code([&] { client.ciba_initiate(params()); }) == "rate_limit_exceeded");
    AXIAM_CHECK(rig.calls("/oauth2/bc-authorize") == 2);
    rig.initiate = [](const HttpRequest&) { return json_response(429, ""); };
    AXIAM_REQUIRE_THROWS_AS(client.ciba_initiate(params()), NetworkError);
    AXIAM_CHECK(rig.calls("/oauth2/bc-authorize") == 3);

    rig.initiate = [](const HttpRequest&) {
        HttpResponse r;
        r.transport_error = "connection reset by peer";
        return r;
    };
    AXIAM_REQUIRE_THROWS_AS(client.ciba_initiate(params()), NetworkError);
    AXIAM_CHECK(rig.calls("/oauth2/bc-authorize") == 4);
}

AXIAM_TEST("§33.4: invalid_binding_message surfaces with its description") {
    Rig rig;
    rig.initiate = [](const HttpRequest&) {
        return json_response(400, json{{"error", "invalid_binding_message"},
                                       {"error_description", "binding_message is too long"}}.dump());
    };
    auto client = rig.client();
    bool caught = false;
    try {
        client.ciba_initiate(params());
    } catch (const OAuthProtocolError& e) {
        caught = e.error_code() == "invalid_binding_message" &&
                 e.error_description() == std::optional<std::string>("binding_message is too long");
    }
    AXIAM_CHECK(caught);
}

// ── t05 Poll outcomes ──────────────────────────────────────────────────────

AXIAM_TEST("§33.8 t05: slow_down twice then pending then tokens sleeps 5, 10, 15, 15") {
    Rig rig;
    rig.token_script = {{400, error_body("slow_down")},
                        {400, error_body("slow_down")},
                        {400, error_body("authorization_pending")},
                        {200, rig.tokens()}};
    auto client = rig.client();
    FakeClock fc;
    CibaAwaitOptions o;
    o.clock = fc.clock();
    const auto tokens = client.ciba_await(fc.initiated(600, 5), o);
    AXIAM_CHECK(*fc.sleeps == std::vector<long>({5, 10, 15, 15}));
    AXIAM_CHECK(rig.token_calls == 4);
    AXIAM_CHECK(tokens.id_claims.has_value());
}

AXIAM_TEST("§33.8 t05: access_denied, expired_token, invalid_grant and an unknown code are terminal after one request") {
    for (const char* code : {"access_denied", "expired_token", "invalid_grant", "something_new"}) {
        Rig rig;
        rig.token_script = {{400, error_body(code)}};
        auto client = rig.client();
        FakeClock fc;
        CibaAwaitOptions o;
        o.clock = fc.clock();
        bool denied = false, expired = false;
        std::string seen;
        try {
            client.ciba_await(fc.initiated(600, 5), o);
        } catch (const OAuthProtocolError& e) {
            seen = e.error_code();
            denied = e.is_access_denied();
            expired = e.is_expired_token();
        }
        AXIAM_CHECK(seen == code);
        AXIAM_CHECK(rig.token_calls == 1);
        AXIAM_CHECK(denied == (seen == "access_denied"));
        AXIAM_CHECK(expired == (seen == "expired_token"));
        AXIAM_CHECK(!(denied && expired));  // the two outcomes are distinct
    }
}

AXIAM_TEST("§33.4: a bodiless 400 and a bodiless 401 at the poll are terminal, by status") {
    Rig rig;
    rig.token_script = {{400, ""}};
    auto client = rig.client();
    FakeClock fc;
    CibaAwaitOptions o;
    o.clock = fc.clock();
    AXIAM_REQUIRE_THROWS_AS(client.ciba_await(fc.initiated(600, 5), o), NetworkError);
    AXIAM_CHECK(rig.token_calls == 1);
    rig.token_script = {{401, ""}};
    rig.token_calls = 0;
    AXIAM_REQUIRE_THROWS_AS(client.ciba_await(fc.initiated(600, 5), o), AuthError);
    AXIAM_CHECK(rig.token_calls == 1);
}

// ── t06 The first poll waits ───────────────────────────────────────────────

AXIAM_TEST("§33.8 t06: the first poll waits the response's interval, or 5 when absent") {
    for (const std::int64_t interval : {7, 0}) {
        Rig rig;
        rig.token_script = {{200, rig.tokens()}};
        auto client = rig.client();
        FakeClock fc;
        CibaAwaitOptions o;
        o.clock = fc.clock();
        client.ciba_await(fc.initiated(600, interval), o);
        AXIAM_CHECK(*fc.sleeps == std::vector<long>({interval == 7 ? 7L : 5L}));
    }
}

// ── t07 Deadline ───────────────────────────────────────────────────────────

AXIAM_TEST("§33.8 t07: expires_in 12, interval 5 polls at 5 and 10, then expired_token locally") {
    Rig rig;
    rig.token_script = {{400, error_body("authorization_pending")}};
    auto client = rig.client();
    FakeClock fc;
    CibaAwaitOptions o;
    o.clock = fc.clock();
    AXIAM_CHECK(oauth_code([&] { client.ciba_await(fc.initiated(12, 5), o); }) == "expired_token");
    AXIAM_CHECK(rig.token_calls == 2);
    AXIAM_CHECK(*fc.sleeps == std::vector<long>({5, 5}));
}

AXIAM_TEST("§33.7 rule 4: with the default clock, an already-expired request raises locally at once") {
    Rig rig;
    auto client = rig.client();
    CibaInitiateResponse late;
    late.auth_req_id = Sensitive<std::string>(axtest::random_secret("arid-"));
    late.expires_in = 3;
    late.interval = 5;
    late.received_at = std::chrono::steady_clock::now();
    AXIAM_CHECK(oauth_code([&] { client.ciba_await(late); }) == "expired_token");
    AXIAM_CHECK(rig.calls("/oauth2/token") == 0);
    const CibaClock system = CibaClock::system();
    const auto before = system.now();
    system.sleep(std::chrono::seconds(0));
    AXIAM_CHECK(system.now() >= before);
}

// ── t08 Transient failure ──────────────────────────────────────────────────

AXIAM_TEST("§33.8 t08: a 500 {\"error\":\"server_error\"} and a 429 mid-loop are survived, then a 200 with its tokens") {
    Rig rig;
    // Contract 1.59 (§34.2 P8): the 500 carries the body AXIAM's token endpoint
    // actually sends — a 5xx on ciba_poll is transient whatever its body.
    rig.token_script = {{400, error_body("authorization_pending")},
                        {500, error_body("server_error")}, {500, error_body("server_error")},
                        {500, error_body("server_error")},
                        {429, error_body("rate_limit_exceeded")},
                        {0, ""}, {429, ""}, {429, ""},
                        {200, rig.tokens()}};
    auto client = rig.client();
    FakeClock fc;
    CibaAwaitOptions o;
    o.clock = fc.clock();
    const auto tokens = client.ciba_await(fc.initiated(600, 5), o);
    AXIAM_CHECK(!detail::reveal(tokens.access_token).empty());
    AXIAM_REQUIRE(tokens.id_token.has_value());
    AXIAM_CHECK(tokens.id_claims->subject == "user-1");
    // pending, 3×500 server_error (one §16-retried poll), rate_limit_exceeded, a reset then two
    // bodiless 429s (one §16-retried poll), the 200: five intervals.
    AXIAM_CHECK(fc.sleeps->size() == 5);
    AXIAM_CHECK(rig.token_calls == 9);
}

// ── t09 Single use ─────────────────────────────────────────────────────────

AXIAM_TEST("§33.8 t09: after a 200, a second poll is invalid_grant and is not retried") {
    Rig rig;
    rig.token_script = {{200, rig.tokens()}, {400, error_body("invalid_grant")}};
    auto client = rig.client();
    const Sensitive<std::string> id(rig.auth_req_id);
    client.ciba_poll(id);
    AXIAM_CHECK(oauth_code([&] { client.ciba_poll(id); }) == "invalid_grant");
    AXIAM_CHECK(rig.token_calls == 2);
}

AXIAM_TEST("§33.7 rule 5: ciba_poll retries a 5xx per §16 and not an empty auth_req_id") {
    Rig rig;
    rig.token_script = {{503, ""}, {200, rig.tokens()}};
    auto client = rig.client();
    client.ciba_poll(Sensitive<std::string>(rig.auth_req_id));
    AXIAM_CHECK(rig.token_calls == 2);
    AXIAM_REQUIRE_THROWS_AS(client.ciba_poll(Sensitive<std::string>("")), AuthError);
    FakeClock fc;
    CibaInitiateResponse empty;
    AXIAM_REQUIRE_THROWS_AS(client.ciba_await(empty), AuthError);
    AXIAM_CHECK(rig.token_calls == 2);

    rig.token_script = {{0, ""}};
    rig.token_calls = 0;
    AXIAM_REQUIRE_THROWS_AS(client.ciba_poll(Sensitive<std::string>(rig.auth_req_id)), NetworkError);
    AXIAM_CHECK(rig.token_calls == 3);

    // §34.2 P8: a 5xx WITH an `error` member is retried the same way — the
    // server's own 500 {"error":"server_error"}, and 503 temporarily_unavailable —
    // and, once §16 is spent, is a NetworkError, never a terminal protocol answer.
    rig.token_script = {{500, error_body("server_error")}, {200, rig.tokens()}};
    rig.token_calls = 0;
    client.ciba_poll(Sensitive<std::string>(rig.auth_req_id));
    AXIAM_CHECK(rig.token_calls == 2);
    rig.token_script = {{503, error_body("temporarily_unavailable")}};
    rig.token_calls = 0;
    AXIAM_REQUIRE_THROWS_AS(client.ciba_poll(Sensitive<std::string>(rig.auth_req_id)), NetworkError);
    AXIAM_CHECK(rig.token_calls == 3);
}

// ── t10–t13 The ping ───────────────────────────────────────────────────────

using Headers = std::vector<std::pair<std::string, std::string>>;

AXIAM_TEST("§33.8 t10: a valid ping returns the auth_req_id, Sensitive, in any scheme case") {
    Rig rig;
    auto client = rig.client();
    const std::string expected = axtest::random_secret("cnt-");
    const std::string id = axtest::random_secret("arid-");
    const std::string body = json{{"auth_req_id", id}}.dump();
    for (const char* scheme : {"Bearer", "bearer", "BEARER"}) {
        const auto got = client.ciba_handle_ping(
            Headers{{"Content-Type", "application/json"}, {"authorization", std::string(scheme) + " " + expected}},
            body, Sensitive<std::string>(expected));
        AXIAM_CHECK(detail::reveal(got) == id);
        std::ostringstream os;
        os << got;
        AXIAM_CHECK(axtest::no_fragment(os.str(), id));
    }
}

AXIAM_TEST("§33.8 t11: a wrong, absent, empty, duplicated, Basic or near-miss bearer is an AuthError") {
    Rig rig;
    auto client = rig.client();
    const std::string expected = axtest::random_secret("cnt-");
    const std::string body = json{{"auth_req_id", "a"}}.dump();
    std::string near = expected;
    near.back() = near.back() == '0' ? '1' : '0';
    const std::vector<Headers> refused = {
        {{"Authorization", "Bearer " + axtest::random_secret("cnt-")}},
        {},
        {{"Authorization", ""}},
        {{"Authorization", "Bearer "}},
        {{"Authorization", "Bearer " + expected}, {"AUTHORIZATION", "Bearer " + expected}},
        {{"Authorization", "Basic " + expected}},
        {{"Authorization", "Bearer " + near}},
        {{"Authorization", "Bearer  " + expected}},
        {{"Authorization", "Bearer" + expected}},
    };
    for (const auto& headers : refused) {
        std::string message;
        try {
            client.ciba_handle_ping(headers, body, Sensitive<std::string>(expected));
        } catch (const AuthError& e) {
            message = e.what();
        }
        AXIAM_CHECK(!message.empty());
        AXIAM_CHECK(axtest::no_fragment(message, expected));
    }
    // An empty expected token never matches, whatever is presented.
    AXIAM_REQUIRE_THROWS_AS(client.ciba_handle_ping(Headers{{"Authorization", "Bearer "}}, body,
                                                    Sensitive<std::string>("")),
                            AuthError);

    // Structurally: the comparison is CRYPTO_memcmp, OpenSSL's constant-time one.
    std::ifstream src(std::string(AXIAM_REPO_ROOT) + "/src/oidc.cpp");
    const std::string text((std::istreambuf_iterator<char>(src)), std::istreambuf_iterator<char>());
    const auto at = text.find("bool ping_token_matches(");
    AXIAM_REQUIRE(at != std::string::npos);
    const std::string fn = text.substr(at, text.find("\n}\n", at) - at);
    AXIAM_CHECK(fn.find("CRYPTO_memcmp(") != std::string::npos);
    AXIAM_CHECK(fn.find("==", fn.find("CRYPTO_memcmp(")) != std::string::npos);
    AXIAM_CHECK(text.find("ping_token_matches(authorization->substr(space + 1)") != std::string::npos);
}

AXIAM_TEST("§33.8 t12: a body that is not an object with a non-empty auth_req_id is refused; extras are ignored") {
    Rig rig;
    auto client = rig.client();
    const std::string expected = axtest::random_secret("cnt-");
    const Headers ok{{"Authorization", "Bearer " + expected}};
    for (const char* body : {"not json", "[]", "{}", R"({"auth_req_id":""})", R"({"auth_req_id":5})"}) {
        AXIAM_REQUIRE_THROWS_AS(client.ciba_handle_ping(ok, body, Sensitive<std::string>(expected)),
                                std::invalid_argument);
    }
    const auto id = client.ciba_handle_ping(
        ok, R"({"auth_req_id":"x-1","status":"approved","access_token":"t"})",
        Sensitive<std::string>(expected));
    AXIAM_CHECK(detail::reveal(id) == "x-1");
}

AXIAM_TEST("§33.8 t13: the ping helper makes no network call") {
    auto st = std::make_shared<FakeState>();
    bool touched = false;
    st->router = [&touched](const HttpRequest&, FakeState&) {
        touched = true;
        return json_response(500, "");
    };
    auto client = Client::builder()
                      .base_url(kBase)
                      .tenant_id(kTenant)
                      .transport(axtest::make_fake(st))
                      .build();
    const std::string expected = axtest::random_secret("cnt-");
    client.ciba_handle_ping(Headers{{"Authorization", "Bearer " + expected}},
                            R"({"auth_req_id":"a"})", Sensitive<std::string>(expected));
    AXIAM_CHECK(!touched && st->count() == 0);
}

// ── t14–t16 The signed form ────────────────────────────────────────────────

AXIAM_TEST("§33.8 t14: the signed form carries only client auth and request, signed under the caller's algorithm") {
    for (const auto alg : {CibaSigningAlg::kEdDSA, CibaSigningAlg::kES256, CibaSigningAlg::kPS256}) {
        Rig rig;
        auto client = rig.client();
        const GeneratedKey key(alg);
        auto p = params();
        p.binding_message = "W4SCT";
        p.requested_expiry = 120;
        const std::string notification = axtest::random_secret("cnt-");
        p.delivery = CibaDelivery::ping(Sensitive<std::string>(notification));
        p.signer = CibaRequestSigner::from_pem(alg, Sensitive<std::string>(key.pem()), "sig-1");
        AXIAM_CHECK(p.signer->alg() == alg && p.signer->kid() == std::optional<std::string>("sig-1"));

        client.ciba_initiate(p);
        const auto first = form_of(rig.st->last().body);
        client.ciba_initiate(p);
        const auto second = form_of(rig.st->last().body);
        AXIAM_CHECK(first.size() == 3);  // client_id, client_secret, request
        AXIAM_CHECK(first.at("client_id") == kClientId && first.count("client_secret") == 1);

        const std::string jws = first.at("request");
        const auto d1 = jws.find('.');
        const auto d2 = jws.rfind('.');
        const json header = json::parse(b64_json(jws.substr(0, d1)));
        const json claims = json::parse(b64_json(jws.substr(d1 + 1, d2 - d1 - 1)));
        AXIAM_CHECK(header.at("alg") == (alg == CibaSigningAlg::kEdDSA ? "EdDSA"
                                         : alg == CibaSigningAlg::kES256 ? "ES256" : "PS256"));
        AXIAM_CHECK(header.at("kid") == "sig-1");
        AXIAM_CHECK(key.verifies(alg, jws.substr(0, d2), b64_json(jws.substr(d2 + 1))));
        AXIAM_CHECK(claims.at("iss") == kClientId);
        AXIAM_CHECK(claims.at("aud") == kIssuer);
        const auto nbf = claims.at("nbf").get<std::int64_t>();
        AXIAM_CHECK(claims.at("iat").get<std::int64_t>() == nbf);
        AXIAM_CHECK(claims.at("exp").get<std::int64_t>() - nbf == kCibaSignedRequestLifetimeSeconds);
        AXIAM_CHECK(claims.at("jti").get<std::string>().size() == 32);  // 128 bits, hex
        AXIAM_CHECK(claims.at("scope") == "openid" && claims.at("login_hint") == "alice");
        AXIAM_CHECK(claims.at("binding_message") == "W4SCT");
        AXIAM_CHECK(claims.at("requested_expiry") == 120);  // a NUMBER inside the JWT
        AXIAM_CHECK(claims.at("client_notification_token") == notification);

        const json claims2 = json::parse(b64_json(second.at("request").substr(
            second.at("request").find('.') + 1,
            second.at("request").rfind('.') - second.at("request").find('.') - 1)));
        AXIAM_CHECK(claims2.at("jti") != claims.at("jti"));
    }
}

AXIAM_TEST("§33.8 t15: no key, or a key of another algorithm, is refused before any request") {
    const GeneratedKey ed(CibaSigningAlg::kEdDSA);
    const GeneratedKey ec(CibaSigningAlg::kES256);
    const GeneratedKey rsa(CibaSigningAlg::kPS256);
    EVP_PKEY* p384 = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-384");
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, p384, nullptr, nullptr, 0, nullptr, nullptr);
    char* data = nullptr;
    const long p384_len = BIO_get_mem_data(bio, &data);  // sets `data` — before it is read
    const std::string p384_pem(data, static_cast<std::size_t>(p384_len));
    BIO_free(bio);
    EVP_PKEY_free(p384);

    const auto refused = [](CibaSigningAlg alg, const std::string& pem) {
        try {
            CibaRequestSigner::from_pem(alg, Sensitive<std::string>(pem));
        } catch (const std::invalid_argument& e) {
            return std::string(e.what()).find("BEGIN") == std::string::npos;
        }
        return false;
    };
    AXIAM_CHECK(refused(CibaSigningAlg::kEdDSA, ""));
    AXIAM_CHECK(refused(CibaSigningAlg::kEdDSA, "not a pem"));
    AXIAM_CHECK(refused(CibaSigningAlg::kEdDSA, ec.pem()));
    AXIAM_CHECK(refused(CibaSigningAlg::kES256, ed.pem()));
    AXIAM_CHECK(refused(CibaSigningAlg::kES256, p384_pem));
    AXIAM_CHECK(refused(CibaSigningAlg::kPS256, ec.pem()));
    AXIAM_CHECK(refused(CibaSigningAlg::kEdDSA, rsa.pem()));
    AXIAM_CHECK(!refused(CibaSigningAlg::kEdDSA, ed.pem()));
    // There is no "form parameter beside `request`" to refuse: the signed form is
    // chosen by setting `signer`, and every member then travels inside the JWT.
}

AXIAM_TEST("§33.8 t16: the key material and the request string appear in no stringification") {
    Rig rig;
    rig.initiate = [](const HttpRequest&) {
        return json_response(400, error_body("invalid_request"));
    };
    auto client = rig.client();
    const GeneratedKey key(CibaSigningAlg::kEdDSA);
    const std::string pem = key.pem();
    auto p = params();
    p.signer = CibaRequestSigner::from_pem(CibaSigningAlg::kEdDSA, Sensitive<std::string>(pem));
    std::string message;
    try {
        client.ciba_initiate(p);
    } catch (const std::exception& e) {
        message = e.what();
    }
    const std::string request = form_of(rig.st->last().body).at("request");
    AXIAM_CHECK(!message.empty());
    AXIAM_CHECK(axtest::no_fragment(message, request));
    AXIAM_CHECK(axtest::no_fragment(message, pem.substr(28, 40)));  // past the PEM header
    std::ostringstream os;
    os << Sensitive<std::string>(pem);
    AXIAM_CHECK(axtest::no_fragment(os.str(), pem.substr(28, 40)));
}

}  // namespace
