// CONTRACT.md §28.12 (contract 1.53) — RFC 7592 client configuration: the five
// required tests of §28.12.6, plus the edges the C++ port has to get right.
//
// Every token here is drawn at run time (secret_util.hpp): a literal would be a
// credential in the repository, and the redaction test needs a value no fixture
// shares.

#include <chrono>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"
#include "secret_util.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::json_response;

namespace {

const char* kBase = "https://iam.example.com";
const char* kTenant = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b";
const char* kClient = "dcr-client-1";

std::string registration_uri(const std::string& base = kBase) {
    return base + "/oauth2/register/" + kClient + "?tenant_id=" + kTenant;
}

nlohmann::json registration_body(const nlohmann::json& extra = nlohmann::json::object()) {
    nlohmann::json body = {
        {"client_id", kClient},
        {"client_id_issued_at", 1700000000},
        {"client_name", "Agent"},
        {"redirect_uris", {"https://agent.example.com/cb"}},
        {"grant_types", {"authorization_code"}},
        {"response_types", {"code"}},
        {"token_endpoint_auth_method", "private_key_jwt"},
        {"scope", "openid"},
        {"registration_client_uri", registration_uri()},
        {"jwks_uri", "https://agent.example.com/jwks"},
    };
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

/// Routes the registration path to `reply`, a login to a session, and counts
/// every refresh — §28.12.2 rule 3 says a 401 here never reaches §9.
struct Rig {
    std::shared_ptr<FakeState> st = std::make_shared<FakeState>();
    std::function<HttpResponse(const HttpRequest&)> reply = [](const HttpRequest&) {
        return json_response(200, registration_body().dump());
    };

    Client client(const std::string& base = kBase) {
        st->router = [this](const HttpRequest& req, FakeState&) -> HttpResponse {
            if (req.url.find("/auth/login") != std::string::npos) {
                HttpResponse r = json_response(
                    200, R"({"session_id":"sess-1","expires_in":900,)"
                         R"("user":{"id":"u-1","username":"admin","tenant_id":"t"}})");
                r.headers["X-CSRF-Token"] = axtest::random_secret("csrf-");
                return r;
            }
            if (req.url.find("/auth/refresh") != std::string::npos) return json_response(500, "");
            return reply(req);
        };
        auto c = Client::builder()
                     .base_url(base)
                     .tenant_id(kTenant)
                     .transport(axtest::make_fake(st))
                     .build();
        c._set_retry_test_seams([] { return 0.0; }, [](std::chrono::milliseconds) {});
        return c;
    }

    std::size_t registration_calls() { return st->count_path("/oauth2/register/"); }
};

template <typename F>
bool refuses_locally(F&& f) {
    try {
        f();
    } catch (const std::invalid_argument&) {
        return true;
    } catch (...) {
        return false;
    }
    return false;
}

// ── 1. Origin refusal ───────────────────────────────────────────────────────

AXIAM_TEST("§28.12.6 (1): a registration URI at another origin is refused before any request") {
    Rig rig;
    auto client = rig.client();
    const Sensitive<std::string> token(axtest::random_secret("rat-"));
    const ClientRegistration metadata = ClientRegistration::from_json(registration_body().dump());

    for (const std::string uri : {
             std::string("https://evil.example.com/oauth2/register/c1"),     // another host
             std::string("https://iam.example.com:8443/oauth2/register/c1"),  // another port
             std::string("http://iam.example.com/oauth2/register/c1"),       // http, https base
             std::string("ftp://iam.example.com/oauth2/register/c1"),        // another scheme
             std::string("/oauth2/register/c1"),                             // not absolute
             std::string("https://user@iam.example.com/oauth2/register/c1"),  // userinfo
         }) {
        AXIAM_CHECK(refuses_locally([&] { client.read_client_registration(uri, token); }));
        AXIAM_CHECK(refuses_locally([&] { client.delete_client_registration(uri, token); }));
        AXIAM_CHECK(refuses_locally(
            [&] { client.update_client_registration(uri, token, metadata); }));
    }
    AXIAM_CHECK(rig.st->count() == 0);
}

AXIAM_TEST("§28.12.2 rule 1: the default port and the host's case still name the same origin") {
    Rig rig;
    auto client = rig.client();
    const Sensitive<std::string> token(axtest::random_secret("rat-"));
    client.read_client_registration(
        std::string("https://IAM.example.com:443/oauth2/register/") + kClient, token);
    AXIAM_CHECK(rig.registration_calls() == 1);
}

AXIAM_TEST("§28.12.2 rule 1: http is accepted only against an http loopback base URL") {
    Rig rig;
    auto client = rig.client("http://127.0.0.1:8080");
    const Sensitive<std::string> token(axtest::random_secret("rat-"));
    client.read_client_registration(registration_uri("http://127.0.0.1:8080"), token);
    AXIAM_CHECK(rig.registration_calls() == 1);
    // Same loopback host, another port: still another origin.
    AXIAM_CHECK(refuses_locally([&] {
        client.read_client_registration(registration_uri("http://127.0.0.1:8081"), token);
    }));
    AXIAM_CHECK(rig.registration_calls() == 1);
}

// ── 2. Header only ──────────────────────────────────────────────────────────

AXIAM_TEST("§28.12.6 (2): read and delete send the bearer only, with a real session present") {
    Rig rig;
    rig.reply = [](const HttpRequest& req) {
        if (req.method == "DELETE") return json_response(204, "");
        return json_response(200, registration_body().dump());
    };
    auto client = rig.client();
    client.login("admin", axtest::random_secret("pw-"));
    AXIAM_REQUIRE(client.has_session());
    AXIAM_REQUIRE(client.csrf_token().has_value());

    const std::string raw = axtest::random_secret("rat-");
    const Sensitive<std::string> token(raw);
    const ClientRegistration read = client.read_client_registration(registration_uri(), token);
    AXIAM_CHECK(read.client_id == kClient);
    AXIAM_CHECK(!read.registration_access_token.has_value());
    client.delete_client_registration(registration_uri(), token);  // 204 returns normally

    std::lock_guard<std::mutex> lock(rig.st->mtx);
    int seen = 0;
    for (const auto& r : rig.st->requests) {
        if (r.url.find("/oauth2/register/") == std::string::npos) continue;
        ++seen;
        AXIAM_CHECK(r.method == "GET" || r.method == "DELETE");
        const auto auth = r.headers.find("Authorization");
        AXIAM_CHECK(auth != r.headers.end() && auth->second == "Bearer " + raw);
        // Not the SDK's session: no cookie jar, no CSRF echo, no tenant header.
        AXIAM_CHECK(r.sessionless);
        AXIAM_CHECK(r.headers.find("X-CSRF-Token") == r.headers.end());
        AXIAM_CHECK(r.headers.find("Cookie") == r.headers.end());
        AXIAM_CHECK(r.headers.find("X-Tenant-ID") == r.headers.end());
        AXIAM_CHECK(r.body.empty());
        // The URI verbatim — its own query kept, the token never in it.
        AXIAM_CHECK(r.url == registration_uri());
    }
    AXIAM_CHECK(seen == 2);
}

AXIAM_TEST("§28.12.2 rule 3: an adopted device credential is not attached either") {
    auto st = std::make_shared<FakeState>();
    const std::string device_token = axtest::random_secret("dev-");
    st->router = [&device_token](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/device") != std::string::npos) {
            return json_response(200, nlohmann::json{{"access_token", device_token},
                                                     {"token_type", "Bearer"},
                                                     {"expires_in", 900}}
                                          .dump());
        }
        return json_response(200, registration_body().dump());
    };
    auto client = Client::builder()
                      .base_url(kBase)
                      .tenant_id(kTenant)
                      .with_client_cert("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                                        "-----BEGIN AXIAM TEST PLACEHOLDER-----\nMIIB\n"
                                        "-----END AXIAM TEST PLACEHOLDER-----\n")
                      .transport(axtest::make_fake(st))
                      .build();
    client.authenticate_device();
    const std::string raw = axtest::random_secret("rat-");
    client.read_client_registration(registration_uri(), Sensitive<std::string>(raw));
    const auto last = st->last();
    AXIAM_CHECK(last.headers.at("Authorization") == "Bearer " + raw);
    AXIAM_CHECK(axtest::no_fragment(last.headers.at("Authorization"), device_token));
}

// ── 3. Update body ──────────────────────────────────────────────────────────

AXIAM_TEST("§28.12.6 (3): update drops the five server-stated members and returns the rotated token") {
    Rig rig;
    const std::string rotated = axtest::random_secret("rat-");
    rig.reply = [&rotated](const HttpRequest&) {
        return json_response(200, registration_body({{"registration_access_token", rotated}}).dump());
    };
    auto client = rig.client();

    ClientRegistration metadata = ClientRegistration::from_json(
        registration_body({{"registration_access_token", axtest::random_secret("rat-")},
                           {"client_secret", axtest::random_secret("cs-")},
                           {"client_secret_expires_at", 0},
                           {"backchannel_token_delivery_mode", "poll"},
                           {"jwks", {{"keys", nlohmann::json::array()}}}})
            .dump());
    metadata.client_name = "Agent v2";

    const ClientRegistration updated = client.update_client_registration(
        registration_uri(), Sensitive<std::string>(axtest::random_secret("rat-")), metadata);
    AXIAM_REQUIRE(updated.registration_access_token.has_value());
    // §28.12.2 rule 5 / §7 rule 3 (R-19): the caller reads the rotated token
    // through the public accessor, to persist it.
    AXIAM_CHECK(updated.registration_access_token->expose() == rotated);

    AXIAM_REQUIRE(rig.registration_calls() == 1);
    const auto last = rig.st->last();
    AXIAM_CHECK(last.method == "PUT");
    AXIAM_CHECK(last.headers.at("Content-Type") == "application/json");
    const auto body = nlohmann::json::parse(last.body);
    for (const char* gone : {"registration_access_token", "registration_client_uri",
                             "client_secret_expires_at", "client_id_issued_at", "client_secret"}) {
        AXIAM_CHECK(!body.contains(gone));
    }
    AXIAM_CHECK(body.at("client_id") == kClient);
    AXIAM_CHECK(body.at("client_name") == "Agent v2");
    AXIAM_CHECK(body.at("jwks_uri") == "https://agent.example.com/jwks");
    AXIAM_CHECK(body.at("jwks") == nlohmann::json({{"keys", nlohmann::json::array()}}));
    AXIAM_CHECK(body.at("backchannel_token_delivery_mode") == "poll");  // extras round-trip
}

AXIAM_TEST("§28.12.2 rule 5: update and delete are never retried; the read is, per §16") {
    Rig rig;
    rig.reply = [](const HttpRequest&) { return json_response(503, ""); };
    auto client = rig.client();  // retry ENABLED (the builder default)
    const Sensitive<std::string> token(axtest::random_secret("rat-"));
    const auto metadata = ClientRegistration::from_json(registration_body().dump());

    AXIAM_REQUIRE_THROWS_AS(client.update_client_registration(registration_uri(), token, metadata),
                            NetworkError);
    AXIAM_CHECK(rig.registration_calls() == 1);
    AXIAM_REQUIRE_THROWS_AS(client.delete_client_registration(registration_uri(), token),
                            NetworkError);
    AXIAM_CHECK(rig.registration_calls() == 2);
    AXIAM_REQUIRE_THROWS_AS(client.read_client_registration(registration_uri(), token),
                            NetworkError);
    AXIAM_CHECK(rig.registration_calls() == 5);  // the read: three attempts

    // A dropped connection on a write is not retried either.
    rig.reply = [](const HttpRequest&) {
        HttpResponse r;
        r.transport_error = "connection reset";
        return r;
    };
    AXIAM_REQUIRE_THROWS_AS(client.update_client_registration(registration_uri(), token, metadata),
                            NetworkError);
    AXIAM_CHECK(rig.registration_calls() == 6);
}

AXIAM_TEST("§28.12.2 rule 5: the read is never retried on a 4xx other than 408/429") {
    Rig rig;
    rig.reply = [](const HttpRequest&) { return json_response(400, ""); };
    auto client = rig.client();
    AXIAM_REQUIRE_THROWS_AS(client.read_client_registration(
                                registration_uri(),
                                Sensitive<std::string>(axtest::random_secret("rat-"))),
                            NetworkError);
    AXIAM_CHECK(rig.registration_calls() == 1);

    rig.reply = [](const HttpRequest&) { return json_response(429, ""); };
    AXIAM_REQUIRE_THROWS_AS(client.read_client_registration(
                                registration_uri(),
                                Sensitive<std::string>(axtest::random_secret("rat-"))),
                            NetworkError);
    AXIAM_CHECK(rig.registration_calls() == 4);  // 429 is §16-retryable
}

// ── 4. Errors ───────────────────────────────────────────────────────────────

AXIAM_TEST("§28.12.6 (4): a 401 invalid_token is an OAuthProtocolError and refreshes nothing") {
    Rig rig;
    rig.reply = [](const HttpRequest&) {
        HttpResponse r = json_response(401, R"({"error":"invalid_token","error_description":"no"})");
        r.headers["WWW-Authenticate"] = "Bearer error=\"invalid_token\"";
        return r;
    };
    auto client = rig.client();
    client.login("admin", axtest::random_secret("pw-"));
    bool caught = false;
    try {
        client.read_client_registration(registration_uri(),
                                        Sensitive<std::string>(axtest::random_secret("rat-")));
    } catch (const OAuthProtocolError& e) {
        caught = e.error_code() == "invalid_token";
    }
    AXIAM_CHECK(caught);
    AXIAM_CHECK(rig.st->count_path("/auth/refresh") == 0);  // §9 is not entered
    AXIAM_CHECK(client.refresh_call_count() == 0);
    AXIAM_CHECK(rig.registration_calls() == 1);
}

AXIAM_TEST("§28.12.6 (4): a 400 invalid_client_metadata, with no description, is an OAuthProtocolError") {
    Rig rig;
    rig.reply = [](const HttpRequest&) {
        return json_response(400, R"({"error":"invalid_client_metadata"})");
    };
    auto client = rig.client();
    bool caught = false;
    try {
        client.update_client_registration(
            registration_uri(), Sensitive<std::string>(axtest::random_secret("rat-")),
            ClientRegistration::from_json(registration_body().dump()));
    } catch (const OAuthProtocolError& e) {
        caught = e.error_code() == "invalid_client_metadata" && !e.error_description();
    }
    AXIAM_CHECK(caught);
}

AXIAM_TEST("§28.12.3: a bodiless 401 or 403 maps by status, and a malformed 200 is a NetworkError") {
    Rig rig;
    rig.reply = [](const HttpRequest&) { return json_response(401, ""); };
    auto client = rig.client();
    const Sensitive<std::string> token(axtest::random_secret("rat-"));
    AXIAM_REQUIRE_THROWS_AS(client.delete_client_registration(registration_uri(), token), AuthError);
    rig.reply = [](const HttpRequest&) { return json_response(403, ""); };
    AXIAM_REQUIRE_THROWS_AS(client.read_client_registration(registration_uri(), token), AuthzError);
    rig.reply = [](const HttpRequest&) { return json_response(200, "[]"); };
    AXIAM_REQUIRE_THROWS_AS(client.read_client_registration(registration_uri(), token),
                            NetworkError);
    rig.reply = [](const HttpRequest&) { return json_response(200, R"({"client_name":"x"})"); };
    AXIAM_REQUIRE_THROWS_AS(client.read_client_registration(registration_uri(), token),
                            NetworkError);
}

AXIAM_TEST("§28.12: a closed client refuses before any request") {
    Rig rig;
    auto client = rig.client();
    client.close();
    AXIAM_REQUIRE_THROWS_AS(client.read_client_registration(
                                registration_uri(),
                                Sensitive<std::string>(axtest::random_secret("rat-"))),
                            NetworkError);
    AXIAM_CHECK(rig.st->count() == 0);
}

// ── 5. Redaction ────────────────────────────────────────────────────────────

AXIAM_TEST("§28.12.6 (5): neither the token nor the secret reaches any rendering") {
    const std::string token = axtest::random_secret("rat-");
    const std::string secret = axtest::random_secret("cs-");
    const auto registration = ClientRegistration::from_json(
        registration_body({{"registration_access_token", token}, {"client_secret", secret}}).dump());
    AXIAM_REQUIRE(registration.registration_access_token.has_value());
    AXIAM_REQUIRE(registration.client_secret.has_value());

    std::ostringstream printed;
    printed << *registration.registration_access_token << ' ' << *registration.client_secret << ' '
            << registration.registration_access_token->to_string() << ' '
            << registration.extra_json << ' ' << registration.update_body();
    AXIAM_CHECK(axtest::no_fragment(printed.str(), token));
    AXIAM_CHECK(axtest::no_fragment(printed.str(), secret));

    // An error raised by an operation given the token: the server's refusal, and
    // the local origin refusal.
    Rig rig;
    rig.reply = [](const HttpRequest&) { return json_response(401, R"({"error":"invalid_token"})"); };
    auto client = rig.client();
    std::string messages;
    try {
        client.read_client_registration(registration_uri(), Sensitive<std::string>(token));
    } catch (const std::exception& e) {
        messages += e.what();
    }
    try {
        client.read_client_registration("https://elsewhere.example.com/r?t=" + token,
                                        Sensitive<std::string>(token));
    } catch (const std::exception& e) {
        messages += e.what();
    }
    AXIAM_CHECK(!messages.empty());
    AXIAM_CHECK(axtest::no_fragment(messages, token));
}

// ── Tolerant decoding ───────────────────────────────────────────────────────

// Contract 1.59 §34.2 P12.4 (R-23): the replacement is built from what the read
// carried. A list the read lacked is not sent — never `[]`, which RFC 7591 reads
// differently from absence (grant_types defaults to authorization_code) — and a
// list of an unexpected shape is sent back exactly as read.
AXIAM_TEST("§28.12.2 rule 4 (P12.4): a list the read lacked is not sent; a mistyped one is kept as read") {
    const auto bare = ClientRegistration::from_json(R"({"client_id":"c1","client_name":"ciba-only"})");
    const auto bare_body = nlohmann::json::parse(bare.update_body());
    for (const char* key : {"redirect_uris", "grant_types", "response_types"}) {
        AXIAM_CHECK(!bare_body.contains(key));
    }
    AXIAM_CHECK(bare_body.at("client_name") == "ciba-only");

    const auto odd = ClientRegistration::from_json(
        R"({"client_id":"c1","redirect_uris":"https://a","grant_types":["a",1],)"
        R"("response_types":[]})");
    const auto odd_body = nlohmann::json::parse(odd.update_body());
    AXIAM_CHECK(odd_body.at("redirect_uris") == "https://a");
    AXIAM_CHECK(odd_body.at("grant_types") == nlohmann::json::parse(R"(["a",1])"));
    AXIAM_CHECK(odd_body.at("response_types") == nlohmann::json::array());  // carried, so sent

    // What the read carried round-trips; what the caller sets is sent.
    auto full = ClientRegistration::from_json(registration_body().dump());
    AXIAM_REQUIRE(full.redirect_uris.has_value());
    AXIAM_CHECK(*full.response_types == std::vector<std::string>{"code"});
    auto added = bare;
    added.grant_types = std::vector<std::string>{"urn:openid:params:grant-type:ciba"};
    AXIAM_CHECK(nlohmann::json::parse(added.update_body()).at("grant_types") ==
                nlohmann::json::parse(R"(["urn:openid:params:grant-type:ciba"])"));
    const auto full_body = nlohmann::json::parse(full.update_body());
    AXIAM_CHECK(full_body.at("redirect_uris") == nlohmann::json::parse(R"(["https://agent.example.com/cb"])"));
    AXIAM_CHECK(full_body.at("grant_types") == nlohmann::json::parse(R"(["authorization_code"])"));
}

AXIAM_TEST("§28.12.1: unknown and mistyped members are kept, and the update body drops the stated ones") {
    const auto r = ClientRegistration::from_json(
        R"({"client_id":"c1","client_id_issued_at":"not-a-number","scope":7,)"
        R"("redirect_uris":"https://a","client_name":null,"jwks":null,)"
        R"("backchannel_token_delivery_mode":"ping","grant_types":["a",1]})");
    const auto extra = nlohmann::json::parse(r.extra_json);
    AXIAM_CHECK(extra.at("backchannel_token_delivery_mode") == "ping");
    AXIAM_CHECK(extra.at("client_id_issued_at") == "not-a-number");
    AXIAM_CHECK(extra.at("scope") == 7);
    AXIAM_CHECK(extra.at("redirect_uris") == "https://a");
    AXIAM_CHECK(!extra.contains("client_name") && !extra.contains("jwks"));
    AXIAM_CHECK(!r.client_id_issued_at && !r.scope && !r.client_name && !r.jwks_json);
    // §34.2 P12.4: a list holding a non-string is kept whole, not filtered.
    AXIAM_CHECK(!r.grant_types && !r.redirect_uris);
    AXIAM_CHECK(extra.at("grant_types") == nlohmann::json::parse(R"(["a",1])"));

    const auto body = nlohmann::json::parse(r.update_body());
    AXIAM_CHECK(!body.contains("client_id_issued_at"));  // even mistyped, never sent
    AXIAM_CHECK(body.at("backchannel_token_delivery_mode") == "ping");
    AXIAM_CHECK(body.at("scope") == 7);  // kept as the server holds it

    AXIAM_REQUIRE_THROWS_AS(ClientRegistration::from_json("not json"), NetworkError);
    AXIAM_REQUIRE_THROWS_AS(ClientRegistration::from_json(R"({"client_id":""})"), NetworkError);

    // A hand-built value whose extra_json is not an object still yields a body.
    ClientRegistration manual;
    manual.client_id = "c2";
    manual.extra_json = "[]";
    manual.jwks_json = "{not json";
    const auto manual_body = nlohmann::json::parse(manual.update_body());
    AXIAM_CHECK(manual_body.at("client_id") == "c2" && !manual_body.contains("jwks"));
}

}  // namespace
