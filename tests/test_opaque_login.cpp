// Client::login_opaque / Client::opaque_enrollment end to end (src/client.cpp,
// CONTRACT.md §23).
//
// The protocol is `libaxiam_opaque_ffi`'s and the binding is covered by
// tests/test_opaque_binding.cpp. What is tested here is the part the SDK owns:
// what goes on the wire — and, more importantly, what does NOT — which failures
// are credential failures and which are configuration facts, and that a failed
// credential check never reaches login/finish.
//
// The fake transport is scriptable rather than protocol-speaking, which is a
// real change from the SRP suite it replaces: that fake held a verifier and
// computed B, M1 and M2 from whatever A the client sent, because a client that
// got u or the padding wrong had to fail against it. There is no arithmetic
// here to get wrong — §23.1 puts all of it inside the shared library — so the
// assertions that matter are about request bodies, error taxonomy and request
// COUNTS.

#include <memory>
#include <random>
#include <string>

#include <json.hpp>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "fake_transport.hpp"
#include "opaque_fake.hpp"

using namespace axiam;
using axtest::FakeEntry;
using axtest::FakeNative;
using axtest::FakeState;
using axtest::json_response;
using axtest::ScopedFakeNative;
using json = nlohmann::json;

namespace {

constexpr const char* kUser = "alice";
// Hex, because that is what the wire carries; the binding hands these to the
// library verbatim and the fake library echoes them back inside its own
// payload, which is how these tests see that nothing was rewritten in between.
constexpr const char* kWireKe2 = "6b6532";
constexpr const char* kWireRegistrationResponse = "726573703a";

// Minted per run; nothing here depends on the value, and a literal that reads
// like a credential is a finding for every secret scanner.
std::string mint_password() {
    static std::mt19937_64 rng{std::random_device{}()};
    static const char* digits = "0123456789abcdef";
    std::string out = "correct-";
    std::uint64_t bits = rng();
    for (int i = 0; i < 16; i++) {
        out.push_back(digits[bits & 0xf]);
        bits >>= 4;
    }
    return out;
}

/// How the fake server should answer, per test.
struct Script {
    long login_start_status = 200;
    long login_finish_status = 200;
    long register_start_status = 200;
    bool mfa_required = false;
    bool mfa_setup_required = false;
    bool omit_ke2 = false;
    bool omit_registration_response = false;
    bool malformed_start_body = false;
    std::string ksf = OpaqueKsfParams::kArgon2id;

    /// The tenant's `opaque_mode`, as login/start reports it (§23.5, contract
    /// 1.29). An EMPTY string omits the field entirely, which is what a server
    /// older than the field does — and is deliberately not the same script as
    /// `"required"`, because §23.4 rule 7 has to reach the same answer by two
    /// different routes and only a test that drives both proves it.
    std::string mode;

    /// What `POST /api/v1/auth/login` — the §23.4 rule 7 fallback — answers.
    long password_login_status = 200;
};

std::string ksf_fields(const Script& s) {
    if (s.ksf == OpaqueKsfParams::kScrypt) {
        return R"("ksf":"scrypt","log_n":15,"r":8,"p":1)";
    }
    return R"("ksf":")" + s.ksf + R"(","memory_kib":19456,"iterations":2,"parallelism":1)";
}

Client make_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://api.example.test")
        .tenant_slug("acme")
        .org_slug("globex")
        .transport(axtest::make_fake(st))
        .build();
}

/// Wires `st` to answer the three OPAQUE endpoints per `script`.
void install_router(std::shared_ptr<FakeState> st, Script script) {
    st->router = [script](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/opaque/login/start") != std::string::npos) {
            if (script.login_start_status != 200) {
                return json_response(script.login_start_status, "{}");
            }
            if (script.malformed_start_body) return json_response(200, "not json at all");
            std::string body = R"({"opaque_session":"handle-42")";
            if (!script.omit_ke2) body += R"(,"ke2":")" + std::string(kWireKe2) + R"(")";
            if (!script.mode.empty()) body += R"(,"mode":")" + script.mode + R"(")";
            body += "," + ksf_fields(script) + "}";
            return json_response(200, body);
        }

        if (req.url.find("/auth/opaque/login/finish") != std::string::npos) {
            if (script.mfa_setup_required) {
                return json_response(403, R"({"mfa_setup_required":true,"setup_token":"s"})");
            }
            if (script.login_finish_status != 200) {
                return json_response(script.login_finish_status, "{}");
            }
            if (script.mfa_required) {
                return json_response(202,
                                     R"({"mfa_required":true,"challenge_token":"mfa-1",)"
                                     R"("available_methods":["totp"]})");
            }
            auto r = json_response(200,
                                   R"({"session_id":"sess-1","expires_in":900,)"
                                   R"("user":{"id":"u-1","username":"alice",)"
                                   R"("email":"a@x.io","tenant_id":"t-1"}})");
            r.headers["X-CSRF-Token"] = "csrf-abc";
            return r;
        }

        if (req.url.find("/auth/opaque/register/start") != std::string::npos) {
            if (script.register_start_status != 200) {
                return json_response(script.register_start_status, "{}");
            }
            std::string body = R"({"opaque_session":"reg-handle")";
            if (!script.omit_registration_response) {
                body += R"(,"registration_response":")" +
                        std::string(kWireRegistrationResponse) + R"(")";
            }
            body += "," + ksf_fields(script) + "}";
            return json_response(200, body);
        }

        // The plaintext endpoint §23.4 rule 7's `optional` clause falls back to.
        // Its user id differs from the OPAQUE one on purpose: that is how a test
        // sees WHICH path produced the result rather than only that one did.
        if (req.url.find("/auth/login") != std::string::npos) {
            if (script.password_login_status != 200) {
                return json_response(script.password_login_status, "{}");
            }
            return json_response(200,
                                 R"({"session_id":"sess-pw","expires_in":900,)"
                                 R"("user":{"id":"u-pw","username":"alice",)"
                                 R"("email":"a@x.io","tenant_id":"t-1"}})");
        }

        return json_response(404, R"({"message":"not found"})");
    };
}

/// The parsed body of the last request whose URL contains `needle`.
json body_of(const std::shared_ptr<FakeState>& st, const std::string& needle) {
    std::lock_guard<std::mutex> lock(st->mtx);
    for (auto it = st->requests.rbegin(); it != st->requests.rend(); ++it) {
        if (it->url.find(needle) != std::string::npos) {
            return json::parse(it->body, nullptr, false);
        }
    }
    return json();
}

/// Runs `body` and returns the message of the error it threw, or "" otherwise.
template <typename ExType, typename Fn>
std::string message_of(Fn body) {
    try {
        body();
    } catch (const ExType& e) {
        return e.what();
    } catch (...) {
        return {};
    }
    return {};
}

}  // namespace

// ---------------------------------------------------------------------------
// What crosses the wire
// ---------------------------------------------------------------------------

AXIAM_TEST("login_opaque: the start body carries ke1 and no password field") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    install_router(st, Script{});
    const std::string password = mint_password();

    Client c = make_client(st);
    (void)c.login_opaque(kUser, password);

    const json body = body_of(st, "/auth/opaque/login/start");
    // The entire point of the exchange. A body that still carried a password
    // would be SRP's failure mode with extra steps.
    AXIAM_CHECK_FALSE(body.contains("password"));
    AXIAM_CHECK(body.value("username_or_email", "") == kUser);
    AXIAM_CHECK(body.value("tenant_slug", "") == "acme");
    AXIAM_CHECK(body.value("ke1", "") == "ke1:" + password);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("opaque_enrollment: register/start names no account at all") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    install_router(st, Script{});
    const std::string password = mint_password();

    Client c = make_client(st);
    OpaqueEnrollment enrolment = c.opaque_enrollment(password);

    AXIAM_CHECK(enrolment.opaque_session == "reg-handle");
    AXIAM_CHECK(enrolment.registration_record.rfind("record:" + password, 0) == 0);

    const json body = body_of(st, "/auth/opaque/register/start");
    AXIAM_CHECK_FALSE(body.contains("password"));
    // No username either: a record binds to a credential identifier the SERVER
    // chooses, which is why a later rename cannot invalidate one — and why the
    // SRP enrolment's `identity` argument has no successor.
    AXIAM_CHECK_FALSE(body.contains("username_or_email"));
    AXIAM_CHECK(body.value("tenant_slug", "") == "acme");
    AXIAM_CHECK(body.value("registration_request", "") == "req:" + password);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: the finish body echoes the server's session handle") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    install_router(st, Script{});
    const std::string password = mint_password();

    Client c = make_client(st);
    (void)c.login_opaque(kUser, password);

    const json body = body_of(st, "/auth/opaque/login/finish");
    AXIAM_CHECK(body.value("opaque_session", "") == "handle-42");
    AXIAM_CHECK(body.value("ke3", "").rfind("ke3:" + password + ":" + kWireKe2 + ":", 0) == 0);
}

AXIAM_TEST("login_opaque: the server-named ksf is the one used") {
    // §23.4 rule 2: never local defaults. A credential enrolled under one cost
    // keeps working after a tenant raises its policy, so a client that guessed
    // would fail against a record that is perfectly good.
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.ksf = OpaqueKsfParams::kScrypt;
    install_router(st, script);

    Client c = make_client(st);
    (void)c.login_opaque(kUser, mint_password());

    // scrypt handles are tagged 0xb....; argon2id's are 0xa.....
    AXIAM_CHECK(fake.last_ksf_tag == 0xB0000u + 15u + 8u + 1u);
}

AXIAM_TEST("login_opaque: an absent cost reaches the library absent") {
    // The argon2id response names no log_n/r/p at all. Reading those as 0 would
    // be §23.4 rule 5's failure; the tag proves the argon2id branch ran with the
    // three costs the server DID name.
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    install_router(st, Script{});

    Client c = make_client(st);
    (void)c.login_opaque(kUser, mint_password());

    AXIAM_CHECK(fake.last_ksf_tag == 0xA0000u + 19456u + 2u + 1u);
}

// ---------------------------------------------------------------------------
// Results — the union login() fills, filled identically
// ---------------------------------------------------------------------------

AXIAM_TEST("login_opaque: a success returns what login returns") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    install_router(st, Script{});

    Client c = make_client(st);
    AXIAM_CHECK(c.opaque_available());

    LoginResult res = c.login_opaque(kUser, mint_password());
    AXIAM_CHECK_FALSE(res.mfa_required);
    AXIAM_REQUIRE(res.user.has_value());
    AXIAM_CHECK(res.user->id == "u-1");
    AXIAM_CHECK(res.expires_in == 900);
    AXIAM_CHECK(c.has_session());
    AXIAM_CHECK(st->count_path("/auth/opaque/login/start") == 1);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 1);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: the MFA-required branch survives the OPAQUE path") {
    // One result handler must serve both login paths, so the second phase has
    // to arrive here exactly as it does from login().
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.mfa_required = true;
    install_router(st, script);

    Client c = make_client(st);
    LoginResult res = c.login_opaque(kUser, mint_password());
    AXIAM_CHECK(res.mfa_required);
    AXIAM_CHECK_FALSE(res.user.has_value());
    AXIAM_REQUIRE(res.available_methods.size() == 1);
    AXIAM_CHECK(res.available_methods[0] == "totp");
}

// ---------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------

AXIAM_TEST("login_opaque: a disabled tenant is a NetworkError a caller can fall back from") {
    // A 404 is a property of the tenant, not of the credentials. As an AuthError
    // it would be shown as "invalid password" and send a user to reset a working
    // one, while stopping a fallback to login().
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.login_start_status = 404;
    install_router(st, script);

    Client c = make_client(st);
    const std::string message = message_of<NetworkError>(
        [&] { (void)c.login_opaque(kUser, mint_password()); });
    AXIAM_CHECK(message.find("opaque_mode is disabled") != std::string::npos);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 0);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("opaque_enrollment: a disabled tenant is reported the same way") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.register_start_status = 404;
    install_router(st, script);

    Client c = make_client(st);
    const std::string message =
        message_of<NetworkError>([&] { (void)c.opaque_enrollment(mint_password()); });
    AXIAM_CHECK(message.find("opaque_mode is disabled") != std::string::npos);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: a 401 at login/start is an AuthError") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.login_start_status = 401;
    install_router(st, script);

    Client c = make_client(st);
    AXIAM_REQUIRE_THROWS_AS((void)c.login_opaque(kUser, mint_password()), AuthError);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 0);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: a wrong password never reaches login/finish") {
    // §23.4 rule 7. The envelope failing to open IS the authentication check;
    // sending anything afterwards would ask the server to decide something the
    // client has already decided.
    FakeNative fake;
    ScopedFakeNative native(fake);
    fake.fail(FakeEntry::kLoginFinish);
    auto st = std::make_shared<FakeState>();
    install_router(st, Script{});

    Client c = make_client(st);
    const std::string message =
        message_of<AuthError>([&] { (void)c.login_opaque(kUser, mint_password()); });
    AXIAM_CHECK(message.find("invalid credentials") != std::string::npos);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/start") == 1);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 0);
    AXIAM_CHECK_FALSE(c.has_session());
    AXIAM_CHECK_FALSE(fake.leaked());
}

// ---------------------------------------------------------------------------
// §23.4 rule 7 — what a failed KE2 does next, decided by `mode` and only by it
//
// The mid-migration case is the one that matters: under `optional` every
// account has no registration record until it next sets a password, so an
// exchange that fails is the ORDINARY case and treating it as final locks out
// the whole tenant. Under `required` — and against any server too old to report
// a mode — the opposite is true and a retry would put a plaintext password on
// the wire for an endpoint that answers 403 to everyone. Every test here also
// pins that KE3 never reaches login/finish, because that is the invariant a
// fallback could plausibly break.
// ---------------------------------------------------------------------------

AXIAM_TEST("login_opaque: optional + a failed KE2 falls back to /auth/login") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    fake.fail(FakeEntry::kLoginFinish);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.mode = "optional";
    install_router(st, script);
    const std::string password = mint_password();

    Client c = make_client(st);
    LoginResult res = c.login_opaque(kUser, password);

    // The caller gets a login, not an error — and the id proves it came from the
    // plaintext endpoint rather than from the OPAQUE one.
    AXIAM_REQUIRE(res.user.has_value());
    AXIAM_CHECK(res.user->id == "u-pw");
    AXIAM_CHECK(res.session_id == "sess-pw");
    AXIAM_CHECK(c.has_session());

    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 0);
    AXIAM_REQUIRE(st->count_path("/auth/login") == 1);

    // The SAME credentials, over the SDK's own login path.
    const json body = body_of(st, "/auth/login");
    AXIAM_CHECK(body.value("username_or_email", "") == kUser);
    AXIAM_CHECK(body.value("password", "") == password);
    AXIAM_CHECK(body.value("tenant_slug", "") == "acme");
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: optional + a failed fallback reports /auth/login's own answer") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    fake.fail(FakeEntry::kLoginFinish);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.mode = "optional";
    script.password_login_status = 401;
    install_router(st, script);

    Client c = make_client(st);
    AXIAM_REQUIRE_THROWS_AS((void)c.login_opaque(kUser, mint_password()), AuthError);
    AXIAM_CHECK(st->count_path("/auth/login") == 1);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 0);
    AXIAM_CHECK_FALSE(c.has_session());
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: required + a failed KE2 never touches /auth/login") {
    // `required` answers 403 opaque_required for every principal, so a retry
    // would hand a plaintext password to an endpoint that cannot accept it.
    FakeNative fake;
    ScopedFakeNative native(fake);
    fake.fail(FakeEntry::kLoginFinish);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.mode = "required";
    install_router(st, script);

    Client c = make_client(st);
    const std::string message =
        message_of<AuthError>([&] { (void)c.login_opaque(kUser, mint_password()); });
    AXIAM_CHECK(message.find("invalid credentials") != std::string::npos);
    AXIAM_CHECK(st->count_path("/auth/login") == 0);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 0);
    AXIAM_CHECK_FALSE(c.has_session());
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: no mode field at all is treated as required") {
    // A server older than contract 1.29 sends no `mode`. Absence must not draw
    // a plaintext password out of this SDK — the field is not a promise, and
    // reading its absence as permission would be the one bug §23.4 rule 7's
    // wording exists to prevent.
    FakeNative fake;
    ScopedFakeNative native(fake);
    fake.fail(FakeEntry::kLoginFinish);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.mode.clear();  // omitted entirely
    install_router(st, script);

    Client c = make_client(st);
    AXIAM_REQUIRE_THROWS_AS((void)c.login_opaque(kUser, mint_password()), AuthError);
    AXIAM_CHECK(st->count_path("/auth/login") == 0);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 0);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: an unrecognised mode fails closed") {
    // Anything that is not exactly `optional` is `required`. A future value read
    // as permission to fall back would be a downgrade this SDK performed on
    // itself.
    FakeNative fake;
    ScopedFakeNative native(fake);
    fake.fail(FakeEntry::kLoginFinish);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.mode = "Optional";  // not the wire value; case matters
    install_router(st, script);

    Client c = make_client(st);
    AXIAM_REQUIRE_THROWS_AS((void)c.login_opaque(kUser, mint_password()), AuthError);
    AXIAM_CHECK(st->count_path("/auth/login") == 0);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 0);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: optional does not turn a 404 into a fallback") {
    // §23.4 rule 7 governs a failed KE2 only. A 404 is the tenant saying it does
    // not offer OPAQUE at all, and stays the distinguishable NetworkError a
    // caller decides about — mode never even arrives on that path.
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.mode = "optional";
    script.login_start_status = 404;
    install_router(st, script);

    Client c = make_client(st);
    const std::string message =
        message_of<NetworkError>([&] { (void)c.login_opaque(kUser, mint_password()); });
    AXIAM_CHECK(message.find("opaque_mode is disabled") != std::string::npos);
    AXIAM_CHECK(st->count_path("/auth/login") == 0);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: optional does not turn a refused ksf into a fallback") {
    // A key-stretching function this SDK cannot ask for is a configuration
    // fault, not a failed credential check — the exchange never reaches KE2, so
    // rule 7 does not apply and no plaintext may leave.
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.mode = "optional";
    script.ksf = "bcrypt";
    install_router(st, script);

    Client c = make_client(st);
    AXIAM_REQUIRE_THROWS_AS((void)c.login_opaque(kUser, mint_password()), NetworkError);
    AXIAM_CHECK(st->count_path("/auth/login") == 0);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 0);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: an unsupported ksf is a configuration error, not a bad password") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.ksf = "bcrypt";
    install_router(st, script);

    Client c = make_client(st);
    const std::string message = message_of<NetworkError>(
        [&] { (void)c.login_opaque(kUser, mint_password()); });
    AXIAM_CHECK(message.find("bcrypt") != std::string::npos);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 0);
    // The exchange was abandoned rather than spent, and its destructor must have
    // released it — otherwise a misconfigured tenant leaks once per login
    // attempt.
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("opaque_enrollment: an unsupported ksf is refused the same way") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.ksf = "bcrypt";
    install_router(st, script);

    Client c = make_client(st);
    const std::string message =
        message_of<NetworkError>([&] { (void)c.opaque_enrollment(mint_password()); });
    AXIAM_CHECK(message.find("bcrypt") != std::string::npos);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: a start response without ke2 is a malformed response") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.omit_ke2 = true;
    install_router(st, script);

    Client c = make_client(st);
    const std::string message = message_of<NetworkError>(
        [&] { (void)c.login_opaque(kUser, mint_password()); });
    AXIAM_CHECK(message.find("no `ke2`") != std::string::npos);
    AXIAM_CHECK(st->count_path("/auth/opaque/login/finish") == 0);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("opaque_enrollment: a start response without a registration_response is refused") {
    // Passing an empty string on to the library would spend the exchange to
    // produce a record no server can ever accept.
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.omit_registration_response = true;
    install_router(st, script);

    Client c = make_client(st);
    const std::string message =
        message_of<NetworkError>([&] { (void)c.opaque_enrollment(mint_password()); });
    AXIAM_CHECK(message.find("no `registration_response`") != std::string::npos);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: a start body that is not JSON names the endpoint") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.malformed_start_body = true;
    install_router(st, script);

    Client c = make_client(st);
    const std::string message = message_of<NetworkError>(
        [&] { (void)c.login_opaque(kUser, mint_password()); });
    AXIAM_CHECK(message.find("login/start") != std::string::npos);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: a 5xx at login/finish is an error and leaves no session") {
    FakeNative fake;
    ScopedFakeNative native(fake);
    auto st = std::make_shared<FakeState>();
    Script script;
    script.login_finish_status = 503;
    install_router(st, script);

    Client c = make_client(st);
    AXIAM_REQUIRE_THROWS_AS((void)c.login_opaque(kUser, mint_password()), NetworkError);
    AXIAM_CHECK_FALSE(c.has_session());
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("login_opaque: an absent library is reported before any request is sent") {
    axiam::opaque::set_native_for_tests(nullptr);
    auto st = std::make_shared<FakeState>();
    install_router(st, Script{});

    Client c = make_client(st);
    AXIAM_CHECK_FALSE(c.opaque_available());

    const std::string message = message_of<NetworkError>(
        [&] { (void)c.login_opaque(kUser, mint_password()); });
    AXIAM_CHECK(message.find("libaxiam_opaque_ffi") != std::string::npos);
    AXIAM_CHECK(st->count() == 0);

    axiam::opaque::reset_native_for_tests();
}
