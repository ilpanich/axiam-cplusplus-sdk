// SEC-074 — the safe-by-default §10 authenticator.
//
// The raw JWKS primitive is signature-only by design. These tests pin the
// difference: every case below feeds a token whose SIGNATURE IS VALID and asserts
// that TokenAuthenticator still rejects it on a claim the primitive does not look
// at, and that the guard path goes through the authenticator rather than the
// primitive.
#include <memory>
#include <string>

#include "assert.hpp"
#include "axiam/authenticator.hpp"
#include "fake_transport.hpp"
#include "test_key.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::jwks_transport;
using axtest::TestKey;

namespace {

constexpr std::int64_t kNow = 1785700000;
const char* kTenant = "11111111-1111-1111-1111-111111111111";
const char* kOtherTenant = "22222222-2222-2222-2222-222222222222";

AuthenticatorOptions fixed_clock(std::int64_t now = kNow) {
    AuthenticatorOptions opts;
    opts.now = [now] { return now; };
    return opts;
}

std::string claims(const std::string& extra) {
    return std::string("{\"sub\":\"user-1\",\"tenant_id\":\"") + kTenant + "\"," + extra + "}";
}

}  // namespace

AXIAM_TEST("authenticator accepts a valid, fresh, same-tenant token") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, fixed_clock());

    const std::string jwt = key.make_jwt(
        "EdDSA", claims("\"exp\":" + std::to_string(kNow + 900) + ",\"roles\":[\"admin\",\"ops\"]"));

    AxiamUser user = auth.authenticate(jwt);
    AXIAM_CHECK(user.user_id == "user-1");
    AXIAM_CHECK(user.tenant_id == kTenant);
    AXIAM_CHECK(user.has_role("admin"));
    AXIAM_CHECK(user.has_role("ops"));
    AXIAM_CHECK_FALSE(user.has_role("nope"));
}

AXIAM_TEST("authenticator rejects an expired token the raw primitive accepts") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, fixed_clock());

    // exp is an hour in the past; the signature is perfectly good.
    const std::string jwt =
        key.make_jwt("EdDSA", claims("\"exp\":" + std::to_string(kNow - 3600)));

    // The expert primitive is happy — that is precisely why it must not be the
    // guard's entry point.
    AXIAM_REQUIRE(v.verify_signature_only_unchecked(jwt).has_value());
    // The safe authenticator is not.
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(jwt), AuthError);
    AXIAM_CHECK_FALSE(auth.try_authenticate(jwt).has_value());
}

AXIAM_TEST("authenticator honours the clock skew at the expiry boundary") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");

    AuthenticatorOptions opts = fixed_clock();
    opts.clock_skew = std::chrono::seconds(30);
    TokenAuthenticator auth(v, kTenant, opts);

    // 20s past exp — inside the 30s skew, accepted.
    const std::string just_expired =
        key.make_jwt("EdDSA", claims("\"exp\":" + std::to_string(kNow - 20)));
    AXIAM_CHECK(auth.try_authenticate(just_expired).has_value());

    // 31s past exp — outside the skew, rejected.
    const std::string too_old =
        key.make_jwt("EdDSA", claims("\"exp\":" + std::to_string(kNow - 31)));
    AXIAM_CHECK_FALSE(auth.try_authenticate(too_old).has_value());
}

AXIAM_TEST("authenticator rejects a foreign-tenant token the raw primitive accepts") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, fixed_clock());

    // Signed by the same org-wide key, but minted for another tenant.
    const std::string jwt =
        key.make_jwt("EdDSA", std::string("{\"sub\":\"user-9\",\"tenant_id\":\"") + kOtherTenant +
                                  "\",\"exp\":" + std::to_string(kNow + 900) + "}");

    AXIAM_REQUIRE(v.verify_signature_only_unchecked(jwt).has_value());
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(jwt), AuthError);
}

AXIAM_TEST("authenticator rejects an nbf-in-the-future token") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, fixed_clock());

    const std::string jwt = key.make_jwt(
        "EdDSA", claims("\"exp\":" + std::to_string(kNow + 900) + ",\"nbf\":" +
                        std::to_string(kNow + 600)));
    AXIAM_REQUIRE(v.verify_signature_only_unchecked(jwt).has_value());
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(jwt), AuthError);

    // An nbf already reached is fine.
    const std::string ok = key.make_jwt(
        "EdDSA", claims("\"exp\":" + std::to_string(kNow + 900) + ",\"nbf\":" +
                        std::to_string(kNow - 10)));
    AXIAM_CHECK(auth.try_authenticate(ok).has_value());
}

AXIAM_TEST("authenticator fails closed on missing / unusable exp and tenant_id") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, fixed_clock());

    // No exp at all — a token that never expires.
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(key.make_jwt("EdDSA", claims("\"iat\":1"))), AuthError);
    // exp present but not a number.
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(key.make_jwt("EdDSA", claims("\"exp\":\"soon\""))),
                            AuthError);
    // nbf present but not a number.
    AXIAM_REQUIRE_THROWS_AS(
        auth.authenticate(key.make_jwt(
            "EdDSA", claims("\"exp\":" + std::to_string(kNow + 60) + ",\"nbf\":\"later\""))),
        AuthError);
    // No tenant_id claim.
    AXIAM_REQUIRE_THROWS_AS(
        auth.authenticate(key.make_jwt(
            "EdDSA", "{\"sub\":\"u\",\"exp\":" + std::to_string(kNow + 60) + "}")),
        AuthError);
    // tenant_id present but empty.
    AXIAM_REQUIRE_THROWS_AS(
        auth.authenticate(key.make_jwt(
            "EdDSA", "{\"sub\":\"u\",\"tenant_id\":\"\",\"exp\":" + std::to_string(kNow + 60) + "}")),
        AuthError);
    // tenant_id present but not a string.
    AXIAM_REQUIRE_THROWS_AS(
        auth.authenticate(key.make_jwt(
            "EdDSA", "{\"sub\":\"u\",\"tenant_id\":7,\"exp\":" + std::to_string(kNow + 60) + "}")),
        AuthError);
    // Payload is not a JSON object.
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(key.make_jwt("EdDSA", "[1,2,3]")), AuthError);
    // Empty token, and a token whose signature does not verify.
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(""), AuthError);
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate("not.a.jwt"), AuthError);
}

AXIAM_TEST("authenticator enforces optional issuer and audience pinning") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");

    AuthenticatorOptions opts = fixed_clock();
    opts.expected_issuer = "https://api.example.test";
    opts.expected_audience = "axiam:user";
    TokenAuthenticator auth(v, kTenant, opts);

    const std::string exp = std::to_string(kNow + 900);
    // aud as an array containing the expected value.
    AXIAM_CHECK(auth.try_authenticate(
                        key.make_jwt("EdDSA",
                                     claims("\"exp\":" + exp +
                                            ",\"iss\":\"https://api.example.test\","
                                            "\"aud\":[\"axiam:user\",\"other\"]")))
                    .has_value());
    // aud as a bare string.
    AXIAM_CHECK(auth.try_authenticate(
                        key.make_jwt("EdDSA", claims("\"exp\":" + exp +
                                                     ",\"iss\":\"https://api.example.test\","
                                                     "\"aud\":\"axiam:user\"")))
                    .has_value());
    // Wrong issuer.
    AXIAM_CHECK_FALSE(auth.try_authenticate(
                              key.make_jwt("EdDSA", claims("\"exp\":" + exp +
                                                           ",\"iss\":\"https://evil.example\","
                                                           "\"aud\":\"axiam:user\"")))
                          .has_value());
    // Missing audience.
    AXIAM_CHECK_FALSE(auth.try_authenticate(
                              key.make_jwt("EdDSA", claims("\"exp\":" + exp +
                                                           ",\"iss\":\"https://api.example.test\"")))
                          .has_value());
    // Audience present but not the expected one.
    AXIAM_CHECK_FALSE(auth.try_authenticate(
                              key.make_jwt("EdDSA", claims("\"exp\":" + exp +
                                                           ",\"iss\":\"https://api.example.test\","
                                                           "\"aud\":[\"axiam:m2m\"]")))
                          .has_value());
}

AXIAM_TEST("authenticator accepts a floating-point NumericDate (RFC 7519)") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, fixed_clock());

    // RFC 7519 permits a non-integer NumericDate; it must still be honoured.
    AXIAM_CHECK(auth.try_authenticate(key.make_jwt("EdDSA", claims("\"exp\":1785700900.5")))
                    .has_value());
    AXIAM_CHECK_FALSE(auth.try_authenticate(key.make_jwt("EdDSA", claims("\"exp\":1785600000.5")))
                          .has_value());
}

AXIAM_TEST("authenticator falls back to the system clock when no now() is injected") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant);  // default AuthenticatorOptions: real clock

    const std::int64_t real_now = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());

    AXIAM_CHECK(auth.try_authenticate(
                        key.make_jwt("EdDSA", claims("\"exp\":" + std::to_string(real_now + 900))))
                    .has_value());
    AXIAM_CHECK_FALSE(auth.try_authenticate(
                              key.make_jwt("EdDSA", claims("\"exp\":" + std::to_string(real_now - 900))))
                          .has_value());
}

AXIAM_TEST("authenticator refuses an empty tenant expectation and a negative skew") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    AXIAM_REQUIRE_THROWS_AS(TokenAuthenticator(v, ""), std::invalid_argument);

    AuthenticatorOptions bad;
    bad.clock_skew = std::chrono::seconds(-1);
    AXIAM_REQUIRE_THROWS_AS(TokenAuthenticator(v, kTenant, bad), std::invalid_argument);
}

// §10.1 rule 7: the leeway is a NAMED constant and is BOUNDED — an operator
// cannot widen it to something that keeps expired tokens alive indefinitely.
AXIAM_TEST("clock skew is a named constant and cannot be widened past the ceiling") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");

    AXIAM_CHECK(AuthenticatorOptions{}.clock_skew == kDefaultClockSkew);
    AXIAM_CHECK(kDefaultClockSkew <= kMaxClockSkew);

    // Exactly at the ceiling is fine.
    AuthenticatorOptions at_max = fixed_clock();
    at_max.clock_skew = kMaxClockSkew;
    TokenAuthenticator ok(v, kTenant, at_max);
    AXIAM_CHECK(ok.expected_tenant_id() == kTenant);

    // One second beyond it, and anything wildly beyond it, is refused.
    AuthenticatorOptions over = fixed_clock();
    over.clock_skew = kMaxClockSkew + std::chrono::seconds(1);
    AXIAM_REQUIRE_THROWS_AS(TokenAuthenticator(v, kTenant, over), std::invalid_argument);
    over.clock_skew = std::chrono::hours(24);
    AXIAM_REQUIRE_THROWS_AS(TokenAuthenticator(v, kTenant, over), std::invalid_argument);
}

// §10.1 rule 1: `alg` is pinned to EdDSA BEFORE a key is looked up, so neither
// confusion shape ever reaches the signature machinery — at the guard entry
// point, not only on the raw primitive.
AXIAM_TEST("authenticator rejects alg:none and an HS-signed token bearing the EdDSA kid") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, fixed_clock());

    const std::string payload = claims("\"exp\":" + std::to_string(kNow + 900));

    // alg:none, canonical shape (empty third part).
    const std::string none_tok = key.make_alg_none_jwt(payload);
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked(none_tok).has_value());
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(none_tok), AuthError);

    // alg:none carrying a real Ed25519 signature, so only the header lies: the
    // token would verify if the key were consulted, and must still be refused.
    const std::string none_signed = key.make_jwt("none", payload);
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked(none_signed).has_value());
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(none_signed), AuthError);

    // HS256 MAC keyed with the published Ed25519 public key, same kid.
    const std::string hs_tok = key.make_hs256_confused_jwt(payload);
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked(hs_tok).has_value());
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(hs_tok), AuthError);

    // And the same three through the §10 guard wiring.
    struct Req {
        std::string authorization;
    };
    auto guard = AxiamGuard<Req>(auth.guard_authenticator<Req>([](const Req& r) {
        return TokenAuthenticator::bearer_from_authorization(r.authorization);
    }));
    AXIAM_REQUIRE_THROWS_AS(guard(Req{"Bearer " + none_tok}), AuthError);
    AXIAM_REQUIRE_THROWS_AS(guard(Req{"Bearer " + none_signed}), AuthError);
    AXIAM_REQUIRE_THROWS_AS(guard(Req{"Bearer " + hs_tok}), AuthError);
}

// §10.1 rules 5/6 are CONDITIONAL: with no expectation configured the claims
// are not checked, and the SDK never assumes an issuer or audience.
AXIAM_TEST("unconfigured issuer/audience are not checked") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    AuthenticatorOptions opts = fixed_clock();
    AXIAM_REQUIRE_FALSE(opts.expected_issuer.has_value());
    AXIAM_REQUIRE_FALSE(opts.expected_audience.has_value());
    TokenAuthenticator auth(v, kTenant, opts);

    // A foreign issuer and audience are irrelevant when nothing is expected.
    AXIAM_CHECK(auth.try_authenticate(
                        key.make_jwt("EdDSA", claims("\"exp\":" + std::to_string(kNow + 900) +
                                                     ",\"iss\":\"https://other.example\","
                                                     "\"aud\":[\"axiam:m2m\"]")))
                    .has_value());
}

// A configured expectation makes the claim REQUIRED: absent or wrong-typed
// fails closed, not "nothing to check, so pass".
AXIAM_TEST("configured issuer/audience fail closed when the claim is absent or mistyped") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    const std::string exp = std::to_string(kNow + 900);

    AuthenticatorOptions iss_only = fixed_clock();
    iss_only.expected_issuer = "https://api.example.test";
    TokenAuthenticator by_iss(v, kTenant, iss_only);
    // No `iss` claim at all.
    AXIAM_CHECK_FALSE(
        by_iss.try_authenticate(key.make_jwt("EdDSA", claims("\"exp\":" + exp))).has_value());
    // `iss` present but not a string.
    AXIAM_CHECK_FALSE(
        by_iss.try_authenticate(key.make_jwt("EdDSA", claims("\"exp\":" + exp + ",\"iss\":42")))
            .has_value());

    AuthenticatorOptions aud_only = fixed_clock();
    aud_only.expected_audience = "axiam:user";
    TokenAuthenticator by_aud(v, kTenant, aud_only);
    // `aud` present but neither a string nor an array of strings.
    AXIAM_CHECK_FALSE(
        by_aud.try_authenticate(key.make_jwt("EdDSA", claims("\"exp\":" + exp + ",\"aud\":7")))
            .has_value());
    AXIAM_CHECK_FALSE(by_aud
                          .try_authenticate(key.make_jwt(
                              "EdDSA", claims("\"exp\":" + exp + ",\"aud\":[1,2]")))
                          .has_value());
}

AXIAM_TEST("credential extraction helpers") {
    AXIAM_CHECK(*TokenAuthenticator::bearer_from_authorization("Bearer abc.def.ghi") ==
                "abc.def.ghi");
    AXIAM_CHECK(*TokenAuthenticator::bearer_from_authorization("  bearer   tok  ") == "tok");
    AXIAM_CHECK_FALSE(TokenAuthenticator::bearer_from_authorization("Basic abc").has_value());
    AXIAM_CHECK_FALSE(TokenAuthenticator::bearer_from_authorization("Bearer ").has_value());
    AXIAM_CHECK_FALSE(TokenAuthenticator::bearer_from_authorization("").has_value());

    AXIAM_CHECK(*TokenAuthenticator::token_from_cookie_header(
                    "axiam_csrf=c; axiam_access=tok; axiam_refresh=r") == "tok");
    AXIAM_CHECK(*TokenAuthenticator::token_from_cookie_header("axiam_access=tok") == "tok");
    AXIAM_CHECK_FALSE(
        TokenAuthenticator::token_from_cookie_header("axiam_csrf=c; other=x").has_value());
    AXIAM_CHECK_FALSE(TokenAuthenticator::token_from_cookie_header("axiam_access=").has_value());
    AXIAM_CHECK_FALSE(TokenAuthenticator::token_from_cookie_header("").has_value());
}

// ---------------------------------------------------------------------------
// The guard path must run through the safe authenticator.
// ---------------------------------------------------------------------------

namespace {

/// Stand-in for a framework request object.
struct FakeRequest {
    std::string authorization;
};

}  // namespace

AXIAM_TEST("AxiamGuard wired to the safe authenticator rejects expired/foreign tokens") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    TokenAuthenticator auth(v, kTenant, fixed_clock());

    AxiamGuard<FakeRequest> guard(auth.guard_authenticator<FakeRequest>(
        [](const FakeRequest& r) { return TokenAuthenticator::bearer_from_authorization(r.authorization); }));

    const std::string good =
        key.make_jwt("EdDSA", claims("\"exp\":" + std::to_string(kNow + 900) + ",\"roles\":[\"admin\"]"));
    const std::string expired =
        key.make_jwt("EdDSA", claims("\"exp\":" + std::to_string(kNow - 3600)));
    const std::string foreign =
        key.make_jwt("EdDSA", std::string("{\"sub\":\"u\",\"tenant_id\":\"") + kOtherTenant +
                                  "\",\"exp\":" + std::to_string(kNow + 900) + "}");

    // Happy path: the guard yields the identity the token carries.
    AxiamUser user = guard(FakeRequest{"Bearer " + good});
    AXIAM_CHECK(user.user_id == "user-1");
    AXIAM_CHECK(user.tenant_id == kTenant);
    AXIAM_CHECK(user.has_role("admin"));

    // Both of these have a VALID SIGNATURE, so a guard built on the raw
    // primitive would have admitted them. Through the safe authenticator they
    // are 401s.
    AXIAM_REQUIRE(v.verify_signature_only_unchecked(expired).has_value());
    AXIAM_REQUIRE(v.verify_signature_only_unchecked(foreign).has_value());
    AXIAM_REQUIRE_THROWS_AS(guard(FakeRequest{"Bearer " + expired}), AuthError);
    AXIAM_REQUIRE_THROWS_AS(guard(FakeRequest{"Bearer " + foreign}), AuthError);

    // No credential at all is a 401, not a crash.
    AXIAM_REQUIRE_THROWS_AS(guard(FakeRequest{""}), AuthError);
}

AXIAM_TEST("make_authenticator binds a client's JWKS verifier") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    Client c = Client::builder()
                   .base_url("https://api.example.test")
                   .tenant_id(kTenant)
                   .transport(jwks_transport(st, key.jwks_json()))
                   .build();

    TokenAuthenticator auth = make_authenticator(c, c.tenant_header(), fixed_clock());
    AXIAM_CHECK(auth.expected_tenant_id() == kTenant);

    const std::string jwt =
        key.make_jwt("EdDSA", claims("\"exp\":" + std::to_string(kNow + 900)));
    AXIAM_CHECK(auth.try_authenticate(jwt).has_value());
    AXIAM_CHECK_FALSE(
        auth.try_authenticate(key.make_jwt("EdDSA", claims("\"exp\":" + std::to_string(kNow - 3600))))
            .has_value());
}
