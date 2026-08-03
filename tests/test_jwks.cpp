#include <memory>
#include <string>

#include "assert.hpp"
#include "axiam/jwks.hpp"
#include "fake_transport.hpp"
#include "test_key.hpp"

using namespace axiam;
using axtest::b64url_encode;
using axtest::FakeState;
using axtest::jwks_transport;
using axtest::TestKey;

AXIAM_TEST("base64url_decode roundtrips and rejects bad chars") {
    auto d = base64url_decode("aGVsbG8");  // "hello"
    AXIAM_REQUIRE(d.has_value());
    AXIAM_CHECK(*d == "hello");
    AXIAM_CHECK_FALSE(base64url_decode("bad*chars").has_value());
}

AXIAM_TEST("JWKS verifies a valid EdDSA token and returns payload") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    std::string jwt = key.make_jwt("EdDSA", R"({"sub":"user-1"})");
    auto res = v.verify_signature_only_unchecked(jwt);
    AXIAM_REQUIRE(res.has_value());
    AXIAM_CHECK(res->payload_json.find("user-1") != std::string::npos);
    AXIAM_CHECK(v.cached_key_count() == 1);
}

AXIAM_TEST("JWKS rejects non-EdDSA alg before any key work") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    std::string jwt = key.make_jwt("RS256", R"({"sub":"user-1"})");
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked(jwt).has_value());
}

AXIAM_TEST("JWKS rejects a tampered signature") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    std::string jwt = key.make_jwt("EdDSA", R"({"sub":"user-1"})");
    // Corrupt the FIRST signature char (top bits of sig byte 0); the last char
    // only carries 2 significant bits so flipping it can be a no-op.
    const auto dot = jwt.rfind('.');
    jwt[dot + 1] = (jwt[dot + 1] == 'A') ? 'B' : 'A';
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked(jwt).has_value());
}

AXIAM_TEST("JWKS rejects malformed compact token") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked("not-a-jwt").has_value());
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked("only.two").has_value());
}

AXIAM_TEST("JWKS rejects unknown kid") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    // Serve a JWKS with a different kid than the token references.
    std::string doc = key.jwks_json();
    // Swap kid in the served doc so the token's kid "key-1" is unknown.
    std::string bad = doc;
    auto pos = bad.find("key-1");
    bad.replace(pos, 5, "key-2");
    JwksVerifier v(jwks_transport(st, bad), "https://api.example.test");
    std::string jwt = key.make_jwt("EdDSA", R"({"sub":"u"})");
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked(jwt).has_value());
}

AXIAM_TEST("JWKS caches keys across verifications (single fetch)") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    std::string jwt = key.make_jwt("EdDSA", R"({"sub":"u"})");
    AXIAM_CHECK(v.verify_signature_only_unchecked(jwt).has_value());
    AXIAM_CHECK(v.verify_signature_only_unchecked(jwt).has_value());
    AXIAM_CHECK(st->count_path("/oauth2/jwks") == 1);
}
