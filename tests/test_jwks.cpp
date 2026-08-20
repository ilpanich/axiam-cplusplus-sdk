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

// §12.3 rule 3 — a JWKS fetch that FAILS must not evict what is already cached.
//
// The rotation path deliberately drops `have_keys_` and re-fetches when an
// unknown `kid` shows up. If a failed re-fetch were allowed to leave the cache
// empty, one blip at the JWKS endpoint would turn every subsequent verification
// into an unknown-kid failure until the cooldown expired — an outage amplified
// into a total authentication outage. So the fetch returns early and keeps
// whatever it had.
AXIAM_TEST("JWKS: a failed refetch keeps the previously cached keys") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    auto fail_now = std::make_shared<bool>(false);
    const std::string doc = key.jwks_json();

    st->router = [doc, fail_now](const axiam::HttpRequest& req, FakeState&) {
        axiam::HttpResponse r;
        if (req.url.find("/oauth2/jwks") == std::string::npos) {
            r.status = 404;
            return r;
        }
        if (*fail_now) {
            // The transport itself failed — the arm that is NOT a status code.
            r.transport_error = "connection refused";
            return r;
        }
        r.status = 200;
        r.body = doc;
        return r;
    };

    JwksVerifier v(axtest::make_fake(st), "https://api.example.test");
    const std::string jwt = key.make_jwt("EdDSA", R"({"sub":"user-1"})");
    AXIAM_REQUIRE(v.verify_signature_only_unchecked(jwt).has_value());
    AXIAM_REQUIRE(v.cached_key_count() == 1);

    // From here the endpoint is down. A token signed by the key already cached
    // must keep verifying.
    *fail_now = true;
    AXIAM_REQUIRE(v.verify_signature_only_unchecked(jwt).has_value());
    AXIAM_REQUIRE(v.cached_key_count() == 1);
}

AXIAM_TEST("JWKS: a first fetch that fails leaves no keys rather than a bad one") {
    // The same early return, reached with nothing cached behind it. The
    // verification must fail — but as unknown-kid, not by trusting an unfetched
    // key, and not by throwing out of a function whose contract is to return a
    // reason.
    TestKey key;
    auto st = std::make_shared<FakeState>();
    st->router = [](const axiam::HttpRequest&, FakeState&) {
        axiam::HttpResponse r;
        r.status = 503;  // the other arm of the same guard: a non-200 status
        r.body = "upstream unavailable";
        return r;
    };
    JwksVerifier v(axtest::make_fake(st), "https://api.example.test");
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked(key.make_jwt("EdDSA", "{}")).has_value());
    AXIAM_CHECK(v.cached_key_count() == 0);
}

AXIAM_TEST("JWKS: a key whose x is not valid base64url fails as a bad signature") {
    // A JWKS the SDK cannot decode is not an unknown kid — the kid matched. It
    // is a key that cannot verify anything, and reporting it as unknown-kid
    // would send the caller into the rotation/re-fetch path over a document
    // that will never improve.
    TestKey key;
    auto st = std::make_shared<FakeState>();
    const std::string bad_doc =
        std::string("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"") + key.kid +
        "\",\"x\":\"not*valid*base64url\"}]}";
    JwksVerifier v(jwks_transport(st, bad_doc), "https://api.example.test");

    const auto res = v.verify_with_reason(key.make_jwt("EdDSA", R"({"sub":"user-1"})"));
    AXIAM_REQUIRE_FALSE(res.ok);
    AXIAM_CHECK(res.reason == std::string("invalid_signature"));
}
