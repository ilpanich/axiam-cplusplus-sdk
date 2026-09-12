// The rejection half of §12 signature verification and §21 certificate binding.
//
// tests/test_jwks.cpp proves a good token verifies and that three obvious bad ones do
// not. What it leaves unwalked is every guard whose job is to say NO: a key set that is
// not a key set, a JWK of an algorithm this SDK will not accept, a compact token with the
// wrong number of segments, and -- the security-critical one -- the `cnf` shapes that
// decide whether a sender-constrained token is treated as constrained.
//
// These are all fail-closed decisions, so an untaken branch here is a branch that has
// never been shown to close.

#include <memory>
#include <string>

#include "assert.hpp"
#include "axiam/errors.hpp"
#include "axiam/jwks.hpp"
#include "axiam/oidc.hpp"
#include "fake_transport.hpp"
#include "test_key.hpp"

using namespace axiam;
using axtest::b64url_encode;
using axtest::FakeState;
using axtest::jwks_transport;
using axtest::TestKey;

namespace {

/// A verifier whose /oauth2/jwks answers with exactly `doc`.
JwksVerifier verifier_serving(std::shared_ptr<FakeState> st, const std::string& doc) {
    return JwksVerifier(jwks_transport(st, doc), "https://api.example.test");
}

}  // namespace

// ---------------------------------------------------------------------------
// base64url decoding.
// ---------------------------------------------------------------------------

AXIAM_TEST("base64url_decode tolerates padding and covers the whole alphabet") {
    // RFC 7515 §2 omits padding, but a value copied from a padded encoder still has to
    // decode -- refusing it would reject a correct key for a cosmetic reason.
    const auto padded = base64url_decode("aGVsbG8=");
    AXIAM_REQUIRE(padded.has_value());
    AXIAM_CHECK(*padded == "hello");

    // Uppercase, digits and both URL-safe substitutions ('-' for '+', '_' for '/').
    const auto mixed = base64url_decode("QUJDMTIz");  // "ABC123"
    AXIAM_REQUIRE(mixed.has_value());
    AXIAM_CHECK(*mixed == "ABC123");
    const auto urlsafe = base64url_decode("-_-_");
    AXIAM_REQUIRE(urlsafe.has_value());
    // '-' is 62 and '_' is 63; standard base64 would have read '+' and '/'.
    AXIAM_CHECK(urlsafe->size() == 3);

    AXIAM_CHECK_FALSE(base64url_decode("bad*chars").has_value());
}

// ---------------------------------------------------------------------------
// Compact-serialization shape. A JWS is exactly three segments, all non-empty.
// ---------------------------------------------------------------------------

AXIAM_TEST("JWKS refuses compact tokens that are not exactly three non-empty segments") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v = verifier_serving(st, key.jwks_json());

    // A fourth dot is a JWE-shaped token, not a JWS. Accepting it would mean verifying
    // the first three segments of something whose real payload is elsewhere.
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked("aGRy.cGF5.c2ln.ZXh0").has_value());

    // An empty segment is not an absent one. ".." in particular is the degenerate token
    // an `alg: none` attack reduces to.
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked("..").has_value());
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked(".cGF5.c2ln").has_value());
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked("aGRy..c2ln").has_value());
    AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked("aGRy.cGF5.").has_value());
}

AXIAM_TEST("JWKS names invalid_alg when the header is not JSON") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v = verifier_serving(st, key.jwks_json());

    // Well-formed base64url that decodes to something that is not a JSON object. There is
    // no `alg` to read, so the token chose no algorithm this SDK will honour.
    const std::string jwt =
        b64url_encode(std::string("not json")) + "." + b64url_encode(std::string("{}")) + ".c2ln";
    const JwtVerification r = v.verify_with_reason(jwt);
    AXIAM_CHECK_FALSE(r.ok);
    AXIAM_CHECK(r.reason == OidcValidationReason::kInvalidAlg);
}

AXIAM_TEST("JWKS names unknown_kid for a key that is not in the served set") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v = verifier_serving(st, key.jwks_json());

    TestKey other;
    other.kid = "rotated-out";
    const JwtVerification r = v.verify_with_reason(other.make_jwt("EdDSA", R"({"sub":"u"})"));
    AXIAM_CHECK_FALSE(r.ok);
    // §12.3 rule 3: distinguishable from invalid_signature on purpose -- this is a stale
    // cache after a rotation, which is an operations problem, not an attack.
    AXIAM_CHECK(r.reason == OidcValidationReason::kUnknownKid);
}

AXIAM_TEST("JWKS names invalid_signature when a segment is not base64url") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v = verifier_serving(st, key.jwks_json());

    std::string jwt = key.make_jwt("EdDSA", R"({"sub":"u"})");
    jwt.replace(jwt.rfind('.') + 1, 3, "**!");
    const JwtVerification r = v.verify_with_reason(jwt);
    AXIAM_CHECK_FALSE(r.ok);
    AXIAM_CHECK(r.reason == OidcValidationReason::kInvalidSignature);
}

AXIAM_TEST("JWKS refuses a correctly signed token whose payload segment is not base64url") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v = verifier_serving(st, key.jwks_json());

    // The signature is GENUINE -- computed over this exact signing input, so Ed25519
    // verification passes -- and the payload segment still cannot be decoded. A token
    // signed over undecodable claims must not come back ok with an empty payload: the
    // caller would read that as "verified, no claims" and apply no constraints at all.
    const std::string header_b64 =
        b64url_encode(std::string(R"({"alg":"EdDSA","typ":"JWT","kid":"key-1"})"));
    const std::string signing_input = header_b64 + ".**not-base64url**";
    const std::string jwt = signing_input + "." + b64url_encode(key.sign(signing_input));

    const JwtVerification r = v.verify_with_reason(jwt);
    AXIAM_CHECK_FALSE(r.ok);
    AXIAM_CHECK(r.reason == OidcValidationReason::kInvalidSignature);
}

// ---------------------------------------------------------------------------
// The key set itself.
// ---------------------------------------------------------------------------

AXIAM_TEST("JWKS ignores a key set that is not a key set") {
    TestKey key;
    const std::string jwt = key.make_jwt("EdDSA", R"({"sub":"u"})");

    for (const char* doc : {"<html>not json</html>", "{}", R"({"keys":{}})", R"({"keys":"none"})"}) {
        auto st = std::make_shared<FakeState>();
        JwksVerifier v = verifier_serving(st, doc);
        v.refresh_keys();
        // No key is adopted from a malformed document -- in particular the verifier does
        // not fall back to "verify against whatever we had", it simply has nothing.
        AXIAM_CHECK(v.cached_key_count() == 0);
        AXIAM_CHECK_FALSE(v.verify_signature_only_unchecked(jwt).has_value());
    }
}

// A `keys` member that is not an object is skipped, exactly like a key of the wrong kty.
//
// This input comes from the ISSUER's key endpoint, not from the caller, so a broken or
// hostile JWKS must not be able to reach into the verifier's control flow. Reading `kty`
// off an unchecked element would do precisely that: nlohmann's `j.value(key, default)`
// does NOT fall back to the default on a non-object, it throws `type_error.306` -- the
// VENDORED exception type the public headers deliberately never name, out of a function
// documented as returning nullopt on malformed input. One junk member in the array would
// then turn every refresh_keys() and verify_signature_only_unchecked() in the process
// into a throw nobody declared and a consumer linking their own nlohmann could not catch.
//
// Skipping is only the right answer if it is surgical, which is what the second half of
// this test is for: a junk member must cost the key set nothing but itself.
AXIAM_TEST("JWKS skips a keys member that is not an object without disturbing the good keys") {
    {
        auto st = std::make_shared<FakeState>();
        JwksVerifier v = verifier_serving(st, R"({"keys":["not-an-object",7,null,[],true]})");
        // No throw, and nothing adopted -- the same outcome as any other unusable entry.
        AXIAM_REQUIRE_NOTHROW(v.refresh_keys());
        AXIAM_CHECK(v.cached_key_count() == 0);
    }

    // The property that matters: a junk member must not take the rest of the key set with
    // it. A verifier that discarded the whole document here would fail every token in the
    // deployment over one bad array element -- a worse outage than the throw it replaced.
    TestKey key;
    auto st = std::make_shared<FakeState>();
    const std::string doc =
        R"({"keys":["not-an-object",7,null,)" +
        key.jwks_json().substr(std::string(R"({"keys":[)").size());
    JwksVerifier v = verifier_serving(st, doc);

    AXIAM_REQUIRE_NOTHROW(v.refresh_keys());
    AXIAM_CHECK(v.cached_key_count() == 1);
    AXIAM_CHECK(
        v.verify_signature_only_unchecked(key.make_jwt("EdDSA", R"({"sub":"u"})")).has_value());
}

AXIAM_TEST("JWKS adopts only Ed25519 OKP keys with a non-empty x") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    // Four junk entries around one usable key: an RSA key, an OKP key on the wrong curve,
    // an Ed25519 key with no `x`, and one with an empty `x`. §12 accepts EdDSA only, so
    // adopting any of these would mean holding a key the verifier can never use -- and
    // the empty-`x` ones would collide in the kid map with a real key.
    const std::string doc =
        R"({"keys":[)"
        R"({"kty":"RSA","kid":"rsa-1","n":"abc","e":"AQAB"},)"
        R"({"kty":"OKP","crv":"X25519","kid":"x25519-1","x":"abc"},)"
        R"({"kty":"OKP","crv":"Ed25519","kid":"no-x"},)"
        R"({"kty":"OKP","crv":"Ed25519","kid":"empty-x","x":""},)" +
        key.jwks_json().substr(std::string(R"({"keys":[)").size());
    JwksVerifier v = verifier_serving(st, doc);
    v.refresh_keys();

    AXIAM_CHECK(v.cached_key_count() == 1);
    AXIAM_CHECK(v.verify_signature_only_unchecked(key.make_jwt("EdDSA", R"({"sub":"u"})"))
                    .has_value());
}

AXIAM_TEST("JWKS refuses a key whose x does not decode to 32 bytes") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    // Structurally a valid JWK, and the kid matches the token -- but the public key is
    // the wrong length for Ed25519. OpenSSL is never asked: a raw-key import of the wrong
    // size is a configuration error, and the size check is what keeps it from becoming an
    // OpenSSL error the caller has to interpret.
    const std::string doc =
        R"({"keys":[{"kty":"OKP","crv":"Ed25519","kid":"key-1","x":"QUJD"}]})";
    JwksVerifier v = verifier_serving(st, doc);
    v.refresh_keys();

    // The JWK is ADOPTED -- nothing about its shape says it is unusable -- and rejected
    // only when the key material itself is imported.
    AXIAM_CHECK(v.cached_key_count() == 1);
    const JwtVerification r = v.verify_with_reason(key.make_jwt("EdDSA", R"({"sub":"u"})"));
    AXIAM_CHECK_FALSE(r.ok);
    AXIAM_CHECK(r.reason == OidcValidationReason::kInvalidSignature);
}

AXIAM_TEST("JWKS keeps the cached key set rather than refetching on every verification") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v = verifier_serving(st, key.jwks_json());
    const std::string jwt = key.make_jwt("EdDSA", R"({"sub":"u"})");

    AXIAM_CHECK(v.verify_signature_only_unchecked(jwt).has_value());
    AXIAM_CHECK(v.verify_signature_only_unchecked(jwt).has_value());
    AXIAM_CHECK(v.verify_signature_only_unchecked(jwt).has_value());
    // One fetch for three verifications: the TTL is what keeps a busy relying party from
    // turning every request into a round trip to the issuer.
    AXIAM_CHECK(st->count_path("/oauth2/jwks") == 1);
}

AXIAM_TEST("JWKS keeps previously cached keys when a refresh fails") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    const std::string doc = key.jwks_json();
    // The first fetch succeeds; every later one is a 503. A zero TTL forces the retry.
    auto failing = std::make_shared<int>(0);
    st->router = [doc, failing](const HttpRequest&, FakeState&) {
        HttpResponse r;
        if ((*failing)++ == 0) {
            r.status = 200;
            r.body = doc;
        } else {
            r.status = 503;
        }
        return r;
    };
    JwksVerifier v(axtest::make_fake(st), "https://api.example.test", std::chrono::seconds(0));
    const std::string jwt = key.make_jwt("EdDSA", R"({"sub":"u"})");

    AXIAM_REQUIRE(v.verify_signature_only_unchecked(jwt).has_value());
    // The issuer is down; the keys it already published have not stopped being its keys.
    // Clearing them would turn an issuer outage into a total authentication outage.
    AXIAM_CHECK(v.verify_signature_only_unchecked(jwt).has_value());
    AXIAM_CHECK(st->count_path("/oauth2/jwks") == 2);
}

AXIAM_TEST("JWKS keeps previously cached keys when the transport itself fails") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    const std::string doc = key.jwks_json();
    auto n = std::make_shared<int>(0);
    st->router = [doc, n](const HttpRequest&, FakeState&) {
        HttpResponse r;
        if ((*n)++ == 0) {
            r.status = 200;
            r.body = doc;
        } else {
            r.transport_error = "connection refused";
        }
        return r;
    };
    JwksVerifier v(axtest::make_fake(st), "https://api.example.test", std::chrono::seconds(0));
    const std::string jwt = key.make_jwt("EdDSA", R"({"sub":"u"})");

    AXIAM_REQUIRE(v.verify_signature_only_unchecked(jwt).has_value());
    AXIAM_CHECK(v.verify_signature_only_unchecked(jwt).has_value());
}

AXIAM_TEST("JwksVerifier strips trailing slashes from the base URL") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test//");
    v.refresh_keys();
    // Not ".test///oauth2/jwks": a doubled slash is a different path to a proxy, and the
    // discovery URL is the one place a typo silently yields an empty key set.
    AXIAM_REQUIRE(st->count() == 1);
    AXIAM_CHECK(st->last().url == "https://api.example.test/oauth2/jwks");
}

// ---------------------------------------------------------------------------
// §21 / RFC 8705 certificate binding. Every branch here is a yes/no on whether a
// sender-constrained token is honoured as constrained.
// ---------------------------------------------------------------------------

AXIAM_TEST("certificate binding accepts a bearer token with or without a certificate") {
    // No `cnf` at all: an ordinary bearer token. Rule 9 constrains tokens that CLAIM a
    // constraint; refusing these would break every deployment that does not use mTLS.
    AXIAM_CHECK(verify_certificate_binding(R"({"sub":"u"})", std::nullopt));
    AXIAM_CHECK(verify_certificate_binding(R"({"sub":"u"})", std::string("some-thumbprint")));
    // An explicit null `cnf` says the same thing as an absent one.
    AXIAM_CHECK(verify_certificate_binding(R"({"sub":"u","cnf":null})", std::nullopt));
}

AXIAM_TEST("certificate binding refuses claims it cannot read") {
    // Fail closed on a malformed input rather than treating "no constraint found" as "no
    // constraint" -- the parse failure is exactly when you cannot know.
    AXIAM_CHECK_FALSE(verify_certificate_binding("not json", std::string("t")));
    AXIAM_CHECK_FALSE(verify_certificate_binding(R"(["sub"])", std::string("t")));
    AXIAM_CHECK_FALSE(verify_certificate_binding("null", std::string("t")));
    // A `cnf` that is not an object is a confirmation this SDK cannot read.
    AXIAM_CHECK_FALSE(verify_certificate_binding(R"({"cnf":"x5t#S256"})", std::string("t")));
}

AXIAM_TEST("certificate binding refuses a confirmation method it cannot check") {
    // A DPoP-only `cnf`. An UNVERIFIABLE constraint is never NO constraint: read the
    // other way, a sender-constrained token degrades to a bearer token the day AXIAM
    // issues a confirmation older SDKs predate.
    AXIAM_CHECK_FALSE(verify_certificate_binding(R"({"cnf":{"jkt":"key-thumb"}})",
                                                 std::string("cert-thumb")));
    // Present but of the wrong type, and present but empty: both are "no usable value".
    AXIAM_CHECK_FALSE(verify_certificate_binding(R"({"cnf":{"x5t#S256":5}})",
                                                 std::string("cert-thumb")));
    AXIAM_CHECK_FALSE(verify_certificate_binding(R"({"cnf":{"x5t#S256":""}})",
                                                 std::string("cert-thumb")));
}

AXIAM_TEST("certificate binding refuses a cnf that names both a certificate and a DPoP key") {
    // Contract 1.16: a `cnf` naming both is a CONJUNCTION. This SDK declines §21.7.2
    // proof verification, so establishing the certificate half and answering for the
    // whole would let a caller holding the certificate but NOT the DPoP key through a
    // door the operator bolted twice.
    AXIAM_CHECK_FALSE(verify_certificate_binding(
        R"({"cnf":{"x5t#S256":"thumb-a","jkt":"key-thumb"}})", std::string("thumb-a")));

    // An empty or non-string `jkt` is not a second constraint, so the certificate half
    // still decides on its own.
    AXIAM_CHECK(verify_certificate_binding(R"({"cnf":{"x5t#S256":"thumb-a","jkt":""}})",
                                           std::string("thumb-a")));
    AXIAM_CHECK(verify_certificate_binding(R"({"cnf":{"x5t#S256":"thumb-a","jkt":7}})",
                                           std::string("thumb-a")));
}

AXIAM_TEST("certificate binding compares the presented thumbprint, and needs one") {
    const std::string claims = R"({"cnf":{"x5t#S256":"thumb-a"}})";

    AXIAM_CHECK(verify_certificate_binding(claims, std::string("thumb-a")));
    // A constrained token with no certificate presented is the whole attack this
    // prevents: a stolen token replayed over a connection that has no client identity.
    AXIAM_CHECK_FALSE(verify_certificate_binding(claims, std::nullopt));
    AXIAM_CHECK_FALSE(verify_certificate_binding(claims, std::string("")));
    AXIAM_CHECK_FALSE(verify_certificate_binding(claims, std::string("thumb-b")));
    // Different LENGTHS take the early exit in the constant-time comparison; a prefix
    // must not compare equal.
    AXIAM_CHECK_FALSE(verify_certificate_binding(claims, std::string("thumb-a-and-more")));
    AXIAM_CHECK_FALSE(verify_certificate_binding(claims, std::string("thumb")));
}

AXIAM_TEST("certificate_thumbprint_s256 is unpadded base64url of 43 characters") {
    const std::string der = "\x30\x82\x01\x0a not really a certificate, just bytes";
    const std::string t = certificate_thumbprint_s256(der);

    // RFC 7515 §2 base64url in JOSE omits '='; a padded value would not compare equal to
    // what AXIAM put in the token, so the binding would fail for a correct certificate.
    AXIAM_REQUIRE(t.size() == 43);
    AXIAM_CHECK(t.find('=') == std::string::npos);
    AXIAM_CHECK(t.find('+') == std::string::npos);
    AXIAM_CHECK(t.find('/') == std::string::npos);
    // Deterministic, and it is the value the binding check compares against.
    AXIAM_CHECK(certificate_thumbprint_s256(der) == t);
    AXIAM_CHECK(certificate_thumbprint_s256(der + "x") != t);
    AXIAM_CHECK(verify_certificate_binding(R"({"cnf":{"x5t#S256":")" + t + R"("}})", t));
}
