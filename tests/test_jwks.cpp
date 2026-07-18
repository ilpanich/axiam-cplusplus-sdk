#include <openssl/evp.h>

#include <memory>
#include <string>
#include <vector>

#include "assert.hpp"
#include "axiam/jwks.hpp"
#include "fake_transport.hpp"

using namespace axiam;
using axtest::FakeState;

namespace {

std::string b64url_encode(const unsigned char* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    int buffer = 0, bits = 0;
    for (size_t i = 0; i < len; ++i) {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(tbl[(buffer >> bits) & 0x3F]);
        }
    }
    if (bits > 0) out.push_back(tbl[(buffer << (6 - bits)) & 0x3F]);
    return out;  // unpadded
}

std::string b64url_encode(const std::string& s) {
    return b64url_encode(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

// Holds a generated Ed25519 keypair and produces signed JWTs + a JWKS document.
struct TestKey {
    EVP_PKEY* pkey = nullptr;
    std::string kid = "key-1";

    TestKey() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);
    }
    ~TestKey() {
        if (pkey) EVP_PKEY_free(pkey);
    }

    std::string raw_public() const {
        size_t len = 0;
        EVP_PKEY_get_raw_public_key(pkey, nullptr, &len);
        std::vector<unsigned char> buf(len);
        EVP_PKEY_get_raw_public_key(pkey, buf.data(), &len);
        return std::string(reinterpret_cast<char*>(buf.data()), len);
    }

    std::string sign(const std::string& msg) const {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey);
        size_t siglen = 0;
        EVP_DigestSign(mdctx, nullptr, &siglen,
                       reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
        std::vector<unsigned char> sig(siglen);
        EVP_DigestSign(mdctx, sig.data(), &siglen,
                       reinterpret_cast<const unsigned char*>(msg.data()), msg.size());
        EVP_MD_CTX_free(mdctx);
        return std::string(reinterpret_cast<char*>(sig.data()), siglen);
    }

    std::string jwks_json() const {
        return std::string("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"") + kid +
               "\",\"x\":\"" + b64url_encode(raw_public()) + "\"}]}";
    }

    std::string make_jwt(const std::string& alg, const std::string& payload) const {
        std::string header = "{\"alg\":\"" + alg + "\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}";
        std::string signing_input = b64url_encode(header) + "." + b64url_encode(payload);
        std::string sig = sign(signing_input);
        return signing_input + "." + b64url_encode(sig);
    }
};

Transport jwks_transport(std::shared_ptr<FakeState> st, std::string doc) {
    st->router = [doc](const HttpRequest& req, FakeState&) {
        axiam::HttpResponse r;
        if (req.url.find("/oauth2/jwks") != std::string::npos) {
            r.status = 200;
            r.body = doc;
        } else {
            r.status = 404;
        }
        return r;
    };
    return axtest::make_fake(st);
}

}  // namespace

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
    auto res = v.verify(jwt);
    AXIAM_REQUIRE(res.has_value());
    AXIAM_CHECK(res->payload_json.find("user-1") != std::string::npos);
    AXIAM_CHECK(v.cached_key_count() == 1);
}

AXIAM_TEST("JWKS rejects non-EdDSA alg before any key work") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    std::string jwt = key.make_jwt("RS256", R"({"sub":"user-1"})");
    AXIAM_CHECK_FALSE(v.verify(jwt).has_value());
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
    AXIAM_CHECK_FALSE(v.verify(jwt).has_value());
}

AXIAM_TEST("JWKS rejects malformed compact token") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    AXIAM_CHECK_FALSE(v.verify("not-a-jwt").has_value());
    AXIAM_CHECK_FALSE(v.verify("only.two").has_value());
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
    AXIAM_CHECK_FALSE(v.verify(jwt).has_value());
}

AXIAM_TEST("JWKS caches keys across verifications (single fetch)") {
    TestKey key;
    auto st = std::make_shared<FakeState>();
    JwksVerifier v(jwks_transport(st, key.jwks_json()), "https://api.example.test");
    std::string jwt = key.make_jwt("EdDSA", R"({"sub":"u"})");
    AXIAM_CHECK(v.verify(jwt).has_value());
    AXIAM_CHECK(v.verify(jwt).has_value());
    AXIAM_CHECK(st->count_path("/oauth2/jwks") == 1);
}
