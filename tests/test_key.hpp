// Shared test fixture: an in-memory Ed25519 keypair that can mint compact JWS
// tokens and serve the matching JWK set. Used by the JWKS primitive tests and by
// the TokenAuthenticator tests.
#pragma once

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "axiam/transport.hpp"
#include "fake_transport.hpp"

namespace axtest {

inline std::string b64url_encode(const unsigned char* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    // Unsigned + masked: only the low `bits` are read back, but the accumulator
    // is never truncated, so a signed one overflows (UB) after a few bytes.
    std::uint32_t buffer = 0;
    int bits = 0;
    for (size_t i = 0; i < len; ++i) {
        buffer = ((buffer << 8) | data[i]) & 0xFFFFFFu;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            out.push_back(tbl[(buffer >> bits) & 0x3F]);
        }
    }
    if (bits > 0) out.push_back(tbl[(buffer << (6 - bits)) & 0x3F]);
    return out;  // unpadded
}

inline std::string b64url_encode(const std::string& s) {
    return b64url_encode(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}

/// Holds a generated Ed25519 keypair and produces signed JWTs + a JWKS document.
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

    TestKey(const TestKey&) = delete;
    TestKey& operator=(const TestKey&) = delete;

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

    /// An `alg: none` token in its canonical shape: three parts, the third
    /// empty. CONTRACT §10.1 rule 1 requires rejection without consulting a key.
    std::string make_alg_none_jwt(const std::string& payload) const {
        std::string header = "{\"alg\":\"none\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}";
        return b64url_encode(header) + "." + b64url_encode(payload) + ".";
    }

    /// The classic HS/EdDSA confusion: the header claims HS256 and carries the
    /// EdDSA `kid`, and the MAC is genuinely computed with the org's PUBLISHED
    /// Ed25519 public key as the HMAC secret. An implementation that trusted
    /// the header would compute the same MAC and accept the token.
    std::string make_hs256_confused_jwt(const std::string& payload) const {
        std::string header = "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"" + kid + "\"}";
        const std::string signing_input = b64url_encode(header) + "." + b64url_encode(payload);
        const std::string secret = raw_public();
        unsigned char mac[EVP_MAX_MD_SIZE];
        unsigned int maclen = 0;
        HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
             reinterpret_cast<const unsigned char*>(signing_input.data()),
             signing_input.size(), mac, &maclen);
        return signing_input + "." + b64url_encode(mac, maclen);
    }
};

/// A transport that serves `doc` at /oauth2/jwks and 404s everything else.
inline axiam::Transport jwks_transport(std::shared_ptr<FakeState> st, std::string doc) {
    st->router = [doc](const axiam::HttpRequest& req, FakeState&) {
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

}  // namespace axtest
