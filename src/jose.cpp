// JOSE primitives over OpenSSL 3 — see jose.hpp.

#include "jose.hpp"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

#include <cstring>
#include <vector>

#include "axiam/errors.hpp"

namespace axiam::detail::jose {
namespace {

EVP_PKEY* as_pkey(void* p) { return static_cast<EVP_PKEY*>(p); }

/// A passphrase callback that refuses: an encrypted PEM is not a key this SDK
/// can use, and OpenSSL's default callback would prompt on the terminal.
int no_passphrase(char*, int, int, void*) { return 0; }

/// The DER ECDSA signature OpenSSL produces, as JOSE's fixed-width r||s.
std::optional<std::string> der_to_jose_p256(const unsigned char* der, std::size_t len) {
    const unsigned char* p = der;
    ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(len));
    if (sig == nullptr) return std::nullopt;
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(sig, &r, &s);
    unsigned char out[64];
    const bool ok = BN_bn2binpad(r, out, 32) == 32 && BN_bn2binpad(s, out + 32, 32) == 32;
    ECDSA_SIG_free(sig);
    if (!ok) return std::nullopt;
    return std::string(reinterpret_cast<const char*>(out), sizeof(out));
}

/// Whether `pkey` is the key type `alg` signs with.
bool key_matches(CibaSigningAlg alg, EVP_PKEY* pkey) {
    switch (alg) {
        case CibaSigningAlg::kEdDSA:
            return EVP_PKEY_get_base_id(pkey) == EVP_PKEY_ED25519;
        case CibaSigningAlg::kES256: {
            if (EVP_PKEY_get_base_id(pkey) != EVP_PKEY_EC) return false;
            char group[64] = {0};
            std::size_t len = 0;
            if (EVP_PKEY_get_group_name(pkey, group, sizeof(group), &len) != 1) return false;
            return std::strcmp(group, "prime256v1") == 0;
        }
        case CibaSigningAlg::kPS256:
            return EVP_PKEY_get_base_id(pkey) == EVP_PKEY_RSA && EVP_PKEY_get_bits(pkey) >= 2048;
    }
    return false;
}

}  // namespace

std::string b64url_encode(const std::string& bytes) {
    static const char* kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    for (std::size_t i = 0; i < bytes.size(); i += 3) {
        unsigned v = static_cast<unsigned>(static_cast<unsigned char>(bytes[i])) << 16;
        std::size_t have = 1;
        if (i + 1 < bytes.size()) {
            v |= static_cast<unsigned>(static_cast<unsigned char>(bytes[i + 1])) << 8;
            have = 2;
        }
        if (i + 2 < bytes.size()) {
            v |= static_cast<unsigned>(static_cast<unsigned char>(bytes[i + 2]));
            have = 3;
        }
        out.push_back(kAlphabet[(v >> 18) & 0x3F]);
        out.push_back(kAlphabet[(v >> 12) & 0x3F]);
        if (have > 1) out.push_back(kAlphabet[(v >> 6) & 0x3F]);
        if (have > 2) out.push_back(kAlphabet[v & 0x3F]);
    }
    return out;
}

bool ed25519_verify(const std::string& raw_public_key, const std::string& input,
                    const std::string& signature) {
    if (raw_public_key.size() != 32 || signature.size() != 64) return false;
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(raw_public_key.data()), raw_public_key.size());
    if (pkey == nullptr) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const bool ok =
        ctx != nullptr && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1 &&
        EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char*>(signature.data()),
                         signature.size(), reinterpret_cast<const unsigned char*>(input.data()),
                         input.size()) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

std::string random_hex(std::size_t bytes) {
    std::vector<unsigned char> raw(bytes);
    if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
        throw NetworkError("could not draw cryptographic randomness", "rand_failure");
    }
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(bytes * 2);
    for (unsigned char b : raw) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

const char* alg_name(CibaSigningAlg alg) noexcept {
    switch (alg) {
        case CibaSigningAlg::kPS256: return "PS256";
        case CibaSigningAlg::kES256: return "ES256";
        case CibaSigningAlg::kEdDSA: return "EdDSA";
    }
    return "EdDSA";
}

std::shared_ptr<const SigningKey> SigningKey::from_pem(CibaSigningAlg alg,
                                                       const std::string& pem) {
    if (pem.empty()) return nullptr;
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr) return nullptr;
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, no_passphrase, nullptr);
    BIO_free(bio);
    if (pkey == nullptr) return nullptr;
    if (!key_matches(alg, pkey)) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    std::shared_ptr<const SigningKey> key(new SigningKey(alg, pkey));
    // A key that parses and has the right type is still only PROBABLY a key for
    // this algorithm; signing proves it, here, rather than at the first request.
    if (!key->sign("axiam-ciba-probe")) return nullptr;
    return key;
}

SigningKey::~SigningKey() { EVP_PKEY_free(as_pkey(pkey_)); }

std::optional<std::string> SigningKey::sign(const std::string& input) const {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return std::nullopt;
    EVP_PKEY_CTX* pctx = nullptr;
    const EVP_MD* md = alg_ == CibaSigningAlg::kEdDSA ? nullptr : EVP_sha256();
    bool ok = EVP_DigestSignInit(ctx, &pctx, md, nullptr, as_pkey(pkey_)) == 1;
    if (ok && alg_ == CibaSigningAlg::kPS256) {
        // RFC 7518 §3.5: PSS with SHA-256, MGF1 with SHA-256, a 32-byte salt.
        ok = EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) == 1 &&
             EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) == 1;
    }
    std::size_t len = 0;
    const auto* msg = reinterpret_cast<const unsigned char*>(input.data());
    ok = ok && EVP_DigestSign(ctx, nullptr, &len, msg, input.size()) == 1;
    std::vector<unsigned char> sig(ok ? len : 0);
    ok = ok && EVP_DigestSign(ctx, sig.data(), &len, msg, input.size()) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) return std::nullopt;
    if (alg_ == CibaSigningAlg::kES256) return der_to_jose_p256(sig.data(), len);
    return std::string(reinterpret_cast<const char*>(sig.data()), len);
}

}  // namespace axiam::detail::jose
