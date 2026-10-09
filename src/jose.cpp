// JOSE primitives over OpenSSL 3 — see jose.hpp.

#include "jose.hpp"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <vector>

#include "axiam/errors.hpp"

namespace axiam::detail::jose {

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

}  // namespace axiam::detail::jose
