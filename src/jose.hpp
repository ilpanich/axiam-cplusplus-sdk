// The JOSE primitives the §32.7 receiver and the §33.2 signed request need,
// over OpenSSL 3's EVP interface.
//
// Internal; not installed. This SDK has no JOSE library dependency and adds
// none: verifying an Ed25519 JWS and signing one under PS256, ES256 or EdDSA is
// a few EVP calls each, and OpenSSL is already a PUBLIC link dependency.

#ifndef AXIAM_JOSE_HPP
#define AXIAM_JOSE_HPP

#include <memory>
#include <optional>
#include <string>

#include "axiam/oidc.hpp"

namespace axiam::detail::jose {

/// base64url without padding (RFC 4648 §5).
std::string b64url_encode(const std::string& bytes);

/// Ed25519 verification of `signature` (64 raw bytes) over `input` with a raw
/// 32-byte public key. False on any malformed input — never throws.
bool ed25519_verify(const std::string& raw_public_key, const std::string& input,
                    const std::string& signature);

/// `bytes` CSPRNG bytes as lower-case hex. Throws NetworkError when the CSPRNG
/// fails, which no caller can recover from by retrying.
std::string random_hex(std::size_t bytes);

/// A private key that signs under exactly one JOSE algorithm.
///
/// Holds the key only as an OpenSSL `EVP_PKEY`, freed (and so cleansed, which
/// `EVP_PKEY_free` does for private material) when the last copy goes. There is
/// no accessor for the key and no stringification of this type at all.
class SigningKey {
public:
    /// Parse `pem` (PKCS#8, or PKCS#1 for RSA; never an encrypted PEM — there is
    /// no passphrase prompt) and probe-sign under `alg`. nullptr when the PEM is
    /// not a private key, or not one that signs under `alg`: an Ed25519 key for
    /// EdDSA, a P-256 key for ES256, an RSA key of at least 2048 bits for PS256.
    static std::shared_ptr<const SigningKey> from_pem(CibaSigningAlg alg,
                                                      const std::string& pem);

    ~SigningKey();
    SigningKey(const SigningKey&) = delete;
    SigningKey& operator=(const SigningKey&) = delete;

    /// The JWS signature over `input`, in JOSE form (ES256's is the raw r||s
    /// pair, not DER), or nullopt when OpenSSL refuses.
    std::optional<std::string> sign(const std::string& input) const;

    CibaSigningAlg alg() const noexcept { return alg_; }

private:
    SigningKey(CibaSigningAlg alg, void* pkey) : alg_(alg), pkey_(pkey) {}
    CibaSigningAlg alg_;
    void* pkey_;  // EVP_PKEY*, kept opaque so this header needs no OpenSSL include
};

/// The JOSE `alg` name.
const char* alg_name(CibaSigningAlg alg) noexcept;

}  // namespace axiam::detail::jose

#endif  // AXIAM_JOSE_HPP
