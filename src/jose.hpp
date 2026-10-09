// The JOSE primitives the §32.7 receiver needs, over OpenSSL 3's EVP interface.
//
// Internal; not installed. This SDK has no JOSE library dependency and adds
// none: verifying an Ed25519 JWS and signing one under PS256, ES256 or EdDSA is
// a few EVP calls each, and OpenSSL is already a PUBLIC link dependency.

#ifndef AXIAM_JOSE_HPP
#define AXIAM_JOSE_HPP

#include <string>

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

}  // namespace axiam::detail::jose

#endif  // AXIAM_JOSE_HPP
