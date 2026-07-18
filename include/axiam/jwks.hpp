// JWKS fetch + Ed25519 (EdDSA) JWT signature verification.
//
// Fetches GET {base}/oauth2/jwks, caches the key set for 300s, and verifies a
// compact JWS using OpenSSL raw Ed25519 keys. Only alg == "EdDSA" is accepted;
// any other alg is rejected before signature work. The verifier does NOT check
// token expiry (`exp`) — that is the caller's concern.
#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <optional>
#include <string>

#include "axiam/transport.hpp"

namespace axiam {

/// One Ed25519 (OKP) public key from the JWK set.
struct Ed25519Jwk {
    std::string kid;
    std::string x_b64url;  // 32-byte public key, base64url (unpadded)
};

/// Result of a successful verification: the decoded payload (claims) JSON string.
struct VerifiedToken {
    std::string payload_json;
};

/// Base64url decode (unpadded or padded). Returns nullopt on malformed input.
std::optional<std::string> base64url_decode(const std::string& in);

class JwksVerifier {
public:
    /// @param transport shared transport seam (same as the client's).
    /// @param base_url  server base URL (no trailing slash required).
    /// @param cache_ttl key-set cache lifetime (default 300s).
    JwksVerifier(Transport transport, std::string base_url,
                 std::chrono::seconds cache_ttl = std::chrono::seconds(300));

    /// Verify a compact JWS. Ed25519/EdDSA only. On success returns the payload;
    /// returns nullopt if the alg is not EdDSA, the kid is unknown, the token is
    /// malformed, or the signature does not verify. Does not check `exp`.
    std::optional<VerifiedToken> verify(const std::string& jwt);

    /// Force-refresh the cached key set (also called lazily by verify()).
    void refresh_keys();

    /// Test/introspection helper: number of currently-cached keys.
    std::size_t cached_key_count();

private:
    void ensure_keys_locked();
    void load_from_json(const std::string& body);

    Transport transport_;
    std::string base_url_;
    std::chrono::seconds cache_ttl_;

    std::mutex mtx_;
    std::map<std::string, Ed25519Jwk> keys_;  // kid -> jwk
    std::chrono::steady_clock::time_point fetched_at_{};
    bool have_keys_ = false;
};

}  // namespace axiam
