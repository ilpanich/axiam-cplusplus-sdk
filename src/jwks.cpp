#include "axiam/jwks.hpp"

#include <openssl/evp.h>

#include <array>
#include <cstdint>

#include <nlohmann/json.hpp>

namespace axiam {

std::optional<std::string> base64url_decode(const std::string& in) {
    static constexpr std::array<int, 256> make_table_placeholder{};
    (void)make_table_placeholder;

    auto val = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-') return 62;
        if (c == '_') return 63;
        return -1;
    };

    std::string out;
    int buffer = 0;
    int bits = 0;
    for (char ch : in) {
        if (ch == '=') break;  // tolerate padding
        const int v = val(static_cast<unsigned char>(ch));
        if (v < 0) return std::nullopt;
        buffer = (buffer << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

namespace {

// Split a compact JWS "a.b.c" into its three parts. Returns false if malformed.
bool split_jwt(const std::string& jwt, std::string& header, std::string& payload,
               std::string& signature) {
    const auto dot1 = jwt.find('.');
    if (dot1 == std::string::npos) return false;
    const auto dot2 = jwt.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return false;
    if (jwt.find('.', dot2 + 1) != std::string::npos) return false;  // 4th dot
    header = jwt.substr(0, dot1);
    payload = jwt.substr(dot1 + 1, dot2 - dot1 - 1);
    signature = jwt.substr(dot2 + 1);
    return !header.empty() && !payload.empty() && !signature.empty();
}

bool ed25519_verify(const std::string& raw_pubkey, const std::string& signing_input,
                    const std::string& signature) {
    if (raw_pubkey.size() != 32 || signature.size() != 64) return false;

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(raw_pubkey.data()), raw_pubkey.size());
    if (pkey == nullptr) return false;

    bool ok = false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx != nullptr) {
        if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
            const int rc = EVP_DigestVerify(
                ctx, reinterpret_cast<const unsigned char*>(signature.data()),
                signature.size(),
                reinterpret_cast<const unsigned char*>(signing_input.data()),
                signing_input.size());
            ok = (rc == 1);
        }
        EVP_MD_CTX_free(ctx);
    }
    EVP_PKEY_free(pkey);
    return ok;
}

}  // namespace

JwksVerifier::JwksVerifier(Transport transport, std::string base_url,
                           std::chrono::seconds cache_ttl)
    : transport_(std::move(transport)),
      base_url_(std::move(base_url)),
      cache_ttl_(cache_ttl) {
    while (!base_url_.empty() && base_url_.back() == '/') base_url_.pop_back();
}

void JwksVerifier::load_from_json(const std::string& body) {
    keys_.clear();
    auto doc = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded() || !doc.contains("keys") || !doc["keys"].is_array()) {
        return;
    }
    for (const auto& k : doc["keys"]) {
        const std::string kty = k.value("kty", "");
        const std::string crv = k.value("crv", "");
        if (kty != "OKP" || crv != "Ed25519") continue;  // Ed25519 only
        Ed25519Jwk jwk;
        jwk.kid = k.value("kid", "");
        jwk.x_b64url = k.value("x", "");
        if (jwk.x_b64url.empty()) continue;
        keys_[jwk.kid] = jwk;
    }
}

void JwksVerifier::ensure_keys_locked() {
    const auto now = std::chrono::steady_clock::now();
    if (have_keys_ && (now - fetched_at_) < cache_ttl_) return;

    HttpRequest req;
    req.method = "GET";
    req.url = base_url_ + "/oauth2/jwks";
    req.headers["Accept"] = "application/json";
    const HttpResponse resp = transport_(req);
    if (!resp.transport_error.empty() || resp.status != 200) {
        return;  // keep any previously cached keys
    }
    load_from_json(resp.body);
    fetched_at_ = now;
    have_keys_ = true;
}

void JwksVerifier::refresh_keys() {
    std::lock_guard<std::mutex> lock(mtx_);
    have_keys_ = false;
    ensure_keys_locked();
}

std::size_t JwksVerifier::cached_key_count() {
    std::lock_guard<std::mutex> lock(mtx_);
    return keys_.size();
}

std::optional<VerifiedToken> JwksVerifier::verify(const std::string& jwt) {
    std::string header_b64, payload_b64, sig_b64;
    if (!split_jwt(jwt, header_b64, payload_b64, sig_b64)) return std::nullopt;

    const auto header_json = base64url_decode(header_b64);
    if (!header_json) return std::nullopt;
    auto header = nlohmann::json::parse(*header_json, nullptr, /*allow_exceptions=*/false);
    if (header.is_discarded()) return std::nullopt;

    // Reject any non-EdDSA algorithm BEFORE any signature work.
    if (header.value("alg", "") != "EdDSA") return std::nullopt;
    const std::string kid = header.value("kid", "");

    Ed25519Jwk jwk;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        ensure_keys_locked();
        auto it = keys_.find(kid);
        if (it == keys_.end()) {
            // Unknown kid: force a single refresh in case of rotation.
            have_keys_ = false;
            ensure_keys_locked();
            it = keys_.find(kid);
            if (it == keys_.end()) return std::nullopt;
        }
        jwk = it->second;
    }

    const auto raw_pub = base64url_decode(jwk.x_b64url);
    const auto sig = base64url_decode(sig_b64);
    if (!raw_pub || !sig) return std::nullopt;

    const std::string signing_input = header_b64 + "." + payload_b64;
    if (!ed25519_verify(*raw_pub, signing_input, *sig)) return std::nullopt;

    const auto payload_json = base64url_decode(payload_b64);
    if (!payload_json) return std::nullopt;
    return VerifiedToken{*payload_json};
}

}  // namespace axiam
