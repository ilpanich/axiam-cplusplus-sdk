#include "axiam/jwks.hpp"

#include "axiam/oidc.hpp"

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
    // The accumulator MUST be unsigned and masked. Only the low `bits` are ever
    // read back, but the accumulator itself is never truncated, so a signed one
    // overflows after a handful of symbols — signed overflow is UB, and this
    // runs on every token the §10.1 verification path decodes. 24 bits is ample:
    // at most 13 are ever live (6 shifted in on top of at most 7 still owed).
    std::uint32_t buffer = 0;
    int bits = 0;
    for (char ch : in) {
        if (ch == '=') break;  // tolerate padding
        const int v = val(static_cast<unsigned char>(ch));
        if (v < 0) return std::nullopt;
        buffer = ((buffer << 6) | static_cast<std::uint32_t>(v)) & 0xFFFFFFu;
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

std::optional<VerifiedToken> JwksVerifier::verify_signature_only_unchecked(
    const std::string& jwt) {
    // One body, two entry points: the §10 authenticator and the §12 relying
    // party must not be able to disagree about what "verified" means.
    const JwtVerification v = verify_with_reason(jwt);
    if (!v.ok) return std::nullopt;
    return VerifiedToken{v.payload_json};
}

JwtVerification JwksVerifier::verify_with_reason(const std::string& jwt) {
    const auto fail = [](const char* reason) {
        JwtVerification v;
        v.reason = reason;
        return v;
    };

    // A token that is not three dot-separated parts cannot even have its
    // algorithm established, which is why §12.3 rule 3 folds that case into
    // `invalid_alg` rather than inventing an eighth code for it.
    std::string header_b64, payload_b64, sig_b64;
    if (!split_jwt(jwt, header_b64, payload_b64, sig_b64)) {
        return fail(OidcValidationReason::kInvalidAlg);
    }

    const auto header_json = base64url_decode(header_b64);
    if (!header_json) return fail(OidcValidationReason::kInvalidAlg);
    auto header = nlohmann::json::parse(*header_json, nullptr, /*allow_exceptions=*/false);
    if (header.is_discarded()) return fail(OidcValidationReason::kInvalidAlg);

    // §12.4 rule 1: read `alg` from the header and check it BEFORE any signature
    // work. An SDK must not let the token select its own verification
    // algorithm, and the discovery document's advertised list cannot widen this
    // either.
    if (header.value("alg", "") != "EdDSA") return fail(OidcValidationReason::kInvalidAlg);
    const std::string kid = header.value("kid", "");

    Ed25519Jwk jwk;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        ensure_keys_locked();
        auto it = keys_.find(kid);
        if (it == keys_.end()) {
            // §12.4 rule 2, per WINDOW rather than per token. The first unknown
            // `kid` costs one re-fetch and opens the cooldown; a further unknown
            // `kid` inside it re-consults the cached set with no network call.
            // Before this, an attacker presenting arbitrary `kid` values drove
            // one JWKS fetch per forged token — the amplification the rule
            // exists to bound.
            const auto now = std::chrono::steady_clock::now();
            if (now >= refetch_cooldown_until_) {
                refetch_cooldown_until_ =
                    now + std::chrono::seconds(kOidcJwksRefetchCooldownSeconds);
                have_keys_ = false;
                ensure_keys_locked();
                it = keys_.find(kid);
            }
            // Covers "no kid in the header at all" as well as "no key matches
            // it", which §12.3 rule 3 folds into one code deliberately.
            if (it == keys_.end()) return fail(OidcValidationReason::kUnknownKid);
        }
        jwk = it->second;
    }

    const auto raw_pub = base64url_decode(jwk.x_b64url);
    const auto sig = base64url_decode(sig_b64);
    if (!raw_pub || !sig) return fail(OidcValidationReason::kInvalidSignature);

    const std::string signing_input = header_b64 + "." + payload_b64;
    if (!ed25519_verify(*raw_pub, signing_input, *sig)) {
        return fail(OidcValidationReason::kInvalidSignature);
    }

    const auto payload_json = base64url_decode(payload_b64);
    if (!payload_json) return fail(OidcValidationReason::kInvalidSignature);

    JwtVerification v;
    v.ok = true;
    v.payload_json = *payload_json;
    return v;
}

// ---------------------------------------------------------------------------
// CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) tokens
// (contract 1.15, RFC 8705 §3 / RFC 7800).
// ---------------------------------------------------------------------------

namespace {

/// Constant-time string comparison.
///
/// The thumbprint is usually public — it derives from a certificate sent in the
/// clear during the handshake — so this is defence in depth. It matters most
/// for a self-signed client, where the registered thumbprint is the whole
/// credential. Length inequality short-circuits, leaking only the length; both
/// operands are fixed-length base64url SHA-256 digests when well-formed.
bool constant_time_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
}

}  // namespace

bool verify_certificate_binding(const std::string& claims_json,
                                const std::optional<std::string>& presented_thumbprint) {
    auto claims = nlohmann::json::parse(claims_json, nullptr, /*allow_exceptions=*/false);
    if (claims.is_discarded() || !claims.is_object()) return false;

    const auto cnf_it = claims.find("cnf");
    if (cnf_it == claims.end() || cnf_it->is_null()) {
        // An ordinary bearer token. Accepted with or without a certificate:
        // rule 9 constrains tokens that CLAIM a constraint, and treating it
        // otherwise would break every deployment that does not use mTLS.
        return true;
    }
    if (!cnf_it->is_object()) return false;

    const auto x5t_it = cnf_it->find("x5t#S256");
    if (x5t_it == cnf_it->end() || !x5t_it->is_string()) {
        // A confirmation naming a method this SDK cannot check — a DPoP `jkt`,
        // say. An UNVERIFIABLE constraint, never NO constraint: read the other
        // way, a sender-constrained token silently degrades to a bearer token
        // the day a newer AXIAM issues a confirmation this SDK predates.
        return false;
    }
    const auto expected = x5t_it->get<std::string>();
    if (expected.empty()) return false;

    // A `cnf` naming BOTH a certificate and a DPoP key is a CONJUNCTION
    // (contract 1.16): both constraints must hold. This SDK declines §21.7.2
    // proof verification, so it can establish one half and must not answer for
    // the whole — accepting on the certificate alone is exactly the "check
    // whichever we can" the rule forbids, and it would let a caller holding the
    // certificate but NOT the DPoP key through a door the operator bolted twice.
    const auto jkt_it = cnf_it->find("jkt");
    if (jkt_it != cnf_it->end() && jkt_it->is_string() &&
        !jkt_it->get<std::string>().empty()) {
        return false;
    }

    if (!presented_thumbprint.has_value() || presented_thumbprint->empty()) return false;
    return constant_time_equal(expected, *presented_thumbprint);
}

std::string certificate_thumbprint_s256(const std::string& der) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return {};
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, der.data(), der.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || digest_len != 32) return {};

    // Base64url WITHOUT padding: RFC 7515 §2 defines base64url in JOSE that
    // way, and a padded value will not compare equal to what AXIAM put in the
    // token. A 32-byte digest encodes to exactly 43 characters.
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve(43);
    for (unsigned int i = 0; i < digest_len; i += 3) {
        const unsigned int remaining = digest_len - i;
        unsigned int v = static_cast<unsigned int>(digest[i]) << 16;
        if (remaining > 1) v |= static_cast<unsigned int>(digest[i + 1]) << 8;
        if (remaining > 2) v |= static_cast<unsigned int>(digest[i + 2]);

        out.push_back(kAlphabet[(v >> 18) & 0x3f]);
        out.push_back(kAlphabet[(v >> 12) & 0x3f]);
        if (remaining > 1) out.push_back(kAlphabet[(v >> 6) & 0x3f]);
        if (remaining > 2) out.push_back(kAlphabet[v & 0x3f]);
    }
    return out;
}

}  // namespace axiam