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

namespace {
// §12.4 rule 2 (contract 1.69, D-10): the TTL is at most 300 s, a larger value is clamped
// down rather than honoured, and a smaller one stands.
std::chrono::seconds clamp_ttl(std::chrono::seconds ttl) {
    if (ttl > std::chrono::seconds(kJwksMaxTtlSeconds)) return std::chrono::seconds(kJwksMaxTtlSeconds);
    if (ttl < std::chrono::seconds(0)) return std::chrono::seconds(0);
    return ttl;
}

// `max-age=N` out of a Cache-Control value, or -1 when absent or malformed.
long parse_max_age(const std::string& cc) {
    std::string l = CaseInsensitiveLess::lower(cc);
    std::size_t pos = 0;
    while ((pos = l.find("max-age", pos)) != std::string::npos) {
        const bool at_start = pos == 0 || l[pos - 1] == ' ' || l[pos - 1] == ',';
        std::size_t i = pos + 7;
        pos = i;
        if (!at_start) continue;
        while (i < l.size() && l[i] == ' ') ++i;
        if (i >= l.size() || l[i] != '=') continue;
        ++i;
        while (i < l.size() && l[i] == ' ') ++i;
        if (i < l.size() && l[i] == '"') ++i;
        long n = 0;
        bool any = false;
        while (i < l.size() && l[i] >= '0' && l[i] <= '9') {
            n = n * 10 + (l[i] - '0');
            if (n > 100000000L) n = 100000000L;
            any = true;
            ++i;
        }
        return any ? n : -1;
    }
    return -1;
}
}  // namespace

JwksVerifier::JwksVerifier(Transport transport, std::string base_url,
                           std::optional<std::chrono::seconds> cache_ttl, TelemetryHook telemetry)
    : transport_(std::move(transport)), base_url_(std::move(base_url)) {
    while (!base_url_.empty() && base_url_.back() == '/') base_url_.pop_back();
    if (cache_ttl) {
        configured_ttl_ = clamp_ttl(*cache_ttl);
        effective_ttl_ = *configured_ttl_;
        if (*configured_ttl_ != *cache_ttl && telemetry) {
            // §19.2 rule 2: a throwing hook cannot fail construction.
            try {
                telemetry(ConfigClampedEvent{"jwks_cache_ttl", std::to_string(cache_ttl->count()) + "s",
                                             std::to_string(configured_ttl_->count()) + "s",
                                             "\u00a712.4 rule 2"});
            } catch (...) {
            }
        }
    }
}

bool JwksVerifier::load_from_json(const std::string& body) {
    std::map<std::string, Ed25519Jwk> parsed;
    auto doc = nlohmann::json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded() || !doc.contains("keys") || !doc["keys"].is_array()) {
        return false;
    }
    // §12.4 rule 2: "a JWKS document holding at least one key". A `keys` array none of whose
    // members is a JWK object with a string `kty` (`[{}]`, `[0]`, `[null]`) is not one. A set of
    // valid JWKs with no Ed25519 key IS one (a success that verifies nothing): the contract
    // does not go further, and neither does this.
    bool any_jwk = false;
    for (const auto& k : doc["keys"]) {
        if (k.is_object()) {
            const auto t = k.find("kty");
            if (t != k.end() && t->is_string()) any_jwk = true;
        }
    }
    if (!any_jwk) return false;
    for (const auto& k : doc["keys"]) {
        // A JWKS whose `keys` array holds a non-object member — `{"keys":["x"]}` —
        // used to reach `k.value("kty", ...)` and throw
        // `nlohmann::detail::type_error`. That input arrives from the ISSUER's key
        // endpoint, not from the caller, so a broken or hostile JWKS turned every
        // `refresh_keys()` and `verify_signature_only_unchecked()` in the process
        // into an uncatchable throw of a VENDORED exception type — against a
        // documented contract that says this path returns `nullopt` on malformed
        // input, and one the caller cannot name to catch. Skipping the member is
        // the same treatment the loop already gives a key with the wrong `kty`.
        if (!k.is_object()) continue;
        // The same applies one level down (C4): `k.value("kty", "")` throws
        // `type_error.302` when the member holds a non-string, so `{"kty":1}`
        // escaped `refresh_keys()` as a vendored exception. Read each member with
        // `find()` and skip the key unless all four are strings.
        const auto kty_it = k.find("kty");
        const auto crv_it = k.find("crv");
        const auto kid_it = k.find("kid");
        const auto x_it = k.find("x");
        if (kty_it == k.end() || !kty_it->is_string() || crv_it == k.end() ||
            !crv_it->is_string() || kid_it == k.end() || !kid_it->is_string() ||
            x_it == k.end() || !x_it->is_string()) {
            continue;
        }
        if (kty_it->get<std::string>() != "OKP" || crv_it->get<std::string>() != "Ed25519") {
            continue;  // Ed25519 only
        }
        Ed25519Jwk jwk;
        jwk.kid = kid_it->get<std::string>();
        jwk.x_b64url = x_it->get<std::string>();
        if (jwk.x_b64url.empty()) continue;
        parsed[jwk.kid] = jwk;
    }
    keys_ = std::move(parsed);
    return true;
}

void JwksVerifier::_set_clock_test_seam(
    std::function<std::chrono::steady_clock::time_point()> clock) {
    std::lock_guard<std::mutex> lock(mtx_);
    clock_ = std::move(clock);
}

void JwksVerifier::wait_idle(Lock& lk) {
    idle_cv_.wait(lk, [this] { return !in_flight_; });
}

bool JwksVerifier::fetch_unlocked(Lock& lk) {
    const auto started = clock_();
    in_flight_ = true;
    ttl_window_until_ = started + std::chrono::seconds(kOidcJwksRefetchCooldownSeconds);
    const bool conditional = have_keys_ && !etag_.empty();
    HttpRequest req;
    req.method = "GET";
    req.url = base_url_ + "/oauth2/jwks";
    req.headers["Accept"] = "application/json";
    if (conditional) req.headers["If-None-Match"] = etag_;
    req.sessionless = true;  // §6.1 rule 11: no session cookie on /oauth2/*

    // The network call runs with the state lock RELEASED: a verification whose held set is
    // usable must never queue behind a slow or hung JWKS endpoint.
    lk.unlock();
    HttpResponse resp;
    try {
        resp = transport_(req);
    } catch (...) {
        resp = HttpResponse{};
        resp.transport_error = "transport threw";
    }
    lk.lock();

    bool ok = false;
    if (resp.transport_error.empty()) {
        if (resp.status == 304) {
            ok = conditional && have_keys_;  // only a 304 to a conditional request counts
        } else if (resp.status == 200) {
            ok = load_from_json(resp.body);
        }
    }
    if (!ok) {
        // A failed refresh keeps the held keys and never moves the anchor; it counts toward
        // the unknown-kid window so a failing endpoint costs one fetch per window.
        last_fetch_failed_ = true;
        refetch_cooldown_until_ = started + std::chrono::seconds(kOidcJwksRefetchCooldownSeconds);
    } else {
        if (resp.status == 200) {
            // An ETag is echoed back in a request header: refuse one with a control character
            // (header injection) or longer than 256 bytes, and revalidate unconditionally.
            etag_.clear();
            const auto etag = resp.headers.find("ETag");
            if (etag != resp.headers.end() && etag->second.size() <= 256) {
                bool clean = true;
                for (unsigned char c : etag->second) {
                    if (c < 0x20 || c == 0x7f) clean = false;
                }
                if (clean) etag_ = etag->second;
            }
        }
        // A 200 and a 304 both (re)state the lifetime. A configured TTL wins; otherwise the
        // advertised max-age (clamped), otherwise 300 s.
        effective_ttl_ = std::chrono::seconds(kJwksMaxTtlSeconds);
        if (configured_ttl_) {
            effective_ttl_ = *configured_ttl_;
        } else {
            const auto cc = resp.headers.find("Cache-Control");
            if (cc != resp.headers.end()) {
                const long max_age = parse_max_age(cc->second);
                if (max_age >= 0) effective_ttl_ = clamp_ttl(std::chrono::seconds(max_age));
            }
        }
        last_fetch_failed_ = false;
        fetched_at_ = started;
        have_keys_ = true;
    }
    in_flight_ = false;
    idle_cv_.notify_all();
    return ok;
}

bool JwksVerifier::held_keys_usable_locked() const {
    if (!have_keys_) return false;
    // Held keys verify until exactly TTL + 300 s after the last successful fetch.
    const auto age = clock_() - fetched_at_;
    if (age < std::chrono::seconds(0)) return false;  // clock moved backwards: not trustworthy
    return age <= effective_ttl_ + std::chrono::seconds(kJwksMaxStaleSeconds);
}

bool JwksVerifier::cooldown_active_locked(std::chrono::steady_clock::time_point now) const {
    // A deadline more than one window ahead can only come from a clock that stepped
    // backwards: treat it as expired rather than wait out an arbitrary span.
    return now < refetch_cooldown_until_ &&
           refetch_cooldown_until_ <= now + std::chrono::seconds(kOidcJwksRefetchCooldownSeconds);
}

bool JwksVerifier::refresh_due_locked(std::chrono::steady_clock::time_point now) const {
    // A clock that moved backwards (negative age) means a refresh is due, never "fresh".
    const auto age = now - fetched_at_;
    if (have_keys_ && age >= std::chrono::seconds(0) && age < effective_ttl_) return false;
    // Whatever the TTL says, an attempt (successful or not) holds off the next TTL-driven
    // refresh for one window. A deadline more than a window ahead (clock stepped back) is over.
    if (now < ttl_window_until_ &&
        ttl_window_until_ <= now + std::chrono::seconds(kOidcJwksRefetchCooldownSeconds)) {
        return false;
    }
    // A refresh already failed inside the current window: do not fetch again per token, with
    // or without a held set (a failing endpoint costs one fetch per window).
    if (last_fetch_failed_ && cooldown_active_locked(now)) return false;
    return true;
}

void JwksVerifier::refresh_keys() {
    Lock lk(mtx_);
    if (in_flight_) {
        wait_idle(lk);
        return;
    }
    fetch_unlocked(lk);
}

std::size_t JwksVerifier::cached_key_count() {
    std::lock_guard<std::mutex> lock(mtx_);
    return have_keys_ ? keys_.size() : 0;
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
    return verify_impl(jwt, /*access_token=*/false);
}

JwtVerification JwksVerifier::verify_access_token_signature_unchecked(const std::string& jwt) {
    return verify_impl(jwt, /*access_token=*/true);
}

JwtVerification JwksVerifier::verify_impl(const std::string& jwt, bool access_token) {
    // C4: the header is attacker-controlled and is read before any key lookup. Every
    // nlohmann accessor that can throw on a type mismatch is guarded below, and this
    // is the backstop for the one that is not: no vendored exception type leaves
    // the verification path, whatever shape the header takes.
    try {
        return verify_impl_unguarded(jwt, access_token);
    } catch (const nlohmann::json::exception&) {
        JwtVerification v;
        v.reason = OidcValidationReason::kInvalidAlg;
        return v;
    }
}

JwtVerification JwksVerifier::verify_impl_unguarded(const std::string& jwt, bool access_token) {
    const auto fail = [](const char* reason) {
        JwtVerification v;
        v.reason = reason;
        return v;
    };

    const auto fail_typ = [&fail]() {
        JwtVerification v = fail(OidcValidationReason::kInvalidAlg);
        v.detail = JwtVerification::kDetailTypNotAccessToken;
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
    if (header.is_discarded() || !header.is_object()) {
        return fail(OidcValidationReason::kInvalidAlg);
    }

    // §12.4 rule 1: read `alg` from the header and check it BEFORE any signature
    // work. An SDK must not let the token select its own verification
    // algorithm, and the discovery document's advertised list cannot widen this
    // either. `find()` plus `is_string()`: `value()` throws on a non-string.
    const auto alg_it = header.find("alg");
    if (alg_it == header.end() || !alg_it->is_string() ||
        alg_it->get<std::string>() != "EdDSA") {
        return fail(OidcValidationReason::kInvalidAlg);
    }
    const auto kid_it = header.find("kid");
    if (kid_it != header.end() && !kid_it->is_string()) {
        return fail(OidcValidationReason::kInvalidAlg);
    }
    const std::string kid = kid_it != header.end() ? kid_it->get<std::string>() : std::string();

    if (access_token) {
        // §10.1 rule 10 (contract 1.68; N14): when `typ` is present it must be
        // `at+jwt`, ASCII case-insensitively, with or without `application/`
        // (RFC 7515 §4.1.9). A non-string `typ` is not "absent" -- fail closed.
        const auto typ_it = header.find("typ");
        if (typ_it != header.end()) {
            if (!typ_it->is_string()) return fail_typ();
            std::string typ = typ_it->get<std::string>();
            for (char& c : typ) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
            }
            static const std::string kPrefix = "application/";
            if (typ.compare(0, kPrefix.size(), kPrefix) == 0) typ.erase(0, kPrefix.size());
            if (typ != "at+jwt") return fail_typ();
        }
        // §10.1 rule 12: a `kid` is REQUIRED and selects the key. No fallback to
        // "the only key in the set" -- the MFA challenge and WebAuthn state tokens
        // carry none. Refused before any key lookup or JWKS fetch.
        if (kid.empty()) {
            JwtVerification v = fail(OidcValidationReason::kUnknownKid);
            v.detail = JwtVerification::kDetailNoKid;
            return v;
        }
    }

    Ed25519Jwk jwk;
    {
        Lock lk(mtx_);
        if (in_flight_) {
            // Nothing usable to answer with: wait for the in-flight fetch. A usable held set
            // answers now, without waiting for it.
            if (!held_keys_usable_locked()) wait_idle(lk);
        } else if (refresh_due_locked(clock_())) {
            fetch_unlocked(lk);
        }
        // Past TTL + 300 s with no successful fetch every token is refused (§12.4 rule 2).
        if (!held_keys_usable_locked()) return fail(OidcValidationReason::kUnknownKid);
        auto it = keys_.find(kid);
        if (it == keys_.end()) {
            // §12.4 rule 2, per WINDOW rather than per token. The first unknown `kid` costs one
            // re-fetch and opens the cooldown; a further unknown `kid` inside it re-consults
            // the cached set with no network call. A fetch already in flight is waited for
            // (this token has no key without it) and its result used, not repeated.
            const auto now = clock_();
            if (in_flight_) {
                wait_idle(lk);
            } else if (!cooldown_active_locked(now)) {
                refetch_cooldown_until_ =
                    now + std::chrono::seconds(kOidcJwksRefetchCooldownSeconds);
                fetch_unlocked(lk);  // a failure keeps the held set and counts toward the window
            }
            it = keys_.find(kid);
            // Covers "no kid in the header at all" as well as "no key matches it", which
            // §12.3 rule 3 folds into one code deliberately.
            if (!held_keys_usable_locked() || it == keys_.end()) {
                return fail(OidcValidationReason::kUnknownKid);
            }
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