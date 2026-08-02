#include "axiam/webhook.hpp"

#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <cstddef>
#include <limits>
#include <vector>

namespace axiam {
namespace webhook {

namespace {

constexpr std::size_t kMacLen = 32;  // SHA-256

std::int64_t system_now_seconds() {
    return static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count());
}

std::string trim(const std::string& s) {
    const auto first = s.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

/// Strict non-negative decimal parse. No sign, no whitespace, no overflow.
bool parse_unix_seconds(const std::string& text, std::int64_t& out) {
    if (text.empty()) return false;
    std::int64_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return false;
        const int digit = c - '0';
        if (value > (std::numeric_limits<std::int64_t>::max() - digit) / 10) return false;
        value = value * 10 + digit;
    }
    out = value;
    return true;
}

/// Strict hex decode (either case). Fails closed on odd length or any non-hex
/// character, so a corrupted `v1` can never be silently treated as a short match.
bool hex_decode(const std::string& hex, std::vector<unsigned char>& out) {
    if (hex.empty() || (hex.size() % 2) != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return true;
}

/// Parsed `t=...,v1=...` header. Unknown keys and future schemes are ignored for
/// forward compatibility; a missing `v1` is a failure, never a pass.
struct ParsedHeader {
    bool ok = false;
    VerifyError error = VerifyError::kNone;
    std::string timestamp_text;
    std::vector<std::string> v1_hex;
};

ParsedHeader parse_signature_header(const std::string& header) {
    ParsedHeader parsed;
    int t_count = 0;
    std::size_t pos = 0;
    bool saw_element = false;

    while (pos <= header.size()) {
        const auto end = header.find(',', pos);
        const std::string element = trim(
            header.substr(pos, end == std::string::npos ? std::string::npos : end - pos));
        if (!element.empty()) {
            saw_element = true;
            const auto eq = element.find('=');
            if (eq == std::string::npos) {
                parsed.error = VerifyError::kMalformedHeader;
                return parsed;
            }
            const std::string key = trim(element.substr(0, eq));
            const std::string value = trim(element.substr(eq + 1));
            if (key == "t") {
                ++t_count;
                parsed.timestamp_text = value;
            } else if (key == "v1") {
                if (value.empty()) {
                    parsed.error = VerifyError::kMalformedHeader;
                    return parsed;
                }
                parsed.v1_hex.push_back(value);
            }
            // Any other key (a future v2, an unknown attribute) is ignored.
        }
        if (end == std::string::npos) break;
        pos = end + 1;
    }

    if (!saw_element || t_count != 1) {
        parsed.error = VerifyError::kMalformedHeader;
        return parsed;
    }
    if (parsed.v1_hex.empty()) {
        // "Nothing to verify" is never success.
        parsed.error = VerifyError::kMissingSignature;
        return parsed;
    }
    parsed.ok = true;
    return parsed;
}

Result fail(VerifyError error) {
    Result r;
    r.ok = false;
    r.error = error;
    return r;
}

}  // namespace

const char* to_string(VerifyError error) noexcept {
    switch (error) {
        case VerifyError::kNone:
            return "ok";
        case VerifyError::kEmptySecret:
            return "webhook_verify_failed: no signing secret configured";
        case VerifyError::kMalformedHeader:
            return "webhook_verify_failed: malformed X-Axiam-Signature header";
        case VerifyError::kMissingSignature:
            return "webhook_verify_failed: X-Axiam-Signature carried no v1 signature";
        case VerifyError::kMalformedTimestamp:
            return "webhook_verify_failed: X-Axiam-Signature timestamp is not a unix-seconds integer";
        case VerifyError::kTimestampHeaderMismatch:
            return "webhook_verify_failed: X-Axiam-Timestamp does not match the signed timestamp";
        case VerifyError::kSignatureMismatch:
            return "webhook_verify_failed: signature does not match";
        case VerifyError::kTimestampOutOfTolerance:
            return "webhook_verify_failed: timestamp is outside the freshness window";
    }
    return "webhook_verify_failed";
}

Result verify(const Sensitive<std::string>& secret, const std::string& signature_header,
              const std::string& body, const Options& options) {
    const std::string& secret_bytes = detail::reveal(secret);
    if (secret_bytes.empty()) return fail(VerifyError::kEmptySecret);
    if (options.tolerance.count() < 0) return fail(VerifyError::kTimestampOutOfTolerance);

    // 1. Parse the header. Exactly one `t`, at least one `v1`.
    const ParsedHeader parsed = parse_signature_header(signature_header);
    if (!parsed.ok) return fail(parsed.error);

    // 2. `t` must be a plain non-negative decimal integer.
    std::int64_t timestamp = 0;
    if (!parse_unix_seconds(parsed.timestamp_text, timestamp)) {
        return fail(VerifyError::kMalformedTimestamp);
    }
    // The redundant header, when read, must agree with the value under the MAC.
    if (options.timestamp_header.has_value() &&
        trim(*options.timestamp_header) != parsed.timestamp_text) {
        return fail(VerifyError::kTimestampHeaderMismatch);
    }

    // 3. Recompute HMAC-SHA256(secret, "<t>.<raw_body>").
    const std::string signed_payload = parsed.timestamp_text + "." + body;
    unsigned char expected[EVP_MAX_MD_SIZE];
    unsigned int expected_len = 0;
    if (HMAC(EVP_sha256(), secret_bytes.data(), static_cast<int>(secret_bytes.size()),
             reinterpret_cast<const unsigned char*>(signed_payload.data()), signed_payload.size(),
             expected, &expected_len) == nullptr ||
        expected_len != kMacLen) {
        return fail(VerifyError::kSignatureMismatch);
    }

    // 4. Constant-time compare over the DECODED bytes, against every candidate.
    //    No early return: the loop always runs to completion and the result is
    //    accumulated, so neither the matching candidate's position nor the first
    //    differing byte is observable in the timing.
    volatile unsigned int matched = 0;
    for (const std::string& candidate_hex : parsed.v1_hex) {
        std::vector<unsigned char> candidate;
        if (!hex_decode(candidate_hex, candidate)) continue;  // fail closed on bad hex
        if (candidate.size() != kMacLen) continue;
        const int diff = CRYPTO_memcmp(candidate.data(), expected, kMacLen);
        matched = matched | static_cast<unsigned int>(diff == 0 ? 1u : 0u);
    }
    OPENSSL_cleanse(expected, sizeof(expected));
    if (matched == 0u) return fail(VerifyError::kSignatureMismatch);

    // 5. Two-sided freshness: future-dated timestamps are rejected too.
    const std::int64_t now = options.now ? options.now() : system_now_seconds();
    const std::int64_t tolerance = static_cast<std::int64_t>(options.tolerance.count());
    const std::int64_t delta = now - timestamp;
    if (delta > tolerance || delta < -tolerance) {
        return fail(VerifyError::kTimestampOutOfTolerance);
    }

    Result result;
    result.ok = true;
    result.error = VerifyError::kNone;
    result.event.timestamp = timestamp;
    result.event.event_type = options.event_type;
    result.event.delivery_id = options.delivery_id;
    result.event.body = body;
    return result;
}

Result verify(const std::string& secret, const std::string& signature_header,
              const std::string& body, const Options& options) {
    return verify(Sensitive<std::string>(secret), signature_header, body, options);
}

Event verify_or_throw(const Sensitive<std::string>& secret, const std::string& signature_header,
                      const std::string& body, const Options& options) {
    Result result = verify(secret, signature_header, body, options);
    if (!result.ok) {
        throw VerifyException(result.error, to_string(result.error));
    }
    return result.event;
}

}  // namespace webhook
}  // namespace axiam
