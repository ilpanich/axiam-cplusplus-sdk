#include "axiam/authenticator.hpp"

#include <nlohmann/json.hpp>

namespace axiam {

using json = nlohmann::json;

namespace {

std::int64_t system_now_seconds() {
    return static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count());
}

/// Read an integral NumericDate claim. Distinguishes "absent" from "present but
/// not usable as an integer" so the caller can fail closed on either.
enum class ClaimRead { kOk, kAbsent, kMalformed };

ClaimRead read_numeric_claim(const json& payload, const char* name, std::int64_t& out) {
    if (!payload.contains(name)) return ClaimRead::kAbsent;
    const json& v = payload.at(name);
    if (v.is_number_integer() || v.is_number_unsigned()) {
        out = v.get<std::int64_t>();
        return ClaimRead::kOk;
    }
    // A float NumericDate is legal per RFC 7519; truncate toward the safe side.
    if (v.is_number_float()) {
        out = static_cast<std::int64_t>(v.get<double>());
        return ClaimRead::kOk;
    }
    return ClaimRead::kMalformed;
}

bool audience_contains(const json& payload, const std::string& expected) {
    if (!payload.contains("aud")) return false;
    const json& aud = payload.at("aud");
    if (aud.is_string()) return aud.get<std::string>() == expected;
    if (aud.is_array()) {
        for (const auto& entry : aud) {
            if (entry.is_string() && entry.get<std::string>() == expected) return true;
        }
    }
    return false;
}

std::string trim(const std::string& s) {
    const auto first = s.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    const auto last = s.find_last_not_of(" \t");
    return s.substr(first, last - first + 1);
}

}  // namespace

TokenAuthenticator::TokenAuthenticator(JwksVerifier& jwks, std::string expected_tenant_id,
                                       AuthenticatorOptions options)
    : jwks_(&jwks), tenant_id_(std::move(expected_tenant_id)), options_(std::move(options)) {
    if (tenant_id_.empty()) {
        throw std::invalid_argument(
            "TokenAuthenticator: expected_tenant_id must not be empty (an empty "
            "expectation would disable the cross-tenant check)");
    }
    if (options_.clock_skew.count() < 0) {
        throw std::invalid_argument("TokenAuthenticator: clock_skew must not be negative");
    }
}

AxiamUser TokenAuthenticator::authenticate(const std::string& token) const {
    if (token.empty()) {
        throw AuthError("authentication_failed: no token presented");
    }

    // (1)(2) signature + alg. The expert primitive stops here; everything below
    // is the part a guard must not be left to hand-add.
    const auto verified = jwks_->verify_signature_only_unchecked(token);
    if (!verified.has_value()) {
        throw AuthError("authentication_failed: token signature is not valid");
    }

    const auto payload = json::parse(verified->payload_json, nullptr, /*allow_exceptions=*/false);
    if (payload.is_discarded() || !payload.is_object()) {
        throw AuthError("authentication_failed: token payload is not a JSON object");
    }

    const std::int64_t now = options_.now ? options_.now() : system_now_seconds();
    const std::int64_t skew = static_cast<std::int64_t>(options_.clock_skew.count());

    // (3) exp — required. A token without a usable exp never expires, which is
    // exactly what the 15-minute access-token bound exists to prevent.
    std::int64_t exp = 0;
    switch (read_numeric_claim(payload, "exp", exp)) {
        case ClaimRead::kOk:
            break;
        case ClaimRead::kAbsent:
            throw AuthError("authentication_failed: token has no exp claim");
        case ClaimRead::kMalformed:
            throw AuthError("authentication_failed: token exp claim is not a number");
    }
    if (now > exp + skew) {
        throw AuthError("authentication_failed: token has expired");
    }

    // (4) nbf — optional, but must be well formed and reached when present.
    std::int64_t nbf = 0;
    switch (read_numeric_claim(payload, "nbf", nbf)) {
        case ClaimRead::kOk:
            if (now + skew < nbf) {
                throw AuthError("authentication_failed: token is not yet valid");
            }
            break;
        case ClaimRead::kAbsent:
            break;
        case ClaimRead::kMalformed:
            throw AuthError("authentication_failed: token nbf claim is not a number");
    }

    // (5) tenant binding — the JWKS endpoint is org-wide, so a good signature
    // does not imply the token belongs to the tenant this server serves.
    if (!payload.contains("tenant_id") || !payload.at("tenant_id").is_string()) {
        throw AuthError("authentication_failed: token has no tenant_id claim");
    }
    const std::string token_tenant = payload.at("tenant_id").get<std::string>();
    if (token_tenant.empty() || token_tenant != tenant_id_) {
        throw AuthError("authentication_failed: token tenant_id does not match the configured tenant");
    }

    // (6) optional issuer / audience pinning.
    if (options_.expected_issuer.has_value()) {
        if (!payload.contains("iss") || !payload.at("iss").is_string() ||
            payload.at("iss").get<std::string>() != *options_.expected_issuer) {
            throw AuthError("authentication_failed: token iss claim does not match the expected issuer");
        }
    }
    if (options_.expected_audience.has_value() &&
        !audience_contains(payload, *options_.expected_audience)) {
        throw AuthError("authentication_failed: token aud claim does not include the expected audience");
    }

    AxiamUser user;
    user.tenant_id = token_tenant;
    if (payload.contains("sub") && payload.at("sub").is_string()) {
        user.user_id = payload.at("sub").get<std::string>();
    }
    if (payload.contains("roles") && payload.at("roles").is_array()) {
        for (const auto& role : payload.at("roles")) {
            if (role.is_string()) user.roles.push_back(role.get<std::string>());
        }
    }
    return user;
}

std::optional<AxiamUser> TokenAuthenticator::try_authenticate(const std::string& token) const {
    try {
        return authenticate(token);
    } catch (const AxiamError&) {
        return std::nullopt;
    }
}

std::optional<std::string> TokenAuthenticator::bearer_from_authorization(
    const std::string& header_value) {
    const std::string value = trim(header_value);
    const std::string prefix = "bearer ";
    if (value.size() <= prefix.size()) return std::nullopt;
    std::string scheme = value.substr(0, prefix.size());
    for (char& c : scheme) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    if (scheme != prefix) return std::nullopt;
    const std::string token = trim(value.substr(prefix.size()));
    if (token.empty()) return std::nullopt;
    return token;
}

std::optional<std::string> TokenAuthenticator::token_from_cookie_header(
    const std::string& cookie_header) {
    const std::string name = "axiam_access";
    std::size_t pos = 0;
    while (pos <= cookie_header.size()) {
        const auto end = cookie_header.find(';', pos);
        const std::string pair =
            trim(cookie_header.substr(pos, end == std::string::npos ? std::string::npos : end - pos));
        const auto eq = pair.find('=');
        if (eq != std::string::npos && pair.substr(0, eq) == name) {
            const std::string value = trim(pair.substr(eq + 1));
            if (!value.empty()) return value;
            return std::nullopt;
        }
        if (end == std::string::npos) break;
        pos = end + 1;
    }
    return std::nullopt;
}

}  // namespace axiam
