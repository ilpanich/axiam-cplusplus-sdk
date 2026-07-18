// Public domain value types returned/accepted by axiam::Client. Mirrors the
// relevant openapi.json schemas (auth + authz).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "axiam/sensitive.hpp"

namespace axiam {

/// Subset of LoginUserInfo returned on a successful authentication.
struct UserInfo {
    std::string id;
    std::string username;
    std::string email;
    std::string tenant_id;
    std::optional<std::string> org_slug;
    std::optional<std::string> tenant_slug;
};

/// Result of login / verify_mfa. `mfa_required` distinguishes the 202 challenge
/// branch (challenge_token + available_methods populated) from the 200 success
/// branch (user + session_id + expires_in populated).
struct LoginResult {
    bool mfa_required = false;

    // Success branch (HTTP 200 LoginSuccessResponse).
    std::optional<UserInfo> user;
    std::string session_id;
    std::int64_t expires_in = 0;

    // MFA-required branch (HTTP 202 MfaRequiredResponse).
    std::string challenge_token;
    std::vector<std::string> available_methods;
};

/// Result of a token refresh (§9). Access/refresh tokens themselves live in the
/// httpOnly cookie jar; this carries the server-reported access-token lifetime.
struct TokenPair {
    std::int64_t expires_in = 0;
};

/// mTLS device authentication result (POST /api/v1/auth/device). The bearer
/// access token is secret material and is wrapped per §7.
struct DeviceAuth {
    Sensitive<std::string> access_token;
    std::string token_type;
    std::int64_t expires_in = 0;
};

/// A single access-check request (CheckAccessBody). Argument order per §1:
/// action before resource.
struct AccessCheck {
    std::string action;
    std::string resource_id;
    std::optional<std::string> scope;
    std::optional<std::string> subject_id;
};

/// Result of an access check (CheckAccessResponse).
struct AccessDecision {
    bool allowed = false;
    std::optional<std::string> reason;
};

}  // namespace axiam
