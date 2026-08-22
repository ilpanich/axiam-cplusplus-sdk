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
    /// Short-lived MFA challenge token. §7 classes this as secret material, so it
    /// is wrapped: it never appears in a log line, stream insertion or to_string().
    /// Pass it straight back to Client::verify_mfa(), which takes the wrapper.
    Sensitive<std::string> challenge_token;
    std::vector<std::string> available_methods;

    // MFA-setup-required branch (§25.2 rule 1).
    /// The tenant requires MFA and this account has none, so the login stopped
    /// short of a session. ADDITIVE rather than breaking, because this type is a
    /// flags struct: an existing caller that checks `mfa_required` and otherwise
    /// assumes success still compiles, and now has a third state it can learn
    /// about rather than a fourth failure mode it cannot name.
    bool mfa_setup_required = false;
    /// The credential for mfa_setup_enroll() and mfa_setup_confirm(). There is
    /// no session yet — this token IS the credential — so §7 wraps it exactly as
    /// it wraps the MFA challenge token above.
    Sensitive<std::string> setup_token;
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

/// The three decision reason codes the server currently emits (§11 rule 9).
///
/// Deliberately string constants and not an `enum class`: §11 rule 9 requires an
/// unrecognised code be surfaced *verbatim*, so a server that adds a fourth code
/// must not become a decode failure in every deployed client. Compare
/// `AccessDecision::reason_code` against these and let anything else fall
/// through to a default branch.
///
/// (A struct rather than a namespace so that `ReasonCode::kAllowed` still
/// resolves in a scope that happens to hold a local named `reason_code`.)
struct ReasonCode {
    /// An allow grant matched and no deny did.
    static constexpr const char* kAllowed = "allowed";
    /// Nothing matched — default deny. Tells the user to *ask an admin for access*.
    static constexpr const char* kNoGrant = "no_grant";
    /// An explicit deny rule matched and overrode any allow. *An admin already decided.*
    static constexpr const char* kDeniedByRule = "denied_by_rule";
};

/// Result of an access check (CheckAccessResponse).
struct AccessDecision {
    bool allowed = false;
    /// Human-readable prose, when the server sends any.
    std::optional<std::string> reason;
    /// §11 rule 9 machine-readable decision reason. `std::nullopt` when the
    /// server predates the clause — absence, not an error. One of the
    /// `reason_code::` constants, or an unrecognised code passed through
    /// untouched. The allow/deny outcome is carried by `allowed` alone; never
    /// re-derive it from this field.
    std::optional<std::string> reason_code;
};

}  // namespace axiam
