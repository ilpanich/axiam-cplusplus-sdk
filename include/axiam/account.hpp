// axiam account lifecycle and MFA enrolment — CONTRACT.md §25.
//
// The calls a user makes about their own account, none of which is
// administration: voluntary and forced TOTP enrolment, email verification, and
// the password-reset triple. All nine have been live server surface since before
// §1 was written; what they lacked was an SDK, which is exactly the divergence
// §1 exists to prevent, arrived at through omission.
//
// SIX OF THE NINE ARE DELIBERATELY UNAUTHENTICATED. A user who cannot log in is
// the entire audience for a password reset, and a user whose email is unverified
// may have no session at all.
//
// WHERE THE TENANT GOES. `verify_email`, `resend_verification` and
// `confirm_password_reset` take it as a BODY field — these are not `/oauth2`
// endpoints, so §12.1 rule 2's query-parameter convention does not reach them.
// `request_password_reset` accepts the workspace in slug form as well, like
// login.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "axiam/sensitive.hpp"

namespace axiam {

/// A TOTP factor offered but not yet active (§25.1).
///
/// BOTH HALVES ARE SENSITIVE, AND THE SECOND ONE IS WHY. The `otpauth://` URI
/// CONTAINS the secret: wrapping the bare secret and leaving the URI a plain
/// string has wrapped nothing, because the URI is the field that actually gets
/// logged — it is the one the caller passes to a QR renderer (§25.3).
struct MfaEnrollment {
    /// The shared TOTP secret. Anyone holding it can generate valid codes
    /// forever.
    Sensitive<std::string> secret_base32;
    /// `otpauth://totp/…?secret=<secret_base32>` — the string an app scans.
    Sensitive<std::string> totp_uri;
};

/// The OPAQUE policy for the account a reset token belongs to (§25.1).
struct PasswordResetContext {
    /// The tenant's §23 parameters as JSON TEXT when it has OPAQUE enabled, and
    /// absent when it does not — in which case the plaintext path is allowed.
    ///
    /// Forwarded to the §23 helpers untouched: this SDK does not model, validate
    /// or re-encode the block.
    std::optional<std::string> opaque_json;
};

/// Arguments to Client::request_password_reset (§25.1).
///
/// The workspace members are all optional: left unset, they are filled from the
/// client's own configured identity, which is what almost every caller wants.
struct PasswordResetRequest {
    std::string email;  ///< The address to send the reset mail to. Required.
    std::optional<std::string> org_slug;
    std::optional<std::string> tenant_id;
    std::optional<std::string> tenant_slug;
};

/// Arguments to Client::confirm_password_reset (§25.1).
struct PasswordResetConfirmation {
    Sensitive<std::string> token;         ///< The single-use token from the reset mail.
    Sensitive<std::string> new_password;  ///< The replacement password.
    /// A BODY field, not a query parameter; see the file header.
    std::string tenant_id;
    /// The §23 registration record as JSON text, spliced into the request body
    /// verbatim exactly as the §23 helpers produced it. Absent on the plaintext
    /// path.
    std::optional<std::string> opaque_json;
};

}  // namespace axiam
