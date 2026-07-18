// §2 Error taxonomy — exactly three top-level error types, exposed as an
// exception hierarchy rooted at AxiamError.
#pragma once

#include <optional>
#include <stdexcept>
#include <string>

namespace axiam {

/// Base class for every error the SDK raises. Never carries raw token material.
class AxiamError : public std::runtime_error {
public:
    explicit AxiamError(const std::string& message) : std::runtime_error(message) {}
};

/// Authentication failure: wrong credentials, expired session, MFA failure,
/// or a 401 on the refresh call itself. Maps HTTP 401.
class AuthError : public AxiamError {
public:
    explicit AuthError(const std::string& message) : AxiamError(message) {}
};

/// Authorization failure: authenticated but not permitted. Maps HTTP 403 / 409.
/// Carries the denied action / resource id when the server provides them.
class AuthzError : public AxiamError {
public:
    explicit AuthzError(const std::string& message) : AxiamError(message) {}

    AuthzError(const std::string& message, std::optional<std::string> action,
               std::optional<std::string> resource_id)
        : AxiamError(message),
          action_(std::move(action)),
          resource_id_(std::move(resource_id)) {}

    const std::optional<std::string>& action() const noexcept { return action_; }
    const std::optional<std::string>& resource_id() const noexcept { return resource_id_; }

private:
    std::optional<std::string> action_;
    std::optional<std::string> resource_id_;
};

/// Transport-level failure: connection refused, timeout, TLS error, DNS failure,
/// malformed request (400), rate-limit (408/429) or server error (5xx).
/// Carries the underlying transport cause string.
class NetworkError : public AxiamError {
public:
    explicit NetworkError(const std::string& message)
        : AxiamError(message), cause_(message) {}

    NetworkError(const std::string& message, std::string cause)
        : AxiamError(message), cause_(std::move(cause)) {}

    /// The underlying OS / transport error that triggered this failure.
    const std::string& cause() const noexcept { return cause_; }

private:
    std::string cause_;
};

}  // namespace axiam
