// axiam::Client — the SDK's REST surface. Built via a fluent builder that
// enforces the §5 tenant-context requirement, wires strict TLS (§6) and optional
// mTLS (§6.1), captures/echoes CSRF (§3), persists cookies (§4), injects the
// tenant header on every request (§5), and performs single-flight token
// refresh (§9). Method names are snake_case per §1.
#pragma once

#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "axiam/errors.hpp"
#include "axiam/jwks.hpp"
#include "axiam/transport.hpp"
#include "axiam/types.hpp"

namespace axiam {

class Client {
public:
    class Builder {
    public:
        Builder& base_url(std::string url);
        Builder& tenant_slug(std::string slug);
        Builder& tenant_id(std::string id);
        Builder& org_slug(std::string slug);
        Builder& org_id(std::string id);

        /// §6: add a custom CA (PEM) to the trust chain. The ONLY TLS-trust
        /// escape hatch; never disables verification.
        Builder& with_custom_ca(std::string ca_pem);

        /// §6.1: present a client identity certificate (PEM chain + PEM key) for
        /// mutual TLS. Strict server verification is unchanged.
        Builder& with_client_cert(std::string cert_pem, std::string key_pem);

        Builder& connect_timeout(std::chrono::milliseconds ms);
        Builder& request_timeout(std::chrono::milliseconds ms);

        /// Override the HTTP transport (test seam). When unset, build() creates
        /// the default libcurl transport from the configured TLS material.
        Builder& transport(Transport t);

        /// Validates required fields and constructs the client.
        /// @throws std::invalid_argument if base_url is empty.
        /// @throws AuthError if neither tenant_slug nor tenant_id was provided.
        Client build();

    private:
        friend class Client;
        std::string base_url_;
        std::optional<std::string> tenant_slug_;
        std::optional<std::string> tenant_id_;
        std::optional<std::string> org_slug_;
        std::optional<std::string> org_id_;
        std::string custom_ca_pem_;
        std::string client_cert_pem_;
        std::string client_key_pem_;
        std::chrono::milliseconds connect_timeout_{10000};
        std::chrono::milliseconds request_timeout_{30000};
        Transport transport_;  // empty => default libcurl
    };

    static Builder builder();

    // ---- §1 canonical operations (snake_case) ----
    LoginResult login(const std::string& username_or_email, const std::string& password);
    LoginResult verify_mfa(const std::string& challenge_token, const std::string& totp_code);
    TokenPair refresh();
    void logout();
    AccessDecision check_access(const std::string& action, const std::string& resource_id,
                                std::optional<std::string> scope = std::nullopt,
                                std::optional<std::string> subject_id = std::nullopt);
    AccessDecision can(const std::string& action, const std::string& resource_id,
                       std::optional<std::string> scope = std::nullopt,
                       std::optional<std::string> subject_id = std::nullopt);
    std::vector<AccessDecision> batch_check(const std::vector<AccessCheck>& checks);

    /// §6.1 device / service-account authentication via the configured mTLS
    /// client certificate (POST /api/v1/auth/device).
    DeviceAuth authenticate_device();

    // ---- Accepted per-language async twins (§1, C++ row: std::future) ----
    std::future<LoginResult> login_async(std::string username_or_email, std::string password);
    std::future<TokenPair> refresh_async();
    std::future<AccessDecision> check_access_async(std::string action, std::string resource_id,
                                                   std::optional<std::string> scope = std::nullopt,
                                                   std::optional<std::string> subject_id = std::nullopt);
    std::future<std::vector<AccessDecision>> batch_check_async(std::vector<AccessCheck> checks);

    // ---- Introspection (used by tests / middleware) ----
    /// Number of times a network refresh call was actually issued (§9 assertion).
    int refresh_call_count() const;
    /// Currently-stored CSRF token, if any (§3).
    std::optional<std::string> csrf_token() const;
    /// Whether a session has been established (login/verify_mfa succeeded).
    bool has_session() const;
    /// Shared JWKS verifier bound to this client's transport + base URL.
    JwksVerifier& jwks();
    /// Tenant identifier injected as X-Tenant-ID on every request (§5).
    const std::string& tenant_header() const;

private:
    struct Impl;
    std::shared_ptr<Impl> p_;
    explicit Client(std::shared_ptr<Impl> impl);
};

}  // namespace axiam
