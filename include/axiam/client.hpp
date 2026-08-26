// axiam::Client — the SDK's REST surface. Built via a fluent builder that
// enforces the §5 tenant-context requirement, wires strict TLS (§6) and optional
// mTLS (§6.1), captures/echoes CSRF (§3), persists cookies (§4), injects the
// tenant header on every request (§5), and performs single-flight token
// refresh (§9). Method names are snake_case per §1.
#pragma once

#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "axiam/account.hpp"
#include "axiam/errors.hpp"
#include "axiam/jwks.hpp"
#include "axiam/oidc.hpp"
#include "axiam/opaque.hpp"
#include "axiam/telemetry.hpp"
#include "axiam/transport.hpp"
#include "axiam/types.hpp"
#include "axiam/uma.hpp"
#include "axiam/webauthn.hpp"

namespace axiam::management {
// Forward declaration only: including <axiam/management.hpp> here would pull 3000 lines
// of generated models into every translation unit that merely wants a Client.
class ManagementApi;
}  // namespace axiam::management

namespace axiam {

class Client {
public:
    class Builder {
    public:
        /// Server base URL. MUST be `https://` (§6); a plaintext `http://` base
        /// is rejected by build() unless the host is a loopback development host
        /// (`localhost`, `127.0.0.1`, `::1`).
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

        /// How many requests this client may have in flight at once (default
        /// 16). The default transport keeps one libcurl handle — and one hot
        /// connection — per in-flight request; callers beyond the cap wait for
        /// a handle rather than opening unbounded connections to the server.
        ///
        /// Before this existed the transport served every caller through a
        /// single mutex-guarded handle, so a Client shared across threads had
        /// a p95 made of lock queueing rather than of server time. Set this to
        /// your application's real concurrency. Ignored when a custom
        /// transport() is supplied.
        Builder& max_concurrent_requests(unsigned n);

        /// Override the HTTP transport (test seam). When unset, build() creates
        /// the default libcurl transport from the configured TLS material.
        Builder& transport(Transport t);

        /// §16: enable or disable the bounded read-only retry policy. ON BY
        /// DEFAULT.
        ///
        /// There is deliberately no builder method for the attempt cap, the base
        /// delay or the delay cap: §16.1 permits *lowering* the budget or
        /// disabling it, never raising it, and a caller who can raise them turns
        /// one client into the herd a backoff exists to prevent. Pass `false` for
        /// exactly one attempt — the right choice for a caller who owns their own
        /// retry layer and knows their own deadline.
        Builder& retry_enabled(bool enabled);

        /// §17: enable the client-side decision memo with a TTL. DISABLED BY
        /// DEFAULT, and zero means disabled — not "cache for zero milliseconds".
        ///
        /// A TTL above 5 s is CLAMPED to 5 s rather than rejected (§17.1 rule 2),
        /// and the clamp is announced through the §19 `ConfigClampedEvent`.
        ///
        /// READ-YOUR-OWN-WRITES IS NOT GUARANTEED. The staleness bound is the TTL
        /// in both directions: a grant revoked on the server can still read as
        /// allowed for up to the TTL, and a grant just *added* can still read as
        /// denied for up to the TTL. An admin UI that grants a role and
        /// immediately re-checks is the case that breaks, and it breaks silently.
        /// Switch this on having read that, not because it looks like an easy win.
        Builder& decision_memo_ttl(std::chrono::milliseconds ttl);

        /// §12: the relying party's `client_id`. Required by every §12 / §14 /
        /// §15 operation that talks to an `/oauth2` endpoint.
        ///
        /// CONFIGURATION rather than a per-call argument, and §12.1 is explicit
        /// about why: §12.4 rule 4 compares an ID token's `aud` against the same
        /// value, and two sources could disagree. An operation called on a
        /// client with none throws with **no wire call** — a missing client
        /// registration is a deployment mistake, not an authentication outcome.
        Builder& oidc_client_id(std::string id);

        /// §12: the relying party's `client_secret`, sent as `client_secret_post`
        /// — never as HTTP Basic, which the server does not document (§12.1
        /// rule 3).
        ///
        /// OPTIONAL. A public client omits it, and `oidc_exchange` /
        /// `oidc_refresh` then send no `client_secret` field at all rather than
        /// an empty one. `introspect`, `revoke` and `token_exchange` are
        /// confidential-only (§12.1 rule 4, §15.1) and refuse client-side
        /// without it.
        Builder& oidc_client_secret(std::string secret);

        /// §12.3 rule 6: discovery-document cache TTL. Default and FLOOR 300 s —
        /// a smaller value is raised to it, not rejected, because an SDK that
        /// honoured 1 s would turn the cache into a per-request fetch.
        Builder& oidc_discovery_ttl(std::chrono::seconds ttl);

        /// §12.4 rule 5: permitted clock skew for the `exp` / `iat` / `nbf`
        /// checks. Default 60 s, which is also the CEILING: a larger value is
        /// clamped DOWN rather than rejected, and a negative one becomes zero.
        /// There is no way to widen it past the contract and no "skip the time
        /// checks" mode.
        Builder& oidc_clock_skew(std::chrono::seconds skew);

        /// §19: install a telemetry sink. Invoked on the calling thread, so it
        /// must not block; buffering is the caller's job (§19.2 rule 4). A hook
        /// that throws cannot fail the operation that fired it.
        Builder& telemetry_hook(TelemetryHook hook);

        /// Validates required fields and constructs the client.
        /// @throws std::invalid_argument if base_url is empty or is not an
        ///         https:// URL (loopback hosts excepted, §6).
        /// @throws AuthError if neither tenant_slug nor tenant_id was provided.
        Client build();

    private:
        friend class Client;
        std::string base_url_;
        std::optional<std::string> tenant_slug_;
        std::optional<std::string> tenant_id_;
        std::optional<std::string> org_slug_;
        std::optional<std::string> org_id_;
        unsigned max_concurrent_requests_ = 16;
        std::string custom_ca_pem_;
        std::string client_cert_pem_;
        std::string client_key_pem_;
        std::chrono::milliseconds connect_timeout_{10000};
        std::chrono::milliseconds request_timeout_{30000};
        Transport transport_;  // empty => default libcurl
        bool retry_enabled_ = true;  // §16.1: the switch MUST default to on
        // Stored UNCLAMPED, so the §19 config_clamped event can report what the
        // caller actually asked for rather than the value it was turned into.
        std::chrono::milliseconds decision_memo_ttl_{0};
        TelemetryHook telemetry_hook_;
        std::optional<std::string> oidc_client_id_;
        std::optional<std::string> oidc_client_secret_;
        std::chrono::seconds oidc_discovery_ttl_{kOidcDiscoveryTtlFloorSeconds};
        std::chrono::seconds oidc_clock_skew_{kOidcMaxClockSkewSeconds};
    };

    static Builder builder();

    // ---- §1 canonical operations (snake_case) ----
    LoginResult login(const std::string& username_or_email, const std::string& password);
    /// Complete an MFA challenge. Takes the wrapped token straight from
    /// LoginResult::challenge_token (§7).
    LoginResult verify_mfa(const Sensitive<std::string>& challenge_token,
                           const std::string& totp_code);
    /// Overload for a challenge token obtained out of band (e.g. relayed by a
    /// front end). Prefer the Sensitive overload.
    LoginResult verify_mfa(const std::string& challenge_token, const std::string& totp_code);

    // ---- §23 OPAQUE, RFC 9807 ----

    /// `POST /api/v1/auth/opaque/login/start` then `/finish` — OPAQUE login
    /// (§23).
    ///
    /// A sibling of \ref login, not a replacement. It takes the same arguments
    /// and returns the same LoginResult, MFA branch included, so an application
    /// can switch a tenant to OPAQUE without touching its own code (§23.1).
    ///
    /// **What this does that \ref login does not.** The password never leaves
    /// this process. What crosses the wire is a blinded group element and a MAC,
    /// neither useful without the account's registration record **and** the
    /// tenant's OPRF seed — so a TLS-terminating proxy, an accidentally verbose
    /// request log, or a heap dump on the server cannot capture a plaintext
    /// password, because the server never has one. It also means a stolen record
    /// database is not offline-crackable on its own, which is the pre-computation
    /// resistance SRP could not offer. It does **not** protect against a
    /// compromised AXIAM server.
    ///
    /// **This SDK no longer needs OpenSSL 3.2.** The SRP client refused an
    /// `argon2id` tenant on an older libcrypto, because Argon2id arrives as an
    /// `EVP_KDF` only in 3.2 — so AXIAM's *default* KDF was unreachable and
    /// operators had to weaken the tenant to `pbkdf2_sha256`. Key stretching now
    /// happens inside `libaxiam_opaque_ffi`, so the only remaining condition is
    /// having that library, which \ref opaque_available reports.
    ///
    /// **One round trip, and no server-proof step.** SRP had to guess a group
    /// before the server named one and restart the exchange if it guessed wrong;
    /// `KE1` does not depend on the key-stretching function. And where the old
    /// §23.3 rule 6 had to mandate an `M2` check in capitals, RFC 9807's AKE
    /// authenticates the server during the handshake, so opening `KE2` *is* the
    /// proof that it holds the record.
    ///
    /// **Cost.** Runs the tenant's key-stretching function: Argon2id at 19 MiB
    /// and t=2 by default, tens to hundreds of milliseconds of CPU plus that
    /// memory, per attempt. That cost is the point — it is what makes a stolen
    /// record expensive to attack even by someone holding the OPRF seed. It is
    /// synchronous and blocking.
    ///
    /// **A failed exchange under `opaque_mode: optional` falls back to \ref
    /// login, here, once** (§23.4 rule 7, contract 1.29). `login/start` reports
    /// the tenant's mode, and under `optional` an account with no registration
    /// record is the ordinary case rather than an error: every account has none
    /// the moment an operator enables OPAQUE, and they acquire one only as they
    /// next set a password. So when the envelope does not open and the tenant
    /// said `optional`, this method retries the same credentials over
    /// `POST /api/v1/auth/login` and returns that call's outcome — its success
    /// on success, its error on failure. Without it, enabling `optional` would
    /// lock out every user of a tenant mid-migration, which is the state
    /// `optional` exists to serve. Under `required`, and against any server too
    /// old to report a mode at all, there is no retry: `required` answers
    /// `403 opaque_required` for every principal, so the attempt would put a
    /// plaintext password on the wire for nothing. An unrecognised mode is
    /// treated as `required` — fail closed.
    ///
    /// That reported mode is **not** downgrade protection and must not be
    /// presented as such: a hostile server that wanted the plaintext could
    /// simply answer `404` and get the fallback whatever mode it claims.
    /// `required` is what closes that, server-side, by refusing `/auth/login`
    /// before any credential is examined.
    ///
    /// \throws NetworkError if the tenant has OPAQUE disabled (the endpoint
    ///         answers 404 — a property of the tenant, not of any user), if
    ///         `libaxiam_opaque_ffi` is not installed, if the server names a
    ///         key-stretching function this SDK cannot ask for, or if the
    ///         response is not the shape §23 defines. Deliberately not
    ///         AuthError: reporting a configuration gap as a credential failure
    ///         would send a user off to reset a password that works, and would
    ///         stop a caller falling back to \ref login.
    /// \throws AuthError when the envelope does not open — a wrong password, an
    ///         account that does not exist, an account with no registration
    ///         record, and a server that does not hold one, indistinguishable by
    ///         design. **Nothing is sent to `login/finish` in that case**
    ///         (§23.4 rule 7). Under `opaque_mode: required`, and against a
    ///         server that reports no mode, that is the end of it and a caller
    ///         must **not** retry over \ref login by hand; under `optional` this
    ///         method has already retried, so an AuthError from it is
    ///         `/auth/login`'s own answer.
    LoginResult login_opaque(const std::string& username_or_email, const std::string& password);

    /// Builds a registration record for `password`, to send with any request
    /// that sets one: `POST /api/v1/users`, `/auth/password/change`,
    /// `/auth/reset/confirm` and `/admin/bootstrap`.
    ///
    /// The server cannot build this — it never sees the plaintext — so it has to
    /// arrive with the request or not at all.
    ///
    /// Unlike the `srp_enrollment` it replaces this performs I/O: one
    /// `register/start` round trip. OPAQUE's envelope is sealed under the
    /// server's oblivious PRF, so there is no offline computation that produces
    /// a valid record.
    ///
    /// Note the parameters that are gone. There is no `identity`: the SRP
    /// version required the account's **username**, and an email there produced
    /// a verifier no login could ever satisfy, whereas a record binds to a
    /// credential identifier the server chooses — so a later rename cannot
    /// invalidate a credential. And there is no `group` or `params`, because
    /// those come from the `register/start` response; a caller cannot pick a
    /// cost the server will not honour.
    ///
    /// \throws NetworkError in the same cases as \ref login_opaque.
    OpaqueEnrollment opaque_enrollment(const std::string& password);

    /// Whether this installation can perform OPAQUE (§23.2).
    ///
    /// Genuinely able to answer `false`: the protocol comes from
    /// `libaxiam_opaque_ffi`, a per-platform release asset rather than a package
    /// dependency, resolved with `dlopen` at run time so a consumer who never
    /// uses OPAQUE is not made to link it.
    ///
    /// Unlike the `srp_available` it replaces, a `true` here **is** a promise
    /// that every tenant will work: `srp_available` was unconditional while an
    /// `argon2id` tenant still failed at login, because this SDK's OpenSSL might
    /// have no Argon2 to offer.
    bool opaque_available() const;

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

    // ---- §20 UMA 2.0 — Protection API and ticket grant ----
    //
    // `pat` is a Protection API Token: a CLIENT-credentials token carrying the
    // `uma_protection` scope (§20.2 rule 1). This SDK never substitutes its own
    // session for it; an empty PAT throws AuthError with no wire call.

    /// `GET /.well-known/uma2-configuration` (§20.1).
    ///
    /// Cached for five minutes, the floor §12.3 rule 6 sets for the OIDC
    /// document: an endpoint map is not a credential, and re-fetching it on
    /// every guarded request is a self-inflicted round trip. Every operation
    /// below calls this itself, so a caller normally never needs to.
    UmaConfiguration uma_discover();

    /// `POST /uma2/rreg/resource_set` (§20.1) — register a resource set. The
    /// returned id is directly usable as a UmaRequestedPermission's resource_id.
    UmaResourceSet uma_register_resource(const Sensitive<std::string>& pat,
                                         const std::string& name,
                                         std::optional<std::string> type = std::nullopt,
                                         std::vector<std::string> resource_scopes = {});

    /// `GET /uma2/rreg/resource_set/{id}` (§20.1).
    UmaResourceSet uma_read_resource(const Sensitive<std::string>& pat, const std::string& id);

    /// `PUT /uma2/rreg/resource_set/{id}` (§20.1) — replace a resource set.
    ///
    /// `resource_scopes` REPLACES the declared list; it does not merge with it
    /// (§20.2 rule 8). No read-modify-write: folding the current scopes in as a
    /// convenience would make removing a scope impossible through this SDK.
    UmaResourceSet uma_update_resource(const Sensitive<std::string>& pat, const std::string& id,
                                       const std::string& name,
                                       std::optional<std::string> type = std::nullopt,
                                       std::vector<std::string> resource_scopes = {});

    /// `DELETE /uma2/rreg/resource_set/{id}` (§20.1) — deregister.
    void uma_delete_resource(const Sensitive<std::string>& pat, const std::string& id);

    /// `GET /uma2/rreg/resource_set` (§20.1) — the ids THIS client registered.
    ///
    /// Not the tenant's resource tree: the server scopes the listing to the
    /// registering client, so a PAT is not an enumeration handle.
    std::vector<std::string> uma_list_resources(const Sensitive<std::string>& pat);

    /// `POST /uma2/perm` (§20.1) — mint a permission ticket.
    ///
    /// The ticket comes back wrapped: for its 60-second life it is the
    /// credential that converts into an RPT, and a short lifetime is not the
    /// same as a harmless one (§20.6).
    Sensitive<std::string> uma_request_ticket(const Sensitive<std::string>& pat,
                                              const std::vector<UmaRequestedPermission>& permissions);

    /// `POST /oauth2/token` with the UMA ticket grant (§20.1) — redeem a
    /// permission ticket for a Requesting Party Token.
    ///
    /// What this method deliberately does NOT do:
    ///
    /// * **No retry, ever** (§20.2 rule 6) — not on `5xx`, not on a transport
    ///   failure, not on `invalid_grant`. This is the one documented exception
    ///   to §16, and a security rule rather than a performance one: the ticket
    ///   is consumed *before* the request is evaluated, so a failed exchange has
    ///   already spent it, and a retry is a second redemption — exactly the
    ///   concurrent redemption a server whose storage engine this SDK cannot
    ///   attest may admit twice (ilpanich/axiam#302). The property holds
    ///   structurally: this call never enters execute_retrying()'s budget.
    /// * **No defaulted claim_token** (rule 2). Defaulting it to the resource
    ///   server's own PAT would mint an RPT for the resource server rather than
    ///   for the user. An empty one throws with no wire call, so a request that
    ///   could not have succeeded never spends a ticket.
    /// * **No auto-narrowing on `access_denied`** (rule 3). A partial grant is
    ///   refused whole; whether two-of-three permissions is useful is the
    ///   calling application's judgement, not this SDK's.
    /// * **No adoption** (rule 4). The RPT is the *requesting party's* token; it
    ///   is returned to the caller and never becomes this client's credential.
    /// * **No refresh token** (rule 5) — RequestingPartyToken has no member for
    ///   one.
    ///
    /// The four ticket refusals — unknown, expired, already used, minted by
    /// another client — all arrive as one `invalid_grant`, and this SDK does not
    /// guess which (§20.4): the server collapses them because telling them apart
    /// lets a caller probe for live ticket handles.
    ///
    /// @throws OAuthProtocolError carrying the `error` code, for any refusal
    ///         whose body is an OAuth2ErrorResponse — at any status.
    RequestingPartyToken uma_exchange_ticket(const UmaExchangeTicketParams& params);

    // ---- §12 OIDC relying party, §12.7 logout, §14 device grant, §15 exchange ----
    //
    // See <axiam/oidc.hpp> for the four things this surface deliberately will
    // not do — chiefly: it stores no correlation values, it never skips
    // ID-token validation, it adopts nothing, and it does not retry a grant.

    /// `GET /.well-known/openid-configuration` (§12.1).
    ///
    /// Cached per client for oidc_discovery_ttl (default and floor 300 s).
    /// §12.3 rule 6 governs that cache: it is per-client-instance, which
    /// satisfies the origin rule by construction because a client is bound to
    /// one base URL for its lifetime, and it is NOT keyed on the tenant —
    /// the document is a per-origin protocol artifact with no tenant-specific
    /// content. Concurrent callers share a single in-flight fetch.
    OidcConfiguration oidc_discover();

    /// Build the authorization-request URL (§12.1). **No network I/O**, and it
    /// does not touch the transport (§12.6).
    ///
    /// Constructs a 32-byte CSPRNG `state` and `nonce` (base64url, unpadded), a
    /// 43-character `code_verifier` from the RFC 7636 §4.1 unreserved set,
    /// `code_challenge = BASE64URL(SHA256(ASCII(verifier)))` with
    /// `code_challenge_method=S256`, and a URL carrying exactly the eight
    /// permitted query parameters and no others. `openid` is added to the scope
    /// when the caller omits it (§12.1 rule 4).
    ///
    /// @param config       An already-fetched document; the
    ///                     `authorization_endpoint` comes from it, never
    ///                     hardcoded.
    /// @param redirect_uri Required, and the CALLER must remember it: §12.1
    ///                     keeps it off AuthorizationRequest, and oidc_exchange
    ///                     must replay it byte-identically.
    AuthorizationRequest oidc_begin(const OidcConfiguration& config,
                                    const std::string& redirect_uri,
                                    std::optional<std::string> scope = std::nullopt);

    /// `POST /oauth2/token` with `grant_type=authorization_code` (§12.1).
    ///
    /// Validates the returned `id_token` against every §12.4 rule before
    /// returning, and discards the ENTIRE token set on any failure (rule 7) —
    /// the access and refresh tokens from the same response are never handed
    /// back. The failing rule is named by OidcValidationError::reason().
    ///
    /// **Not retried, ever** (§16.2): the authorization code is consumed by the
    /// attempt, so a retry replays a spent credential and turns a transient blip
    /// into an `invalid_grant` the caller cannot interpret.
    OidcTokenSet oidc_exchange(const OidcExchangeParams& params);

    /// `POST /oauth2/token` with `grant_type=refresh_token` (§12.1).
    ///
    /// A **distinct operation** from refresh(), which drives the cookie/opaque
    /// session at `/api/v1/auth/refresh` (§5.1). §12.1 forbids merging,
    /// aliasing, or falling back between them.
    ///
    /// **Single-flight** (§12.1, §9 rule 2). Concurrent callers presenting the
    /// SAME refresh token share ONE wire call and its one outcome; callers with
    /// different tokens do not contend. That is not a performance tweak — AXIAM
    /// rotates refresh tokens, so two threads racing on one would spend it twice
    /// and the loser would get an `invalid_grant` for a token that was good a
    /// millisecond earlier. §9 rule 5 permits this dedicated guard rather than
    /// the §1 cookie guard, whose API compares an access token's freshness — a
    /// comparison with no meaning for a `refresh_token` grant.
    OidcTokenSet oidc_refresh(const Sensitive<std::string>& refresh_token,
                              std::optional<std::string> scope = std::nullopt,
                              std::optional<std::string> tenant_id = std::nullopt);

    /// `POST /oauth2/token` with `grant_type=client_credentials` (§12.1) — the
    /// machine-to-machine login.
    ///
    /// **Two kinds of principal use this and the token differs** (§12.1). The
    /// configured `client_id` names either an OAuth2 client (`oa_…`) or a
    /// service account (`sa_…`); the request is byte-identical, so nothing here
    /// changes. What changes is the token: a service account's `sub` is its UUID
    /// rather than the client id (check `sub_kind` before assuming either), and
    /// it carries NO `scope` claim at all — a service account registers no
    /// scopes, so requesting one answers `invalid_scope`, and its authorization
    /// comes from its assigned roles. Both kinds get `aud: axiam:m2m`, so a §10
    /// guard fronting a resource server that accepts machine callers must be
    /// configured to expect that (§10.1 rule 6).
    ///
    /// **Adoption is a MAY (§12.1) and this SDK does not.** The token is
    /// returned; nothing is installed on the client. §14.3 rule 4 requires
    /// device_login() to take the same posture, and it does.
    OidcTokenSet login_client_credentials(std::optional<std::string> scope = std::nullopt,
                                          std::optional<std::string> tenant_id = std::nullopt);

    /// `POST /oauth2/introspect` (§12.1) — RFC 7662.
    ///
    /// **Confidential clients only** (§12.1 rule 4): `token`, `client_id` and
    /// `client_secret` are all required, so a client built without a secret is
    /// refused client-side rather than sending a request that cannot succeed.
    ///
    /// A `401` carrying an `OAuth2ErrorResponse` is a CLIENT-AUTHENTICATION
    /// failure, not a session expiry: §12.3 rule 3 forbids it entering the §9
    /// refresh guard, because refreshing cannot fix a wrong client secret.
    IntrospectionResult introspect(const Sensitive<std::string>& token,
                                   std::optional<std::string> token_type_hint = std::nullopt,
                                   std::optional<std::string> tenant_id = std::nullopt);

    /// `POST /oauth2/revoke` (§12.1) — RFC 7009. Returns nothing.
    ///
    /// **Idempotent by design**: per RFC 7009 the server answers `200` for an
    /// unknown, expired or already-revoked token, and this MUST report that as
    /// success — that idempotence is the whole point of the endpoint. A `5xx` is
    /// still a failure (§12.1 rule 5, corrected in contract 1.5: returning void
    /// does not turn a server error into a success).
    void revoke(const Sensitive<std::string>& token,
                std::optional<std::string> token_type_hint = std::nullopt,
                std::optional<std::string> tenant_id = std::nullopt);

    /// `POST /api/v1/auth/federation/oidc/start` (§12.1) — begin SSO against an
    /// upstream IdP.
    ///
    /// Carries org/tenant context in the JSON body per §5.1: one tenant form and
    /// one org form, whichever this client was constructed with. Slug forms are
    /// valid here — unlike the five `/oauth2` operations, which need a UUID
    /// query parameter.
    ///
    /// §12.4 does NOT apply to this pair: no ID token reaches the SDK, and the
    /// federation nonce never leaves the server (§12.1 note 7). Round-trip
    /// `state` unmodified into sso_complete() and do not synthesise a nonce.
    SsoStartResult sso_start(const std::string& federation_config_id,
                             const std::string& redirect_uri);

    /// `POST /api/v1/auth/federation/oidc/callback` (§12.1) — complete SSO.
    ///
    /// The session arrives as `Set-Cookie` (§12.1 note 6), so the §4 cookie-jar
    /// requirement applies verbatim.
    SsoCompleteResult sso_complete(const std::string& code, const std::string& state);

    /// Verify a back-channel logout token the OP POSTed to this RP (§12.7.1).
    ///
    /// No network I/O of its own: it verifies against the JWKS this client
    /// already caches, through the same §12.4 verifier — there is no second
    /// key-fetching path (§12.7.3 rule 1).
    ///
    /// **This is the half that carries security weight.** The input arrives
    /// unsolicited, from the network, and instructs the RP to terminate a
    /// session. Every §12.7.3 check is enforced, and the two easiest to skip are
    /// the two that matter most: `events` must carry the backchannel-logout key
    /// with an object value (it is what distinguishes a logout token from an ID
    /// token), and `nonce` MUST BE ABSENT (its presence is the documented
    /// signature of an ID token being replayed — this rejects rather than
    /// ignoring).
    ///
    /// Verifying the SAME token twice succeeds both times, deliberately:
    /// delivery is at-least-once, dedup is the RP's job through `jwt_id`, and an
    /// SDK that failed the second delivery would break a legitimate retry.
    ///
    /// @throws OidcValidationError on a signature-layer failure, AuthError on
    ///         any other rule. Neither message echoes the token (rule 8).
    VerifiedLogoutToken verify_logout_token(const std::string& logout_token);

    /// `POST /oauth2/device_authorization` (§14.1) — start the RFC 8628 grant.
    ///
    /// **Unauthenticated.** A device that cannot show a browser also cannot hold
    /// a client secret, so §14.1 forbids sending one here AND forbids refusing
    /// to call this from a client constructed without one. Only `client_id`
    /// goes out.
    DeviceAuthorization device_authorize(std::optional<std::string> scope = std::nullopt,
                                         std::optional<std::string> tenant_id = std::nullopt);

    /// One `POST /oauth2/token` with the device-code grant (§14.1) — a SINGLE
    /// poll.
    ///
    /// The five RFC 8628 §3.5 answers all arrive as `400`, which §2 would map to
    /// a generic error; §14.2 rule 5 overrides that and requires dispatching on
    /// the `error` field first. This throws OAuthProtocolError carrying that
    /// field, so a caller driving its own loop can tell `authorization_pending`
    /// and `slow_down` (keep going) from `access_denied`, `expired_token` and
    /// `invalid_grant` (stop) — §14.2 rule 3 keeps the first two of those
    /// terminal codes DISTINCT, because "a human said no" and "nobody answered"
    /// are the only thing a device can act on.
    OidcTokenSet device_poll(const Sensitive<std::string>& device_code,
                             std::optional<std::string> tenant_id = std::nullopt);

    /// The composed helper (§14.3): authorize, hand the caller the codes, poll
    /// to completion.
    ///
    /// Polling follows §14.2 exactly. The interval starts at the SERVER's value
    /// (5 s when it sent none — no faster floor may be hard-coded); `slow_down`
    /// adds 5 s to the CURRENT interval permanently and never resets it, because
    /// an SDK that backs off for one round and returns to the original rate will
    /// be told to slow down again forever; and the loop stops at `expires_in`
    /// even if the server has not yet said `expired_token`, because the deadline
    /// is authoritative and the extra requests are pure load.
    ///
    /// A `5xx` or transport failure mid-poll is NOT terminal (§14.2 rule 6): it
    /// has already been through the §16 bounded retry inside the poll, whose
    /// budget is per attempt and separate from this loop, and a server restart
    /// mid-flow must not lose a grant the user already approved.
    ///
    /// The token set is RETURNED, not adopted — the same posture
    /// login_client_credentials() takes, which §14.3 rule 4 requires an SDK to
    /// match rather than inventing a second one.
    ///
    /// @param display Called ONCE, before the first poll (§14.3 rule 2). The SDK
    ///        does not print the codes on the caller's behalf and does not begin
    ///        polling until this returns.
    OidcTokenSet device_login(DeviceCodeDisplay display,
                              std::optional<std::string> scope = std::nullopt,
                              std::optional<std::string> tenant_id = std::nullopt);

    /// `POST /oauth2/token` with the RFC 8693 grant (§15.1).
    ///
    /// The exchanging client AUTHENTICATES — unlike §14's device, this is a
    /// confidential service, and a client with no configured secret is refused
    /// client-side.
    ///
    /// What this deliberately does NOT do: no retry, downgrade or rewrite on
    /// `unauthorized_client` (§15.2 rule 2); no auto-narrowing on
    /// `invalid_scope` (rule 3); no refresh token, ever (rule 4 — ExchangedToken
    /// has nowhere to put one, and this result never enters the §9 guard); and
    /// **no adoption** (rule 5), which is a MUST NOT here where adoption
    /// elsewhere is a MAY.
    ///
    /// A cross-tenant subject token answers `invalid_grant`, and this SDK does
    /// not try to tell "wrong tenant" from "bad token" (§15.3): the server
    /// collapses them because distinguishing them is a tenant-enumeration
    /// signal.
    ExchangedToken token_exchange(const TokenExchangeParams& params);

    // ---- §24 WebAuthn / passkeys ----
    //
    // The six wire operations. See <axiam/webauthn.hpp> for what is deliberately
    // absent (§24.6b's ceremony helper — a C++ program has no authenticator) and
    // for the JSON bridge that stands in its place.
    //
    // THE SERVER OWNS THE OPTIONS AND VERIFIES THE RESPONSE (§24.0). Every
    // `response` argument below is the platform's own response JSON, forwarded
    // VERBATIM: it is spliced into the request body as text rather than parsed
    // into a model and printed back out, because re-encoding a signed buffer is
    // three chances to corrupt it in service of nothing. A string that is not a
    // JSON object is refused client-side, with no wire call.

    /// `POST /api/v1/auth/webauthn/register/start` (§24.1) — begin enrolling a
    /// passkey for the signed-in user.
    ///
    /// Requires a session, and refuses CLIENT-SIDE WITH NO WIRE CALL when there
    /// is none: a passkey is enrolled BY a signed-in user, for themselves.
    ///
    /// A `503` here means the tenant's attestation policy needs FIDO metadata
    /// the server cannot reach — a configuration state, not a transient one —
    /// and §24.4 rule 2 deliberately does not retry it.
    WebauthnChallenge webauthn_register_start();

    /// `POST /api/v1/auth/webauthn/register/finish` (§24.1) — hand the
    /// authenticator's answer back and store the credential.
    ///
    /// A `403` here is the one error whose BODY matters (§24.4 rule 1): the
    /// tenant's attestation policy rejected THIS authenticator, and the server's
    /// message is the only place that says which one would be accepted, so it is
    /// surfaced in the thrown AuthzError.
    WebauthnCredential webauthn_register_finish(const Sensitive<std::string>& state_token,
                                                const std::string& credential_name,
                                                const std::string& response);

    /// `POST /api/v1/auth/webauthn/authenticate/start` (§24.1) — begin the
    /// SECOND-FACTOR ceremony.
    ///
    /// Continues a login() that answered `mfa_required` with `"webauthn"` among
    /// its available methods; `challenge_token` is that login's token. A
    /// DIFFERENT FLOW from webauthn_discoverable_start(), not the same one with
    /// a flag (§24.2) — which is why the token is required here and absent
    /// there.
    WebauthnChallenge webauthn_authenticate_start(const Sensitive<std::string>& challenge_token);

    /// `POST /api/v1/auth/webauthn/authenticate/finish` (§24.1).
    ///
    /// On success this client is signed in: the server sets the same cookie
    /// triple `POST /api/v1/auth/login` sets, and the §17 decision memo is
    /// cleared because the subject changed (§24.3).
    WebauthnLoginResult webauthn_authenticate_finish(const Sensitive<std::string>& state_token,
                                                     const std::string& response);

    /// `POST /api/v1/auth/webauthn/authenticate/discoverable/start` (§24.1) —
    /// begin the usernameless ceremony.
    ///
    /// A PRIMARY FACTOR: nothing precedes it, `allowCredentials` comes back
    /// empty, and the assertion itself identifies the user. Pass no workspace to
    /// have it filled from this client's own configured identity.
    ///
    /// Unlike authenticate/finish, discoverable/finish fires the
    /// `login.post_auth` reactor hook (§22.5) — the former continues a login
    /// already gated at its password step, and this one has no such step.
    WebauthnChallenge webauthn_discoverable_start(
        std::optional<WebauthnWorkspace> workspace = std::nullopt);

    /// `POST /api/v1/auth/webauthn/authenticate/discoverable/finish` (§24.1).
    /// Adopts credentials exactly as webauthn_authenticate_finish() does.
    WebauthnLoginResult webauthn_discoverable_finish(const Sensitive<std::string>& state_token,
                                                     const std::string& response);

    // ---- §25 account lifecycle and MFA enrolment ----
    //
    // See <axiam/account.hpp>. Six of the nine are unauthenticated by design.

    /// `POST /api/v1/auth/mfa/enroll` (§25.1) — start voluntary TOTP enrolment
    /// for the signed-in user.
    ///
    /// Changes nothing about the current session. In particular it does NOT
    /// clear the §17 decision memo: the subject has not changed, and discarding
    /// a warm memo on an unrelated profile action costs a round trip on every
    /// check that follows (§25.2 rule 3).
    ///
    /// ENROLMENT IS TWO CALLS AND THIS IS ONLY THE FIRST. The factor is not
    /// active until mfa_confirm() accepts a code derived from the returned
    /// secret, and §25.2 rule 4 forbids a composed one-call helper here — the
    /// human step in the middle is not something a helper can wait for.
    MfaEnrollment mfa_enroll();

    /// `POST /api/v1/auth/mfa/confirm` (§25.1) — activate the factor
    /// mfa_enroll() offered. Returns the server's own `mfa_enabled` answer.
    bool mfa_confirm(const std::string& totp_code);

    /// `POST /api/v1/auth/mfa/setup/enroll` (§25.1) — start the enrolment a
    /// login() demanded.
    ///
    /// Reached when LoginResult::mfa_setup_required is set: the tenant requires
    /// MFA and this account has none. There is no session yet — the setup token
    /// IS the credential.
    MfaEnrollment mfa_setup_enroll(const Sensitive<std::string>& setup_token);

    /// `POST /api/v1/auth/mfa/setup/confirm` (§25.1) — finish forced enrolment
    /// and, with it, the login that was interrupted.
    ///
    /// Adopts credentials exactly as login() does, because it IS the completion
    /// of a login (§25.2 rule 2) — including clearing the §17 memo.
    LoginResult mfa_setup_confirm(const Sensitive<std::string>& setup_token,
                                  const std::string& totp_code);

    /// `POST /api/v1/auth/verify-email` (§25.1). Unauthenticated; the tenant is
    /// a BODY field.
    void verify_email(const Sensitive<std::string>& token, const std::string& tenant_id);

    /// `POST /api/v1/auth/resend-verification` (§25.1). Unauthenticated; the
    /// tenant is a BODY field.
    void resend_verification(const std::string& email, const std::string& tenant_id);

    /// `POST /api/v1/auth/reset` (§25.1) — ask for a reset mail.
    ///
    /// RETURNS NORMALLY WHETHER OR NOT THE ADDRESS EXISTS, and this SDK exposes
    /// no way to tell the two apart. That is not an omission to improve on: a
    /// client that surfaced a "no such user" state — even one inferred from
    /// timing — would turn the endpoint into the account-enumeration oracle its
    /// uniform response exists to prevent (§25.4).
    void request_password_reset(const PasswordResetRequest& request);

    /// `GET /api/v1/auth/reset/context?token=…` (§25.1) — the OPAQUE policy for
    /// the account a reset token belongs to.
    ///
    /// Call this before confirm_password_reset() on any tenant that might have
    /// §23 enabled: the client has to build a registration record, and building
    /// one needs parameters it cannot know before it has a token to ask with.
    /// Sending a plaintext password to a tenant in `opaque_mode: required` is
    /// refused, and refused late (§25.4 rule 1).
    ///
    /// A `404` means unknown, expired OR already-consumed, deliberately without
    /// distinguishing them; this SDK does not distinguish them either (§25.4
    /// rule 3).
    PasswordResetContext password_reset_context(const Sensitive<std::string>& token);

    /// `POST /api/v1/auth/reset/confirm` (§25.1) — set the new password.
    void confirm_password_reset(const PasswordResetConfirmation& confirmation);

    // ---- §26 Pushed Authorization Requests (RFC 9126) ----

    /// `POST /oauth2/par?tenant_id=<uuid>` (§26.1) — push the authorization
    /// request over the back channel and get an opaque handle to redirect with.
    ///
    /// PAR moves the authorization request off the browser. Instead of putting
    /// `scope`, `redirect_uri`, `state` and the PKCE challenge into a URL the
    /// user agent carries, the client POSTs them straight to AXIAM over an
    /// authenticated channel and puts an opaque `request_uri` in the redirect.
    /// What travels through the browser is then a random string that cannot be
    /// edited into meaning something else.
    ///
    /// REQUIRED FOR A FAPI 2.0 CLIENT: `profile: "fapi2"` refuses a registration
    /// that does not set `require_par`, so such a client cannot authorize any
    /// other way (§21.1).
    ///
    /// NOT RETRIED on a 5xx or a transport failure — it is a POST that creates
    /// server state, so it falls outside §16.2's read-only eligibility exactly
    /// as oidc_exchange() does. The safe recovery is a fresh push, which costs
    /// one round trip and cannot double-consume anything (§26.2 rule 4).
    ///
    /// @param request what oidc_begin() returned. Its state, nonce and PKCE
    ///                verifier are pushed as-is (§26.2 rule 1) — there is no
    ///                second generator here, and there must not be.
    /// @throws AuthError, client-side with NO wire call, when the discovery
    ///         document advertises no PAR endpoint. §12.7.2 rule 1's discipline:
    ///         never synthesise the URL from the issuer.
    PushedAuthorizationRequest oidc_par(const OidcConfiguration& config,
                                        const AuthorizationRequest& request,
                                        const std::string& redirect_uri,
                                        std::optional<std::string> scope = std::nullopt,
                                        std::optional<std::string> tenant_id = std::nullopt);

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

    /// Test seam: replace the §16 jitter source and the sleep.
    ///
    /// §16.7 requires backoff and jitter to be tested with an injected clock and
    /// an injected PRNG, never by sleeping — a test that really waits 200 ms is a
    /// test nobody runs. This is the only way to reach those from outside, since
    /// the policy is otherwise sealed inside the impl. NEVER called in
    /// production; nothing in src/ writes it.
    void _set_retry_test_seams(std::function<double()> jitter,
                               std::function<void(std::chrono::milliseconds)> sleeper);
    /// Currently-stored CSRF token, if any (§3).
    std::optional<std::string> csrf_token() const;
    /// Whether a session has been established (login/verify_mfa succeeded).
    bool has_session() const;
    /// Shared JWKS verifier bound to this client's transport + base URL.
    JwksVerifier& jwks();
    /// Tenant identifier injected as X-Tenant-ID on every request (§5).
    const std::string& tenant_header() const;

    /// Deterministic shutdown (CONTRACT.md §18).
    ///
    /// Releases the transport and its connection pool, and clears the cookie
    /// jar, the CSRF token and the §17 memo.
    ///
    /// * IDEMPOTENT (§18.1 rule 2): calling it twice is a no-op the second time,
    ///   never a double release. Cleanup runs from error paths, and an error path
    ///   that itself throws hides the original failure.
    /// * DOES NOT LOG OUT (§18.1 rule 5): it issues no request. The server-side
    ///   session deliberately outlives the client object — that is what lets a
    ///   process restart and resume — so a close() that logged out would silently
    ///   end every user's session on each deploy.
    /// * USE AFTER CLOSE IS AN ERROR, NOT UNDEFINED (§18.1 rule 4): every
    ///   operation afterwards throws NetworkError naming the cause rather than
    ///   silently reconnecting.
    ///
    /// The destructor releases whatever close() has not, so a Client that goes
    /// out of scope without an explicit close() still frees its transport —
    /// §18.1 rule 1's "a destructor plus close()" for C++.
    void close();

    /// The shared private state behind every method.
    ///
    /// Declared (never defined) in the public header so that the §12 / §12.7 /
    /// §14 / §15 translation unit can reach the same transport, tenant header
    /// and §16 seams the other operations use. It is DEFINED only in
    /// src/client_impl.hpp, which is not installed, so no application can
    /// construct or inspect one — the alternative was a second copy of the
    /// request plumbing living beside the first, which is exactly the "second,
    /// parallel stack" the §12.6 deferral warned about.
    /// The CONTRACT.md §27 management surface: 146 operations across 24 namespaces.
    ///
    /// `client.management().users().list()`. §27.3's C++ row is
    /// `client.service_accounts().rotate_secret(id)` — a method returning a handle,
    /// snake_case — and that is what the accessors on the returned object are.
    ///
    /// Built on the same request path every other operation uses, so §3 CSRF, the §4
    /// cookie jar, the §5 tenant header, §6 TLS, §16 retry and §19 telemetry apply to all
    /// 146 by construction rather than by 146 opportunities to forget one (§27.8).
    ///
    /// Returned by value: it holds a shared_ptr to the transport and a scope, and
    /// building one per call is what keeps `in_org()` from having anything shared to
    /// re-point. That is not a §27.4 rule 10 violation — that rule forbids caching
    /// RESPONSES, and nothing here caches one.
    management::ManagementApi management();

    struct Impl;

private:
    std::shared_ptr<Impl> p_;
    explicit Client(std::shared_ptr<Impl> impl);
};

}  // namespace axiam
