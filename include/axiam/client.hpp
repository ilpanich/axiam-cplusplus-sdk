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

#include "axiam/errors.hpp"
#include "axiam/jwks.hpp"
#include "axiam/oidc.hpp"
#include "axiam/srp.hpp"
#include "axiam/telemetry.hpp"
#include "axiam/transport.hpp"
#include "axiam/types.hpp"
#include "axiam/uma.hpp"

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

    // ---- §23 Secure Remote Password ----

    /// `POST /api/v1/auth/srp/challenge` then `/verify` — SRP-6a login (§23).
    ///
    /// A sibling of \ref login, not a replacement. It takes the same arguments
    /// and returns the same LoginResult, MFA branch included, so an application
    /// can switch a tenant to SRP without touching its own code (§23.1).
    ///
    /// **What this does that \ref login does not.** The password never leaves
    /// this process. What crosses the wire is `A` and a proof, neither of which
    /// is useful without the account's verifier — so a TLS-terminating proxy, an
    /// accidentally verbose request log, or a heap dump on the server cannot
    /// capture a plaintext password, because the server never has one. It does
    /// **not** protect against a compromised AXIAM server.
    ///
    /// **Cost.** Runs the tenant's KDF: Argon2id at 19 MiB and t=2 by default,
    /// tens to hundreds of milliseconds of CPU plus that memory, per attempt.
    /// That cost is the point. It is synchronous and blocking.
    ///
    /// \throws NetworkError if the tenant has SRP disabled (the endpoint answers
    ///         404 — a property of the tenant, not of any user), or if this build
    ///         cannot perform the group or KDF the server named. Deliberately not
    ///         AuthError: reporting a client capability gap as a credential
    ///         failure would send a user off to reset a password that works.
    /// \throws AuthError for a wrong password, and for a server whose `M2` does
    ///         not verify — in the latter case nothing is returned, because an
    ///         endpoint that cannot prove it holds the verifier is not the server
    ///         it claims to be (§23.3 rule 6).
    LoginResult login_srp(const std::string& username_or_email, const std::string& password);

    /// Computes a verifier for `password`, to send with any request that sets
    /// one: `POST /api/v1/users`, `/auth/password/change`,
    /// `/auth/reset/confirm` and `/admin/bootstrap` (§23.3 rule 11).
    ///
    /// The server cannot compute this — it never sees the plaintext — so it has
    /// to arrive with the request or not at all. The salt is 32 fresh bytes from
    /// the platform CSPRNG on every call. Performs no I/O; it is a method on the
    /// client only so it sits beside \ref login_srp in the API.
    ///
    /// \param identity The account's **username** — the canonical identity the
    ///        challenge endpoint hands back. An email here produces a verifier no
    ///        login can ever satisfy.
    /// \param group The tenant's group, from `GET /api/v1/auth/me` or the reset
    ///        context; `std::nullopt` means AXIAM's default.
    /// \param params The tenant's KDF and costs; any zero cost is filled in with
    ///        AXIAM's default for that KDF.
    SrpEnrollment srp_enrollment(const std::string& identity, const std::string& password,
                                 std::optional<std::string> group = std::nullopt,
                                 std::optional<SrpKdfParams> params = std::nullopt);

    /// Whether this build can perform SRP (§23.1).
    ///
    /// Unconditional here. It exists because §23.1 puts the probe in every SDK's
    /// vocabulary, and because a `true` is **not** a promise that every tenant
    /// will work: Argon2id needs OpenSSL >= 3.2 — see `srp::argon2_available()`.
    bool srp_available() const;

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
    struct Impl;

private:
    std::shared_ptr<Impl> p_;
    explicit Client(std::shared_ptr<Impl> impl);
};

}  // namespace axiam
