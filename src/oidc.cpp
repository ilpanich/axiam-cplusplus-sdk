// §12 OIDC relying party, §12.7 logout, §14 device grant, §15 token exchange.
//
// See include/axiam/oidc.hpp for the design notes and for why contract 1.11
// un-deferred this section here. Three things are worth repeating where the
// code lives:
//
//  * Client::oidc_begin touches NO network and does not acquire the transport
//    (§12.6). It computes a URL and a verifier and returns them.
//  * The five tenant-scoped operations refuse a slug CLIENT-SIDE, with no wire
//    call (§12.3 rule 4). Sending a slug where the server wants a UUID would
//    fail anyway; refusing here is about not making the caller read a server
//    error to learn something the SDK already knew.
//  * Nothing here adopts a token. Every operation returns one; the client's own
//    credential is untouched.

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <ctime>
#include <utility>

#include "client_impl.hpp"

namespace axiam {
namespace {

/// Percent-encode for a form value or query parameter (RFC 3986 unreserved set).
std::string pct(const std::string& in) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size());
    for (unsigned char ch : in) {
        const bool unreserved = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                                (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' ||
                                ch == '_' || ch == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(ch));
        } else {
            out.push_back('%');
            out.push_back(kHex[ch >> 4]);
            out.push_back(kHex[ch & 0xF]);
        }
    }
    return out;
}

/// A form body under construction.
///
/// §12.1: "MUST omit (rather than send empty/null) any optional field the caller
/// did not supply". Every optional field in this file routes through add(), so
/// the rule is enforced in one place rather than at each call site.
class Form {
public:
    void add(const std::string& key, const std::string& value) {
        if (value.empty()) return;
        if (!body_.empty()) body_.push_back('&');
        body_ += pct(key);
        body_.push_back('=');
        body_ += pct(value);
    }
    /// A string literal is convertible to both std::string and
    /// std::optional<std::string>, so without this the two-overload set is
    /// ambiguous at every `add("grant_type", "…")` call site.
    void add(const std::string& key, const char* value) { add(key, std::string(value)); }
    void add(const std::string& key, const std::optional<std::string>& value) {
        if (value) add(key, *value);
    }
    const std::string& str() const { return body_; }

private:
    std::string body_;
};

/// Append `?tenant_id=` (or `&`) to an endpoint from the discovery document.
///
/// §12.1 note 2: tenant_id is a QUERY parameter and never a body field —
/// TokenRequest, IntrospectRequest and RevokeRequest have no such property. Any
/// query the discovered endpoint already carries is preserved.
std::string with_tenant(const std::string& endpoint, const std::string& tenant) {
    std::string url = endpoint;
    url += (url.find('?') == std::string::npos) ? '?' : '&';
    url += "tenant_id=" + pct(tenant);
    return url;
}

bool looks_like_uuid(const std::string& s) {
    static const int kGroups[] = {8, 4, 4, 4, 12};
    std::size_t at = 0;
    for (int g = 0; g < 5; ++g) {
        for (int i = 0; i < kGroups[g]; ++i) {
            if (at >= s.size()) return false;
            const char ch = s[at++];
            const bool hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                             (ch >= 'A' && ch <= 'F');
            if (!hex) return false;
        }
        if (g < 4) {
            if (at >= s.size() || s[at++] != '-') return false;
        }
    }
    return at == s.size();
}

json parse_or_object(const std::string& body) {
    auto j = json::parse(body, nullptr, false);
    return j.is_discarded() ? json::object() : j;
}

std::optional<std::string> opt_string(const json& j, const char* key) {
    if (!j.contains(key) || !j[key].is_string()) return std::nullopt;
    auto v = j[key].get<std::string>();
    if (v.empty()) return std::nullopt;
    return v;
}

std::vector<std::string> string_array(const json& j, const char* key) {
    std::vector<std::string> out;
    if (!j.contains(key)) return out;
    const auto& v = j[key];
    // RFC 7519 §4.1.3 permits `aud` as a bare string or an array; a non-string
    // member of an array is skipped rather than fataling the call.
    if (v.is_string()) {
        out.push_back(v.get<std::string>());
        return out;
    }
    if (!v.is_array()) return out;
    for (const auto& item : v) {
        if (item.is_string()) out.push_back(item.get<std::string>());
    }
    return out;
}

std::optional<std::int64_t> opt_int(const json& j, const char* key) {
    if (!j.contains(key) || !j[key].is_number()) return std::nullopt;
    return j[key].get<std::int64_t>();
}

/// base64url without padding (RFC 4648 §5).
std::string b64url(const unsigned char* data, std::size_t len) {
    static const char* kAlphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((len + 2) / 3 * 4);
    for (std::size_t i = 0; i < len; i += 3) {
        unsigned v = static_cast<unsigned>(data[i]) << 16;
        std::size_t have = 1;
        if (i + 1 < len) { v |= static_cast<unsigned>(data[i + 1]) << 8; have = 2; }
        if (i + 2 < len) { v |= static_cast<unsigned>(data[i + 2]); have = 3; }
        out.push_back(kAlphabet[(v >> 18) & 0x3F]);
        out.push_back(kAlphabet[(v >> 12) & 0x3F]);
        if (have > 1) out.push_back(kAlphabet[(v >> 6) & 0x3F]);
        if (have > 2) out.push_back(kAlphabet[v & 0x3F]);
    }
    return out;
}

/// 32 CSPRNG bytes, base64url unpadded — 43 characters, which is both §12.1's
/// RECOMMENDED code_verifier construction and comfortably over the 16-byte floor
/// for `state` and `nonce`.
std::string random_b64url() {
    std::array<unsigned char, 32> raw{};
    if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
        throw NetworkError("oidc_begin: could not draw cryptographic randomness",
                           "rand_failure");
    }
    std::string out = b64url(raw.data(), raw.size());
    OPENSSL_cleanse(raw.data(), raw.size());
    return out;
}

/// §12.1 rule 3: `code_challenge = BASE64URL(SHA256(ASCII(verifier)))`.
std::string s256_challenge(const std::string& verifier) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) throw NetworkError("oidc_begin: digest init failed", "digest");
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, verifier.data(), verifier.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, digest, &len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) throw NetworkError("oidc_begin: digest failed", "digest");
    return b64url(digest, len);
}

/// Hex SHA-256, for the §9 single-flight key. Keyed on the DIGEST rather than
/// the token so the flight registry never holds a second copy of a live
/// credential.
std::string digest_hex(const std::string& s) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) throw NetworkError("oidc_refresh: digest init failed", "digest");
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, s.data(), s.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, digest, &len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok) throw NetworkError("oidc_refresh: digest failed", "digest");
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned i = 0; i < len; ++i) {
        out.push_back(kHex[digest[i] >> 4]);
        out.push_back(kHex[digest[i] & 0xF]);
    }
    return out;
}

/// Constant-time string equality, for the §12.4 rule 6 nonce comparison.
///
/// The nonce is not a secret in the §7 sense — it is returned to the caller as a
/// plain string — but rule 6 names constant-time comparison explicitly, and the
/// reason is timing: a variable-time compare against an attacker-chosen nonce
/// leaks a prefix oracle, and recovering the expected nonce byte by byte is
/// enough to forge the one check standing between a replayed ID token and
/// acceptance.
bool ct_equal(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    return diff == 0;
}

std::int64_t now_seconds() {
    return static_cast<std::int64_t>(std::time(nullptr));
}

/// §12.3 rule 3 / §14.2 rule 5 / §15.3: dispatch on the body's `error` field
/// FIRST and at any status.
///
/// A `400` from `/oauth2/token` therefore surfaces as OAuthProtocolError with
/// the code intact rather than as the generic §2 400 row — which is exactly what
/// §12.3 rule 3 requires and what lets §14.2's five answers be told apart. A body
/// that is not an OAuth2ErrorResponse at all (a proxy's HTML 502) falls back to
/// the §2 status mapping.
[[noreturn]] void raise_grant_error(const HttpResponse& resp, const std::string& context) {
    const json j = parse_or_object(resp.body);
    if (j.contains("error") && j["error"].is_string() &&
        !j["error"].get<std::string>().empty()) {
        const auto code = j["error"].get<std::string>();
        std::optional<std::string> description;
        if (j.contains("error_description") && j["error_description"].is_string() &&
            !j["error_description"].get<std::string>().empty()) {
            description = j["error_description"].get<std::string>();
        }
        // §12.3 rule 3 fixes the message shape as "<error>: <error_description>".
        // The description is server free text; it is copied because the contract
        // specifies that shape, and no token, secret or verifier from this SDK
        // ever reaches it.
        const std::string message = description ? (code + ": " + *description) : (code + " (" + context + ")");
        throw OAuthProtocolError(message, code, std::move(description));
    }
    if (resp.status == 401) throw AuthError(context);
    if (resp.status == 403 || resp.status == 409) throw AuthzError(context);
    throw NetworkError(context + " (HTTP " + std::to_string(resp.status) + ")",
                       "http_" + std::to_string(resp.status));
}

}  // namespace

// ---------------------------------------------------------------------------
// §12.7.2 logout_url — pure local computation, no client involved
// ---------------------------------------------------------------------------

std::optional<std::string> logout_url(const OidcConfiguration& config,
                                      const std::string& id_token,
                                      std::optional<std::string> post_logout_redirect_uri,
                                      std::optional<std::string> state) {
    // §12.7.2 rule 1: the endpoint comes from DISCOVERY. Building
    // "{issuer}/oauth2/end_session" happens to work against AXIAM and breaks
    // against every other OP the same code is pointed at, which is the whole
    // reason discovery exists. A server that advertises none gets nullopt rather
    // than a guess.
    if (!config.end_session_endpoint || config.end_session_endpoint->empty()) {
        return std::nullopt;
    }
    // §12.7.1: there is no hint-less mode. `id_token_hint` is the only parameter
    // on the wire that names the user, and an SDK that invented a `sub`-based
    // alternative would be encouraging exactly the request the server refuses to
    // act on.
    if (id_token.empty()) return std::nullopt;

    Form q;
    q.add("id_token_hint", id_token);
    // Rule 3: NOT pre-validated against a local list. The allow-list lives in
    // the client's server-side registration; a client-side copy would drift and
    // would reject a URI an operator had just registered.
    q.add("post_logout_redirect_uri", post_logout_redirect_uri);
    // Rule 2: passed through unmodified, and never invented — the value only
    // means something to the application that will receive it back.
    q.add("state", state);

    std::string url = *config.end_session_endpoint;
    url += (url.find('?') == std::string::npos) ? '?' : '&';
    url += q.str();
    return url;
}

// ---------------------------------------------------------------------------
// Impl helpers
// ---------------------------------------------------------------------------

namespace {

const std::string& require_client_id(const Client::Impl& impl, const char* operation) {
    if (impl.oidc_client_id && !impl.oidc_client_id->empty()) return *impl.oidc_client_id;
    // §12.1: fail fast with NO wire call. A missing client registration is a
    // deployment mistake, not an authentication outcome.
    throw AuthError(std::string(operation) +
                    " requires an OIDC client_id; set it on the builder "
                    "(CONTRACT.md §12.1: it is configuration, not a per-call argument)");
}

const std::string& require_client_secret(const Client::Impl& impl, const char* operation) {
    if (impl.oidc_client_secret && !detail::reveal(*impl.oidc_client_secret).empty()) {
        return detail::reveal(*impl.oidc_client_secret);
    }
    throw AuthError(std::string(operation) +
                    " is a confidential-client operation and requires an OIDC client_secret; "
                    "a public client cannot call it (CONTRACT.md §12.1 rule 4)");
}

std::string require_tenant_uuid(const Client::Impl& impl,
                                const std::optional<std::string>& explicit_id,
                                const char* operation) {
    std::string tenant = (explicit_id && !explicit_id->empty())
                             ? *explicit_id
                             : impl.tenant_id.value_or(std::string{});
    if (looks_like_uuid(tenant)) return tenant;
    // §12.3 rule 4 and §12.1 note 2's "a slug-only client cannot call five of
    // the nine operations". The header and the query parameter legitimately
    // disagree in FORM — X-Tenant-ID carries whatever the client was built with,
    // which may be a slug — but a slug is never a valid substitute in the query
    // parameter, and sending one is what this refuses. The remedy is in the
    // message because an operator hitting this needs to know it is a
    // construction choice, not an outage.
    throw AuthError(
        std::string(operation) +
        " requires a tenant_id UUID for the /oauth2 query parameter; this client has only a "
        "tenant slug and a slug is never a substitute (CONTRACT.md §12.3 rule 4). "
        "Construct the client with tenant_id, or pass one per call.");
}

/// The client's §12.4 rule 5 skew, already clamped at build().
std::int64_t clock_skew(const Client::Impl& impl) {
    return static_cast<std::int64_t>(impl.oidc_clock_skew.count());
}

}  // namespace

// ---------------------------------------------------------------------------
// §12.1 oidc_discover
// ---------------------------------------------------------------------------

OidcConfiguration Client::oidc_discover() {
    p_->ensure_open();

    // §12.3 rule 6's single-flight, in its simplest correct form: the lock is
    // held across the FETCH, not just around the cache read. A second caller
    // arriving mid-fetch blocks here and then finds the cache warm, so a burst
    // of N concurrent callers produces exactly one wire call — the observable §9
    // rule 2 asks for. A leader/follower arrangement would buy nothing: there is
    // one document and every waiter wants the same one.
    std::lock_guard<std::mutex> lock(p_->oidc_config_mtx);
    if (p_->oidc_config && std::chrono::steady_clock::now() < p_->oidc_config_expires_at) {
        return *p_->oidc_config;
    }

    HttpRequest req;
    req.method = "GET";
    req.url = p_->base_url + "/.well-known/openid-configuration";
    req.headers["X-Tenant-ID"] = p_->tenant_header;  // §5 rule 2, unconditional
    req.headers["Accept"] = "application/json";

    const HttpResponse resp = p_->send_raw(req);
    if (resp.status < 200 || resp.status >= 300) {
        throw NetworkError("oidc discovery failed (HTTP " + std::to_string(resp.status) + ")",
                           "http_" + std::to_string(resp.status));
    }
    const json j = parse_or_object(resp.body);

    OidcConfiguration cfg;
    cfg.issuer = j.value("issuer", "");
    cfg.authorization_endpoint = j.value("authorization_endpoint", "");
    cfg.token_endpoint = j.value("token_endpoint", "");
    cfg.jwks_uri = j.value("jwks_uri", "");
    // The four §12 cannot work without. The optional endpoints stay unset and
    // the operations that need them say so by name — a server without an
    // `end_session_endpoint` should fail at logout_url(), not at discovery,
    // which every other operation depends on.
    if (cfg.issuer.empty() || cfg.authorization_endpoint.empty() ||
        cfg.token_endpoint.empty() || cfg.jwks_uri.empty()) {
        throw NetworkError(
            "oidc discovery: missing issuer / authorization_endpoint / token_endpoint / jwks_uri",
            "malformed_body");
    }
    cfg.userinfo_endpoint = opt_string(j, "userinfo_endpoint");
    cfg.introspection_endpoint = opt_string(j, "introspection_endpoint");
    cfg.revocation_endpoint = opt_string(j, "revocation_endpoint");
    cfg.end_session_endpoint = opt_string(j, "end_session_endpoint");
    cfg.device_authorization_endpoint = opt_string(j, "device_authorization_endpoint");
    cfg.scopes_supported = string_array(j, "scopes_supported");
    cfg.response_types_supported = string_array(j, "response_types_supported");
    cfg.id_token_signing_alg_values_supported =
        string_array(j, "id_token_signing_alg_values_supported");

    p_->oidc_config = cfg;
    p_->oidc_config_expires_at = std::chrono::steady_clock::now() + p_->oidc_discovery_ttl;
    return cfg;
}

// ---------------------------------------------------------------------------
// §12.1 oidc_begin — PKCE, state, nonce. No network I/O.
// ---------------------------------------------------------------------------

AuthorizationRequest Client::oidc_begin(const OidcConfiguration& config,
                                        const std::string& redirect_uri,
                                        std::optional<std::string> scope) {
    // NO ensure_open() and no transport acquisition: §12.6 makes oidc_begin
    // synchronous and network-free in this SDK specifically, so it must keep
    // working on a client whose transport has been released.
    if (config.authorization_endpoint.empty() || redirect_uri.empty()) {
        throw NetworkError("oidc_begin requires a discovery document and a redirect_uri",
                           "invalid_argument");
    }
    const std::string& client_id = require_client_id(*p_, "oidc_begin");

    AuthorizationRequest req;
    req.state = random_b64url();
    req.nonce = random_b64url();
    const std::string verifier = random_b64url();
    const std::string challenge = s256_challenge(verifier);

    // §12.1 rule 4: the scope MUST contain `openid`; the helper adds it when the
    // caller omits it. WHOLE-TOKEN matching — a substring test would see
    // `openid` inside `openid_connect_admin` and skip the addition, producing an
    // authorization request the OP treats as plain OAuth2, with no ID token and
    // therefore no §12.4 validation at all. That failure is silent until
    // something downstream reads id_claims and finds nothing.
    std::string scopes = scope.value_or(std::string{});
    {
        bool has_openid = false;
        std::size_t at = 0;
        while (at <= scopes.size()) {
            const auto sp = scopes.find(' ', at);
            const auto len = (sp == std::string::npos ? scopes.size() : sp) - at;
            if (scopes.compare(at, len, "openid") == 0) { has_openid = true; break; }
            if (sp == std::string::npos) break;
            at = sp + 1;
        }
        if (!has_openid) scopes = scopes.empty() ? "openid" : ("openid " + scopes);
    }

    // §12.1 rule 5: exactly these eight parameters, and none of the SDK's own.
    // The endpoint comes from the discovery document, never hardcoded.
    Form q;
    q.add("response_type", "code");
    q.add("client_id", client_id);
    q.add("redirect_uri", redirect_uri);
    q.add("scope", scopes);
    q.add("state", req.state);
    q.add("nonce", req.nonce);
    q.add("code_challenge", challenge);
    q.add("code_challenge_method", "S256");

    req.url = config.authorization_endpoint;
    req.url += (req.url.find('?') == std::string::npos) ? '?' : '&';
    req.url += q.str();
    // From here the verifier lives only behind the wrapper (§12.5 — secret for
    // its whole lifetime, including while it sits in this result).
    req.code_verifier = Sensitive<std::string>(verifier);
    return req;
}

// ---------------------------------------------------------------------------
// §12.4 ID-token validation
// ---------------------------------------------------------------------------

namespace {

/// §12.4 rule 4. `aud` must contain the RP's client_id; when it holds MORE THAN
/// ONE audience, `azp` must be present and equal to that client_id.
bool audience_ok(const std::vector<std::string>& aud,
                 const std::optional<std::string>& azp, const std::string& client_id) {
    if (std::find(aud.begin(), aud.end(), client_id) == aud.end()) return false;
    if (aud.size() > 1) return azp && *azp == client_id;
    return true;
}

/// Rules 3 to 6 against an already-signature-verified claim set.
///
/// `expected_nonce` unset means rule 6 is skipped, which is correct for
/// `oidc_refresh`, `login_client_credentials` and `device_poll` — OIDC Core
/// §12.2 does not require a nonce in a refresh-issued ID token, and those flows
/// had no authorization request to carry one. It is NEVER unset for
/// `oidc_exchange`, where rule 6 is mandatory.
IdTokenClaims check_id_claims(const Client::Impl& impl, const json& j,
                              const OidcConfiguration& config,
                              const std::optional<std::string>& expected_nonce,
                              const std::string& raw_payload) {
    const std::string& client_id = require_client_id(impl, "oidc id_token validation");

    // Rule 3: EXACT string comparison against the discovery document's issuer.
    // No normalization, no trailing-slash tolerance, no prefix matching — each
    // of those has been an OP-confusion CVE somewhere.
    const auto iss = opt_string(j, "iss");
    if (!iss || *iss != config.issuer) {
        throw OidcValidationError("id_token iss does not equal the discovery document's issuer",
                                  OidcValidationReason::kInvalidIssuer);
    }

    // Rule 4.
    const auto aud = string_array(j, "aud");
    const auto azp = opt_string(j, "azp");
    if (!audience_ok(aud, azp, client_id)) {
        throw OidcValidationError(
            "id_token aud does not name this client (or azp is missing on a "
            "multi-audience token)",
            OidcValidationReason::kInvalidAudience);
    }

    // Rule 5. `exp` and `iat` are BOTH required (contract 1.5 clarified that an
    // ID token missing either is rejected), and EVERY failure of this rule —
    // past exp, absent exp, absent or future iat, future nbf — reports the
    // single code `token_expired`. The vocabulary is closed at seven; there is
    // no `missing_exp` and no `token_not_yet_valid` to reach for.
    const std::int64_t now = now_seconds();
    const std::int64_t skew = clock_skew(impl);
    const auto exp = opt_int(j, "exp");
    const auto iat = opt_int(j, "iat");
    if (!exp) {
        throw OidcValidationError("id_token has no usable exp claim",
                                  OidcValidationReason::kTokenExpired);
    }
    if (now > *exp + skew) {
        throw OidcValidationError("id_token has expired", OidcValidationReason::kTokenExpired);
    }
    if (!iat) {
        throw OidcValidationError("id_token has no usable iat claim",
                                  OidcValidationReason::kTokenExpired);
    }
    if (*iat > now + skew) {
        throw OidcValidationError("id_token was issued in the future",
                                  OidcValidationReason::kTokenExpired);
    }
    if (j.contains("nbf")) {
        const auto nbf = opt_int(j, "nbf");
        // An `nbf` the SDK cannot read is not the same as no `nbf`: honouring it
        // means honouring it.
        if (!nbf || *nbf > now + skew) {
            throw OidcValidationError("id_token is not yet valid",
                                      OidcValidationReason::kTokenExpired);
        }
    }

    // Rule 6.
    if (expected_nonce) {
        const auto nonce = opt_string(j, "nonce");
        if (!nonce || !ct_equal(*nonce, *expected_nonce)) {
            throw OidcValidationError(
                "id_token nonce is absent or does not match the one oidc_begin produced",
                OidcValidationReason::kNonceMismatch);
        }
    }

    IdTokenClaims claims;
    claims.subject = j.value("sub", "");
    claims.issuer = *iss;
    claims.audience = aud;
    claims.expires_at = *exp;
    claims.issued_at = *iat;
    claims.nonce = opt_string(j, "nonce");
    claims.authorized_party = azp;
    claims.email = opt_string(j, "email");
    claims.preferred_username = opt_string(j, "preferred_username");
    claims.tenant_id = opt_string(j, "tenant_id");
    claims.roles = string_array(j, "roles");
    // §12.1: preserve every further claim the server sent. `openapi.json` types
    // the ID token as an opaque string, so the claim set is not enumerable and
    // an SDK MUST NOT reject what it does not recognise.
    claims.raw_claims_json = raw_payload;
    return claims;
}

}  // namespace

// ---------------------------------------------------------------------------
// The token-endpoint grants
// ---------------------------------------------------------------------------

namespace {

/// One `POST /oauth2/token?tenant_id=<uuid>`, form-encoded.
///
/// `retryable` is false for every grant §16.2 names ineligible. It is a
/// parameter rather than a constant so `device_poll` — the one token-endpoint
/// call that section DOES allow to retry, on a 5xx or transport failure — can
/// share this body instead of forking it.
std::string token_grant(Client::Impl& impl, const OidcConfiguration& config,
                        const std::string& tenant, const Form& form, bool retryable,
                        const std::string& context) {
    const std::string url = with_tenant(config.token_endpoint, tenant);

    HttpRequest req;
    req.method = "POST";
    req.url = url;
    req.headers["X-Tenant-ID"] = impl.tenant_header;  // §5 rule 2, unconditional
    req.headers["Accept"] = "application/json";
    // §12.1 rule 1: form-encoded, not JSON. An SDK that posts JSON here is
    // non-conformant. §12.1 note 8: /oauth2 is unauthenticated, so no
    // `axiam_csrf` cookie exists yet — §3 step 3 says omit the header rather
    // than invent a value, so none is added. §12.1 rule 3: client_secret_post,
    // so no Authorization header either.
    req.headers["Content-Type"] = "application/x-www-form-urlencoded";
    req.body = form.str();

    const int budget = (retryable && impl.retry_enabled) ? detail::kRetryMaxAttempts : 1;
    HttpResponse resp;
    for (int attempt = 1; attempt <= budget; ++attempt) {
        resp = impl.send_raw(req);
        if (attempt == budget) break;
        const std::optional<long> status =
            resp.transport_error.empty() ? std::optional<long>(resp.status) : std::nullopt;
        if (!detail::retry_should_retry(status)) break;
        const auto hint = resp.headers.find("Retry-After");
        impl.sleeper(detail::retry_delay(
            attempt,
            hint == resp.headers.end() ? std::nullopt
                                       : detail::retry_after_from_header(hint->second),
            impl.jitter()));
    }

    if (!resp.transport_error.empty()) {
        throw NetworkError(context + ": " + resp.transport_error, resp.transport_error);
    }
    if (resp.status < 200 || resp.status >= 300) raise_grant_error(resp, context);
    return resp.body;
}

/// Parse a `TokenResponse` and, when it carries an `id_token`, validate it
/// against every §12.4 rule before returning.
///
/// **All-or-nothing (§12.4 rule 7)**, and the reason the validation runs before
/// anything is assembled: the access and refresh tokens in this same response
/// are discarded with the ID token. There is no partial success, and "the access
/// token was probably fine" is exactly the reasoning that turns a failed
/// audience check into a live session for the wrong relying party.
OidcTokenSet parse_token_set(Client::Impl& impl, const std::string& body,
                             const OidcConfiguration& config,
                             const std::optional<std::string>& expected_nonce) {
    const json j = parse_or_object(body);
    const auto access = opt_string(j, "access_token");
    if (!access) {
        throw NetworkError("malformed TokenResponse (missing access_token)", "malformed_body");
    }

    OidcTokenSet set;
    const auto id_token = opt_string(j, "id_token");
    if (id_token) {
        const JwtVerification v = impl.jwks_verifier->verify_with_reason(*id_token);
        if (!v.ok) {
            // Rules 1 and 2, from the verifier the §10 authenticator already
            // uses — §12.4 says to extend it, never fork it.
            throw OidcValidationError("id_token signature verification failed", v.reason);
        }
        const json claims_json = parse_or_object(v.payload_json);
        if (!claims_json.is_object()) {
            throw OidcValidationError("id_token payload is not a JSON object",
                                      OidcValidationReason::kInvalidSignature);
        }
        set.id_claims = check_id_claims(impl, claims_json, config, expected_nonce, v.payload_json);
        set.id_token = Sensitive<std::string>(*id_token);
    }

    set.access_token = Sensitive<std::string>(*access);
    set.token_type = opt_string(j, "token_type").value_or("Bearer");
    set.expires_in = opt_int(j, "expires_in").value_or(0);
    set.scope = opt_string(j, "scope");
    if (const auto refresh = opt_string(j, "refresh_token")) {
        set.refresh_token = Sensitive<std::string>(*refresh);
    }
    return set;
}

/// Add `client_id` plus, when the client is confidential, `client_secret`
/// (client_secret_post — §12.1 rule 3 forbids HTTP Basic on the /oauth2 paths).
/// A public client sends no secret field at all.
void add_client_auth(const Client::Impl& impl, Form& form, const std::string& client_id) {
    form.add("client_id", client_id);
    if (impl.oidc_client_secret) {
        form.add("client_secret", detail::reveal(*impl.oidc_client_secret));
    }
}

}  // namespace

OidcTokenSet Client::oidc_exchange(const OidcExchangeParams& params) {
    p_->ensure_open();
    if (params.code.empty() || params.redirect_uri.empty() ||
        detail::reveal(params.code_verifier).empty()) {
        throw AuthError(
            "oidc_exchange requires code, code_verifier and the same redirect_uri the "
            "authorization request carried");
    }
    if (params.nonce.empty()) {
        // §12.4 rule 6 is MANDATORY for this operation: the helper always
        // requests `openid`, so the server always issues a nonce, and a caller
        // with nothing to compare against has silently lost replay protection.
        // Refusing here is louder than skipping the check.
        throw AuthError(
            "oidc_exchange requires the nonce oidc_begin produced "
            "(CONTRACT.md §12.4 rule 6 is mandatory here)");
    }
    const std::string& client_id = require_client_id(*p_, "oidc_exchange");
    const std::string tenant = require_tenant_uuid(*p_, params.tenant_id, "oidc_exchange");
    const OidcConfiguration config = oidc_discover();

    Form form;
    form.add("grant_type", "authorization_code");
    form.add("code", params.code);
    form.add("code_verifier", detail::reveal(params.code_verifier));
    form.add("redirect_uri", params.redirect_uri);
    add_client_auth(*p_, form, client_id);

    // NOT retryable (§16.2): the authorization code is consumed by the attempt.
    const std::string body =
        token_grant(*p_, config, tenant, form, /*retryable=*/false, "oidc exchange failed");
    return parse_token_set(*p_, body, config, params.nonce);
}

OidcTokenSet Client::login_client_credentials(std::optional<std::string> scope,
                                              std::optional<std::string> tenant_id) {
    p_->ensure_open();
    const std::string& client_id = require_client_id(*p_, "login_client_credentials");
    const std::string& secret = require_client_secret(*p_, "login_client_credentials");
    const std::string tenant = require_tenant_uuid(*p_, tenant_id, "login_client_credentials");
    const OidcConfiguration config = oidc_discover();

    Form form;
    form.add("grant_type", "client_credentials");
    form.add("client_id", client_id);
    form.add("client_secret", secret);
    // Optional — and omitted rather than sent empty. A SERVICE ACCOUNT registers
    // no scopes at all, so asking for one answers `invalid_scope` (§12.1).
    form.add("scope", scope);

    const std::string body = token_grant(*p_, config, tenant, form, /*retryable=*/false,
                                         "client credentials login failed");
    // §12.4 rule 6 is skipped: this grant requests no `openid` scope and had no
    // authorization request to carry a nonce. Rules 1-5 and 7 still apply to any
    // id_token that arrives anyway.
    //
    // Nothing below touches client state — §12.1's adoption MAY, declined.
    return parse_token_set(*p_, body, config, std::nullopt);
}

OidcTokenSet Client::oidc_refresh(const Sensitive<std::string>& refresh_token,
                                  std::optional<std::string> scope,
                                  std::optional<std::string> tenant_id) {
    p_->ensure_open();
    const std::string& raw = detail::reveal(refresh_token);
    if (raw.empty()) throw AuthError("oidc_refresh requires a refresh token");
    const std::string& client_id = require_client_id(*p_, "oidc_refresh");
    const std::string tenant = require_tenant_uuid(*p_, tenant_id, "oidc_refresh");
    const std::string key = digest_hex(raw);

    std::shared_ptr<Client::Impl::OidcRefreshFlight> flight;
    bool leader = false;
    {
        std::unique_lock<std::mutex> lock(p_->oidc_refresh_mtx);
        auto it = p_->oidc_refresh_flights.find(key);
        if (it != p_->oidc_refresh_flights.end()) {
            // A FOLLOWER. It issues no request of its own and shares the
            // leader's one outcome — the observable §9 rule 2 requires, and the
            // reason the assertion for this is a wire-call COUNT rather than a
            // check that the helper exists.
            flight = it->second;
            p_->oidc_refresh_cv.wait(lock, [&] { return flight->done; });
            if (flight->error) std::rethrow_exception(flight->error);
            return *flight->result;
        }
        flight = std::make_shared<Client::Impl::OidcRefreshFlight>();
        p_->oidc_refresh_flights.emplace(key, flight);
        leader = true;
    }
    (void)leader;

    const auto publish = [&](std::exception_ptr err, std::optional<OidcTokenSet> result) {
        std::lock_guard<std::mutex> lock(p_->oidc_refresh_mtx);
        // UNLINK BEFORE PUBLISHING. A caller arriving after this point must
        // start a fresh flight rather than attach to a finished one: the token
        // this flight redeemed is now spent, and handing its result to a later
        // caller would be a cache, not a coalesce — with no TTL and no
        // invalidation.
        p_->oidc_refresh_flights.erase(key);
        flight->error = std::move(err);
        flight->result = std::move(result);
        flight->done = true;
        p_->oidc_refresh_count.fetch_add(1);
        p_->oidc_refresh_cv.notify_all();
    };

    try {
        const OidcConfiguration config = oidc_discover();
        Form form;
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", raw);
        add_client_auth(*p_, form, client_id);
        form.add("scope", scope);

        // NOT retryable. §16.2 disqualifies it twice over — a rotating refresh
        // token is single-use — and §9 rule 3 already forbids a retry loop here
        // by name. §16 does not amend §9.
        const std::string body =
            token_grant(*p_, config, tenant, form, /*retryable=*/false, "oidc refresh failed");
        OidcTokenSet set = parse_token_set(*p_, body, config, std::nullopt);
        publish(nullptr, set);
        return set;
    } catch (...) {
        // The other half of §9 rule 2: "that ONE OUTCOME shared with every
        // concurrent caller" — outcome, not success. A guard that only shared
        // successes would leave the followers to make their own requests and
        // collect a second, differently-worded refusal each.
        publish(std::current_exception(), std::nullopt);
        throw;
    }
}

// ---------------------------------------------------------------------------
// §12.1 introspect / revoke
// ---------------------------------------------------------------------------

namespace {

/// Both are `POST` + form + `?tenant_id=`, both confidential-only, and both map
/// a 401 straight to an auth error WITHOUT entering the §9 refresh guard
/// (§12.3 rule 3: a wrong client secret is not a session expiry, and refreshing
/// cannot help). One shared body keeps that property from drifting.
std::string token_admin_call(Client::Impl& impl, const OidcConfiguration& config,
                             const std::optional<std::string>& discovered,
                             const char* fallback_path, const Sensitive<std::string>& token,
                             const std::optional<std::string>& token_type_hint,
                             const std::string& tenant, const char* operation, bool retryable) {
    if (detail::reveal(token).empty()) {
        throw AuthError(std::string(operation) + " requires a token");
    }
    const std::string& client_id = require_client_id(impl, operation);
    const std::string& secret = require_client_secret(impl, operation);

    // The document advertises both endpoints; the fallback exists only for a
    // deployment whose discovery omits one, and is joined onto the CLIENT'S BASE
    // URL rather than onto the issuer — §12.7.2 rule 1 makes the same point
    // about `end_session_endpoint`, and the reasoning is identical: the issuer
    // may legitimately be some other origin behind a proxy.
    const std::string endpoint =
        (discovered && !discovered->empty()) ? *discovered : (impl.base_url + fallback_path);

    Form form;
    form.add("token", detail::reveal(token));
    form.add("token_type_hint", token_type_hint);
    form.add("client_id", client_id);
    form.add("client_secret", secret);

    HttpRequest req;
    req.method = "POST";
    req.url = with_tenant(endpoint, tenant);
    req.headers["X-Tenant-ID"] = impl.tenant_header;
    req.headers["Accept"] = "application/json";
    req.headers["Content-Type"] = "application/x-www-form-urlencoded";
    req.body = form.str();

    const int budget = (retryable && impl.retry_enabled) ? detail::kRetryMaxAttempts : 1;
    HttpResponse resp;
    for (int attempt = 1; attempt <= budget; ++attempt) {
        resp = impl.send_raw(req);
        if (attempt == budget) break;
        const std::optional<long> status =
            resp.transport_error.empty() ? std::optional<long>(resp.status) : std::nullopt;
        if (!detail::retry_should_retry(status)) break;
        const auto hint = resp.headers.find("Retry-After");
        impl.sleeper(detail::retry_delay(
            attempt,
            hint == resp.headers.end() ? std::nullopt
                                       : detail::retry_after_from_header(hint->second),
            impl.jitter()));
    }

    if (!resp.transport_error.empty()) {
        throw NetworkError(std::string(operation) + " failed: " + resp.transport_error,
                           resp.transport_error);
    }
    if (resp.status < 200 || resp.status >= 300) {
        raise_grant_error(resp, std::string(operation) + " failed");
    }
    (void)config;
    return resp.body;
}

}  // namespace

IntrospectionResult Client::introspect(const Sensitive<std::string>& token,
                                       std::optional<std::string> token_type_hint,
                                       std::optional<std::string> tenant_id) {
    p_->ensure_open();
    const std::string tenant = require_tenant_uuid(*p_, tenant_id, "introspect");
    const OidcConfiguration config = oidc_discover();
    // §16.2 lists introspection as eligible — it is a read ABOUT a token and
    // mints nothing.
    const std::string body =
        token_admin_call(*p_, config, config.introspection_endpoint, "/oauth2/introspect", token,
                         token_type_hint, tenant, "introspect", /*retryable=*/true);

    const json j = parse_or_object(body);
    IntrospectionResult r;
    // `active` is the only guaranteed field: an inactive token answers
    // {"active":false} and nothing else, which is the point of RFC 7662.
    r.active = j.contains("active") && j["active"].is_boolean() && j["active"].get<bool>();
    r.scope = opt_string(j, "scope");
    r.client_id = opt_string(j, "client_id");
    r.username = opt_string(j, "username");
    r.token_type = opt_string(j, "token_type");
    r.subject = opt_string(j, "sub");
    r.audience = opt_string(j, "aud");
    r.issuer = opt_string(j, "iss");
    r.jwt_id = opt_string(j, "jti");
    r.expires_at = opt_int(j, "exp");
    r.issued_at = opt_int(j, "iat");
    return r;
}

void Client::revoke(const Sensitive<std::string>& token,
                    std::optional<std::string> token_type_hint,
                    std::optional<std::string> tenant_id) {
    p_->ensure_open();
    const std::string tenant = require_tenant_uuid(*p_, tenant_id, "revoke");
    const OidcConfiguration config = oidc_discover();
    // retryable=false: revocation is a mutation, and §16.2 names `oidc_revoke`
    // explicitly among the ineligible operations.
    //
    // §12.1 rule 5: any 2xx is success, INCLUDING for a token the server has
    // never issued — RFC 7009 answers 200 for unknown, expired and
    // already-revoked tokens, and that idempotence is the point of the endpoint.
    // A 5xx is still a failure: returning void does not turn a server error into
    // a success (the correction contract 1.5 made to 1.4), and token_admin_call
    // throws on one.
    (void)token_admin_call(*p_, config, config.revocation_endpoint, "/oauth2/revoke", token,
                           token_type_hint, tenant, "revoke", /*retryable=*/false);
}

// ---------------------------------------------------------------------------
// §12.1 sso_start / sso_complete
// ---------------------------------------------------------------------------

SsoStartResult Client::sso_start(const std::string& federation_config_id,
                                 const std::string& redirect_uri) {
    p_->ensure_open();
    json body;
    body["federation_config_id"] = federation_config_id;
    body["redirect_uri"] = redirect_uri;
    // §5.1: one tenant form and one org form, whichever this client carries.
    // Slugs are valid here — unlike the five /oauth2 operations, this pair
    // carries context in the JSON body rather than a UUID query parameter.
    if (p_->tenant_id) body["tenant_id"] = *p_->tenant_id;
    else if (p_->tenant_slug) body["tenant_slug"] = *p_->tenant_slug;
    if (p_->org_id) body["org_id"] = *p_->org_id;
    else if (p_->org_slug) body["org_slug"] = *p_->org_slug;

    const HttpResponse resp =
        p_->execute("POST", "/api/v1/auth/federation/oidc/start", body.dump(),
                    /*allow_refresh=*/false);
    const json j = parse_or_object(resp.body);
    SsoStartResult r;
    const auto url = opt_string(j, "authorize_url");
    const auto state = opt_string(j, "state");
    if (!url || !state) {
        throw NetworkError("sso start: malformed OidcStartResponse", "malformed_body");
    }
    r.authorize_url = *url;
    r.state = *state;
    r.expires_in_secs = opt_int(j, "expires_in_secs").value_or(0);
    // §12.1 note 7: there is no nonce here and the SDK must not synthesise one —
    // the federation nonce never leaves the server. `state` round-trips
    // unmodified into sso_complete.
    return r;
}

SsoCompleteResult Client::sso_complete(const std::string& code, const std::string& state) {
    p_->ensure_open();
    json body;
    body["code"] = code;
    body["state"] = state;

    const HttpResponse resp =
        p_->execute("POST", "/api/v1/auth/federation/oidc/callback", body.dump(),
                    /*allow_refresh=*/false);
    const json j = parse_or_object(resp.body);
    SsoCompleteResult r;
    const auto user_id = opt_string(j, "user_id");
    const auto session_id = opt_string(j, "session_id");
    if (!user_id || !session_id) {
        throw NetworkError("sso complete: malformed SsoLoginSuccessResponse", "malformed_body");
    }
    r.user_id = *user_id;
    r.session_id = *session_id;
    r.expires_in = opt_int(j, "expires_in").value_or(0);
    r.redirect_uri = opt_string(j, "redirect_uri");
    // §12.1 note 6: no token material comes back — the session is a Set-Cookie
    // the §4 cookie jar keeps. A transport without cookie support loses it
    // silently, which is why §4 is a requirement rather than a suggestion.
    return r;
}

// ---------------------------------------------------------------------------
// §12.7.3 verify_logout_token
// ---------------------------------------------------------------------------

VerifiedLogoutToken Client::verify_logout_token(const std::string& logout_token) {
    p_->ensure_open();
    if (logout_token.empty()) throw AuthError("verify_logout_token requires a token");
    const std::string& client_id = require_client_id(*p_, "verify_logout_token");

    // Rule 1: the signature goes through the SAME §12.4 verifier the RP already
    // uses. No second key-fetching path, so key rotation, the EdDSA pin and the
    // unknown-`kid` cooldown all behave identically here.
    const JwtVerification v = p_->jwks_verifier->verify_with_reason(logout_token);
    if (!v.ok) {
        // Rule 8: the error names the failure, never the token.
        throw OidcValidationError("logout token signature verification failed", v.reason);
    }
    const json j = parse_or_object(v.payload_json);
    if (!j.is_object()) {
        throw AuthError("logout token payload is not a JSON object");
    }

    const OidcConfiguration config = oidc_discover();
    const auto iss = opt_string(j, "iss");
    if (!iss || *iss != config.issuer) {
        throw AuthError("logout token iss does not match the discovered issuer");
    }
    // Rule 2: a token minted for another RP must not be accepted here.
    const auto aud = string_array(j, "aud");
    if (std::find(aud.begin(), aud.end(), client_id) == aud.end()) {
        throw AuthError("logout token aud does not name this client");
    }

    // Rule 3. Without this an SDK accepts a replayed ID token as a logout
    // instruction: an ID token has every other property this function checks.
    if (!j.contains("events") || !j["events"].is_object() ||
        !j["events"].contains(kBackchannelLogoutEvent) ||
        !j["events"][kBackchannelLogoutEvent].is_object()) {
        throw AuthError(
            "logout token has no backchannel-logout events member "
            "(CONTRACT.md §12.7.3 rule 3)");
    }

    // Rule 4. REJECT, do not ignore — Back-Channel Logout 1.0 §2.4 forbids a
    // nonce, and its presence is the documented signature of the replay above.
    if (j.contains("nonce")) {
        throw AuthError(
            "logout token carries a nonce, which Back-Channel Logout 1.0 §2.4 forbids "
            "(CONTRACT.md §12.7.3 rule 4)");
    }

    // Rule 6. AXIAM issues a 120 s lifetime; the same tolerance the ID-token
    // path uses applies.
    const auto exp = opt_int(j, "exp");
    if (!exp || now_seconds() > *exp + clock_skew(*p_)) {
        throw AuthError("logout token has expired or carries no usable exp");
    }

    VerifiedLogoutToken out;
    out.sid = opt_string(j, "sid");
    out.subject = opt_string(j, "sub");
    if (!out.sid && !out.subject) {
        // Rule 5: a token naming neither identifies nothing.
        throw AuthError("logout token names neither sid nor sub");
    }
    // Rule 7: surfaced so the RP can dedup. This SDK deliberately does NOT dedup
    // internally — delivery is at-least-once, so a valid token legitimately
    // arrives twice, and a library with no durable store would silently drop a
    // real second logout after a restart. Verifying the same token twice
    // therefore succeeds both times, on purpose.
    out.jwt_id = opt_string(j, "jti");
    out.issuer = *iss;
    out.issued_at = opt_int(j, "iat").value_or(0);
    return out;
}

// ---------------------------------------------------------------------------
// §14 device authorization grant
// ---------------------------------------------------------------------------

DeviceAuthorization Client::device_authorize(std::optional<std::string> scope,
                                             std::optional<std::string> tenant_id) {
    p_->ensure_open();
    const std::string& client_id = require_client_id(*p_, "device_authorize");
    const std::string tenant = require_tenant_uuid(*p_, tenant_id, "device_authorize");
    const OidcConfiguration config = oidc_discover();
    if (!config.device_authorization_endpoint) {
        throw NetworkError("the discovery document advertises no device_authorization_endpoint",
                           "missing_endpoint");
    }

    Form form;
    // ONLY client_id. §14.1 is explicit on both halves: a device that cannot
    // show a browser also cannot hold a client secret, so an SDK MUST NOT send
    // one here AND MUST NOT refuse to call this from a client constructed
    // without one. Note that this deliberately does not route through
    // add_client_auth(), which would attach a configured secret.
    form.add("client_id", client_id);
    form.add("scope", scope);

    HttpRequest req;
    req.method = "POST";
    req.url = with_tenant(*config.device_authorization_endpoint, tenant);
    req.headers["X-Tenant-ID"] = p_->tenant_header;
    req.headers["Accept"] = "application/json";
    req.headers["Content-Type"] = "application/x-www-form-urlencoded";
    req.body = form.str();

    // §16.2 names `device_authorize` ineligible: it mints a device code, and a
    // silent retry would strand a first one the user might already be typing.
    const HttpResponse resp = p_->send_raw(req);
    if (!resp.transport_error.empty()) {
        throw NetworkError("device authorization failed: " + resp.transport_error,
                           resp.transport_error);
    }
    if (resp.status < 200 || resp.status >= 300) {
        raise_grant_error(resp, "device authorization failed");
    }

    const json j = parse_or_object(resp.body);
    const auto device_code = opt_string(j, "device_code");
    const auto user_code = opt_string(j, "user_code");
    const auto verification_uri = opt_string(j, "verification_uri");
    if (!device_code || !user_code || !verification_uri) {
        throw NetworkError("malformed DeviceAuthorizationResponse", "malformed_body");
    }

    DeviceAuthorization out;
    // §14.5: the device code is a bearer credential for the life of the grant
    // and is wrapped; the user code is NOT, because it exists to be read aloud
    // and typed, and wrapping it would defeat that.
    out.device_code = Sensitive<std::string>(*device_code);
    out.user_code = *user_code;
    out.verification_uri = *verification_uri;
    // §14.3: surfaced when present, and NEVER synthesised by concatenation when
    // absent — its format is the server's to choose.
    out.verification_uri_complete = opt_string(j, "verification_uri_complete");
    out.expires_in = opt_int(j, "expires_in").value_or(0);
    // §14.2 rule 2: from the RESPONSE, with RFC 8628 §3.2's 5 s as the only
    // fallback. No faster floor.
    const auto interval = opt_int(j, "interval");
    out.interval = (interval && *interval > 0) ? *interval : kDeviceDefaultIntervalSeconds;
    return out;
}

namespace {

OidcTokenSet device_poll_with(Client::Impl& impl, const OidcConfiguration& config,
                              const std::string& device_code, const std::string& client_id,
                              const std::string& tenant) {
    Form form;
    form.add("grant_type", kDeviceCodeGrantType);
    form.add("device_code", device_code);
    form.add("client_id", client_id);
    // A device client is public by definition (see device_authorize), but a
    // confidential one driving the same grant must still authenticate — the
    // secret goes out only when one is configured.
    if (impl.oidc_client_secret) {
        form.add("client_secret", detail::reveal(*impl.oidc_client_secret));
    }

    // retryable=true, and this is the ONE token-endpoint call §16.2 allows it
    // for: a 5xx or transport failure mid-poll is not terminal, because a server
    // restart must not lose a grant the user has already approved. That budget
    // is per poll ATTEMPT and does not consume the grant's own `expires_in`
    // loop.
    const std::string body =
        token_grant(impl, config, tenant, form, /*retryable=*/true, "device poll failed");
    // §12.4 rules 1-5 and 7 apply to any id_token; rule 6 is skipped — there was
    // no authorization request in this flow to carry a nonce.
    return parse_token_set(impl, body, config, std::nullopt);
}

}  // namespace

OidcTokenSet Client::device_poll(const Sensitive<std::string>& device_code,
                                 std::optional<std::string> tenant_id) {
    p_->ensure_open();
    const std::string& raw = detail::reveal(device_code);
    if (raw.empty()) throw AuthError("device_poll requires a device code");
    const std::string& client_id = require_client_id(*p_, "device_poll");
    const std::string tenant = require_tenant_uuid(*p_, tenant_id, "device_poll");
    const OidcConfiguration config = oidc_discover();
    return device_poll_with(*p_, config, raw, client_id, tenant);
}

OidcTokenSet Client::device_login(DeviceCodeDisplay display, std::optional<std::string> scope,
                                  std::optional<std::string> tenant_id) {
    p_->ensure_open();
    const DeviceAuthorization authorization = device_authorize(scope, tenant_id);

    // §14.3 rule 2: the caller gets the codes BEFORE the first poll, always. An
    // SDK must not print them to stdout on the caller's behalf — a device shows
    // them however it can, and only the application knows how.
    if (display) display(authorization);

    const std::string& client_id = require_client_id(*p_, "device_login");
    const std::string tenant = require_tenant_uuid(*p_, tenant_id, "device_login");
    const OidcConfiguration config = oidc_discover();
    const std::string device_code = detail::reveal(authorization.device_code);

    std::int64_t interval = authorization.interval;
    const auto deadline = now_seconds() + authorization.expires_in;

    for (;;) {
        // §14.2 rule 4, and the subtlety that makes it worth a comment: it is
        // the NEXT ATTEMPT that must fall inside the deadline, not the current
        // moment. Checking `now < deadline` before sleeping looks equivalent and
        // is not — after a `slow_down` takes the interval past the time
        // remaining, that check passes, the loop sleeps through the deadline,
        // and polls anyway. That request is exactly the "pure load" this rule
        // exists to prevent.
        if (now_seconds() + interval >= deadline) {
            throw OAuthProtocolError(
                "expired_token: the device grant expired before the user approved it",
                "expired_token", std::nullopt);
        }
        p_->sleeper(std::chrono::milliseconds(interval * 1000));

        try {
            return device_poll_with(*p_, config, device_code, client_id, tenant);
        } catch (const OAuthProtocolError& e) {
            const std::string& code = e.error_code();
            if (code == "authorization_pending") continue;
            if (code == "slow_down") {
                // Rule 1: permanent, cumulative, never reset. An SDK that backed
                // off for one round and returned to the original rate would be
                // told to slow down again, forever.
                interval += kDeviceSlowDownIncrementSeconds;
                continue;
            }
            // access_denied, expired_token, invalid_grant — and anything else
            // the server names. All terminal, each surfacing with its own code
            // intact (rule 3: the two refusals stay distinguishable).
            throw;
        } catch (const NetworkError&) {
            // §14.2 rule 6: a 5xx or transport failure is not terminal — it has
            // already been through the §16 bounded retry inside the poll, and a
            // server restart mid-flow must not lose a grant the user already
            // approved.
            continue;
        }
    }
    // §14.3 rule 4: the token set is RETURNED, not adopted — the same posture
    // login_client_credentials() takes, which that rule requires an SDK to match
    // rather than inventing a second one.
}

// ---------------------------------------------------------------------------
// §15 token exchange
// ---------------------------------------------------------------------------

ExchangedToken Client::token_exchange(const TokenExchangeParams& params) {
    p_->ensure_open();
    const std::string& subject = detail::reveal(params.subject_token);
    if (subject.empty()) throw AuthError("token_exchange requires a subject_token");
    const std::string& client_id = require_client_id(*p_, "token_exchange");
    // §15.1: the exchanging client authenticates — unlike §14's device, this is
    // a confidential service.
    const std::string& secret = require_client_secret(*p_, "token_exchange");
    const std::string tenant = require_tenant_uuid(*p_, params.tenant_id, "token_exchange");
    const OidcConfiguration config = oidc_discover();

    Form form;
    form.add("grant_type", kTokenExchangeGrantType);
    form.add("subject_token", subject);
    form.add("subject_token_type", kAccessTokenType);
    // §15.2 rule 1. The presence of an actor token selects DELEGATION; its
    // absence selects IMPERSONATION. Two different operations with different
    // risk, and this SDK supplies no default and never substitutes the client's
    // own session — passing nothing here asks for impersonation, and the server
    // refuses unless this client holds that grant. An EMPTY actor token is not
    // an actor token and must not flip the request.
    if (params.actor_token && !detail::reveal(*params.actor_token).empty()) {
        form.add("actor_token", detail::reveal(*params.actor_token));
        form.add("actor_token_type", kAccessTokenType);
    }
    if (!params.scopes.empty()) {
        std::string joined;
        for (const auto& s : params.scopes) {
            if (s.empty()) continue;
            if (!joined.empty()) joined.push_back(' ');
            joined += s;
        }
        form.add("scope", joined);
    }
    form.add("audience", params.audience);
    form.add("resource", params.resource);
    form.add("client_id", client_id);
    form.add("client_secret", secret);

    // retryable=false: §16.2 names `token_exchange` ineligible outright.
    // Combined with §15.2 rule 2 that means a refusal is surfaced verbatim — no
    // retry, no downgrade, no rewriting the request into a delegation the caller
    // never wrote. §15.3: a cross-tenant subject token answers `invalid_grant`
    // and this SDK does not try to refine it; the server collapses "wrong
    // tenant" into "bad token" because telling them apart is a
    // tenant-enumeration signal.
    const std::string body =
        token_grant(*p_, config, tenant, form, /*retryable=*/false, "token exchange failed");

    const json j = parse_or_object(body);
    const auto access = opt_string(j, "access_token");
    if (!access) {
        throw NetworkError("token exchange: malformed TokenExchangeResponse", "malformed_body");
    }
    ExchangedToken out;
    out.access_token = Sensitive<std::string>(*access);
    // §15.2 rule 6: surfaced, never dropped.
    out.issued_token_type = opt_string(j, "issued_token_type").value_or(kAccessTokenType);
    out.token_type = opt_string(j, "token_type").value_or("Bearer");
    out.expires_in = opt_int(j, "expires_in").value_or(0);
    // §15.2 rule 7: the GRANTED set, which may be narrower than the requested
    // one even on success.
    out.scope = opt_string(j, "scope");
    // §15.2 rule 4: any refresh_token the server sent is ignored — there is no
    // member for it, this result never enters the §9 guard, and re-running the
    // exchange is how a caller gets a fresh token.
    //
    // §15.2 rule 5: NOT adopted. This is a MUST NOT where adoption elsewhere is
    // a MAY — nothing above touches client state.
    return out;
}

}  // namespace axiam
