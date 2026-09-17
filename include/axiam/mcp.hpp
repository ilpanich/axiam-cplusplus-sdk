// §28 MCP Resource-Server Helpers (RFC 9728 + RFC 6750), CONTRACT.md contract
// 1.48.
//
// This is the RESOURCE SERVER's half of the Model Context Protocol
// authorization handshake: publishing the RFC 9728 protected-resource
// metadata document that names the authorization server guarding this
// resource, and building the `WWW-Authenticate` challenge that starts an MCP
// client's discovery. AXIAM is the authorization server and implements none
// of this; the *client* half — parsing a challenge, fetching a document,
// deciding whether to trust the authorization server it names — is
// deliberately not in this contract version, for the same reason §20.3 stops
// at parsing a UMA challenge rather than acting on one.
//
// §28.0: **no operation here performs network I/O.** All three are pure
// local computation, like oidc_begin (§12.1) and uma_parse_challenge (§20.5),
// so §16's retry policy and §9's single-flight refresh do not apply and
// nothing here touches the SDK client's own session.
//
// **Nothing in this file is a source of truth about a token.** The document
// is a claim a resource server publishes about itself; the challenge is a
// hint given to a caller that already failed. Whether a request is
// authorized stays §10.1's and §11's decision, unchanged and unreachable from
// here — see <axiam/authenticator.hpp> and <axiam/guard.hpp> for where the
// challenges built here actually get attached to a 401/403.
//
// **C++ has no router** (§28.3), so there is no `serve_protected_resource_metadata`
// function in this SDK: README.md documents the Crow/Pistache adapter that
// registers the derived path by hand, using `protected_resource_metadata()`
// and `ProtectedResourceMetadataDocument::to_json()` below.
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace axiam {

/// RFC 6750 §3.1's three challenge error codes — the complete vocabulary a
/// challenge may name (§28.4). There is no `invalid_grant` or other
/// token-endpoint code here: a challenge is not a token response.
enum class BearerChallengeError {
    kInvalidRequest,
    kInvalidToken,
    kInsufficientScope,
};

/// The RFC 9728 §2 document, carrying **at most** the five members §28.2
/// permits, in that order, and no others.
///
/// `scopes_supported` empty and `resource_documentation` absent both mean
/// "omit the member from the JSON" (§28.2 rules 5 and 7) — never `null`, and
/// never an explicit empty array for the former: an empty `scopes_supported`
/// would assert that this resource server understands no scopes, a different
/// and almost always false claim.
struct ProtectedResourceMetadataDocument {
    /// The resource identifier this server publishes about itself — the
    /// string an RFC 8707 `resource` parameter carries, and the `aud` the
    /// guard checks (§28.2 rule 9).
    std::string resource;
    /// The issuer identifiers of the authorization servers guarding this
    /// resource. At least one, each verbatim, no duplicates.
    std::vector<std::string> authorization_servers;
    /// The scope tokens this resource server understands, in the caller's
    /// order. Empty omits the member from the JSON.
    std::vector<std::string> scopes_supported;
    /// Always exactly `["header"]` in this contract version (§28.2 rule 6) —
    /// §10's guard reads a bearer credential from the `Authorization` header
    /// alone.
    std::vector<std::string> bearer_methods_supported;
    /// A human-readable documentation page. Absent omits the member.
    std::optional<std::string> resource_documentation;

    /// The exact §28.2 JSON for this document: fixed member order,
    /// `scopes_supported` and `resource_documentation` omitted rather than
    /// `null` when absent. Member order is not semantically significant
    /// (§28.2) — it is fixed here so the bytes have one obvious shape, not so
    /// a byte comparison becomes meaningful.
    std::string to_json() const;
};

/// §28.1's `protected_resource_metadata` arguments, in canonical order.
struct ProtectedResourceMetadataOptions {
    /// Absolute, `https` (or `http` on a loopback host — §28.2 rule 2), with
    /// no query and no fragment. A trailing slash is significant.
    std::string resource;
    /// At least one entry, each an absolute URI with no query and no
    /// fragment, no duplicates.
    std::vector<std::string> authorization_servers;
    /// The caller's order is preserved; an empty list omits the member.
    std::vector<std::string> scopes_supported;
    /// Defaults to `["header"]`, the only accepted value in this contract
    /// version.
    std::vector<std::string> bearer_methods_supported{"header"};
    /// Optional documentation page. May carry a query and a fragment; absent
    /// omits the member.
    std::optional<std::string> resource_documentation;
};

/// What `protected_resource_metadata()` returns: the document, and where it
/// is served.
struct ProtectedResourceMetadata {
    /// The RFC 9728 §2 document, ready to serialize via `document.to_json()`.
    ProtectedResourceMetadataDocument document;
    /// The absolute path the document is served at, derived from `resource`
    /// per §28.3 — never chosen.
    std::string metadata_path;
    /// `metadata_path` resolved against the resource's scheme and authority.
    /// Feed this to `AuthenticatorOptions::resource_metadata_url` so the two
    /// can never be retyped out of sync.
    std::string metadata_url;
};

/// §28.1 `protected_resource_metadata(options)` — build and validate the RFC
/// 9728 protected-resource metadata document this server publishes about
/// itself, and derive the path and URL it is served at.
///
/// Validation happens here and it refuses; it never repairs (§28.2). Every
/// rule is checked before any route exists and before any request is served.
/// Nothing is normalised, trimmed, lowercased or re-encoded to make a value
/// pass: a value that needs adjusting is a configuration mistake an operator
/// fixes in one line, and silently fixing it would publish a document
/// describing a resource server that does not exist.
///
/// **Nothing in the document may come from a request** (§28.2 rule 8). Both
/// `resource` and `authorization_servers` are configuration; there is no
/// overload that builds either from a header or a request URL.
///
/// @throws std::invalid_argument when any §28.2 rule is violated — a local
///         configuration mistake, exactly like the other constructor-time
///         refusals in this SDK (`TokenAuthenticator`'s empty tenant id,
///         `Client::Builder`'s malformed base URL). §28 performs no network
///         I/O (§28.0), so there is no server response to map a `ValidationError`
///         from; a refusal here is a caller bug caught before any request
///         exists, the same class `std::invalid_argument` already names
///         elsewhere in this SDK.
ProtectedResourceMetadata protected_resource_metadata(
    const ProtectedResourceMetadataOptions& options);

/// §28.4's `bearer_challenge` arguments, in canonical order.
struct BearerChallengeOptions {
    /// The document's URL — the one parameter that is always present. May
    /// carry a query and a fragment.
    std::string resource_metadata_url;
    /// One of RFC 6750 §3.1's three codes, or absent when the request carried
    /// no authentication information at all.
    std::optional<BearerChallengeError> error;
    /// A human-readable description, for an application building **its own**
    /// challenge for its own 400. The SDK's own guard never sets this: every
    /// distinction a 401 draws for an unauthenticated stranger is an oracle
    /// (§28.4, §28.8).
    std::optional<std::string> error_description;
    /// The scope the route asked for, verbatim — one or more tokens joined by
    /// a single space.
    std::optional<std::string> scope;
};

/// §28.4 `bearer_challenge(options)` — build the **value** of a
/// `WWW-Authenticate` header, never the whole header line and never a map.
/// The caller sets the header.
///
/// Parameters appear in a fixed order — `error`, `error_description`,
/// `scope`, `resource_metadata` — separated by exactly `", "`.
/// `resource_metadata` is always present; the other three are omitted when
/// not given.
///
/// **Every value is quoted and no value is ever escaped.** RFC 6750 §3
/// restricts each parameter to a character set that cannot contain `"` or
/// `\`, so a value needing an escape does not belong in a challenge: this
/// refuses it rather than escaping, truncating or stripping it.
///
/// @throws std::invalid_argument when any parameter is outside RFC 6750's
///         syntax — a programming error, since a challenge is built from the
///         code's own constants and a route's own configuration, not a
///         runtime condition to degrade around.
std::string bearer_challenge(const BearerChallengeOptions& options);

/// The §28.5 challenge values one resource-server configuration emits, all
/// built once so an invalid configuration is a construction-time failure
/// rather than a surprise on the 401 path.
///
/// `expected_audience` is carried through only so
/// `check_mcp_configuration_matches()` can cross-check it against a
/// document's `resource` without asking the operator to configure it a
/// second time (§28.5 rule 2 forbids a second audience OPTION; this is not
/// one — it is always exactly the string `mcp_challenges()` below was given,
/// never independently settable).
struct McpChallenges {
    /// Echoed from the call that built this — never independently settable.
    std::string resource_metadata_url;
    /// Echoed from the call that built this — never independently settable.
    /// See the struct comment: not a second place to configure the audience.
    std::string expected_audience;
    /// `resource_metadata_url`'s path component, exempted from
    /// authentication (§28.3 rule 2). Query and fragment, if any, are not
    /// part of it — see `is_metadata_document_request()`.
    std::string metadata_path;
    /// §28.4 vector 1 — the request carried **no** authentication
    /// information, so RFC 6750 §3 says not to name an error.
    std::string no_credential;
    /// §28.4 vector 2 — a credential was presented and rejected. The only
    /// thing a 401 ever says about why (§28.4, §28.8).
    std::string invalid_token;
};

/// §28.5 rule 2, made impossible rather than discouraged: build the §28
/// challenges for one `resource_metadata_url` / `expected_audience` pair.
///
/// There is no overload that takes `resource_metadata_url` alone — every
/// caller that wants the option on must supply both strings in the same
/// call, so "the challenge is configured but the audience is not" cannot be
/// expressed. `expected_audience` here is §10.1 row 6's existing
/// configuration under whatever name the caller already gives it
/// (`AuthenticatorOptions::expected_audience`); this function adds no second
/// place to set it.
///
/// §28 is opt-in (§28.5 rule 1): a caller that does not want the option
/// simply never calls this and passes `std::nullopt` wherever an
/// `AxiamGuard`/`require_access` overload asks for `McpChallenges` — nothing
/// about the byte-for-byte-unconfigured guarantee lives in this function.
///
/// @throws std::invalid_argument when `expected_audience` is empty (naming
///         both options, per §28.5 rule 2), or when `resource_metadata_url`
///         fails §28.4's own `resource_metadata` syntax.
McpChallenges mcp_challenges(const std::string& resource_metadata_url,
                             const std::string& expected_audience);

/// §28.4 vector 3, for one route's scope — built on demand rather than
/// precomputed in `McpChallenges`, because §28.5 rule 6 requires the scope
/// named to be the one the specific route asked for, verbatim, and different
/// routes behind one resource server ask for different scopes.
///
/// @throws std::invalid_argument when `scope` is outside §28.4's syntax.
std::string mcp_insufficient_scope_challenge(const McpChallenges& challenges,
                                             const std::string& scope);

/// §28.3 rule 2: is `method`/`path` the unauthenticated `GET`/`HEAD` of the
/// metadata document these challenges point at? An adapter that applies a
/// guard globally (the Crow/Pistache adapters README.md documents) checks
/// this **before** calling the guard, and serves the document with no
/// credential of any kind when it is true — a document that 401s cannot
/// start the handshake it exists to start.
///
/// Always `false` when `challenges` is `std::nullopt`: with §28 off, no path
/// is exempted (§28.9's regression).
bool is_metadata_document_request(const std::optional<McpChallenges>& challenges,
                                  const std::string& method, const std::string& path);

/// §28.5 rule 3's cross-check, for a deployment where the guard and the
/// document it should describe are configured in the same process: the
/// guard's `resource_metadata_url` must equal the document's `metadata_url`,
/// and its `expected_audience` must equal the document's `resource` — two
/// *different* string pairs, each compared against its own counterpart by
/// exact equality (RFC 3986 §6.2.1) — no normalisation, no case folding, no
/// trailing-slash tolerance.
///
/// Call this once, at startup, wherever the Crow/Pistache adapter wires the
/// guard together with `protected_resource_metadata()` — README.md shows
/// where. Where the guard is configured in a different process from the one
/// serving the document, nothing can be checked and this MUST NOT be called
/// with guessed values; configure both from the one `metadata_url` a shared
/// constant provides instead.
///
/// A `challenges` of `std::nullopt` (§28 off) never throws: there is nothing
/// to cross-check.
///
/// @throws std::invalid_argument naming whichever comparison failed.
void check_mcp_configuration_matches(const std::optional<McpChallenges>& challenges,
                                     const ProtectedResourceMetadata& metadata);

}  // namespace axiam
