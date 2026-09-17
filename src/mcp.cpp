#include "axiam/mcp.hpp"

#include <algorithm>
#include <array>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>

namespace axiam {

namespace {

using ordered_json = nlohmann::ordered_json;

/// RFC 9728 §3.1's well-known prefix — the segment inserted between a
/// resource's authority and its path to reach the document that describes it.
constexpr const char* kMetadataPrefix = "/.well-known/oauth-protected-resource";

/// The three hosts §28.2 rule 2 lets an `http` URL use, and the only ones —
/// AXIAM's RFC 8252 §7.3 loopback hosts, reused verbatim. There is
/// deliberately no flag, environment variable or debug build that widens
/// this: a resource server reachable over plaintext on a routable host
/// publishes an identifier an attacker can impersonate.
bool is_loopback_host(const std::string& host) {
    return host == "127.0.0.1" || host == "[::1]" || host == "localhost";
}

[[noreturn]] void refuse(const std::string& field, const std::string& message) {
    throw std::invalid_argument(field + ": " + message + " (CONTRACT.md §28)");
}

/// `NQCHAR` (RFC 6749 Appendix A): `%x21` / `%x23`-`%x5B` / `%x5D`-`%x7E`. No
/// space, no `"`, no `\`, no control character, no non-ASCII.
bool is_nqchar(unsigned char c) {
    return c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E);
}

/// `NQSCHAR`: `NQCHAR` plus the space (`%x20`).
bool is_nqschar(unsigned char c) { return c == 0x20 || is_nqchar(c); }

template <typename Predicate>
bool is_all(const std::string& value, Predicate predicate) {
    if (value.empty()) return false;
    for (unsigned char c : value) {
        if (!predicate(c)) return false;
    }
    return true;
}

/// `scheme://authority[path][?query][#fragment]`, sliced out of the caller's
/// string exactly as given.
///
/// Deliberately not a normalising URL parser: normalising would lowercase the
/// host, resolve `..` segments and re-encode, and §28.2 forbids adjusting a
/// value to make it pass. §28.3 derives the document's own path from this
/// string, so what is validated must be what was written.
struct ParsedUri {
    std::string scheme;     ///< Verbatim (compared case-insensitively below).
    std::string authority;  ///< `userinfo@host:port`, verbatim.
    std::string path;       ///< Empty, or starting with `/`. A trailing slash is preserved.
    bool has_query = false;
    bool has_fragment = false;
};

std::string ascii_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool is_scheme_char(unsigned char c, bool first) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) return true;
    if (first) return false;
    return (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-';
}

std::optional<ParsedUri> parse_absolute_uri(const std::string& raw) {
    const auto scheme_end = raw.find("://");
    if (scheme_end == std::string::npos || scheme_end == 0) return std::nullopt;
    for (std::size_t i = 0; i < scheme_end; ++i) {
        if (!is_scheme_char(static_cast<unsigned char>(raw[i]), i == 0)) return std::nullopt;
    }
    const std::size_t authority_start = scheme_end + 3;
    std::size_t authority_end = raw.find_first_of("/?#", authority_start);
    if (authority_end == std::string::npos) authority_end = raw.size();
    const std::string authority = raw.substr(authority_start, authority_end - authority_start);
    if (authority.empty()) return std::nullopt;

    std::size_t path_end = raw.find_first_of("?#", authority_end);
    if (path_end == std::string::npos) path_end = raw.size();
    const std::string path = raw.substr(authority_end, path_end - authority_end);

    ParsedUri parsed;
    parsed.scheme = raw.substr(0, scheme_end);
    parsed.authority = authority;
    parsed.path = path;

    std::size_t cursor = path_end;
    if (cursor < raw.size() && raw[cursor] == '?') {
        parsed.has_query = true;
        const std::size_t frag = raw.find('#', cursor);
        cursor = (frag == std::string::npos) ? raw.size() : frag;
    }
    if (cursor < raw.size() && raw[cursor] == '#') {
        parsed.has_fragment = true;
    }
    return parsed;
}

/// The host inside an authority: `userinfo@` stripped, port stripped, an
/// IPv6 literal's brackets kept (so `[::1]` compares as §28.2 rule 2 spells
/// it). Stripping `userinfo` is what makes `http://localhost@evil.example.com/`
/// a refusal rather than a loopback pass — the host there is `evil.example.com`.
std::string host_of(const std::string& authority) {
    const auto at = authority.find_last_of('@');
    const std::string hostport = (at == std::string::npos) ? authority : authority.substr(at + 1);
    if (!hostport.empty() && hostport.front() == '[') {
        const auto close = hostport.find(']');
        return close == std::string::npos ? hostport : hostport.substr(0, close + 1);
    }
    const auto colon = hostport.find(':');
    return colon == std::string::npos ? hostport : hostport.substr(0, colon);
}

/// How much of §28.2 rule 1 a member is held to. `resource_documentation`
/// (rule 7) and `resource_metadata` (§28.4) relax the query/fragment ban: a
/// page for a human, or a URL the client is meant to fetch, may be
/// parameterised.
struct UriPolicy {
    bool allow_query = false;
    bool allow_fragment = false;
};

constexpr UriPolicy kIdentifier{false, false};
constexpr UriPolicy kLocator{true, true};

/// §28.2 rules 1 and 2, applied to one member. Returns the parse so a caller
/// that needs the path (§28.3) does not parse twice.
ParsedUri require_absolute_uri(const std::string& field, const std::string& raw,
                               const UriPolicy& policy) {
    if (raw.empty()) refuse(field, "must be a non-empty absolute URI");
    auto parsed = parse_absolute_uri(raw);
    if (!parsed) {
        refuse(field, "must be an absolute URI with a scheme and an authority, not \"" + raw + "\"");
    }
    if (parsed->has_query && !policy.allow_query) {
        refuse(field, "must carry no query — §28.3 derives the metadata path from it");
    }
    if (parsed->has_fragment && !policy.allow_fragment) {
        refuse(field, "must carry no fragment");
    }
    const std::string scheme = ascii_lower(parsed->scheme);
    if (scheme == "https") return *parsed;
    if (scheme == "http" && is_loopback_host(ascii_lower(host_of(parsed->authority)))) {
        return *parsed;
    }
    refuse(field, "must use https — http is accepted only on 127.0.0.1, [::1] or localhost, "
                  "and \"" + raw + "\" is neither");
}

/// §28.3's derivation: RFC 9728 §3.1 inserts the well-known segment between
/// the authority and the path. An empty path and a bare `/` both reach the
/// root form; anything else is appended, trailing slash included — it is
/// part of the identifier a client compares, and two resources that differ
/// only by it are two resources.
std::string derive_metadata_path(const std::string& resource_path) {
    if (resource_path.empty() || resource_path == "/") return kMetadataPrefix;
    return std::string(kMetadataPrefix) + resource_path;
}

const char* error_wire_name(BearerChallengeError error) {
    switch (error) {
        case BearerChallengeError::kInvalidRequest: return "invalid_request";
        case BearerChallengeError::kInvalidToken: return "invalid_token";
        case BearerChallengeError::kInsufficientScope: return "insufficient_scope";
    }
    refuse("error", "must be one of invalid_request, invalid_token, insufficient_scope");
}

}  // namespace

std::string ProtectedResourceMetadataDocument::to_json() const {
    // §28.2 fixes the member order; ordered_json preserves insertion order so
    // the emitted bytes match the contract's worked example even though
    // member order carries no semantic weight.
    ordered_json doc;
    doc["resource"] = resource;
    doc["authorization_servers"] = authorization_servers;
    if (!scopes_supported.empty()) {
        doc["scopes_supported"] = scopes_supported;
    }
    doc["bearer_methods_supported"] = bearer_methods_supported;
    if (resource_documentation.has_value()) {
        doc["resource_documentation"] = *resource_documentation;
    }
    return doc.dump();
}

ProtectedResourceMetadata protected_resource_metadata(
    const ProtectedResourceMetadataOptions& options) {
    // Rule 1 + rule 2.
    const ParsedUri parsed = require_absolute_uri("resource", options.resource, kIdentifier);

    // Rule 3 + rule 4: at least one entry, each an issuer verbatim, no duplicates.
    if (options.authorization_servers.empty()) {
        refuse("authorization_servers",
               "must name at least one authorization server — a document that names none "
               "answers none of the question the client asked");
    }
    std::set<std::string> seen_servers;
    for (const auto& entry : options.authorization_servers) {
        require_absolute_uri("authorization_servers", entry, kIdentifier);
        if (!seen_servers.insert(entry).second) {
            refuse("authorization_servers", "duplicate entry \"" + entry + "\"");
        }
    }

    // Rule 5: NQCHAR tokens, order preserved, duplicates refused, empty omits.
    std::set<std::string> seen_scopes;
    for (const auto& scope : options.scopes_supported) {
        if (!is_all(scope, is_nqchar)) {
            refuse("scopes_supported",
                   "\"" + scope + "\" is not a scope token — one or more NQCHAR (no space, "
                   "no '\"', no '\\', no control character, no non-ASCII)");
        }
        if (!seen_scopes.insert(scope).second) {
            refuse("scopes_supported", "duplicate scope \"" + scope + "\"");
        }
    }

    // Rule 6: exactly ["header"].
    if (options.bearer_methods_supported.size() != 1 ||
        options.bearer_methods_supported[0] != "header") {
        refuse("bearer_methods_supported",
               "must be exactly [\"header\"] in this contract version — §10's guard reads a "
               "bearer credential from the Authorization header alone");
    }

    // Rule 7: absolute URL, query and fragment permitted, omitted when absent.
    if (options.resource_documentation.has_value()) {
        require_absolute_uri("resource_documentation", *options.resource_documentation, kLocator);
    }

    ProtectedResourceMetadata result;
    result.document.resource = options.resource;
    result.document.authorization_servers = options.authorization_servers;
    result.document.scopes_supported = options.scopes_supported;
    result.document.bearer_methods_supported = {"header"};
    result.document.resource_documentation = options.resource_documentation;

    result.metadata_path = derive_metadata_path(parsed.path);
    result.metadata_url = parsed.scheme + "://" + parsed.authority + result.metadata_path;
    return result;
}

std::string bearer_challenge(const BearerChallengeOptions& options) {
    std::string params;
    auto append = [&params](const std::string& name, const std::string& value) {
        if (!params.empty()) params += ", ";
        params += name + "=\"" + value + "\"";
    };

    if (options.error.has_value()) {
        append("error", error_wire_name(*options.error));
    }

    if (options.error_description.has_value()) {
        const std::string& description = *options.error_description;
        if (!is_all(description, is_nqschar)) {
            refuse("error_description",
                   "must be one or more NQSCHAR (no '\"', no '\\', no control character, no "
                   "non-ASCII) — a value needing an escape does not belong in a challenge");
        }
        append("error_description", description);
    }

    if (options.scope.has_value()) {
        const std::string& scope = *options.scope;
        if (scope.empty()) {
            refuse("scope", "must be one or more scope tokens joined by a single space");
        }
        std::size_t start = 0;
        while (start <= scope.size()) {
            const auto space = scope.find(' ', start);
            const std::string token = scope.substr(start, space == std::string::npos
                                                               ? std::string::npos
                                                               : space - start);
            if (!is_all(token, is_nqchar)) {
                refuse("scope",
                       "\"" + scope + "\" is not a space-joined list of scope tokens — no "
                       "leading, trailing or doubled space, and no empty token");
            }
            if (space == std::string::npos) break;
            start = space + 1;
        }
        append("scope", scope);
    }

    const std::string& url = options.resource_metadata_url;
    require_absolute_uri("resource_metadata", url, kLocator);
    if (!is_all(url, is_nqchar)) {
        refuse("resource_metadata",
               "must carry no '\"', no '\\', no space and no control character — a correctly "
               "encoded URL cannot, so one that does has not been encoded");
    }
    append("resource_metadata", url);

    return "Bearer " + params;
}

McpChallenges mcp_challenges(const std::string& resource_metadata_url,
                             const std::string& expected_audience) {
    if (expected_audience.empty()) {
        refuse("resource_metadata_url",
               "requires expected_audience to be set on the same configuration (CONTRACT.md "
               "§28.5 rule 2) — announcing a resource identifier obliges this server to check "
               "that an inbound token's `aud` is that identifier, and a resource server that "
               "announces itself without checking is opened by a token minted for somebody else");
    }
    const ParsedUri parsed = require_absolute_uri("resource_metadata_url", resource_metadata_url, kLocator);

    McpChallenges challenges;
    challenges.resource_metadata_url = resource_metadata_url;
    challenges.expected_audience = expected_audience;
    challenges.metadata_path = parsed.path.empty() ? "/" : parsed.path;
    challenges.no_credential = bearer_challenge({resource_metadata_url, std::nullopt, std::nullopt, std::nullopt});
    challenges.invalid_token = bearer_challenge(
        {resource_metadata_url, BearerChallengeError::kInvalidToken, std::nullopt, std::nullopt});
    return challenges;
}

std::string mcp_insufficient_scope_challenge(const McpChallenges& challenges,
                                             const std::string& scope) {
    return bearer_challenge({challenges.resource_metadata_url,
                             BearerChallengeError::kInsufficientScope, std::nullopt, scope});
}

bool is_metadata_document_request(const std::optional<McpChallenges>& challenges,
                                  const std::string& method, const std::string& path) {
    if (!challenges.has_value()) return false;
    if (method != "GET" && method != "HEAD") return false;
    const auto end = path.find_first_of("?#");
    const std::string bare_path = (end == std::string::npos) ? path : path.substr(0, end);
    return bare_path == challenges->metadata_path;
}

void check_mcp_configuration_matches(const std::optional<McpChallenges>& challenges,
                                     const ProtectedResourceMetadata& metadata) {
    if (!challenges.has_value()) return;
    if (challenges->resource_metadata_url != metadata.metadata_url) {
        refuse("resource_metadata_url",
               "is \"" + challenges->resource_metadata_url + "\" but this document is published "
               "at \"" + metadata.metadata_url + "\" — the challenge would point at a document "
               "that is not this resource server's");
    }
    if (challenges->expected_audience != metadata.document.resource) {
        refuse("expected_audience",
               "is \"" + challenges->expected_audience + "\" but this document announces \"" +
               metadata.document.resource + "\" — the document would announce one identifier "
               "while the guard checked `aud` against another, so every token the flow "
               "produced would be refused");
    }
}

}  // namespace axiam
