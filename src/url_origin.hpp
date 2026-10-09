// The (scheme, host, port) of an absolute URL — what "the same origin" compares.
//
// Internal; not installed. Shared by the §28.12 registration helpers (rule 1:
// the registration URI must be at the configured AXIAM) and the §32.7 receiver
// (a JWKS or discovery URL must be https unless it is a loopback development
// host — the same carve-out §6 gives the base URL).
//
// Deliberately a split, not a parser: nothing here decodes, normalises a path or
// resolves a relative reference. A URL this cannot split is refused by its
// caller, which is the right answer for a value about to receive a bearer.

#ifndef AXIAM_URL_ORIGIN_HPP
#define AXIAM_URL_ORIGIN_HPP

#include <optional>
#include <string>

#include "axiam/transport.hpp"

namespace axiam::detail {

struct Origin {
    std::string scheme;  ///< lower-cased
    std::string host;    ///< lower-cased, IPv6 without brackets
    int port = 0;        ///< explicit, or the scheme's default (443 / 80)

    bool operator==(const Origin& o) const {
        return scheme == o.scheme && host == o.host && port == o.port;
    }
};

/// The origin of `url`, or nullopt when it is not `scheme://host[:port]...` with
/// a non-empty host, no userinfo, and a port that is all digits.
inline std::optional<Origin> origin_of(const std::string& url) {
    const auto sep = url.find("://");
    if (sep == std::string::npos || sep == 0) return std::nullopt;
    Origin out;
    out.scheme = CaseInsensitiveLess::lower(url.substr(0, sep));
    std::string authority = url.substr(sep + 3);
    const auto end = authority.find_first_of("/?#");
    if (end != std::string::npos) authority.erase(end);
    // Userinfo in a URL that is about to carry a bearer is refused outright: the
    // part before '@' is what a confusable URL hides its real host behind.
    if (authority.find('@') != std::string::npos) return std::nullopt;

    std::string port;
    if (!authority.empty() && authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string::npos) return std::nullopt;
        out.host = authority.substr(1, close - 1);
        const std::string rest = authority.substr(close + 1);
        if (!rest.empty()) {
            if (rest.front() != ':') return std::nullopt;
            port = rest.substr(1);
        }
    } else {
        const auto colon = authority.find(':');
        out.host = authority.substr(0, colon);
        if (colon != std::string::npos) port = authority.substr(colon + 1);
    }
    if (out.host.empty()) return std::nullopt;
    out.host = CaseInsensitiveLess::lower(out.host);

    if (port.empty()) {
        if (out.scheme == "https") out.port = 443;
        else if (out.scheme == "http") out.port = 80;
        return out;
    }
    if (port.size() > 5) return std::nullopt;
    int value = 0;
    for (char c : port) {
        if (c < '0' || c > '9') return std::nullopt;
        value = value * 10 + (c - '0');
    }
    out.port = value;
    return out;
}

/// The loopback development hosts §6 lets a base URL use over plain http.
inline bool is_loopback_host(const std::string& host) {
    return host == "localhost" || host == "127.0.0.1" || host == "::1";
}

/// `https`, or `http` on a loopback host — §6's rule for anything this SDK sends
/// a credential to or trusts a key from.
inline bool is_secure_or_loopback(const Origin& o) {
    return o.scheme == "https" || (o.scheme == "http" && is_loopback_host(o.host));
}

}  // namespace axiam::detail

#endif  // AXIAM_URL_ORIGIN_HPP
