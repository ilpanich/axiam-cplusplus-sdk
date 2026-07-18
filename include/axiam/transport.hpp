// HTTP transport seam. The client depends only on the std::function<HttpResponse(
// const HttpRequest&)> alias below; the default implementation is libcurl
// (http_curl.hpp), and tests substitute an in-memory fake for full coverage of
// the logic layer without any network.
#pragma once

#include <functional>
#include <map>
#include <string>

#include "axiam/sensitive.hpp"

namespace axiam {

/// Case-insensitive header map key comparison.
struct CaseInsensitiveLess {
    bool operator()(const std::string& a, const std::string& b) const {
        return lower(a) < lower(b);
    }
    static std::string lower(std::string s) {
        for (char& c : s) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        return s;
    }
};

using HeaderMap = std::map<std::string, std::string, CaseInsensitiveLess>;

/// An outgoing HTTP request produced by the client's request builder.
struct HttpRequest {
    std::string method;  // "GET", "POST", ...
    std::string url;     // fully-qualified
    HeaderMap headers;
    std::string body;    // JSON body (may be empty)
};

/// An HTTP response, or a transport failure. When `transport_error` is non-empty
/// the request never completed (connection/DNS/TLS) and the client raises
/// NetworkError; otherwise `status` + `headers` + `body` describe the response.
struct HttpResponse {
    long status = 0;
    HeaderMap headers;
    std::string body;
    std::string transport_error;  // empty on a completed HTTP exchange
};

/// The transport seam. Injectable; defaults to the libcurl implementation.
using Transport = std::function<HttpResponse(const HttpRequest&)>;

/// Immutable TLS / mTLS material handed to the libcurl transport factory.
/// Strict server verification is ALWAYS on (§6); these fields only add a custom
/// CA to the trust chain and/or present a client identity certificate (§6.1).
struct TlsConfig {
    std::string custom_ca_pem;       // optional additional trusted CA (PEM)
    std::string client_cert_pem;     // optional mTLS client cert chain (PEM)
    Sensitive<std::string> client_key_pem;  // optional mTLS private key (PEM, §7)
    long connect_timeout_ms = 10000;
    long request_timeout_ms = 30000;

    bool has_client_cert() const {
        return !client_cert_pem.empty() && !client_key_pem.empty();
    }
    bool has_custom_ca() const { return !custom_ca_pem.empty(); }
};

}  // namespace axiam
