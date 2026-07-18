// Default libcurl-backed transport: HTTP + strict TLS (§6) + in-memory mTLS
// client identity (§6.1) + a per-client cookie engine (§4). No temporary files:
// CA and client identity are passed as libcurl BLOBs.
#pragma once

#include <memory>

#include "axiam/transport.hpp"

namespace axiam {

/// Owns a single libcurl easy handle (serialized by an internal mutex) whose
/// cookie engine persists the session across requests for one client instance.
class CurlTransport {
public:
    explicit CurlTransport(TlsConfig cfg);
    ~CurlTransport();

    CurlTransport(const CurlTransport&) = delete;
    CurlTransport& operator=(const CurlTransport&) = delete;

    /// Perform one HTTP exchange. On connection/DNS/TLS failure the returned
    /// HttpResponse has a non-empty `transport_error` and status 0.
    HttpResponse perform(const HttpRequest& req);

    /// Build a Transport (std::function) that forwards to a shared CurlTransport,
    /// so the cookie engine and TLS material are shared for the client's lifetime.
    static Transport make_transport(TlsConfig cfg);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

/// Process-wide libcurl init/cleanup guard (idempotent).
void ensure_curl_global_init();

}  // namespace axiam
