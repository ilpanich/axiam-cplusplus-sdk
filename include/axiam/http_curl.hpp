// Default libcurl-backed transport: HTTP + strict TLS (§6) + in-memory mTLS
// client identity (§6.1) + a per-client cookie engine (§4). No temporary files:
// CA and client identity are passed as libcurl BLOBs.
#pragma once

#include <memory>
#include <string>
#include <vector>

#include "axiam/transport.hpp"

namespace axiam {

/// Owns a POOL of libcurl easy handles (up to
/// `TlsConfig::max_concurrent_requests`) whose cookie jar, DNS cache and TLS
/// session cache are shared through a `CURLSH`, so one client instance keeps
/// one session across requests while still performing them concurrently.
///
/// This class owned exactly one handle behind a mutex until benchmark run 5
/// showed what that costs: check p50 3.2 ms against p95 280 ms, i.e. a tail
/// made almost entirely of callers queueing for the lock rather than of
/// anything on the wire. A pooled handle per in-flight request removes the
/// queue; shared cookies keep §4's session semantics exactly as they were.
///
/// Each handle is long-lived so libcurl's connection cache keeps its TCP+TLS
/// connection hot. Keep-alive is not optional: `CURLOPT_FORBID_REUSE` and
/// `CURLOPT_FRESH_CONNECT` are pinned off, connection age-based retirement is
/// disabled, and `Expect: 100-continue` is suppressed so a large POST body
/// never waits on an interim response. See the comments in
/// `src/http_curl.cpp` for why each of those defaults produced a latency tail.
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
    struct HandleLease;
    std::unique_ptr<Impl> impl_;

    // Internal helpers, defined in http_curl.cpp. `curl_handle` is an opaque
    // `CURL*` — spelled `void*` here so this header need not include
    // <curl/curl.h> for a private implementation detail.
    //
    // transfer() is everything about one exchange that does not depend on
    // which handle carries it (URL, method/body, headers, TLS, timeouts); it
    // backs both perform()'s pooled path and perform_isolated()'s §24.1 path
    // (CONTRACT.md §24.1, contract 1.45 — `webauthn_setup_register_start` /
    // `_finish` MUST NOT replay the shared cookie jar even when a session is
    // configured), so §6's TLS policy applies identically to both.
    HttpResponse transfer(void* curl_handle, const HttpRequest& req);
    HttpResponse perform_isolated(const HttpRequest& req);
    void merge_into_shared_jar(const std::string& request_url,
                               const std::vector<std::string>& set_cookies);
};

/// Process-wide libcurl init/cleanup guard (idempotent).
void ensure_curl_global_init();

}  // namespace axiam
