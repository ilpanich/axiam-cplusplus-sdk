#include "axiam/http_curl.hpp"

#include <curl/curl.h>

#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>

namespace axiam {

void ensure_curl_global_init() {
    static std::once_flag flag;
    std::call_once(flag, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

namespace {

size_t write_body_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

size_t header_cb(char* buffer, size_t size, size_t nitems, void* userdata) {
    auto* resp = static_cast<HttpResponse*>(userdata);
    const size_t len = size * nitems;
    std::string line(buffer, len);
    // Strip trailing CRLF.
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    const auto colon = line.find(':');
    if (colon != std::string::npos) {
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        // Trim leading spaces on value.
        size_t start = value.find_first_not_of(" \t");
        value = (start == std::string::npos) ? std::string{} : value.substr(start);
        // Set-Cookie repeats per response; keep every value (see HttpResponse).
        if (CaseInsensitiveLess::lower(name) == "set-cookie") {
            resp->set_cookies.push_back(value);
        }
        resp->headers[name] = value;
    }
    return len;
}

}  // namespace

struct CurlTransport::Impl {
    TlsConfig cfg;

    // ---- D2: a POOL of easy handles, not one handle behind a mutex. ----
    //
    // Benchmark run 5 measured this SDK at check p50 3.2 ms / p95 280 ms —
    // the same signature as run 4, unmoved by the I11 connection-lifetime
    // fixes below, and failing the SDK's own acceptance bar (p95 <= 3x p50).
    // The I11 work was not wrong; it was aimed at the wrong thing. The tail
    // was never reconnects.
    //
    // It was this class. `perform()` used to take a lock_guard over a single
    // shared CURL easy handle, so a Client used from N threads served its
    // requests strictly one at a time. p50 3.2 ms is the uncontended service
    // time — the connection really is hot, so I11 did work — and p95 280 ms
    // is what a caller waits when fifteen others hold the lock ahead of it.
    // `std::mutex` is also barging rather than FIFO, so an unlucky thread can
    // be passed over repeatedly; that is why the tail is heavy rather than
    // merely 16x the median, and why the shape reproduced identically across
    // runs.
    //
    // A pool of handles fixes the actual problem. Each handle keeps its own
    // hot connection (which is exactly what the I11 options below are for),
    // while cookies, DNS and TLS session state are SHARED through libcurl's
    // `CURLSH` so the session stays one session regardless of which handle
    // serves a given request — the §4 cookie semantics are preserved, not
    // approximated.
    //
    // Connections are deliberately NOT shared (`CURL_LOCK_DATA_CONNECT` is
    // not registered): a shared connection cache would put every handle back
    // behind one lock at acquisition time, reintroducing a smaller version of
    // the very contention this removes.
    CURLSH* share = nullptr;
    std::mutex share_locks[CURL_LOCK_DATA_LAST];

    std::mutex pool_mtx;
    std::condition_variable pool_cv;
    std::vector<CURL*> idle;      // handles available for reuse
    std::vector<CURL*> all;       // every handle ever created, for cleanup
    unsigned in_use = 0;

    explicit Impl(TlsConfig c) : cfg(std::move(c)) {
        ensure_curl_global_init();
        if (cfg.max_concurrent_requests == 0) cfg.max_concurrent_requests = 1;
        share = curl_share_init();
        if (share != nullptr) {
            curl_share_setopt(share, CURLSHOPT_LOCKFUNC, &Impl::lock_cb);
            curl_share_setopt(share, CURLSHOPT_UNLOCKFUNC, &Impl::unlock_cb);
            curl_share_setopt(share, CURLSHOPT_USERDATA, this);
            curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_COOKIE);
            curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_DNS);
            curl_share_setopt(share, CURLSHOPT_SHARE, CURL_LOCK_DATA_SSL_SESSION);
        }
    }

    ~Impl() {
        // Easy handles first: an easy handle still referencing a freed share
        // is a use-after-free inside libcurl.
        for (CURL* h : all) curl_easy_cleanup(h);
        if (share != nullptr) curl_share_cleanup(share);
    }

    static void lock_cb(CURL*, curl_lock_data data, curl_lock_access, void* user) {
        static_cast<Impl*>(user)->share_locks[data].lock();
    }
    static void unlock_cb(CURL*, curl_lock_data data, void* user) {
        static_cast<Impl*>(user)->share_locks[data].unlock();
    }

    /// Take a handle from the pool, creating one if the pool is below its
    /// cap, otherwise waiting for a busy handle to come back. Blocking rather
    /// than growing without bound keeps a burst of callers from opening an
    /// unbounded number of connections to the server.
    CURL* acquire() {
        std::unique_lock<std::mutex> lock(pool_mtx);
        for (;;) {
            if (!idle.empty()) {
                CURL* h = idle.back();
                idle.pop_back();
                ++in_use;
                return h;
            }
            if (all.size() < cfg.max_concurrent_requests) {
                CURL* h = curl_easy_init();
                if (h == nullptr) return nullptr;
                configure_new_handle(h);
                all.push_back(h);
                ++in_use;
                return h;
            }
            pool_cv.wait(lock);
        }
    }

    void release(CURL* h) {
        if (h == nullptr) return;
        {
            std::lock_guard<std::mutex> lock(pool_mtx);
            idle.push_back(h);
            --in_use;
        }
        pool_cv.notify_one();
    }

    /// Per-handle setup that never changes between requests.
    void configure_new_handle(CURL* h) {
        // Enable the in-memory cookie engine for this handle (§4). An empty
        // filename turns the engine on without reading/writing any file; the
        // jar itself lives in the shared CURLSH, so every handle sees the
        // same session cookies.
        curl_easy_setopt(h, CURLOPT_COOKIEFILE, "");
        if (share != nullptr) curl_easy_setopt(h, CURLOPT_SHARE, share);
        apply_connection_reuse_options(h);
    }

    // ---- I11: keep the connection hot for the handle's whole lifetime. ----
    //
    // Each pooled handle should keep its own TCP+TLS connection hot for the
    // client's lifetime, and the ~3 ms p50 shows that it does. These options
    // undo libcurl *defaults* that periodically throw that connection away and
    // then make re-establishing it expensive:
    //
    //   * `CURLOPT_MAXAGE_CONN` defaults to 118 s — libcurl refuses to reuse a
    //     connection older than that and opens a fresh one instead. For a
    //     long-lived benchmark worker that is exactly "one reconnect per worker
    //     per interval", and it is invisible in p50 but owns the tail.
    //   * a fresh connect to a dual-stack name pays the Happy-Eyeballs timer
    //     (`CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS`, default 200 ms) before the IPv4
    //     attempt starts whenever AAAA resolves but IPv6 is not routable — the
    //     usual case inside a container network, and the ~200 ms floor under the
    //     observed ~280 ms tail.
    //   * `CURLOPT_DNS_CACHE_TIMEOUT` defaults to 60 s, so that reconnect also
    //     re-resolves the name.
    //   * without TCP keepalive an idle connection can be dropped silently by a
    //     NAT/load balancer, and the next write stalls for a TCP RTO (200 ms
    //     minimum on Linux) before libcurl notices and retries on a new socket.
    //
    // These are all connection-scoped, so they are set once per handle.
    // `FORBID_REUSE`/`FRESH_CONNECT` are explicitly pinned OFF: nothing in this
    // SDK may opt out of keep-alive, and pinning them documents that.
    static void apply_connection_reuse_options(CURL* h) {
        if (h == nullptr) return;

        curl_easy_setopt(h, CURLOPT_FORBID_REUSE, 0L);
        curl_easy_setopt(h, CURLOPT_FRESH_CONNECT, 0L);

        // Room for the JWKS host alongside the API host without evicting either.
        curl_easy_setopt(h, CURLOPT_MAXCONNECTS, 8L);

        // Do not retire a healthy pooled connection on a timer. libcurl still
        // probes the socket for a server-side FIN before reuse, and the TCP
        // keepalive below detects a silently-dropped path, so age alone is not a
        // useful liveness signal here.
#if LIBCURL_VERSION_NUM >= 0x074100  // 7.65.0
        curl_easy_setopt(h, CURLOPT_MAXAGE_CONN, 3600L);
#endif

        // Cap the dual-stack fallback stall. IPv6 is still tried first; the IPv4
        // attempt just starts 50 ms later instead of 200 ms later.
#if LIBCURL_VERSION_NUM >= 0x073b00  // 7.59.0
        curl_easy_setopt(h, CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS, 50L);
#endif

        // Re-resolving every 60s buys nothing for a pinned API endpoint.
        curl_easy_setopt(h, CURLOPT_DNS_CACHE_TIMEOUT, 300L);

        curl_easy_setopt(h, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(h, CURLOPT_TCP_KEEPIDLE, 30L);
        curl_easy_setopt(h, CURLOPT_TCP_KEEPINTVL, 15L);
        curl_easy_setopt(h, CURLOPT_TCP_NODELAY, 1L);
    }
};

CurlTransport::CurlTransport(TlsConfig cfg) : impl_(std::make_unique<Impl>(std::move(cfg))) {}
CurlTransport::~CurlTransport() = default;

HttpResponse CurlTransport::perform(const HttpRequest& req) {
    // RAII borrow of a pooled handle, so every return path — including one
    // taken by an exception out of a callback — puts the handle back. Defined
    // here rather than at namespace scope because `Impl` is private to this
    // class; a local class inside a member function shares that access.
    struct HandleLease {
        Impl* impl;
        CURL* h;
        ~HandleLease() { impl->release(h); }
    };

    HttpResponse resp;
    HandleLease lease{impl_.get(), impl_->acquire()};
    CURL* h = lease.h;
    if (h == nullptr) {
        resp.transport_error = "could not allocate a libcurl handle";
        return resp;
    }

    curl_easy_setopt(h, CURLOPT_URL, req.url.c_str());

    // Method + body. The handle is reused across requests, so every method-shaped
    // option MUST be reset on each call: CURLOPT_CUSTOMREQUEST is sticky and would
    // otherwise keep overriding the request line of a later GET with the verb of
    // the previous POST (silently turning the JWKS fetch into `POST /oauth2/jwks`).
    if (req.method == "GET") {
        curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, nullptr);
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, nullptr);
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, -1L);
        curl_easy_setopt(h, CURLOPT_HTTPGET, 1L);
    } else {
        curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, req.method.c_str());
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, req.body.c_str());
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE, static_cast<long>(req.body.size()));
    }

    // Request headers.
    struct curl_slist* header_list = nullptr;
    for (const auto& kv : req.headers) {
        std::string h_line = kv.first + ": " + kv.second;
        header_list = curl_slist_append(header_list, h_line.c_str());
    }
    // I11: suppress `Expect: 100-continue`. libcurl adds it automatically once a
    // request body crosses EXPECT_100_THRESHOLD and then waits up to
    // CURLOPT_EXPECT_100_TIMEOUT_MS (1 s by default) for an interim response the
    // server may never send. Measured against libcurl 8.5 that threshold is 1 MiB
    // — so it is NOT the source of the observed ~280 ms tail, whose bodies are far
    // smaller — but older libcurl builds use 1 KiB, and a large enough batch-check
    // payload crosses even 1 MiB. Suppressing it is free: the body is fully in
    // memory, so sending it optimistically always wins over a round trip.
    header_list = curl_slist_append(header_list, "Expect:");
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, header_list);

    // Response capture.
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_body_cb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, &resp);

    // ---- §6 strict TLS: ALWAYS verify peer + host. Never disabled. ----
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);

    // Optional custom CA added to the trust chain (in-memory blob; §6).
    if (impl_->cfg.has_custom_ca()) {
        struct curl_blob ca_blob;
        ca_blob.data = const_cast<char*>(impl_->cfg.custom_ca_pem.data());
        ca_blob.len = impl_->cfg.custom_ca_pem.size();
        ca_blob.flags = CURL_BLOB_COPY;
        curl_easy_setopt(h, CURLOPT_CAINFO_BLOB, &ca_blob);
    }

    // Optional mTLS client identity (in-memory blobs, no temp files; §6.1).
    if (impl_->cfg.has_client_cert()) {
        struct curl_blob cert_blob;
        cert_blob.data = const_cast<char*>(impl_->cfg.client_cert_pem.data());
        cert_blob.len = impl_->cfg.client_cert_pem.size();
        cert_blob.flags = CURL_BLOB_COPY;
        curl_easy_setopt(h, CURLOPT_SSLCERT_BLOB, &cert_blob);
        curl_easy_setopt(h, CURLOPT_SSLCERTTYPE, "PEM");

        const std::string& key_pem = detail::reveal(impl_->cfg.client_key_pem);
        struct curl_blob key_blob;
        key_blob.data = const_cast<char*>(key_pem.data());
        key_blob.len = key_pem.size();
        key_blob.flags = CURL_BLOB_COPY;
        curl_easy_setopt(h, CURLOPT_SSLKEY_BLOB, &key_blob);
        curl_easy_setopt(h, CURLOPT_SSLKEYTYPE, "PEM");
    }

    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT_MS, impl_->cfg.connect_timeout_ms);
    curl_easy_setopt(h, CURLOPT_TIMEOUT_MS, impl_->cfg.request_timeout_ms);
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);

    const CURLcode rc = curl_easy_perform(h);
    if (rc == CURLE_OK) {
        long status = 0;
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &status);
        resp.status = status;
    } else {
        resp.transport_error = curl_easy_strerror(rc);
    }

    if (header_list != nullptr) curl_slist_free_all(header_list);
    return resp;
}

Transport CurlTransport::make_transport(TlsConfig cfg) {
    auto shared = std::make_shared<CurlTransport>(std::move(cfg));
    return [shared](const HttpRequest& req) -> HttpResponse { return shared->perform(req); };
}

}  // namespace axiam
