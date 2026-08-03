#include "axiam/http_curl.hpp"

#include <curl/curl.h>

#include <mutex>
#include <string>

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
    CURL* handle = nullptr;
    std::mutex mtx;

    explicit Impl(TlsConfig c) : cfg(std::move(c)) {
        ensure_curl_global_init();
        handle = curl_easy_init();
        // Enable the in-memory cookie engine for this handle (§4). An empty
        // filename turns the engine on without reading/writing any file.
        curl_easy_setopt(handle, CURLOPT_COOKIEFILE, "");
        apply_connection_reuse_options(handle);
    }

    ~Impl() {
        if (handle != nullptr) curl_easy_cleanup(handle);
    }

    // ---- I11: keep the connection hot for the handle's whole lifetime. ----
    //
    // One easy handle serves every request a Client makes, so libcurl's
    // connection cache should keep a single TCP+TLS connection hot and the p50
    // reflects that (~3 ms). The bimodal tail came from libcurl *defaults* that
    // periodically throw that connection away and then make re-establishing it
    // expensive:
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
    std::lock_guard<std::mutex> lock(impl_->mtx);
    CURL* h = impl_->handle;
    HttpResponse resp;

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
