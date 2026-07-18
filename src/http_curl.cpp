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
    auto* headers = static_cast<HeaderMap*>(userdata);
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
        (*headers)[name] = value;
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
    }

    ~Impl() {
        if (handle != nullptr) curl_easy_cleanup(handle);
    }
};

CurlTransport::CurlTransport(TlsConfig cfg) : impl_(std::make_unique<Impl>(std::move(cfg))) {}
CurlTransport::~CurlTransport() = default;

HttpResponse CurlTransport::perform(const HttpRequest& req) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    CURL* h = impl_->handle;
    HttpResponse resp;

    curl_easy_setopt(h, CURLOPT_URL, req.url.c_str());

    // Method + body.
    if (req.method == "GET") {
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
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, header_list);

    // Response capture.
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, write_body_cb);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, &resp.headers);

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
