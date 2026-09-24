// CONTRACT.md §6.1 rule 6 (contract 1.51) — "authenticate_device() issues POST
// /api/v1/auth/device with no request body", against a REAL loopback TLS server and
// the SDK's real libcurl transport.
//
// The lesson this file exists to not repeat (test_device_auth.cpp's fake transport has
// no libcurl handle to default a Content-Type on its own): a fake transport builds
// exactly the HttpRequest the SDK handed it and nothing more, so it cannot catch a
// defect that lives in what libcurl ADDS on top of that request. Rule 6 was broken in
// two independent places at once -- client.cpp stated `Content-Type: application/json`
// explicitly, AND (found while fixing the first) libcurl defaults an UNSTATED
// Content-Type to `application/x-www-form-urlencoded` on its own whenever
// CURLOPT_POSTFIELDS is set, even to an empty buffer. A test against the fake transport
// only ever sees the first. This one looks at the raw bytes a real curl handle put on
// the wire, which is the only place both defects are visible at once.
//
// PKI (throwaway CA, server cert with an IP:127.0.0.1 SAN, client cert/key) is
// generated once, at test-binary startup, into a temp directory removed on exit --
// shelled out to the system `openssl` CLI, the same tool
// scripts/make-swagger-ui-placeholder.sh-style generation elsewhere in this project's
// tooling already assumes is present, and the same commands the C SDK's
// tests/gen_pki.sh runs at CMake-fixture time. Generating it once per process, in
// process, keeps this self-contained the way test_integration_curl.cpp already is,
// with no new CMake fixture or second test binary.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "assert.hpp"
#include "axiam/client.hpp"

using namespace axiam;

namespace {

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Throwaway test PKI, generated once for the whole binary and cleaned up at exit.
// Mirrors tests/gen_pki.sh in the C SDK: a self-signed CA, a server cert with a
// loopback SAN (so libcurl's strict CURLOPT_SSL_VERIFYHOST passes against
// https://127.0.0.1), and a client identity cert signed by the same CA.
struct TestPki {
    char dir[64] = {};
    std::string ca_pem, ca_crt_path, server_crt_path, server_key_path, client_cert_pem,
        client_key_pem;
    bool ok = false;

    TestPki() {
        std::snprintf(dir, sizeof(dir), "/tmp/axiam_cpp_tls_pki_XXXXXX");
        if (::mkdtemp(dir) == nullptr) return;
        const std::string d = dir;
        auto run = [](const std::string& cmd) {
            std::string full = cmd + " >/dev/null 2>&1";
            return std::system(full.c_str()) == 0;
        };
        bool good = true;
        good &= run("openssl req -x509 -newkey rsa:2048 -nodes -keyout " + d +
                    "/ca.key -out " + d + "/ca.crt -days 2 -subj \"/CN=AXIAM Test CA\"");
        good &= run("openssl req -newkey rsa:2048 -nodes -keyout " + d + "/client.key -out " +
                    d + "/client.csr -subj \"/CN=test-device\"");
        good &= run("openssl x509 -req -in " + d + "/client.csr -CA " + d + "/ca.crt -CAkey " +
                    d + "/ca.key -CAcreateserial -out " + d + "/client.crt -days 2");
        good &= run("openssl req -newkey rsa:2048 -nodes -keyout " + d + "/server.key -out " +
                    d + "/server.csr -subj \"/CN=localhost\"");
        {
            std::ofstream ext(d + "/server_ext.cnf");
            ext << "subjectAltName = IP:127.0.0.1, DNS:localhost\n";
        }
        good &= run("openssl x509 -req -in " + d + "/server.csr -CA " + d + "/ca.crt -CAkey " +
                    d + "/ca.key -CAcreateserial -extfile " + d +
                    "/server_ext.cnf -out " + d + "/server.crt -days 2");
        if (!good) return;

        ca_pem = read_file(d + "/ca.crt");
        ca_crt_path = d + "/ca.crt";
        server_crt_path = d + "/server.crt";
        server_key_path = d + "/server.key";
        client_cert_pem = read_file(d + "/client.crt");
        client_key_pem = read_file(d + "/client.key");
        ok = !ca_pem.empty() && !client_cert_pem.empty() && !client_key_pem.empty();
    }

    ~TestPki() {
        if (dir[0] == '\0') return;
        // Best-effort cleanup of a directory this process created and fully controls.
        const char* names[] = {"ca.key", "ca.crt", "ca.srl",       "client.key",
                               "client.csr", "client.crt",   "server.key",
                               "server.csr", "server.crt",  "server_ext.cnf"};
        for (const char* n : names) {
            std::string p = std::string(dir) + "/" + n;
            ::unlink(p.c_str());
        }
        ::rmdir(dir);
    }
};

int bind_listen(int* out_port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    if (::listen(fd, 4) != 0) {
        ::close(fd);
        return -1;
    }
    socklen_t alen = sizeof(addr);
    ::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &alen);
    *out_port = ntohs(addr.sin_port);
    return fd;
}

// Accepts ONE connection, completes ONE TLS handshake requesting (not requiring) a
// client certificate, reads the request up to the blank line ending the headers
// (there is no body on this request -- that is exactly what is under test, so the
// header terminator is the whole message on success), and answers with a device-auth
// body. `out_raw` receives the raw HTTP header text; `out_ok`/`out_saw_cert` receive
// completion/certificate flags.
//
// Lesson from C-10 (C SDK, tests/test_device_auth_tls.c, orchestrator fix 7f3d5db): the
// completion flag is set BEFORE SSL_write, not after. The client can only observe this
// round complete once it has read the response, which happens after SSL_write returns
// here -- so setting the flag first guarantees the main thread's read of it (which only
// happens after the client call has returned) sees it true. Set AFTER the write, the
// two threads' orderings are unconstrained by anything but the socket, and valgrind's
// serialised scheduling turned that into an observed race in the C port.
void handle_one(int listen_fd, const std::string& server_crt, const std::string& server_key,
               const std::string& ca_crt_path, bool* out_ok, bool* out_saw_cert,
               std::string* out_raw) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(listen_fd, &rfds);
    timeval tv{5, 0};
    if (::select(listen_fd + 1, &rfds, nullptr, nullptr, &tv) <= 0) return;

    int cfd = ::accept(listen_fd, nullptr, nullptr);
    if (cfd < 0) return;
    timeval io{3, 0};
    ::setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &io, sizeof(io));
    ::setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &io, sizeof(io));

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        ::close(cfd);
        return;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, server_crt.c_str(), SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, server_key.c_str(), SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        ::close(cfd);
        return;
    }
    // §6.1: the fixture client always presents its configured identity, so requesting
    // (not requiring -- SSL_VERIFY_PEER without SSL_VERIFY_FAIL_IF_NO_PEER_CERT) it is
    // harmless either way and lets out_saw_cert confirm mTLS actually ran.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_load_verify_locations(ctx, ca_crt_path.c_str(), nullptr);
    STACK_OF(X509_NAME)* cas = SSL_load_client_CA_file(ca_crt_path.c_str());
    if (cas) SSL_CTX_set_client_CA_list(ctx, cas);

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        ::close(cfd);
        return;
    }
    SSL_set_fd(ssl, cfd);

    if (SSL_accept(ssl) == 1) {
        if (out_saw_cert) {
            X509* peer = SSL_get1_peer_certificate(ssl);
            if (peer) {
                *out_saw_cert = true;
                X509_free(peer);
            }
        }

        char buf[8192];
        int total = 0;
        while (total < static_cast<int>(sizeof(buf)) - 1) {
            int r = SSL_read(ssl, buf + total, static_cast<int>(sizeof(buf)) - 1 - total);
            if (r <= 0) break;
            total += r;
            buf[total] = '\0';
            if (std::strstr(buf, "\r\n\r\n")) break;
        }
        if (out_raw && total > 0) *out_raw = std::string(buf, static_cast<size_t>(total));

        static const char kBody[] =
            R"({"access_token":"dev-tok-tls","token_type":"Bearer","expires_in":900})";
        char resp[512];
        int n = std::snprintf(resp, sizeof(resp),
                              "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                              "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                              std::strlen(kBody), kBody);
        // The lesson: mark complete BEFORE the response leaves.
        if (out_ok) *out_ok = true;
        if (n > 0) SSL_write(ssl, resp, n);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ::close(cfd);
}

}  // namespace

AXIAM_TEST("§6.1 rule 6: authenticate_device() over a REAL TLS connection sends no "
          "request body and no Content-Type") {
    // "The toolchain is unavailable" is a claim about a search, made twice
    // (fix-common.md): OpenSSL the LIBRARY is a hard `find_package(OpenSSL REQUIRED)`
    // dependency of this whole test binary already, and the `openssl` CLI used here
    // only to generate throwaway PKI is the same tool this project's build-hygiene
    // notes already assume is on PATH. A failed generation fails loudly rather than
    // silently skipping, so a real regression on a machine that does have it is never
    // hidden as "PKI unavailable".
    TestPki pki;
    AXIAM_REQUIRE(pki.ok);

    int port = -1;
    int fd = bind_listen(&port);
    AXIAM_REQUIRE(fd >= 0);

    bool srv_ok = false;
    bool srv_saw_cert = false;
    std::string raw_request;
    std::thread server([&] {
        handle_one(fd, pki.server_crt_path, pki.server_key_path, pki.ca_crt_path, &srv_ok,
                  &srv_saw_cert, &raw_request);
    });

    Client client = Client::builder()
                        .base_url("https://127.0.0.1:" + std::to_string(port))
                        .tenant_slug("acme")
                        .connect_timeout(std::chrono::milliseconds(3000))
                        .request_timeout(std::chrono::milliseconds(5000))
                        .with_custom_ca(pki.ca_pem)
                        .with_client_cert(pki.client_cert_pem, pki.client_key_pem)
                        .build();

    DeviceAuth result = client.authenticate_device();

    server.join();
    ::close(fd);

    AXIAM_REQUIRE(srv_ok);  // device login did not complete server-side
    AXIAM_CHECK(srv_saw_cert);
    AXIAM_CHECK(result.token_type == "Bearer");

    // Case-insensitive search for a header LINE starting "content-type:" -- present
    // anywhere in the captured request text is the defect (client.cpp's own explicit
    // header, OR libcurl's un-suppressed default for an empty POSTFIELDS buffer).
    std::string lower = raw_request;
    for (auto& c : lower) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
    AXIAM_CHECK(lower.find("content-type:") == std::string::npos);

    // The body is either declared zero-length or simply absent from the wire. Find the
    // header/body boundary and check both: a Content-Length header, if present, names
    // exactly 0; and nothing follows the blank line that ends the headers.
    auto term = raw_request.find("\r\n\r\n");
    AXIAM_REQUIRE(term != std::string::npos);
    const std::string after_headers = raw_request.substr(term + 4);
    AXIAM_CHECK(after_headers.empty());

    auto cl_pos = lower.find("content-length:");
    if (cl_pos != std::string::npos) {
        auto eol = raw_request.find("\r\n", cl_pos);
        std::string value = raw_request.substr(cl_pos + std::strlen("content-length:"),
                                                eol - (cl_pos + std::strlen("content-length:")));
        size_t s = value.find_first_not_of(" \t");
        size_t e = value.find_last_not_of(" \t");
        std::string trimmed = (s == std::string::npos) ? "" : value.substr(s, e - s + 1);
        AXIAM_CHECK(trimmed == "0");
    }
    // No Content-Length header at all is the other acceptable shape (curl omits it
    // entirely for some code paths on a truly empty, non-form body).
}
