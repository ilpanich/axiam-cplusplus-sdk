// I11 — connection reuse / latency-tail regression tests.
//
// The run-4 SDK benchmark showed an excellent p50 (~3.3 ms) with a p95 of
// 264-336 ms on check/batch at every profile: the classic shape of a workload
// that is mostly served off a hot keep-alive connection but occasionally pays a
// full reconnect. These tests pin the two behaviours the transport must have for
// that not to happen:
//
//   1. N sequential requests through one Client open exactly ONE TCP connection
//      (keep-alive is honoured; nothing forbids reuse or forces a fresh connect).
//   2. A POST body over libcurl's auto-Expect threshold does NOT carry
//      `Expect: 100-continue`, so the request never waits on an interim response
//      the server may not send. (Measured against libcurl 8.5 that threshold is
//      1 MiB, not the 1 KiB of older builds — so Expect is ruled out as the cause
//      of the observed tail, but suppressing it is still required for large batch
//      payloads and for SDK consumers linking an older libcurl.)
//
// The server here is a keep-alive-capable HTTP/1.1 stub on loopback that counts
// accepted connections and records the headers it saw.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "assert.hpp"
#include "axiam/client.hpp"

using namespace axiam;

namespace {

/// HTTP/1.1 stub that keeps connections alive and counts accepts.
struct KeepAliveServer {
    int listen_fd = -1;
    int port = 0;
    std::atomic<bool> stop{false};
    std::atomic<int> connections{0};
    std::atomic<int> requests{0};
    std::thread thr;

    std::mutex mtx;
    std::vector<std::string> expect_headers;  // one entry per request ("" when absent)
    std::vector<std::string> methods;         // request-line verb per request

    bool start() {
        listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) return false;
        int one = 1;
        ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) return false;
        socklen_t len = sizeof(addr);
        ::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &len);
        port = ntohs(addr.sin_port);
        if (::listen(listen_fd, 8) < 0) return false;
        thr = std::thread([this] { run(); });
        return true;
    }

    /// Idempotent, and also run from the destructor: a failing assertion unwinds
    /// past shutdown(), and a joinable std::thread in a destructor terminates the
    /// whole process — which would hide the assertion that actually failed.
    ~KeepAliveServer() { shutdown(); }

    void shutdown() {
        stop.store(true);
        if (thr.joinable()) thr.join();
        if (listen_fd >= 0) ::close(listen_fd);
        listen_fd = -1;
    }

    static bool readable(int fd, int timeout_ms) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
        return ::select(fd + 1, &rfds, nullptr, nullptr, &tv) > 0;
    }

    static std::string header_value(const std::string& req, const std::string& name) {
        std::string lower_req = req, lower_name = name;
        for (auto& ch : lower_req) ch = static_cast<char>(::tolower(ch));
        for (auto& ch : lower_name) ch = static_cast<char>(::tolower(ch));
        auto pos = lower_req.find("\n" + lower_name + ":");
        if (pos == std::string::npos) return {};
        pos = req.find(':', pos);
        auto end = req.find("\r\n", pos);
        std::string v = req.substr(pos + 1, end - pos - 1);
        size_t s = v.find_first_not_of(" \t");
        return s == std::string::npos ? std::string{} : v.substr(s);
    }

    void run() {
        while (!stop.load()) {
            if (!readable(listen_fd, 100)) continue;
            int fd = ::accept(listen_fd, nullptr, nullptr);
            if (fd < 0) continue;
            connections.fetch_add(1);
            serve_connection(fd);
            ::close(fd);
        }
    }

    /// Serve requests on one connection until the peer closes or we are stopped.
    void serve_connection(int fd) {
        std::string pending;
        while (!stop.load()) {
            if (!readable(fd, 100)) continue;

            char buf[4096];
            const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) return;  // peer closed
            pending.append(buf, static_cast<size_t>(n));

            // Drain as many complete requests as the buffer holds.
            for (;;) {
                const auto header_end = pending.find("\r\n\r\n");
                if (header_end == std::string::npos) break;
                const std::string head = pending.substr(0, header_end + 4);

                size_t want = 0;
                const std::string cl = header_value(head, "Content-Length");
                if (!cl.empty()) want = static_cast<size_t>(std::stoul(cl));
                size_t have = pending.size() - (header_end + 4);
                while (have < want) {
                    if (!readable(fd, 200)) break;
                    const ssize_t m = ::recv(fd, buf, sizeof(buf), 0);
                    if (m <= 0) return;
                    pending.append(buf, static_cast<size_t>(m));
                    have = pending.size() - (header_end + 4);
                }
                if (have < want) return;

                {
                    std::lock_guard<std::mutex> lock(mtx);
                    expect_headers.push_back(header_value(head, "Expect"));
                    const auto sp = head.find(' ');
                    methods.push_back(sp == std::string::npos ? std::string{} : head.substr(0, sp));
                }
                requests.fetch_add(1);

                const std::string body = R"({"allowed":true})";
                std::string resp = "HTTP/1.1 200 OK\r\n";
                resp += "Content-Type: application/json\r\n";
                resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
                resp += "Connection: keep-alive\r\n\r\n";  // NO `Connection: close`
                resp += body;
                if (::send(fd, resp.data(), resp.size(), 0) < 0) return;

                pending.erase(0, header_end + 4 + want);
            }
        }
    }
};

}  // namespace

AXIAM_TEST("I11: N sequential requests reuse a single TCP connection") {
    KeepAliveServer server;
    AXIAM_REQUIRE(server.start());

    Client c = Client::builder()
                   .base_url("http://127.0.0.1:" + std::to_string(server.port))
                   .tenant_slug("acme")
                   .build();  // real libcurl transport

    constexpr int kRequests = 12;
    for (int i = 0; i < kRequests; ++i) {
        AccessDecision d = c.check_access("read", "res-" + std::to_string(i));
        AXIAM_CHECK(d.allowed);
    }

    // The client must be torn down before the server: the connection is held
    // open for the client's lifetime, which is exactly the point.
    server.shutdown();

    AXIAM_CHECK(server.requests.load() == kRequests);
    // The regression: anything that churns handles, sets CURLOPT_FORBID_REUSE /
    // CURLOPT_FRESH_CONNECT, or retires the pooled connection would show up here
    // as more than one accept.
    AXIAM_CHECK(server.connections.load() == 1);
}

AXIAM_TEST("I11: a GET after a POST keeps the same connection and the right verb") {
    KeepAliveServer server;
    AXIAM_REQUIRE(server.start());

    Client c = Client::builder()
                   .base_url("http://127.0.0.1:" + std::to_string(server.port))
                   .tenant_slug("acme")
                   .build();

    c.check_access("read", "res-1");   // POST
    c.jwks().refresh_keys();           // GET /oauth2/jwks
    c.check_access("read", "res-2");   // POST again

    server.shutdown();

    AXIAM_REQUIRE(server.methods.size() == 3);
    AXIAM_CHECK(server.methods[0] == "POST");
    // CURLOPT_CUSTOMREQUEST is sticky on a reused easy handle: without an explicit
    // reset this GET goes out with the previous POST's verb.
    AXIAM_CHECK(server.methods[1] == "GET");
    AXIAM_CHECK(server.methods[2] == "POST");
    AXIAM_CHECK(server.connections.load() == 1);
}

AXIAM_TEST("I11: a large POST body carries no Expect: 100-continue header") {
    KeepAliveServer server;
    AXIAM_REQUIRE(server.start());

    Client c = Client::builder()
                   .base_url("http://127.0.0.1:" + std::to_string(server.port))
                   .tenant_slug("acme")
                   .build();

    // Deliberately past 1 MiB — libcurl 8.5's measured EXPECT_100_THRESHOLD, and
    // well past the 1 KiB used by older libcurl. Without the explicit `Expect:`
    // suppression in the transport this request goes out with
    // `Expect: 100-continue` and stalls waiting for an interim response.
    std::vector<AccessCheck> checks;
    const std::string long_id(1100, 'r');
    for (int i = 0; i < 1024; ++i) {
        AccessCheck chk;
        chk.action = "read";
        chk.resource_id = long_id + std::to_string(i);
        checks.push_back(chk);
    }
    c.batch_check(checks);

    server.shutdown();

    AXIAM_REQUIRE(server.expect_headers.size() == 1);
    // Empty means the header was absent — libcurl's automatic
    // `Expect: 100-continue` (and its 1s stall waiting for the interim response)
    // is suppressed.
    AXIAM_CHECK(server.expect_headers[0].empty());
}
