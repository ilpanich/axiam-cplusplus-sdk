// D2: prove the libcurl transport performs requests CONCURRENTLY.
//
// Benchmark run 5 measured this SDK at check_access p50 3.2 ms against p95
// 280 ms — a tail its own acceptance bar (p95 <= 3x p50) rejects, unchanged
// from run 4 despite the I11 connection-lifetime work. The cause was not the
// wire: `CurlTransport::perform` held a mutex over a single libcurl easy
// handle, so a Client shared by N threads served requests strictly one at a
// time. p50 was the uncontended service time; p95 was queueing.
//
// A timing assertion would be flaky on a loaded CI box, so this test asserts
// the structural fact instead: with a server that holds each request open
// long enough for the others to arrive, the server must OBSERVE more than one
// request in flight simultaneously. A serialized transport can never make
// that true, no matter how fast or slow the machine is.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "assert.hpp"
#include "axiam/client.hpp"

using namespace axiam;

namespace {

/// A loopback HTTP/1.1 server that handles every accepted connection on its
/// own thread and deliberately dawdles before answering, so overlapping
/// requests overlap observably.
struct ConcurrentMiniServer {
    int listen_fd = -1;
    int port = 0;
    std::atomic<bool> stop{false};
    std::thread acceptor;
    std::vector<std::thread> workers;
    std::mutex workers_mtx;

    std::atomic<int> in_flight{0};
    std::atomic<int> max_in_flight{0};
    std::atomic<int> total{0};
    /// How long each request is held before the response is written.
    std::chrono::milliseconds hold{60};

    bool start() {
        listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) return false;
        int one = 1;
        ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;  // ephemeral
        if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) return false;
        socklen_t len = sizeof(addr);
        ::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&addr), &len);
        port = ntohs(addr.sin_port);
        if (::listen(listen_fd, 32) < 0) return false;
        acceptor = std::thread([this] { run(); });
        return true;
    }

    void shutdown() {
        stop.store(true);
        if (acceptor.joinable()) acceptor.join();
        {
            std::lock_guard<std::mutex> lock(workers_mtx);
            for (auto& t : workers) {
                if (t.joinable()) t.join();
            }
            workers.clear();
        }
        if (listen_fd >= 0) ::close(listen_fd);
    }

    void run() {
        while (!stop.load()) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listen_fd, &rfds);
            timeval tv{0, 100000};  // 100 ms
            if (::select(listen_fd + 1, &rfds, nullptr, nullptr, &tv) <= 0) continue;
            int fd = ::accept(listen_fd, nullptr, nullptr);
            if (fd < 0) continue;
            std::lock_guard<std::mutex> lock(workers_mtx);
            workers.emplace_back([this, fd] {
                serve(fd);
                ::close(fd);
            });
        }
    }

    /// One connection, potentially several keep-alive requests on it.
    void serve(int fd) {
        std::string data;
        char buf[4096];
        while (!stop.load()) {
            size_t header_end = data.find("\r\n\r\n");
            while (header_end == std::string::npos) {
                ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                if (n <= 0) return;
                data.append(buf, static_cast<size_t>(n));
                header_end = data.find("\r\n\r\n");
            }
            // Drain a Content-Length body if present.
            size_t body_start = header_end + 4;
            size_t want = 0;
            {
                std::string head = data.substr(0, header_end);
                for (auto& ch : head) ch = static_cast<char>(::tolower(ch));
                auto pos = head.find("content-length:");
                if (pos != std::string::npos) {
                    want = static_cast<size_t>(std::stoul(head.substr(pos + 15)));
                }
            }
            while (data.size() - body_start < want) {
                ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                if (n <= 0) return;
                data.append(buf, static_cast<size_t>(n));
            }

            const std::string path = request_path(data);

            const int now = in_flight.fetch_add(1) + 1;
            int seen_max = max_in_flight.load();
            while (now > seen_max && !max_in_flight.compare_exchange_weak(seen_max, now)) {
            }
            // Hold the request open so its siblings have time to arrive. A
            // serialized client cannot produce an overlap here; a concurrent
            // one cannot avoid it.
            std::this_thread::sleep_for(hold);
            in_flight.fetch_sub(1);
            total.fetch_add(1);

            std::string body;
            std::string extra;
            if (path.find("/auth/login") != std::string::npos) {
                body =
                    R"({"session_id":"s","expires_in":900,)"
                    R"("user":{"id":"u","username":"a","email":"a@x","tenant_id":"t"}})";
                extra =
                    "Set-Cookie: axiam_session=xyz; Path=/\r\n"
                    "X-CSRF-Token: csrf-conc\r\n";
            } else {
                body = R"({"allowed":true})";
            }
            std::string resp = "HTTP/1.1 200 OK\r\n";
            resp += "Content-Type: application/json\r\n";
            resp += extra;
            resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
            // Keep-alive: the point is that each pooled handle keeps its own
            // connection hot, so the server must not close after one request.
            resp += "Connection: keep-alive\r\n\r\n";
            resp += body;
            if (::send(fd, resp.data(), resp.size(), 0) <= 0) return;

            data.erase(0, body_start + want);
        }
    }

    static std::string request_path(const std::string& data) {
        auto sp1 = data.find(' ');
        auto sp2 = data.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) return {};
        return data.substr(sp1 + 1, sp2 - sp1 - 1);
    }
};

}  // namespace

AXIAM_TEST("libcurl transport serves concurrent callers in parallel, not one at a time") {
    ConcurrentMiniServer server;
    AXIAM_REQUIRE(server.start());
    const std::string base = "http://127.0.0.1:" + std::to_string(server.port);

    Client client = Client::builder()
                        .base_url(base)
                        .tenant_slug("default")
                        .org_slug("bench-org")
                        .build();
    // One login first, so the session cookie is in the shared jar before the
    // concurrent fan-out — this also exercises the CURLSH cookie sharing:
    // the checks below run on OTHER pooled handles and must still be
    // authenticated.
    client.login("u", "p");

    constexpr int kThreads = 6;
    std::vector<std::thread> callers;
    std::atomic<int> ok{0};
    callers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        callers.emplace_back([&client, &ok] {
            try {
                if (client.check_access("read", "11111111-1111-4111-8111-111111111111").allowed) {
                    ok.fetch_add(1);
                }
            } catch (...) {
                // Counted as not-ok; the assertions below report it.
            }
        });
    }
    for (auto& t : callers) t.join();

    const int overlap = server.max_in_flight.load();
    server.shutdown();

    // Every call must have succeeded — a check running on a handle other than
    // the one that logged in still has to carry the session cookie.
    AXIAM_CHECK(ok.load() == kThreads);
    // The actual regression guard. Before D2 this was exactly 1, always,
    // because one mutex-guarded easy handle served every caller in turn.
    AXIAM_CHECK(overlap > 1);
}

AXIAM_TEST("libcurl transport bounds itself at max_concurrent_requests") {
    ConcurrentMiniServer server;
    server.hold = std::chrono::milliseconds(40);
    AXIAM_REQUIRE(server.start());
    const std::string base = "http://127.0.0.1:" + std::to_string(server.port);

    // A pool capped at 2: eight callers must still all succeed, but the
    // server must never see more than two in flight. Blocking rather than
    // growing without bound is what keeps a burst of callers from opening an
    // unbounded number of connections to the server.
    Client client = Client::builder()
                        .base_url(base)
                        .tenant_slug("default")
                        .org_slug("bench-org")
                        .max_concurrent_requests(2)
                        .build();
    client.login("u", "p");

    constexpr int kThreads = 8;
    std::vector<std::thread> callers;
    std::atomic<int> ok{0};
    callers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        callers.emplace_back([&client, &ok] {
            try {
                if (client.check_access("read", "11111111-1111-4111-8111-111111111111").allowed) {
                    ok.fetch_add(1);
                }
            } catch (...) {
            }
        });
    }
    for (auto& t : callers) t.join();

    const int overlap = server.max_in_flight.load();
    server.shutdown();

    AXIAM_CHECK(ok.load() == kThreads);
    AXIAM_CHECK(overlap >= 1);
    AXIAM_CHECK(overlap <= 2);
}
