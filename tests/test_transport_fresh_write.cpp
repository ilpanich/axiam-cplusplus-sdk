// CONTRACT.md §34.2 P11 / §34.4 A6 (contract 1.60) -- "no second request by another route".
//
// "MUST NOT be retried" includes an HTTP library's own transparent re-send after a dropped
// connection. libcurl re-sends a request when a REUSED connection turns out dead before any
// byte of the reply -- including a POST/PUT/DELETE the server already read. The remedy where
// the library has no switch is a fresh connection per never-retried write that nothing reuses
// afterwards: CURLOPT_FRESH_CONNECT plus CURLOPT_FORBID_REUSE.
//
// The test the contract names: "a server that reads a write and drops the connection
// unanswered receives that write exactly once." Its companion: two GETs still share one
// connection (the options are per request, not a switch that costs keep-alive everywhere).
//
// The server is a loopback HTTP/1.1 stub, one thread per connection, that reads every request
// completely, answers a GET with 200 on a kept-alive connection, and on any other method
// closes the connection WITHOUT answering.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"

using namespace axiam;

namespace {

struct DropWriteServer {
    int listen_fd = -1;
    int port = 0;
    std::atomic<bool> stop{false};
    std::atomic<int> connections{0};
    std::atomic<int> gets{0};
    std::atomic<int> writes{0};  // writes READ in full, whether or not on a reused connection
    std::thread acceptor;
    std::mutex mtx;
    std::vector<std::thread> workers;

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
        if (::listen(listen_fd, 16) < 0) return false;
        acceptor = std::thread([this] { accept_loop(); });
        return true;
    }

    ~DropWriteServer() { shutdown(); }

    void shutdown() {
        stop.store(true);
        if (acceptor.joinable()) acceptor.join();
        std::vector<std::thread> done;
        {
            std::lock_guard<std::mutex> lock(mtx);
            done.swap(workers);
        }
        for (auto& t : done) {
            if (t.joinable()) t.join();
        }
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

    static size_t content_length(const std::string& head) {
        std::string lower = head;
        for (auto& ch : lower) ch = static_cast<char>(::tolower(ch));
        const auto pos = lower.find("\ncontent-length:");
        if (pos == std::string::npos) return 0;
        return static_cast<size_t>(std::stoul(head.substr(pos + 16)));
    }

    void accept_loop() {
        while (!stop.load()) {
            if (!readable(listen_fd, 50)) continue;
            const int fd = ::accept(listen_fd, nullptr, nullptr);
            if (fd < 0) continue;
            connections.fetch_add(1);
            std::lock_guard<std::mutex> lock(mtx);
            workers.emplace_back([this, fd] {
                serve(fd);
                ::close(fd);
            });
        }
    }

    void serve(int fd) {
        std::string pending;
        while (!stop.load()) {
            if (!readable(fd, 50)) continue;
            char buf[4096];
            const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) return;  // the client closed it
            pending.append(buf, static_cast<size_t>(n));
            for (;;) {
                const auto end = pending.find("\r\n\r\n");
                if (end == std::string::npos) break;
                const std::string head = pending.substr(0, end + 4);
                const size_t want = content_length(head);
                while (pending.size() < end + 4 + want) {
                    if (!readable(fd, 200)) return;
                    const ssize_t m = ::recv(fd, buf, sizeof(buf), 0);
                    if (m <= 0) return;
                    pending.append(buf, static_cast<size_t>(m));
                }
                pending.erase(0, end + 4 + want);
                if (head.compare(0, 4, "GET ") == 0) {
                    gets.fetch_add(1);
                    const std::string body = R"({"keys":[]})";
                    const std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                             "Content-Length: " + std::to_string(body.size()) +
                                             "\r\nConnection: keep-alive\r\n\r\n" + body;
                    if (::send(fd, resp.data(), resp.size(), 0) < 0) return;
                } else {
                    // The write was read in full. Drop the connection: no status line, no FIN
                    // before the request is counted -- exactly the "applied, answer lost" case.
                    writes.fetch_add(1);
                    return;
                }
            }
        }
    }
};

Client real_client(const DropWriteServer& server) {
    return Client::builder()
        .base_url("http://127.0.0.1:" + std::to_string(server.port))
        .tenant_slug("acme")
        .build();  // the real libcurl transport
}

}  // namespace

AXIAM_TEST("§34.2 P11 / A6: a write the server reads and drops unanswered arrives exactly once") {
    DropWriteServer server;
    AXIAM_REQUIRE(server.start());
    Client c = real_client(server);

    // A GET first, so a kept-alive connection sits in libcurl's pool: the one libcurl would
    // re-send a dropped write over, transparently, if the write were allowed to reuse it.
    c.jwks().refresh_keys();
    AXIAM_CHECK(server.gets.load() == 1);

    AXIAM_REQUIRE_THROWS_AS(c.login("alice", "pw"), NetworkError);

    server.shutdown();
    // Without CURLOPT_FRESH_CONNECT / CURLOPT_FORBID_REUSE this is 2: the write goes out on the
    // pooled connection, is dropped, and libcurl re-sends it on a new one.
    AXIAM_CHECK(server.writes.load() == 1);
}

AXIAM_TEST("§34.2 P11 / A6: a second write after a dropped one also arrives once each") {
    DropWriteServer server;
    AXIAM_REQUIRE(server.start());
    Client c = real_client(server);

    AXIAM_REQUIRE_THROWS_AS(c.login("alice", "pw"), NetworkError);
    AXIAM_REQUIRE_THROWS_AS(c.login("alice", "pw"), NetworkError);
    c.logout();  // best-effort: the failure is swallowed, but the write was still sent once

    server.shutdown();
    AXIAM_CHECK(server.writes.load() == 3);
    AXIAM_CHECK(server.connections.load() == 3);  // one fresh connection per write
}

AXIAM_TEST("§34.2 P11 / A6 companion: two GETs share one connection") {
    DropWriteServer server;
    AXIAM_REQUIRE(server.start());
    Client c = real_client(server);

    c.jwks().refresh_keys();
    c.jwks().refresh_keys();

    server.shutdown();
    AXIAM_CHECK(server.gets.load() == 2);
    AXIAM_CHECK(server.connections.load() == 1);
}

AXIAM_TEST("§34.2 P11 / A6 companion: a dropped write does not cost the GETs after it their connection") {
    DropWriteServer server;
    AXIAM_REQUIRE(server.start());
    Client c = real_client(server);

    c.jwks().refresh_keys();                                        // connection 1
    AXIAM_REQUIRE_THROWS_AS(c.login("alice", "pw"), NetworkError);  // connection 2, never reused
    c.jwks().refresh_keys();                                        // connection 1 again
    c.jwks().refresh_keys();

    server.shutdown();
    AXIAM_CHECK(server.gets.load() == 3);
    AXIAM_CHECK(server.writes.load() == 1);
    // The options are set per request in both directions on a pooled handle: the write's
    // FORBID_REUSE must not leak into the GETs that follow it.
    AXIAM_CHECK(server.connections.load() == 2);
}

// ---------------------------------------------------------------------------
// The seam: which requests the SDK marks as ones it may itself send twice.
// ---------------------------------------------------------------------------

AXIAM_TEST("§34.2 P11 / A6: only a request the SDK itself repeats is marked replayable") {
    auto st = std::make_shared<axtest::FakeState>();
    st->router = [](const HttpRequest& req, axtest::FakeState&) {
        if (req.url.find("/auth/login") != std::string::npos) {
            return axtest::json_response(
                200, R"({"session_id":"s","expires_in":900,"user":{"id":"u","username":"a",)"
                     R"("email":"a@x.io","tenant_id":"t","tenant_slug":"acme"}})");
        }
        return axtest::json_response(200, R"({"allowed":true,"results":[]})");
    };
    Client c = Client::builder()
                   .base_url("https://iam.example.com")
                   .tenant_slug("acme")
                   .transport(axtest::make_fake(st))
                   .build();

    c.login("alice", "pw");
    AXIAM_CHECK(st->last().method == "POST" && !st->last().replayable);  // a write, once

    c.check_access("read", "r-1");
    AXIAM_CHECK(st->last().method == "POST" && st->last().replayable);   // §16: a read, repeated
    AccessCheck one;
    one.action = "read";
    one.resource_id = "r-2";
    c.batch_check({one});
    AXIAM_CHECK(st->last().method == "POST" && st->last().replayable);

    c.logout();
    AXIAM_CHECK(!st->last().replayable);
}
