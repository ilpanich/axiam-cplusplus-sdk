// Integration test: drive the REAL libcurl transport against a tiny in-process
// HTTP/1.1 server (raw sockets on a background thread). Exercises request
// building, response/header parsing, the §4 cookie engine (session cookie set on
// login is replayed on the next request), and §3 CSRF capture — end to end,
// over loopback plaintext HTTP (no TLS material needed).
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

struct SeenRequest {
    std::string path;
    bool had_cookie = false;
    std::string cookie_header;  // raw value, so a specific cookie can be told apart from "some cookie"
    std::string tenant;
    std::string csrf;
};

struct MiniServer {
    int listen_fd = -1;
    int port = 0;
    std::atomic<bool> stop{false};
    std::thread thr;
    std::mutex mtx;
    std::vector<SeenRequest> seen;

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
        if (::listen(listen_fd, 8) < 0) return false;
        thr = std::thread([this] { run(); });
        return true;
    }

    void shutdown() {
        stop.store(true);
        if (thr.joinable()) thr.join();
        if (listen_fd >= 0) ::close(listen_fd);
    }

    static std::string header_value(const std::string& req, const std::string& name) {
        // Case-insensitive header search within the request head.
        std::string lower_req = req;
        std::string lower_name = name;
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
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listen_fd, &rfds);
            timeval tv{0, 200000};  // 200ms
            int rc = ::select(listen_fd + 1, &rfds, nullptr, nullptr, &tv);
            if (rc <= 0) continue;
            int fd = ::accept(listen_fd, nullptr, nullptr);
            if (fd < 0) continue;
            handle(fd);
            ::close(fd);
        }
    }

    void handle(int fd) {
        std::string data;
        char buf[2048];
        // Read until end of headers.
        size_t header_end = std::string::npos;
        while (header_end == std::string::npos) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) return;
            data.append(buf, static_cast<size_t>(n));
            header_end = data.find("\r\n\r\n");
        }
        // Drain the body if Content-Length is present.
        std::string cl = header_value(data, "Content-Length");
        if (!cl.empty()) {
            size_t want = static_cast<size_t>(std::stoul(cl));
            size_t have = data.size() - (header_end + 4);
            while (have < want) {
                ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                if (n <= 0) break;
                data.append(buf, static_cast<size_t>(n));
                have += static_cast<size_t>(n);
            }
        }

        // Parse request line: METHOD SP PATH SP HTTP/1.1
        std::string path;
        {
            auto sp1 = data.find(' ');
            auto sp2 = data.find(' ', sp1 + 1);
            if (sp1 != std::string::npos && sp2 != std::string::npos)
                path = data.substr(sp1 + 1, sp2 - sp1 - 1);
        }

        SeenRequest sr;
        sr.path = path;
        sr.cookie_header = header_value(data, "Cookie");
        sr.had_cookie = !sr.cookie_header.empty();
        sr.tenant = header_value(data, "X-Tenant-ID");
        sr.csrf = header_value(data, "X-CSRF-Token");
        {
            std::lock_guard<std::mutex> lock(mtx);
            seen.push_back(sr);
        }

        std::string body;
        std::string extra_headers;
        if (path.find("/oauth2/jwks") != std::string::npos) {
            body = R"({"keys":[]})";
        } else if (path.find("/auth/login") != std::string::npos) {
            body =
                R"({"session_id":"s","expires_in":900,)"
                R"("user":{"id":"u","username":"a","email":"a@x","tenant_id":"t"}})";
            extra_headers =
                "Set-Cookie: axiam_session=xyz; Path=/\r\n"
                "X-CSRF-Token: csrf-int\r\n";
        } else if (path.find("/webauthn/setup/register/start") != std::string::npos) {
            // §24.1 (contract 1.45): a StartRegistrationResponse, same shape as
            // every other webauthn */start.
            body = R"({"challenge":{"publicKey":{"challenge":"abc"}},"state_token":"st-int"})";
        } else if (path.find("/webauthn/setup/register/finish") != std::string::npos) {
            // A LoginSuccessResponse that ADOPTS a session — a DIFFERENT cookie
            // from login's, so a later request carrying it proves the merge into
            // the shared jar actually happened rather than the original login
            // cookie merely surviving.
            body =
                R"({"session_id":"s2","expires_in":900,)"
                R"("user":{"id":"u2","username":"a2","email":"a2@x","tenant_id":"t"}})";
            extra_headers =
                "Set-Cookie: axiam_access=post_setup_token; Path=/\r\n"
                "X-CSRF-Token: csrf-post-setup\r\n";
        } else {
            body = R"({"allowed":true})";
        }

        std::string resp = "HTTP/1.1 200 OK\r\n";
        resp += "Content-Type: application/json\r\n";
        resp += extra_headers;
        resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        resp += "Connection: close\r\n\r\n";
        resp += body;
        ::send(fd, resp.data(), resp.size(), 0);
    }
};

}  // namespace

AXIAM_TEST("libcurl transport: cookie engine + CSRF + tenant header end-to-end") {
    MiniServer server;
    AXIAM_REQUIRE(server.start());

    Client c = Client::builder()
                   .base_url("http://127.0.0.1:" + std::to_string(server.port))
                   .tenant_slug("acme")
                   .org_id("org-1")
                   .build();  // real libcurl transport

    LoginResult login = c.login("a", "b");
    AXIAM_REQUIRE(login.user.has_value());
    AXIAM_REQUIRE(c.csrf_token().has_value());
    AXIAM_CHECK(*c.csrf_token() == "csrf-int");

    AccessDecision d = c.check_access("read", "res-1");
    AXIAM_CHECK(d.allowed);

    server.shutdown();

    // Assertions on what the server actually received.
    AXIAM_REQUIRE(server.seen.size() >= 2);
    const auto& login_req = server.seen[0];
    const auto& check_req = server.seen[1];
    AXIAM_CHECK(login_req.tenant == "acme");           // §5 on first request
    AXIAM_CHECK(check_req.tenant == "acme");            // §5 on every request
    AXIAM_CHECK(check_req.had_cookie);                  // §4 cookie replayed
    AXIAM_CHECK(check_req.csrf == "csrf-int");          // §3 CSRF echoed
}

// CONTRACT.md §24.8 (contract 1.45): "With a session configured AND a setup
// token supplied, assert on the transport that neither call sent the
// session's Authorization header or cookie." This is the one property
// test_webauthn.cpp's fake transport cannot prove — it has no cookie jar of
// its own to leak a session out of — so it is asserted here, against the REAL
// libcurl transport and a shared jar that genuinely holds a session cookie by
// the time these two calls run.
//
// The second half of the same test is the other side of §24.8's "adopts
// credentials exactly as mfa_setup_confirm does": setup/register/finish's own
// Set-Cookie must still reach every request AFTER it, through the ordinary
// pooled/shared path — proving perform_isolated()'s merge back into the
// shared jar (http_curl.cpp) actually works, not just that it compiles.
AXIAM_TEST("libcurl transport: setup/register/* never replays the jar, and finish's cookie still lands in it") {
    MiniServer server;
    AXIAM_REQUIRE(server.start());

    Client c = Client::builder()
                   .base_url("http://127.0.0.1:" + std::to_string(server.port))
                   .tenant_slug("acme")
                   .org_id("org-1")
                   .build();  // real libcurl transport, one shared cookie jar

    // A session IS configured — §24.8's precondition — via an ordinary login,
    // exactly as the test above does.
    LoginResult login = c.login("a", "b");
    AXIAM_REQUIRE(login.user.has_value());

    const auto challenge =
        c.webauthn_setup_register_start(axiam::Sensitive<std::string>("setup-tok-int"));
    const LoginResult setup_done = c.webauthn_setup_register_finish(
        axiam::Sensitive<std::string>("setup-tok-int"), challenge.state_token, "Ada's laptop",
        "{}");
    AXIAM_REQUIRE(setup_done.user.has_value());

    // One more ordinary, session-authenticated call — through the SAME pooled
    // handles login() and check_access() already used above.
    AccessDecision d = c.check_access("read", "res-2");
    AXIAM_CHECK(d.allowed);

    server.shutdown();

    AXIAM_REQUIRE(server.seen.size() >= 4);
    const auto& login_req = server.seen[0];
    const auto& setup_start_req = server.seen[1];
    const auto& setup_finish_req = server.seen[2];
    const auto& check_req = server.seen[3];

    AXIAM_CHECK(login_req.path.find("/auth/login") != std::string::npos);
    AXIAM_CHECK(setup_start_req.path.find("/webauthn/setup/register/start") != std::string::npos);
    AXIAM_CHECK(setup_finish_req.path.find("/webauthn/setup/register/finish") !=
               std::string::npos);

    // §24.8: NEITHER setup/register call carried the session cookie login()
    // had already caused curl to store — even though it exists, in the same
    // shared jar, for the whole rest of this test.
    AXIAM_CHECK_FALSE(setup_start_req.had_cookie);
    AXIAM_CHECK_FALSE(setup_finish_req.had_cookie);
    // §5 rule 2 admits no exceptions — the tenant header still goes out.
    AXIAM_CHECK(setup_start_req.tenant == "acme");
    AXIAM_CHECK(setup_finish_req.tenant == "acme");

    // setup/register/finish's OWN Set-Cookie reached the shared jar despite the
    // isolated handle that carried the request itself never touching it — the
    // ordinary check_access() call afterward carries it.
    AXIAM_CHECK(check_req.had_cookie);
    AXIAM_CHECK(check_req.cookie_header.find("axiam_access=post_setup_token") !=
               std::string::npos);
    // The CSRF token captured from setup/register/finish's response, not
    // login's — proving the adoption happened on FINISH's response and not
    // merely left over from the earlier login.
    AXIAM_CHECK(check_req.csrf == "csrf-post-setup");
}

// Non-secret PEM stubs (see note in test_builder.cpp). The key marker is
// concatenated so no committed source contains a contiguous key header.
static const std::string kIntCaPem = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n";
static const std::string kIntCert = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n";
static const std::string kIntKey =
    std::string("-----BEGIN ") + "PRIVATE" + " KEY-----\nMIIBfake\n-----END KEY-----\n";

AXIAM_TEST("libcurl transport wires custom CA + client-cert blobs and a GET (jwks)") {
    MiniServer server;
    AXIAM_REQUIRE(server.start());

    // Custom CA + mTLS client identity are set as in-memory blobs. Over loopback
    // HTTP they are ignored by curl (no handshake), but the wiring branches in the
    // transport still execute — verifying they don't disturb a normal request.
    Client c = Client::builder()
                   .base_url("http://127.0.0.1:" + std::to_string(server.port))
                   .tenant_slug("acme")
                   .org_id("org-1")
                   .with_custom_ca(kIntCaPem)
                   .with_client_cert(kIntCert, kIntKey)
                   .build();

    LoginResult login = c.login("a", "b");
    AXIAM_CHECK(login.user.has_value());

    // Drive a GET through the real transport (JWKS fetch path).
    AXIAM_REQUIRE_NOTHROW(c.jwks().refresh_keys());

    server.shutdown();
    AXIAM_CHECK(server.seen.size() >= 2);
}

AXIAM_TEST("libcurl transport surfaces a real connection failure as NetworkError") {
    // Bind then immediately close a socket to obtain a definitely-closed port.
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    ::bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    socklen_t len = sizeof(addr);
    ::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len);
    int closed_port = ntohs(addr.sin_port);
    ::close(s);

    Client c = Client::builder()
                   .base_url("http://127.0.0.1:" + std::to_string(closed_port))
                   .tenant_slug("acme")
                   .connect_timeout(std::chrono::milliseconds(1500))
                   .request_timeout(std::chrono::milliseconds(1500))
                   .build();
    AXIAM_REQUIRE_THROWS_AS(c.login("a", "b"), NetworkError);
}
