// CONTRACT.md §12.4 rule 2 "Stale-if-error, bounded" (contract 1.69, D-10): the JWKS cache's
// TTL ceiling, what counts as a successful fetch, and the TTL + 300 s bound after which held
// keys are never used. Every case runs on an injected clock, so the instants the conformance
// test names (TTL + 1 s, + 250 s, + 301 s) are exact and nothing sleeps.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "assert.hpp"
#include "axiam/http_curl.hpp"
#include "axiam/jwks.hpp"
#include "axiam/oidc.hpp"
#include "fake_transport.hpp"
#include "test_key.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::TestKey;

namespace {

using Clock = std::chrono::steady_clock;

/// What the fake JWKS endpoint answers while a test runs.
struct Mode {
    enum Kind { kServe, kFail503, kTransportError, kEmptySet, kGarbage, kNoJwkObjects, kRsaOnly, kNotModified } kind = kServe;
    std::string doc;
    std::string cache_control;
    std::string etag = "\"v1\"";
};

struct Rig {
    TestKey key;
    TestKey other;
    std::shared_ptr<FakeState> st = std::make_shared<FakeState>();
    std::shared_ptr<Mode> mode = std::make_shared<Mode>();
    std::shared_ptr<Clock::time_point> now = std::make_shared<Clock::time_point>(Clock::now());
    std::unique_ptr<JwksVerifier> v;

    explicit Rig(std::chrono::seconds ttl = std::chrono::seconds(300)) {
        other.kid = "unknown-kid";
        mode->doc = key.jwks_json();
        auto m = mode;
        st->router = [m](const HttpRequest&, FakeState&) {
            HttpResponse r;
            switch (m->kind) {
                case Mode::kServe:
                    r.status = 200;
                    r.body = m->doc;
                    r.headers["ETag"] = m->etag;
                    if (!m->cache_control.empty()) r.headers["Cache-Control"] = m->cache_control;
                    break;
                case Mode::kFail503: r.status = 503; break;
                case Mode::kTransportError: r.transport_error = "connection refused"; break;
                case Mode::kEmptySet: r.status = 200; r.body = R"({"keys":[]})"; break;
                case Mode::kGarbage: r.status = 200; r.body = "<html>not a jwks</html>"; break;
                case Mode::kNoJwkObjects: r.status = 200; r.body = R"({"keys":[{}]})"; break;
                case Mode::kRsaOnly:
                    r.status = 200;
                    r.body = R"({"keys":[{"kty":"RSA","kid":"r","n":"AQAB","e":"AQAB"}]})";
                    break;
                case Mode::kNotModified:
                    r.status = 304;
                    if (!m->cache_control.empty()) r.headers["Cache-Control"] = m->cache_control;
                    break;
            }
            return r;
        };
        v = std::make_unique<JwksVerifier>(axtest::make_fake(st), "https://api.example.test", ttl);
        auto n = now;
        v->_set_clock_test_seam([n] { return *n; });
    }
    void advance(int seconds) { *now += std::chrono::seconds(seconds); }
    std::size_t fetches() { return st->count_path("/oauth2/jwks"); }
    bool accepts(const TestKey& k) {
        return v->verify_with_reason(k.make_jwt("EdDSA", R"({"sub":"u"})")).ok;
    }
    std::string reason_for(const TestKey& k) {
        return v->verify_with_reason(k.make_jwt("EdDSA", R"({"sub":"u"})")).reason;
    }
};

}  // namespace

AXIAM_TEST("§12.4 rule 2 conformance: failing refresh serves held keys until TTL + 300 s, then refuses") {
    Rig r;
    AXIAM_REQUIRE(r.accepts(r.key));  // t0: cache filled
    AXIAM_REQUIRE(r.fetches() == 1);

    r.mode->kind = Mode::kFail503;  // every later fetch fails
    r.advance(299);
    AXIAM_CHECK(r.accepts(r.key));  // still within TTL: no fetch
    AXIAM_CHECK(r.fetches() == 1);

    r.advance(2);  // t0 + 301 s = TTL + 1 s
    AXIAM_CHECK(r.accepts(r.key));  // held kid accepted; one failed refresh attempted
    AXIAM_CHECK(r.fetches() == 2);

    r.advance(249);  // t0 + TTL + 250 s
    AXIAM_CHECK_FALSE(r.accepts(r.other));  // unknown kid refused
    AXIAM_CHECK(r.reason_for(r.other) == OidcValidationReason::kUnknownKid);
    AXIAM_CHECK(r.accepts(r.key));  // held kid still accepted (the failed unknown-kid refresh did not drop it)

    r.advance(51);  // t0 + TTL + 301 s
    AXIAM_CHECK_FALSE(r.accepts(r.key));  // past the bound: every token refused
    AXIAM_CHECK(r.reason_for(r.key) == OidcValidationReason::kUnknownKid);

    r.advance(120);  // past the failure window, mock serves the set again
    r.mode->kind = Mode::kServe;
    const std::size_t before = r.fetches();
    AXIAM_CHECK(r.accepts(r.key));  // accepted again after ONE successful fetch
    AXIAM_CHECK(r.fetches() == before + 1);
    AXIAM_CHECK(r.accepts(r.key));
    AXIAM_CHECK(r.fetches() == before + 1);
}

AXIAM_TEST("§12.4 rule 2 an empty key set is a failed refresh, not a replacement") {
    Rig r;
    AXIAM_REQUIRE(r.accepts(r.key));
    r.mode->kind = Mode::kEmptySet;
    r.advance(301);  // TTL + 1 s
    AXIAM_CHECK(r.accepts(r.key));
    AXIAM_CHECK(r.fetches() == 2);
    AXIAM_CHECK(r.v->cached_key_count() == 1);

    // The empty answer did not move the anchor either: the bound still runs from t0.
    r.advance(300);  // TTL + 301 s
    AXIAM_CHECK_FALSE(r.accepts(r.key));
}

AXIAM_TEST("§12.4 rule 2 a transport error and a non-JWKS body are failed refreshes too") {
    for (const auto kind :
         {Mode::kTransportError, Mode::kGarbage, Mode::kFail503, Mode::kNoJwkObjects}) {
        Rig r;
        AXIAM_REQUIRE(r.accepts(r.key));
        r.mode->kind = kind;
        r.advance(301);
        AXIAM_CHECK(r.accepts(r.key));
        AXIAM_CHECK(r.v->cached_key_count() == 1);
        r.advance(300);
        AXIAM_CHECK_FALSE(r.accepts(r.key));
    }
}

AXIAM_TEST("§12.4 rule 2 a failing endpoint costs one fetch per window, not one per token") {
    Rig r;
    AXIAM_REQUIRE(r.accepts(r.key));
    r.mode->kind = Mode::kFail503;
    r.advance(301);
    for (int i = 0; i < 20; ++i) AXIAM_CHECK(r.accepts(r.key));
    AXIAM_CHECK(r.fetches() == 2);  // the fill plus exactly one failed attempt
    r.advance(61);                  // the window has closed: one more attempt is allowed
    AXIAM_CHECK(r.accepts(r.key));
    AXIAM_CHECK(r.fetches() == 3);
}

AXIAM_TEST("§12.4 rule 2 a 304 to the conditional request re-confirms the set and moves the anchor") {
    Rig r;
    AXIAM_REQUIRE(r.accepts(r.key));
    r.mode->kind = Mode::kNotModified;
    r.advance(301);
    AXIAM_CHECK(r.accepts(r.key));
    AXIAM_CHECK(r.st->last().headers.count("If-None-Match") == 1);
    AXIAM_CHECK(r.st->last().headers.at("If-None-Match") == "\"v1\"");

    // Anchor is now t0 + 301, so t0 + 601 (TTL + 301 from the ORIGINAL fill) still verifies.
    r.advance(300);
    AXIAM_CHECK(r.accepts(r.key));
}

AXIAM_TEST("§12.4 rule 2 TTL is clamped to 300 s, configured or advertised") {
    {
        // A configured TTL of an hour is clamped: held keys retire at 300 + 300 s, not 3600 + 300.
        Rig r(std::chrono::seconds(3600));
        AXIAM_REQUIRE(r.accepts(r.key));
        r.mode->kind = Mode::kFail503;
        r.advance(301);
        AXIAM_CHECK(r.accepts(r.key));
        AXIAM_CHECK(r.fetches() == 2);  // a refresh was due at 300 s
        r.advance(300);
        AXIAM_CHECK_FALSE(r.accepts(r.key));
    }
    {
        // An advertised max-age=86400 is clamped the same way.
        Rig r;
        r.mode->cache_control = "public, max-age=86400";
        AXIAM_REQUIRE(r.accepts(r.key));
        r.advance(301);
        AXIAM_CHECK(r.accepts(r.key));
        AXIAM_CHECK(r.fetches() == 2);
    }
    {
        // A smaller advertised max-age is honoured.
        Rig r;
        r.mode->cache_control = "max-age=30";
        AXIAM_REQUIRE(r.accepts(r.key));
        r.advance(31);
        AXIAM_CHECK(r.accepts(r.key));
        AXIAM_CHECK(r.fetches() == 2);
    }
}

AXIAM_TEST("§12.4 rule 2 keys:[{}] is not a JWKS document; valid JWKs with no Ed25519 key are") {
    {
        Rig r;
        AXIAM_REQUIRE(r.accepts(r.key));
        r.mode->kind = Mode::kNoJwkObjects;
        r.advance(301);
        AXIAM_CHECK(r.accepts(r.key));  // failed refresh: held key kept
        AXIAM_CHECK(r.v->cached_key_count() == 1);
    }
    {
        // Pinned current behaviour: an RSA-only set is a valid JWKS (a success the contract
        // counts), so it replaces the held set and verifies nothing.
        Rig r;
        AXIAM_REQUIRE(r.accepts(r.key));
        r.mode->kind = Mode::kRsaOnly;
        r.advance(301);
        AXIAM_CHECK_FALSE(r.accepts(r.key));
    }
}

AXIAM_TEST("§12.4 rule 2 a failing endpoint on a COLD cache costs one fetch per window") {
    Rig r;
    r.mode->kind = Mode::kFail503;
    for (int i = 0; i < 20; ++i) AXIAM_CHECK_FALSE(r.accepts(r.key));
    AXIAM_CHECK(r.fetches() == 1);
    r.advance(61);
    r.mode->kind = Mode::kServe;
    AXIAM_CHECK(r.accepts(r.key));
    AXIAM_CHECK(r.fetches() == 2);
}

AXIAM_TEST("§12.4 rule 2 a clock that moves backwards makes a refresh due, never fresh") {
    Rig r;
    AXIAM_REQUIRE(r.accepts(r.key));
    r.advance(-10);
    AXIAM_CHECK(r.accepts(r.key));
    AXIAM_CHECK(r.fetches() == 2);
}

AXIAM_TEST("§12.4 rule 2 a 304 re-reads max-age; an ETag with a control character is not echoed") {
    {
        Rig r;
        r.mode->cache_control = "max-age=300";
        AXIAM_REQUIRE(r.accepts(r.key));
        r.mode->kind = Mode::kNotModified;
        r.mode->cache_control = "max-age=10";
        r.advance(301);
        AXIAM_CHECK(r.accepts(r.key));
        AXIAM_CHECK(r.fetches() == 2);
        r.advance(11);  // the 304's max-age=10 now governs
        AXIAM_CHECK(r.accepts(r.key));
        AXIAM_CHECK(r.fetches() == 3);
    }
    {
        Rig r;
        r.mode->etag = std::string("\"a\r\nX-Evil: 1\"");
        AXIAM_REQUIRE(r.accepts(r.key));
        r.advance(301);
        r.accepts(r.key);
        AXIAM_CHECK(r.st->last().headers.count("If-None-Match") == 0);
        Rig r2;
        r2.mode->etag = std::string(257, 'a');
        AXIAM_REQUIRE(r2.accepts(r2.key));
        r2.advance(301);
        r2.accepts(r2.key);
        AXIAM_CHECK(r2.st->last().headers.count("If-None-Match") == 0);
    }
}

AXIAM_TEST("§12.4 rule 2 the REAL transport exposes ETag and Cache-Control: 200 then a conditional 304") {
    TestKey key;
    const int lfd = ::socket(AF_INET, SOCK_STREAM, 0);
    AXIAM_REQUIRE(lfd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    AXIAM_REQUIRE(::bind(lfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    socklen_t len = sizeof(addr);
    ::getsockname(lfd, reinterpret_cast<sockaddr*>(&addr), &len);
    AXIAM_REQUIRE(::listen(lfd, 4) == 0);
    const int port = ntohs(addr.sin_port);

    std::vector<std::string> seen;  // request heads, written by the server thread only
    const std::string doc = key.jwks_json();
    std::thread server([&] {
        for (int i = 0; i < 2; ++i) {
            const int fd = ::accept(lfd, nullptr, nullptr);
            if (fd < 0) return;
            std::string data;
            char buf[2048];
            while (data.find("\r\n\r\n") == std::string::npos) {
                const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                if (n <= 0) break;
                data.append(buf, static_cast<std::size_t>(n));
            }
            seen.push_back(data);
            std::string resp;
            if (i == 0) {
                resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nETag: \"real-1\"\r\n"
                       "Cache-Control: public, max-age=60\r\nContent-Length: " +
                       std::to_string(doc.size()) + "\r\nConnection: close\r\n\r\n" + doc;
            } else {
                resp = "HTTP/1.1 304 Not Modified\r\nCache-Control: max-age=60\r\n"
                       "Connection: close\r\n\r\n";
            }
            ::send(fd, resp.data(), resp.size(), MSG_NOSIGNAL);
            ::close(fd);
        }
    });

    TlsConfig cfg;
    auto now = std::make_shared<Clock::time_point>(Clock::now());
    JwksVerifier v(CurlTransport::make_transport(cfg), "http://127.0.0.1:" + std::to_string(port));
    v._set_clock_test_seam([now] { return *now; });
    const std::string jwt = key.make_jwt("EdDSA", R"({"sub":"u"})");
    const bool first = v.verify_with_reason(jwt).ok;
    *now += std::chrono::seconds(61);  // past the advertised max-age=60, not the 300 s default
    const bool second = v.verify_with_reason(jwt).ok;
    server.join();
    ::close(lfd);

    AXIAM_CHECK(first);
    AXIAM_CHECK(second);
    AXIAM_REQUIRE(seen.size() == 2);
    AXIAM_CHECK(seen[0].find("If-None-Match") == std::string::npos);
    AXIAM_CHECK(seen[1].find("If-None-Match: \"real-1\"") != std::string::npos);
}
