#include <stdexcept>
#include <string>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "fake_transport.hpp"

using namespace axiam;

// NB: these are non-secret PEM *stubs* used only to exercise builder validation
// (which checks for a "-----BEGIN" marker). The private-key marker is assembled by
// string concatenation so no real-looking key material is committed to source.
static const std::string kFakeCaPem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
static const std::string kFakeCert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
static const std::string kFakeKey =
    std::string("-----BEGIN ") + "PRIVATE" + " KEY-----\nMIIB\n-----END KEY-----\n";

AXIAM_TEST("builder requires base_url") {
    AXIAM_REQUIRE_THROWS_AS(Client::builder().tenant_slug("acme").build(), std::invalid_argument);
}

AXIAM_TEST("builder requires a tenant (no default tenant, §5)") {
    AXIAM_REQUIRE_THROWS_AS(Client::builder().base_url("https://x").build(), AuthError);
}

AXIAM_TEST("builder accepts tenant_slug and sets X-Tenant-ID header value") {
    auto st = std::make_shared<axtest::FakeState>();
    Client c = Client::builder()
                   .base_url("https://api.example.test/")
                   .tenant_slug("acme")
                   .transport(axtest::make_fake(st))
                   .build();
    AXIAM_CHECK(c.tenant_header() == "acme");
}

AXIAM_TEST("builder tenant_id takes precedence for the tenant header") {
    auto st = std::make_shared<axtest::FakeState>();
    Client c = Client::builder()
                   .base_url("https://api.example.test")
                   .tenant_id("11111111-2222-3333-4444-555555555555")
                   .tenant_slug("acme")
                   .transport(axtest::make_fake(st))
                   .build();
    AXIAM_CHECK(c.tenant_header() == "11111111-2222-3333-4444-555555555555");
}

AXIAM_TEST("with_custom_ca rejects non-PEM input (§6)") {
    AXIAM_REQUIRE_THROWS_AS(Client::builder().base_url("https://x").tenant_slug("a").with_custom_ca(
                                "not-a-pem"),
                            std::invalid_argument);
}

AXIAM_TEST("with_custom_ca accepts PEM input") {
    AXIAM_REQUIRE_NOTHROW(
        Client::builder().base_url("https://x").tenant_slug("a").with_custom_ca(kFakeCaPem));
}

AXIAM_TEST("with_client_cert rejects non-PEM cert or key (§6.1)") {
    AXIAM_REQUIRE_THROWS_AS(
        Client::builder().base_url("https://x").tenant_slug("a").with_client_cert("nope", kFakeKey),
        std::invalid_argument);
    AXIAM_REQUIRE_THROWS_AS(
        Client::builder().base_url("https://x").tenant_slug("a").with_client_cert(kFakeCert, "nope"),
        std::invalid_argument);
}

AXIAM_TEST("with_client_cert accepts PEM cert + key and builds") {
    AXIAM_REQUIRE_NOTHROW(Client::builder()
                              .base_url("https://x")
                              .tenant_slug("a")
                              .with_client_cert(kFakeCert, kFakeKey)
                              .build());
}

// ---------------------------------------------------------------------------
// SEC-073 — §6 requires rejecting a plaintext base URL at construction.
// ---------------------------------------------------------------------------

AXIAM_TEST("builder rejects a plaintext http:// base_url (SEC-073, §6)") {
    auto build_with = [](const std::string& url) {
        return Client::builder().base_url(url).tenant_slug("acme").build();
    };
    AXIAM_REQUIRE_THROWS_AS(build_with("http://api.axiam.example"), std::invalid_argument);
    AXIAM_REQUIRE_THROWS_AS(build_with("http://api.axiam.example:8080/v1"),
                            std::invalid_argument);
    // A loopback-looking hostname is not loopback.
    AXIAM_REQUIRE_THROWS_AS(build_with("http://localhost.evil.example"), std::invalid_argument);
    AXIAM_REQUIRE_THROWS_AS(build_with("http://127.0.0.1.evil.example"), std::invalid_argument);
    // Userinfo must not smuggle a loopback host past the check.
    AXIAM_REQUIRE_THROWS_AS(build_with("http://localhost@api.axiam.example"),
                            std::invalid_argument);
    // Other plaintext schemes, and a scheme-less URL.
    AXIAM_REQUIRE_THROWS_AS(build_with("ws://api.axiam.example"), std::invalid_argument);
    AXIAM_REQUIRE_THROWS_AS(build_with("ftp://api.axiam.example"), std::invalid_argument);
    AXIAM_REQUIRE_THROWS_AS(build_with("api.axiam.example"), std::invalid_argument);
}

AXIAM_TEST("builder allows http:// for loopback development hosts (SEC-073, §6)") {
    auto build_with = [](const std::string& url) {
        return Client::builder().base_url(url).tenant_slug("acme").build();
    };
    AXIAM_REQUIRE_NOTHROW(build_with("http://localhost"));
    AXIAM_REQUIRE_NOTHROW(build_with("http://localhost:8080"));
    AXIAM_REQUIRE_NOTHROW(build_with("http://LOCALHOST:8080/api"));
    AXIAM_REQUIRE_NOTHROW(build_with("http://127.0.0.1:9443"));
    AXIAM_REQUIRE_NOTHROW(build_with("http://[::1]:8080"));
    // https is always fine, in any case spelling.
    AXIAM_REQUIRE_NOTHROW(build_with("https://api.axiam.example"));
    AXIAM_REQUIRE_NOTHROW(build_with("HTTPS://api.axiam.example"));
}

AXIAM_TEST("builder timeout setters are chainable and build succeeds") {
    auto st = std::make_shared<axtest::FakeState>();
    AXIAM_REQUIRE_NOTHROW(Client::builder()
                              .base_url("https://x")
                              .tenant_id("t-1")
                              .org_id("o-1")
                              .connect_timeout(std::chrono::milliseconds(5000))
                              .request_timeout(std::chrono::milliseconds(15000))
                              .transport(axtest::make_fake(st))
                              .build());
}
