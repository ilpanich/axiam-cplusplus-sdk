// CONTRACT.md §6.1 rules 6-10 (contract 1.51) — authenticate_device(), the mTLS device
// login. `authenticate_device()` already existed in this SDK before this contract
// version (returning DeviceAuth, exactly the { access_token, token_type, expires_in }
// shape rule 6 specifies); what did not exist was rule 7's reachability gate, rule 6's
// adoption of the token as this client's own credential, and the withholding of a
// stale cookie the server would otherwise read before the Authorization header.

#include <memory>
#include <string>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "fake_transport.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::json_response;

namespace {

// with_client_cert() only checks for a "-----BEGIN" prefix; deliberately no
// real (or real-looking) key material, matching test_mtls_endpoint_aliases.cpp.
const std::string kCertPem =
    "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
const std::string kKeyPem =
    "-----BEGIN AXIAM TEST PLACEHOLDER-----\nMIIB\n-----END AXIAM TEST PLACEHOLDER-----\n";
const char* kDeviceOk =
    R"({"access_token":"device-token-xyz","token_type":"Bearer","expires_in":900})";

Client device_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://iam.example.com")
        .tenant_slug("acme")
        .with_client_cert(kCertPem, kKeyPem)
        .transport(axtest::make_fake(st))
        .build();
}

Client plain_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://iam.example.com")
        .tenant_slug("acme")
        .transport(axtest::make_fake(st))
        .build();
}

// ---------------------------------------------------------------------------
// Rule 7: unreachable without a client certificate, zero wire calls
// ---------------------------------------------------------------------------

AXIAM_TEST("§6.1 rule 7: authenticate_device() is unreachable without a client "
          "certificate (zero wire calls)") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(200, kDeviceOk); };
    auto client = plain_client(st);

    bool threw = false;
    try {
        client.authenticate_device();
    } catch (const AuthError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(st->count() == 0);  // zero wire calls
}

// The I4 twin: a client built WITH a certificate reaches the wire and succeeds.
AXIAM_TEST("§6.1 rule 7 (I4): a client built with a certificate can authenticate_device()") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(200, kDeviceOk); };
    auto client = device_client(st);

    const auto da = client.authenticate_device();

    AXIAM_CHECK(st->count() == 1);
    AXIAM_CHECK(da.token_type == "Bearer");
    AXIAM_CHECK(axiam::detail::reveal(da.access_token) == "device-token-xyz");
}

// ---------------------------------------------------------------------------
// Rule 6: adopted as this client's credential — subsequent calls carry it
// ---------------------------------------------------------------------------

AXIAM_TEST("§6.1 rule 6: the device token is adopted and reaches a later check_access "
          "as Authorization: Bearer") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/device") != std::string::npos) {
            return json_response(200, kDeviceOk);
        }
        return json_response(200, R"({"allowed":true})");
    };
    auto client = device_client(st);
    client.authenticate_device();

    client.check_access("read", "r-1");

    const auto req = st->last();
    auto it = req.headers.find("Authorization");
    AXIAM_CHECK(it != req.headers.end());
    AXIAM_CHECK(it->second == "Bearer device-token-xyz");
    AXIAM_CHECK(client.has_session());
}

// The withheld-stale-cookie half: a client that logged in via cookie FIRST, then
// authenticates as a device, must not carry the old session's cookie on the device
// login request or on any request after it — the server reads axiam_access before
// Authorization, so a stale cookie would silently keep the client acting as the OLD
// principal. Observed on the wire the mock transport actually sees, not through a mock
// that intercepts above the cookie-attachment layer (the axiam-typescript-sdk lesson).
AXIAM_TEST("§6.1 rule 6: a device login withholds a stale session cookie, on itself and "
          "on every call after it") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            HttpResponse resp = json_response(
                200, R"({"session_id":"sess-1","expires_in":900,)"
                     R"("user":{"id":"u1","username":"root","email":"root@example.com",)"
                     R"("tenant_id":"11111111-1111-4111-8111-111111111111"}})");
            resp.set_cookies.push_back("axiam_access=stale-cookie-value; HttpOnly; Path=/");
            return resp;
        }
        if (req.url.find("/auth/device") != std::string::npos) {
            return json_response(200, kDeviceOk);
        }
        return json_response(200, R"({"allowed":true})");
    };
    auto client = device_client(st);
    client.login("root@example.com", "pw");  // leaves a cookie in the jar
    client.authenticate_device();

    // The device login request itself must not have replayed the stale cookie.
    axtest::RecordedReq device_req;
    {
        std::lock_guard<std::mutex> lock(st->mtx);
        for (const auto& r : st->requests) {
            if (r.url.find("/auth/device") != std::string::npos) device_req = r;
        }
    }
    AXIAM_CHECK(device_req.headers.find("Cookie") == device_req.headers.end());

    // Nor does a call made AFTER adopting the device token.
    client.check_access("read", "r-1");
    const auto after = st->last();
    AXIAM_CHECK(after.headers.find("Cookie") == after.headers.end());
    auto auth = after.headers.find("Authorization");
    AXIAM_CHECK(auth != after.headers.end());
    AXIAM_CHECK(auth->second == "Bearer device-token-xyz");
}

// ---------------------------------------------------------------------------
// No refresh on the device login's 401, or a later 401 (no refresh token exists)
// ---------------------------------------------------------------------------

AXIAM_TEST("§6.1 rule 8: a 401 from authenticate_device() itself is AuthError, with no "
          "refresh attempt") {
    auto st = std::make_shared<FakeState>();
    int calls = 0;
    st->router = [&calls](const HttpRequest&, FakeState&) -> HttpResponse {
        ++calls;
        return json_response(401, R"({"error":"authentication_failed"})");
    };
    auto client = device_client(st);

    bool threw = false;
    try {
        client.authenticate_device();
    } catch (const AuthError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    // Exactly one request: the device login itself, no /auth/refresh attempt.
    AXIAM_CHECK(calls == 1);
    AXIAM_CHECK(st->count_path("/auth/refresh") == 0);
}

AXIAM_TEST("§6.1 rule 6: a LATER 401 on an adopted device token is AuthError with no "
          "refresh attempt (there is no refresh token for it)") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/device") != std::string::npos) {
            return json_response(200, kDeviceOk);
        }
        // Every call after the device login answers 401 -- the token was revoked, say.
        return json_response(401, R"({"error":"authentication_failed"})");
    };
    auto client = device_client(st);
    client.authenticate_device();

    bool threw = false;
    try {
        client.check_access("read", "r-1");
    } catch (const AuthError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(st->count_path("/auth/refresh") == 0);
}

// The scenario the `device_session` flag exists for: a client that logged in via
// cookie FIRST (so `session` is true) and then ALSO adopted a device token. Gating the
// §9 refresh guard on `session` alone -- forgetting the device exclusion -- would still
// attempt a refresh here, spending a wire call this credential cannot use (D-6: no
// refresh token) before finally surfacing AuthError.
AXIAM_TEST("§6.1 rule 6: no refresh attempt on a 401 even when this client ALSO holds a "
          "cookie session (session=true, device_session=true)") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(
                200, R"({"session_id":"sess-1","expires_in":900,)"
                     R"("user":{"id":"u1","username":"root","email":"root@example.com",)"
                     R"("tenant_id":"11111111-1111-4111-8111-111111111111"}})");
        }
        if (req.url.find("/auth/device") != std::string::npos) {
            return json_response(200, kDeviceOk);
        }
        return json_response(401, R"({"error":"authentication_failed"})");
    };
    auto client = device_client(st);
    client.login("root@example.com", "pw");   // session = true
    client.authenticate_device();              // device_session = true, ALSO

    bool threw = false;
    try {
        client.check_access("read", "r-1");
    } catch (const AuthError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(st->count_path("/auth/refresh") == 0);
}

// ---------------------------------------------------------------------------
// A 429 is not an authentication error, and is not retried
// ---------------------------------------------------------------------------

AXIAM_TEST("§6.1 rule 8: a 429 from authenticate_device() is NetworkError, not AuthError, "
          "and is not retried") {
    auto st = std::make_shared<FakeState>();
    int calls = 0;
    st->router = [&calls](const HttpRequest&, FakeState&) -> HttpResponse {
        ++calls;
        HttpResponse resp = json_response(429, R"({"error":"rate_limit_exceeded"})");
        resp.headers["Retry-After"] = "1";
        return resp;
    };
    auto client = device_client(st);

    bool network_error = false;
    bool auth_error = false;
    try {
        client.authenticate_device();
    } catch (const AuthError&) {
        auth_error = true;
    } catch (const NetworkError&) {
        network_error = true;
    }
    AXIAM_CHECK(network_error);
    AXIAM_CHECK(!auth_error);
    AXIAM_CHECK(calls == 1);  // not retried
}

// ---------------------------------------------------------------------------
// §5.2 rule 1: a device token carries no LoginUserInfo
// ---------------------------------------------------------------------------

AXIAM_TEST("§5.2 rule 1: authenticate_device() resets the acting-tenant gate to unknown "
          "(no LoginUserInfo) — the header is still sent, letting the server decide") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/device") != std::string::npos) {
            return json_response(200, kDeviceOk);
        }
        return json_response(200, R"({"items":[],"total":0})");
    };
    auto client = device_client(st);
    client.authenticate_device();

    // Must not throw: a device credential has no login result to gate on.
    client.acting_tenant("22222222-2222-4222-8222-222222222222");
    AXIAM_CHECK(client.acting_tenant_id().has_value());
}

// ---------------------------------------------------------------------------
// C-12 N4.2: a refused or MALFORMED device login changes no client state
// ---------------------------------------------------------------------------

AXIAM_TEST("C-12 N4.2: a 200 with an unparseable body is refused, not adopted") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) { return json_response(200, "not json at all"); };
    auto client = device_client(st);

    bool threw = false;
    try {
        client.authenticate_device();
    } catch (const NetworkError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    // Before the fix: an empty Sensitive<std::string> was still ADOPTED
    // (device_session = true), so has_session() reported true for a
    // credential that could never authenticate anything.
    AXIAM_CHECK_FALSE(client.has_session());
}

AXIAM_TEST("C-12 N4.2: a 200 with no access_token field is refused, not adopted") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"token_type":"Bearer","expires_in":900})");
    };
    auto client = device_client(st);

    AXIAM_REQUIRE_THROWS_AS(client.authenticate_device(), NetworkError);
    AXIAM_CHECK_FALSE(client.has_session());
}

AXIAM_TEST("C-12 N4.2: a 200 with an empty access_token is refused, not adopted") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"access_token":"","token_type":"Bearer","expires_in":900})");
    };
    auto client = device_client(st);

    AXIAM_REQUIRE_THROWS_AS(client.authenticate_device(), NetworkError);
    AXIAM_CHECK_FALSE(client.has_session());
}

AXIAM_TEST("C-12 N4.2: a malformed RE-authentication leaves the previous device "
          "credential exactly as it was") {
    auto st = std::make_shared<FakeState>();
    int device_calls = 0;
    st->router = [&device_calls](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/device") != std::string::npos) {
            ++device_calls;
            if (device_calls == 1) return json_response(200, kDeviceOk);
            return json_response(200, "not json at all");  // the re-auth attempt
        }
        return json_response(200, R"({"allowed":true})");
    };
    auto client = device_client(st);
    client.authenticate_device();  // adopts "device-token-xyz"

    AXIAM_REQUIRE_THROWS_AS(client.authenticate_device(), NetworkError);

    // The ORIGINAL device credential is still the one presented -- unchanged
    // by the refused re-authentication attempt.
    client.check_access("read", "r-1");
    const auto req = st->last();
    auto it = req.headers.find("Authorization");
    AXIAM_CHECK(it != req.headers.end());
    AXIAM_CHECK(it->second == "Bearer device-token-xyz");
}

// ---------------------------------------------------------------------------
// C-12 N4.4: "any later session-establishing call replaces" the device
// credential, and logout() clears it. Before this fix, ONLY close() touched
// device_access_token/device_session at all — a device credential, once
// adopted, was permanent for the client's whole lifetime.
// ---------------------------------------------------------------------------

AXIAM_TEST("C-12 N4.4: logout() releases an adopted device credential") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/device") != std::string::npos) {
            return json_response(200, kDeviceOk);
        }
        if (req.url.find("/auth/logout") != std::string::npos) {
            return json_response(200, "{}");
        }
        return json_response(200, R"({"allowed":true})");
    };
    auto client = device_client(st);
    client.authenticate_device();
    AXIAM_REQUIRE(client.has_session());

    client.logout();

    // Before the fix: logout() cleared only `session`, leaving `device_session`
    // set, so has_session() (session || device_session) stayed true and the
    // released device bearer kept riding on every later request.
    AXIAM_CHECK_FALSE(client.has_session());
}

AXIAM_TEST("C-12 N4.4: login() replaces an adopted device credential") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/device") != std::string::npos) {
            return json_response(200, kDeviceOk);
        }
        if (req.url.find("/auth/login") != std::string::npos) {
            HttpResponse resp = json_response(
                200, R"({"session_id":"sess-1","expires_in":900,)"
                     R"("user":{"id":"u1","username":"root","email":"root@example.com",)"
                     R"("tenant_id":"11111111-1111-4111-8111-111111111111"}})");
            resp.set_cookies.push_back("axiam_access=fresh-cookie; HttpOnly; Path=/");
            return resp;
        }
        return json_response(200, R"({"allowed":true})");
    };
    auto client = device_client(st);
    client.authenticate_device();  // adopts device_access_token/device_session

    client.login("root@example.com", "pw");

    // Before the fix: build_request()'s `!device_access_token.empty()` branch
    // kept firing after login() too, so this request still carried
    // `Authorization: Bearer device-token-xyz` and withheld login()'s own
    // fresh cookie — the new session was unreachable.
    client.check_access("read", "r-1");
    const auto req = st->last();
    AXIAM_CHECK(req.headers.find("Authorization") == req.headers.end());
}

AXIAM_TEST("C-12 N4.4: verify_mfa() replaces an adopted device credential") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/device") != std::string::npos) {
            return json_response(200, kDeviceOk);
        }
        if (req.url.find("/auth/mfa/verify") != std::string::npos) {
            return json_response(
                200, R"({"session_id":"sess-1","expires_in":900,)"
                     R"("user":{"id":"u1","username":"root","email":"root@example.com",)"
                     R"("tenant_id":"11111111-1111-4111-8111-111111111111"}})");
        }
        return json_response(200, R"({"allowed":true})");
    };
    auto client = device_client(st);
    client.authenticate_device();

    client.verify_mfa("challenge-tok", "123456");

    client.check_access("read", "r-1");
    const auto req = st->last();
    AXIAM_CHECK(req.headers.find("Authorization") == req.headers.end());
}

// The I4 twin: re-authenticating as the device (calling authenticate_device()
// again) is "the device re-authenticates" (rule 6), not one of the calls this
// fix touches — it must keep working exactly as before, overwriting the old
// device credential with the new one.
AXIAM_TEST("C-12 N4.4 (I4): a second authenticate_device() call still replaces the "
          "device credential with the new one") {
    auto st = std::make_shared<FakeState>();
    int device_calls = 0;
    st->router = [&device_calls](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/device") != std::string::npos) {
            ++device_calls;
            const char* body = device_calls == 1
                                    ? kDeviceOk
                                    : R"({"access_token":"device-token-2","token_type":)"
                                      R"("Bearer","expires_in":900})";
            return json_response(200, body);
        }
        return json_response(200, R"({"allowed":true})");
    };
    auto client = device_client(st);
    client.authenticate_device();
    client.authenticate_device();  // re-authenticates, per rule 6

    client.check_access("read", "r-1");
    const auto req = st->last();
    auto it = req.headers.find("Authorization");
    AXIAM_CHECK(it != req.headers.end());
    AXIAM_CHECK(it->second == "Bearer device-token-2");
}

}  // namespace
