// CONTRACT.md §5.2 rule 1 (contract 1.51) — the acting-tenant gate reset, for every
// SSO/federation session completion.
//
// sso_complete() (OIDC callback), sso_complete_oauth2() (OAuth2 callback) and
// sso_complete_handoff() are the three ways this SDK's Client adopts a NEW session
// through federation. SsoLoginSuccessResponse carries no LoginUserInfo at all, so each
// of them is one of the "which sessions count as holding a login result" carve-outs
// (C-1's "For C-12" question 5): a session-completing call with no `user` object resets
// the gate to UNKNOWN, never to "not organization-level". A restricted first login
// followed by any of the three must not still refuse acting_tenant() on the FIRST
// login's report — exactly the axiam-csharp-sdk C-5 lesson, applied to the three call
// shapes that lesson's own fix (test_acting_tenant.cpp) did not cover.
//
// Each positive case has a REFUSED-completion twin: when the callback itself fails, the
// gate must NOT reset — there is no new session to reset it to, and the client is still
// exactly the restricted principal it was a moment ago.

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

constexpr const char* kOtherTenant = "44444444-4444-4444-8444-444444444444";

// A login whose principal is NOT organization-level -- the restriction
// acting_tenant() must refuse on, until an SSO completion resets it.
const char* kRestrictedLogin =
    R"({"session_id":"sess-1","expires_in":900,)"
    R"("user":{"id":"user-1","username":"alice","email":"alice@example.com",)"
    R"("tenant_id":"11111111-1111-4111-8111-111111111111","organization_level":false}})";

const char* kSsoSuccess =
    R"({"user_id":"user-2","session_id":"sess-2","expires_in":900})";

Client make_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://iam.example.com")
        .tenant_id("11111111-1111-4111-8111-111111111111")
        .transport(axtest::make_fake(st))
        .build();
}

// ---------------------------------------------------------------------------
// sso_complete() — OIDC callback
// ---------------------------------------------------------------------------

AXIAM_TEST("§5.2 rule 1: sso_complete() resets the acting-tenant gate to unknown") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(200, kRestrictedLogin);
        }
        if (req.url.find("/federation/oidc/callback") != std::string::npos) {
            return json_response(200, kSsoSuccess);
        }
        return json_response(200, R"({"items":[],"total":0})");
    };
    auto client = make_client(st);
    client.login("alice@example.com", "pw");  // organization_level: false, recorded

    // Must not throw before the reset -- pins the fixture, not the behaviour under test.
    bool threw_before = false;
    try {
        client.acting_tenant(kOtherTenant);
    } catch (const AuthzError&) {
        threw_before = true;
    }
    AXIAM_CHECK(threw_before);
    client.clear_acting_tenant();

    client.sso_complete("the-code", "the-state");

    // Must NOT throw now: the gate reset to unknown, so acting_tenant() sends the
    // header and lets the server's 403 decide, rather than refusing on the FIRST
    // login's (non-organization-level) report.
    bool threw_after = false;
    try {
        client.acting_tenant(kOtherTenant);
    } catch (const AuthzError&) {
        threw_after = true;
    }
    AXIAM_CHECK(!threw_after);
}

// The refused-completion twin: a callback that fails leaves the gate exactly as the
// restricted first login set it.
AXIAM_TEST("§5.2 rule 1: a REFUSED sso_complete() does not reset the gate") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(200, kRestrictedLogin);
        }
        if (req.url.find("/federation/oidc/callback") != std::string::npos) {
            return json_response(401, R"({"error":"authentication_failed"})");
        }
        return json_response(200, R"({"items":[],"total":0})");
    };
    auto client = make_client(st);
    client.login("alice@example.com", "pw");

    bool threw = false;
    try {
        client.sso_complete("the-code", "the-state");
    } catch (const AuthError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);

    // The gate is UNCHANGED: still the restricted first login's report.
    bool still_refused = false;
    try {
        client.acting_tenant(kOtherTenant);
    } catch (const AuthzError&) {
        still_refused = true;
    }
    AXIAM_CHECK(still_refused);
}

// ---------------------------------------------------------------------------
// sso_complete_oauth2() — OAuth2 callback
// ---------------------------------------------------------------------------

AXIAM_TEST("§5.2 rule 1: sso_complete_oauth2() resets the acting-tenant gate to unknown") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(200, kRestrictedLogin);
        }
        if (req.url.find("/federation/oauth2/callback") != std::string::npos) {
            return json_response(200, kSsoSuccess);
        }
        return json_response(200, R"({"items":[],"total":0})");
    };
    auto client = make_client(st);
    client.login("alice@example.com", "pw");

    client.sso_complete_oauth2("the-code", "the-state");

    bool threw = false;
    try {
        client.acting_tenant(kOtherTenant);
    } catch (const AuthzError&) {
        threw = true;
    }
    AXIAM_CHECK(!threw);
}

AXIAM_TEST("§5.2 rule 1: a REFUSED sso_complete_oauth2() does not reset the gate") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(200, kRestrictedLogin);
        }
        if (req.url.find("/federation/oauth2/callback") != std::string::npos) {
            return json_response(401, R"({"error":"authentication_failed"})");
        }
        return json_response(200, R"({"items":[],"total":0})");
    };
    auto client = make_client(st);
    client.login("alice@example.com", "pw");

    bool threw_completion = false;
    try {
        client.sso_complete_oauth2("the-code", "the-state");
    } catch (const AuthError&) {
        threw_completion = true;
    }
    AXIAM_CHECK(threw_completion);

    bool still_refused = false;
    try {
        client.acting_tenant(kOtherTenant);
    } catch (const AuthzError&) {
        still_refused = true;
    }
    AXIAM_CHECK(still_refused);
}

// ---------------------------------------------------------------------------
// sso_complete_handoff() — the code-only handoff
// ---------------------------------------------------------------------------

AXIAM_TEST("§5.2 rule 1: sso_complete_handoff() resets the acting-tenant gate to unknown") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(200, kRestrictedLogin);
        }
        if (req.url.find("/federation/handoff") != std::string::npos) {
            return json_response(200, kSsoSuccess);
        }
        return json_response(200, R"({"items":[],"total":0})");
    };
    auto client = make_client(st);
    client.login("alice@example.com", "pw");

    client.sso_complete_handoff("the-code");

    bool threw = false;
    try {
        client.acting_tenant(kOtherTenant);
    } catch (const AuthzError&) {
        threw = true;
    }
    AXIAM_CHECK(!threw);
}

AXIAM_TEST("§5.2 rule 1: a REFUSED sso_complete_handoff() does not reset the gate") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(200, kRestrictedLogin);
        }
        if (req.url.find("/federation/handoff") != std::string::npos) {
            return json_response(401, R"({"error":"authentication_failed"})");
        }
        return json_response(200, R"({"items":[],"total":0})");
    };
    auto client = make_client(st);
    client.login("alice@example.com", "pw");

    bool threw_completion = false;
    try {
        client.sso_complete_handoff("the-code");
    } catch (const AuthError&) {
        threw_completion = true;
    }
    AXIAM_CHECK(threw_completion);

    bool still_refused = false;
    try {
        client.acting_tenant(kOtherTenant);
    } catch (const AuthzError&) {
        still_refused = true;
    }
    AXIAM_CHECK(still_refused);
}

// ---------------------------------------------------------------------------
// §17.1 rule 9: each completion clears the decision memo, on success
// ---------------------------------------------------------------------------

AXIAM_TEST("§17.1 rule 9: sso_complete() clears the decision memo") {
    auto st = std::make_shared<FakeState>();
    int check_calls = 0;
    st->router = [&check_calls](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/login") != std::string::npos) {
            return json_response(200, kRestrictedLogin);
        }
        if (req.url.find("/federation/oidc/callback") != std::string::npos) {
            return json_response(200, kSsoSuccess);
        }
        if (req.url.find("/authz/check") != std::string::npos) {
            ++check_calls;
            return json_response(200, R"({"allowed":true})");
        }
        return json_response(200, "{}");
    };
    auto client = Client::builder()
                     .base_url("https://iam.example.com")
                     .tenant_id("11111111-1111-4111-8111-111111111111")
                     .decision_memo_ttl(std::chrono::milliseconds(5000))
                     .transport(axtest::make_fake(st))
                     .build();
    client.login("alice@example.com", "pw");
    client.check_access("read", "r-1");
    AXIAM_CHECK(check_calls == 1);
    client.check_access("read", "r-1");  // memoized -- no second wire call
    AXIAM_CHECK(check_calls == 1);

    client.sso_complete("the-code", "the-state");

    client.check_access("read", "r-1");
    AXIAM_CHECK(check_calls == 2);  // memo was cleared -- reached the wire again
}

// ---------------------------------------------------------------------------
// C-12 N4.4: an SSO completion is one of the calls that "replaces" a
// previously adopted device credential. sso_complete() has its own inline
// adoption block; sso_complete_oauth2()/sso_complete_handoff() share
// parse_federation_session() -- both code paths get their own test.
// ---------------------------------------------------------------------------

Client device_capable_client(std::shared_ptr<FakeState> st) {
    const char* cert = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
    const char* key =
        "-----BEGIN AXIAM TEST PLACEHOLDER-----\nMIIB\n-----END AXIAM TEST PLACEHOLDER-----\n";
    return Client::builder()
        .base_url("https://iam.example.com")
        .tenant_id("11111111-1111-4111-8111-111111111111")
        .with_client_cert(cert, key)
        .transport(axtest::make_fake(st))
        .build();
}

AXIAM_TEST("C-12 N4.4: sso_complete() replaces an adopted device credential") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/device") != std::string::npos) {
            return json_response(
                200, R"({"access_token":"device-tok","token_type":"Bearer","expires_in":900})");
        }
        if (req.url.find("/federation/oidc/callback") != std::string::npos) {
            return json_response(200, kSsoSuccess);
        }
        return json_response(200, R"({"allowed":true})");
    };
    auto client = device_capable_client(st);
    client.authenticate_device();

    client.sso_complete("the-code", "the-state");

    client.check_access("read", "r-1");
    const auto req = st->last();
    AXIAM_CHECK(req.headers.find("Authorization") == req.headers.end());
}

AXIAM_TEST("C-12 N4.4: sso_complete_oauth2() replaces an adopted device credential") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest& req, FakeState&) -> HttpResponse {
        if (req.url.find("/auth/device") != std::string::npos) {
            return json_response(
                200, R"({"access_token":"device-tok","token_type":"Bearer","expires_in":900})");
        }
        if (req.url.find("/federation/oauth2/callback") != std::string::npos) {
            return json_response(200, kSsoSuccess);
        }
        return json_response(200, R"({"allowed":true})");
    };
    auto client = device_capable_client(st);
    client.authenticate_device();

    client.sso_complete_oauth2("the-code", "the-state");

    client.check_access("read", "r-1");
    const auto req = st->last();
    AXIAM_CHECK(req.headers.find("Authorization") == req.headers.end());
}

}  // namespace
