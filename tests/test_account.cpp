// Account lifecycle and MFA enrolment — CONTRACT.md §25.
//
// Nine operations, six of them deliberately unauthenticated, and a set of rules
// that are mostly about what an SDK must NOT do: not clear the decision memo on
// a voluntary enrolment, not compose the two-call enrolment into one, not tell a
// caller whether an email address exists, not leave the otpauth URI unwrapped
// because "the secret field is the secret one".
//
// The §25.3 test is the one worth reading twice. It scans for the SECRET VALUE
// rather than the field name — a test that asserts `totp_uri` is absent from a
// rendering passes for an SDK that renamed the field and still printed the
// secret.

#include <memory>
#include <sstream>
#include <string>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"

namespace {

const char* kTenantUuid = "22222222-2222-2222-2222-222222222222";
const char* kSecret = "JBSWY3DPEHPK3PXP";
const char* kTotpUri = "otpauth://totp/Acme:ada@acme.test?secret=JBSWY3DPEHPK3PXP&issuer=Acme";
const char* kSetupToken = "setup-token-value";
const char* kResetToken = "reset-token-value/with+reserved=chars";

const char* kEnrollBody =
    R"({"secret_base32":"JBSWY3DPEHPK3PXP",)"
    R"("totp_uri":"otpauth://totp/Acme:ada@acme.test?secret=JBSWY3DPEHPK3PXP&issuer=Acme"})";

const char* kLoginOk =
    R"({"session_id":"sess-1","expires_in":900,)"
    R"("user":{"id":"user-1","username":"ada","email":"ada@acme.test",)"
    R"("tenant_id":"22222222-2222-2222-2222-222222222222"}})";

struct Replies {
    long login_status = 200;
    std::string login_body = kLoginOk;
    long enroll_status = 200;
    std::string enroll_body = kEnrollBody;
    long confirm_status = 200;
    std::string confirm_body = R"({"mfa_enabled":true})";
    long setup_confirm_status = 200;
    long verify_email_status = 204;
    long resend_status = 202;
    long resend_own_status = 200;
    long reset_status = 202;
    long reset_context_status = 200;
    std::string reset_context_body = "{}";
    long reset_confirm_status = 204;
    bool transport_fails = false;
};

axiam::Transport routed(std::shared_ptr<axtest::FakeState> st, std::shared_ptr<Replies> r) {
    st->router = [r](const axiam::HttpRequest& req, axtest::FakeState&) -> axiam::HttpResponse {
        const std::string& url = req.url;
        auto reply = [&](long status, const std::string& body,
                         bool csrf = false) -> axiam::HttpResponse {
            axiam::HttpResponse resp;
            if (r->transport_fails && url.find("/auth/login") == std::string::npos) {
                resp.transport_error = "connection refused";
                return resp;
            }
            resp.status = status;
            resp.body = body;
            if (csrf) resp.headers["X-CSRF-Token"] = "csrf-1";
            return resp;
        };
        if (url.find("/auth/login") != std::string::npos) {
            return reply(r->login_status, r->login_body, true);
        }
        if (url.find("/auth/mfa/setup/enroll") != std::string::npos) {
            return reply(r->enroll_status, r->enroll_body);
        }
        if (url.find("/auth/mfa/setup/confirm") != std::string::npos) {
            return reply(r->setup_confirm_status, kLoginOk, true);
        }
        if (url.find("/auth/mfa/enroll") != std::string::npos) {
            return reply(r->enroll_status, r->enroll_body);
        }
        if (url.find("/auth/mfa/confirm") != std::string::npos) {
            return reply(r->confirm_status, r->confirm_body);
        }
        if (url.find("/auth/verify-email") != std::string::npos) {
            return reply(r->verify_email_status, "");
        }
        if (url.find("/users/me/resend-verification") != std::string::npos) {
            return reply(r->resend_own_status, R"({"sent":true})");
        }
        if (url.find("/auth/resend-verification") != std::string::npos) {
            return reply(r->resend_status, "");
        }
        if (url.find("/auth/reset/context") != std::string::npos) {
            return reply(r->reset_context_status, r->reset_context_body);
        }
        if (url.find("/auth/reset/confirm") != std::string::npos) {
            return reply(r->reset_confirm_status, "");
        }
        if (url.find("/auth/reset") != std::string::npos) return reply(r->reset_status, "");
        if (url.find("/authz/check") != std::string::npos) {
            return reply(200, R"({"allowed":true})");
        }
        return reply(404, "{}");
    };
    return axtest::make_fake(std::move(st));
}

axiam::Client make_client(std::shared_ptr<axtest::FakeState> st, std::shared_ptr<Replies> r) {
    return axiam::Client::builder()
        .base_url("https://iam.example.com")
        .tenant_slug("acme")
        .tenant_id(kTenantUuid)
        .org_slug("acme-org")
        // Two tests here assert what an operation does to the §17 memo, and with
        // the memo off (the default) both would pass either way.
        .decision_memo_ttl(std::chrono::milliseconds{5000})
        .transport(routed(std::move(st), std::move(r)))
        .build();
}

axiam::Client signed_in_client(std::shared_ptr<axtest::FakeState> st,
                               std::shared_ptr<Replies> r) {
    auto client = make_client(std::move(st), std::move(r));
    client.login("ada@acme.test", "correct horse");
    return client;
}

std::string last_to(axtest::FakeState& st, const std::string& needle, bool url_not_body) {
    std::lock_guard<std::mutex> lock(st.mtx);
    for (auto it = st.requests.rbegin(); it != st.requests.rend(); ++it) {
        if (it->url.find(needle) != std::string::npos) return url_not_body ? it->url : it->body;
    }
    return {};
}

std::string last_body(axtest::FakeState& st, const std::string& n) { return last_to(st, n, false); }
std::string last_url(axtest::FakeState& st, const std::string& n) { return last_to(st, n, true); }

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

std::string rendered(const axiam::Sensitive<std::string>& s) {
    std::ostringstream os;
    os << s;
    return os.str();
}

}  // namespace

// ---------------------------------------------------------------------------
// §25.2 rule 1 — login's third outcome
// ---------------------------------------------------------------------------

AXIAM_TEST("account: login surfaces the mfa_setup_required outcome") {
    // The tenant requires MFA and this account has none. Before §25 an SDK
    // either reported this as a generic failure or, worse, as a successful login
    // with no session — both leave the caller with nothing to do next. The setup
    // token IS the credential for what follows.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->login_status = 403;
    r->login_body = R"({"mfa_setup_required":true,"setup_token":"setup-token-value"})";
    auto client = make_client(st, r);

    const auto result = client.login("ada@acme.test", "pw");
    AXIAM_REQUIRE(result.mfa_setup_required);
    AXIAM_REQUIRE_FALSE(result.mfa_required);
    AXIAM_REQUIRE_FALSE(result.user.has_value());
    AXIAM_REQUIRE(axiam::detail::reveal(result.setup_token) == kSetupToken);
    // §7: a token the caller must carry across two more calls is wrapped.
    AXIAM_REQUIRE(rendered(result.setup_token) == "[SENSITIVE]");
}

AXIAM_TEST("account: a plain 403 from login is still a failure") {
    // The new branch must not swallow every 403 into "setup required".
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->login_status = 403;
    r->login_body = R"({"error":"account_locked"})";
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.login("ada@acme.test", "pw"), axiam::AuthzError);
}

AXIAM_TEST("account: a successful login is unchanged by the new branch") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto result = client.login("ada@acme.test", "pw");
    AXIAM_REQUIRE_FALSE(result.mfa_setup_required);
    AXIAM_REQUIRE(result.session_id == "sess-1");
    AXIAM_REQUIRE(client.has_session());
}

// ---------------------------------------------------------------------------
// Voluntary enrolment
// ---------------------------------------------------------------------------

AXIAM_TEST("account: mfa_enroll returns both halves wrapped") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    const auto enrollment = client.mfa_enroll();
    AXIAM_REQUIRE(axiam::detail::reveal(enrollment.secret_base32) == kSecret);
    AXIAM_REQUIRE(axiam::detail::reveal(enrollment.totp_uri) == kTotpUri);
}

AXIAM_TEST("account: the otpauth URI is Sensitive because it CONTAINS the secret") {
    // §25.3. THE ASSERTION SCANS FOR THE SECRET VALUE, NOT THE FIELD NAME.
    // Wrapping `secret_base32` and leaving `totp_uri` a plain string wraps
    // nothing: the URI is the field that actually gets logged, because it is the
    // one the caller passes to a QR renderer.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    const auto enrollment = client.mfa_enroll();
    AXIAM_REQUIRE_FALSE(contains(rendered(enrollment.secret_base32), kSecret));
    AXIAM_REQUIRE_FALSE(contains(rendered(enrollment.totp_uri), kSecret));
}

AXIAM_TEST("account: mfa_enroll does NOT clear the decision memo") {
    // §25.2 rule 3. The subject has not changed — offering a factor is a profile
    // action — and discarding a warm memo over it costs a round trip on every
    // check that follows. The assertion is a REQUEST COUNT, because that is the
    // only thing a caller can actually observe.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    client.check_access("read", "doc-1");
    client.mfa_enroll();
    const std::size_t after_enroll = st->count();

    client.check_access("read", "doc-1");
    AXIAM_REQUIRE(st->count() == after_enroll);
}

AXIAM_TEST("account: mfa_confirm sends the code and reports the server's answer") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    AXIAM_REQUIRE(client.mfa_confirm("123456"));
    AXIAM_REQUIRE(contains(last_body(*st, "/mfa/confirm"), R"("totp_code":"123456")"));

    // A 200 that says `mfa_enabled: false` is a successful call reporting a
    // factor that did not turn on; collapsing the two loses that.
    r->confirm_body = R"({"mfa_enabled":false})";
    AXIAM_REQUIRE_FALSE(client.mfa_confirm("123456"));
}

AXIAM_TEST("account: enrolment is two calls and nothing composes them") {
    // §25.2 rule 4. The human step in the middle — read the QR code, type the
    // six digits — is not something a helper can wait for, and an SDK offering
    // `enroll_and_confirm(code)` would be offering a call that cannot work. The
    // assertion is that each call makes exactly one request.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);
    const std::size_t before = st->count();

    client.mfa_enroll();
    AXIAM_REQUIRE(st->count() == before + 1);
    client.mfa_confirm("123456");
    AXIAM_REQUIRE(st->count() == before + 2);
}

// ---------------------------------------------------------------------------
// Forced enrolment (§25.2 rule 2)
// ---------------------------------------------------------------------------

AXIAM_TEST("account: setup/enroll uses the setup token and needs no session") {
    // There is no session yet — the login that produced the token stopped short
    // of one. An SDK that required a session here would make the forced path
    // unreachable.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto enrollment = client.mfa_setup_enroll(axiam::Sensitive<std::string>(kSetupToken));
    AXIAM_REQUIRE(axiam::detail::reveal(enrollment.totp_uri) == kTotpUri);
    AXIAM_REQUIRE(contains(last_body(*st, "/mfa/setup/enroll"),
                           R"("setup_token":"setup-token-value")"));
}

AXIAM_TEST("account: setup/confirm adopts credentials exactly as login does") {
    // §25.2 rule 2: this IS the completion of a login. The proof is that the
    // client is authenticated afterwards without a separate login call.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto result =
        client.mfa_setup_confirm(axiam::Sensitive<std::string>(kSetupToken), "123456");
    AXIAM_REQUIRE(result.session_id == "sess-1");
    AXIAM_REQUIRE(result.user.has_value());
    AXIAM_REQUIRE(client.has_session());

    const std::string body = last_body(*st, "/mfa/setup/confirm");
    AXIAM_REQUIRE(contains(body, R"("setup_token":"setup-token-value")"));
    AXIAM_REQUIRE(contains(body, R"("totp_code":"123456")"));
}

AXIAM_TEST("account: setup/confirm clears the decision memo") {
    // The other half of "adopts credentials exactly as login does": a new
    // subject means the memo cannot be reused.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    client.check_access("read", "doc-1");
    client.mfa_setup_confirm(axiam::Sensitive<std::string>(kSetupToken), "123456");
    const std::size_t after = st->count();

    client.check_access("read", "doc-1");
    AXIAM_REQUIRE(st->count() == after + 1);
}

// ---------------------------------------------------------------------------
// Email verification (§25.1)
// ---------------------------------------------------------------------------

AXIAM_TEST("account: verify_email carries the tenant in the BODY") {
    // §25.1: a BODY field. These are not /oauth2 endpoints, so §12.1 rule 2's
    // query-parameter convention does not reach them — and an SDK that put it in
    // the query would get a 400 that reads like a bad token.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    // Unauthenticated: a user whose email is unverified may have no session at
    // all, which is the whole reason this operation is open.
    AXIAM_REQUIRE_FALSE(client.has_session());
    client.verify_email(axiam::Sensitive<std::string>("verify-token"), kTenantUuid);

    const std::string body = last_body(*st, "/verify-email");
    AXIAM_REQUIRE(contains(body, R"("tenant_id":"22222222-2222-2222-2222-222222222222")"));
    AXIAM_REQUIRE(contains(body, R"("token":"verify-token")"));
    AXIAM_REQUIRE_FALSE(contains(last_url(*st, "/verify-email"), "tenant_id="));
}

AXIAM_TEST("account: resend_verification carries the tenant in the BODY") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    client.resend_verification("ada@acme.test", kTenantUuid);
    const std::string body = last_body(*st, "/resend-verification");
    AXIAM_REQUIRE(contains(body, R"("email":"ada@acme.test")"));
    AXIAM_REQUIRE(contains(body, R"("tenant_id":"22222222-2222-2222-2222-222222222222")"));
}

// ---- §25.7: the two resends -------------------------------------------

// The signed-in resend sends NO caller-supplied data (§25.6).
//
// Asserted on the serialized request rather than on the signature: a method that takes no
// address but reads one off the client and sends it anyway would pass a signature check
// and still be the bug §25.7 exists to prevent. The empty object -- the same thing
// mfa_enroll() already sends -- is conformant; an `email` key is not.
AXIAM_TEST("account: resend_own_verification sends no address") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    client.resend_own_verification();

    AXIAM_REQUIRE(last_body(*st, "/users/me/resend-verification") == "{}");
    AXIAM_REQUIRE_FALSE(contains(last_url(*st, "/users/me/resend-verification"), "email="));
}

// §25.7 rule 2 forbids routing either to the other in either direction; an SDK that
// aliased one reintroduces exactly the defect that section describes.
AXIAM_TEST("account: the two resends hit distinct paths") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    client.resend_own_verification();
    client.resend_verification("ada@acme.test", kTenantUuid);

    AXIAM_REQUIRE(st->count_path("/api/v1/users/me/resend-verification") == 1);
    AXIAM_REQUIRE(st->count_path("/api/v1/auth/resend-verification") == 1);
}

// A 409 raises, and is NOT retried against the public endpoint.
//
// This matters more than it looks: the bug this operation exists to fix was a success
// return on a request that sent nothing, and §25.7 rule 2's forbidden "helpful" fallback
// would restore it with an extra round trip. The absence of a call to the public path is
// what pins that.
AXIAM_TEST("account: resend_own_verification raises on 409 and does not fall back") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->resend_own_status = 409;
    auto client = signed_in_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.resend_own_verification(), axiam::AuthzError);
    AXIAM_REQUIRE(st->count_path("/api/v1/auth/resend-verification") == 0);
}

// A 429 is the §2 mapping of the daily resend limit, and is likewise not retried.
AXIAM_TEST("account: resend_own_verification raises on 429 and does not fall back") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->resend_own_status = 429;
    auto client = signed_in_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.resend_own_verification(), axiam::NetworkError);
    AXIAM_REQUIRE(st->count_path("/api/v1/auth/resend-verification") == 0);
}

// With no session it refuses client-side, with ZERO wire calls.
AXIAM_TEST("account: resend_own_verification with no session makes no wire call") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.resend_own_verification(), axiam::AuthError);
    AXIAM_REQUIRE(st->count() == 0);
}

// ---- §5.2: organization-level principals -------------------------------

// The flag is the only thing that makes a tenant switch meaningful: such a principal
// changes the tenant it acts on by sending a different X-Tenant-ID, with no re-login. An
// application checks it BEFORE offering the switch rather than discovering the answer
// from a 403.
AXIAM_TEST("account: login surfaces an organization-level principal") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->login_body =
        R"({"session_id":"sess-1","expires_in":900,)"
        R"("user":{"id":"user-1","username":"root","email":"root@acme.test",)"
        R"("tenant_id":"22222222-2222-2222-2222-222222222222",)"
        R"("organization_level":true}})";
    auto client = make_client(st, r);

    const auto result = client.login("root@acme.test", "pw");

    AXIAM_REQUIRE(result.user.has_value());
    AXIAM_REQUIRE(result.user->organization_level);
}

// Absent means false -- what a server older than contract 1.31 answers, and the safe
// direction: the application then offers no cross-tenant action. Anything that is not the
// JSON literal true is read the same way, because a truthy string is exactly how a field
// the SDK does not really understand becomes a UI offering a switch that 403s.
AXIAM_TEST("account: an absent or non-boolean organization_level is false") {
    {
        auto st = std::make_shared<axtest::FakeState>();
        auto r = std::make_shared<Replies>();
        auto client = make_client(st, r);
        const auto result = client.login("ada@acme.test", "pw");
        AXIAM_REQUIRE(result.user.has_value());
        AXIAM_REQUIRE_FALSE(result.user->organization_level);
    }
    {
        auto st = std::make_shared<axtest::FakeState>();
        auto r = std::make_shared<Replies>();
        r->login_body =
            R"({"session_id":"sess-1","expires_in":900,)"
            R"("user":{"id":"user-1",)"
            R"("tenant_id":"22222222-2222-2222-2222-222222222222",)"
            R"("organization_level":"yes"}})";
        auto client = make_client(st, r);
        const auto result = client.login("ada@acme.test", "pw");
        AXIAM_REQUIRE(result.user.has_value());
        AXIAM_REQUIRE_FALSE(result.user->organization_level);
    }
}

// §5.2 rule 2: it is derived, never asserted -- the SDK never SENDS it. A field a client
// could put on the request would be a client claiming a capability the server is supposed
// to resolve, which is why the rule is a prohibition rather than a convention.
AXIAM_TEST("account: organization_level is never sent on the login request") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    client.login("ada@acme.test", "pw");

    AXIAM_REQUIRE_FALSE(contains(last_body(*st, "/auth/login"), "organization_level"));
}

AXIAM_TEST("account: a 204 is success, not a parse failure") {
    // Three of the nine answer No Content. An SDK that insists on a JSON body
    // reports every successful reset as a failure.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    AXIAM_REQUIRE_NOTHROW(
        client.verify_email(axiam::Sensitive<std::string>("t"), kTenantUuid));
    axiam::PasswordResetRequest req;
    req.email = "ada@acme.test";
    AXIAM_REQUIRE_NOTHROW(client.request_password_reset(req));
}

// ---------------------------------------------------------------------------
// Password reset (§25.4)
// ---------------------------------------------------------------------------

AXIAM_TEST("account: request_password_reset discloses nothing about the account") {
    // §25.4. The server answers identically whether or not the address exists,
    // and this SDK exposes no way to tell the two apart — not a boolean, not a
    // distinct error. A client that surfaced "no such user" would turn the
    // endpoint into the enumeration oracle its uniform response prevents.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    axiam::PasswordResetRequest nobody;
    nobody.email = "nobody@acme.test";
    AXIAM_REQUIRE_NOTHROW(client.request_password_reset(nobody));
    axiam::PasswordResetRequest ada;
    ada.email = "ada@acme.test";
    AXIAM_REQUIRE_NOTHROW(client.request_password_reset(ada));
}

AXIAM_TEST("account: request_password_reset fills the workspace from the client") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    axiam::PasswordResetRequest req;
    req.email = "ada@acme.test";
    client.request_password_reset(req);

    const std::string body = last_body(*st, "/auth/reset");
    AXIAM_REQUIRE(contains(body, R"("org_slug":"acme-org")"));
    AXIAM_REQUIRE(contains(body, R"("tenant_id":"22222222-2222-2222-2222-222222222222")"));
}

AXIAM_TEST("account: a reset override beats the configured workspace") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    axiam::PasswordResetRequest req;
    req.email = "ada@acme.test";
    req.org_slug = "other-org";
    req.tenant_slug = "other-tenant";
    client.request_password_reset(req);

    const std::string body = last_body(*st, "/auth/reset");
    AXIAM_REQUIRE(contains(body, R"("org_slug":"other-org")"));
    AXIAM_REQUIRE(contains(body, R"("tenant_slug":"other-tenant")"));
    AXIAM_REQUIRE_FALSE(contains(body, "acme-org"));
}

AXIAM_TEST("account: a reset request with no email is refused with no wire call") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    axiam::PasswordResetRequest req;
    AXIAM_REQUIRE_THROWS_AS(client.request_password_reset(req), axiam::AuthError);
    AXIAM_REQUIRE(st->count() == 0);
}

AXIAM_TEST("account: reset/context percent-encodes the token") {
    // A token spliced into the query raw can end the query early or land in the
    // path, and the 404 that produces reads EXACTLY like an expired token —
    // which is the worst possible failure mode for a debugging user.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    client.password_reset_context(axiam::Sensitive<std::string>(kResetToken));

    const std::string url = last_url(*st, "/reset/context");
    AXIAM_REQUIRE(contains(url, "token="));
    AXIAM_REQUIRE(contains(url, "%2F"));  // the '/'
    AXIAM_REQUIRE(contains(url, "%2B"));  // the '+'
    AXIAM_REQUIRE(contains(url, "%3D"));  // the '='
    AXIAM_REQUIRE_FALSE(contains(url, "with+reserved"));
}

AXIAM_TEST("account: reset/context hands the OPAQUE block through untouched") {
    // Forwarded to the §23 helpers as TEXT. This SDK does not model, validate or
    // re-encode the block — it cannot, and anything it did to it would be a
    // guess about a protocol it deliberately does not implement.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->reset_context_body =
        R"({"opaque":{"mode":"required","suite":"ristretto255-SHA512","server_public_key":"c2VydmVyLXBr"}})";
    auto client = make_client(st, r);

    const auto context = client.password_reset_context(axiam::Sensitive<std::string>("t"));
    AXIAM_REQUIRE(context.opaque_json.has_value());
    AXIAM_REQUIRE(contains(*context.opaque_json, "ristretto255-SHA512"));
    AXIAM_REQUIRE(contains(*context.opaque_json, "c2VydmVyLXBr"));
}

AXIAM_TEST("account: a tenant without OPAQUE reports no block rather than an empty one") {
    // Absent means "the plaintext path is allowed". An empty object would mean
    // "OPAQUE is on and configured with nothing", a different and unrecoverable
    // state.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto context = client.password_reset_context(axiam::Sensitive<std::string>("t"));
    AXIAM_REQUIRE_FALSE(context.opaque_json.has_value());
}

AXIAM_TEST("account: a 404 from reset/context does not say which of the three") {
    // §25.4 rule 3: unknown, expired or already-consumed, deliberately
    // indistinguishable. This SDK does not distinguish them either — and the
    // error message must not invent a distinction the server refused to make.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->reset_context_status = 404;
    auto client = make_client(st, r);

    try {
        client.password_reset_context(axiam::Sensitive<std::string>("expired"));
        AXIAM_REQUIRE(false);
    } catch (const axiam::AxiamError& e) {
        const std::string msg = e.what();
        AXIAM_REQUIRE_FALSE(contains(msg, "expired"));
        AXIAM_REQUIRE_FALSE(contains(msg, "consumed"));
        AXIAM_REQUIRE_FALSE(contains(msg, "unknown"));
    }
}

AXIAM_TEST("account: a reset/context body that is not JSON does not read as no-OPAQUE") {
    // Reporting an unparseable 200 as "this tenant has no OPAQUE" hands the
    // caller permission to send a plaintext password to a tenant that may be in
    // `opaque_mode: required`.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->reset_context_body = "<html>gateway</html>";
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.password_reset_context(axiam::Sensitive<std::string>("t")),
                            axiam::NetworkError);
}

AXIAM_TEST("account: confirm_password_reset sends the plaintext shape") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    axiam::PasswordResetConfirmation conf;
    conf.token = axiam::Sensitive<std::string>("reset-token");
    conf.new_password = axiam::Sensitive<std::string>("new-password");
    conf.tenant_id = kTenantUuid;
    client.confirm_password_reset(conf);

    const std::string body = last_body(*st, "/reset/confirm");
    AXIAM_REQUIRE(contains(body, R"("token":"reset-token")"));
    AXIAM_REQUIRE(contains(body, R"("new_password":"new-password")"));
    AXIAM_REQUIRE(contains(body, R"("tenant_id":"22222222-2222-2222-2222-222222222222")"));
    AXIAM_REQUIRE_FALSE(contains(body, "opaque"));
}

AXIAM_TEST("account: confirm_password_reset attaches the OPAQUE record") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    axiam::PasswordResetConfirmation conf;
    conf.token = axiam::Sensitive<std::string>("reset-token");
    conf.new_password = axiam::Sensitive<std::string>("new-password");
    conf.tenant_id = kTenantUuid;
    conf.opaque_json = R"({"registration_record":"cmVjb3Jk","suite":"ristretto255-SHA512"})";
    client.confirm_password_reset(conf);

    const std::string body = last_body(*st, "/reset/confirm");
    AXIAM_REQUIRE(contains(body, R"("opaque":)"));
    AXIAM_REQUIRE(contains(body, "cmVjb3Jk"));
}

AXIAM_TEST("account: a malformed OPAQUE record is refused with no wire call") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    axiam::PasswordResetConfirmation conf;
    conf.token = axiam::Sensitive<std::string>("reset-token");
    conf.new_password = axiam::Sensitive<std::string>("new-password");
    conf.tenant_id = kTenantUuid;
    conf.opaque_json = "not json";
    AXIAM_REQUIRE_THROWS_AS(client.confirm_password_reset(conf), axiam::AuthError);
    AXIAM_REQUIRE(st->count() == 0);
}

AXIAM_TEST("account: confirm_password_reset without a tenant is refused with no wire call") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    axiam::PasswordResetConfirmation conf;
    conf.token = axiam::Sensitive<std::string>("reset-token");
    conf.new_password = axiam::Sensitive<std::string>("new-password");
    AXIAM_REQUIRE_THROWS_AS(client.confirm_password_reset(conf), axiam::AuthError);
    AXIAM_REQUIRE(st->count() == 0);
}

// ---------------------------------------------------------------------------
// Housekeeping
// ---------------------------------------------------------------------------

AXIAM_TEST("account: an enrolment body that is not JSON is a network error") {
    // A 200 whose body cannot be parsed is not an enrolment with missing fields:
    // there is no secret to show, and an empty wrapper would send the user to
    // scan a QR code for a factor that can never confirm.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->enroll_body = "<html>gateway timeout</html>";
    auto client = signed_in_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.mfa_enroll(), axiam::NetworkError);
}

AXIAM_TEST("account: a transport failure is a network error, not an HTTP one") {
    // "The server said no" and "there was no server" lead a caller to different
    // places — a reset that never left the machine is worth retrying.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);
    r->transport_fails = true;

    AXIAM_REQUIRE_THROWS_AS(client.mfa_enroll(), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.password_reset_context(axiam::Sensitive<std::string>("t")),
                            axiam::NetworkError);
}

AXIAM_TEST("account: a non-2xx maps through §2") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->enroll_status = 401;
    auto client = signed_in_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.mfa_enroll(), axiam::AuthError);
}

AXIAM_TEST("account: a closed client refuses every operation") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);
    client.close();
    const std::size_t before = st->count();
    const axiam::Sensitive<std::string> token{"t"};

    axiam::PasswordResetRequest req;
    req.email = "ada@acme.test";
    axiam::PasswordResetConfirmation conf;
    conf.token = token;
    conf.new_password = axiam::Sensitive<std::string>("p");
    conf.tenant_id = kTenantUuid;

    AXIAM_REQUIRE_THROWS_AS(client.mfa_enroll(), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.mfa_confirm("123456"), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.mfa_setup_enroll(token), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.mfa_setup_confirm(token, "123456"), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.verify_email(token, kTenantUuid), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.resend_verification("ada@acme.test", kTenantUuid),
                            axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.request_password_reset(req), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.password_reset_context(token), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.confirm_password_reset(conf), axiam::NetworkError);
    AXIAM_REQUIRE(st->count() == before);
}

AXIAM_TEST("account: a reset request falls back to a configured org_id and tenant_slug") {
    // A client built with UUIDs where slugs are absent sends UUIDs — the reset
    // endpoint takes either form, and inventing a slug it was never given is how
    // an SDK sends a workspace that does not resolve.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = axiam::Client::builder()
                      .base_url("https://iam.example.com")
                      .org_id("11111111-1111-1111-1111-111111111111")
                      .tenant_slug("acme-tenant")
                      .transport(routed(st, r))
                      .build();

    axiam::PasswordResetRequest req;
    req.email = "ada@acme.test";
    client.request_password_reset(req);

    const std::string body = last_body(*st, "/auth/reset");
    AXIAM_REQUIRE(contains(body, R"("org_id":"11111111-1111-1111-1111-111111111111")"));
    AXIAM_REQUIRE(contains(body, R"("tenant_slug":"acme-tenant")"));
}

AXIAM_TEST("account: an explicit tenant_id override beats the configured workspace") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    axiam::PasswordResetRequest req;
    req.email = "ada@acme.test";
    req.tenant_id = "33333333-3333-3333-3333-333333333333";
    client.request_password_reset(req);

    const std::string body = last_body(*st, "/auth/reset");
    AXIAM_REQUIRE(contains(body, R"("tenant_id":"33333333-3333-3333-3333-333333333333")"));
    AXIAM_REQUIRE_FALSE(contains(body, kTenantUuid));
}
