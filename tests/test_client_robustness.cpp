// What the client does with an answer the server should not have sent.
//
// tests/test_client.cpp drives the happy shapes: a login body with every field, of the
// right type. That leaves the whole defensive half of src/client.cpp unwalked -- every
// `j.contains(x) && j[x].is_string()` has only ever been true, so nothing states what the
// SDK does when it is false. Each of those guards exists because the wrong answer is
// worse than no answer: `organization_level` read from the STRING "true" would offer a
// cross-tenant action the server never granted, an `reachable_tenant_ids` of `[]` read as
// a value would say "reaches nothing" where an omitted field means "unknown", and a
// `principal_tenant_id` defaulted to empty would seal an OPAQUE record against no tenant
// at all.
//
// The other half of the file is the base_url and builder validation -- the arguments a
// caller gets wrong, as opposed to the server.

#include <memory>
#include <stdexcept>
#include <string>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "axiam/errors.hpp"
#include "fake_transport.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::json_response;

namespace {

Client robust_client(std::shared_ptr<FakeState> st) {
    return Client::builder()
        .base_url("https://api.example.test")
        .tenant_slug("acme")
        .org_slug("globex")
        .transport(axtest::make_fake(st))
        .build();
}

/// A client whose next login answers with `body` at `status`, plus any Set-Cookie lines.
Client answering(std::shared_ptr<FakeState> st, long status, std::string body,
                 std::vector<std::string> set_cookies = {}) {
    st->router = [status, body, set_cookies](const HttpRequest&, FakeState&) {
        auto r = json_response(status, body);
        r.set_cookies = set_cookies;
        return r;
    };
    return robust_client(st);
}

}  // namespace

// ---------------------------------------------------------------------------
// The user object: fields absent, and fields of the wrong JSON type.
// ---------------------------------------------------------------------------

AXIAM_TEST("login reads a user object carrying only what a pre-1.34 server sends") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 200,
                         R"({"session_id":"s","expires_in":900,)"
                         R"("user":{"id":"u-1","tenant_id":"t-1"}})");

    LoginResult res = c.login("alice", "pw");
    AXIAM_REQUIRE(res.user.has_value());
    AXIAM_CHECK(res.user->id == "u-1");
    // Absent string members read as empty, not as garbage.
    AXIAM_CHECK(res.user->username.empty());
    AXIAM_CHECK(res.user->email.empty());
    AXIAM_CHECK_FALSE(res.user->org_slug.has_value());
    AXIAM_CHECK_FALSE(res.user->tenant_slug.has_value());
    AXIAM_CHECK_FALSE(res.user->principal_tenant_slug.has_value());
    AXIAM_CHECK_FALSE(res.user->org_id.has_value());
    // §5.2: absent means false. A server older than contract 1.31 answers nothing here,
    // and offering a cross-tenant action on that silence is the failure direction.
    AXIAM_CHECK_FALSE(res.user->organization_level);
    // §5.2.2: an absent principal_tenant_id means EQUAL to the acting tenant -- not
    // unknown, and not empty. An empty one would later seal an OPAQUE record against no
    // tenant at all.
    AXIAM_CHECK(res.user->principal_tenant_id == "t-1");
    // §5.2.3: absent stays disengaged.
    AXIAM_CHECK_FALSE(res.user->reachable_tenant_ids.has_value());
}

AXIAM_TEST("login ignores user fields the server sent with the wrong JSON type") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 200,
                         R"({"session_id":"s","expires_in":900,"user":{)"
                         R"("id":"u-1","tenant_id":"t-1",)"
                         R"("org_slug":7,"tenant_slug":null,"principal_tenant_slug":[],)"
                         R"("org_id":false,"principal_tenant_id":12,)"
                         R"("organization_level":"true","reachable_tenant_ids":"t-9"}})");

    LoginResult res = c.login("alice", "pw");
    AXIAM_REQUIRE(res.user.has_value());
    // A string member that arrived as a number, a null, an array or a bool is ABSENT.
    // Coercing it would hand the caller a value the server never asserted.
    AXIAM_CHECK_FALSE(res.user->org_slug.has_value());
    AXIAM_CHECK_FALSE(res.user->tenant_slug.has_value());
    AXIAM_CHECK_FALSE(res.user->principal_tenant_slug.has_value());
    AXIAM_CHECK_FALSE(res.user->org_id.has_value());
    // The STRING "true" is not the JSON literal `true`. This is the one that matters:
    // a truthy read here offers cross-tenant actions on a principal that has none.
    AXIAM_CHECK_FALSE(res.user->organization_level);
    // A non-string principal_tenant_id falls back to the acting tenant, same as absent.
    AXIAM_CHECK(res.user->principal_tenant_id == "t-1");
    // A non-array reachable_tenant_ids is not a one-element list.
    AXIAM_CHECK_FALSE(res.user->reachable_tenant_ids.has_value());
}

AXIAM_TEST("login keeps only the string entries of reachable_tenant_ids") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 200,
                         R"({"session_id":"s","expires_in":900,"user":{)"
                         R"("id":"u-1","tenant_id":"t-1",)"
                         R"("reachable_tenant_ids":["t-1",5,null,{"x":1},"t-2"]}})");

    LoginResult res = c.login("alice", "pw");
    AXIAM_REQUIRE(res.user.has_value());
    AXIAM_REQUIRE(res.user->reachable_tenant_ids.has_value());
    // The junk entries are dropped, not turned into empty strings that would later be
    // sent back as a tenant id.
    AXIAM_REQUIRE(res.user->reachable_tenant_ids->size() == 2);
    AXIAM_CHECK((*res.user->reachable_tenant_ids)[0] == "t-1");
    AXIAM_CHECK((*res.user->reachable_tenant_ids)[1] == "t-2");
}

AXIAM_TEST("login leaves reachable_tenant_ids disengaged when the array is empty") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 200,
                         R"({"session_id":"s","expires_in":900,"user":{)"
                         R"("id":"u-1","tenant_id":"t-1","reachable_tenant_ids":[]}})");

    LoginResult res = c.login("alice", "pw");
    AXIAM_REQUIRE(res.user.has_value());
    // §5.2.3: an engaged zero-length list would read as "reaches NOTHING" -- the exact
    // opposite of what an omitted field means. It stays disengaged instead.
    AXIAM_CHECK_FALSE(res.user->reachable_tenant_ids.has_value());
}

AXIAM_TEST("login ignores a user member that is not an object") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 200, R"({"session_id":"s","expires_in":900,"user":"alice"})");

    LoginResult res = c.login("alice", "pw");
    // No half-built UserInfo from a string: the caller sees that no user arrived.
    AXIAM_CHECK_FALSE(res.user.has_value());
    AXIAM_CHECK(res.session_id == "s");
}

// ---------------------------------------------------------------------------
// A body that is not JSON at all.
// ---------------------------------------------------------------------------

AXIAM_TEST("login survives a 200 whose body is not JSON") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 200, "<html>gateway rewrote the body</html>");

    LoginResult res = c.login("alice", "pw");
    // Nothing is invented out of an unparseable body -- no user, no session id, and an
    // expiry of zero rather than a plausible-looking guess.
    AXIAM_CHECK_FALSE(res.mfa_required);
    AXIAM_CHECK_FALSE(res.user.has_value());
    AXIAM_CHECK(res.session_id.empty());
    AXIAM_CHECK(res.expires_in == 0);
}

AXIAM_TEST("login treats a 202 with an unparseable body as an MFA challenge with no token") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 202, "not json");

    LoginResult res = c.login("alice", "pw");
    // The STATUS carries the meaning here, so the challenge branch is still taken; what
    // it cannot do is hand back a challenge token it never received.
    AXIAM_CHECK(res.mfa_required);
    AXIAM_CHECK(res.challenge_token.empty());
    AXIAM_CHECK(res.available_methods.empty());
    AXIAM_CHECK_FALSE(c.has_session());
}

AXIAM_TEST("login honours mfa_required in a 200 body, not only the 202 status") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 200,
                         R"({"mfa_required":true,"challenge_token":"chal-7",)"
                         R"("available_methods":["totp","webauthn"]})");

    LoginResult res = c.login("alice", "pw");
    AXIAM_CHECK(res.mfa_required);
    AXIAM_CHECK(detail::reveal(res.challenge_token) == "chal-7");
    AXIAM_REQUIRE(res.available_methods.size() == 2);
    // No session is established: a body that says the login is not finished outranks the
    // 200 that carried it.
    AXIAM_CHECK_FALSE(c.has_session());
}

AXIAM_TEST("login drops available_methods entries that are not strings") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 202,
                         R"({"challenge_token":"chal-7",)"
                         R"("available_methods":["totp",3,null,"webauthn"]})");

    LoginResult res = c.login("alice", "pw");
    AXIAM_REQUIRE(res.available_methods.size() == 2);
    AXIAM_CHECK(res.available_methods[0] == "totp");
    AXIAM_CHECK(res.available_methods[1] == "webauthn");
}

AXIAM_TEST("login ignores an available_methods that is not an array") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 202, R"({"challenge_token":"c","available_methods":"totp"})");

    LoginResult res = c.login("alice", "pw");
    AXIAM_CHECK(res.mfa_required);
    // A bare string is not a one-element list of methods.
    AXIAM_CHECK(res.available_methods.empty());
}

// ---------------------------------------------------------------------------
// §25.2 rule 1: the 403 that means "enrol MFA", and the 403s that do not.
// ---------------------------------------------------------------------------

AXIAM_TEST("login reads a 403 mfa_setup_required as a setup challenge, not a denial") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 403, R"({"mfa_setup_required":true,"setup_token":"setup-1"})");

    LoginResult res = c.login("alice", "pw");
    AXIAM_CHECK(res.mfa_setup_required);
    AXIAM_CHECK(detail::reveal(res.setup_token) == "setup-1");
}

AXIAM_TEST("login raises on a 403 whose body is not JSON") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 403, "Forbidden");
    // §25.2's non-error reading is granted by the BODY. Without one, a 403 is a denial
    // like any other -- swallowing it would leave the caller believing a login half
    // succeeded with no setup token to act on.
    AXIAM_REQUIRE_THROWS_AS(c.login("alice", "pw"), AuthzError);
}

// A denial whose body is valid JSON but NOT an object still has to land in the SDK's
// error taxonomy as an AuthzError.
//
// The realistic input is `null`: that is what a gateway writes for an empty error body,
// and an array or a bare string arrive just as easily from a proxy that rewrote the
// response. Structured detail is read out of a 403/409 body -- `message`, `action`,
// `resource_id` -- and reading those from a value that may not be an object is the whole
// hazard. nlohmann's `j.value(key, default)` does NOT fall back to the default on a
// non-object; it throws `type_error.306`. Letting that escape would be wrong twice over:
// the type is not an AxiamError, so the documented `catch (const AxiamError&)` would miss
// a status every caller handles, and it is the VENDORED nlohmann exception, which
// include/axiam/management_models.hpp says must never reach a consumer's API -- a
// consumer linking their own nlohmann cannot even spell the type to catch it.
//
// So Client::Impl::raise_for_status narrows to an object before reading it, which turns a
// non-object body into "no structured detail" rather than into an exception nobody
// declared. It is the SHARED status mapping, not the login path, which the check_access
// case below is here to hold: the same body on a management or OIDC call behaves the
// same way.
AXIAM_TEST("a 403 whose JSON body is not an object is still mapped to AuthzError") {
    // Reported as a code rather than a bool so a regression says WHICH way it went: an
    // escaped vendored exception and a wrongly-mapped NetworkError are different bugs.
    enum Outcome { kNoThrow = 0, kNotAxiamError = 1, kOtherAxiamError = 2, kAuthzError = 3 };

    const auto classify = [](const std::string& body, bool via_login) {
        auto st = std::make_shared<FakeState>();
        st->router = [body](const HttpRequest&, FakeState&) {
            return json_response(403, body);
        };
        Client c = robust_client(st);
        try {
            if (via_login) {
                c.login("alice", "pw");
            } else {
                c.check_access("read", "res-1");
            }
        } catch (const AuthzError&) {
            return kAuthzError;
        } catch (const AxiamError&) {
            return kOtherAxiamError;
        } catch (const std::exception&) {
            return kNotAxiamError;
        }
        return kNoThrow;
    };

    // The control: an object body, which was never in doubt. It is here so a failure
    // below is readable as "the is_object() narrowing broke" rather than "the 403 mapping
    // broke".
    AXIAM_CHECK(classify(R"({"message":"nope"})", true) == kAuthzError);

    // Every non-object JSON body maps the same way. `null` is the one most likely to
    // arrive in production.
    AXIAM_CHECK(classify(R"(["mfa_setup_required"])", true) == kAuthzError);
    AXIAM_CHECK(classify("null", true) == kAuthzError);
    AXIAM_CHECK(classify(R"("forbidden")", true) == kAuthzError);
    AXIAM_CHECK(classify("123", true) == kAuthzError);

    // And it is the shared mapping, not the login path: same body, different call.
    AXIAM_CHECK(classify(R"([1,2,3])", false) == kAuthzError);
}

AXIAM_TEST("login raises on a 403 object that does not claim mfa_setup_required") {
    auto st = std::make_shared<FakeState>();
    Client c = answering(st, 403, R"({"error":"tenant_disabled"})");
    AXIAM_REQUIRE_THROWS_AS(c.login("alice", "pw"), AuthzError);
}

// ---------------------------------------------------------------------------
// D-14: recovering the org_id UUID from the access-token cookie.
//
// The login body carries tenant_id and org_slug but NOT org_id, so refresh() would have
// no UUID to send when the client was built from slugs. The claim is read WITHOUT
// verifying the signature and carries no trust weight -- the server re-derives the
// authoritative org_id -- which is exactly why every malformed shape below has to end in
// "send nothing" rather than in an exception or a guess.
// ---------------------------------------------------------------------------

namespace {

// header.payload.signature, with the payload spelled out below each use.
constexpr const char* kJwtOrgId =
    "aGRy.eyJvcmdfaWQiOiIxMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTEifQ.c2ln";
constexpr const char* kJwtNoOrgId = "aGRy.eyJ0ZW5hbnRfaWQiOiJ0LTEifQ.c2ln";
constexpr const char* kJwtOrgIdNumber = "aGRy.eyJvcmdfaWQiOjEyM30.c2ln";
constexpr const char* kJwtPayloadNotJson = "aGRy.dGhpcyBpcyBub3QganNvbg.c2ln";

/// Log in against `cookies`, then refresh, and return the refresh request body. The
/// refresh body always carries an `org_id` member -- empty when nothing was resolved --
/// so it is the observable for what the cookie yielded.
std::string refresh_body_after_login(std::vector<std::string> cookies) {
    auto st = std::make_shared<FakeState>();
    st->router = [cookies](const HttpRequest& req, FakeState&) {
        if (req.url.find("/auth/login") != std::string::npos) {
            auto r = json_response(200,
                                   R"({"session_id":"s","expires_in":900,)"
                                   R"("user":{"id":"u-1","tenant_id":"t-1"}})");
            r.set_cookies = cookies;
            return r;
        }
        return json_response(200, R"({"expires_in":900})");
    };
    Client c = robust_client(st);
    c.login("alice", "pw");
    c.refresh();
    return st->last().body;
}

}  // namespace

AXIAM_TEST("refresh sends the org_id decoded from the access-token cookie") {
    const std::string body = refresh_body_after_login(
        {std::string("axiam_access=") + kJwtOrgId + "; Path=/; HttpOnly; SameSite=Lax"});
    AXIAM_CHECK(body.find("11111111-1111-4111-8111-111111111111") != std::string::npos);
}

AXIAM_TEST("refresh decodes an access cookie that carries no attributes after it") {
    // No trailing "; Path=/": the value runs to the end of the header, which is the other
    // side of the semicolon split and the shape a minimal server emits.
    const std::string body =
        refresh_body_after_login({std::string("axiam_access=") + kJwtOrgId});
    AXIAM_CHECK(body.find("11111111-1111-4111-8111-111111111111") != std::string::npos);
}

AXIAM_TEST("refresh sends an empty org_id when no access cookie was set") {
    const std::string body = refresh_body_after_login({"axiam_refresh=r-1; Path=/"});
    AXIAM_CHECK(body.find(R"("org_id":"")") != std::string::npos);
}

AXIAM_TEST("refresh sends an empty org_id when the access cookie is not a JWT") {
    // No dots at all, then only one: both are malformed, and neither may throw -- the
    // claim is a convenience, and failing the login over it would be a worse bug than
    // sending no org_id.
    AXIAM_CHECK(refresh_body_after_login({"axiam_access=opaque-token"})
                    .find(R"("org_id":"")") != std::string::npos);
    AXIAM_CHECK(refresh_body_after_login({"axiam_access=aGRy.eyJ9"})
                    .find(R"("org_id":"")") != std::string::npos);
}

AXIAM_TEST("refresh sends an empty org_id when the JWT payload is not base64url") {
    AXIAM_CHECK(refresh_body_after_login({"axiam_access=aGRy.!!not-base64!!.c2ln"})
                    .find(R"("org_id":"")") != std::string::npos);
}

AXIAM_TEST("refresh sends an empty org_id when the JWT payload is not JSON") {
    AXIAM_CHECK(refresh_body_after_login({std::string("axiam_access=") + kJwtPayloadNotJson})
                    .find(R"("org_id":"")") != std::string::npos);
}

AXIAM_TEST("refresh sends an empty org_id when the payload has no org_id claim") {
    AXIAM_CHECK(refresh_body_after_login({std::string("axiam_access=") + kJwtNoOrgId})
                    .find(R"("org_id":"")") != std::string::npos);
}

AXIAM_TEST("refresh sends an empty org_id when the org_id claim is not a string") {
    // `"org_id": 123` must not become the string "123": the server keys on a UUID, and a
    // coerced number would be a lookup that fails in a way nobody can read.
    AXIAM_CHECK(refresh_body_after_login({std::string("axiam_access=") + kJwtOrgIdNumber})
                    .find(R"("org_id":"")") != std::string::npos);
}

// ---------------------------------------------------------------------------
// check_access: the decision half of a malformed answer.
// ---------------------------------------------------------------------------

AXIAM_TEST("check_access denies when the decision body is not JSON") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, "not a decision");
    };
    Client c = robust_client(st);

    const AccessDecision d = c.check_access("read", "res-1");
    // Default-deny. A body the SDK cannot read is not an allow.
    AXIAM_CHECK_FALSE(d.allowed);
    AXIAM_CHECK_FALSE(d.reason.has_value());
    AXIAM_CHECK_FALSE(d.reason_code.has_value());
}

AXIAM_TEST("check_access ignores a reason and reason_code that are not strings") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"allowed":true,"reason":42,"reason_code":null})");
    };
    Client c = robust_client(st);

    const AccessDecision d = c.check_access("read", "res-1");
    AXIAM_CHECK(d.allowed);
    AXIAM_CHECK_FALSE(d.reason.has_value());
    // §11 rule 9: a server that omits the code (or sends null) reads as ABSENT rather
    // than as the empty code, which is a value the caller could branch on.
    AXIAM_CHECK_FALSE(d.reason_code.has_value());
}

// ---------------------------------------------------------------------------
// base_url: what the caller got wrong.
// ---------------------------------------------------------------------------

AXIAM_TEST("base_url strips every trailing slash before paths are appended") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"session_id":"s","expires_in":900})");
    };
    Client c = Client::builder()
                   .base_url("https://api.example.test///")
                   .tenant_slug("acme")
                   .org_slug("globex")
                   .transport(axtest::make_fake(st))
                   .build();
    c.login("alice", "pw");
    // Not "https://api.example.test///api/v1/..." -- a doubled slash is a different path
    // to a proxy, and routes that work in one deployment 404 in the next.
    AXIAM_CHECK(st->last().url == "https://api.example.test/api/v1/auth/login");
}

AXIAM_TEST("base_url allows plaintext http only for the loopback hosts, IPv6 included") {
    const auto build_with = [](const std::string& url) {
        return Client::builder()
            .base_url(url)
            .tenant_slug("acme")
            .org_slug("globex")
            .transport([](const HttpRequest&) { return HttpResponse{}; })
            .build();
    };

    // §6 permits http:// for development loopback, and "[::1]:8080" is the bracketed
    // authority form -- the host is what is INSIDE the brackets, not "[::1".
    AXIAM_REQUIRE_NOTHROW(build_with("http://[::1]:8080"));
    AXIAM_REQUIRE_NOTHROW(build_with("http://localhost:8090"));
    AXIAM_REQUIRE_NOTHROW(build_with("http://127.0.0.1"));

    // A routable IPv6 literal is still the open internet.
    AXIAM_REQUIRE_THROWS_AS(build_with("http://[2001:db8::1]:8080/base"),
                            std::invalid_argument);
    // An unterminated bracket leaves no host to recognise, so it is refused rather than
    // salvaged -- guessing here would be guessing about whether TLS is required.
    AXIAM_REQUIRE_THROWS_AS(build_with("http://[::1"), std::invalid_argument);
    // userinfo does not make a host loopback.
    AXIAM_REQUIRE_THROWS_AS(build_with("http://localhost@evil.example/"),
                            std::invalid_argument);
    AXIAM_REQUIRE_THROWS_AS(build_with("ftp://localhost/"), std::invalid_argument);
}

// ---------------------------------------------------------------------------
// Builder validation.
// ---------------------------------------------------------------------------

AXIAM_TEST("builder refuses a tenant_id that is present but blank") {
    // Set-but-blank is the dangerous one: an absent tenant_id is a client that names its
    // tenant by slug, while a whitespace one is a caller who thinks they supplied it.
    AXIAM_REQUIRE_THROWS_AS(Client::builder()
                                .base_url("https://api.example.test")
                                .tenant_slug("acme")
                                .tenant_id("   ")
                                .org_slug("globex")
                                .transport([](const HttpRequest&) { return HttpResponse{}; })
                                .build(),
                            AuthError);
}

AXIAM_TEST("builder refuses an org_slug that is present but blank") {
    AXIAM_REQUIRE_THROWS_AS(Client::builder()
                                .base_url("https://api.example.test")
                                .tenant_slug("acme")
                                .org_slug("  ")
                                .transport([](const HttpRequest&) { return HttpResponse{}; })
                                .build(),
                            AuthError);
}

AXIAM_TEST("builder refuses a tenant_slug that is blank") {
    AXIAM_REQUIRE_THROWS_AS(Client::builder()
                                .base_url("https://api.example.test")
                                .tenant_slug("\t ")
                                .org_slug("globex")
                                .transport([](const HttpRequest&) { return HttpResponse{}; })
                                .build(),
                            AuthError);
}

AXIAM_TEST("max_concurrent_requests(0) clamps to one rather than admitting nobody") {
    auto st = std::make_shared<FakeState>();
    st->router = [](const HttpRequest&, FakeState&) {
        return json_response(200, R"({"session_id":"s","expires_in":900})");
    };
    Client c = Client::builder()
                   .base_url("https://api.example.test")
                   .tenant_slug("acme")
                   .org_slug("globex")
                   .max_concurrent_requests(0)
                   .transport(axtest::make_fake(st))
                   .build();
    // A literal zero would be a semaphore no request can ever enter -- the client would
    // hang on its first call instead of reporting anything.
    AXIAM_REQUIRE_NOTHROW(c.login("alice", "pw"));
    AXIAM_CHECK(st->count() == 1);
}
