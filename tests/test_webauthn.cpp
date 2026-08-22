// WebAuthn / passkeys — CONTRACT.md §24.
//
// §24.0 is the clause the rest of the section exists to protect: the server
// chooses every option and verifies every response, and the SDK passes both
// through byte for byte. Almost every assertion below is therefore an assertion
// about BYTES ON THE WIRE — that a buffer arrived unchanged, that a member order
// survived, that a field nobody modelled still made it across. A test that round
// tripped through a model and compared the model would pass while the signature
// the server checks failed.
//
// The rest are about the three refusals §24 makes client-side (no session, a
// response that is not a JSON object, a second-factor ceremony with no token)
// and the two §24.4 overrides of the generic §2 mapping.

#include <memory>
#include <string>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "fake_transport.hpp"

namespace {

const char* kTenantUuid = "22222222-2222-2222-2222-222222222222";
const char* kState = "state-token-value";
const char* kAccess = "access-token-value";
const char* kRefresh = "refresh-token-value";

// The options exactly as a server sends them: a `publicKey` wrapper, base64url
// buffers, and members in an order no alphabetical printer would produce. Both
// facts are load-bearing — §24.6a rule 1 says the WRAPPER is dropped and nothing
// else is, and the ordering is what catches a re-encode.
const char* kCreateOptions =
    R"({"publicKey":{"challenge":"q83vAAAAAAAAAAAAAAAAAA","rp":{"id":"acme.test","name":"Acme"},)"
    R"("user":{"id":"dXNlci0x","name":"ada","displayName":"Ada"},)"
    R"("pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":60000,"attestation":"direct"}})";

const char* kInnerCreateOptions =
    R"({"challenge":"q83vAAAAAAAAAAAAAAAAAA","rp":{"id":"acme.test","name":"Acme"},)"
    R"("user":{"id":"dXNlci0x","name":"ada","displayName":"Ada"},)"
    R"("pubKeyCredParams":[{"type":"public-key","alg":-7}],"timeout":60000,"attestation":"direct"})";

// An authenticator response with members in a deliberately awkward order, a
// member this SDK has never heard of, and a number that a round trip through a
// double would render differently. If any of the three comes out changed, the
// splice is not a splice.
const char* kResponse =
    R"({"type":"public-key","rawId":"Y3JlZC1pZA","id":"Y3JlZC1pZA",)"
    R"("response":{"clientDataJSON":"eyJ0eXAiOiJ3ZWJhdXRobi5jcmVhdGUifQ",)"
    R"("attestationObject":"o2NmbXRkbm9uZQ","transports":["internal"]},)"
    R"("clientExtensionResults":{},"authenticatorAttachment":"platform",)"
    R"("unknownFutureMember":1234567890123})";

const char* kLoginOk =
    R"({"session_id":"sess-1","expires_in":900,)"
    R"("user":{"id":"user-1","username":"ada","email":"ada@acme.test",)"
    R"("tenant_id":"22222222-2222-2222-2222-222222222222"}})";

struct Replies {
    long register_start_status = 200;
    std::string register_start_body;
    long register_finish_status = 201;
    std::string register_finish_body =
        R"({"id":"cred-1","credential_id":"Y3JlZC1pZA","name":"Ada's laptop",)"
        R"("credential_type":"passkey","created_at":"2026-08-22T10:00:00Z","last_used_at":null})";
    long auth_start_status = 200;
    std::string auth_start_body;
    long auth_finish_status = 200;
    std::string auth_finish_body;
    long disc_start_status = 200;
    long disc_finish_status = 200;
    /// A refused connection is not an HTTP status, and every operation has to
    /// tell the difference: "the server said no" and "there was no server" lead
    /// a caller to different places.
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
        const std::string challenge_create =
            std::string(R"({"challenge":)") + kCreateOptions + R"(,"state_token":")" + kState + R"("})";
        const std::string challenge_get =
            std::string(R"({"challenge":{"publicKey":{"challenge":"Zm9v","rpId":"acme.test",)"
                        R"("allowCredentials":[],"userVerification":"required"}},"state_token":")") +
            kState + R"("})";
        const std::string login_body = std::string(R"({"access_token":")") + kAccess +
                                       R"(","refresh_token":")" + kRefresh +
                                       R"(","session_id":"sess-wa","expires_in":900})";

        if (url.find("/auth/login") != std::string::npos) return reply(200, kLoginOk, true);
        if (url.find("/webauthn/register/start") != std::string::npos) {
            return reply(r->register_start_status,
                         r->register_start_body.empty() ? challenge_create : r->register_start_body);
        }
        if (url.find("/webauthn/register/finish") != std::string::npos) {
            return reply(r->register_finish_status, r->register_finish_body);
        }
        if (url.find("/webauthn/authenticate/discoverable/start") != std::string::npos) {
            return reply(r->disc_start_status, challenge_get);
        }
        if (url.find("/webauthn/authenticate/discoverable/finish") != std::string::npos) {
            return reply(r->disc_finish_status, login_body, true);
        }
        if (url.find("/webauthn/authenticate/start") != std::string::npos) {
            return reply(r->auth_start_status,
                         r->auth_start_body.empty() ? challenge_get : r->auth_start_body);
        }
        if (url.find("/webauthn/authenticate/finish") != std::string::npos) {
            return reply(r->auth_finish_status,
                         r->auth_finish_body.empty() ? login_body : r->auth_finish_body, true);
        }
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
        // The §17 memo is OFF by default. The ceremony tests assert what a
        // finish call does to it, and with the memo off both behaviours would
        // pass — every check would go to the wire regardless.
        .decision_memo_ttl(std::chrono::milliseconds{5000})
        .transport(routed(std::move(st), std::move(r)))
        .build();
}

/// A client that has actually completed a login, so §24.1's session requirement
/// is satisfied by the same state a real caller would have.
axiam::Client signed_in_client(std::shared_ptr<axtest::FakeState> st,
                               std::shared_ptr<Replies> r) {
    auto client = make_client(std::move(st), std::move(r));
    client.login("ada@acme.test", "correct horse");
    return client;
}

std::string last_body_to(axtest::FakeState& st, const std::string& needle) {
    std::lock_guard<std::mutex> lock(st.mtx);
    for (auto it = st.requests.rbegin(); it != st.requests.rend(); ++it) {
        if (it->url.find(needle) != std::string::npos) return it->body;
    }
    return {};
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

// ---------------------------------------------------------------------------
// §24.1 the six wire operations
// ---------------------------------------------------------------------------

AXIAM_TEST("webauthn: register/start returns the server's options untouched") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    const auto challenge = client.webauthn_register_start();
    // §24.0: what came back is what the server sent. Not "an equivalent object"
    // — the same one, wrapper and member order included.
    AXIAM_REQUIRE(challenge.challenge_json == kCreateOptions);
    AXIAM_REQUIRE(axiam::detail::reveal(challenge.state_token) == kState);
}

AXIAM_TEST("webauthn: register/start without a session makes no wire call") {
    // §24.1: register/… needs a session and the refusal is CLIENT-SIDE. The
    // assertion that matters is the call count, not the exception type: an SDK
    // that lets the request out and maps the 401 has told the caller the same
    // thing while leaking that the account exists.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.webauthn_register_start(), axiam::AuthError);
    AXIAM_REQUIRE(st->count() == 0);
}

AXIAM_TEST("webauthn: register/finish without a session makes no wire call") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(
        client.webauthn_register_finish(axiam::Sensitive<std::string>(kState), "laptop", kResponse),
        axiam::AuthError);
    AXIAM_REQUIRE(st->count() == 0);
}

AXIAM_TEST("webauthn: register/finish splices the authenticator response verbatim") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    const auto cred = client.webauthn_register_finish(axiam::Sensitive<std::string>(kState),
                                                      "Ada's laptop", kResponse);

    // THE CENTRAL ASSERTION OF §24. The authenticator's bytes appear in the
    // request body as one contiguous, unmodified run — member order, the
    // unmodelled member and the large integer all intact. A parse-and-dump would
    // reorder the members and could render 1234567890123 differently, and this
    // substring search is what refuses to let that pass.
    const std::string body = last_body_to(*st, "/register/finish");
    AXIAM_REQUIRE(contains(body, kResponse));
    AXIAM_REQUIRE(contains(body, R"("credential_name":"Ada's laptop")"));
    AXIAM_REQUIRE(contains(body, kState));

    AXIAM_REQUIRE(cred.id == "cred-1");
    AXIAM_REQUIRE(cred.credential_type == "passkey");
    // A credential never used comes back with a null, and null is not "".
    AXIAM_REQUIRE_FALSE(cred.last_used_at.has_value());
}

AXIAM_TEST("webauthn: register/finish accepts the 201 the RFC specifies") {
    // A success predicate written `== 200` fails every real enrolment while
    // passing everything else.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->register_finish_status = 201;
    auto client = signed_in_client(st, r);

    AXIAM_REQUIRE_NOTHROW(client.webauthn_register_finish(
        axiam::Sensitive<std::string>(kState), "laptop", kResponse));
}

AXIAM_TEST("webauthn: a credential that has been used reports when") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->register_finish_body =
        R"({"id":"cred-1","credential_id":"Y3JlZC1pZA","name":"key",)"
        R"("credential_type":"security_key","created_at":"2026-01-01T00:00:00Z",)"
        R"("last_used_at":"2026-08-22T09:00:00Z"})";
    auto client = signed_in_client(st, r);

    const auto cred = client.webauthn_register_finish(axiam::Sensitive<std::string>(kState),
                                                      "key", kResponse);
    AXIAM_REQUIRE(cred.last_used_at.has_value());
    AXIAM_REQUIRE(*cred.last_used_at == "2026-08-22T09:00:00Z");
    AXIAM_REQUIRE(cred.credential_type == "security_key");
}

AXIAM_TEST("webauthn: a response that is not JSON is refused with no wire call") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);
    const std::size_t before = st->count();

    AXIAM_REQUIRE_THROWS_AS(client.webauthn_register_finish(
                                axiam::Sensitive<std::string>(kState), "laptop", "not json at all"),
                            axiam::AuthError);
    AXIAM_REQUIRE(st->count() == before);
}

AXIAM_TEST("webauthn: a response that is a JSON array is refused") {
    // Valid JSON, wrong shape. The check is "is it an object", not "does it
    // parse" — an array parses and the server can do nothing with it.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);
    const std::size_t before = st->count();

    AXIAM_REQUIRE_THROWS_AS(
        client.webauthn_register_finish(axiam::Sensitive<std::string>(kState), "laptop", "[1,2,3]"),
        axiam::AuthError);
    AXIAM_REQUIRE(st->count() == before);
}

AXIAM_TEST("webauthn: leading whitespace does not defeat the object check") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    AXIAM_REQUIRE_NOTHROW(client.webauthn_register_finish(
        axiam::Sensitive<std::string>(kState), "laptop", std::string("\n  ") + kResponse));
}

AXIAM_TEST("webauthn: register/finish without a credential name is refused") {
    // The label is what the user later recognises the key by in a list. An SDK
    // that defaulted it to "passkey" would produce an account with four
    // indistinguishable entries and no way to tell which device to remove.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);
    const std::size_t before = st->count();

    AXIAM_REQUIRE_THROWS_AS(
        client.webauthn_register_finish(axiam::Sensitive<std::string>(kState), "", kResponse),
        axiam::AuthError);
    AXIAM_REQUIRE(st->count() == before);
}

// ---------------------------------------------------------------------------
// §24.2 two ceremonies, not one with a flag
// ---------------------------------------------------------------------------

AXIAM_TEST("webauthn: authenticate/start requires the challenge token") {
    // §24.2: the second-factor ceremony continues a login that was already gated
    // at its password step, so the token is not optional. Merging the two
    // ceremonies behind an empty argument is the bug the clause names.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(client.webauthn_authenticate_start(axiam::Sensitive<std::string>("")),
                            axiam::AuthError);
    AXIAM_REQUIRE(st->count() == 0);
}

AXIAM_TEST("webauthn: authenticate/start sends the token and no workspace") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    client.webauthn_authenticate_start(axiam::Sensitive<std::string>("challenge-token-value"));

    const std::string body = last_body_to(*st, "/authenticate/start");
    AXIAM_REQUIRE(contains(body, R"("challenge_token":"challenge-token-value")"));
    // A second factor knows its workspace from the token; sending one here would
    // be the SDK inventing a field the flow does not have.
    AXIAM_REQUIRE_FALSE(contains(body, "org_"));
    AXIAM_REQUIRE_FALSE(contains(body, "tenant_"));
}

AXIAM_TEST("webauthn: discoverable/start needs no token and carries the workspace") {
    // The mirror image, and the reason §24.2 says these are different flows: a
    // usernameless ceremony has no prior step to have minted a token, so the
    // workspace has to travel explicitly.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    client.webauthn_discoverable_start();

    const std::string body = last_body_to(*st, "/discoverable/start");
    AXIAM_REQUIRE(contains(body, R"("org_slug":"acme-org")"));
    AXIAM_REQUIRE(contains(body, R"("tenant_id":"22222222-2222-2222-2222-222222222222")"));
    AXIAM_REQUIRE_FALSE(contains(body, "challenge_token"));
}

AXIAM_TEST("webauthn: discoverable/start accepts slugs") {
    // Unlike the five /oauth2 operations of §12.1 rule 2, this endpoint takes
    // slugs — so a slug-only client can run the ceremony at all.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    axiam::WebauthnWorkspace ws;
    ws.org_slug = "other-org";
    ws.tenant_slug = "other-tenant";
    client.webauthn_discoverable_start(ws);

    const std::string body = last_body_to(*st, "/discoverable/start");
    AXIAM_REQUIRE(contains(body, R"("org_slug":"other-org")"));
    AXIAM_REQUIRE(contains(body, R"("tenant_slug":"other-tenant")"));
}

AXIAM_TEST("webauthn: the workspace prefers ids over slugs and sends only one form") {
    // A UUID is unambiguous and a slug is only unique within its parent, so when
    // a caller supplies both the id wins — and only ONE form of each level is
    // sent, because a server given both has to decide which one it trusts.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    axiam::WebauthnWorkspace ws;
    ws.org_id = "org-uuid";
    ws.org_slug = "org-slug";
    ws.tenant_id = "tenant-uuid";
    ws.tenant_slug = "tenant-slug";
    client.webauthn_discoverable_start(ws);

    const std::string body = last_body_to(*st, "/discoverable/start");
    AXIAM_REQUIRE(contains(body, R"("org_id":"org-uuid")"));
    AXIAM_REQUIRE_FALSE(contains(body, "org_slug"));
    AXIAM_REQUIRE(contains(body, R"("tenant_id":"tenant-uuid")"));
    AXIAM_REQUIRE_FALSE(contains(body, "tenant_slug"));
}

AXIAM_TEST("webauthn: discoverable/start without an organization is refused client-side") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = axiam::Client::builder()
                      .base_url("https://iam.example.com")
                      .tenant_id(kTenantUuid)
                      .transport(routed(st, r))
                      .build();

    AXIAM_REQUIRE_THROWS_AS(client.webauthn_discoverable_start(), axiam::AuthError);
    AXIAM_REQUIRE(st->count() == 0);
}

// ---------------------------------------------------------------------------
// §24.3 both finish calls establish a session
// ---------------------------------------------------------------------------

AXIAM_TEST("webauthn: authenticate/finish adopts the session") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto login = client.webauthn_authenticate_finish(axiam::Sensitive<std::string>(kState),
                                                           kResponse);
    AXIAM_REQUIRE(axiam::detail::reveal(login.access_token) == kAccess);
    AXIAM_REQUIRE(axiam::detail::reveal(login.refresh_token) == kRefresh);
    AXIAM_REQUIRE(login.session_id == "sess-wa");
    AXIAM_REQUIRE(login.expires_in == 900);
    // §24.3: the ceremony signed this client in, so register/… now works.
    AXIAM_REQUIRE(client.has_session());
}

AXIAM_TEST("webauthn: discoverable/finish adopts the session the same way") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = make_client(st, r);

    const auto login = client.webauthn_discoverable_finish(axiam::Sensitive<std::string>(kState),
                                                           kResponse);
    AXIAM_REQUIRE(login.session_id == "sess-wa");
    AXIAM_REQUIRE(client.has_session());
}

AXIAM_TEST("webauthn: authenticate/finish clears the decision memo") {
    // §24.3 / §17.1 rule 9: memo entries are keyed by subject, and this call
    // changes the subject. Serving a decision cached for the previous user is an
    // authorization bug, so the assertion is a REQUEST COUNT: the second check
    // must go back to the wire.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    client.check_access("read", "doc-1");
    const std::size_t after_first = st->count();
    client.check_access("read", "doc-1");  // warm: served from the memo
    AXIAM_REQUIRE(st->count() == after_first);

    client.webauthn_authenticate_finish(axiam::Sensitive<std::string>(kState), kResponse);
    const std::size_t after_ceremony = st->count();

    client.check_access("read", "doc-1");
    AXIAM_REQUIRE(st->count() == after_ceremony + 1);
}

// ---------------------------------------------------------------------------
// §24.4 the two overrides of the generic §2 mapping
// ---------------------------------------------------------------------------

AXIAM_TEST("webauthn: a 403 on register/finish surfaces the attestation-policy message") {
    // §24.4 rule 1. The generic mapping would say "authorization denied", which
    // tells the person holding the key nothing they can act on: the tenant's
    // policy rejected THIS authenticator, and the server's message is the only
    // place that says which one would be accepted.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->register_finish_status = 403;
    r->register_finish_body =
        R"({"error":"attestation_rejected","message":"This tenant requires a certified security key from an approved vendor."})";
    auto client = signed_in_client(st, r);

    try {
        client.webauthn_register_finish(axiam::Sensitive<std::string>(kState), "laptop", kResponse);
        AXIAM_REQUIRE(false);
    } catch (const axiam::AuthzError& e) {
        AXIAM_REQUIRE(contains(e.what(), "certified security key"));
    }
}

AXIAM_TEST("webauthn: a 403 with no message does not echo the rest of the body") {
    // Only the NAMED `message` field is lifted; a body without one degrades to a
    // generic explanation rather than dumping the body into the error.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->register_finish_status = 403;
    r->register_finish_body = R"({"error":"forbidden","detail":"do-not-echo-me"})";
    auto client = signed_in_client(st, r);

    try {
        client.webauthn_register_finish(axiam::Sensitive<std::string>(kState), "laptop", kResponse);
        AXIAM_REQUIRE(false);
    } catch (const axiam::AuthzError& e) {
        AXIAM_REQUIRE_FALSE(contains(e.what(), "do-not-echo-me"));
    }
}

AXIAM_TEST("webauthn: a 503 on register/start is not retried") {
    // §24.4 rule 2. A 503 here means the tenant's attestation policy needs FIDO
    // metadata the server cannot reach: a CONFIGURATION state, not a transient
    // one. Retrying it three times turns a clear error into a slow one.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->register_start_status = 503;
    r->register_start_body = R"({"error":"metadata_unavailable"})";
    auto client = signed_in_client(st, r);
    const std::size_t before = st->count();

    AXIAM_REQUIRE_THROWS_AS(client.webauthn_register_start(), axiam::NetworkError);
    AXIAM_REQUIRE(st->count() == before + 1);
}

AXIAM_TEST("webauthn: a non-2xx on authenticate/finish maps through §2 and adopts nothing") {
    // The authentication ceremonies get the GENERIC mapping — §24.4's two
    // overrides are both about register/*, and widening them here would dress a
    // failed assertion up as a policy problem.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->auth_finish_status = 401;
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(
        client.webauthn_authenticate_finish(axiam::Sensitive<std::string>(kState), kResponse),
        axiam::AuthError);
    AXIAM_REQUIRE_FALSE(client.has_session());
}

AXIAM_TEST("webauthn: a start body that is not JSON is a network error") {
    // A 200 whose body cannot be parsed is not a challenge with missing fields;
    // there is nothing to hand an authenticator, and an empty options object
    // would send the caller into a ceremony that cannot succeed.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->auth_start_body = "<html>gateway</html>";
    auto client = make_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(
        client.webauthn_authenticate_start(axiam::Sensitive<std::string>("challenge-token-value")),
        axiam::NetworkError);
}

AXIAM_TEST("webauthn: a transport failure is a network error, not an HTTP one") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);
    r->transport_fails = true;

    AXIAM_REQUIRE_THROWS_AS(client.webauthn_register_start(), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(
        client.webauthn_discoverable_finish(axiam::Sensitive<std::string>(kState), kResponse),
        axiam::NetworkError);
}

// ---------------------------------------------------------------------------
// §24.6a the JSON bridge
// ---------------------------------------------------------------------------

AXIAM_TEST("webauthn: request_json drops the publicKey wrapper and nothing else") {
    // §24.6a rule 1: this is the string a browser hands to
    // PublicKeyCredential.parseCreationOptionsFromJSON() and an Android app
    // hands to CreatePublicKeyCredentialRequest. Both want the INNER object —
    // the wrapper belongs to the DOM's CredentialCreationOptions.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    const auto challenge = client.webauthn_register_start();
    const std::string json = challenge.request_json();
    AXIAM_REQUIRE_FALSE(contains(json, "publicKey"));
    // Everything inside survives, in order: this is a wrapper removal, not a
    // re-serialisation with a filter.
    AXIAM_REQUIRE(json == kInnerCreateOptions);
}

AXIAM_TEST("webauthn: request_json passes bare options through") {
    // A server that sent the bare options rather than the wrapper is not wrong
    // for every consumer, and this call has one job.
    axiam::WebauthnChallenge challenge;
    challenge.challenge_json = R"({"challenge":"abc"})";
    AXIAM_REQUIRE(challenge.request_json() == R"({"challenge":"abc"})");
}

AXIAM_TEST("webauthn: request_json never throws on a malformed challenge") {
    axiam::WebauthnChallenge challenge;
    challenge.challenge_json = "not json";
    AXIAM_REQUIRE(challenge.request_json() == "not json");
}

// ---------------------------------------------------------------------------
// §24.6b rule 5 the failure classification
// ---------------------------------------------------------------------------

AXIAM_TEST("webauthn: the classification covers the five outcomes") {
    AXIAM_REQUIRE(axiam::webauthn_classify("NotAllowedError") ==
                  axiam::WebauthnFailure::kCancelled);
    AXIAM_REQUIRE(axiam::webauthn_classify("InvalidStateError") ==
                  axiam::WebauthnFailure::kAlreadyRegistered);
    AXIAM_REQUIRE(axiam::webauthn_classify("AbortError") == axiam::WebauthnFailure::kTimeout);
    AXIAM_REQUIRE(axiam::webauthn_classify("NotSupportedError") ==
                  axiam::WebauthnFailure::kUnsupported);
    AXIAM_REQUIRE(axiam::webauthn_classify("SecurityError") ==
                  axiam::WebauthnFailure::kUnsupported);
    AXIAM_REQUIRE(axiam::webauthn_classify("SomethingElseError") ==
                  axiam::WebauthnFailure::kUnknown);
}

AXIAM_TEST("webauthn: the classification never fails") {
    // A classifier that can fail is one more thing for an error handler to
    // handle, at the moment the caller already has an error in hand.
    AXIAM_REQUIRE(axiam::webauthn_classify("") == axiam::WebauthnFailure::kUnknown);
    AXIAM_REQUIRE(axiam::webauthn_classify("  notallowederror ") ==
                  axiam::WebauthnFailure::kCancelled);
}

AXIAM_TEST("webauthn: the cancelled message does not accuse the user") {
    // kCancelled covers BOTH an explicit refusal and a silent timeout — the spec
    // refuses to distinguish them, because telling a website which happened
    // leaks whether an authenticator was present. Copy that says "you cancelled"
    // is wrong half the time it is shown.
    const std::string msg = axiam::webauthn_failure_message(axiam::WebauthnFailure::kCancelled);
    AXIAM_REQUIRE_FALSE(contains(msg, "You cancelled"));
    AXIAM_REQUIRE(contains(msg, "try again"));
}

AXIAM_TEST("webauthn: every failure has a message") {
    for (auto f : {axiam::WebauthnFailure::kCancelled, axiam::WebauthnFailure::kAlreadyRegistered,
                   axiam::WebauthnFailure::kTimeout, axiam::WebauthnFailure::kUnsupported,
                   axiam::WebauthnFailure::kUnknown}) {
        AXIAM_REQUIRE_FALSE(axiam::webauthn_failure_message(f).empty());
    }
}

// ---------------------------------------------------------------------------
// §7 / §18
// ---------------------------------------------------------------------------

AXIAM_TEST("webauthn: no state token renders through the public surface") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);

    const auto challenge = client.webauthn_register_start();
    std::ostringstream os;
    os << challenge.state_token;
    AXIAM_REQUIRE(os.str() == "[SENSITIVE]");
    AXIAM_REQUIRE(challenge.state_token.to_string() == "[SENSITIVE]");
}

AXIAM_TEST("webauthn: a closed client refuses every operation") {
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = signed_in_client(st, r);
    client.close();
    const std::size_t before = st->count();
    const axiam::Sensitive<std::string> state{kState};

    AXIAM_REQUIRE_THROWS_AS(client.webauthn_register_start(), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.webauthn_register_finish(state, "laptop", kResponse),
                            axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.webauthn_authenticate_start(state), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.webauthn_authenticate_finish(state, kResponse),
                            axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.webauthn_discoverable_start(), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.webauthn_discoverable_finish(state, kResponse),
                            axiam::NetworkError);
    AXIAM_REQUIRE(st->count() == before);
}

AXIAM_TEST("webauthn: a finish body that is not JSON is a network error") {
    // A 200 whose body cannot be parsed is not a ceremony that half-succeeded.
    // Returning an empty result would tell the caller they are signed in while
    // handing them no tokens to prove it — and a credential the caller cannot
    // name is one they can never find again to remove.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    r->auth_finish_body = "<html>gateway</html>";
    r->register_finish_body = "<html>gateway</html>";
    auto client = signed_in_client(st, r);

    AXIAM_REQUIRE_THROWS_AS(
        client.webauthn_authenticate_finish(axiam::Sensitive<std::string>(kState), kResponse),
        axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(client.webauthn_register_finish(
                                axiam::Sensitive<std::string>(kState), "laptop", kResponse),
                            axiam::NetworkError);
}

AXIAM_TEST("webauthn: the workspace falls back to a configured tenant slug") {
    // §5 makes one of tenant_id / tenant_slug mandatory at construction, so a
    // slug-only client is a supported shape — and this endpoint takes slugs
    // where the five /oauth2 operations of §12.1 rule 2 do not.
    auto st = std::make_shared<axtest::FakeState>();
    auto r = std::make_shared<Replies>();
    auto client = axiam::Client::builder()
                      .base_url("https://iam.example.com")
                      .tenant_slug("acme-tenant")
                      .org_slug("acme-org")
                      .transport(routed(st, r))
                      .build();

    client.webauthn_discoverable_start();
    AXIAM_REQUIRE(contains(last_body_to(*st, "/discoverable/start"),
                           R"("tenant_slug":"acme-tenant")"));
}
