// CONTRACT.md §10.4 — the optional session-revocation feed (contract 1.44,
// AXIAM threats T-39 and T-143).
//
// Two things are under test and they are separable: what the poller does with a
// document, and what attaching one changes about a verification. The second is
// the shorter half and the one that matters — the feed may only ever turn an
// accept into a reject, and only for a token that names a session.
//
// Every negative is paired with its I4 twin: an authenticator built as it was
// before 1.44, a token with no session behind it, a feed that cannot be read. A
// guard that started denying requests because an advisory document went missing
// would be a worse failure than the fifteen-minute window §10.2 records, and
// those twins are what rule it out.

#include <chrono>
#include <memory>
#include <mutex>
#include <string>

#include "assert.hpp"
#include "axiam/authenticator.hpp"
#include "axiam/revocation.hpp"
#include "fake_transport.hpp"
#include "test_key.hpp"

using namespace axiam;
using axtest::FakeState;
using axtest::TestKey;

namespace {

constexpr std::int64_t kNow = 1785700000;
const char* kTenant = "11111111-1111-1111-1111-111111111111";
const char* kRevokedSid = "6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b";
const char* kLiveSid = "11111111-2222-3333-4444-555555555555";
const char* kBase = "https://api.example.test";

AuthenticatorOptions fixed_clock(std::int64_t now = kNow) {
    AuthenticatorOptions opts;
    opts.now = [now] { return now; };
    return opts;
}

std::string claims_with_sid(const std::string& sid) {
    std::string out = std::string("{\"sub\":\"user-1\",\"tenant_id\":\"") + kTenant +
                      "\",\"exp\":" + std::to_string(kNow + 900);
    // Omitted entirely when empty, so "a token with no session behind it" —
    // client credentials, an RPT, a token exchange — stays expressible.
    if (!sid.empty()) out += ",\"sid\":\"" + sid + "\"";
    return out + "}";
}

std::string feed_document(const std::string& alg, const std::string& entry) {
    return "{\"alg\":\"" + alg + "\",\"revoked\":[" + (entry.empty() ? "" : "\"" + entry + "\"") +
           "]}";
}

/// Counts feed fetches, and serves both the JWKS and the feed.
struct FeedFixture {
    std::shared_ptr<FakeState> st = std::make_shared<FakeState>();
    std::string jwks;
    long feed_status = 200;
    std::string feed_body;
    bool feed_transport_error = false;

    axiam::Transport transport() {
        auto* self = this;
        st->router = [self](const axiam::HttpRequest& req, FakeState&) -> axiam::HttpResponse {
            axiam::HttpResponse r;
            if (req.url.find(axiam::kRevocationFeedPath) != std::string::npos) {
                if (self->feed_transport_error) {
                    r.transport_error = "connection refused";
                    return r;
                }
                r.status = self->feed_status;
                r.body = self->feed_body;
                return r;
            }
            if (req.url.find("/oauth2/jwks") != std::string::npos) {
                r.status = 200;
                r.body = self->jwks;
                return r;
            }
            r.status = 404;
            return r;
        };
        return axtest::make_fake(st);
    }

    std::size_t feed_fetches() { return st->count_path(axiam::kRevocationFeedPath); }
};

}  // namespace

// ── The entry format ───────────────────────────────────────────────────────

// The server computes this entry in axiam_core::revocation_feed and every SDK
// recomputes it from a `sid` claim. A pinned vector is the only thing keeping
// twelve implementations of one wire format in agreement; a round trip through
// this file's own hash would agree with itself while agreeing with nobody.
AXIAM_TEST("§10.4 the feed entry matches the pinned vector") {
    AXIAM_CHECK(revocation_entry_for(kRevokedSid) ==
                "i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ");
}

// Hashed over the claim's exact string. An implementation that parsed the sid as
// a UUID and re-rendered it would agree on canonical input and disagree the
// moment a server issued anything else.
AXIAM_TEST("§10.4 the entry hashes the string, not a parsed UUID") {
    AXIAM_CHECK(revocation_entry_for(kRevokedSid) !=
                revocation_entry_for("6F3E0A5C-1B2D-4E8F-9A7B-0C1D2E3F4A5B"));
}

// ── The poller ─────────────────────────────────────────────────────────────

AXIAM_TEST("§10.4 a listed session is reported revoked and an unlisted one is not") {
    FeedFixture f;
    f.feed_body = feed_document("SHA-256", revocation_entry_for(kRevokedSid));
    RevocationFeed feed(f.transport(), kBase);

    AXIAM_CHECK(feed.is_revoked(kRevokedSid));
    AXIAM_CHECK_FALSE(feed.is_revoked(kLiveSid));
}

// §10.4 rule 3 — every way the feed can be unusable behaves exactly as no feed
// at all. The failure this forecloses is the opposite: a guard that starts
// denying every request because a document it treats as advisory became
// unreachable.
AXIAM_TEST("§10.4 rule 3 an unusable feed denies nothing") {
    const std::string listed = revocation_entry_for(kRevokedSid);

    struct Case {
        const char* name;
        long status;
        std::string body;
        bool transport_error;
    };
    const Case cases[] = {
        {"a 404 — the deployment does not publish the feed", 404, "", false},
        {"a 500 — the feed is broken", 500, "", false},
        {"a transport failure — the host is unreachable", 200, "", true},
        {"a body that is not JSON", 200, "not json", false},
        {"a document that is not an object", 200, "[]", false},
        {"an alg this build does not know", 200, feed_document("SHA-512", listed), false},
        {"a revoked member that is not an array", 200, R"({"alg":"SHA-256","revoked":"x"})", false},
        {"no revoked member at all", 200, R"({"alg":"SHA-256"})", false},
    };

    for (const auto& c : cases) {
        FeedFixture f;
        f.feed_status = c.status;
        f.feed_body = c.body;
        f.feed_transport_error = c.transport_error;
        RevocationFeed feed(f.transport(), kBase);

        AXIAM_CHECK_FALSE(feed.is_revoked(kRevokedSid));
    }
}

// An over-sized document drops the WHOLE set rather than truncating it. A
// truncated set is a guard that admits some revoked sessions and reports none,
// which is worse than one that admits all of them and says so.
AXIAM_TEST("§10.4 an oversized document drops everything rather than truncating") {
    std::string body = R"({"alg":"SHA-256","revoked":[")" + revocation_entry_for(kRevokedSid) + "\"";
    for (std::size_t i = 0; i <= kMaxRevocationEntries; ++i) {
        body += ",\"e" + std::to_string(i) + "\"";
    }
    body += "]}";

    FeedFixture f;
    f.feed_body = body;
    RevocationFeed feed(f.transport(), kBase);

    AXIAM_CHECK_FALSE(feed.is_revoked(kRevokedSid));
}

// A blip must not un-revoke a session the guard already knows about: the
// previous set stays in place across a failed refresh.
AXIAM_TEST("§10.4 a failed poll keeps the previous set") {
    FeedFixture f;
    f.feed_body = feed_document("SHA-256", revocation_entry_for(kRevokedSid));
    RevocationFeed feed(f.transport(), kBase);

    AXIAM_REQUIRE(feed.is_revoked(kRevokedSid));

    f.feed_status = 500;
    feed.refresh();

    AXIAM_CHECK(feed.is_revoked(kRevokedSid));
}

// ── §10.4 rule 2 — the poll interval ───────────────────────────────────────

// The request path never waits on a fetch it does not need: inside one interval,
// repeated checks answer from the cache.
AXIAM_TEST("§10.4 rule 2 repeated checks inside one interval do not refetch") {
    FeedFixture f;
    f.feed_body = feed_document("SHA-256", "");
    RevocationFeed feed(f.transport(), kBase);

    for (int i = 0; i < 5; ++i) feed.is_revoked(kLiveSid);

    AXIAM_CHECK(f.feed_fetches() == 1);
}

// Once the interval has elapsed, the next check refetches. Asserted through the
// injected clock rather than by sleeping — a test that really waited fifteen
// seconds is a test nobody runs.
AXIAM_TEST("§10.4 rule 2 an elapsed interval refetches") {
    FeedFixture f;
    f.feed_body = feed_document("SHA-256", "");
    RevocationFeed feed(f.transport(), kBase);

    auto clock = std::chrono::steady_clock::now();
    feed.set_clock_for_testing([&clock] { return clock; });

    feed.is_revoked(kLiveSid);
    clock += kDefaultRevocationPollInterval + std::chrono::seconds(1);
    feed.is_revoked(kLiveSid);

    AXIAM_CHECK(f.feed_fetches() == 2);
}

// A feed that is down must not be retried on every request, which would put the
// request path back on the network — the cost §10.4 exists to avoid. The
// interval is measured from the last ATTEMPT, not the last success.
AXIAM_TEST("§10.4 rule 2 a down feed is not retried on every request") {
    FeedFixture f;
    f.feed_status = 500;
    RevocationFeed feed(f.transport(), kBase);

    for (int i = 0; i < 5; ++i) feed.is_revoked(kLiveSid);

    AXIAM_CHECK(f.feed_fetches() == 1);
}

// The floor is applied by clamping, not by refusing: a caller who asks for
// something faster gets the fastest thing on offer.
AXIAM_TEST("§10.4 rule 2 a shorter interval is clamped rather than refused") {
    FeedFixture f;
    RevocationFeed clamped(f.transport(), kBase, std::chrono::seconds(1));
    RevocationFeed kept(f.transport(), kBase, std::chrono::minutes(2));

    AXIAM_CHECK(clamped.poll_interval() == kMinRevocationPollInterval);
    AXIAM_CHECK(kept.poll_interval() == std::chrono::seconds(120));
}

AXIAM_TEST("§10.4 the feed path is appended to the base URL") {
    FeedFixture f;
    RevocationFeed feed(f.transport(), std::string(kBase) + "/");

    AXIAM_CHECK(feed.feed_url() == std::string(kBase) + "/oauth2/revocations");
}

// A token with no session behind it asks the feed no question at all.
AXIAM_TEST("§10.4 an empty sid is never matched and triggers no fetch") {
    FeedFixture f;
    f.feed_body = feed_document("SHA-256", revocation_entry_for(""));
    RevocationFeed feed(f.transport(), kBase);

    AXIAM_CHECK_FALSE(feed.is_revoked(""));
    AXIAM_CHECK(f.feed_fetches() == 0);
}

// ── What attaching one changes about a verification ────────────────────────

AXIAM_TEST("§10.4 a revoked session is rejected") {
    TestKey key;
    FeedFixture f;
    f.jwks = key.jwks_json();
    f.feed_body = feed_document("SHA-256", revocation_entry_for(kRevokedSid));
    auto transport = f.transport();

    JwksVerifier v(transport, kBase);
    RevocationFeed feed(transport, kBase);
    AuthenticatorOptions opts = fixed_clock();
    opts.revocation_feed = &feed;
    TokenAuthenticator auth(v, kTenant, opts);

    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(key.make_jwt("EdDSA", claims_with_sid(kRevokedSid))),
                            AuthError);
}

AXIAM_TEST("§10.4 a session the feed does not list is admitted") {
    TestKey key;
    FeedFixture f;
    f.jwks = key.jwks_json();
    f.feed_body = feed_document("SHA-256", revocation_entry_for(kRevokedSid));
    auto transport = f.transport();

    JwksVerifier v(transport, kBase);
    RevocationFeed feed(transport, kBase);
    AuthenticatorOptions opts = fixed_clock();
    opts.revocation_feed = &feed;
    TokenAuthenticator auth(v, kTenant, opts);

    const AxiamUser user = auth.authenticate(key.make_jwt("EdDSA", claims_with_sid(kLiveSid)));
    AXIAM_CHECK(user.user_id == "user-1");
}

// The feed can only ever turn an accept into a reject: a token that fails §10.1
// still fails for its own reason, so a feed listing nothing can never rescue an
// expired token.
AXIAM_TEST("§10.4 the feed never turns a reject into an accept") {
    TestKey key;
    FeedFixture f;
    f.jwks = key.jwks_json();
    f.feed_body = feed_document("SHA-256", "");
    auto transport = f.transport();

    JwksVerifier v(transport, kBase);
    RevocationFeed feed(transport, kBase);
    AuthenticatorOptions opts = fixed_clock();
    opts.revocation_feed = &feed;
    TokenAuthenticator auth(v, kTenant, opts);

    const std::string expired =
        std::string("{\"sub\":\"user-1\",\"tenant_id\":\"") + kTenant +
        "\",\"exp\":" + std::to_string(kNow - 3600) + ",\"sid\":\"" + kLiveSid + "\"}";
    AXIAM_REQUIRE_THROWS_AS(auth.authenticate(key.make_jwt("EdDSA", expired)), AuthError);
}

// ── I4 — configured as today, behaves as today ─────────────────────────────

// The default. An authenticator built as it was before contract 1.44 accepts
// exactly what it accepted then, including a token whose session a feed WOULD
// have listed — the §10.2 posture this narrows rather than replaces. And it
// never polls.
AXIAM_TEST("§10.4 no feed attached is unchanged behaviour") {
    TestKey key;
    FeedFixture f;
    f.jwks = key.jwks_json();
    f.feed_body = feed_document("SHA-256", revocation_entry_for(kRevokedSid));

    JwksVerifier v(f.transport(), kBase);
    TokenAuthenticator auth(v, kTenant, fixed_clock());

    const AxiamUser user = auth.authenticate(key.make_jwt("EdDSA", claims_with_sid(kRevokedSid)));
    AXIAM_CHECK(user.user_id == "user-1");
    AXIAM_CHECK(f.feed_fetches() == 0);
}

// A token with no session behind it is never matched against the feed, even when
// the document happens to list the hash of the empty string. Hashing `jti`
// instead would match nothing while looking like it worked.
AXIAM_TEST("§10.4 a token with no session is never matched") {
    TestKey key;
    FeedFixture f;
    f.jwks = key.jwks_json();
    f.feed_body = feed_document("SHA-256", revocation_entry_for(""));
    auto transport = f.transport();

    JwksVerifier v(transport, kBase);
    RevocationFeed feed(transport, kBase);
    AuthenticatorOptions opts = fixed_clock();
    opts.revocation_feed = &feed;
    TokenAuthenticator auth(v, kTenant, opts);

    const AxiamUser user = auth.authenticate(key.make_jwt("EdDSA", claims_with_sid("")));
    AXIAM_CHECK(user.user_id == "user-1");
    // Not even a fetch: a sid-less token asks the feed no question at all.
    AXIAM_CHECK(f.feed_fetches() == 0);
}

// §10.4 rule 3 at the authenticator, not just at the poller: an unreachable feed
// denies nothing. This is what keeps the feature safe to turn on — the
// alternative is a guard that stops serving when an advisory document goes
// missing.
AXIAM_TEST("§10.4 rule 3 an unreachable feed denies nothing at the authenticator") {
    TestKey key;
    FeedFixture f;
    f.jwks = key.jwks_json();
    f.feed_transport_error = true;
    auto transport = f.transport();

    JwksVerifier v(transport, kBase);
    RevocationFeed feed(transport, kBase);
    AuthenticatorOptions opts = fixed_clock();
    opts.revocation_feed = &feed;
    TokenAuthenticator auth(v, kTenant, opts);

    const AxiamUser user = auth.authenticate(key.make_jwt("EdDSA", claims_with_sid(kRevokedSid)));
    AXIAM_CHECK(user.user_id == "user-1");
}
