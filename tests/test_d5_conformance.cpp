// D5 conformance — CONTRACT.md §16, §17, §18, §19.
//
// The wire-count assertions here are normative as of contract 1.8.1, not
// stylistic. The TypeScript SDK shipped a retry helper that was exported,
// unit-tested and green while no production path called it; the C# SDK had three
// retry settings that were defaulted, documented and asserted in tests and read
// by nothing. Both suites passed. Neither SDK retried anything.
//
// §16.7 is the response: conformance MUST be asserted through the public
// check_access surface by counting requests ON THE WIRE. Every §16 case below
// therefore drives a real Client against a counting transport rather than calling
// detail::retry_* in isolation — the pure-function cases exist only where §16.7
// explicitly requires an injected PRNG (a test that really waits 200 ms is a test
// nobody runs).

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "assert.hpp"
#include "axiam/client.hpp"
#include "decision_memo.hpp"
#include "fake_transport.hpp"
#include "retry.hpp"

using namespace std::chrono_literals;

namespace {

const char* kAllowBody = R"({"allowed":true,"reason_code":"allowed"})";

struct Script {
    std::vector<long> statuses;  // 0 = transport failure; the last entry repeats
    std::string body = kAllowBody;
    std::string retry_after;
};

/// Builds a router that serves `script` and counts every request that reaches it.
axiam::Transport scripted(std::shared_ptr<axtest::FakeState> st, Script script) {
    st->router = [script](const axiam::HttpRequest&,
                          axtest::FakeState& state) -> axiam::HttpResponse {
        const std::size_t n = state.requests.size();  // already includes this one
        const std::size_t idx = n > 0 ? std::min(n - 1, script.statuses.size() - 1) : 0;
        const long status = script.statuses.empty() ? 200 : script.statuses[idx];

        axiam::HttpResponse r;
        if (status == 0) {
            // No HTTP response arrived at all.
            r.transport_error = "connection refused";
            return r;
        }
        r = axtest::json_response(status, script.body);
        if (!script.retry_after.empty()) r.headers["Retry-After"] = script.retry_after;
        return r;
    };
    return axtest::make_fake(st);
}

struct ClientOpts {
    bool retry_enabled = true;
    std::chrono::milliseconds memo_ttl{0};
    axiam::TelemetryHook hook;
};

axiam::Client make_client(std::shared_ptr<axtest::FakeState> st, Script script,
                          ClientOpts opts = {}) {
    auto builder = axiam::Client::builder()
                       .base_url("https://iam.example.com")
                       .tenant_slug("acme")
                       .transport(scripted(std::move(st), std::move(script)))
                       .retry_enabled(opts.retry_enabled);
    if (opts.memo_ttl != 0ms) builder.decision_memo_ttl(opts.memo_ttl);
    if (opts.hook) builder.telemetry_hook(opts.hook);
    return builder.build();
}

/// A thread-safe §19 sink. The hook fires on the calling thread inside the
/// client, so the recorder has to be safe to call from there.
struct Recorder {
    std::mutex mtx;
    std::vector<axiam::TelemetryEvent> events;

    axiam::TelemetryHook hook() {
        return [this](const axiam::TelemetryEvent& e) {
            std::lock_guard<std::mutex> lock(mtx);
            events.push_back(e);
        };
    }

    std::vector<std::string> kinds() {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<std::string> out;
        for (const auto& e : events) {
            if (std::holds_alternative<axiam::RequestStartEvent>(e)) out.push_back("start");
            else if (std::holds_alternative<axiam::RequestEndEvent>(e)) out.push_back("end");
            else if (std::holds_alternative<axiam::RetryEvent>(e)) out.push_back("retry");
            else if (std::holds_alternative<axiam::RefreshEvent>(e)) out.push_back("refresh");
            else out.push_back("clamped");
        }
        return out;
    }

    template <typename T>
    std::vector<T> of() {
        std::lock_guard<std::mutex> lock(mtx);
        std::vector<T> out;
        for (const auto& e : events) {
            if (const auto* t = std::get_if<T>(&e)) out.push_back(*t);
        }
        return out;
    }
};

/// Records the §16 sleeps a client would have taken, so a delay can be asserted
/// without waiting for it.
struct Sleeps {
    std::mutex mtx;
    std::vector<long long> ms;
    void record(std::chrono::milliseconds d) {
        std::lock_guard<std::mutex> lock(mtx);
        ms.push_back(d.count());
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// §16 — the policy, asserted through the public surface
// ---------------------------------------------------------------------------

AXIAM_TEST("§16: a persistent 503 makes exactly three attempts") {
    auto st = std::make_shared<axtest::FakeState>();
    auto c = make_client(st, Script{{503}});
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r-1"), axiam::NetworkError);
    // Not 2, not 4. The cap is the whole point of a bounded policy.
    AXIAM_REQUIRE(st->count() == 3);
}

AXIAM_TEST("§16: a transient failure is retried and the success returned") {
    auto st = std::make_shared<axtest::FakeState>();
    auto c = make_client(st, Script{{503, 200}});
    auto decision = c.check_access("read", "r-1");
    AXIAM_REQUIRE(decision.allowed);
    AXIAM_REQUIRE(st->count() == 2);
}

AXIAM_TEST("§16: a transport failure is retried") {
    auto st = std::make_shared<axtest::FakeState>();
    auto c = make_client(st, Script{{0}});
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r-1"), axiam::NetworkError);
    AXIAM_REQUIRE(st->count() == 3);
}

AXIAM_TEST("§16: a decisive status makes exactly one attempt") {
    // 401 reaches one attempt because no session is active — §9 owns the refresh
    // path, and §16 must not turn a decisive answer into three identical
    // rejections.
    for (long status : {403L, 401L, 400L, 404L, 409L}) {
        auto st = std::make_shared<axtest::FakeState>();
        auto c = make_client(st, Script{{status}});
        try {
            c.check_access("read", "r-1");
        } catch (const axiam::AxiamError&) {
        }
        AXIAM_CHECK(st->count() == 1);
    }
}

AXIAM_TEST("§16.1: retry_enabled(false) makes exactly one attempt") {
    auto st = std::make_shared<axtest::FakeState>();
    ClientOpts opts;
    opts.retry_enabled = false;
    auto c = make_client(st, Script{{503}}, opts);
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r-1"), axiam::NetworkError);
    AXIAM_REQUIRE(st->count() == 1);
}

AXIAM_TEST("§16.2: a non-idempotent operation is never retried") {
    // §16.7's named trap: this is the assertion that catches a retry wired at the
    // TRANSPORT layer instead of the operation layer. login is ineligible because
    // it changes state and because its credential is single-use — a silent replay
    // turns a recoverable blip into a hard rejection the caller cannot interpret.
    auto st = std::make_shared<axtest::FakeState>();
    auto c = make_client(st, Script{{503}});
    AXIAM_REQUIRE_THROWS_AS(c.login("u@example.com", "pw"), axiam::NetworkError);
    AXIAM_REQUIRE(st->count() == 1);
}

AXIAM_TEST("§16.1: the delay sequence with jitter pinned to max is 200ms, 400ms") {
    // Observed through the injected sleep, never taken. §16.7: a test that really
    // waits 200 ms is a test nobody runs.
    auto st = std::make_shared<axtest::FakeState>();
    auto c = make_client(st, Script{{503}});
    Sleeps sleeps;
    c._set_retry_test_seams([] { return 1.0; },
                            [&sleeps](std::chrono::milliseconds d) { sleeps.record(d); });
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r-1"), axiam::NetworkError);
    AXIAM_REQUIRE(sleeps.ms.size() == 2);
    AXIAM_REQUIRE(sleeps.ms[0] == 200);
    AXIAM_REQUIRE(sleeps.ms[1] == 400);
}

AXIAM_TEST("§16.1: jitter pinned to zero waits zero on the wire") {
    // The range is [0, backoff], not backoff ± something. Asserting it through
    // the client rather than the pure function is what proves the injected PRNG
    // is the one the retry loop actually consults.
    auto st = std::make_shared<axtest::FakeState>();
    auto c = make_client(st, Script{{503}});
    Sleeps sleeps;
    c._set_retry_test_seams([] { return 0.0; },
                            [&sleeps](std::chrono::milliseconds d) { sleeps.record(d); });
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r-1"), axiam::NetworkError);
    AXIAM_REQUIRE(st->count() == 3);  // still three attempts
    AXIAM_REQUIRE(sleeps.ms.size() == 2);
    AXIAM_REQUIRE(sleeps.ms[0] == 0);
    AXIAM_REQUIRE(sleeps.ms[1] == 0);
}

AXIAM_TEST("§16.1: a Retry-After header reaches the wait") {
    // 429 is exactly where Retry-After usually arrives.
    auto st = std::make_shared<axtest::FakeState>();
    Script script{{429}};
    script.retry_after = "2";
    auto c = make_client(st, script);
    Sleeps sleeps;
    c._set_retry_test_seams([] { return 1.0; },
                            [&sleeps](std::chrono::milliseconds d) { sleeps.record(d); });
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r-1"), axiam::NetworkError);
    AXIAM_REQUIRE(st->count() == 3);
    AXIAM_REQUIRE(sleeps.ms.size() == 2);
    AXIAM_REQUIRE(sleeps.ms[0] == 2000);  // floors the 200ms backoff
    AXIAM_REQUIRE(sleeps.ms[1] == 2000);  // and the 400ms one
}

AXIAM_TEST("§16.1: the backoff doubles from the base and stops at the cap") {
    AXIAM_REQUIRE(axiam::detail::retry_backoff(1) == 200ms);
    AXIAM_REQUIRE(axiam::detail::retry_backoff(2) == 400ms);
    AXIAM_REQUIRE(axiam::detail::retry_backoff(3) == 800ms);
    AXIAM_REQUIRE(axiam::detail::retry_backoff(20) == 5000ms);
    // An attempt below 1 is the first attempt, not a shift by -1.
    AXIAM_REQUIRE(axiam::detail::retry_backoff(0) == 200ms);
}

AXIAM_TEST("§16.1: full jitter spans zero to the backoff") {
    // The range is [0, backoff], NOT backoff ± something. Partial jitter keeps
    // every client's retries clustered around the same instant, which is the
    // failure mode retries cause rather than fix.
    AXIAM_REQUIRE(axiam::detail::retry_delay(1, std::nullopt, 0.0) == 0ms);
    AXIAM_REQUIRE(axiam::detail::retry_delay(1, std::nullopt, 1.0) == 200ms);
    AXIAM_REQUIRE(axiam::detail::retry_delay(1, std::nullopt, 0.5) == 100ms);
    // A fraction outside the unit interval is clamped rather than trusted.
    AXIAM_REQUIRE(axiam::detail::retry_delay(1, std::nullopt, -3.0) == 0ms);
    AXIAM_REQUIRE(axiam::detail::retry_delay(1, std::nullopt, 9.0) == 200ms);
}

AXIAM_TEST("§16.1: Retry-After is a floor, never a ceiling") {
    // Longer than the backoff: the server wins.
    AXIAM_REQUIRE(axiam::detail::retry_delay(1, 3000ms, 1.0) == 3000ms);
    // Shorter than the backoff: it does NOT shorten the wait. `Retry-After: 0`
    // replacing the backoff is the shipped bug §16.1's wording describes.
    AXIAM_REQUIRE(axiam::detail::retry_delay(1, 0ms, 1.0) == 200ms);
    AXIAM_REQUIRE(axiam::detail::retry_delay(1, 50ms, 1.0) == 200ms);
    AXIAM_REQUIRE(axiam::detail::retry_delay(1, std::nullopt, 1.0) == 200ms);
}

AXIAM_TEST("§16.1: Retry-After header parsing") {
    AXIAM_REQUIRE(axiam::detail::retry_after_from_header("2") == 2000ms);
    AXIAM_REQUIRE(axiam::detail::retry_after_from_header("0") == 0ms);
    AXIAM_REQUIRE(axiam::detail::retry_after_from_header("  2  ") == 2000ms);
    // An unparseable hint is ABSENT, not a zero-length floor.
    AXIAM_REQUIRE(!axiam::detail::retry_after_from_header("").has_value());
    AXIAM_REQUIRE(!axiam::detail::retry_after_from_header("soon").has_value());
    AXIAM_REQUIRE(!axiam::detail::retry_after_from_header("2x").has_value());
    AXIAM_REQUIRE(!axiam::detail::retry_after_from_header("-5").has_value());
    // A date already in the past is not a wait.
    AXIAM_REQUIRE(
        !axiam::detail::retry_after_from_header("Wed, 21 Oct 2015 07:28:00 GMT").has_value());
    // Bounded, so a hostile header cannot park a thread for a day.
    AXIAM_REQUIRE(axiam::detail::retry_after_from_header("999999") == 3600000ms);
    // Both RFC 7231 forms appear in the wild; an SDK that read only delta-seconds
    // would silently drop the hint from every server that sends a date, which
    // means retrying sooner than the server asked.
    const std::time_t now = 1000000000;
    std::tm gm{};
    const std::time_t future = now + 120;
    gmtime_r(&future, &gm);
    char header[64];
    strftime(header, sizeof(header), "%a, %d %b %Y %H:%M:%S GMT", &gm);
    auto parsed = axiam::detail::retry_after_from_header(header, now);
    AXIAM_REQUIRE(parsed.has_value());
    AXIAM_REQUIRE(*parsed == 120000ms);
}

AXIAM_TEST("§16.3: which failures retry") {
    AXIAM_REQUIRE(axiam::detail::retry_should_retry(std::nullopt));
    AXIAM_REQUIRE(axiam::detail::retry_should_retry(408));
    AXIAM_REQUIRE(axiam::detail::retry_should_retry(429));
    AXIAM_REQUIRE(axiam::detail::retry_should_retry(500));
    AXIAM_REQUIRE(axiam::detail::retry_should_retry(599));
    AXIAM_REQUIRE_FALSE(axiam::detail::retry_should_retry(200));
    AXIAM_REQUIRE_FALSE(axiam::detail::retry_should_retry(401));
    AXIAM_REQUIRE_FALSE(axiam::detail::retry_should_retry(403));
    AXIAM_REQUIRE_FALSE(axiam::detail::retry_should_retry(400));
    AXIAM_REQUIRE_FALSE(axiam::detail::retry_should_retry(404));
    AXIAM_REQUIRE_FALSE(axiam::detail::retry_should_retry(409));
}

// ---------------------------------------------------------------------------
// §17 — client-side decision memo
// ---------------------------------------------------------------------------

AXIAM_TEST("§17: the memo is off by default") {
    // With the default configuration EVERY repeat check reaches the wire. §11.2
    // rule 6's ban is still the default behaviour.
    auto st = std::make_shared<axtest::FakeState>();
    auto c = make_client(st, Script{{200}});
    for (int i = 0; i < 3; ++i) c.check_access("read", "r-1");
    AXIAM_REQUIRE(st->count() == 3);
}

AXIAM_TEST("§17: a repeat inside the TTL makes no second wire call") {
    auto st = std::make_shared<axtest::FakeState>();
    ClientOpts opts;
    opts.memo_ttl = 5000ms;
    auto c = make_client(st, Script{{200}}, opts);
    auto first = c.check_access("read", "r-1");
    auto second = c.check_access("read", "r-1");
    AXIAM_REQUIRE(st->count() == 1);
    AXIAM_REQUIRE(first.allowed == second.allowed);
    // §17.1 rule 5: the reason code comes back with the decision. A memo that
    // returned `allowed` while dropping the code would make the field
    // intermittently absent — worse than never having had it.
    AXIAM_REQUIRE(second.reason_code.has_value());
    AXIAM_REQUIRE(*second.reason_code == "allowed");
}

AXIAM_TEST("§17.1 rule 4: denies are memoized exactly like allows") {
    // Asymmetric caching changes the TIMING of the two outcomes and so leaks
    // which one occurred to anyone who can observe latency.
    auto st = std::make_shared<axtest::FakeState>();
    Script script{{200}};
    script.body = R"({"allowed":false,"reason_code":"denied_by_rule"})";
    ClientOpts opts;
    opts.memo_ttl = 5000ms;
    auto c = make_client(st, script, opts);
    c.check_access("read", "r-1");
    auto second = c.check_access("read", "r-1");
    AXIAM_REQUIRE(st->count() == 1);
    AXIAM_REQUIRE_FALSE(second.allowed);
    AXIAM_REQUIRE(*second.reason_code == "denied_by_rule");
}

AXIAM_TEST("§17.1 rule 7: a failure is never memoized") {
    // Memoizing a transport error as a deny would turn a blip into a TTL-long
    // outage; memoizing it as an allow is unthinkable.
    auto st = std::make_shared<axtest::FakeState>();
    ClientOpts opts;
    opts.retry_enabled = false;  // so the count is the call count
    opts.memo_ttl = 5000ms;
    auto c = make_client(st, Script{{503}}, opts);
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r-1"), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r-1"), axiam::NetworkError);
    AXIAM_REQUIRE(st->count() == 2);
}

AXIAM_TEST("§17.1 rule 3: every key component is distinguished") {
    using Memo = axiam::detail::DecisionMemo;
    std::vector<std::string> keys{
        Memo::key(std::nullopt, "r1", "read", std::nullopt),
        Memo::key("s1", "r1", "read", std::nullopt),
        Memo::key(std::nullopt, "r2", "read", std::nullopt),
        Memo::key(std::nullopt, "r1", "write", std::nullopt),
        Memo::key(std::nullopt, "r1", "read", "sc"),
    };
    for (std::size_t i = 0; i < keys.size(); ++i) {
        for (std::size_t j = i + 1; j < keys.size(); ++j) AXIAM_CHECK(keys[i] != keys[j]);
    }
    // Same inputs, same key — otherwise nothing would ever hit.
    AXIAM_REQUIRE(Memo::key(std::nullopt, "r1", "read", std::nullopt) == keys[0]);
    // An absent scope must never collide with a present empty one: a memo that
    // let them collide would answer a narrower question with a broader answer.
    AXIAM_REQUIRE(Memo::key(std::nullopt, "r1", "read", std::nullopt) !=
                  Memo::key(std::nullopt, "r1", "read", ""));
}

AXIAM_TEST("§17: differing components miss rather than collide") {
    auto st = std::make_shared<axtest::FakeState>();
    ClientOpts opts;
    opts.memo_ttl = 5000ms;
    auto c = make_client(st, Script{{200}}, opts);
    c.check_access("read", "r-1");
    c.check_access("read", "r-1", std::string("scope-a"));
    c.check_access("write", "r-1");
    c.check_access("read", "r-2");
    c.check_access("read", "r-1", std::nullopt, std::string("subj"));
    AXIAM_REQUIRE(st->count() == 5);
}

AXIAM_TEST("§17.1 rule 2: a TTL above the ceiling is clamped, not rejected") {
    using Memo = axiam::detail::DecisionMemo;
    AXIAM_REQUIRE(Memo(3600000ms).effective_ttl() == axiam::detail::kMemoMaxTtl);
    AXIAM_REQUIRE(Memo(2000ms).effective_ttl() == 2000ms);
    AXIAM_REQUIRE_FALSE(Memo(0ms).enabled());
    // A negative TTL DISABLES rather than clamping up to the ceiling.
    AXIAM_REQUIRE_FALSE(Memo(-5000ms).enabled());
}

AXIAM_TEST("§17: an entry expires at exactly the TTL") {
    auto now = std::chrono::steady_clock::now();
    auto clock = [&now] { return now; };
    axiam::detail::DecisionMemo memo(5000ms, clock);
    axiam::AccessDecision d;
    d.allowed = true;
    memo.put("k", d);

    now += 4999ms;
    AXIAM_REQUIRE(memo.get("k").has_value());  // still live just before the TTL
    now += 1ms;
    AXIAM_REQUIRE_FALSE(memo.get("k").has_value());  // expired at exactly the TTL
}

AXIAM_TEST("§17.1 rule 8: the memo evicts rather than growing without bound") {
    // An unbounded per-client cache keyed by (subject, resource, action, scope)
    // is a memory leak in any service that checks many resources.
    axiam::detail::DecisionMemo memo(5000ms);
    axiam::AccessDecision d;
    d.allowed = true;
    for (std::size_t i = 0; i < axiam::detail::kMemoMaxEntries + 100; ++i) {
        memo.put("k-" + std::to_string(i), d);
    }
    AXIAM_REQUIRE(memo.size() == axiam::detail::kMemoMaxEntries);
}

AXIAM_TEST("§17.1 rule 9: the memo is cleared on a credential change") {
    // Entries are keyed by subject, not by session, so a re-authentication as a
    // DIFFERENT principal would otherwise read the previous principal's
    // decisions.
    auto st = std::make_shared<axtest::FakeState>();
    ClientOpts opts;
    opts.memo_ttl = 5000ms;
    auto c = make_client(st, Script{{200}}, opts);
    c.check_access("read", "r-1");
    c.check_access("read", "r-1");
    AXIAM_REQUIRE(st->count() == 1);

    c.logout();
    const std::size_t after_logout = st->count();

    c.check_access("read", "r-1");
    AXIAM_REQUIRE(st->count() == after_logout + 1);
}

// ---------------------------------------------------------------------------
// §18 — deterministic shutdown
// ---------------------------------------------------------------------------

AXIAM_TEST("§18.1 rule 2: close() is idempotent") {
    auto st = std::make_shared<axtest::FakeState>();
    auto c = make_client(st, Script{{200}});
    AXIAM_REQUIRE_NOTHROW(c.close());
    AXIAM_REQUIRE_NOTHROW(c.close());
    AXIAM_REQUIRE_NOTHROW(c.close());
}

AXIAM_TEST("§18.1 rule 5: close() issues no network request") {
    // The server-side session deliberately outlives the client object — that is
    // what lets a process restart and resume — so a close() that logged out would
    // silently end every user's session on each deploy. Asserted against the
    // wire, because a logout wired into close succeeds silently and would pass
    // any return-value assertion.
    auto st = std::make_shared<axtest::FakeState>();
    auto c = make_client(st, Script{{200}});
    c.close();
    AXIAM_REQUIRE(st->count() == 0);
}

AXIAM_TEST("§18.1 rule 4: use after close throws rather than reconnecting") {
    auto st = std::make_shared<axtest::FakeState>();
    auto c = make_client(st, Script{{200}});
    c.check_access("read", "r-1");
    const std::size_t before = st->count();

    c.close();

    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r-1"), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(c.login("u", "p"), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(c.logout(), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(c.refresh(), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(c.batch_check({}), axiam::NetworkError);
    AXIAM_REQUIRE_THROWS_AS(c.authenticate_device(), axiam::NetworkError);
    // Not one request reached the wire after close.
    AXIAM_REQUIRE(st->count() == before);
}

// ---------------------------------------------------------------------------
// §19 — telemetry
// ---------------------------------------------------------------------------

AXIAM_TEST("§19.2 rule 5: one request pair per attempt, with a retry between") {
    auto st = std::make_shared<axtest::FakeState>();
    Recorder rec;
    ClientOpts opts;
    opts.hook = rec.hook();
    auto c = make_client(st, Script{{503, 200}}, opts);
    c.check_access("read", "r-1");

    const std::vector<std::string> expected{"start", "end", "retry", "start", "end"};
    AXIAM_REQUIRE(rec.kinds() == expected);

    auto starts = rec.of<axiam::RequestStartEvent>();
    AXIAM_REQUIRE(starts.size() == 2);
    // Emitting both pairs as attempt 1 would make a retried call
    // indistinguishable from a single slow one.
    AXIAM_REQUIRE(starts[0].attempt == 1);
    AXIAM_REQUIRE(starts[1].attempt == 2);
    AXIAM_REQUIRE(starts[0].operation == "check_access");
    // The path TEMPLATE, never a substituted URL — a metric label carrying a UUID
    // is a cardinality bomb.
    AXIAM_REQUIRE(starts[0].path_template == "/api/v1/authz/check");

    auto ends = rec.of<axiam::RequestEndEvent>();
    AXIAM_REQUIRE(ends[0].outcome == axiam::Outcome::kFailure);
    AXIAM_REQUIRE(ends[0].status.has_value() && *ends[0].status == 503);
    AXIAM_REQUIRE(ends[1].outcome == axiam::Outcome::kSuccess);
}

AXIAM_TEST("§19: a failing call still emits request_end") {
    auto st = std::make_shared<axtest::FakeState>();
    Recorder rec;
    ClientOpts opts;
    opts.retry_enabled = false;
    opts.hook = rec.hook();
    auto c = make_client(st, Script{{0}}, opts);
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r-1"), axiam::NetworkError);

    auto ends = rec.of<axiam::RequestEndEvent>();
    AXIAM_REQUIRE(ends.size() == 1);
    AXIAM_REQUIRE(ends[0].outcome == axiam::Outcome::kFailure);
    // An absent status means the call never got a response, which is a different
    // fact from a 500 and must stay distinguishable in a metrics backend.
    AXIAM_REQUIRE_FALSE(ends[0].status.has_value());
}

AXIAM_TEST("§19.2 rule 2: a throwing hook cannot fail the operation") {
    auto st = std::make_shared<axtest::FakeState>();
    ClientOpts opts;
    opts.hook = [](const axiam::TelemetryEvent&) { throw std::runtime_error("hook exploded"); };
    auto c = make_client(st, Script{{200}}, opts);
    auto decision = c.check_access("read", "r-1");
    AXIAM_REQUIRE(decision.allowed);
}

AXIAM_TEST("§19.2 rule 1: no hook installed behaves identically") {
    // And §19.4's "a client with no hook installed behaves identically to one
    // before this section existed".
    auto st = std::make_shared<axtest::FakeState>();
    auto c = make_client(st, Script{{503, 200}});
    auto decision = c.check_access("read", "r-1");
    AXIAM_REQUIRE(decision.allowed);
    AXIAM_REQUIRE(st->count() == 2);
}

AXIAM_TEST("§19.2 rule 3: no event payload carries a token") {
    // This surface exists to be shipped to a metrics backend, which is the last
    // place a bearer token should land.
    auto st = std::make_shared<axtest::FakeState>();
    Recorder rec;
    Script script{{503}};
    script.body = R"({"access_token":"eyJhbGciOiJFZERTQSJ9.secret.sig"})";
    ClientOpts opts;
    opts.hook = rec.hook();
    auto c = make_client(st, script, opts);
    AXIAM_REQUIRE_THROWS_AS(c.check_access("read", "r-1"), axiam::NetworkError);

    std::string rendered;
    for (const auto& e : rec.of<axiam::RequestStartEvent>())
        rendered += e.operation + e.method + e.path_template;
    for (const auto& e : rec.of<axiam::RequestEndEvent>())
        rendered += e.operation + e.method + e.path_template;
    for (const auto& e : rec.of<axiam::RetryEvent>()) rendered += e.operation + e.reason;
    AXIAM_REQUIRE(!rendered.empty());
    AXIAM_REQUIRE(rendered.find("eyJ") == std::string::npos);
    AXIAM_REQUIRE(rendered.find("secret") == std::string::npos);
}

AXIAM_TEST("§19.2 rule 6: a clamped setting is reported, not swallowed") {
    // An operator who set a 60-second memo TTL believes their staleness bound is
    // 60 seconds. It is five. Clamping is right; doing it silently leaves their
    // revocation reasoning wrong by a factor of twelve with nothing anywhere to
    // say so.
    auto st = std::make_shared<axtest::FakeState>();
    Recorder rec;
    ClientOpts opts;
    opts.memo_ttl = 60000ms;
    opts.hook = rec.hook();
    auto c = make_client(st, Script{{200}}, opts);

    auto clamps = rec.of<axiam::ConfigClampedEvent>();
    AXIAM_REQUIRE(clamps.size() == 1);
    AXIAM_REQUIRE(clamps[0].setting == "decision_memo_ttl");
    AXIAM_REQUIRE(clamps[0].requested == "60000ms");
    AXIAM_REQUIRE(clamps[0].effective == "5000ms");
}

AXIAM_TEST("§19.2 rule 6: a value inside its limit reports nothing") {
    // An event that fires when nothing happened trains its reader to ignore it,
    // which costs exactly the case above.
    {
        auto st = std::make_shared<axtest::FakeState>();
        Recorder rec;
        ClientOpts opts;
        opts.memo_ttl = 2000ms;
        opts.hook = rec.hook();
        auto c = make_client(st, Script{{200}}, opts);
        AXIAM_CHECK(rec.of<axiam::ConfigClampedEvent>().empty());  // inside the ceiling
    }
    {
        auto st = std::make_shared<axtest::FakeState>();
        Recorder rec;
        ClientOpts opts;
        opts.memo_ttl = axiam::detail::kMemoMaxTtl;
        opts.hook = rec.hook();
        auto c = make_client(st, Script{{200}}, opts);
        AXIAM_CHECK(rec.of<axiam::ConfigClampedEvent>().empty());  // the ceiling exactly
    }
    {
        auto st = std::make_shared<axtest::FakeState>();
        Recorder rec;
        ClientOpts opts;
        opts.hook = rec.hook();
        auto c = make_client(st, Script{{200}}, opts);
        AXIAM_CHECK(rec.of<axiam::ConfigClampedEvent>().empty());  // the disabled default
    }
}
