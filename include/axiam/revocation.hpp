/// @file revocation.hpp
/// CONTRACT.md §10.4 — the optional session-revocation feed (contract 1.44,
/// AXIAM threats T-39 and T-143).
///
/// §10.2 records the gap this narrows: local verification proves a token was
/// issued and has not expired, never that the session behind it still exists. A
/// logout or a role removal therefore does not reach a token already in a
/// caller's hands until it expires — up to fifteen minutes. The documented
/// answer has been "route the decision through gRPC introspection instead",
/// which is correct and costs a round trip **per request**.
///
/// A deployment may publish `GET /oauth2/revocations`: the base64url-unpadded
/// SHA-256 of every session id revoked within the last access-token lifetime. A
/// guard that polls it rejects a revoked session within **one poll interval**
/// instead of one token lifetime, for one cacheable fetch per interval.
///
/// It is **not a control**, and every rule below follows from that:
///
///  - **Default off.** Nothing polls unless a caller attaches a feed to an
///    AuthenticatorOptions.
///  - **Never on the request path.** is_revoked() answers from the cached set.
///  - **Never fail closed.** An unreachable feed, a non-200, a body that does
///    not parse, an `alg` this build does not know — every one of them behaves
///    exactly as no feed at all. Not as an empty list: an empty list asserts
///    that nothing has been revoked, which is a guard that silently honours no
///    revocations while appearing to honour them.
///  - **It only ever rejects.** Every §10.1 rule runs first and still decides.
///  - **A token with no `sid` is never matched.** There is no session behind a
///    client-credentials token, an RPT or a token exchange, and hashing `jti`
///    instead would match nothing while looking like it worked.
#ifndef AXIAM_REVOCATION_HPP
#define AXIAM_REVOCATION_HPP

#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_set>

#include "axiam/transport.hpp"

namespace axiam {

/// The published feed's path, appended to a deployment's base URL.
inline constexpr const char* kRevocationFeedPath = "/oauth2/revocations";

/// The shortest interval a caller may configure (§10.4 rule 2).
///
/// Bounded because the feed is one deployment-wide document and a fleet of
/// guards polling it at a hundred milliseconds is a load source rather than a
/// security improvement. The floor is applied by clamping, not by refusing: a
/// caller who asked for something faster gets the fastest thing on offer.
inline constexpr std::chrono::seconds kMinRevocationPollInterval{15};

/// The default interval, and the one §10.4 recommends.
inline constexpr std::chrono::seconds kDefaultRevocationPollInterval{30};

/// The largest number of entries kept in the cache (§10.4 rule 2).
///
/// The server bounds the document by its own revocation rate over one token
/// lifetime, so this is defence against a server that stops doing so — a cache
/// with no ceiling is an allocation an unauthenticated endpoint controls.
/// Overflow drops the **whole** set rather than truncating it: a truncated set
/// is a guard that admits some revoked sessions and reports none, which is worse
/// than a guard that admits all of them and says the feed is unusable.
inline constexpr std::size_t kMaxRevocationEntries = 100000;

/// The feed entry for a `sid`, as the server computes it.
///
/// Base64url without padding over the claim's **exact string** — never a
/// parsed-and-re-rendered UUID, or the answer would depend on this library's
/// UUID handling rather than on the feed.
std::string revocation_entry_for(const std::string& sid);

/// A poller for one deployment's revocation feed.
///
/// Thread-safe, and meant to be shared: several authenticators built from one
/// feed poll once between them rather than once each. Hold it by reference in
/// AuthenticatorOptions; it must outlive the authenticators that name it.
class RevocationFeed {
public:
    /// @param transport     shared transport seam (same as the client's).
    /// @param base_url      server base URL (trailing slash tolerated).
    /// @param poll_interval how often a check after this long refetches;
    ///                      anything below kMinRevocationPollInterval is raised
    ///                      to it rather than refused.
    ///
    /// A deployment that does not publish the feed is not an error here — that
    /// is discovered on the first poll, and behaves as no feed at all from then
    /// on.
    RevocationFeed(Transport transport, std::string base_url,
                   std::chrono::seconds poll_interval = kDefaultRevocationPollInterval);

    /// Has this session been revoked, as far as this poller knows?
    ///
    /// `false` whenever the answer is not a confident yes — a feed never
    /// fetched, unreachable, malformed, or simply not listing this session. The
    /// caller admits the request in all of those cases, which is §10.4 rule 3
    /// and is the whole reason the feature is safe to turn on.
    ///
    /// An empty `sid` is never matched: there is no session behind one.
    bool is_revoked(const std::string& sid);

    /// Fetch now, whatever the interval says. For tests, and for a caller that
    /// wants the first poll to have happened before it starts serving.
    void refresh();

    /// The feed document's URL, for diagnostics.
    const std::string& feed_url() const noexcept { return feed_url_; }

    /// The poll interval actually in force, after the floor is applied.
    std::chrono::seconds poll_interval() const noexcept { return poll_interval_; }

    /// Test seam: the monotonic clock the staleness check reads. Private in
    /// spirit — exposed only so a test can age the cache without sleeping
    /// fifteen seconds, which is a test nobody runs.
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;
    void set_clock_for_testing(ClockFn clock);

private:
    void refresh_if_stale();
    /// One fetch. Disengaged for every kind of failure, which the caller treats
    /// identically — see the file header on why "unusable" must not collapse
    /// into "empty".
    std::optional<std::unordered_set<std::string>> fetch_once();
    std::chrono::steady_clock::time_point now() const;

    Transport transport_;
    std::string feed_url_;
    std::chrono::seconds poll_interval_;
    ClockFn clock_;

    std::mutex fetch_mtx_;  ///< collapses a concurrent burst into one fetch
    mutable std::mutex mtx_;
    /// Disengaged means "never successfully fetched", which is NOT the same as
    /// a fetched-but-empty document, and is why this is an optional rather than
    /// a bare set.
    std::optional<std::unordered_set<std::string>> entries_;
    std::optional<std::chrono::steady_clock::time_point> last_attempt_;
};

}  // namespace axiam

#endif  // AXIAM_REVOCATION_HPP
