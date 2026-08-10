// Client-side decision memo — CONTRACT.md §17. Internal (not installed).
//
// DISABLED BY DEFAULT. §11.2 rule 6's ban on caching allow/deny decisions is
// still the default behaviour; this is the single opt-in exception that section
// carves out, and a caller has to switch it on having read the cost.
//
// WHAT IT COSTS
//
// The staleness bound is the TTL, IN BOTH DIRECTIONS. A grant revoked on the
// server can still read as allowed for up to the TTL, and a grant just added can
// still read as denied for up to the TTL. That second direction is the one that
// surprises people: READ-YOUR-OWN-WRITES IS NOT GUARANTEED. An admin UI that
// grants a role and immediately re-checks is the case that breaks, and it breaks
// silently.
//
// This mirrors the server's own bound rather than inventing a second staleness
// story — AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS (default 5s) makes the same trade
// server-side. One deliberate difference: the server's setting is an unclamped
// integer, so an operator can configure a multi-hour staleness window.
// kMemoMaxTtl clamps this one at 5s, because the client has no reason to repeat
// that.
//
// Guarded by its own mutex: a C++ Client is a shared_ptr-backed handle routinely
// copied across threads, and a cache that corrupted under concurrency would be a
// worse bug than the one it is optimising away.
#pragma once

#include <chrono>
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "axiam/types.hpp"

namespace axiam {
namespace detail {

/// The §17.1 rule 2 ceiling. A configured TTL above this is clamped, not
/// rejected: a caller who asked for a minute wants caching, and silently giving
/// them the maximum safe value beats failing construction.
inline constexpr std::chrono::milliseconds kMemoMaxTtl{5000};

/// Entry cap before FIFO eviction (§17.1 rule 8). The memo is a latency
/// optimisation, so dropping an entry is always correct — but it must drop rather
/// than grow without bound.
inline constexpr std::size_t kMemoMaxEntries = 1024;

class DecisionMemo {
public:
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    /// Build a memo from a requested (unclamped) TTL. Zero or negative disables
    /// it — that is "off", not "cache for zero milliseconds".
    explicit DecisionMemo(std::chrono::milliseconds requested_ttl = std::chrono::milliseconds{0},
                          Clock clock = [] { return std::chrono::steady_clock::now(); })
        : ttl_(requested_ttl <= std::chrono::milliseconds{0} ? std::chrono::milliseconds{0}
                                                             : std::min(requested_ttl, kMemoMaxTtl)),
          clock_(std::move(clock)) {}

    /// Whether this memo does anything. `false` for the default configuration.
    bool enabled() const { return ttl_ > std::chrono::milliseconds{0}; }

    /// The TTL after clamping.
    std::chrono::milliseconds effective_ttl() const { return ttl_; }

    /// The §17.1 rule 3 key: all four components, absent distinguished from
    /// present.
    ///
    /// U+001F (unit separator) cannot appear in an action, a UUID or a scope, so
    /// no combination of caller-supplied values can forge a collision. U+0001
    /// marks an absent optional — which is why an absent scope can never collide
    /// with a present one; a memo that let them collide would answer a narrower
    /// question with a broader answer. U+0001 rather than U+0000 so the key stays
    /// a well-behaved std::string in every container and debugger.
    static std::string key(const std::optional<std::string>& subject_id,
                           const std::string& resource_id, const std::string& action,
                           const std::optional<std::string>& scope) {
        static const std::string kSep = "\x1F";
        static const std::string kAbsent = "\x01";
        return (subject_id ? *subject_id : kAbsent) + kSep + resource_id + kSep + action + kSep +
               (scope ? *scope : kAbsent);
    }

    /// A live decision for `k`, if one is memoized and unexpired.
    std::optional<AccessDecision> get(const std::string& k) {
        if (!enabled()) return std::nullopt;
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = entries_.find(k);
        if (it == entries_.end()) return std::nullopt;
        if (clock_() - it->second.stored_at >= ttl_) {
            erase_locked(k);
            return std::nullopt;
        }
        // Returned WHOLE, including reason_code: §17.1 rule 5 forbids returning
        // `allowed` while dropping the code, which would make the field
        // intermittently absent — worse than never having had it.
        return it->second.decision;
    }

    /// Memoize a decision the server actually returned.
    ///
    /// Callers must only reach here on success. §17.1 rule 7 forbids
    /// negative-caching a failure: memoizing a transport error as a deny would
    /// turn a blip into a TTL-long outage, and memoizing it as an allow is
    /// unthinkable.
    void put(const std::string& k, const AccessDecision& decision) {
        if (!enabled()) return;
        std::lock_guard<std::mutex> lock(mtx_);
        erase_locked(k);
        entries_.emplace(k, Entry{decision, clock_()});
        // Push-back plus front-eviction makes this FIFO by age: entries expire on
        // age, so the oldest is the one that was going to expire first anyway.
        order_.push_back(k);
        while (order_.size() > kMemoMaxEntries) {
            const std::string oldest = order_.front();
            order_.pop_front();
            entries_.erase(oldest);
        }
    }

    /// Drop every entry (§17.1 rule 9).
    ///
    /// Called on login, verify_mfa, refresh and logout. Entries are keyed by
    /// subject, not by session, so a re-authentication as a DIFFERENT principal
    /// would otherwise read the previous principal's decisions.
    void clear() {
        std::lock_guard<std::mutex> lock(mtx_);
        entries_.clear();
        order_.clear();
    }

    /// Entry count, for tests.
    std::size_t size() {
        std::lock_guard<std::mutex> lock(mtx_);
        return entries_.size();
    }

private:
    struct Entry {
        AccessDecision decision;
        std::chrono::steady_clock::time_point stored_at;
    };

    void erase_locked(const std::string& k) {
        if (entries_.erase(k) == 0) return;
        for (auto it = order_.begin(); it != order_.end(); ++it) {
            if (*it == k) {
                order_.erase(it);
                return;
            }
        }
    }

    const std::chrono::milliseconds ttl_;
    Clock clock_;
    std::mutex mtx_;
    std::unordered_map<std::string, Entry> entries_;
    std::deque<std::string> order_;  // front = oldest
};

}  // namespace detail
}  // namespace axiam
