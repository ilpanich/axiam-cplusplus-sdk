// §9 single-flight refresh guard (CONTRACT.md §9) — internal implementation
// detail of axiam::Client, factored out of client.cpp so its concurrency
// invariants can be unit-tested directly against a stub refresh function
// (tests/test_refresh_guard.cpp). NOT part of the installed public API: it lives
// under src/ on purpose and no public header includes it.
//
// ---------------------------------------------------------------------------
// The invariant, which CONTRACT.md §9 does not spell out and which two bugs
// have already been built on top of — do not reintroduce either:
//
//   The in-flight slot is a RESULT-SHARING CHANNEL, not a busy flag.
//
// `inflight_` holds the shared_future that publishes the one refresh's outcome
// to every caller that is contending for it (§9 rule 2). Two consequences:
//
//  1. Publication must precede vacating. The owner satisfies the promise BEFORE
//     it clears the slot, so a caller arriving at any instant either finds the
//     slot occupied and joins the shared outcome, or finds it clear with the
//     rotated credentials already installed. (In this SDK the credentials are
//     httpOnly cookies in the transport's jar (§4), not a token cached here:
//     the wire call itself publishes them, and it has returned by the time the
//     future settles. That is why this guard — unlike the Java SDK's
//     RefreshGuard — needs no `current` TokenPair cache to satisfy the
//     "never empty-and-nothing-published" half of the invariant.)
//     Never "slot empty and the outcome not yet published", which is the one
//     state that lets a caller issue a redundant SECOND refresh wire call.
//     AXIAM refresh tokens are single-use and rotating, so that second grant
//     fails invalid_grant and logs the user out.
//
//  2. Because of (1) the slot can legitimately hold an ALREADY-SETTLED future.
//     Occupancy therefore does not mean "a refresh is on the wire": liveness is
//     tested with wait_for(0s) != ready (live_locked()), never with valid().
//     A settled future must NOT be served to a caller that arrived after it
//     settled — that caller would be handed a token pair from a refresh whose
//     (single-use) refresh token was already consumed before the caller even
//     started, and its retry would 401 again. Such a caller counts as
//     uncontended: it takes ownership and performs its own wire call. This
//     matches the C SDK's single_flight_refresh(), where the flag is cleared
//     and the result broadcast under one mutex, and a later arrival starts a
//     fresh refresh.
//
//  3. Only the OWNER may vacate the slot, and only while the slot still holds
//     its own generation. A waiter that vacated on its way out (e.g. from an
//     exception path) could wipe a NEWER owner's live future, and the next
//     caller would then start a second concurrent refresh — the same
//     invalid_grant failure as (1). Generations make the "is this still mine?"
//     test cheap and exact; std::shared_future has no identity comparison.
//
// Exception safety: the owner's bookkeeping runs in a destructor (OwnerScope),
// so no throw can leave the promise unsatisfied (waiters would block) or the
// slot permanently occupied (a stuck slot would be treated as live and stall
// every later refresh — for extra safety it would not, see (2), but the slot is
// still always released).
//
// Locking: the mutex is never held across the network call (§9 rule 4 /
// CONTRACT §9's C++ row) — it is released before do_refresh() runs and before
// any caller blocks on the shared future.
// ---------------------------------------------------------------------------
#pragma once

#include <chrono>
#include <cstdint>
#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <utility>

#include "axiam/errors.hpp"
#include "axiam/types.hpp"

namespace axiam {
namespace detail {

/// Coalesces concurrent token refreshes: exactly one `do_refresh` wire call is
/// in flight at any time and every caller contending with it receives that one
/// call's outcome (§9 rules 1 + 2). Failures propagate as-is, once, to each
/// contending caller, and are never retried automatically (§9.3).
class RefreshGuard {
public:
    /// Performs the actual refresh wire call. Invoked at most once per
    /// contended refresh, always with no lock held.
    using RefreshFn = std::function<TokenPair()>;

    /// Points in run() at which the visible-for-testing hook fires. They exist
    /// so a test can pin open the narrow windows the invariants above are about,
    /// instead of racing for them. No hook is ever installed in production.
    enum class Phase {
        owner_published,  ///< owner: outcome published, slot not yet vacated
        waiter_joining,   ///< waiter: committed to the live future, about to block
        waiter_settled,   ///< waiter: that future has settled for it
    };

    /// Visible-for-testing seam; never installed in production.
    using Hook = std::function<void(Phase)>;

    RefreshGuard() = default;
    RefreshGuard(const RefreshGuard&) = delete;
    RefreshGuard& operator=(const RefreshGuard&) = delete;

    /// Runs (or joins) a single-flight refresh.
    ///
    /// @param do_refresh the wire call; invoked only by the owning caller.
    /// @return the owner's own result, or the result of the live refresh this
    ///         caller joined.
    /// @throws whatever `do_refresh` threw — rethrown as-is to the owner and to
    ///         every caller that joined it, exactly once each, with no retry.
    TokenPair run(const RefreshFn& do_refresh) {
        std::shared_future<TokenPair> joined;
        std::shared_ptr<std::promise<TokenPair>> promise;
        std::uint64_t generation = 0;
        Hook hook;
        {
            std::lock_guard<std::mutex> lock(mtx_);
            hook = test_hook_;
            if (live_locked()) {
                joined = inflight_;
            } else {
                // Slot empty, or occupied by a future that has already settled
                // (see header note 2) — either way no refresh is on the wire,
                // so this caller becomes the owner and replaces the slot.
                promise = std::make_shared<std::promise<TokenPair>>();
                inflight_ = promise->get_future().share();
                generation = ++generation_;
            }
        }

        if (!promise) {
            // Waiter: shares the live refresh's outcome (§9 rule 2). It must
            // NOT touch the slot — it does not own it, and by the time it wakes
            // the slot may already belong to a newer refresh (header note 3).
            RunOnExit on_settle(hook, Phase::waiter_settled);
            fire(hook, Phase::waiter_joining);
            return joined.get();
        }

        // Owner: the wire call runs with no lock held; OwnerScope publishes the
        // outcome (if the body somehow did not) and then vacates our own
        // generation, in that order, on every path.
        OwnerScope scope(*this, *promise, generation, hook);
        try {
            TokenPair tp = do_refresh();
            scope.publish(tp);
            return tp;
        } catch (...) {
            // §9.3: hand the one failure to every waiter, then propagate it
            // unchanged. Never retried here.
            scope.publish_exception(std::current_exception());
            throw;
        }
    }

    /// Visible-for-testing: is the result-sharing slot populated at all
    /// (live OR settled-but-not-yet-vacated)?
    bool slot_occupied() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return inflight_.valid();
    }

    /// Visible-for-testing: is a refresh genuinely on the wire?
    bool slot_live() const {
        std::lock_guard<std::mutex> lock(mtx_);
        return live_locked();
    }

    /// Visible-for-testing: install the Phase hook. Call before starting any
    /// thread that uses this guard.
    void set_test_hook(Hook hook) {
        std::lock_guard<std::mutex> lock(mtx_);
        test_hook_ = std::move(hook);
    }

private:
    /// Invokes a (possibly empty) hook, swallowing any throw so it is safe to
    /// call while an exception is propagating.
    static void fire(const Hook& hook, Phase phase) {
        if (!hook) return;
        try {
            hook(phase);
        } catch (...) {
        }
    }

    /// Fires `phase` on scope exit — used for the waiter, whose settle point is
    /// reached both by a normal return and by a rethrown refresh failure.
    class RunOnExit {
    public:
        RunOnExit(const Hook& hook, Phase phase) : hook_(hook), phase_(phase) {}
        RunOnExit(const RunOnExit&) = delete;
        RunOnExit& operator=(const RunOnExit&) = delete;
        ~RunOnExit() { fire(hook_, phase_); }

    private:
        const Hook& hook_;
        Phase phase_;
    };

    /// Owner-side bookkeeping, in a destructor so that no exception (not even
    /// one thrown while publishing) can leave waiters blocked on an unsatisfied
    /// promise or the slot occupied forever.
    class OwnerScope {
    public:
        OwnerScope(RefreshGuard& guard, std::promise<TokenPair>& promise,
                   std::uint64_t generation, const Hook& hook)
            : guard_(guard), promise_(promise), generation_(generation), hook_(hook) {}
        OwnerScope(const OwnerScope&) = delete;
        OwnerScope& operator=(const OwnerScope&) = delete;

        void publish(const TokenPair& tp) {
            if (published_) return;
            published_ = true;
            promise_.set_value(tp);
        }

        void publish_exception(std::exception_ptr ex) {
            if (published_) return;
            published_ = true;
            promise_.set_exception(std::move(ex));
        }

        ~OwnerScope() {
            // Publication strictly before vacating (header note 1).
            if (!published_) {
                published_ = true;
                try {
                    promise_.set_exception(std::make_exception_ptr(
                        AuthError("token refresh aborted before its outcome was published")));
                } catch (...) {
                }
            }
            fire(hook_, Phase::owner_published);
            guard_.vacate(generation_);
        }

    private:
        RefreshGuard& guard_;
        std::promise<TokenPair>& promise_;
        std::uint64_t generation_;
        const Hook& hook_;
        bool published_ = false;
    };

    /// A refresh is live only while its future has not settled; an occupied slot
    /// alone proves nothing (header note 2). Called with mtx_ held.
    bool live_locked() const {
        return inflight_.valid() &&
               inflight_.wait_for(std::chrono::seconds(0)) != std::future_status::ready;
    }

    /// Clears the slot iff it still holds `generation` — i.e. iff this owner's
    /// future has not already been replaced by a newer owner (header note 3).
    void vacate(std::uint64_t generation) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (generation_ == generation) {
            inflight_ = std::shared_future<TokenPair>();
        }
    }

    mutable std::mutex mtx_;
    std::shared_future<TokenPair> inflight_;
    /// Bumped for every future installed in the slot; identifies its owner.
    std::uint64_t generation_ = 0;
    Hook test_hook_;
};

}  // namespace detail
}  // namespace axiam
