// Concurrency regression tests for the §9 single-flight refresh guard
// (src/refresh_guard.hpp). They drive the guard directly with a stub refresh
// function so the two narrow windows its invariants are about can be pinned open
// deterministically, instead of raced for:
//
//   * a caller that arrives AFTER the shared future settled must not be handed
//     that already-consumed result — it needs its own refresh; and
//   * a waiter must never vacate the in-flight slot, because by the time it
//     wakes the slot may belong to a NEWER, still-live refresh.
//
// Both used to be violated. AXIAM refresh tokens are single-use and rotating, so
// either violation costs a redundant `refresh_token` grant that the server
// rejects with invalid_grant (CONTRACT.md §9 rule 2).
//
// All AXIAM_CHECK assertions run on the main thread only (the vendored harness'
// Stats is not thread-safe); worker threads record into atomics or into locals
// that are read back after join().
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "assert.hpp"
#include "axiam/errors.hpp"
#include "refresh_guard.hpp"

using axiam::AuthError;
using axiam::AxiamError;
using axiam::TokenPair;
using axiam::detail::RefreshGuard;

namespace {

/// One-shot gate: open() releases every current and future wait().
class Gate {
public:
    void open() {
        {
            std::lock_guard<std::mutex> lock(m_);
            open_ = true;
        }
        cv_.notify_all();
    }
    void wait() {
        std::unique_lock<std::mutex> lock(m_);
        cv_.wait(lock, [this] { return open_; });
    }
    /// Bounded wait so a regression makes the test FAIL rather than hang.
    bool wait_for(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(m_);
        return cv_.wait_for(lock, timeout, [this] { return open_; });
    }

private:
    std::mutex m_;
    std::condition_variable cv_;
    bool open_ = false;
};

TokenPair token(std::int64_t expires_in) {
    TokenPair tp;
    tp.expires_in = expires_in;
    return tp;
}

/// Tracks how many stub refresh calls execute simultaneously, so a test can
/// assert §9 rule 1 directly: never more than one on the wire.
class Concurrency {
public:
    void enter() {
        const int now = live_.fetch_add(1) + 1;
        int seen = peak_.load();
        while (now > seen && !peak_.compare_exchange_weak(seen, now)) {
        }
    }
    void leave() { live_.fetch_sub(1); }
    int peak() const { return peak_.load(); }

private:
    std::atomic<int> live_{0};
    std::atomic<int> peak_{0};
};

}  // namespace

// Bug (b): the slot legitimately holds an already-settled future for a moment
// (publication precedes vacating). A caller arriving in that window must NOT be
// served that settled result — the refresh token behind it was already consumed
// by a call that finished before this caller even started, so the caller must
// perform its own refresh. Previously it joined the settled future and was
// handed the stale pair.
AXIAM_TEST("§9 refresh guard: a caller arriving after the future settled performs its own refresh") {
    RefreshGuard g;
    Gate window_open, hold_window;
    std::atomic<int> leader_calls{0};
    std::atomic<int> late_calls{0};

    // Pin open the settled-but-not-yet-vacated window on the FIRST owner only
    // (the late caller is an owner too, and must not be held).
    std::atomic<bool> pinned{false};
    g.set_test_hook([&](RefreshGuard::Phase phase) {
        if (phase != RefreshGuard::Phase::owner_published) return;
        if (pinned.exchange(true)) return;
        window_open.open();
        hold_window.wait();
    });

    TokenPair leader_result{};
    std::thread leader([&] {
        leader_result = g.run([&] {
            leader_calls.fetch_add(1);
            return token(111);
        });
    });

    window_open.wait();  // leader published 111 and has not vacated yet
    const bool occupied_in_window = g.slot_occupied();
    const bool live_in_window = g.slot_live();

    TokenPair late_result{};
    bool late_threw = false;
    try {
        late_result = g.run([&] {
            late_calls.fetch_add(1);
            return token(222);
        });
    } catch (...) {
        late_threw = true;
    }

    hold_window.open();
    leader.join();

    // The window really was open: slot populated, but nothing on the wire.
    AXIAM_CHECK(occupied_in_window);
    AXIAM_CHECK_FALSE(live_in_window);

    AXIAM_CHECK_FALSE(late_threw);
    AXIAM_CHECK(leader_result.expires_in == 111);
    // The regression: the late caller must get its OWN refresh's result (222),
    // never the leader's already-consumed 111.
    AXIAM_CHECK(late_result.expires_in == 222);
    AXIAM_CHECK(leader_calls.load() == 1);
    AXIAM_CHECK(late_calls.load() == 1);
    // Both owners vacated, and the leader's stale generation wiped nothing.
    AXIAM_CHECK_FALSE(g.slot_occupied());
}

// Bug (a): a waiter used to clear the in-flight slot on its way out of the
// failure path — including when the slot had since been re-occupied by a newer
// leader's LIVE future. The next caller then found an empty slot and issued a
// second, concurrent refresh.
//
// Timeline (each step waits for the previous one; no unbounded sleeps):
//   1. leader-1 starts a refresh that will fail, and blocks in the wire call.
//   2. a waiter joins leader-1's live future.
//   3. leader-1 fails; the waiter is held exactly where it used to vacate.
//   4. leader-2 starts a NEW refresh and blocks in its wire call (slot live).
//   5. the waiter is released — it must not touch leader-2's slot.
//   6. a fresh caller must join leader-2's live refresh, not start a third one.
AXIAM_TEST("§9 refresh guard: a waiter never vacates a newer refresh's slot") {
    RefreshGuard g;
    Concurrency conc;
    Gate first_started, fail_first, waiter_joining, waiter_settled, release_waiter;
    Gate second_started, third_joined, release_second;
    std::atomic<int> joining_count{0};

    std::atomic<int> first_calls{0};
    std::atomic<int> waiter_own_calls{0};  // must stay 0: the waiter joins, never refreshes
    std::atomic<int> second_calls{0};
    std::atomic<int> third_calls{0};  // must stay 0: caller 3 joins leader-2

    g.set_test_hook([&](RefreshGuard::Phase phase) {
        switch (phase) {
            case RefreshGuard::Phase::waiter_joining:
                // First firing is the waiter, second is caller 3 (fixed guard only).
                if (joining_count.fetch_add(1) == 0) {
                    waiter_joining.open();
                } else {
                    third_joined.open();
                }
                break;
            case RefreshGuard::Phase::waiter_settled:
                waiter_settled.open();
                release_waiter.wait();  // hold the waiter in its old vacate spot
                break;
            case RefreshGuard::Phase::owner_published:
                break;
        }
    });

    std::string leader1_error;
    std::thread leader1([&] {
        try {
            g.run([&]() -> TokenPair {
                first_calls.fetch_add(1);
                conc.enter();
                first_started.open();
                fail_first.wait();
                conc.leave();
                throw AuthError("refresh-1 rejected");
            });
        } catch (const AxiamError& e) {
            leader1_error = e.what();
        }
    });

    first_started.wait();  // leader-1's wire call is live => the next caller waits

    std::string waiter_error;
    std::thread waiter([&] {
        try {
            g.run([&] {
                waiter_own_calls.fetch_add(1);
                return token(-1);
            });
        } catch (const AxiamError& e) {
            waiter_error = e.what();
        }
    });

    waiter_joining.wait();  // the waiter is committed to leader-1's future
    fail_first.open();      // leader-1 fails; the outcome is shared with the waiter
    waiter_settled.wait();  // the waiter is now held where it used to vacate
    leader1.join();         // leader-1 vacated its own generation and rethrew

    TokenPair leader2_result{};
    std::thread leader2([&] {
        leader2_result = g.run([&] {
            second_calls.fetch_add(1);
            conc.enter();
            second_started.open();
            release_second.wait();
            conc.leave();
            return token(222);
        });
    });
    second_started.wait();  // leader-2's refresh is LIVE and owns the slot
    const bool live_before_release = g.slot_live();

    release_waiter.open();  // the buggy waiter wiped leader-2's slot right here
    waiter.join();

    const bool live_after_release = g.slot_live();

    TokenPair third_result{};
    std::thread third([&] {
        third_result = g.run([&] {
            third_calls.fetch_add(1);
            conc.enter();
            conc.leave();
            return token(333);
        });
    });

    // Caller 3 must become a WAITER on leader-2. Bounded wait: with the bug it
    // never joins (it starts its own refresh instead), and the assertions below
    // report that rather than the test hanging.
    const bool third_became_waiter = third_joined.wait_for(std::chrono::seconds(2));
    release_second.open();
    leader2.join();
    third.join();

    // §9.2/§9.3: the one failure reached both the owner and the waiter, as-is.
    AXIAM_CHECK(leader1_error == "refresh-1 rejected");
    AXIAM_CHECK(waiter_error == "refresh-1 rejected");
    AXIAM_CHECK(first_calls.load() == 1);
    AXIAM_CHECK(waiter_own_calls.load() == 0);

    AXIAM_CHECK(live_before_release);
    // The regression: the waiter must leave leader-2's live future in place.
    AXIAM_CHECK(live_after_release);

    // Caller 3 joined leader-2 instead of issuing a redundant grant.
    AXIAM_CHECK(third_became_waiter);
    AXIAM_CHECK(third_calls.load() == 0);
    AXIAM_CHECK(third_result.expires_in == 222);
    AXIAM_CHECK(leader2_result.expires_in == 222);
    AXIAM_CHECK(second_calls.load() == 1);
    // §9 rule 1, stated directly: never two refresh calls on the wire at once.
    AXIAM_CHECK(conc.peak() == 1);
    AXIAM_CHECK_FALSE(g.slot_occupied());
}

// The guard stays usable after a failure: no leaked ownership, no stuck slot
// (a stuck slot would deadlock or permanently stall every later refresh).
AXIAM_TEST("§9 refresh guard: a failed refresh leaves the guard usable (no stuck slot)") {
    RefreshGuard g;
    int calls = 0;
    for (int i = 0; i < 3; ++i) {
        bool threw = false;
        try {
            g.run([&]() -> TokenPair {
                ++calls;
                throw AuthError("nope");
            });
        } catch (const AuthError&) {
            threw = true;
        }
        AXIAM_CHECK(threw);
        AXIAM_CHECK_FALSE(g.slot_occupied());
    }
    // Each sequential caller gets its own attempt (§9.3 forbids an automatic
    // retry of a failed refresh, not a later caller's fresh attempt), and a
    // success still works afterwards.
    AXIAM_CHECK(calls == 3);
    AXIAM_CHECK(g.run([] { return token(900); }).expires_in == 900);
    AXIAM_CHECK_FALSE(g.slot_occupied());
}

// A refresh function that throws a non-AxiamError type must still publish to
// waiters (nobody blocks forever) and propagate unchanged.
//
// The two catch blocks are ordered against each other (waiter copies, then owner
// copies, then the waiter leaves its catch): §9 rule 2 hands ONE exception object
// to several threads, and libstdc++ releases it inside uninstrumented library
// code, so a thread leaving its catch block while another reads what() shows up
// as a ThreadSanitizer "data race" on the exception's buffer. It is a benign
// refcount blind spot — ASan reports no use-after-free, and the reports appear
// with the pre-fix implementation too — but ordering the blocks here keeps the
// suite TSan-clean so a genuine race would stand out.
AXIAM_TEST("§9 refresh guard: an arbitrary exception is shared with waiters and propagated") {
    RefreshGuard g;
    Gate started, joining, release, waiter_recorded, owner_recorded;
    std::string owner_error;
    std::string waiter_error;

    g.set_test_hook([&](RefreshGuard::Phase phase) {
        if (phase == RefreshGuard::Phase::waiter_joining) joining.open();
    });

    std::thread owner([&] {
        try {
            g.run([&]() -> TokenPair {
                started.open();
                release.wait();
                throw std::runtime_error("odd failure");
            });
        } catch (const std::exception& e) {
            waiter_recorded.wait();
            owner_error = e.what();
            owner_recorded.open();
        }
    });
    started.wait();
    std::thread w([&] {
        try {
            g.run([] { return token(-1); });
        } catch (const std::exception& e) {
            waiter_error = e.what();
            waiter_recorded.open();
            owner_recorded.wait();  // keep this reference alive past the owner's read
        }
    });
    joining.wait();
    release.open();
    owner.join();
    w.join();

    AXIAM_CHECK(owner_error == "odd failure");
    AXIAM_CHECK(waiter_error == "odd failure");
    AXIAM_CHECK_FALSE(g.slot_occupied());
}

// Stress: hammer the guard from many threads across many rounds and assert the
// invariants that must hold at every instant —
//   1. at most one refresh call on the wire (§9 rule 1); and
//   2. no caller is served the result of a refresh that had already SETTLED
//      before that caller entered the guard.
// (2) uses completion stamps: each refresh returns its completion ordinal, and
// `settled_seen` tracks the highest ordinal any caller has already RETURNED with
// — i.e. an ordinal known to have settled. A caller entering afterwards must get
// a strictly higher one. Since at most one refresh is ever on the wire (checked
// by (1)), ordinals are totally ordered by settle time, so this detector has no
// false positives; it is one-sided (it can miss, never mis-accuse).
AXIAM_TEST("§9 refresh guard: stress — one call on the wire, never a pre-settled result") {
    RefreshGuard g;
    Concurrency conc;
    std::atomic<std::int64_t> completed{0};
    std::atomic<std::int64_t> settled_seen{0};
    std::atomic<int> stale_results{0};
    std::atomic<int> total_calls{0};

    constexpr int rounds = 40;
    constexpr int threads_per_round = 6;

    auto refresh = [&] {
        total_calls.fetch_add(1);
        conc.enter();
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
        conc.leave();
        return token(completed.fetch_add(1) + 1);
    };

    for (int r = 0; r < rounds; ++r) {
        Gate go;
        std::vector<std::thread> ts;
        for (int i = 0; i < threads_per_round; ++i) {
            ts.emplace_back([&] {
                go.wait();
                const std::int64_t seen_before = settled_seen.load();
                const TokenPair tp = g.run(refresh);
                if (tp.expires_in <= seen_before) stale_results.fetch_add(1);
                std::int64_t high = settled_seen.load();
                while (tp.expires_in > high &&
                       !settled_seen.compare_exchange_weak(high, tp.expires_in)) {
                }
            });
        }
        go.open();
        for (auto& t : ts) t.join();
    }

    AXIAM_CHECK(conc.peak() == 1);
    AXIAM_CHECK(stale_results.load() == 0);
    // Coalescing actually happened (far fewer wire calls than callers).
    AXIAM_CHECK(total_calls.load() < rounds * threads_per_round);
    AXIAM_CHECK_FALSE(g.slot_occupied());
}
