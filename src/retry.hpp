// Bounded read-only retry — CONTRACT.md §16. Internal (not installed).
//
// The policy is machinery, not surface: the only public knob is
// `Client::Builder::retry_enabled`. §16.1 permits lowering the budget or turning
// it off, never raising it — a caller who can raise the cap turns one client into
// the herd the backoff exists to prevent — so there is deliberately no builder
// method for the attempt count, the base delay or the delay cap.
//
// Everything here is a pure function of (attempt, header, fraction), so §16.7's
// "injected clock and injected PRNG — never by sleeping" is achievable: a test
// that really waits 200 ms is a test nobody runs.
#pragma once

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <optional>
#include <string>

namespace axiam {
namespace detail {

/// §16.1: 1 initial attempt + 2 retries. Bounds worst-case added latency at
/// ~10 s; a caller who needs more retries at their own layer knows their own
/// deadline.
inline constexpr int kRetryMaxAttempts = 3;

/// §16.1 base delay. Long enough that a retry is not simply re-entering the same
/// overload, short enough to be invisible on a recovery from a dropped packet.
inline constexpr std::chrono::milliseconds kRetryBaseDelay{200};

/// §16.1 ceiling on any single wait.
inline constexpr std::chrono::milliseconds kRetryMaxDelay{5000};

/// §16.1 backoff before jitter: `min(cap, base * 2^(attempt-1))`.
inline std::chrono::milliseconds retry_backoff(int attempt) {
    const int n = std::max(attempt, 1);
    auto delay = kRetryBaseDelay;
    for (int i = 1; i < n && delay < kRetryMaxDelay; ++i) delay *= 2;
    return std::min(delay, kRetryMaxDelay);
}

/// §16.1 wait for `attempt`, given a uniform `fraction` in [0, 1] and an optional
/// `Retry-After`.
///
/// FULL jitter: the wait is `backoff * fraction`, i.e. uniform over
/// [0, backoff] — not `backoff ± something`. Partial jitter keeps every client's
/// retries clustered around the same instant, which is the failure mode retries
/// cause rather than fix.
///
/// `Retry-After` is a FLOOR, never a ceiling. The server is telling you when it
/// will be ready, so retrying sooner is not permitted; and because the hint only
/// ever lengthens the wait, a `Retry-After: 0` cannot defeat the backoff.
/// Replacing the backoff with the hint — which is what a `retry_after ?
/// *retry_after : backoff` idiom does — is the shipped bug this wording names.
inline std::chrono::milliseconds retry_delay(int attempt,
                                             std::optional<std::chrono::milliseconds> retry_after,
                                             double fraction) {
    const double clamped = std::min(std::max(fraction, 0.0), 1.0);
    const auto jittered = std::chrono::milliseconds(
        static_cast<long long>(static_cast<double>(retry_backoff(attempt).count()) * clamped));
    if (!retry_after) return jittered;
    return std::max(jittered, *retry_after);
}

/// §16.3: whether a completed exchange should be retried. `status` is
/// `std::nullopt` when no HTTP response arrived at all.
inline bool retry_should_retry(std::optional<long> status) {
    // Connection refused / DNS / TLS / read timeout: no response arrived, so the
    // request may never have been seen.
    if (!status) return true;
    // 429 is exactly where Retry-After usually arrives.
    if (*status == 408 || *status == 429) return true;
    if (*status >= 500 && *status <= 599) return true;
    // Everything else is decisive: 401 belongs to §9's refresh path, 403 is the
    // server having decided, and every other 4xx would produce an identical
    // rejection on a second attempt.
    return false;
}

/// Parse a `Retry-After` header. RFC 7231 allows either delta-seconds or an
/// HTTP-date and both appear in the wild, so both are parsed.
///
/// Returns `std::nullopt` — absent — for anything unparseable, rather than zero:
/// an unparseable hint must not become a zero-length floor.
inline std::optional<std::chrono::milliseconds> retry_after_from_header(
    const std::string& value, std::time_t now = std::time(nullptr)) {
    std::size_t begin = value.find_first_not_of(" \t");
    if (begin == std::string::npos) return std::nullopt;
    std::size_t end = value.find_last_not_of(" \t");
    const std::string raw = value.substr(begin, end - begin + 1);
    if (raw.empty()) return std::nullopt;

    const bool all_digits =
        std::all_of(raw.begin(), raw.end(), [](unsigned char c) { return std::isdigit(c) != 0; });
    if (all_digits) {
        char* stop = nullptr;
        const long long seconds = std::strtoll(raw.c_str(), &stop, 10);
        if (stop == raw.c_str() || seconds < 0) return std::nullopt;
        // Clamped at an hour so a hostile or broken header cannot park a thread
        // for a day. The §16.1 cap governs the backoff, not the floor, so without
        // this the floor would be unbounded.
        return std::chrono::milliseconds(std::min<long long>(seconds, 3600) * 1000);
    }

    std::tm tm{};
    // IMF-fixdate, the only form a server is required to send.
    if (strptime(raw.c_str(), "%a, %d %b %Y %H:%M:%S", &tm) == nullptr) return std::nullopt;
    const std::time_t when = timegm(&tm);
    if (when == static_cast<std::time_t>(-1)) return std::nullopt;
    const double delta = std::difftime(when, now);
    // A date already in the past is not a wait.
    if (delta <= 0) return std::nullopt;
    return std::chrono::milliseconds(static_cast<long long>(std::min(delta, 3600.0) * 1000));
}

}  // namespace detail
}  // namespace axiam
