// §13 Webhook signature verification (T-145).
//
// AXIAM signs every webhook delivery with a Stripe-style signed timestamp:
//
//   X-Axiam-Timestamp : <unix seconds, decimal ASCII>
//   X-Axiam-Signature : t=<unix seconds>,v1=<hex lowercase HMAC-SHA256>
//   X-Axiam-Event     : <event type>
//   X-Axiam-Delivery  : <delivery UUID>
//
// where `v1 = HMAC-SHA256(secret_utf8_bytes, "<t>.<raw_body>")`.
//
// !! The body MUST be the exact raw bytes received off the wire. !!
// Never re-serialize parsed JSON before verifying — a change in key order or
// whitespace changes the MAC and the signature will not match. Capture the body
// before your framework's JSON parser touches it.
//
// Dedup is the receiver's job: `X-Axiam-Delivery` is the at-least-once dedup
// key. A retry replays a byte-identical, still-valid signature inside the
// freshness window, so keep a short-lived seen-set of delivery ids if your
// handler is not idempotent.
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>

#include "axiam/errors.hpp"
#include "axiam/sensitive.hpp"

namespace axiam {
namespace webhook {

/// Why verification failed. Deliberately coarse: nothing here, and nothing in
/// the matching message, discloses the expected signature.
enum class VerifyError {
    kNone = 0,
    kEmptySecret,             ///< no secret configured — fail closed, never skip
    kMalformedHeader,         ///< unparseable, empty, or no/duplicate `t=`
    kMissingSignature,        ///< header parsed but carried no `v1=` value
    kMalformedTimestamp,      ///< `t=` was not a non-negative decimal integer
    kTimestampHeaderMismatch, ///< X-Axiam-Timestamp disagreed with `t=`
    kSignatureMismatch,       ///< no supplied `v1` matched the computed MAC
    kTimestampOutOfTolerance, ///< |now - t| exceeded the freshness window
};

/// Stable, secret-free description of a VerifyError.
const char* to_string(VerifyError error) noexcept;

/// A verified delivery.
struct Event {
    /// The `t=` value covered by the MAC.
    std::int64_t timestamp = 0;
    /// X-Axiam-Event, when supplied to verify() via Options.
    std::string event_type;
    /// X-Axiam-Delivery, when supplied to verify() via Options. Use it as the
    /// at-least-once dedup key.
    std::string delivery_id;
    /// The raw body that was verified.
    std::string body;
};

/// Optional inputs to verify().
struct Options {
    /// Two-sided freshness window. A delivery is rejected when
    /// `abs(now - t) > tolerance`, so a future-dated timestamp is rejected just
    /// like a stale one.
    std::chrono::seconds tolerance{300};

    /// Time source in unix seconds. Empty => the system clock. Injection seam
    /// for tests.
    std::function<std::int64_t()> now;

    /// The separate `X-Axiam-Timestamp` header, if the receiver read it. It is
    /// redundant with `t=` (only `t=` is covered by the MAC), but when supplied
    /// it MUST match `t=` exactly or verification fails.
    std::optional<std::string> timestamp_header;

    /// X-Axiam-Event, copied into the returned Event. Not covered by the MAC.
    std::string event_type;

    /// X-Axiam-Delivery, copied into the returned Event. Not covered by the MAC.
    std::string delivery_id;
};

/// Outcome of verify(). Contextually convertible to bool; falsy means rejected.
struct Result {
    bool ok = false;
    VerifyError error = VerifyError::kNone;
    Event event;

    explicit operator bool() const noexcept { return ok; }
    const char* error_message() const noexcept { return to_string(error); }
};

/// Thrown by verify_or_throw() when a delivery does not verify.
class VerifyException : public AxiamError {
public:
    VerifyException(VerifyError error, const std::string& message)
        : AxiamError(message), error_(error) {}
    VerifyError error() const noexcept { return error_; }

private:
    VerifyError error_;
};

/// Verify a webhook delivery. Never throws; fails closed on anything unexpected.
///
/// @param secret           the webhook's plaintext secret (§7 Sensitive).
/// @param signature_header the raw `X-Axiam-Signature` value.
/// @param body             the RAW request body bytes, exactly as received.
/// @param options          freshness window, clock seam, optional headers.
Result verify(const Sensitive<std::string>& secret, const std::string& signature_header,
              const std::string& body, const Options& options = Options{});

/// Overload for a secret that is not already wrapped. Prefer the Sensitive form.
Result verify(const std::string& secret, const std::string& signature_header,
              const std::string& body, const Options& options = Options{});

/// Throwing twin of verify(), for handlers that prefer an exception.
/// @throws VerifyException — the message names the failure class only, never the
///         expected signature.
Event verify_or_throw(const Sensitive<std::string>& secret, const std::string& signature_header,
                      const std::string& body, const Options& options = Options{});

}  // namespace webhook
}  // namespace axiam
