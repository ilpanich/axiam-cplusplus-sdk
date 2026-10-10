// axiam telemetry hooks — CONTRACT.md §19.
//
// An optional callback surface so a caller can wire OpenTelemetry, Prometheus
// or a log line WITHOUT this library depending on any of them. Install one with
// `Client::Builder::telemetry_hook`; with none installed the cost is a single
// empty-std::function check per request.
//
// Two of §19.2's rules are enforced by the shape of this header rather than left
// to documentation:
//
//   * No secrets, ever (rule 3). `TelemetryEvent` is a `std::variant` over the
//     six structs below, each with a fixed member list and no map. The variant
//     is closed by construction — a caller cannot add a seventh alternative — so
//     "there is nowhere to put a token in a payload bound for a metrics backend"
//     is checkable by reading one declaration rather than trusting a review.
//   * No cost when uninstalled (rule 1). Nothing here allocates; building an
//     event is a handful of string copies taken only when a hook exists.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <variant>

namespace axiam {

/// Why a request finished.
enum class Outcome {
    /// The call returned a usable response.
    kSuccess,
    /// The call failed, at any layer.
    kFailure,
};

/// Whether this caller performed a §9 refresh or waited on another thread's.
enum class RefreshRole {
    /// This caller performed the refresh.
    kLeader,
    /// This caller waited on another thread's refresh.
    kFollower,
};

/// Emitted before an outbound call leaves the SDK.
struct RequestStartEvent {
    /// Canonical operation name, e.g. `check_access`.
    std::string operation;
    /// HTTP method.
    std::string method;
    /// The route CONSTANT — `/api/v1/authz/check`, never a URL with ids
    /// substituted in. A metric label carrying a UUID is a cardinality bomb.
    std::string path_template;
    /// 1 for the first try, incrementing per §16 retry.
    int attempt = 1;
};

/// Emitted after a call completes, success or failure.
struct RequestEndEvent {
    std::string operation;
    std::string method;
    std::string path_template;
    int attempt = 1;
    /// HTTP status, or `std::nullopt` when the call never got a response.
    std::optional<long> status;
    /// Wall-clock time this attempt took.
    std::chrono::milliseconds duration{0};
    Outcome outcome = Outcome::kSuccess;
};

/// Emitted before each §16 retry wait.
///
/// §16.5 requires this: a retried-then-succeeded operation is otherwise
/// invisible — the caller sees a slow success and no signal that the server is
/// failing. That silence is the standing objection to automatic retry.
struct RetryEvent {
    std::string operation;
    /// The attempt that just failed.
    int attempt = 1;
    /// The wait about to be taken, after jitter and any `Retry-After`.
    std::chrono::milliseconds delay{0};
    /// A redacted description of the failure. Carries a status or a transport
    /// category, never a token.
    std::string reason;
};

/// Emitted around a §9 single-flight refresh.
struct RefreshEvent {
    RefreshRole role = RefreshRole::kLeader;
    std::chrono::milliseconds duration{0};
};

/// Emitted at client construction, once per caller-supplied setting the SDK
/// clamped (§19.1, §19.2 rule 6).
///
/// Clamping rather than rejecting is the right call — rejecting would fail
/// construction for a caller whose configuration was merely optimistic, and
/// honoring would let one client become the herd §16 exists to prevent. Doing it
/// SILENTLY is the part that is wrong: an operator who set a 60-second memo TTL
/// believes their staleness bound is 60 seconds. It is five, and their
/// revocation reasoning is off by a factor of twelve with nothing anywhere to
/// say so.
///
/// It is NOT emitted for a value already within its limit: an event that fires
/// when nothing happened trains its reader to ignore it.
struct ConfigClampedEvent {
    /// The builder setting's name, e.g. `decision_memo_ttl`.
    std::string setting;
    /// The value the caller asked for, rendered.
    std::string requested;
    /// The value actually in force, rendered.
    std::string effective;
    /// The §-reference for the limit, e.g. `§17.1 rule 2`.
    std::string contract_reference;
};

/// Emitted when `ssf::SsfReceiver::poll` (§32.7) returns normally leaving at
/// least one SET unjudged (§19.1, contract 1.60 SHOULD; §34.2 P1).
///
/// An unjudged SET is not an error the caller sees: poll() returns, and the
/// transmitter offers the SET again. Without this event a JWKS or replay-store
/// outage is invisible until the backlog grows. Counts only: no `jti`, no SET.
/// One event per failure category present in the batch.
struct SsfUnjudgedEvent {
    /// The operation name, `ssf.poll`.
    std::string operation;
    /// How many SETs of the batch this category left unjudged.
    std::size_t unjudged = 0;
    /// What left them unjudged: `key_fetch` (a JWKS or discovery fetch that
    /// failed or is held off for the minute) or `replay_store` (a store that
    /// could not answer, and the SETs after it that were not put to it).
    std::string category;
};

/// One §19.1 event.
///
/// A closed `std::variant` rather than a class hierarchy: no code outside this
/// header can add an alternative, which is what makes the "no field can carry a
/// secret" guarantee above hold by construction. Dispatch with `std::visit` or
/// `std::holds_alternative`.
using TelemetryEvent = std::variant<RequestStartEvent, RequestEndEvent, RetryEvent, RefreshEvent,
                                    ConfigClampedEvent, SsfUnjudgedEvent>;

/// A caller-supplied telemetry sink (§19).
///
/// Invoked on the calling thread, inside the operation that produced the event,
/// so it must not block (§19.2 rule 4). Buffering is the caller's job so they can
/// pick the policy; every mature metrics library already buffers.
///
/// A hook that throws cannot fail the operation that fired it (§19.2 rule 2) —
/// the dispatcher swallows it. That is a backstop, not a licence.
using TelemetryHook = std::function<void(const TelemetryEvent&)>;

}  // namespace axiam
