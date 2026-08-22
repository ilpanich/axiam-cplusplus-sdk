// axiam Reactor — CONTRACT.md §22, the protocol core over a caller-supplied
// transport.
//
// WHAT THIS SHIPS, AND WHAT IT DOES NOT.
//
// §22.1–§22.8 and §22.14 in full: the §8 v2 verification set on the event, the
// canonical serialization and MAC in both directions, the §22.5 registry and its
// mutable-field allow-lists, §22.8's strictest-wins default, and the declarative
// binder. What it does NOT do is open a connection. §22.11 defers only the
// transport, because there is no maintained AMQP client for the targets this SDK
// serves that this project is willing to vendor.
//
// That split is deliberate and it is the newer one. Until contract 1.28 this SDK
// shipped nothing from §22 at all while the section still bound an integrator to
// §22.1–§22.8 — so the half deferred for want of a *dependency* was the
// transport, and the half left to hand-roll from prose was the **protocol**: v2
// HMAC over a canonical serialization with a `null` signature placeholder,
// freshness in both directions, nonce and correlation binding, the allow-lists.
// That is the half with the sharp edges, none of them AMQP-shaped, and asking
// every integrator to reimplement it is how a signing bug ships.
//
// THE TRANSPORT SEAM HAS EXACTLY TWO CAPABILITIES (§22.11 rule 1): take the next
// delivery, and publish a reply to a named destination. It is not wider than
// that on purpose — an interface that also exposed declare, bind or queue-name
// derivation would hand an integrator the tools §22.1 forbids using.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "axiam/sensitive.hpp"

namespace axiam {

// ---------------------------------------------------------------------------
// §22.5 — the event registry
//
// WHAT IS ABSENT IS LOAD-BEARING. §22.7 is a normative MUST NOT: the three
// hot-path decision operations are not hookable, and no SDK may present them as
// such. They are in no constant here and in no list here — §22.13 asserts on the
// constants, not on a comment. A reactor round trip is milliseconds; the check
// path's budget is microseconds. An application needing external input on an
// authorization decision writes a deny grant, which the engine evaluates in the
// hot path at hot-path cost.
// ---------------------------------------------------------------------------

inline constexpr const char* kReactorEventTokenPreIssue = "token.pre_issue";
inline constexpr const char* kReactorEventLoginPostAuth = "login.post_auth";
inline constexpr const char* kReactorEventUserPreCreate = "user.pre_create";
inline constexpr const char* kReactorEventUserPreUpdate = "user.pre_update";
inline constexpr const char* kReactorEventGrantPreAssign = "grant.pre_assign";

/// Every hookable event, in registry order. The complete list — an event absent
/// from it is not hookable, and that includes §22.7's three.
const std::vector<std::string>& reactor_event_names();

/// Whether `field` may appear in a patch for `event` (§22.5).
///
/// A registry entry ending in `.` names a NAMESPACE: `ext.` admits
/// `ext.department` and `ext.a.b.c`, and refuses `ext.` itself, `ext`, `extra`,
/// `external_id` (a prefix match on the string is not a match on the namespace)
/// and `evil.ext.department`.
///
/// This is a QUERY, not a filter. §22.4 rule 1 sends a patch unfiltered; nothing
/// in this SDK calls this to prune one.
bool reactor_patch_field_allowed(const std::string& event, const std::string& field);

/// §22.8's strictest-wins default, in either array order.
///
/// A reactor registered for both `token.pre_issue` (open) and `login.post_auth`
/// (closed) can veto a login, so it inherits `fail_closed`. Reducing this to
/// "take the first event's default" would let the order of a JSON array decide
/// whether an unreachable fraud check passes.
std::string reactor_default_failure_policy(const std::vector<std::string>& events);

/// §22.1 topology names. RENDERING THESE IS NOT DECLARING THEM: a reactor
/// consumes the queue the server declared and never declares or binds anything.
std::string reactor_routing_key(const std::string& tenant_id, const std::string& event);
std::string reactor_queue_name(const std::string& tenant_id, const std::string& reactor_id);

// ---------------------------------------------------------------------------
// §22.3 — the event, after verification
// ---------------------------------------------------------------------------

/// A delivery that passed every §22.3 check. A handler never sees anything else:
/// a runtime that hands unverified bytes to user code has already lost, because
/// the handler will act on them and "we checked afterwards" is not a check.
struct ReactorEvent {
    std::string tenant_id;
    std::string event;
    std::string correlation_id;
    /// The server's payload as JSON TEXT. Not a parsed model: this SDK's public
    /// headers carry no JSON type, and handing back the bytes keeps the handler
    /// free to use whatever parser it already has.
    ///
    /// `_reactor_patch`, when present, is the patch accumulated by earlier
    /// reactors in the chain — READ-ONLY context. Echoing it back inside your own
    /// patch is not how a field is preserved; the server merges (§22.6).
    std::string payload_json;
    /// The window the server will wait. §22.10 rule 4: work whose window has
    /// closed is abandoned rather than answered late.
    std::int64_t timeout_ms = 0;
    std::string nonce;
};

// ---------------------------------------------------------------------------
// §22.4 — the reply
// ---------------------------------------------------------------------------

/// One of the three answers, plus `require_mfa` as a flag on the allow answer.
///
/// There is deliberately no way to spell `allow` + `patch`: both allow
/// constructors take none (§22.4 rule 2), and a patch travels only on `mutate`.
class ReactorDecision {
public:
    static ReactorDecision allow();

    /// `allow` + `require_mfa: true` on `login.post_auth` means "proceed only
    /// after step-up". It is NOT a fourth decision value.
    ///
    /// On the federated paths (SAML ACS, OIDC callback) there is no step-up
    /// branch, so it FAILS the sign-in rather than being quietly dropped — answer
    /// deny there and drive enrolment out of band (§22.5).
    static ReactorDecision allow_with_step_up();

    /// A deny with no reason still denies; the server substitutes "denied by
    /// reactor". An empty reason is therefore OMITTED, not sent as `""` — the
    /// omission changes the canonical bytes and therefore the MAC.
    static ReactorDecision deny(std::string reason);

    /// §22.4 rule 1: a patch is sent UNFILTERED. One forbidden key rejects the
    /// WHOLE patch server-side, including the fields that would have been fine —
    /// and dropping the offender to rescue the rest would leave the author
    /// believing a field was set when it was dropped, which is exactly the
    /// failure the server refuses to produce.
    static ReactorDecision mutate(std::map<std::string, std::string> patch);

    const std::string& decision() const noexcept { return decision_; }
    const std::optional<std::string>& reason() const noexcept { return reason_; }
    const std::map<std::string, std::string>& patch() const noexcept { return patch_; }
    bool require_mfa() const noexcept { return require_mfa_; }

private:
    std::string decision_;
    std::optional<std::string> reason_;
    std::map<std::string, std::string> patch_;
    bool require_mfa_ = false;
};

/// A handler's answer, or ABSTENTION.
///
/// `std::nullopt` publishes no reply and lets the registration's
/// `failure_policy` resolve the event exactly as §22.8 resolves a timeout. It is
/// what §22.14 rule 4 requires of an unbound event, and it is expressible by a
/// plain handler too — a handler that cannot decide must be able to say so
/// rather than pick one of the three answers on the operator's behalf.
using ReactorAnswer = std::optional<ReactorDecision>;

/// One function from a verified event to one answer (§22.10). A plain
/// `ReactorDecision` converts implicitly, so a handler that always decides reads
/// exactly as it would without the optional.
using ReactorHandler = std::function<ReactorAnswer(const ReactorEvent&)>;

// ---------------------------------------------------------------------------
// §22.11 — the transport seam
// ---------------------------------------------------------------------------

/// One inbound message, as the broker hands it over.
struct ReactorDelivery {
    /// The raw message body. Verified by the runtime, never by the transport.
    std::string body;
    /// The `reply_to` basic property — where the reply is published.
    std::string reply_to;
    /// The `correlation_id` basic property.
    std::string correlation_id;
};

/// EXACTLY TWO CAPABILITIES (§22.11 rule 1). Deliberately not wider: an
/// interface that also exposed declare, bind or queue-name derivation would hand
/// the integrator the tools §22.1 forbids using.
class ReactorTransport {
public:
    virtual ~ReactorTransport() = default;

    /// The next delivery, or `std::nullopt` when the consumer is done — which is
    /// how reactor_serve() returns.
    virtual std::optional<ReactorDelivery> next_delivery() = 0;

    /// Publish a signed reply. `destination` is the delivery's `reply_to`.
    virtual void publish_reply(const std::string& destination,
                               const std::string& correlation_id,
                               const std::string& body) = 0;
};

// ---------------------------------------------------------------------------
// §22.10 — the runtime
// ---------------------------------------------------------------------------

struct ReactorConfig {
    /// The tenant this reactor is registered for. An event naming another tenant
    /// is refused after the MAC — identity is not cryptography, and spending it
    /// on unauthenticated bytes tells an unauthenticated party what this reactor
    /// accepts.
    std::string tenant_id;
    std::string reactor_id;
    /// The tenant's HKDF-derived AMQP subkey (§8.1) as RAW BYTES — the same key
    /// in both directions. §22.12 makes it a credential: it MUST NOT be logged at
    /// any level, and MUST NOT appear in a reconnect diagnostic.
    Sensitive<std::string> signing_key;

    /// Test seams. §22.13's sign-direction vectors pin an exact `issued_at` and
    /// `nonce`, and a runtime whose values are unreachable can only be tested
    /// through a reimplementation of the thing under test. Never set in
    /// production; both default to the real clock and a CSPRNG.
    std::function<std::int64_t()> clock;
    std::function<std::string()> nonce_source;
};

/// Consume, verify, dispatch, sign, publish — until the transport is done.
///
/// For each delivery, in this order (§22.3): refuse `key_version` below 2;
/// verify the MAC; check freshness in BOTH directions; check the nonce against a
/// seen-set held for this call's whole lifetime. Only then is the payload decoded
/// and the handler invoked.
///
/// Four rules from §22.10, all of them observable:
///
///  1. **It declares no topology.** Nothing here declares or binds anything; the
///     transport is not even given the vocabulary to.
///  2. **It fails closed on its own errors.** A handler that throws, or a body
///     the runtime cannot verify, produces NO REPLY — letting the server's
///     `failure_policy` decide. A runtime that answered `allow` for a handler
///     that crashed would have overridden the operator's `fail_closed` setting
///     from inside the library.
///  3. **It does not filter a patch** (§22.4 rule 1).
///  4. **It honours `timeout_ms`** by abandoning work whose window has closed
///     rather than replying late.
void reactor_serve(const ReactorConfig& config, ReactorTransport& transport,
                   const ReactorHandler& handler);

// ---------------------------------------------------------------------------
// §22.14 — declarative handler binding
// ---------------------------------------------------------------------------

/// Bind one handler per event and let the SDK compose them into the single
/// handler reactor_serve() takes.
///
/// §22.10's handler is ONE function from an event to one answer, which is the
/// right shape for the wire and the wrong shape for the code. A reactor
/// registered for three events opens with a dispatch on `event.event`, and that
/// dispatch is where two defects live. The first is cheap: a misspelled event
/// name compiles, binds nothing, and is discovered as an event that never fires.
/// The second is not — it is the catch-all arm that returns `allow` on behalf of
/// code that never ran, which is §22.10 rule 2's defect relocated into user code
/// where the rule does not reach it.
///
/// This is a BINDING TABLE rather than an attribute, for the same reason Go's is:
/// C++ has no metadata mechanism this SDK already uses, and inventing one to hand
/// out an attribute would cost more than it buys (§22.14).
///
/// PURE SUGAR. It opens no connection, consumes no queue, verifies no event,
/// signs no reply and interprets no `timeout_ms`; its output is exactly the
/// handler reactor_serve() accepts (rule 1).
class ReactorRouter {
public:
    /// Bind `handler` to `event`.
    ///
    /// @throws AuthError when `event` is not in the §22.5 registry — AT BIND
    ///         TIME, not at dispatch time. Failing when the binding is written is
    ///         the entire point: a typo that survives to production is discovered
    ///         as silence, and silence on a `fail_open` event is
    ///         indistinguishable from a healthy reactor with nothing to say.
    ///         This is also how §22.7's three hot-path operations are refused —
    ///         they are in no registry row, so they fail like any other unknown
    ///         name, and the message names the registry rather than naming what
    ///         is absent from it.
    /// @throws AuthError on a second binding for an already-bound event (rule 3).
    ///         Never a silent overwrite: which of two handlers runs is not
    ///         something the author of either can see from their own file.
    ReactorRouter& on(const std::string& event, ReactorHandler handler);

    /// An explicit fallback for unbound events.
    ///
    /// OPTIONAL, and it has no default (rule 4). Without one an unbound event
    /// ABSTAINS — no reply, and the registration's `failure_policy` resolves it.
    /// It is not answered `allow`, and not answered `deny` either: the binder does
    /// not know what the registration was for, and the operator's policy does.
    ReactorRouter& fallback(ReactorHandler handler);

    /// The bound event names, so a reactor author can compute §22.8's
    /// strictest-wins default from the code that actually handles the events
    /// rather than from a restatement of the registration.
    std::vector<std::string> bound_events() const;

    /// The composed handler. A handler's own failure propagates UNCHANGED
    /// (rule 5): nothing here catches an exception or converts one into an
    /// answer, because §22.10 rule 2 puts the fail-closed obligation on the
    /// runtime and a binder that swallowed a failure first would satisfy the
    /// letter of that rule while defeating it.
    ReactorHandler build() const;

private:
    std::vector<std::pair<std::string, ReactorHandler>> bindings_;
    ReactorHandler fallback_;
};

// ---------------------------------------------------------------------------
// §8b rules 1–5 — the broker URL guard
// ---------------------------------------------------------------------------

/// A validated broker endpoint: everything a caller needs to open an `amqps://`
/// connection, and nothing that could open a plaintext one.
struct AmqpsEndpoint {
    std::string url;   ///< The validated `amqps://` URL, unchanged.
    std::string host;
    int port = 5671;   ///< The broker TLS port, defaulted when the URL omits it.
    std::string virtual_host;  ///< `/` when the URL carries no path.
    std::string ca_pem;          ///< A privately-issued broker certificate's CA.
    std::string client_cert_pem;
    std::string client_key_pem;
};

/// Validate a broker URL and its TLS material against §8b rules 1–5.
///
/// §22.11 rule 3 is why this is a PUBLIC, TESTED FUNCTION rather than a
/// paragraph. Rule 7 of §8b cannot be satisfied by a runtime that never sees a
/// URL — this SDK bundles no AMQP client — so the SDK hands the integrator the
/// check instead. Documenting the requirement is precisely the failure contract
/// 1.23 was written to stop: three SDKs asserting `amqps://` in a doc comment
/// above a call that accepted anything.
///
/// What it enforces:
///
///  1. The scheme MUST be `amqps://`. Every other scheme is refused, `amqp://`
///     included, and there is **no loopback exception** (§8b rule 8): this
///     applies to `localhost`, `127.0.0.1` and `::1` exactly as to any other
///     host. §6's `http://localhost` dev carve-out does not extend here, and the
///     server has no plaintext listener for such an exception to reach.
///  2. A custom CA bundle is supported, because an in-cluster broker's
///     certificate is not issued by a public CA — this is the common case, and it
///     exists so nobody has a legitimate reason to want rule 4 relaxed.
///  3. A client certificate and its key are required TOGETHER. Half a client
///     identity fails closed rather than connecting without the mutual half.
///  4. There is no verification-skip option, under any name. It is the most
///     reliably misused option in TLS: it appears in a dev compose file, it
///     works, and it travels unchanged into production, where it turns TLS into
///     an expensive no-op against precisely the attacker TLS exists to stop.
///  5. There is no plaintext fallback. A failed `amqps://` connection is an error
///     to surface, not a condition to work around — and this function offers no
///     way to express one.
///
/// @throws AuthError on any refusal, naming the rule. An unparseable URL fails
///         closed: a URL this cannot read is not a URL it can vouch for.
AmqpsEndpoint amqps_endpoint(const std::string& url, std::string ca_pem = {},
                             std::string client_cert_pem = {}, std::string client_key_pem = {});

// ---------------------------------------------------------------------------
// §22.2 — the primitives, exposed because §22.13 tests them directly
// ---------------------------------------------------------------------------

/// Why a delivery was refused. A CATEGORY, never the MAC, the key or the payload.
enum class ReactorRefusal {
    kMalformed,
    kKeyVersionTooOld,
    kBadSignature,
    kStale,
    kReplay,
    kTenantMismatch,
    kUnknownEvent,
};

/// The outcome of §22.3's verification set.
struct ReactorVerification {
    bool ok = false;
    ReactorRefusal refusal = ReactorRefusal::kMalformed;
    ReactorEvent event;
};

/// Verify one delivery body against §22.3, in order: `key_version` before
/// anything else about the body is considered; then the MAC over the body with
/// `hmac_signature` set to **null**; then freshness in both directions; then the
/// nonce. Identity and registry membership come after the MAC.
///
/// `now` is Unix seconds. `seen_nonces` may be null to skip replay dedup — a real
/// reactor keeps one set for its whole lifetime, and building a fresh one per
/// delivery defeats the check entirely, which is why reactor_serve() owns one.
ReactorVerification reactor_verify_event(const Sensitive<std::string>& signing_key,
                                         const std::string& body,
                                         const std::string& expected_tenant, std::int64_t now,
                                         std::map<std::string, std::int64_t>* seen_nonces);

/// The reply as it goes on the wire: the canonical bytes with the `null`
/// placeholder replaced by the MAC computed over them.
///
/// WHAT EXACTLY IS SIGNED: the message serialized in its DECLARED FIELD ORDER,
/// with `hmac_signature` present and set to **null** — not omitted. That differs
/// from §8's own two message types, whose `hmac_signature` is absent from their
/// canonical bytes, and it is the single most likely place to produce a MAC that
/// will not verify.
///
/// @throws AuthError when `require_mfa` is set on any event other than
///         `login.post_auth` (§22.4 row 7), or when a `mutate` answer carries an
///         empty patch. Both are refusals rather than corrections: the result is
///         NO REPLY, and the registration's failure policy decides.
std::string reactor_build_reply(const Sensitive<std::string>& signing_key,
                                const std::string& correlation_id, const std::string& tenant_id,
                                const std::string& event, const ReactorDecision& decision,
                                const std::string& nonce, const std::string& issued_at);

/// The exact bytes reactor_build_reply() signs, before the MAC replaces the
/// placeholder. Exposed because §22.13's sign-direction vectors compare against
/// `canonical_signed_json` byte-for-byte.
std::string reactor_canonical_reply(const std::string& correlation_id,
                                    const std::string& tenant_id, const std::string& event,
                                    const ReactorDecision& decision, const std::string& nonce,
                                    const std::string& issued_at);

}  // namespace axiam
