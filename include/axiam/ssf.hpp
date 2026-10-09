// §32.7 The SSF receiver helper — verify a Security Event Token, and poll.
//
// AXIAM is a Shared Signals Framework transmitter (CONTRACT.md §32): it sends
// CAEP and RISC security events as Security Event Tokens (RFC 8417) to the
// relying parties a tenant administrator registered with the §27 `ssf`
// namespace. This header is for the RELYING PARTY that receives them — a
// different audience from that namespace:
//
//  * SsfReceiver::verify_set() verifies one compact SET, pushed to your endpoint
//    (RFC 8935) or returned by a poll, in the contract's fixed order, and refuses
//    at the first failure with a SetVerificationError naming the step.
//  * SsfReceiver::poll() calls the stream's RFC 8936 poll endpoint, verifies
//    every SET it returns and hands back the verified and the refused apart.
//
// Neither transmits, signs or registers anything, and neither trusts a key it
// did not fetch from the configured JWKS: no `jwk` or `x5c` header member is
// ever honoured (§32.9).
#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "axiam/errors.hpp"
#include "axiam/sensitive.hpp"

namespace axiam {

class Client;

namespace ssf {

/// The six event types AXIAM transmits, plus the two SSF stream events (§32.6).
///
/// Event types are OPEN: a SET whose type is not among these still verifies,
/// and SecurityEvent::event_type carries it verbatim.
namespace event_types {
inline constexpr const char* kSessionRevoked =
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
inline constexpr const char* kCredentialChange =
    "https://schemas.openid.net/secevent/caep/event-type/credential-change";
inline constexpr const char* kAssuranceLevelChange =
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
inline constexpr const char* kAccountDisabled =
    "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
inline constexpr const char* kAccountEnabled =
    "https://schemas.openid.net/secevent/risc/event-type/account-enabled";
inline constexpr const char* kAccountPurged =
    "https://schemas.openid.net/secevent/risc/event-type/account-purged";
inline constexpr const char* kVerification =
    "https://schemas.openid.net/secevent/ssf/event-type/verification";
inline constexpr const char* kStreamUpdated =
    "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";
}  // namespace event_types

/// The replay window's default AND floor: seven days, the transmitter's buffer
/// retention (§32.6). A shorter window would forget a `jti` the transmitter can
/// still re-send, so one is refused at construction rather than shortened.
inline constexpr std::chrono::seconds kMinReplayWindow{7 * 24 * 60 * 60};

/// Why verify_set() refused a SET — the step that failed (§32.7).
enum class SetFailureReason {
    kMalformed,        ///< step 1: not three base64url parts, or not JSON objects
    kInvalidType,      ///< step 2: `typ` is not `secevent+jwt`
    kInvalidKey,       ///< steps 3–5: `alg`, `kid` or the signature
    kInvalidIssuer,    ///< step 6
    kInvalidAudience,  ///< step 7
    kInvalidRequest,   ///< step 8: the claim set is not a SET's
    kReplayed,         ///< step 9: the `jti` was already accepted
};

/// The reason code as §32.7 spells it: `malformed`, `invalid_type`, …
const char* reason_code(SetFailureReason reason) noexcept;

/// The RFC 8935 §2.4 `err` to answer a push with (or to pass in a poll's
/// `setErrs`). The reason itself for `invalid_key`, `invalid_issuer`,
/// `invalid_audience` and `invalid_request`; **`invalid_request` for
/// `malformed`, `invalid_type` and `replayed`**, which RFC 8935 does not define.
const char* push_error_code(SetFailureReason reason) noexcept;

/// A SET refused by verify_set() (§32.7). An AuthError, as §32.7 requires.
///
/// The message names the step, never a claim value or the token.
class SetVerificationError : public AuthError {
public:
    SetVerificationError(const std::string& message, SetFailureReason reason)
        : AuthError(message), reason_(reason) {}

    SetFailureReason reason() const noexcept { return reason_; }
    const char* reason_code() const noexcept { return ssf::reason_code(reason_); }
    const char* push_error_code() const noexcept { return ssf::push_error_code(reason_); }

private:
    SetFailureReason reason_;
};

/// One RFC 8936 `setErrs` entry.
struct SetErr {
    std::string err;                         ///< an RFC 8935 §2.4 code
    std::optional<std::string> description;  ///< AXIAM never stores it (§32.6)

    /// The entry for a refusal: its push_error_code().
    static SetErr from_reason(SetFailureReason reason);
};

/// Remembers the `jti`s already accepted, for step 9. Pluggable so a receiver
/// running several instances can share one store.
class ReplayStore {
public:
    virtual ~ReplayStore() = default;
    /// Record `jti` for `window` and return true, or return false WITHOUT
    /// recording when it is already held. Must be atomic: two concurrent calls
    /// with one `jti` must not both see true. When the store cannot answer,
    /// THROW, having recorded nothing: verify_set() then fails closed, and
    /// poll() leaves the SET unjudged (contract 1.59, §34.2 P1, P4).
    virtual bool check_and_record(const std::string& jti, std::chrono::seconds window) = 0;
};

/// The default ReplayStore: one process, lost on restart; expired entries are
/// dropped as new ones arrive. Bounded in time by the replay window and
/// unbounded in count (§34.2 P4).
class MemoryReplayStore final : public ReplayStore {
public:
    bool check_and_record(const std::string& jti, std::chrono::seconds window) override;

private:
    std::mutex mtx_;
    std::map<std::string, std::chrono::steady_clock::time_point> seen_;
};

/// Where the transmitter's signing keys come from.
struct SsfKeySource {
    enum class Kind { kJwksUri, kDiscoveryUrl };
    Kind kind = Kind::kJwksUri;
    std::string url;

    /// The JWKS URL itself (AXIAM: `{issuer}/oauth2/jwks`).
    static SsfKeySource jwks_uri(std::string url) { return {Kind::kJwksUri, std::move(url)}; }
    /// The transmitter's SSF configuration document
    /// (`/.well-known/ssf-configuration…`): its `jwks_uri` is used, and its
    /// `issuer` must equal the configured one.
    static SsfKeySource discovery_url(std::string url) {
        return {Kind::kDiscoveryUrl, std::move(url)};
    }
};

/// Supplies the bearer poll() presents: a client-credentials access token
/// carrying `ssf.manage` (for example from Client::login_client_credentials()).
/// Called once per poll; throw to abort it.
using AccessTokenProvider = std::function<Sensitive<std::string>()>;

/// §32.7's `{ issuer, audience, jwks_uri | discovery_url, access_token_provider }`.
struct SsfReceiverConfig {
    std::string issuer;    ///< compared to `iss` exactly
    std::string audience;  ///< this receiver's audience — the stream's `audience`
    SsfKeySource keys;
    /// Only poll() needs it; a push-only receiver leaves it empty.
    AccessTokenProvider access_token_provider;
    /// How long a `jti` is remembered. At least kMinReplayWindow.
    std::chrono::seconds replay_window = kMinReplayWindow;
    /// Where accepted `jti`s are kept; empty uses a MemoryReplayStore.
    std::shared_ptr<ReplayStore> replay_store;
};

/// A verified Security Event Token (§32.7's result).
///
/// The three JSON members are raw JSON text, the same stand-in this SDK uses
/// for every open map (IdTokenClaims::raw_claims_json): the vendored JSON
/// library is not part of the installed API.
struct SecurityEvent {
    std::string jti;
    std::int64_t iat = 0;
    std::string iss;
    std::string aud_json;  ///< the audience as sent: a JSON string, or an array containing yours
    std::optional<std::string> txn;
    std::string event_type;   ///< the single `events` key, e.g. event_types::kSessionRevoked
    std::string event_json;   ///< that event's object, opaque to the helper
    std::string sub_id_json;  ///< the RFC 9493 subject identifier, opaque to the helper
};

/// A SET a poll returned and the helper refused.
struct RefusedSet {
    std::string jti;  ///< the key the transmitter returned it under
    SetFailureReason reason;
};

/// poll()'s arguments. Every member is passed through as given, and an unset
/// one is not sent.
struct SsfPollOptions {
    /// `maxEvents` — the server clamps it to 100; 0 acknowledges and returns nothing.
    std::optional<std::int64_t> max_events;
    /// `returnImmediately` — without it the server long-polls up to 30 s.
    std::optional<bool> return_immediately;
    /// `ack` — the `jti`s you PROCESSED since the last poll.
    std::optional<std::vector<std::string>> ack;
    /// `setErrs` — the `jti`s you refuse, each with its code (SetErr::from_reason).
    std::optional<std::map<std::string, SetErr>> set_errs;
};

/// A SET a poll returned that the helper could not judge: its key fetch, the
/// discovery document or the replay store failed, which is no verdict on the
/// SET (contract 1.59, §34.2 P1 and P3). Its `jti` is NOT recorded.
struct UnjudgedSet {
    std::string jti;    ///< the key the transmitter returned it under
    std::string error;  ///< what failed (the exception's message), for a log line
};

/// What poll() returns.
struct SsfPollResult {
    std::vector<SecurityEvent> events;  ///< the SETs that verified
    bool more_available = false;        ///< the transmitter holds more
    std::vector<RefusedSet> refused;    ///< the SETs that did not
    /// The SETs neither verified nor refused (§34.2 P1). Neither acknowledge them
    /// nor pass them in `set_errs`: left alone, the transmitter offers them again
    /// and the next poll judges them.
    std::vector<UnjudgedSet> unjudged;
};

/// The receiver helper (§32.7).
///
/// Copies share one state — the key cache and the replay store — so a copy
/// handed to another thread refuses a replay the original accepted.
class SsfReceiver {
public:
    /// A receiver over `client`'s transport: its §6 TLS policy fetches the JWKS,
    /// and its base URL is the transmitter root poll() calls. Neither request
    /// carries the client's session.
    ///
    /// @throws std::invalid_argument (C++'s local ValidationError mapping,
    ///         CONTRACT.md §28.7) when `replay_window` is below
    ///         kMinReplayWindow, `issuer`, `audience` or the key URL is empty, or
    ///         the key URL is not https (http only on a loopback host).
    SsfReceiver(const Client& client, SsfReceiverConfig config);

    /// Verify one compact SET, in this order, refusing at the first failure with
    /// the reason in brackets:
    ///
    ///  1. three base64url parts, a JSON object header and payload [malformed];
    ///  2. `typ` `secevent+jwt` or `application/secevent+jwt`, any case [invalid_type];
    ///  3. `alg` exactly `EdDSA` [invalid_key];
    ///  4. the `kid` in the configured JWKS — on a miss, ONE refetch, at most once
    ///     a minute [invalid_key]. A FAILED fetch, the one that fills an empty
    ///     cache included, also waits out the minute: until it has passed, a SET
    ///     needing that fetch raises NetworkError without a request (contract
    ///     1.59, §34.2 P6), so a JWKS outage is not one fetch per SET;
    ///  5. the Ed25519 signature [invalid_key];
    ///  6. `iss` equal to the configured issuer [invalid_issuer];
    ///  7. `aud` equal to, or an array containing, the audience [invalid_audience];
    ///  8. no `exp`, no `sub`; a non-empty `jti`, a numeric `iat`, an object
    ///     `sub_id`; `events` with exactly one member [invalid_request];
    ///  9. a `jti` not seen within the replay window [replayed] — recorded only
    ///     once steps 1–8 passed.
    ///
    /// **A SET that verifies has been recorded**: verifying it again is
    /// `replayed`. Acknowledge a polled SET once you have processed it.
    ///
    /// @throws SetVerificationError for a refused SET.
    /// @throws NetworkError when the JWKS (or the discovery document) could not
    ///         be fetched — which is not a verdict on the SET.
    SecurityEvent verify_set(const std::string& set);

    /// Poll the stream's RFC 8936 endpoint, `{base_url}/ssf/v1/poll/{stream_id}`,
    /// with a bearer from the configured access_token_provider.
    ///
    /// `ack` and `set_errs` are sent exactly as given. **Nothing is acknowledged
    /// on your behalf**: acknowledge, on the next call, the `jti`s you processed,
    /// and pass each refused one in `set_errs`. A SET you neither acknowledge nor
    /// refuse is re-offered and — recorded when it verified — then reads as
    /// `replayed`.
    ///
    /// Retried per §16 on a transport failure, 408, 429 or 5xx; never on another
    /// 4xx, which maps as on the management surface (400 ValidationError, 404
    /// NotFoundError, 409 ConflictError, else §2).
    ///
    /// **poll never keeps a `jti` it does not return** (contract 1.59, §34.2 P1,
    /// the second of its two forms). A failure that is not a verdict on a SET —
    /// the JWKS or discovery fetch, a replay store that cannot answer — leaves
    /// that SET in SsfPollResult::unjudged, in neither `events` nor `refused`,
    /// with its `jti` unrecorded; the rest of the batch is still judged and
    /// returned. Do not acknowledge an unjudged SET: the transmitter offers it
    /// again.
    ///
    /// @throws AuthError, with no request sent, when no access_token_provider is set.
    SsfPollResult poll(const std::string& stream_id, const SsfPollOptions& options = {});

    /// TEST SEAM — the monotonic clock the once-a-minute JWKS fetch limit reads
    /// (§32.7 step 4), so a test can step past the minute without sleeping.
    /// NEVER called in production; nothing in src/ writes it.
    void _set_clock_for_testing(std::function<std::chrono::steady_clock::time_point()> now);

    struct State;

private:
    std::shared_ptr<State> state_;
};

}  // namespace ssf
}  // namespace axiam
