// axiam WebAuthn / passkeys — CONTRACT.md §24.
//
// WHAT IS HERE, AND WHAT DELIBERATELY IS NOT.
//
// The six relying-party wire operations, plus §24.6a's JSON bridge. What is not
// here is §24.6b's linked-API ceremony helper: a C++ program has no
// authenticator on the targets this SDK serves — there is no platform API to
// link — and §24.6b rule 2 forbids emulating one in software, because a
// "credential" held in process memory is not a second factor.
//
// That is a statement about convenience, not about capability. §24.6a is the
// seam that makes it so: WebauthnChallenge::request_json() hands out the
// challenge in the exact JSON form every platform authenticator API takes, and
// every *_finish takes the platform's response JSON back as a string, byte for
// byte. An embedded gateway that fronts a browser, a native app talking to a C++
// service, or a test harness driving a virtual authenticator all use the same
// two seams.
//
// THE SERVER OWNS THE OPTIONS (§24.0). Nothing here defaults a field, validates
// one, or re-encodes a buffer. The challenge arrives as JSON text and leaves as
// JSON text; the authenticator's response is spliced into the request body
// without being parsed into a model and printed back out. A signed buffer that
// makes a round trip through a JSON model is a signed buffer that can come out
// different.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "axiam/sensitive.hpp"

namespace axiam {

/// A started ceremony: the server's options plus the token binding a response to
/// them (§24.1).
struct WebauthnChallenge {
    /// The server's options as JSON TEXT, exactly as they arrived — a
    /// `{"publicKey": {…}}` object carrying base64url buffers.
    ///
    /// Hand it to the authenticator unchanged (§24.0), or call request_json()
    /// for the string a platform API takes.
    std::string challenge_json;

    /// Binds the authenticator's answer to this challenge.
    ///
    /// A bearer credential for the length of the ceremony — one that leaks
    /// inside that window is a ceremony an attacker can try to complete — so it
    /// is wrapped (§24.5). It is OPAQUE: this SDK never decodes it, and neither
    /// should a caller.
    Sensitive<std::string> state_token;

    /// The challenge in the JSON form every platform authenticator API takes
    /// (§24.6a rule 1).
    ///
    /// This is the string a browser passes to
    /// `PublicKeyCredential.parseCreationOptionsFromJSON()` and an Android app
    /// passes to `CreatePublicKeyCredentialRequest`. It is the INNER options
    /// object: the `publicKey` wrapper belongs to the DOM's
    /// `CredentialCreationOptions`, and the platform JSON APIs do not want it.
    ///
    /// Pure local computation, no I/O. Nothing is defaulted, dropped or
    /// reordered on the way through (§24.0). A challenge that carries no
    /// `publicKey` wrapper is returned whole — a server that sent the bare
    /// options is not wrong for every consumer, and this call has one job.
    std::string request_json() const;
};

/// A credential the user just enrolled — the `201` body of register/finish.
struct WebauthnCredential {
    std::string id;               ///< This credential's AXIAM id, for a later delete.
    std::string credential_id;    ///< The authenticator's own base64url credential id.
    std::string name;             ///< The label it was stored under.
    std::string credential_type;  ///< "passkey" or "security_key".
    std::string created_at;       ///< RFC 3339 timestamp.
    /// RFC 3339 timestamp, or absent for a credential never used. Absent is not
    /// the empty string: one means "never", the other means "at the epoch".
    std::optional<std::string> last_used_at;
};

/// A completed authentication ceremony (§24.3).
///
/// The tokens are also adopted by the client that produced this value — the
/// server sets the axiam_access / axiam_refresh / axiam_csrf cookie triple
/// alongside them — so a caller who only wants to be signed in can drop it.
struct WebauthnLoginResult {
    Sensitive<std::string> access_token;   ///< §24.5.
    Sensitive<std::string> refresh_token;  ///< §24.5.
    std::string session_id;                ///< The session this ceremony established.
    std::int64_t expires_in = 0;           ///< Access-token TTL, seconds.
};

/// The workspace a usernameless ceremony runs in (§24.1).
///
/// `discoverable/start` is the one WebAuthn endpoint that carries the workspace
/// explicitly, because a usernameless ceremony has no prior step to have minted
/// a token that names it. Unlike the five `/oauth2` operations of §12.1 rule 2
/// it ACCEPTS SLUGS, so a slug-only client can run it.
///
/// Default-construct it (or pass none) to have it filled from the client's own
/// configured identity, which is what almost every caller wants.
struct WebauthnWorkspace {
    std::optional<std::string> org_id;
    std::optional<std::string> org_slug;
    std::optional<std::string> tenant_id;
    std::optional<std::string> tenant_slug;
};

/// A ceremony failure a caller can say something useful about (§24.6b rule 5).
///
/// This SDK ships no linked-API helper, but the classification is still required
/// of it: whatever DID run the ceremony — a browser, a phone — reports the
/// failure as one opaque type whose only machine-readable part is a name, and
/// translating that once beats translating it in every caller.
enum class WebauthnFailure {
    /// Covers BOTH an explicit refusal and a silent timeout.
    ///
    /// The WebAuthn spec deliberately refuses to distinguish them, because
    /// telling a website which one happened leaks whether an authenticator was
    /// present. It must not be recovered by timing the call, and user-facing
    /// copy must not accuse the user of cancelling.
    kCancelled,
    /// The authenticator already holds a credential for this account and refused
    /// to silently mint a second — the exclusion list working, not a failure.
    /// The only classification whose remedy is "use a different device".
    kAlreadyRegistered,
    /// An explicitly aborted ceremony.
    kTimeout,
    /// This device or browser cannot run the ceremony.
    kUnsupported,
    /// Everything else.
    kUnknown,
};

/// Map a platform ceremony error name to its canonical classification.
///
/// Anything unrecognised — including an empty string — is
/// WebauthnFailure::kUnknown rather than an error: a classifier that can fail is
/// one more thing for an error handler to handle, at the moment the caller
/// already has an error in hand. Case-insensitive, and tolerant of surrounding
/// whitespace.
WebauthnFailure webauthn_classify(const std::string& platform_error_name);

/// Copy for a failure, safe to show a user. Never empty.
///
/// The kCancelled string deliberately does not accuse anyone of cancelling: the
/// same classification covers a silent timeout, and the spec will not say which
/// happened.
std::string webauthn_failure_message(WebauthnFailure failure);

}  // namespace axiam
