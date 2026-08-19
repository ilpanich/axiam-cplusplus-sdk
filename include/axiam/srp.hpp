/// \file
/// Secure Remote Password (SRP-6a) — CONTRACT.md §23.
///
/// SRP is an *augmented PAKE*: the client proves knowledge of the password
/// without the password, or anything from which the password can be cheaply
/// recovered, ever crossing the wire. The server stores a verifier
/// `v = g^x mod N` instead of a password hash.
///
/// **What this closes, and what it does not** (§23.0). SRP defends against a
/// TLS-terminating proxy, an accidental request-body log, and a heap dump —
/// places a plaintext password exists today and would not under SRP. It does
/// **not** defend against a compromised AXIAM server.
///
/// **Conditional support** (§23.8). The arithmetic uses OpenSSL's
/// `BN_mod_exp`, always available. Argon2id arrives as an OpenSSL `EVP_KDF`
/// only in 3.2; PBKDF2-HMAC-SHA256 is available everywhere. A build linked
/// against an older libcrypto therefore cannot serve a tenant configured for
/// argon2id, and `Client::login_srp` reports that as a `NetworkError` naming
/// the KDF rather than deriving a wrong `x` and reporting a wrong password.
///
/// Everything in this header is pure arithmetic and performs no I/O. The login
/// flow that uses it is `Client::login_srp`.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace axiam {

/// The RFC 5054 Appendix A groups AXIAM speaks (§23.4).
///
/// These moduli are embedded as constants and a modulus is **never** accepted
/// from the server: a server-supplied `N` is a server-supplied trapdoor. The
/// §23.7 test suite asserts each one's width, primality and safe-primality,
/// because a transcription slip here is a silent, total break that a
/// client/server round-trip cannot catch — both sides would share the same
/// wrong constant.
struct SrpGroup {
    /// The name this group carries on the wire, e.g. `rfc5054_4096`.
    std::string wire_name;
    /// The modulus `N`, uppercase hex.
    std::string modulus_hex;
    /// The generator `g`.
    unsigned generator = 0;
    /// The modulus width in bytes — the width every hashed value is padded to.
    int byte_length = 0;

    /// The AXIAM default: it matches the RSA-4096 floor the project already
    /// sets for certificates.
    static constexpr const char* kDefaultWireName = "rfc5054_4096";

    /// Resolves a wire group name, refusing anything this SDK does not
    /// recognise rather than guessing (§23.4).
    ///
    /// \return The group, or `std::nullopt` for a name this SDK does not
    ///         implement. The caller reports that as a `NetworkError`, never an
    ///         `AuthError` — a client capability gap reported as a credential
    ///         failure would send a user to reset a working password.
    static std::optional<SrpGroup> from_wire(const std::string& wire_name);

    /// Every group this SDK implements, for tests that must assert all of them.
    static std::vector<SrpGroup> all();
};

/// The KDF and cost the server dictates for one exchange (§23.5).
///
/// §23.3 rule 4: these arrive per exchange and are honoured as given. They are
/// deliberately **not** cached across logins — a verifier enrolled under
/// different costs is still valid and has to keep working.
struct SrpKdfParams {
    /// `argon2id` or `pbkdf2_sha256`.
    std::string kdf;
    /// Argon2id's time cost, or PBKDF2's iteration count.
    unsigned iterations = 0;
    /// Argon2id's memory cost in KiB; ignored for PBKDF2.
    unsigned memory_kib = 0;
    /// Argon2id's lane count; ignored for PBKDF2.
    unsigned parallelism = 0;

    /// The wire name of the memory-hard KDF AXIAM asks for by default.
    static constexpr const char* kArgon2id = "argon2id";
    /// The wire name of the fallback for runtimes with no vetted Argon2.
    static constexpr const char* kPbkdf2Sha256 = "pbkdf2_sha256";

    /// This instance with any zero cost replaced by AXIAM's default for the
    /// chosen KDF.
    ///
    /// Used on the enrolment path, where the caller may know only which KDF the
    /// tenant runs. Never applied to a challenge response: a server that omits a
    /// cost it is required to send is a server this SDK should not be guessing
    /// on behalf of.
    SrpKdfParams with_defaults() const;
};

/// The `srp` object §23.5 defines: a verifier and the parameters it was
/// computed under.
///
/// The server cannot compute this — it never sees the plaintext — so any
/// request that **sets** a password has to carry it: `POST /api/v1/users`,
/// `/auth/password/change`, `/auth/reset/confirm` and `/admin/bootstrap`
/// (§23.3 rule 11).
///
/// Neither `salt` nor `verifier` may be logged (§23.3 rule 12).
struct SrpEnrollment {
    std::string group;      ///< The wire group name the verifier lives in.
    std::string kdf;        ///< The KDF used to derive `x`.
    unsigned memory_kib = 0;  ///< Argon2id's memory cost, or 0 for PBKDF2.
    unsigned iterations = 0;  ///< The KDF's iteration/time cost.
    unsigned parallelism = 0; ///< Argon2id's lane count, or 0 for PBKDF2.
    std::string salt;       ///< The 32-byte enrolment salt, lowercase hex.
    std::string verifier;   ///< `v = g^x mod N`, lowercase hex.
};

/// The two proofs an SRP exchange produces (§23.2).
///
/// `client_proof` goes on the verify request. `expected_server_proof` stays
/// here and is compared against the response's `server_proof`: that comparison
/// is the half of SRP that authenticates the *server*, and §23.3 rule 6 makes
/// it mandatory.
struct SrpProofs {
    std::string client_proof;
    std::string expected_server_proof;
};

/// SRP-6a protocol arithmetic. No I/O, no client state, no network.
///
/// `H` is **SHA-256** throughout. RFC 5054 specifies SHA-1; AXIAM does not use
/// SHA-1 anywhere and does not start here.
namespace srp {

/// Whether this build can perform SRP at all.
///
/// Unconditional here: `BN_mod_exp` and `PKCS5_PBKDF2_HMAC` are in every
/// OpenSSL this SDK links against. It exists because §23.1 puts the probe in
/// every SDK's vocabulary, and because a `true` here is **not** a promise that
/// every tenant will work — see \ref argon2_available.
bool available();

/// Whether this build can perform the Argon2id KDF (§23.8).
///
/// Argon2id arrives as an OpenSSL `EVP_KDF` in 3.2 and later. Against an older
/// libcrypto this returns `false`, and a tenant configured for `argon2id`
/// cannot be served — `Client::login_srp` reports a `NetworkError` naming the
/// KDF rather than substituting PBKDF2, which would derive a different `x` and
/// surface as a wrong password.
///
/// Fetched at runtime rather than read off a version macro, because a macro
/// answers for the headers this was *compiled* against rather than the
/// libcrypto it is *running* against, and those differ routinely where OpenSSL
/// is shared.
bool argon2_available();

/// `PAD(v)` — a hex value as exactly `byte_length` big-endian bytes
/// (§23.3 rule 1), returned as lowercase hex.
///
/// Skipping this is the classic SRP interop bug: two implementations agree
/// until a value happens to have a leading zero byte, and then roughly one
/// login in 256 fails in a way that reads as a flaky network.
///
/// \throws NetworkError if the value is wider than `byte_length` — a caller
///         error, not something to truncate, since dropping high bytes would
///         produce a wrong hash that still looked well-formed.
std::string pad_hex(const std::string& hex, int byte_length);

/// SHA-256 over the concatenation of `parts`, as lowercase hex.
std::string hash_hex(const std::vector<std::string>& parts);

/// Raw bytes as lowercase hex — the encoding every SRP field uses on the wire.
std::string to_hex(const std::string& bytes);

/// A lowercase-hex wire field as raw bytes.
///
/// Never truncates: a malformed field is refused, because silently dropping a
/// nibble would produce a wrong hash that still looked well-formed.
///
/// \param field The field's name, for the error message.
/// \throws NetworkError if `hex` is not valid hex.
std::string from_hex(const std::string& hex, const char* field);

/// `k = H(N | PAD(g))`, lowercase hex — depends only on the group.
std::string multiplier_hex(const SrpGroup& group);

/// `x = KDF(identity ":" password, salt)`, as raw bytes (§23.3 rule 3).
///
/// RFC 5054's bare-hash `x` would make a leaked verifier *cheaper* to attack
/// offline than the Argon2id hashes AXIAM stores today, which would make
/// adopting SRP a net regression at rest — so the KDF is memory-hard, and the
/// server dictates which one per exchange.
///
/// `identity` is the one the server named in the challenge, never what the
/// human typed (§23.3 rule 2).
///
/// \throws NetworkError if `params.kdf` is not one this build can perform.
std::string derive_x(const std::string& identity, const std::string& password,
                     const std::string& salt, const SrpKdfParams& params);

/// `v = g^x mod N`, lowercase hex — the verifier the server stores instead of a
/// password hash.
std::string compute_verifier(const SrpGroup& group, const std::string& x);

/// 32 fresh bytes from the platform CSPRNG, for an enrolment salt
/// (§23.3 rule 11).
///
/// A reused salt would make every verifier in a tenant equally attackable with
/// one precomputation.
std::string generate_salt();

/// Constant-time comparison of the server's `M2` against the expected one
/// (§23.3 rule 6).
bool verify_server_proof(const std::string& expected, const std::string& actual);

/// One exchange's client half: the ephemeral secret `a` held between the
/// challenge request and the proof that answers it (§23.2).
///
/// Single-use. `a` is drawn fresh per exchange by \ref begin and there is no way
/// to supply one there, because reusing it across logins leaks the relationship
/// between two session secrets (§23.3 rule 7).
class ClientSession {
public:
    /// Starts an exchange in `group`: draws a fresh `a` of at least 256 bits
    /// from the platform CSPRNG and computes `A`.
    static ClientSession begin(const SrpGroup& group);

    /// Starts an exchange with `a` pinned to a supplied value.
    ///
    /// For the §23.7 cross-language vectors **only**: they fix `a` so every
    /// intermediate is reproducible. Never call this from application code — a
    /// predictable `a` defeats the protocol.
    static ClientSession with_fixed_ephemeral(const SrpGroup& group,
                                              const std::string& ephemeral_hex);

    ~ClientSession();
    ClientSession(ClientSession&&) noexcept;
    ClientSession& operator=(ClientSession&&) noexcept;
    ClientSession(const ClientSession&) = delete;
    ClientSession& operator=(const ClientSession&) = delete;

    /// The group this exchange runs in.
    const SrpGroup& group() const noexcept { return group_; }

    /// `A = g^a mod N`, lowercase hex — sent with the challenge request.
    const std::string& client_public() const noexcept { return client_public_; }

    /// Completes the exchange: `S`, `K`, `M1` and the `M2` the server must
    /// return.
    ///
    /// \param identity The identity from the challenge response, never what the
    ///                 user typed (§23.3 rule 2).
    /// \param salt_hex The `salt` field of the challenge response.
    /// \param server_public_hex The `b_pub` field of the challenge response.
    /// \param x The KDF output from \ref derive_x.
    /// \throws NetworkError if `B mod N == 0`, if `u` would be zero, or if a hex
    ///         field is malformed.
    SrpProofs finish(const std::string& identity, const std::string& salt_hex,
                     const std::string& server_public_hex, const std::string& x) const;

private:
    ClientSession(SrpGroup group, std::string ephemeral_hex);

    SrpGroup group_;
    /// Held as hex rather than a BIGNUM so this header carries no OpenSSL
    /// types; it is wiped in the destructor.
    std::string ephemeral_hex_;
    std::string client_public_;
};

}  // namespace srp
}  // namespace axiam
