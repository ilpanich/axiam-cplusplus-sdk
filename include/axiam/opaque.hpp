/// \file
/// OPAQUE (RFC 9807) — CONTRACT.md §23.
///
/// OPAQUE is an *augmented PAKE*: the client proves knowledge of the password
/// without the password, or anything from which the password can be cheaply
/// recovered, ever crossing the wire. The server stores a registration record
/// sealed under a tenant-scoped oblivious PRF instead of a password hash.
///
/// **What this closes, and what it does not** (§23.0). OPAQUE defends against a
/// TLS-terminating proxy, an accidental request-body log, and a heap dump —
/// places a plaintext password exists today and would not under OPAQUE. It also
/// does what the SRP-6a it replaces could not: a stolen record database is not
/// offline-crackable on its own, because grinding candidates needs the tenant's
/// OPRF seed as well as the records. That property is pre-computation
/// resistance. It does **not** defend against a compromised AXIAM server.
///
/// **This SDK does not implement OPAQUE** (§23.1), and that is the design
/// rather than a gap. OPAQUE needs an oblivious PRF, `hash_to_curve`,
/// `expand_message_xmd`, an envelope construction and a three-message
/// authenticated key exchange; eleven independent implementations of that is
/// eleven chances to be subtly and silently wrong, in a way test vectors do not
/// catch because a wrong answer is still a well-formed group element. What
/// lives here is a binding to `libaxiam_opaque_ffi`, the C ABI of the same
/// audited core the AXIAM server links.
///
/// That library is a per-platform release asset, resolved with `dlopen` at run
/// time rather than linked. A consumer who never uses OPAQUE therefore needs
/// nothing extra, and \ref axiam::opaque::available can honestly answer
/// `false`. Install the library where the dynamic loader looks, or set
/// `AXIAM_OPAQUE_LIBRARY` to its full path.
///
/// **The conditional support this replaces is gone.** The SRP client needed
/// OpenSSL >= 3.2 for Argon2id, so a build against an older libcrypto could not
/// serve a tenant on AXIAM's default KDF. Key stretching now happens inside
/// `libaxiam_opaque_ffi`, so the OpenSSL version no longer decides which
/// tenants work — and unlike `srp::available()`, a `true` from
/// \ref axiam::opaque::available **is** a promise that every tenant will work.
#pragma once

#include <memory>
#include <optional>
#include <string>

namespace axiam {

/// The key-stretching function and cost a `*/start` response names (§23.4).
///
/// Every cost is an `optional` rather than a zero-defaulted `unsigned`, and
/// that is load-bearing. A field that does not apply to the named function is
/// **absent** on the wire, not zero (§23.4 rule 5), and reading a missing
/// `memory_kib` as `0` would stretch at the wrong cost and fail against a
/// record that is perfectly good.
///
/// These arrive per exchange and are honoured as given. They are deliberately
/// **not** cached across logins and never defaulted locally (§23.4 rule 2): a
/// credential enrolled under one cost keeps working after a tenant raises its
/// policy, so a client that guessed would derive a different randomized
/// password and report "invalid password" for one that is entirely correct.
struct OpaqueKsfParams {
    /// `argon2id` or `scrypt`.
    std::string ksf;
    std::optional<unsigned> memory_kib;   ///< Argon2id's memory cost in KiB.
    std::optional<unsigned> iterations;   ///< Argon2id's time cost.
    std::optional<unsigned> parallelism;  ///< Argon2id's lane count.
    std::optional<unsigned> log_n;        ///< scrypt's base-2 CPU/memory cost.
    std::optional<unsigned> r;            ///< scrypt's block size.
    std::optional<unsigned> p;            ///< scrypt's parallelisation parameter.

    /// The wire name of the memory-hard function AXIAM asks for by default.
    static constexpr const char* kArgon2id = "argon2id";
    /// The wire name of the alternative AXIAM accepts.
    static constexpr const char* kScrypt = "scrypt";
};

/// The `opaque` object §23.5 defines: a registration record and the
/// server-issued handle identifying the exchange it came from.
///
/// The server cannot build this — it never sees the plaintext — so any request
/// that **sets** a password has to carry it: `POST /api/v1/users`,
/// `/auth/password/change`, `/auth/reset/confirm` and `/admin/bootstrap`.
///
/// Note what is **not** here. The SRP enrolment this replaces carried a salt, a
/// group and a full set of KDF costs, and required the account's canonical
/// **username** — an email there produced a verifier no login could ever
/// satisfy, and renaming a user invalidated their verifier outright. A record
/// binds to a credential identifier the server chooses, and the key-stretching
/// parameters are the server's, so there is nothing here a caller can get
/// wrong.
///
/// `registration_record` is credential material and may not be logged.
struct OpaqueEnrollment {
    std::string opaque_session;       ///< The handle `register/start` issued.
    std::string registration_record;  ///< The hex `RegistrationRecord`.
};

/// The binding to `libaxiam_opaque_ffi`. No cryptography lives in this
/// namespace, or anywhere in this SDK (§23.1).
namespace opaque {

/// The `libaxiam_opaque_ffi` C ABI, expressed in C++ terms.
///
/// An interface rather than the `dlsym` calls themselves, for one reason: it is
/// what a test can implement. There is no cryptography here to test — what
/// there is, and what a fake can exercise exhaustively, is the layer above:
/// single-use exchanges, the key-stretching function the *server* named being
/// the one used, and which failure means what.
///
/// The methods take and return `std::string`s rather than `char*`s. Pointer
/// ownership — who frees a returned string, when a state handle is spent — is
/// real but is entirely the dynamic implementation's, because it is the only
/// one that has pointers at all. That keeps the part needing the real shared
/// library as small as it can be.
///
/// A `std::nullopt` return always means the library refused; \ref last_error
/// says why.
class Native {
public:
    /// An opaque handle the library owns. This SDK only ever passes it back.
    using Handle = void*;

    virtual ~Native() = default;

    /// Whether this build can perform OPAQUE.
    virtual bool available() const = 0;

    /// The library's description of the last failure, or an empty string.
    virtual std::string last_error() const = 0;

    /// Builds an Argon2id key-stretching handle, or `nullptr` when refused.
    virtual Handle ksf_argon2id(unsigned memory_kib, unsigned iterations,
                                unsigned parallelism) = 0;

    /// Builds a scrypt key-stretching handle, or `nullptr` when refused.
    virtual Handle ksf_scrypt(unsigned char log_n, unsigned r, unsigned p) = 0;

    /// Releases a key-stretching handle.
    virtual void ksf_free(Handle ksf) = 0;

    /// Begins an enrolment. On success `out_request` is the hex
    /// `RegistrationRequest`.
    virtual Handle registration_start(const std::string& password,
                                      std::string& out_request) = 0;

    /// Completes an enrolment, **consuming** `state` whether it succeeds or
    /// fails.
    virtual std::optional<std::string> registration_finish(
        Handle state, const std::string& password,
        const std::string& registration_response, Handle ksf) = 0;

    /// Releases enrolment state that was never finished.
    virtual void registration_free(Handle state) = 0;

    /// Begins a login. On success `out_ke1` is the hex `KE1`.
    virtual Handle login_start(const std::string& password, std::string& out_ke1) = 0;

    /// Completes a login, **consuming** `state`.
    ///
    /// A `std::nullopt` return is the whole of the client's authentication
    /// check, and it covers both halves of the mutual authentication: the
    /// envelope only opens under the right password, and `KE2`'s MAC only
    /// verifies if the server actually holds the record. Per §23.4 rule 7
    /// nothing may be sent to `login/finish` after it.
    virtual std::optional<std::string> login_finish(Handle state,
                                                    const std::string& password,
                                                    const std::string& ke2,
                                                    Handle ksf) = 0;

    /// Releases login state that was never finished.
    virtual void login_free(Handle state) = 0;
};

/// Whether this installation can perform OPAQUE (§23.2).
///
/// Reports rather than throwing, so an application chooses the password path up
/// front instead of discovering the gap mid-login. Genuinely able to answer
/// `false` — and unlike `srp::available()`, which was effectively hard-coded to
/// `true` while an `argon2id` tenant still failed at login, a `true` here **is**
/// a promise that every tenant will work.
bool available();

/// The environment variable naming the full path to `libaxiam_opaque_ffi`.
///
/// Checked before the platform's own search path, which is the normal case for
/// a container image that ships the artifact alongside the application rather
/// than installing it system-wide.
constexpr const char* kLibraryPathEnv = "AXIAM_OPAQUE_LIBRARY";

/// The loaded library, or `nullptr` when it is absent.
///
/// Memoized, failure included: retrying `dlopen` on every login is a
/// per-request filesystem walk for a file that is not going to appear.
Native* native();

/// Installs a binding, bypassing the loader. Test-only.
void set_native_for_tests(Native* native);

/// Forgets the memoized load. Test-only.
void reset_native_for_tests();

/// A key-stretching handle, released when it goes out of scope.
///
/// Move-only: two owners would mean two `ksf_free`s.
class KsfHandle {
public:
    KsfHandle() = default;
    KsfHandle(Native& lib, Native::Handle handle) noexcept;
    ~KsfHandle();
    KsfHandle(KsfHandle&& other) noexcept;
    KsfHandle& operator=(KsfHandle&& other) noexcept;
    KsfHandle(const KsfHandle&) = delete;
    KsfHandle& operator=(const KsfHandle&) = delete;

    Native::Handle get() const noexcept { return handle_; }

private:
    Native* lib_ = nullptr;
    Native::Handle handle_ = nullptr;
};

/// Builds the library's key-stretching handle from what the *server* named.
///
/// An unrecognised function is refused, never substituted: substituting
/// produces a well-formed randomized password no AXIAM server agrees with,
/// which surfaces to the user as a wrong password (§23.4 rule 3).
///
/// Costs are additionally range-checked here, so a refusal names the field. A
/// server is trusted to name its own policy, not to name a cost that would
/// wedge every device an account owns; the library range-checks too.
///
/// \throws NetworkError for an unrecognised function, a cost the named function
///         needs but the server omitted, or a cost outside the accepted band.
KsfHandle build_ksf(Native& lib, const OpaqueKsfParams& params);

/// One in-flight exchange, owning a native state handle.
///
/// The handle is **single-use**: the library consumes it in `finish` whether
/// that succeeds or fails. This class takes it out of a one-shot slot, so a
/// second `finish` throws rather than handing a dangling pointer across the
/// ABI.
///
/// The destructor releases an exchange the caller abandoned — a login started
/// and never completed. Which release to call is decided by a flag set at
/// construction rather than by a virtual, because a destructor cannot dispatch
/// into a subclass whose own storage has already been torn down.
class Exchange {
public:
    ~Exchange();
    Exchange(Exchange&& other) noexcept;
    Exchange& operator=(Exchange&& other) noexcept;
    Exchange(const Exchange&) = delete;
    Exchange& operator=(const Exchange&) = delete;

    /// Releases the exchange if it was never finished.
    ///
    /// Idempotent, and a no-op once `finish` has spent the handle. Calling it
    /// is optional — the destructor does the same thing — but an application
    /// that knows the exchange is over should not wait for a scope to end.
    void close() noexcept;

    /// The first protocol message, hex — `RegistrationRequest` or `KE1`.
    const std::string& first_message() const noexcept { return first_message_; }

    /// Whether the handle is still live.
    bool open() const noexcept { return state_ != nullptr; }

protected:
    Exchange(Native& lib, Native::Handle state, std::string first_message, bool is_login);

    /// Spends the handle, or throws if it is already spent.
    Native::Handle consume();

    Native* lib_;

private:
    Native::Handle state_;
    std::string first_message_;
    bool is_login_;
};

/// One in-flight enrolment (§23).
class RegistrationExchange : public Exchange {
public:
    RegistrationExchange(Native& lib, Native::Handle state, std::string request);

    /// The hex `RegistrationRequest` to send to `register/start`.
    const std::string& request() const noexcept { return first_message(); }

    /// Seals the envelope under the server's oblivious PRF, returning the hex
    /// `RegistrationRecord`.
    ///
    /// \throws NetworkError if the exchange is already spent, the
    ///         key-stretching function is one this SDK cannot ask for, or the
    ///         library refuses the response.
    std::string finish(const std::string& password,
                       const std::string& registration_response,
                       const OpaqueKsfParams& ksf);
};

/// One in-flight login (§23).
class LoginExchange : public Exchange {
public:
    LoginExchange(Native& lib, Native::Handle state, std::string ke1);

    /// The hex `KE1` to send to `login/start`.
    const std::string& ke1() const noexcept { return first_message(); }

    /// Opens the envelope, producing `KE3`.
    ///
    /// A failure here is the **whole** of the client's authentication check,
    /// and covers both halves of the mutual authentication. Nothing may be sent
    /// afterwards (§23.4 rule 7).
    ///
    /// That case is an `AuthError`, unlike every other refusal in this
    /// namespace. The distinction is the point: a wrong password, an account
    /// that does not exist and a server that does not hold the record are
    /// indistinguishable by design and are all authentication failures, whereas
    /// a key-stretching function this build cannot perform is a configuration
    /// problem, and reporting it as "invalid password" would send an operator
    /// looking in the wrong place.
    ///
    /// \throws AuthError when the envelope does not open or `KE2` does not
    ///         verify.
    /// \throws NetworkError if the exchange is already spent, or the
    ///         key-stretching function is one this SDK cannot ask for.
    std::string finish(const std::string& password, const std::string& ke2,
                       const OpaqueKsfParams& ksf);
};

/// Blinds `password` to open an enrolment.
///
/// \throws NetworkError if the library is unavailable or refuses.
RegistrationExchange start_registration(const std::string& password);

/// Blinds `password` to open a login.
///
/// \throws NetworkError if the library is unavailable or refuses.
LoginExchange start_login(const std::string& password);

}  // namespace opaque
}  // namespace axiam
