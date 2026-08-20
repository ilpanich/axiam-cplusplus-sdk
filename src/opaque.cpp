// OPAQUE (RFC 9807) — the binding, CONTRACT.md §23.
//
// There is no cryptography in this file, and that is what §23.1 requires.
// OPAQUE needs an oblivious PRF, hash_to_curve, expand_message_xmd, an envelope
// construction and a three-message AKE; eleven independent implementations of
// that is eleven chances to be subtly and silently wrong, in a way test vectors
// do not catch because a wrong answer is still a well-formed group element.
// The SRP-6a this replaces was arithmetic every language can express — which
// here meant BN_mod_exp plus a hard dependency on OpenSSL >= 3.2 for Argon2id,
// and a build against anything older could not serve a tenant on AXIAM's
// default KDF.
//
// What is here instead: dlopen of `libaxiam_opaque_ffi`, the exchange lifetime
// around it, and the bounds this SDK applies to a server-named cost.
//
// Two ownership rules run through the whole file, both stated where they are
// implemented:
//
//  1. Every `char*` the library returns is Rust-allocated and must be released
//     with `string_free` EXACTLY ONCE — on the failure paths as well as the
//     success ones. A binding that freed only on success would leak once per
//     failed login, which is the login rate an installation under attack sees.
//  2. A state handle is CONSUMED by its finish, success or failure, and this
//     file never frees one afterwards.

#include "axiam/opaque.hpp"

#include <dlfcn.h>

#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>

#include <openssl/crypto.h>

#include "axiam/errors.hpp"

namespace axiam {
namespace opaque {
namespace {

// The platform default. A bare name, so the dynamic loader resolves it from its
// own search path — dlopen is handed the string as-is.
#if defined(__APPLE__)
constexpr const char* kDefaultLibrary = "libaxiam_opaque_ffi.dylib";
#else
constexpr const char* kDefaultLibrary = "libaxiam_opaque_ffi.so";
#endif

// The bands this SDK will act on, per field. The library range-checks too;
// doing it here as well means the refusal names the field.
struct Band {
    unsigned lo;
    unsigned hi;
};
constexpr Band kMemoryKib{8192u, 1048576u};
constexpr Band kIterations{1u, 10u};
constexpr Band kParallelism{1u, 16u};
constexpr Band kLogN{14u, 20u};
constexpr Band kR{1u, 16u};
constexpr Band kP{1u, 16u};

// The library's description of the last failure, or `fallback`. A failure with
// nothing behind it is a library bug, but a caller still deserves a sentence
// rather than an empty one.
std::string last_error_or(Native& lib, const char* fallback) {
    std::string message = lib.last_error();
    return message.empty() ? std::string(fallback) : message;
}

// One cost the named function needs: present, and inside its band.
//
// `optional` rather than a zero sentinel because a field that does not apply to
// the named function is ABSENT, not zero (§23.4 rule 5), and the two failures
// deserve different sentences.
unsigned require_cost(const std::string& ksf_name, const char* field,
                      const std::optional<unsigned>& value, Band band) {
    if (!value) {
        throw NetworkError("OPAQUE: the server named ksf `" + ksf_name + "` without `" +
                               field + "`",
                           "opaque_ksf_incomplete");
    }
    if (*value < band.lo || *value > band.hi) {
        throw NetworkError("OPAQUE: the server named " + std::string(field) + "=" +
                               std::to_string(*value) + " for `" + ksf_name +
                               "`, outside the accepted " + std::to_string(band.lo) + ".." +
                               std::to_string(band.hi),
                           "opaque_ksf_out_of_range");
    }
    return *value;
}

// ---------------------------------------------------------------------------
// The dynamic binding
// ---------------------------------------------------------------------------

// The C signatures, as function-pointer types.
using StringFreeFn = void (*)(char*);
using LastErrorFn = const char* (*)();
using AvailableFn = int (*)();
using KsfArgon2idFn = void* (*)(unsigned, unsigned, unsigned);
using KsfScryptFn = void* (*)(unsigned char, unsigned, unsigned);
using KsfFreeFn = void (*)(void*);
using StartFn = void* (*)(const char*, char**);
using RegistrationFinishFn = char* (*)(void*, const char*, const char*, const void*, char**);
using LoginFinishFn = char* (*)(void*, const char*, const char*, const void*, char**, char**);
using FreeFn = void (*)(void*);

/// The real binding, resolved with dlopen/dlsym.
///
/// Deliberately the only class here that has pointers at all. Everything above
/// it — exchange lifetime, key-stretching selection, error mapping — is driven
/// in tests against a fake \ref Native, so what needs the actual shared library
/// to exercise is as small as the job allows.
class DynamicNative final : public Native {
public:
    /// Opens the library at `path`, or returns `nullptr` when it — or any
    /// symbol — is absent.
    ///
    /// Every symbol is resolved up front rather than lazily. A library that
    /// loads and is missing one export is some *other* library of the same name
    /// on the search path, and the moment to discover that is now, not at the
    /// first login.
    static std::unique_ptr<DynamicNative> open(const char* path) {
        // RTLD_NOW so a missing symbol is a failure to load rather than a crash
        // at the first login.
        void* handle = ::dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (handle == nullptr) return nullptr;

        auto self = std::unique_ptr<DynamicNative>(new DynamicNative());
        const bool resolved =
            self->bind(handle, "axiam_opaque_string_free", self->string_free_) &&
            self->bind(handle, "axiam_opaque_last_error", self->last_error_) &&
            self->bind(handle, "axiam_opaque_available", self->available_) &&
            self->bind(handle, "axiam_opaque_ksf_argon2id", self->ksf_argon2id_) &&
            self->bind(handle, "axiam_opaque_ksf_scrypt", self->ksf_scrypt_) &&
            self->bind(handle, "axiam_opaque_ksf_free", self->ksf_free_) &&
            self->bind(handle, "axiam_opaque_registration_start", self->registration_start_) &&
            self->bind(handle, "axiam_opaque_registration_finish", self->registration_finish_) &&
            self->bind(handle, "axiam_opaque_registration_free", self->registration_free_) &&
            self->bind(handle, "axiam_opaque_login_start", self->login_start_) &&
            self->bind(handle, "axiam_opaque_login_finish", self->login_finish_) &&
            self->bind(handle, "axiam_opaque_login_free", self->login_free_);
        if (!resolved) {
            ::dlclose(handle);
            return nullptr;
        }
        return self;
    }

    // No destructor calling dlclose: the loader memoizes one instance for the
    // process lifetime, and closing a library whose function pointers may still
    // be reachable is a worse failure than holding a handle until exit.

    bool available() const override { return available_() != 0; }

    // Borrowed, not owned: library-allocated and NOT freed here.
    std::string last_error() const override {
        const char* raw = last_error_();
        return raw != nullptr ? std::string(raw) : std::string();
    }

    Handle ksf_argon2id(unsigned memory_kib, unsigned iterations,
                        unsigned parallelism) override {
        return ksf_argon2id_(memory_kib, iterations, parallelism);
    }

    Handle ksf_scrypt(unsigned char log_n, unsigned r, unsigned p) override {
        return ksf_scrypt_(log_n, r, p);
    }

    void ksf_free(Handle ksf) override { ksf_free_(ksf); }

    Handle registration_start(const std::string& password, std::string& out_request) override {
        return start(registration_start_, password, out_request);
    }

    std::optional<std::string> registration_finish(Handle state, const std::string& password,
                                                   const std::string& registration_response,
                                                   Handle ksf) override {
        return take(registration_finish_(state, password.c_str(),
                                         registration_response.c_str(), ksf, nullptr));
    }

    void registration_free(Handle state) override { registration_free_(state); }

    Handle login_start(const std::string& password, std::string& out_ke1) override {
        return start(login_start_, password, out_ke1);
    }

    std::optional<std::string> login_finish(Handle state, const std::string& password,
                                            const std::string& ke2, Handle ksf) override {
        return take(login_finish_(state, password.c_str(), ke2.c_str(), ksf, nullptr, nullptr));
    }

    void login_free(Handle state) override { login_free_(state); }

private:
    DynamicNative() = default;

    // An object pointer is not a function pointer in ISO C++, and dlsym hands
    // back the former. The memcpy is the portable spelling of the conversion
    // POSIX blesses; a reinterpret_cast is what -Wpedantic objects to.
    template <typename Fn>
    bool bind(void* handle, const char* name, Fn& slot) {
        void* sym = ::dlsym(handle, name);
        if (sym == nullptr) return false;
        std::memcpy(&slot, &sym, sizeof(sym));
        return true;
    }

    // The shape both `*_start` entry points share: a state handle plus one
    // out-parameter string.
    Handle start(StartFn fn, const std::string& password, std::string& out_message) {
        out_message.clear();
        char* raw = nullptr;
        void* state = fn(password.c_str(), &raw);
        auto message = take(raw);
        if (state == nullptr) return nullptr;  // `raw`, if any, was freed by take()
        if (!message) return state;
        out_message = std::move(*message);
        return state;
    }

    // Copies a returned string into a std::string and frees the Rust
    // allocation. Doing the free in the same function that reads the value is
    // what makes "exactly once" true by construction rather than by every
    // caller remembering.
    std::optional<std::string> take(char* raw) {
        if (raw == nullptr) return std::nullopt;
        std::string copy(raw);
        string_free_(raw);
        return copy;
    }

    StringFreeFn string_free_ = nullptr;
    LastErrorFn last_error_ = nullptr;
    AvailableFn available_ = nullptr;
    KsfArgon2idFn ksf_argon2id_ = nullptr;
    KsfScryptFn ksf_scrypt_ = nullptr;
    KsfFreeFn ksf_free_ = nullptr;
    StartFn registration_start_ = nullptr;
    RegistrationFinishFn registration_finish_ = nullptr;
    FreeFn registration_free_ = nullptr;
    StartFn login_start_ = nullptr;
    LoginFinishFn login_finish_ = nullptr;
    FreeFn login_free_ = nullptr;
};

// The resolved binding. `attempted` memoizes FAILURE as well as success:
// retrying dlopen on every login is a per-request filesystem walk for a file
// that is not going to appear.
std::mutex& native_mutex() {
    static std::mutex m;
    return m;
}
std::unique_ptr<DynamicNative>& dynamic_slot() {
    static std::unique_ptr<DynamicNative> slot;
    return slot;
}
Native*& native_slot() {
    static Native* slot = nullptr;
    return slot;
}
bool& attempted_slot() {
    static bool attempted = false;
    return attempted;
}

// Caller must hold native_mutex().
Native* load_locked() {
    if (attempted_slot()) return native_slot();
    attempted_slot() = true;

    const char* override_path = std::getenv(kLibraryPathEnv);
    const char* path =
        (override_path != nullptr && override_path[0] != '\0') ? override_path : kDefaultLibrary;

    auto loaded = DynamicNative::open(path);
    if (!loaded || !loaded->available()) return nullptr;

    dynamic_slot() = std::move(loaded);
    native_slot() = dynamic_slot().get();
    return native_slot();
}

// The library, or a refusal naming the artifact.
//
// Never an AuthError: absent is a deployment fact, and reporting it as a
// credential failure would send a user off to reset a password that works.
Native& require_native() {
    Native* lib = native();
    if (lib == nullptr) {
        throw NetworkError(
            std::string("OPAQUE is not available: the shared library "
                        "`libaxiam_opaque_ffi` could not be loaded. Download the asset for "
                        "your platform, then put it on the system library path or set ") +
                kLibraryPathEnv + " to its full path.",
            "opaque_library_missing");
    }
    return *lib;
}

// Clears a string's storage before it is released. §23.4 rule 8 asks for what
// can be cleared to be cleared; the first protocol message is derived from the
// password, so it goes the same way a request body does.
void wipe(std::string& value) {
    if (!value.empty()) OPENSSL_cleanse(&value[0], value.size());
    value.clear();
}

}  // namespace

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

Native* native() {
    std::lock_guard<std::mutex> lock(native_mutex());
    return load_locked();
}

void set_native_for_tests(Native* native) {
    std::lock_guard<std::mutex> lock(native_mutex());
    native_slot() = native;
    attempted_slot() = true;
}

void reset_native_for_tests() {
    std::lock_guard<std::mutex> lock(native_mutex());
    native_slot() = nullptr;
    dynamic_slot().reset();
    attempted_slot() = false;
}

bool available() { return native() != nullptr; }

// ---------------------------------------------------------------------------
// Key stretching (§23.4)
// ---------------------------------------------------------------------------

KsfHandle::KsfHandle(Native& lib, Native::Handle handle) noexcept
    : lib_(&lib), handle_(handle) {}

KsfHandle::~KsfHandle() {
    if (lib_ != nullptr && handle_ != nullptr) lib_->ksf_free(handle_);
}

KsfHandle::KsfHandle(KsfHandle&& other) noexcept
    : lib_(other.lib_), handle_(other.handle_) {
    other.lib_ = nullptr;
    other.handle_ = nullptr;
}

KsfHandle& KsfHandle::operator=(KsfHandle&& other) noexcept {
    if (this != &other) {
        if (lib_ != nullptr && handle_ != nullptr) lib_->ksf_free(handle_);
        lib_ = other.lib_;
        handle_ = other.handle_;
        other.lib_ = nullptr;
        other.handle_ = nullptr;
    }
    return *this;
}

KsfHandle build_ksf(Native& lib, const OpaqueKsfParams& params) {
    Native::Handle handle = nullptr;

    if (params.ksf == OpaqueKsfParams::kArgon2id) {
        // Every cost is validated BEFORE the library is called, so a refusal
        // costs nothing to unwind.
        const unsigned memory_kib =
            require_cost(params.ksf, "memory_kib", params.memory_kib, kMemoryKib);
        const unsigned iterations =
            require_cost(params.ksf, "iterations", params.iterations, kIterations);
        const unsigned parallelism =
            require_cost(params.ksf, "parallelism", params.parallelism, kParallelism);
        handle = lib.ksf_argon2id(memory_kib, iterations, parallelism);
    } else if (params.ksf == OpaqueKsfParams::kScrypt) {
        const unsigned log_n = require_cost(params.ksf, "log_n", params.log_n, kLogN);
        const unsigned r = require_cost(params.ksf, "r", params.r, kR);
        const unsigned p = require_cost(params.ksf, "p", params.p, kP);
        handle = lib.ksf_scrypt(static_cast<unsigned char>(log_n), r, p);
    } else {
        // Refused, never substituted. Substituting produces a well-formed
        // randomized password no AXIAM server agrees with, which surfaces to
        // the user as a wrong password (§23.4 rule 3). NetworkError, not
        // AuthError — a client capability gap reported as a credential failure
        // would send a user to reset a working password.
        throw NetworkError(
            "OPAQUE: this SDK cannot perform the key-stretching function the server named (`" +
                params.ksf + "`)",
            "opaque_unsupported_ksf");
    }

    if (handle == nullptr) {
        throw NetworkError("OPAQUE: " + last_error_or(lib, "invalid KSF parameters"),
                           "opaque_ksf_rejected");
    }
    return KsfHandle(lib, handle);
}

// ---------------------------------------------------------------------------
// Exchanges
// ---------------------------------------------------------------------------

Exchange::Exchange(Native& lib, Native::Handle state, std::string first_message, bool is_login)
    : lib_(&lib), state_(state), first_message_(std::move(first_message)), is_login_(is_login) {}

Exchange::~Exchange() { close(); }

Exchange::Exchange(Exchange&& other) noexcept
    : lib_(other.lib_),
      state_(other.state_),
      first_message_(std::move(other.first_message_)),
      is_login_(other.is_login_) {
    other.state_ = nullptr;
    other.first_message_.clear();
}

Exchange& Exchange::operator=(Exchange&& other) noexcept {
    if (this != &other) {
        close();
        lib_ = other.lib_;
        state_ = other.state_;
        first_message_ = std::move(other.first_message_);
        is_login_ = other.is_login_;
        other.state_ = nullptr;
        other.first_message_.clear();
    }
    return *this;
}

void Exchange::close() noexcept {
    if (lib_ != nullptr && state_ != nullptr) {
        if (is_login_) {
            lib_->login_free(state_);
        } else {
            lib_->registration_free(state_);
        }
    }
    state_ = nullptr;
    wipe(first_message_);
}

Native::Handle Exchange::consume() {
    if (state_ == nullptr) {
        throw NetworkError("OPAQUE: this exchange has already been completed",
                           "opaque_exchange_spent");
    }
    Native::Handle spent = state_;
    state_ = nullptr;
    return spent;
}

RegistrationExchange::RegistrationExchange(Native& lib, Native::Handle state, std::string request)
    : Exchange(lib, state, std::move(request), /*is_login=*/false) {}

std::string RegistrationExchange::finish(const std::string& password,
                                         const std::string& registration_response,
                                         const OpaqueKsfParams& ksf) {
    // The key-stretching handle is built BEFORE the state is spent, and the
    // order is load-bearing. build_ksf refuses an unrecognised function or an
    // out-of-band cost, and if the state had already been taken out of its
    // one-shot slot by then it could never be freed -- a leaked native
    // allocation per refused attempt, which is once per login against a
    // misconfigured tenant. Built first, a refusal leaves the exchange intact:
    // close() still releases it, and a caller who fixes the parameters can
    // retry.
    KsfHandle handle = build_ksf(*lib_, ksf);

    Native::Handle state = consume();
    auto record = lib_->registration_finish(state, password, registration_response, handle.get());
    if (!record) {
        throw NetworkError("OPAQUE: " + last_error_or(*lib_, "the envelope could not be sealed"),
                           "opaque_registration_failed");
    }
    return *record;
}

LoginExchange::LoginExchange(Native& lib, Native::Handle state, std::string ke1)
    : Exchange(lib, state, std::move(ke1), /*is_login=*/true) {}

std::string LoginExchange::finish(const std::string& password, const std::string& ke2,
                                  const OpaqueKsfParams& ksf) {
    // Built before the state is spent -- see RegistrationExchange::finish.
    KsfHandle handle = build_ksf(*lib_, ksf);

    Native::Handle state = consume();
    auto ke3 = lib_->login_finish(state, password, ke2, handle.get());
    if (!ke3) {
        // The whole of the client's authentication check, and it covers both
        // halves of the mutual authentication: the envelope only opens under
        // the right password, and KE2's MAC only verifies if the server
        // actually holds the record. RFC 9807's AKE authenticates the server
        // during the handshake, so there is no separate M2 step the way SRP
        // needed one -- and per §23.4 rule 7 nothing may be sent to
        // login/finish after this.
        throw AuthError("OPAQUE: invalid credentials: " +
                        last_error_or(*lib_, "the OPAQUE envelope did not open"));
    }
    return *ke3;
}

RegistrationExchange start_registration(const std::string& password) {
    Native& lib = require_native();

    std::string request;
    Native::Handle state = lib.registration_start(password, request);
    if (state == nullptr) {
        throw NetworkError(
            "OPAQUE: " + last_error_or(lib, "registration could not be started"),
            "opaque_registration_start_failed");
    }
    return RegistrationExchange(lib, state, std::move(request));
}

LoginExchange start_login(const std::string& password) {
    Native& lib = require_native();

    std::string ke1;
    Native::Handle state = lib.login_start(password, ke1);
    if (state == nullptr) {
        throw NetworkError("OPAQUE: " + last_error_or(lib, "login could not be started"),
                           "opaque_login_start_failed");
    }
    return LoginExchange(lib, state, std::move(ke1));
}

}  // namespace opaque
}  // namespace axiam
