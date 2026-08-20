// An in-process stand-in for `libaxiam_opaque_ffi`.
//
// CONTRACT.md §23.1 forbids this SDK from implementing OPAQUE, so there is no
// cryptography to test and no cross-language vector suite to run — the SRP
// suite this replaces spent 375 lines proving a modular exponentiation
// reproduced six vectors and that the RFC 5054 moduli were transcribed
// correctly, and that arithmetic is gone. What remains, and what this fake
// exercises, is the layer above the ABI: single-use exchanges, the
// key-stretching function the SERVER named being the one used, which failure
// means what, and what goes on the wire.
//
// It does NOT stand in for the dlopen/dlsym resolution — tests/opaque_stub.cpp
// is a real shared library for that. Requiring the real cdylib here would give
// a suite that runs only where a per-platform release asset happens to be
// installed, and would be testing `opaque-ke` rather than this SDK.
//
// Every handle it hands out is counted. `leaked()` is non-zero if the SDK
// dropped a key-stretching handle or a state handle, and that counter is the
// assertion that carries the weight here: the ordering defect this migration
// was built to avoid (spending the state handle before the KSF is built) shows
// up in it and nowhere else.
#pragma once

#include <map>
#include <optional>
#include <set>
#include <string>

#include "axiam/opaque.hpp"

namespace axtest {

/// Entry points that can be made to fail.
enum class FakeEntry {
    kKsfArgon2id,
    kKsfScrypt,
    kRegistrationStart,
    kRegistrationFinish,
    kLoginStart,
    kLoginFinish,
};

/// A fake `libaxiam_opaque_ffi`.
///
/// Handles are small integers cast to `void*` rather than allocations: nothing
/// here needs a heap, and the counters are what the assertions read.
class FakeNative final : public axiam::opaque::Native {
public:
    /// What `available()` answers.
    bool available_value = true;

    /// Makes an entry point return failure, reporting its own default message.
    void fail(FakeEntry entry) { failing_.insert(entry); }

    /// Makes an entry point fail with exactly `message`.
    ///
    /// An EMPTY string is a meaningful value here, not a "use the default":
    /// it models a library that failed without saying why — a bug, but one the
    /// caller still needs a sentence for, and the SDK's own fallback is what
    /// has to supply it.
    void fail_with(FakeEntry entry, std::string message) {
        failing_.insert(entry);
        messages_[entry] = std::move(message);
    }

    /// Key-stretching handles built and not yet released. Zero after any finish.
    int ksf_alive = 0;
    /// State handles neither consumed nor released.
    int states_alive() const { return static_cast<int>(states_.size()); }
    /// Non-zero when the SDK dropped a handle of either kind.
    bool leaked() const { return ksf_alive != 0 || !states_.empty(); }

    /// What the last finish was given, so a test can assert the SERVER's ksf is
    /// the one that reached the library.
    std::uintptr_t last_ksf_tag = 0;
    std::string last_peer_message;
    std::string last_password;

    // -- the ABI -----------------------------------------------------------

    bool available() const override { return available_value; }

    std::string last_error() const override { return last_error_; }

    Handle ksf_argon2id(unsigned memory_kib, unsigned iterations,
                        unsigned parallelism) override {
        if (failed(FakeEntry::kKsfArgon2id, "argon2id parameters rejected")) return nullptr;
        ksf_alive++;
        return tag(0xA0000u + memory_kib + iterations + parallelism);
    }

    Handle ksf_scrypt(unsigned char log_n, unsigned r, unsigned p) override {
        if (failed(FakeEntry::kKsfScrypt, "scrypt parameters rejected")) return nullptr;
        ksf_alive++;
        return tag(0xB0000u + static_cast<unsigned>(log_n) + r + p);
    }

    void ksf_free(Handle) override { ksf_alive--; }

    Handle registration_start(const std::string& password, std::string& out_request) override {
        out_request.clear();
        if (failed(FakeEntry::kRegistrationStart, "registration could not be started")) {
            return nullptr;
        }
        out_request = "req:" + password;
        return new_state(/*is_login=*/false);
    }

    std::optional<std::string> registration_finish(Handle state, const std::string& password,
                                                   const std::string& registration_response,
                                                   Handle ksf) override {
        consume_state(state, /*is_login=*/false);
        record(password, registration_response, ksf);
        if (failed(FakeEntry::kRegistrationFinish, "the envelope could not be sealed")) {
            return std::nullopt;
        }
        return "record:" + password + ":" + registration_response + ":" + hex(ksf);
    }

    void registration_free(Handle state) override { consume_state(state, /*is_login=*/false); }

    Handle login_start(const std::string& password, std::string& out_ke1) override {
        out_ke1.clear();
        if (failed(FakeEntry::kLoginStart, "login could not be started")) return nullptr;
        out_ke1 = "ke1:" + password;
        return new_state(/*is_login=*/true);
    }

    std::optional<std::string> login_finish(Handle state, const std::string& password,
                                            const std::string& ke2, Handle ksf) override {
        consume_state(state, /*is_login=*/true);
        record(password, ke2, ksf);
        if (failed(FakeEntry::kLoginFinish, "the envelope did not open")) return std::nullopt;
        return "ke3:" + password + ":" + ke2 + ":" + hex(ksf);
    }

    void login_free(Handle state) override { consume_state(state, /*is_login=*/true); }

    /// Set when a finish or free was handed a handle that was not live, or was
    /// live for the other half of the protocol. Checked by the tests rather
    /// than asserted here, so a harness bug reads as a failing assertion in the
    /// test that caused it.
    bool misuse = false;

private:
    static Handle tag(std::uintptr_t value) { return reinterpret_cast<Handle>(value); }

    static std::string hex(Handle handle) {
        static const char* digits = "0123456789abcdef";
        auto value = reinterpret_cast<std::uintptr_t>(handle);
        std::string out;
        while (value != 0) {
            out.insert(out.begin(), digits[value & 0xf]);
            value >>= 4;
        }
        return out.empty() ? "0" : out;
    }

    bool failed(FakeEntry entry, const char* fallback) {
        if (failing_.count(entry) == 0) return false;
        auto it = messages_.find(entry);
        last_error_ = (it != messages_.end()) ? it->second : fallback;
        return true;
    }

    Handle new_state(bool is_login) {
        Handle handle = tag(next_state_);
        next_state_ += 0x10;
        states_[handle] = is_login;
        return handle;
    }

    void consume_state(Handle handle, bool is_login) {
        auto it = states_.find(handle);
        if (it == states_.end() || it->second != is_login) {
            misuse = true;
            return;
        }
        states_.erase(it);
    }

    void record(const std::string& password, const std::string& peer, Handle ksf) {
        last_password = password;
        last_peer_message = peer;
        last_ksf_tag = reinterpret_cast<std::uintptr_t>(ksf);
    }

    std::set<FakeEntry> failing_;
    std::map<FakeEntry, std::string> messages_;
    std::string last_error_;
    std::map<Handle, bool> states_;
    std::uintptr_t next_state_ = 0x1000;
};

/// Installs `fake` for the lifetime of the scope, and removes it after.
///
/// The loader memoizes, so a test that installed a fake and did not remove it
/// would silently decide what every later test sees.
class ScopedFakeNative {
public:
    explicit ScopedFakeNative(FakeNative& fake) {
        axiam::opaque::set_native_for_tests(&fake);
    }
    ~ScopedFakeNative() { axiam::opaque::reset_native_for_tests(); }
    ScopedFakeNative(const ScopedFakeNative&) = delete;
    ScopedFakeNative& operator=(const ScopedFakeNative&) = delete;
};

}  // namespace axtest
