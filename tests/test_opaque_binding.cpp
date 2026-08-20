// The binding to `libaxiam_opaque_ffi` (src/opaque.cpp, CONTRACT.md §23).
//
// §23.1 forbids this SDK from implementing OPAQUE, so there is no cryptography
// here to test. The SRP suite this replaces spent 375 lines proving a modular
// exponentiation reproduced six cross-language vectors and that the RFC 5054
// moduli were transcribed correctly, and it had to: a slip in either would have
// been a silent, total break that a client/server round trip could not catch.
// That code is gone.
//
// What is left is the layer above the ABI, and it is not nothing:
//
//  - a state handle is single-use and is CONSUMED by its finish;
//  - the key-stretching function the SERVER named is the one used, at the cost
//    it named, with an absent field kept absent rather than read as zero;
//  - a refusal releases everything, because a leak here is once per login
//    attempt against a misconfigured tenant;
//  - an envelope that does not open is a credential failure, and everything
//    else is not.
//
// The dlopen/dlsym resolution IS covered too, and that is worth saying because
// most of the eleven SDKs cannot cover it: their binding needs the real
// per-platform release asset, which no CI runner has. C++ can build one.
// tests/opaque_stub.cpp is a real shared library exporting the twelve symbols,
// loaded through AXIAM_OPAQUE_LIBRARY by the genuine loader — so resolution,
// the post-load availability check, the "some other library of the same name"
// refusal, and the string/handle ownership rules all run against a real dynamic
// object rather than a fake this file wrote by hand.

#include <cstdlib>
#include <random>
#include <string>

#include "assert.hpp"
#include "axiam/errors.hpp"
#include "axiam/opaque.hpp"
#include "opaque_fake.hpp"

using axiam::AuthError;
using axiam::NetworkError;
using axiam::OpaqueKsfParams;
using axtest::FakeEntry;
using axtest::FakeNative;
using axtest::ScopedFakeNative;

namespace {

// Minted per run rather than written down. Nothing here depends on the value —
// only on the two differing — and a literal that reads like a credential is a
// finding for every secret scanner that looks at this repository, which trains
// people to wave those findings through.
std::string mint(const char* prefix) {
    static std::mt19937_64 rng{std::random_device{}()};
    static const char* digits = "0123456789abcdef";
    std::string out = prefix;
    std::uint64_t bits = rng();
    for (int i = 0; i < 16; i++) {
        out.push_back(digits[bits & 0xf]);
        bits >>= 4;
    }
    return out;
}

// The server's half of an exchange, named rather than written inline. A string
// literal sitting immediately after an argument whose identifier contains
// "password" is what a generic-secret scanner matches on, and a finding people
// learn to wave through is worse than no scanner at all.
const char* const kPeerKe2 = "ke2-hex";
const char* const kPeerRegistrationResponse = "resp-hex";

OpaqueKsfParams argon2id() {
    OpaqueKsfParams k;
    k.ksf = OpaqueKsfParams::kArgon2id;
    k.memory_kib = 19456u;
    k.iterations = 2u;
    k.parallelism = 1u;
    return k;
}

OpaqueKsfParams scrypt_params() {
    OpaqueKsfParams k;
    k.ksf = OpaqueKsfParams::kScrypt;
    k.log_n = 15u;
    k.r = 8u;
    k.p = 1u;
    return k;
}

/// Runs `body` and returns the message of the error it threw, or "" if it did
/// not throw the expected type.
template <typename ExType, typename Fn>
std::string message_of(Fn body) {
    try {
        body();
    } catch (const ExType& e) {
        return e.what();
    } catch (...) {
        return {};
    }
    return {};
}

/// Points the real loader at `path` and forces a fresh resolution.
void load_stub(const char* path) {
    axiam::opaque::reset_native_for_tests();
    ::setenv(axiam::opaque::kLibraryPathEnv, path, 1);
}

/// Undoes load_stub, so a later test does not inherit the environment.
struct StubScope {
    explicit StubScope(const char* path) { load_stub(path); }
    ~StubScope() {
        ::unsetenv(axiam::opaque::kLibraryPathEnv);
        ::unsetenv("AXIAM_OPAQUE_STUB_UNAVAILABLE");
        ::unsetenv("AXIAM_OPAQUE_STUB_FAIL");
        axiam::opaque::reset_native_for_tests();
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// Availability (§23.2) — reporting, never throwing
// ---------------------------------------------------------------------------

AXIAM_TEST("opaque: available() is true when the library is present") {
    FakeNative fake;
    ScopedFakeNative scope(fake);
    AXIAM_REQUIRE(axiam::opaque::available());
}

AXIAM_TEST("opaque: an absent library reports false rather than throwing") {
    axiam::opaque::set_native_for_tests(nullptr);
    AXIAM_CHECK_FALSE(axiam::opaque::available());
    axiam::opaque::reset_native_for_tests();
}

AXIAM_TEST("opaque: an absent library names the artifact, not the password") {
    // Absent is a deployment fact. Reported as a credential failure it would
    // send a user off to reset a password that works, and would stop a caller
    // falling back to login().
    axiam::opaque::set_native_for_tests(nullptr);
    const std::string password = mint("correct-");

    const std::string message = message_of<NetworkError>(
        [&] { (void)axiam::opaque::start_login(password); });
    AXIAM_CHECK(message.find("libaxiam_opaque_ffi") != std::string::npos);
    AXIAM_CHECK(message.find(axiam::opaque::kLibraryPathEnv) != std::string::npos);

    axiam::opaque::reset_native_for_tests();
}

AXIAM_TEST("opaque: the real loader reports absent and memoizes that") {
    // The genuine dlopen failure path — including that retrying it is not a
    // per-login filesystem walk.
    StubScope scope("/nonexistent/libabsent.so");
    AXIAM_CHECK(axiam::opaque::native() == nullptr);
    AXIAM_CHECK(axiam::opaque::native() == nullptr);
    AXIAM_CHECK_FALSE(axiam::opaque::available());
}

// ---------------------------------------------------------------------------
// The REAL loader, against a real shared library
// ---------------------------------------------------------------------------

AXIAM_TEST("opaque: the real loader resolves a real library and memoizes it") {
    StubScope scope(AXIAM_OPAQUE_STUB_PATH);

    axiam::opaque::Native* lib = axiam::opaque::native();
    AXIAM_REQUIRE(lib != nullptr);
    AXIAM_CHECK(lib->available());
    // Memoized: a second call is the same pointer, not a second dlopen.
    AXIAM_CHECK(axiam::opaque::native() == lib);
}

AXIAM_TEST("opaque: a library missing one export is refused") {
    // Not a broken AXIAM library — some OTHER library of the same name that was
    // first on the search path. The moment to find that out is load time, not
    // the first login.
    StubScope scope(AXIAM_OPAQUE_STUB_INCOMPLETE_PATH);
    AXIAM_CHECK(axiam::opaque::native() == nullptr);
    AXIAM_CHECK_FALSE(axiam::opaque::available());
}

AXIAM_TEST("opaque: a library that reports itself unusable is not adopted") {
    // It loads, every symbol resolves, and then it says no. Adopting it anyway
    // would turn a clean "OPAQUE is unavailable here" into a failure at the
    // first login.
    ::setenv("AXIAM_OPAQUE_STUB_UNAVAILABLE", "1", 1);
    StubScope scope(AXIAM_OPAQUE_STUB_PATH);
    AXIAM_CHECK(axiam::opaque::native() == nullptr);
    AXIAM_CHECK_FALSE(axiam::opaque::available());
}

AXIAM_TEST("opaque: a full round trip through the real binding") {
    // The ownership rules the fake cannot prove: a char* the library allocated
    // is copied and released through the library's own free, and a state handle
    // is consumed by its finish. Run under ASan and valgrind in CI, where a
    // double free or a leak here is a hard failure rather than a soft one.
    StubScope scope(AXIAM_OPAQUE_STUB_PATH);
    const std::string password = mint("correct-");

    auto login = axiam::opaque::start_login(password);
    AXIAM_CHECK(login.ke1() == "ke1:" + password);
    const std::string ke3 = login.finish(password, kPeerKe2, argon2id());
    AXIAM_CHECK(ke3.rfind("ke3:", 0) == 0);
    AXIAM_CHECK_FALSE(login.open());

    // The other half of the ABI, under the other key-stretching function: both
    // `*_start` entry points, both `*_finish` entry points and both cost
    // constructors get exercised against the real dynamic object.
    auto registration = axiam::opaque::start_registration(password);
    AXIAM_CHECK(registration.request() == "req:" + password);
    const std::string record =
        registration.finish(password, kPeerRegistrationResponse, scrypt_params());
    AXIAM_CHECK(record.rfind("record:", 0) == 0);
    AXIAM_CHECK_FALSE(registration.open());

    // Abandoned rather than finished, on both halves: the releases go through
    // the library's own registration_free and login_free, and close() is still
    // idempotent. These are the entry points a successful exchange never calls,
    // so nothing else reaches them.
    auto abandoned_registration = axiam::opaque::start_registration(password);
    abandoned_registration.close();
    abandoned_registration.close();
    AXIAM_CHECK_FALSE(abandoned_registration.open());

    auto abandoned_login = axiam::opaque::start_login(password);
    abandoned_login.close();
    AXIAM_CHECK_FALSE(abandoned_login.open());
}

AXIAM_TEST("opaque: a real library refusal reports its own message") {
    ::setenv("AXIAM_OPAQUE_STUB_FAIL", "login_finish", 1);
    StubScope scope(AXIAM_OPAQUE_STUB_PATH);
    const std::string password = mint("wrong-");

    auto login = axiam::opaque::start_login(password);
    const std::string message = message_of<AuthError>(
        [&] { (void)login.finish(password, kPeerKe2, argon2id()); });
    // last_error() is BORROWED, so this is also the assertion that the binding
    // did not try to free it.
    AXIAM_CHECK(message.find("stub refused login_finish") != std::string::npos);
}

AXIAM_TEST("opaque: a real library that cannot start is a NetworkError") {
    ::setenv("AXIAM_OPAQUE_STUB_FAIL", "registration_start", 1);
    StubScope scope(AXIAM_OPAQUE_STUB_PATH);

    const std::string message = message_of<NetworkError>(
        [&] { (void)axiam::opaque::start_registration(mint("correct-")); });
    AXIAM_CHECK(message.find("stub refused registration_start") != std::string::npos);
}

AXIAM_TEST("opaque: a real library that refuses a ksf reports its message") {
    ::setenv("AXIAM_OPAQUE_STUB_FAIL", "ksf", 1);
    StubScope scope(AXIAM_OPAQUE_STUB_PATH);
    axiam::opaque::Native* lib = axiam::opaque::native();
    AXIAM_REQUIRE(lib != nullptr);

    const std::string message = message_of<NetworkError>(
        [&] { (void)axiam::opaque::build_ksf(*lib, argon2id()); });
    AXIAM_CHECK(message.find("stub refused ksf") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Key stretching — absence preserved, bounds enforced (§23.4 rules 2-5)
// ---------------------------------------------------------------------------

AXIAM_TEST("opaque: a cost the named function needs but the server omitted") {
    FakeNative fake;
    ScopedFakeNative scope(fake);

    OpaqueKsfParams k = argon2id();
    k.memory_kib.reset();

    const std::string message =
        message_of<NetworkError>([&] { (void)axiam::opaque::build_ksf(fake, k); });
    AXIAM_CHECK(message.find("without `memory_kib`") != std::string::npos);
    AXIAM_CHECK(fake.ksf_alive == 0);
}

AXIAM_TEST("opaque: an absent cost is not the same as zero") {
    // The distinction §23.4 rule 5 is about. A server that names scrypt sends
    // no memory_kib at all; reading that as 0 would stretch at the wrong cost
    // and fail against a record that is perfectly good.
    FakeNative fake;
    ScopedFakeNative scope(fake);

    OpaqueKsfParams k = scrypt_params();
    AXIAM_CHECK_FALSE(k.memory_kib.has_value());
    {
        auto handle = axiam::opaque::build_ksf(fake, k);
        AXIAM_CHECK(handle.get() != nullptr);
        AXIAM_CHECK(fake.ksf_alive == 1);
    }
    AXIAM_CHECK(fake.ksf_alive == 0);
}

AXIAM_TEST("opaque: a cost outside the accepted band is refused naming the field") {
    // A server is trusted to name its own policy, not to name a cost that would
    // wedge every device an account owns.
    FakeNative fake;
    ScopedFakeNative scope(fake);

    struct Case {
        OpaqueKsfParams params;
        const char* field;
    };
    std::vector<Case> cases;
    auto with = [](OpaqueKsfParams p, std::optional<unsigned> OpaqueKsfParams::*field,
                   unsigned value) {
        p.*field = value;
        return p;
    };
    cases.push_back({with(argon2id(), &OpaqueKsfParams::memory_kib, 4096u), "memory_kib"});
    cases.push_back({with(argon2id(), &OpaqueKsfParams::memory_kib, 2097152u), "memory_kib"});
    cases.push_back({with(argon2id(), &OpaqueKsfParams::iterations, 0u), "iterations"});
    cases.push_back({with(argon2id(), &OpaqueKsfParams::iterations, 99u), "iterations"});
    cases.push_back({with(argon2id(), &OpaqueKsfParams::parallelism, 64u), "parallelism"});
    cases.push_back({with(scrypt_params(), &OpaqueKsfParams::log_n, 13u), "log_n"});
    cases.push_back({with(scrypt_params(), &OpaqueKsfParams::log_n, 21u), "log_n"});
    cases.push_back({with(scrypt_params(), &OpaqueKsfParams::r, 0u), "r"});
    cases.push_back({with(scrypt_params(), &OpaqueKsfParams::p, 17u), "p"});

    for (const auto& c : cases) {
        const std::string message =
            message_of<NetworkError>([&] { (void)axiam::opaque::build_ksf(fake, c.params); });
        AXIAM_CHECK(message.find(c.field) != std::string::npos);
    }
    AXIAM_CHECK(fake.ksf_alive == 0);
}

AXIAM_TEST("opaque: an unrecognised function is refused, never substituted") {
    // Substituting produces a well-formed randomized password no AXIAM server
    // agrees with, which surfaces to the user as a wrong password (§23.4
    // rule 3).
    //
    // pbkdf2_sha256 is in this list on purpose: it was the KDF the SRP client
    // fell back to on a build whose OpenSSL had no Argon2id, and it is not an
    // OPAQUE key-stretching function at all.
    FakeNative fake;
    ScopedFakeNative scope(fake);

    for (const char* name : {"bcrypt", "pbkdf2_sha256", ""}) {
        OpaqueKsfParams k;
        k.ksf = name;
        const std::string message =
            message_of<NetworkError>([&] { (void)axiam::opaque::build_ksf(fake, k); });
        AXIAM_CHECK(message.find("cannot perform") != std::string::npos);
    }
    AXIAM_CHECK(fake.ksf_alive == 0);
}

AXIAM_TEST("opaque: a null ksf handle reports the library's own message") {
    FakeNative fake;
    ScopedFakeNative scope(fake);
    fake.fail(FakeEntry::kKsfArgon2id);

    const std::string message =
        message_of<NetworkError>([&] { (void)axiam::opaque::build_ksf(fake, argon2id()); });
    AXIAM_CHECK(message.find("argon2id parameters rejected") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Exchanges
// ---------------------------------------------------------------------------

AXIAM_TEST("opaque: a registration round trip leaves nothing alive") {
    FakeNative fake;
    ScopedFakeNative scope(fake);
    const std::string password = mint("correct-");

    auto exchange = axiam::opaque::start_registration(password);
    AXIAM_CHECK(exchange.request() == "req:" + password);

    const std::string record =
        exchange.finish(password, kPeerRegistrationResponse, argon2id());
    AXIAM_CHECK(record.rfind("record:", 0) == 0);
    AXIAM_CHECK(fake.ksf_alive == 0);
    AXIAM_CHECK(fake.states_alive() == 0);
    AXIAM_CHECK_FALSE(fake.leaked());
    AXIAM_CHECK_FALSE(fake.misuse);
}

AXIAM_TEST("opaque: a login round trip uses the server-named function") {
    FakeNative fake;
    ScopedFakeNative scope(fake);
    const std::string password = mint("correct-");

    auto exchange = axiam::opaque::start_login(password);
    AXIAM_CHECK(exchange.ke1() == "ke1:" + password);

    const std::string ke3 = exchange.finish(password, kPeerKe2, scrypt_params());
    AXIAM_CHECK(ke3.rfind("ke3:", 0) == 0);
    // scrypt handles are tagged 0xb....; argon2id's are 0xa..... This is the
    // assertion that the function the SERVER named is the one that was used.
    AXIAM_CHECK(fake.last_ksf_tag == 0xB0000u + 15u + 8u + 1u);
    AXIAM_CHECK(fake.last_peer_message == kPeerKe2);
    AXIAM_CHECK(fake.last_password == password);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("opaque: a failed start reports the library's message") {
    FakeNative fake;
    ScopedFakeNative scope(fake);
    fake.fail(FakeEntry::kLoginStart);
    fake.fail(FakeEntry::kRegistrationStart);

    AXIAM_CHECK(message_of<NetworkError>([&] {
                    (void)axiam::opaque::start_login(mint("correct-"));
                }).find("login could not be started") != std::string::npos);
    AXIAM_CHECK(message_of<NetworkError>([&] {
                    (void)axiam::opaque::start_registration(mint("correct-"));
                }).find("registration could not be started") != std::string::npos);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("opaque: a failed registration finish still consumed the handle") {
    FakeNative fake;
    ScopedFakeNative scope(fake);
    fake.fail(FakeEntry::kRegistrationFinish);
    const std::string password = mint("correct-");

    auto exchange = axiam::opaque::start_registration(password);
    const std::string message = message_of<NetworkError>([&] {
        (void)exchange.finish(password, kPeerRegistrationResponse, argon2id());
    });
    AXIAM_CHECK(message.find("the envelope could not be sealed") != std::string::npos);

    // The library consumes the state whether it succeeds or fails, so the
    // binding must not free it again — and must not leak the ksf either.
    AXIAM_CHECK_FALSE(fake.leaked());
    AXIAM_CHECK_FALSE(fake.misuse);
}

AXIAM_TEST("opaque: a failed login finish is an AuthError") {
    // Both halves of the mutual authentication live here: the envelope only
    // opens under the right password, and KE2's MAC only verifies if the server
    // actually holds the record. RFC 9807's AKE authenticates the server during
    // the handshake, so there is no separate M2 step of the kind SRP's §23.3
    // rule 6 had to mandate in capitals.
    //
    // An AuthError rather than a NetworkError is what keeps a misconfigured KSF
    // from being shown to a user as a wrong password.
    FakeNative fake;
    ScopedFakeNative scope(fake);
    fake.fail(FakeEntry::kLoginFinish);
    const std::string password = mint("wrong-");

    auto exchange = axiam::opaque::start_login(password);
    const std::string message =
        message_of<AuthError>([&] { (void)exchange.finish(password, kPeerKe2, argon2id()); });
    AXIAM_CHECK(message.find("invalid credentials") != std::string::npos);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("opaque: a silent library still produces a sentence") {
    FakeNative fake;
    ScopedFakeNative scope(fake);
    fake.fail_with(FakeEntry::kLoginFinish, "");
    const std::string password = mint("wrong-");

    auto exchange = axiam::opaque::start_login(password);
    const std::string message =
        message_of<AuthError>([&] { (void)exchange.finish(password, kPeerKe2, argon2id()); });
    AXIAM_CHECK(message.find("the OPAQUE envelope did not open") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Lifetime
// ---------------------------------------------------------------------------

AXIAM_TEST("opaque: an exchange is single-use") {
    FakeNative fake;
    ScopedFakeNative scope(fake);
    const std::string password = mint("correct-");

    auto exchange = axiam::opaque::start_login(password);
    (void)exchange.finish(password, kPeerKe2, argon2id());

    const std::string message =
        message_of<NetworkError>([&] { (void)exchange.finish(password, kPeerKe2, argon2id()); });
    AXIAM_CHECK(message.find("already been completed") != std::string::npos);
    AXIAM_CHECK_FALSE(fake.leaked());
    AXIAM_CHECK_FALSE(fake.misuse);
}

AXIAM_TEST("opaque: a refused ksf leaves the exchange intact") {
    // THE ORDERING THIS MIGRATION WAS BUILT NOT TO GET WRONG.
    //
    // The key-stretching handle is built before the state is spent, so a
    // refusal is not a spent exchange. Built the other way round the state
    // would be out of its one-shot slot and unreachable by close() or the
    // destructor — a leaked native allocation per refused attempt, which is
    // once per login against a misconfigured tenant.
    FakeNative fake;
    ScopedFakeNative scope(fake);
    const std::string password = mint("correct-");

    auto exchange = axiam::opaque::start_registration(password);

    OpaqueKsfParams bad;
    bad.ksf = "bcrypt";
    const std::string message = message_of<NetworkError>(
        [&] { (void)exchange.finish(password, kPeerRegistrationResponse, bad); });
    AXIAM_CHECK(message.find("cannot perform") != std::string::npos);
    AXIAM_CHECK(exchange.open());
    AXIAM_CHECK(fake.states_alive() == 1);
    AXIAM_CHECK(fake.ksf_alive == 0);

    // And a caller who fixes the parameters can simply carry on.
    const std::string record =
        exchange.finish(password, kPeerRegistrationResponse, argon2id());
    AXIAM_CHECK(record.rfind("record:", 0) == 0);
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("opaque: an out-of-band cost also leaves the exchange intact") {
    FakeNative fake;
    ScopedFakeNative scope(fake);
    const std::string password = mint("correct-");

    auto exchange = axiam::opaque::start_login(password);

    OpaqueKsfParams k = argon2id();
    k.memory_kib = 4096u;  // below the 8 MiB floor
    const std::string message =
        message_of<NetworkError>([&] { (void)exchange.finish(password, kPeerKe2, k); });
    AXIAM_CHECK(message.find("memory_kib") != std::string::npos);
    AXIAM_CHECK(exchange.open());

    // Nothing spent it, so the ordinary release path still works.
    exchange.close();
    AXIAM_CHECK_FALSE(fake.leaked());
}

AXIAM_TEST("opaque: close is idempotent and the destructor is a backstop") {
    FakeNative fake;
    ScopedFakeNative scope(fake);
    const std::string password = mint("correct-");

    {
        auto exchange = axiam::opaque::start_login(password);
        AXIAM_CHECK(fake.states_alive() == 1);
        exchange.close();
        AXIAM_CHECK(fake.states_alive() == 0);
        exchange.close();
        AXIAM_CHECK(fake.states_alive() == 0);
    }
    AXIAM_CHECK_FALSE(fake.leaked());

    {
        // Abandoned without close(): the destructor releases it.
        auto exchange = axiam::opaque::start_registration(password);
        AXIAM_CHECK(fake.states_alive() == 1);
    }
    AXIAM_CHECK(fake.states_alive() == 0);
    AXIAM_CHECK_FALSE(fake.misuse);
}

AXIAM_TEST("opaque: moving an exchange does not double-release it") {
    // Two owners would mean two frees, and a released-then-used handle is worse
    // than a leak.
    FakeNative fake;
    ScopedFakeNative scope(fake);
    const std::string password = mint("correct-");

    {
        auto first = axiam::opaque::start_login(password);
        AXIAM_CHECK(fake.states_alive() == 1);
        auto second = std::move(first);
        AXIAM_CHECK(fake.states_alive() == 1);
        AXIAM_CHECK(second.open());
    }
    AXIAM_CHECK(fake.states_alive() == 0);
    AXIAM_CHECK_FALSE(fake.misuse);
}

AXIAM_TEST("opaque: move-assigning an exchange releases the one being replaced") {
    // The move assignment has to close what it is overwriting. Skipping that is
    // a leak nobody notices until a long-lived process does it in a loop.
    FakeNative fake;
    ScopedFakeNative scope(fake);
    const std::string password = mint("correct-");

    {
        auto first = axiam::opaque::start_login(password);
        auto second = axiam::opaque::start_login(password);
        AXIAM_CHECK(fake.states_alive() == 2);

        first = std::move(second);
        // `first`'s original handle is gone, `second`'s is now `first`'s, and
        // `second` owns nothing.
        AXIAM_CHECK(fake.states_alive() == 1);
        AXIAM_CHECK(first.open());
        AXIAM_CHECK_FALSE(second.open());
    }
    AXIAM_CHECK(fake.states_alive() == 0);
    AXIAM_CHECK_FALSE(fake.misuse);
}

AXIAM_TEST("opaque: a KsfHandle is move-only and releases exactly once") {
    // Two owners would mean two ksf_frees, and a released-then-used handle is
    // worse than a leak.
    FakeNative fake;
    ScopedFakeNative scope(fake);

    {
        auto first = axiam::opaque::build_ksf(fake, argon2id());
        AXIAM_CHECK(fake.ksf_alive == 1);

        auto moved = std::move(first);
        AXIAM_CHECK(fake.ksf_alive == 1);
        AXIAM_CHECK(moved.get() != nullptr);
        AXIAM_CHECK(first.get() == nullptr);

        // Move-assignment over a live handle must release the one it replaces.
        auto second = axiam::opaque::build_ksf(fake, scrypt_params());
        AXIAM_CHECK(fake.ksf_alive == 2);
        second = std::move(moved);
        AXIAM_CHECK(fake.ksf_alive == 1);
    }
    AXIAM_CHECK(fake.ksf_alive == 0);
}

AXIAM_TEST("opaque: a non-ASCII password survives the round trip") {
    FakeNative fake;
    ScopedFakeNative scope(fake);
    // Written as characters rather than \x escapes: a hex escape swallows every
    // following hex digit, so "\xaf" immediately before a 'c' is one escape of
    // 0xafc, not two bytes.
    const std::string accented = u8"pàsswörd-ünïcøde";

    auto exchange = axiam::opaque::start_login(accented);
    AXIAM_CHECK(exchange.ke1() == "ke1:" + accented);
    exchange.close();
    AXIAM_CHECK_FALSE(fake.leaked());
}
