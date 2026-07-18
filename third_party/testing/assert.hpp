// AXIAM C++ SDK — minimal self-contained test harness (vendored, offline-friendly).
//
// A tiny alternative to Catch2 v2. It provides just enough surface for the SDK's
// unit tests: test-case registration, sections-free flat cases, and the assertion
// macros the tests use. Chosen because the CI/build environment cannot fetch the
// upstream Catch2 single-header offline. Correctness of the assertions — not the
// framework brand — is what matters here.
//
// Usage:
//   #include "axiam_test.hpp"
//   AXIAM_TEST("does a thing") { AXIAM_REQUIRE(1 + 1 == 2); }
//   // exactly one translation unit adds:  AXIAM_TEST_MAIN()
#pragma once

#include <functional>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace axtest {

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

struct Registrar {
    Registrar(std::string n, std::function<void()> f) {
        registry().push_back({std::move(n), std::move(f)});
    }
};

struct Stats {
    int checks = 0;
    int failures = 0;
    std::vector<std::string> messages;
};

inline Stats*& current() {
    static Stats* s = nullptr;
    return s;
}

// Thrown to abort the current test on a REQUIRE-style failure.
struct FailAbort {};

inline void report_fail(const char* file, int line, const std::string& expr, bool fatal) {
    Stats* s = current();
    if (s != nullptr) {
        s->failures++;
        std::ostringstream os;
        os << "    FAILED " << file << ":" << line << "  " << expr;
        s->messages.push_back(os.str());
    }
    if (fatal) {
        throw FailAbort{};
    }
}

inline int run_all() {
    int failed_tests = 0;
    int total_checks = 0;
    for (auto& tc : registry()) {
        Stats s;
        current() = &s;
        try {
            tc.fn();
        } catch (const FailAbort&) {
            // already recorded
        } catch (const std::exception& e) {
            s.failures++;
            s.messages.push_back(std::string("    UNCAUGHT std::exception: ") + e.what());
        } catch (...) {
            s.failures++;
            s.messages.push_back("    UNCAUGHT unknown exception");
        }
        total_checks += s.checks;
        if (s.failures > 0) {
            failed_tests++;
            std::cout << "[FAIL] " << tc.name << "\n";
            for (const auto& m : s.messages) {
                std::cout << m << "\n";
            }
        } else {
            std::cout << "[ ok ] " << tc.name << "\n";
        }
        current() = nullptr;
    }
    std::cout << "\n"
              << registry().size() << " test cases, " << total_checks << " checks, "
              << failed_tests << " failed\n";
    return failed_tests > 0 ? 1 : 0;
}

}  // namespace axtest

#define AXIAM_TEST_CONCAT2(a, b) a##b
#define AXIAM_TEST_CONCAT(a, b) AXIAM_TEST_CONCAT2(a, b)

// All three identifiers key off __LINE__ so they refer to the same function.
// (Two AXIAM_TEST macros never share a source line.)
#define AXIAM_TEST(name)                                                              \
    static void AXIAM_TEST_CONCAT(axtest_fn_, __LINE__)();                            \
    namespace {                                                                       \
    ::axtest::Registrar AXIAM_TEST_CONCAT(axtest_reg_, __LINE__)(                     \
        name, &AXIAM_TEST_CONCAT(axtest_fn_, __LINE__));                              \
    }                                                                                 \
    static void AXIAM_TEST_CONCAT(axtest_fn_, __LINE__)()

#define AXIAM_CHECK_IMPL(cond, fatal, text)                                          \
    do {                                                                            \
        if (::axtest::current() != nullptr) ::axtest::current()->checks++;          \
        if (!(cond)) {                                                              \
            ::axtest::report_fail(__FILE__, __LINE__, text, fatal);                 \
        }                                                                           \
    } while (0)

#define AXIAM_CHECK(cond) AXIAM_CHECK_IMPL((cond), false, #cond)
#define AXIAM_REQUIRE(cond) AXIAM_CHECK_IMPL((cond), true, #cond)
#define AXIAM_CHECK_FALSE(cond) AXIAM_CHECK_IMPL(!(cond), false, "!(" #cond ")")
#define AXIAM_REQUIRE_FALSE(cond) AXIAM_CHECK_IMPL(!(cond), true, "!(" #cond ")")

#define AXIAM_REQUIRE_THROWS_AS(expr, ExType)                                        \
    do {                                                                            \
        if (::axtest::current() != nullptr) ::axtest::current()->checks++;          \
        bool axtest_caught = false;                                                 \
        try {                                                                       \
            (void)(expr);                                                           \
        } catch (const ExType&) {                                                   \
            axtest_caught = true;                                                   \
        } catch (...) {                                                             \
        }                                                                           \
        if (!axtest_caught) {                                                       \
            ::axtest::report_fail(__FILE__, __LINE__,                               \
                                  "expected " #ExType " from " #expr, true);        \
        }                                                                           \
    } while (0)

#define AXIAM_REQUIRE_NOTHROW(expr)                                                  \
    do {                                                                            \
        if (::axtest::current() != nullptr) ::axtest::current()->checks++;          \
        try {                                                                       \
            (void)(expr);                                                           \
        } catch (...) {                                                             \
            ::axtest::report_fail(__FILE__, __LINE__,                               \
                                  "unexpected throw from " #expr, true);            \
        }                                                                           \
    } while (0)

#define AXIAM_TEST_MAIN()                                                            \
    int main() { return ::axtest::run_all(); }
