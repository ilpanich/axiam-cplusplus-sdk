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

#include <cstdlib>
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

// Progress lines are written and FLUSHED before each case runs (issue #83). Under
// ctest (or gdb, or any CI log) stdout is a pipe, so it is fully buffered: when
// the process crashed or was killed on timeout, everything still sitting in the
// 4 KiB buffer was lost and the log stopped at a block boundary somewhere BEFORE
// the case that actually failed, naming nothing. `[ .. ] <name>` + std::endl
// means the last line of any log is the case that was running when it stopped.
//
// AXIAM_TEST_FILTER=<a>|<b>|... runs only the cases whose name contains one of
// the `|`-separated substrings, so a suspect group can be looped until it fails
// without the other 1600 cases around it.
inline int run_all() {
    int failed_tests = 0;
    int total_checks = 0;
    std::size_t ran = 0;
    std::vector<std::string> filters;
    if (const char* env = std::getenv("AXIAM_TEST_FILTER")) {
        std::string all = env;
        std::size_t pos = 0;
        while (pos <= all.size()) {
            const std::size_t bar = all.find('|', pos);
            const std::string one = all.substr(pos, bar == std::string::npos ? std::string::npos : bar - pos);
            if (!one.empty()) filters.push_back(one);
            if (bar == std::string::npos) break;
            pos = bar + 1;
        }
    }
    for (auto& tc : registry()) {
        if (!filters.empty()) {
            bool hit = false;
            for (const auto& f : filters) hit = hit || tc.name.find(f) != std::string::npos;
            if (!hit) continue;
        }
        ++ran;
        std::cout << "[ .. ] " << tc.name << std::endl;
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
            std::cout << std::flush;
        } else {
            std::cout << "[ ok ] " << tc.name << std::endl;
        }
        current() = nullptr;
    }
    std::cout << "\n"
              << ran << " test cases, " << total_checks << " checks, "
              << failed_tests << " failed" << std::endl;
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
