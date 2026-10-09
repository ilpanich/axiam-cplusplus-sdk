#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <type_traits>

#include "assert.hpp"
#include "axiam/sensitive.hpp"

using axiam::Sensitive;

AXIAM_TEST("Sensitive redacts to_string") {
    Sensitive<std::string> s("super-secret-token");
    AXIAM_CHECK(s.to_string() == "[SENSITIVE]");
}

AXIAM_TEST("Sensitive redacts in stream output, never leaks value") {
    Sensitive<std::string> s("abc123-refresh");
    std::ostringstream os;
    os << s;
    AXIAM_CHECK(os.str() == "[SENSITIVE]");
    AXIAM_CHECK(os.str().find("abc123") == std::string::npos);
}

AXIAM_TEST("Sensitive raw value reachable only via friend reveal") {
    Sensitive<std::string> s("raw-key-material");
    AXIAM_CHECK(axiam::detail::reveal(s) == "raw-key-material");
}

// §7 rule 3, C++ row: expose() is the single explicit PUBLIC accessor — a named
// call on a const object, returning the very value the wrapper holds (the SDK's
// internal detail::reveal is its module-private equivalent, rule 4).
AXIAM_TEST("§7 rule 3 (R-19): expose() is the public accessor and returns the held value") {
    const std::string raw(24, 'q');
    const Sensitive<std::string> s(raw);
    static_assert(std::is_same<decltype(s.expose()), const std::string&>::value,
                  "expose() returns a const reference, no copy, no conversion");
    AXIAM_CHECK(s.expose() == raw);
    AXIAM_CHECK(&s.expose() == &axiam::detail::reveal(s));
    static_assert(!std::is_convertible<Sensitive<std::string>, std::string>::value,
                  "no implicit reachability (§7 rule 2)");
}

AXIAM_TEST("Sensitive empty() reflects contents") {
    Sensitive<std::string> empty;
    Sensitive<std::string> full("x");
    AXIAM_CHECK(empty.empty());
    AXIAM_CHECK_FALSE(full.empty());
}

// Contract 1.53–1.58 (§28.12.4, §30.5, §31.5, §32.5, §33.5): a secret is not kept
// after it is done with. What is observable from outside is the state the wipe
// leaves: a moved-from or reassigned wrapper holds nothing.
AXIAM_TEST("Sensitive: moving out leaves the source empty, and reassignment replaces the value") {
    Sensitive<std::string> a(std::string(40, 'k'));
    Sensitive<std::string> b(std::move(a));
    AXIAM_CHECK(a.empty());  // NOLINT(bugprone-use-after-move): the wiped state is the point
    AXIAM_CHECK(axiam::detail::reveal(b) == std::string(40, 'k'));

    Sensitive<std::string> c("short");
    c = b;  // copy-assign wipes the old value first
    AXIAM_CHECK(axiam::detail::reveal(c) == std::string(40, 'k'));
    const Sensitive<std::string>& same = c;
    c = same;  // self-assignment keeps the value
    AXIAM_CHECK(axiam::detail::reveal(c) == std::string(40, 'k'));

    Sensitive<std::string> d("old");
    d = std::move(c);
    AXIAM_CHECK(c.empty());  // NOLINT(bugprone-use-after-move)
    AXIAM_CHECK(axiam::detail::reveal(d) == std::string(40, 'k'));
    Sensitive<std::string>& alias = d;
    d = std::move(alias);  // self-move keeps the value
    AXIAM_CHECK(axiam::detail::reveal(d) == std::string(40, 'k'));
}

// CONTRACT.md §7 rule 3 and its C++ row, §28.12.2 rule 5 (contract 1.59 R-19):
// the single public accessor is expose(), and the documentation a caller copies
// from names it — never axiam::detail::reveal, which is internal. The §28.12
// example must show the rotated registration token leaving the wrapper to be
// persisted, not merely re-wrapped in memory.
namespace {
std::string repo_file(const std::string& rel) {
    std::ifstream in(std::string(AXIAM_REPO_ROOT) + "/" + rel, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}
}  // namespace

AXIAM_TEST("§7 rule 3 (R-19): the README and the examples direct callers to expose(), never detail::reveal") {
    const std::string readme = repo_file("README.md");
    AXIAM_REQUIRE(!readme.empty());
    AXIAM_CHECK(readme.find("detail::reveal") == std::string::npos);
    for (const char* ex : {"examples/oidc_login.cpp", "examples/account_lifecycle.cpp",
                           "examples/device_login.cpp", "examples/device_mtls_provisioning.cpp"}) {
        const std::string text = repo_file(ex);
        AXIAM_REQUIRE(!text.empty());
        AXIAM_CHECK(text.find("detail::reveal") == std::string::npos);
    }
    const auto section = readme.find("## §28.12 RFC 7592 client configuration");
    AXIAM_REQUIRE(section != std::string::npos);
    const std::string s2812 = readme.substr(section, readme.find("\n## ", section + 1) - section);
    AXIAM_CHECK(s2812.find("registration_access_token->expose()") != std::string::npos);
}
