#include <sstream>
#include <string>

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
