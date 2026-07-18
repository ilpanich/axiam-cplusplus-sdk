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
