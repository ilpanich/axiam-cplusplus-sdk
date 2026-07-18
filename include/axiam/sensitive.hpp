// §7 Sensitive<T> — token / key material wrapper that never reveals its value
// through any public display, logging, or serialization path.
#pragma once

#include <ostream>
#include <string>
#include <utility>

namespace axiam {

template <typename T>
class Sensitive;  // primary template, defined below

namespace detail {
// Module-private reveal. Not part of the public API surface — SDK internals that
// genuinely need the raw value call this; application code cannot reach it without
// naming the axiam::detail namespace, and it is documented as internal-only.
template <typename T>
const T& reveal(const Sensitive<T>& s) noexcept;
}  // namespace detail

/// Wraps secret material (access tokens, mTLS private keys). Its string / stream
/// representation is always the redacted placeholder "[SENSITIVE]"; the raw value
/// is reachable only through the friend accessor axiam::detail::reveal().
template <typename T>
class Sensitive {
public:
    Sensitive() = default;
    explicit Sensitive(T value) : value_(std::move(value)) {}

    Sensitive(const Sensitive&) = default;
    Sensitive(Sensitive&&) noexcept = default;
    Sensitive& operator=(const Sensitive&) = default;
    Sensitive& operator=(Sensitive&&) noexcept = default;

    /// Redacted textual form. Never emits the wrapped value.
    std::string to_string() const { return "[SENSITIVE]"; }

    /// True when no secret is held (default-constructed / empty string).
    bool empty() const { return is_empty(value_); }

private:
    static bool is_empty(const std::string& v) { return v.empty(); }
    template <typename U>
    static bool is_empty(const U&) { return false; }

    T value_{};

    friend const T& detail::reveal<T>(const Sensitive<T>& s) noexcept;
};

template <typename T>
std::ostream& operator<<(std::ostream& os, const Sensitive<T>& s) {
    return os << s.to_string();
}

namespace detail {
template <typename T>
const T& reveal(const Sensitive<T>& s) noexcept {
    return s.value_;
}
}  // namespace detail

}  // namespace axiam
