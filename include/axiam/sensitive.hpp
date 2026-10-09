// §7 Sensitive<T> — token / key material wrapper that never reveals its value
// through any public display, logging, or serialization path.
#pragma once

#include <cstddef>
#include <ostream>
#include <string>
#include <utility>

namespace axiam {

template <typename T>
class Sensitive;  // primary template, defined below

namespace detail {
// The SDK's module-private equivalent of Sensitive::expose() (CONTRACT.md §7
// rule 4). Not part of the public API surface: SDK internals call it at the
// point of use; application code calls expose().
template <typename T>
const T& reveal(const Sensitive<T>& s) noexcept;
}  // namespace detail

/// Wraps secret material (access tokens, mTLS private keys). Its string / stream
/// representation is always the redacted placeholder "[SENSITIVE]"; the raw value
/// is reachable only through the one explicit, named accessor expose()
/// (CONTRACT.md §7 rule 3 and its C++ row).
///
/// **Wiped on destruction and on reassignment** (contract 1.53–1.58: §28.12.4,
/// §30.5, §31.5, §32.5 and §33.5 each say an SDK must not keep a secret after
/// the request that carried it). The bytes a `Sensitive<std::string>` holds are
/// overwritten through a volatile pointer — which the optimiser may not elide —
/// before the buffer is released. Best effort by construction: a copy a caller
/// took with expose(), or a buffer std::string reallocated away from
/// earlier, is outside this object's reach.
template <typename T>
class Sensitive {
public:
    Sensitive() = default;
    explicit Sensitive(T value) : value_(std::move(value)) {}

    Sensitive(const Sensitive&) = default;
    Sensitive(Sensitive&& other) noexcept : value_(std::move(other.value_)) {
        wipe(other.value_);
    }
    Sensitive& operator=(const Sensitive& other) {
        if (this != &other) {
            wipe(value_);
            value_ = other.value_;
        }
        return *this;
    }
    Sensitive& operator=(Sensitive&& other) noexcept {
        if (this != &other) {
            wipe(value_);
            value_ = std::move(other.value_);
            wipe(other.value_);
        }
        return *this;
    }
    ~Sensitive() { wipe(value_); }

    /// Redacted textual form. Never emits the wrapped value.
    std::string to_string() const { return "[SENSITIVE]"; }

    /// **The single public accessor** (CONTRACT.md §7 rule 3): the raw value,
    /// for the one point where your application must use it — persisting the
    /// rotated §28.12 `registration_access_token`, storing a §12 token set,
    /// writing a one-time `private_key_pem` to its key store. Deliberate and
    /// greppable; never pass the result to a log, trace or serialization sink
    /// (rule 4). The reference lives as long as this object, which wipes the
    /// bytes when it is destroyed or reassigned.
    const T& expose() const noexcept { return value_; }

    /// True when no secret is held (default-constructed / empty string).
    bool empty() const { return is_empty(value_); }

private:
    static bool is_empty(const std::string& v) { return v.empty(); }

    /// Overwrite the held characters, then empty the string.
    static void wipe(std::string& v) noexcept {
        volatile char* p = v.empty() ? nullptr : &v[0];
        for (std::size_t i = 0; i < v.size(); ++i) p[i] = 0;
        v.clear();
    }
    template <typename U>
    static void wipe(U&) noexcept {}

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
