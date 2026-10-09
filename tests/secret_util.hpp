// Run-time secrets for the contract 1.53–1.58 suites, and the redaction check.
//
// No credential, key or token literal appears in those suites: every secret is
// drawn here at run time, so a fixture cannot share a value with the code under
// test and a redaction test cannot pass by coincidence.
#pragma once

#include <openssl/rand.h>

#include <cstddef>
#include <string>

namespace axtest {

/// `bytes` CSPRNG bytes as lower-case hex, behind a fixed prefix.
inline std::string random_secret(const char* prefix = "s-", std::size_t bytes = 20) {
    unsigned char raw[64] = {0};
    if (bytes > sizeof(raw)) bytes = sizeof(raw);
    RAND_bytes(raw, static_cast<int>(bytes));
    static const char* kHex = "0123456789abcdef";
    std::string out = prefix;
    for (std::size_t i = 0; i < bytes; ++i) {
        out.push_back(kHex[raw[i] >> 4]);
        out.push_back(kHex[raw[i] & 0xF]);
    }
    return out;
}

/// True when no 8-character substring of `secret` occurs in `haystack`.
///
/// Returns a bool rather than asserting, and the suites wrap it in
/// AXIAM_CHECK, whose failure message is the EXPRESSION text: a failing
/// redaction test must never print the secret, a fragment of it, or the
/// rendering it was found in (CodeQL's cleartext-logging finding).
inline bool no_fragment(const std::string& haystack, const std::string& secret) {
    if (secret.size() < 8) return haystack.find(secret) == std::string::npos;
    for (std::size_t i = 0; i + 8 <= secret.size(); ++i) {
        if (haystack.find(secret.substr(i, 8)) != std::string::npos) return false;
    }
    return true;
}

}  // namespace axtest
