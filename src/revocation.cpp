#include "axiam/revocation.hpp"

#include <openssl/evp.h>

#include <array>
#include <nlohmann/json.hpp>

namespace axiam {
namespace {

using json = nlohmann::json;

/// The only digest the feed publishes, and the only one this poller accepts.
///
/// A document naming anything else is treated as unusable — exactly as an
/// unreachable feed is — rather than as a list of entries that happen not to
/// match. Silently matching nothing is how a guard ends up reporting that it
/// honours revocations while honouring none.
constexpr const char* kSupportedAlg = "SHA-256";

std::string strip_trailing_slash(std::string url) {
    while (!url.empty() && url.back() == '/') url.pop_back();
    return url;
}

}  // namespace

std::string revocation_entry_for(const std::string& sid) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return {};
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, sid.data(), sid.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || digest_len != 32) return {};

    // Base64url WITHOUT padding, exactly as certificate_thumbprint_s256 does
    // and for the same reason: a padded value would not compare equal to what
    // the server published. A 32-byte digest encodes to 43 characters.
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve(43);
    for (unsigned int i = 0; i < digest_len; i += 3) {
        const unsigned int remaining = digest_len - i;
        unsigned int v = static_cast<unsigned int>(digest[i]) << 16;
        if (remaining > 1) v |= static_cast<unsigned int>(digest[i + 1]) << 8;
        if (remaining > 2) v |= static_cast<unsigned int>(digest[i + 2]);

        out.push_back(kAlphabet[(v >> 18) & 0x3f]);
        out.push_back(kAlphabet[(v >> 12) & 0x3f]);
        if (remaining > 1) out.push_back(kAlphabet[(v >> 6) & 0x3f]);
        if (remaining > 2) out.push_back(kAlphabet[v & 0x3f]);
    }
    return out;
}

RevocationFeed::RevocationFeed(Transport transport, std::string base_url,
                               std::chrono::seconds poll_interval)
    : transport_(std::move(transport)),
      feed_url_(strip_trailing_slash(std::move(base_url)) + kRevocationFeedPath),
      poll_interval_(poll_interval < kMinRevocationPollInterval ? kMinRevocationPollInterval
                                                                : poll_interval) {}

void RevocationFeed::set_clock_for_testing(ClockFn clock) {
    std::lock_guard<std::mutex> lock(mtx_);
    clock_ = std::move(clock);
}

std::chrono::steady_clock::time_point RevocationFeed::now() const {
    if (clock_) return clock_();
    return std::chrono::steady_clock::now();
}

bool RevocationFeed::is_revoked(const std::string& sid) {
    if (sid.empty()) return false;
    refresh_if_stale();

    const std::string entry = revocation_entry_for(sid);
    std::lock_guard<std::mutex> lock(mtx_);
    // A disengaged set means "never successfully fetched" and is deliberately
    // distinct from a fetched-but-empty document; both answer "not revoked",
    // but only the second is an assertion about the deployment.
    return entries_.has_value() && entries_->count(entry) != 0;
}

void RevocationFeed::refresh() {
    // Serializes refreshers, so a burst of guards that all notice the cache is
    // stale produces one fetch rather than one each — the same shape as
    // JwksVerifier's refresh lock, and for the same reason.
    std::lock_guard<std::mutex> fetch_lock(fetch_mtx_);
    std::optional<std::unordered_set<std::string>> fetched = fetch_once();

    std::lock_guard<std::mutex> lock(mtx_);
    last_attempt_ = now();
    if (fetched.has_value()) entries_ = std::move(fetched);
    // On failure the previous set is deliberately left in place: a blip must not
    // un-revoke a session the guard already knows about.
}

void RevocationFeed::refresh_if_stale() {
    {
        std::lock_guard<std::mutex> lock(mtx_);
        // Attempt, not success: a feed that is down must not be retried on every
        // request, which would put the request path back on the network — the
        // cost §10.4 exists to avoid.
        if (last_attempt_.has_value() && now() - *last_attempt_ < poll_interval_) return;
    }
    refresh();
}

std::optional<std::unordered_set<std::string>> RevocationFeed::fetch_once() {
    HttpRequest request;
    request.method = "GET";
    request.url = feed_url_;

    HttpResponse response;
    try {
        response = transport_(request);
    } catch (...) {
        // Every failure mode is the same answer, deliberately: an unreachable
        // host, a throwing transport, a malformed body. Reporting them apart
        // would invite a caller to treat one of them as a denial.
        return std::nullopt;
    }
    if (!response.transport_error.empty() || response.status != 200) return std::nullopt;

    const json document = json::parse(response.body, nullptr, /*allow_exceptions=*/false);
    if (document.is_discarded() || !document.is_object()) return std::nullopt;
    if (!document.contains("alg") || !document.at("alg").is_string() ||
        document.at("alg").get<std::string>() != kSupportedAlg) {
        return std::nullopt;
    }
    if (!document.contains("revoked") || !document.at("revoked").is_array()) return std::nullopt;

    const json& revoked = document.at("revoked");
    if (revoked.size() > kMaxRevocationEntries) return std::nullopt;

    std::unordered_set<std::string> entries;
    entries.reserve(revoked.size());
    for (const auto& entry : revoked) {
        if (entry.is_string()) entries.insert(entry.get<std::string>());
    }
    return entries;
}

}  // namespace axiam
