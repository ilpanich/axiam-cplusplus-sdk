// T-145 / CONTRACT §13 — webhook signature verification.
//
// Every expected signature in this file is computed here from the spec
// (HMAC-SHA256 over "<t>.<raw_body>", hex lowercase) rather than pasted in, so
// the tests pin the algorithm rather than a transcription of it. The shared
// cross-SDK vector at the bottom is the pin that all eleven SDKs agree on.
#include <openssl/hmac.h>

#include <string>

#include "assert.hpp"
#include "axiam/webhook.hpp"

using namespace axiam;
namespace wh = axiam::webhook;

namespace {

constexpr std::int64_t kNow = 1785700000;

wh::Options at(std::int64_t now) {
    wh::Options o;
    o.now = [now] { return now; };
    return o;
}

/// Reference implementation of the server's algorithm, used to build fixtures.
std::string hmac_hex(const std::string& secret, const std::string& message) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(message.data()), message.size(), mac, &len);
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(hex[mac[i] >> 4]);
        out.push_back(hex[mac[i] & 0x0F]);
    }
    return out;
}

std::string sign_header(const std::string& secret, std::int64_t timestamp,
                        const std::string& body) {
    const std::string t = std::to_string(timestamp);
    return "t=" + t + ",v1=" + hmac_hex(secret, t + "." + body);
}

const char* kSecret = "whsec_test_0123456789abcdef";
const char* kBody = R"({"event":"user.created","id":"01JQ0000000000000000000000"})";

}  // namespace

AXIAM_TEST("webhook: valid signature and fresh timestamp is accepted") {
    wh::Options o = at(kNow + 5);
    o.event_type = "user.created";
    o.delivery_id = "01JQDELIVERY";

    wh::Result r = wh::verify(Sensitive<std::string>(kSecret), sign_header(kSecret, kNow, kBody),
                              kBody, o);
    AXIAM_REQUIRE(r.ok);
    AXIAM_CHECK(static_cast<bool>(r));
    AXIAM_CHECK(r.error == wh::VerifyError::kNone);
    AXIAM_CHECK(r.event.timestamp == kNow);
    AXIAM_CHECK(r.event.event_type == "user.created");
    AXIAM_CHECK(r.event.delivery_id == "01JQDELIVERY");
    AXIAM_CHECK(r.event.body == kBody);
}

AXIAM_TEST("webhook: a body tampered by one byte is rejected") {
    const std::string header = sign_header(kSecret, kNow, kBody);
    std::string tampered = kBody;
    tampered[tampered.size() - 3] = (tampered[tampered.size() - 3] == '0') ? '1' : '0';
    AXIAM_REQUIRE(tampered != kBody);

    wh::Result r = wh::verify(Sensitive<std::string>(kSecret), header, tampered, at(kNow));
    AXIAM_CHECK_FALSE(r.ok);
    AXIAM_CHECK(r.error == wh::VerifyError::kSignatureMismatch);
}

AXIAM_TEST("webhook: the wrong secret is rejected") {
    const std::string header = sign_header(kSecret, kNow, kBody);
    wh::Result r =
        wh::verify(Sensitive<std::string>("whsec_test_wrong_secret_value"), header, kBody, at(kNow));
    AXIAM_CHECK_FALSE(r.ok);
    AXIAM_CHECK(r.error == wh::VerifyError::kSignatureMismatch);
}

AXIAM_TEST("webhook: a stale timestamp is rejected, and the boundary is inclusive") {
    const std::string header = sign_header(kSecret, kNow, kBody);
    // Default tolerance is 300s.
    AXIAM_CHECK(wh::verify(Sensitive<std::string>(kSecret), header, kBody, at(kNow + 300)).ok);
    wh::Result stale =
        wh::verify(Sensitive<std::string>(kSecret), header, kBody, at(kNow + 301));
    AXIAM_CHECK_FALSE(stale.ok);
    AXIAM_CHECK(stale.error == wh::VerifyError::kTimestampOutOfTolerance);
}

AXIAM_TEST("webhook: a future timestamp beyond tolerance is rejected") {
    const std::string header = sign_header(kSecret, kNow, kBody);
    // The delivery claims to be 301s in the future relative to our clock.
    AXIAM_CHECK(wh::verify(Sensitive<std::string>(kSecret), header, kBody, at(kNow - 300)).ok);
    wh::Result future =
        wh::verify(Sensitive<std::string>(kSecret), header, kBody, at(kNow - 301));
    AXIAM_CHECK_FALSE(future.ok);
    AXIAM_CHECK(future.error == wh::VerifyError::kTimestampOutOfTolerance);
}

AXIAM_TEST("webhook: a custom tolerance is honoured") {
    const std::string header = sign_header(kSecret, kNow, kBody);
    wh::Options tight = at(kNow + 30);
    tight.tolerance = std::chrono::seconds(10);
    AXIAM_CHECK_FALSE(wh::verify(Sensitive<std::string>(kSecret), header, kBody, tight).ok);

    wh::Options loose = at(kNow + 30);
    loose.tolerance = std::chrono::seconds(60);
    AXIAM_CHECK(wh::verify(Sensitive<std::string>(kSecret), header, kBody, loose).ok);

    wh::Options negative = at(kNow);
    negative.tolerance = std::chrono::seconds(-1);
    AXIAM_CHECK_FALSE(wh::verify(Sensitive<std::string>(kSecret), header, kBody, negative).ok);
}

AXIAM_TEST("webhook: malformed signature headers are rejected") {
    const std::string good_v1 = hmac_hex(kSecret, std::to_string(kNow) + "." + std::string(kBody));
    auto v = [&](const std::string& header) {
        return wh::verify(Sensitive<std::string>(kSecret), header, kBody, at(kNow));
    };

    // Empty header.
    AXIAM_CHECK(v("").error == wh::VerifyError::kMalformedHeader);
    AXIAM_CHECK(v("   ").error == wh::VerifyError::kMalformedHeader);
    // No v1 at all — "nothing to verify" must never be success.
    AXIAM_CHECK(v("t=" + std::to_string(kNow)).error == wh::VerifyError::kMissingSignature);
    // Only an unknown scheme present.
    AXIAM_CHECK(v("t=" + std::to_string(kNow) + ",v9=deadbeef").error ==
                wh::VerifyError::kMissingSignature);
    // No t.
    AXIAM_CHECK(v("v1=" + good_v1).error == wh::VerifyError::kMalformedHeader);
    // Duplicate t.
    AXIAM_CHECK(v("t=1,t=2,v1=" + good_v1).error == wh::VerifyError::kMalformedHeader);
    // Element with no '='.
    AXIAM_CHECK(v("t=" + std::to_string(kNow) + ",garbage").error ==
                wh::VerifyError::kMalformedHeader);
    // Empty v1 value.
    AXIAM_CHECK(v("t=" + std::to_string(kNow) + ",v1=").error == wh::VerifyError::kMalformedHeader);
    // Non-numeric / signed / non-integral t.
    AXIAM_CHECK(v("t=abc,v1=" + good_v1).error == wh::VerifyError::kMalformedTimestamp);
    AXIAM_CHECK(v("t=-5,v1=" + good_v1).error == wh::VerifyError::kMalformedTimestamp);
    AXIAM_CHECK(v("t=17857000.5,v1=" + good_v1).error == wh::VerifyError::kMalformedTimestamp);
    // t that overflows int64.
    AXIAM_CHECK(v("t=99999999999999999999999,v1=" + good_v1).error ==
                wh::VerifyError::kMalformedTimestamp);
}

AXIAM_TEST("webhook: bad hex in v1 fails closed") {
    const std::string t = std::to_string(kNow);
    auto v = [&](const std::string& v1) {
        return wh::verify(Sensitive<std::string>(kSecret), "t=" + t + ",v1=" + v1, kBody, at(kNow));
    };
    // Odd length, non-hex characters, and a correct-looking but short MAC.
    AXIAM_CHECK(v("abc").error == wh::VerifyError::kSignatureMismatch);
    AXIAM_CHECK(v("zzzz").error == wh::VerifyError::kSignatureMismatch);
    AXIAM_CHECK(v("deadbeef").error == wh::VerifyError::kSignatureMismatch);
}

AXIAM_TEST("webhook: an empty secret fails closed") {
    const std::string header = sign_header("", kNow, kBody);
    wh::Result r = wh::verify(Sensitive<std::string>(""), header, kBody, at(kNow));
    AXIAM_CHECK_FALSE(r.ok);
    AXIAM_CHECK(r.error == wh::VerifyError::kEmptySecret);
}

AXIAM_TEST("webhook: unknown keys and multiple v1 values are handled") {
    const std::string t = std::to_string(kNow);
    const std::string good = hmac_hex(kSecret, t + "." + std::string(kBody));
    const std::string bad(64, 'a');

    // Forward compatibility: an unknown key alongside a good v1 is ignored.
    AXIAM_CHECK(wh::verify(Sensitive<std::string>(kSecret),
                           "t=" + t + ",v2=whatever,v1=" + good, kBody, at(kNow))
                    .ok);
    // Key rotation: several v1 values, one of which matches — in either order.
    AXIAM_CHECK(wh::verify(Sensitive<std::string>(kSecret), "t=" + t + ",v1=" + bad + ",v1=" + good,
                           kBody, at(kNow))
                    .ok);
    AXIAM_CHECK(wh::verify(Sensitive<std::string>(kSecret), "t=" + t + ",v1=" + good + ",v1=" + bad,
                           kBody, at(kNow))
                    .ok);
    // None matching is still a rejection.
    AXIAM_CHECK_FALSE(
        wh::verify(Sensitive<std::string>(kSecret), "t=" + t + ",v1=" + bad + ",v1=" + bad, kBody,
                   at(kNow))
            .ok);
    // Whitespace around elements is tolerated (Stripe-style headers are often
    // emitted with spaces after the comma).
    AXIAM_CHECK(
        wh::verify(Sensitive<std::string>(kSecret), " t=" + t + " , v1=" + good + " ", kBody, at(kNow))
            .ok);
}

AXIAM_TEST("webhook: X-Axiam-Timestamp must agree with the signed t= when supplied") {
    const std::string header = sign_header(kSecret, kNow, kBody);

    wh::Options matching = at(kNow);
    matching.timestamp_header = std::to_string(kNow);
    AXIAM_CHECK(wh::verify(Sensitive<std::string>(kSecret), header, kBody, matching).ok);

    wh::Options mismatched = at(kNow);
    mismatched.timestamp_header = std::to_string(kNow + 1);
    wh::Result r = wh::verify(Sensitive<std::string>(kSecret), header, kBody, mismatched);
    AXIAM_CHECK_FALSE(r.ok);
    AXIAM_CHECK(r.error == wh::VerifyError::kTimestampHeaderMismatch);
}

AXIAM_TEST("webhook: plain-string secret overload and the throwing twin") {
    const std::string header = sign_header(kSecret, kNow, kBody);
    AXIAM_CHECK(wh::verify(std::string(kSecret), header, kBody, at(kNow)).ok);

    wh::Event ev = wh::verify_or_throw(Sensitive<std::string>(kSecret), header, kBody, at(kNow));
    AXIAM_CHECK(ev.timestamp == kNow);

    AXIAM_REQUIRE_THROWS_AS(
        wh::verify_or_throw(Sensitive<std::string>("nope"), header, kBody, at(kNow)),
        wh::VerifyException);
    // The typed error is reachable, and no message leaks the expected MAC.
    try {
        wh::verify_or_throw(Sensitive<std::string>("nope"), header, kBody, at(kNow));
        AXIAM_CHECK(false);
    } catch (const wh::VerifyException& e) {
        AXIAM_CHECK(e.error() == wh::VerifyError::kSignatureMismatch);
        const std::string msg = e.what();
        AXIAM_CHECK(msg.find(hmac_hex(kSecret, std::to_string(kNow) + "." + kBody)) ==
                    std::string::npos);
        AXIAM_CHECK(msg.find(kSecret) == std::string::npos);
    }
}

AXIAM_TEST("webhook: error strings are stable and secret-free") {
    AXIAM_CHECK(std::string(wh::to_string(wh::VerifyError::kNone)) == "ok");
    for (auto e : {wh::VerifyError::kEmptySecret, wh::VerifyError::kMalformedHeader,
                   wh::VerifyError::kMissingSignature, wh::VerifyError::kMalformedTimestamp,
                   wh::VerifyError::kTimestampHeaderMismatch, wh::VerifyError::kSignatureMismatch,
                   wh::VerifyError::kTimestampOutOfTolerance}) {
        const std::string msg = wh::to_string(e);
        AXIAM_CHECK(msg.rfind("webhook_verify_failed", 0) == 0);
    }
    wh::Result r;
    r.error = wh::VerifyError::kSignatureMismatch;
    AXIAM_CHECK(std::string(r.error_message()).find("signature does not match") !=
                std::string::npos);
    // Defensive fallback for a value outside the enumeration.
    AXIAM_CHECK(std::string(wh::to_string(static_cast<wh::VerifyError>(9999))) ==
                "webhook_verify_failed");
}

AXIAM_TEST("webhook: falls back to the system clock when no now() is injected") {
    const std::int64_t real_now = static_cast<std::int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());

    // Default Options: no `now` seam, default 300s tolerance.
    AXIAM_CHECK(wh::verify(Sensitive<std::string>(kSecret), sign_header(kSecret, real_now, kBody),
                           kBody)
                    .ok);
    // An hour old, against the real clock.
    wh::Result stale = wh::verify(Sensitive<std::string>(kSecret),
                                  sign_header(kSecret, real_now - 3600, kBody), kBody);
    AXIAM_CHECK_FALSE(stale.ok);
    AXIAM_CHECK(stale.error == wh::VerifyError::kTimestampOutOfTolerance);
}

// ---------------------------------------------------------------------------
// Cross-SDK pin. Same (secret, timestamp, body) vector in all eleven SDKs; the
// expected v1 is computed here from the spec, not copied from it.
// ---------------------------------------------------------------------------
AXIAM_TEST("webhook: shared cross-SDK fixture round-trips") {
    const std::string secret = "whsec_test_0123456789abcdef";
    const std::int64_t timestamp = 1785700000;
    const std::string body = R"({"event":"user.created","id":"01JQ0000000000000000000000"})";
    const std::string signed_payload = "1785700000." + body;
    const std::string v1 = hmac_hex(secret, signed_payload);

    AXIAM_CHECK(v1.size() == 64);
    const std::string header = "t=1785700000,v1=" + v1;

    wh::Options o = at(timestamp);
    o.timestamp_header = "1785700000";
    wh::Result r = wh::verify(Sensitive<std::string>(secret), header, body, o);
    AXIAM_REQUIRE(r.ok);
    AXIAM_CHECK(r.event.timestamp == timestamp);

    // The same vector with one body byte flipped must be rejected.
    std::string flipped = body;
    flipped[flipped.size() - 2] = '1';
    AXIAM_CHECK_FALSE(wh::verify(Sensitive<std::string>(secret), header, flipped, o).ok);
}
