// CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access
// tokens (contract 1.15, RFC 8705 §3 / RFC 7800).
//
// A token carrying `cnf` is not a bearer token and must not be accepted as one.
// Three negatives and one positive — and the POSITIVE is the one that matters
// most: rule 9 must not become "every caller must present a certificate", which
// would break every deployment that does not use mTLS at all.

#include <optional>
#include <string>

#include "assert.hpp"
#include "axiam/jwks.hpp"

using namespace axiam;

namespace {

// A real 43-character base64url x5t#S256, and a different one.
const std::string kThumbprint = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const std::string kOtherThumbprint = "bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18";

const std::string kUnbound = R"({"sub":"u","tenant_id":"t","exp":9999999999})";
const std::string kBound =
    R"({"sub":"u","tenant_id":"t","exp":9999999999,)"
    R"("cnf":{"x5t#S256":"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}})";
// A cnf naming a method this SDK cannot check — a DPoP jkt.
const std::string kDpopish =
    R"({"sub":"u","tenant_id":"t","exp":9999999999,)"
    R"("cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}})";

}  // namespace

// The regression test that keeps rule 9 from becoming a certificate mandate.
AXIAM_TEST("rule 9: an unbound token is accepted with or without a certificate") {
    AXIAM_CHECK(verify_certificate_binding(kUnbound, std::nullopt));
    AXIAM_CHECK(verify_certificate_binding(kUnbound, kThumbprint));
}

AXIAM_TEST("rule 9: a bound token is accepted with its own certificate") {
    AXIAM_CHECK(verify_certificate_binding(kBound, kThumbprint));
}

AXIAM_TEST("rule 9: a bound token is rejected with no certificate") {
    AXIAM_CHECK(!verify_certificate_binding(kBound, std::nullopt));
    AXIAM_CHECK(!verify_certificate_binding(kBound, std::string("")));
}

AXIAM_TEST("rule 9: a bound token is rejected with a different certificate") {
    AXIAM_CHECK(!verify_certificate_binding(kBound, kOtherThumbprint));
}

// The subtle one. A cnf naming a confirmation method this SDK cannot check is
// an UNVERIFIABLE constraint, never NO constraint — read the other way, a
// sender-constrained token silently degrades to a bearer token the day a newer
// AXIAM issues a confirmation this SDK predates.
AXIAM_TEST("rule 9: an unverifiable confirmation is rejected, not ignored") {
    AXIAM_CHECK(!verify_certificate_binding(kDpopish, std::nullopt));
    AXIAM_CHECK(!verify_certificate_binding(kDpopish, kThumbprint));
}

AXIAM_TEST("rule 9: malformed input fails closed") {
    AXIAM_CHECK(!verify_certificate_binding("not json", kThumbprint));
    AXIAM_CHECK(!verify_certificate_binding(R"({"cnf":"a string"})", kThumbprint));
    AXIAM_CHECK(!verify_certificate_binding(R"({"cnf":{"x5t#S256":""}})", kThumbprint));
    AXIAM_CHECK(!verify_certificate_binding(R"({"cnf":{"x5t#S256":42}})", kThumbprint));
}

// RFC 7515 §2 base64url: unpadded, '-'/'_' rather than '+'/'/'. A padded or
// standard-base64 value will not compare equal to what AXIAM put in the token.
AXIAM_TEST("rule 9: the thumbprint helper produces unpadded base64url") {
    const std::string der(512, '\x42');
    const std::string tp = certificate_thumbprint_s256(der);

    AXIAM_CHECK(tp.size() == 43);
    AXIAM_CHECK(tp.find('=') == std::string::npos);
    AXIAM_CHECK(tp.find('+') == std::string::npos);
    AXIAM_CHECK(tp.find('/') == std::string::npos);
    AXIAM_CHECK(tp == certificate_thumbprint_s256(der));

    // A different certificate must produce a different thumbprint.
    std::string other_der = der;
    other_der[0] = '\x43';
    AXIAM_CHECK(tp != certificate_thumbprint_s256(other_der));
}


// A `cnf` naming BOTH a certificate and a DPoP key is a CONJUNCTION (contract
// 1.16): both constraints must hold. This SDK declines §21.7.2 proof
// verification (§21.9), so it can establish one half and must not answer for
// the whole.
//
// The regression this guards: accepting on the matching certificate alone —
// "check whichever we can" — would let a caller holding the certificate but NOT
// the DPoP key through a door the operator bolted twice.
AXIAM_TEST("rule 9: a both-bound token is refused even with the right certificate") {
    const std::string both =
        R"({"cnf":{"x5t#S256":")" + kThumbprint +
        R"(","jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}})";

    AXIAM_CHECK(!verify_certificate_binding(both, kThumbprint));
    AXIAM_CHECK(!verify_certificate_binding(both, std::nullopt));
}

// The pure-DPoP case: this SDK declines §21.7.2, so a jkt-bound token is
// REJECTED rather than accepted as a bearer token. That rejection is the first
// of the three obligations §21.7.3 attaches to declining.
AXIAM_TEST("rule 9: a jkt-bound token is refused, not read as unbound") {
    const std::string dpop_bound =
        R"({"cnf":{"jkt":"0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"}})";

    AXIAM_CHECK(!verify_certificate_binding(dpop_bound, kThumbprint));
    AXIAM_CHECK(!verify_certificate_binding(dpop_bound, std::nullopt));
}
