// CONTRACT.md §27.11 rule 5 (contract 1.61, §34.5) -- `Certificate.user_id`:
//
//   * an optional, nullable member of every `Certificate` read (and of
//     `GeneratedCertificate`): a UUID, `null` and an absent member (a server before 1.0.1)
//     each decode, the last two as "no account named" -- never a nil UUID, never taken from
//     `metadata` or the subject;
//   * an optional request member of `certificates.generate` and `certificates.sign_csr`:
//     sent exactly as the caller set it, the key omitted -- not `null` -- when unset.
//
// The SSF half of 1.61 (`SsfStreamInput.expected_updated_at`, §32.8 test 1) is in
// test_ssf_management.cpp. `CibaPendingList` (§33.3 rule 16) is not modelled: no registry
// operation returns it and this SDK drives no console route.

#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include "assert.hpp"
#include "axiam/axiam.hpp"
#include "axiam/management.hpp"
#include "management_json.hpp"
#include "management_test_util.hpp"

namespace {

using namespace axiam;
using namespace axiam::management;
using nlohmann::json;

constexpr const char* kUuid = "11111111-1111-4111-8111-111111111111";
constexpr const char* kUser = "55555555-5555-4555-8555-555555555555";

json certificate_body(const json& extra = json::object()) {
    json body = {{"cert_type", "User"},
                 {"created_at", "2026-10-10T00:00:00Z"},
                 {"fingerprint", "aa:bb"},
                 {"id", kUuid},
                 {"issuer_ca_id", kUuid},
                 {"key_algorithm", "Ed25519"},
                 {"metadata", json::object()},
                 {"not_after", "2027-10-10T00:00:00Z"},
                 {"not_before", "2026-10-10T00:00:00Z"},
                 {"public_cert_pem", "pem"},
                 {"status", "Active"},
                 {"subject", "CN=ada"},
                 {"tenant_id", kUuid}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

CreateCertificateRequest generate_input() {
    CreateCertificateRequest in{};
    in.cert_type = CertificateType::User;
    in.issuer_ca_id = kUuid;
    in.key_algorithm = KeyAlgorithm::Ed25519;
    in.subject = "CN=ada";
    in.validity_days = 30;
    return in;
}

SignCertificateCsrRequest sign_input() {
    SignCertificateCsrRequest in{};
    in.cert_type = CertificateType::User;
    in.csr_pem = "-----BEGIN CERTIFICATE REQUEST-----";
    in.issuer_ca_id = kUuid;
    in.validity_days = 30;
    return in;
}

AXIAM_TEST("§27.11 rule 5 (contract 1.61): generate sends user_id exactly as given and omits the key without one") {
    auto fixture = axtest::mgmt::signed_in_many(
        {{200, certificate_body({{"private_key_pem", "k"}, {"user_id", kUser}}).dump()},
         {200, certificate_body({{"private_key_pem", "k"}}).dump()},
         {200, certificate_body({{"private_key_pem", "k"}}).dump()}});
    auto certificates = fixture.client.management().certificates();

    auto named = generate_input();
    named.user_id = kUser;
    const auto out = certificates.generate(named);
    AXIAM_CHECK(fixture.state->last().method == "POST");
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("user_id") == kUser);
    AXIAM_CHECK(out.user_id == std::optional<std::string>(kUser));

    // Not judged client-side: the server answers 400 for what it refuses.
    auto odd = generate_input();
    odd.user_id = "not-a-uuid";
    certificates.generate(odd);
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("user_id") == "not-a-uuid");

    // Unset: no `user_id` key at all, and in particular not `null`.
    const auto unnamed = certificates.generate(generate_input());
    AXIAM_CHECK(!json::parse(fixture.state->last().body).contains("user_id"));
    AXIAM_CHECK(!unnamed.user_id.has_value());
}

AXIAM_TEST("§27.11 rule 5 (contract 1.61): sign_csr sends user_id exactly as given and omits the key without one") {
    auto fixture = axtest::mgmt::signed_in_many(
        {{200, certificate_body({{"user_id", kUser}}).dump()},
         {200, certificate_body({{"user_id", nullptr}}).dump()}});
    auto certificates = fixture.client.management().certificates();

    auto named = sign_input();
    named.user_id = kUser;
    const auto out = certificates.sign_csr(named);
    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == "/api/v1/certificates/sign-csr");
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("user_id") == kUser);
    AXIAM_CHECK(out.user_id == std::optional<std::string>(kUser));

    certificates.sign_csr(sign_input());
    AXIAM_CHECK(!json::parse(fixture.state->last().body).contains("user_id"));
}

AXIAM_TEST("§27.11 rule 5 (contract 1.61): a Certificate decodes a UUID, a null and an absent user_id") {
    // A UUID.
    const auto named = certificate_body({{"user_id", kUser}}).get<Certificate>();
    AXIAM_CHECK(named.user_id == std::optional<std::string>(kUser));
    // null and absence both mean "no account named" -- not a nil UUID, not a value taken
    // from `metadata` or the subject (which here would name `ada`).
    const auto nulled = certificate_body({{"user_id", nullptr},
                                          {"metadata", {{"user_id", kUser}}}})
                            .get<Certificate>();
    AXIAM_CHECK(!nulled.user_id.has_value());
    const auto absent = certificate_body().get<Certificate>();
    AXIAM_CHECK(!absent.user_id.has_value());

    // The same through the wire on `get`, and on a list page whose items differ.
    auto fixture = axtest::mgmt::signed_in_many(
        {{200, certificate_body({{"user_id", nullptr}}).dump()},
         {200, json{{"items", {certificate_body({{"user_id", kUser}}), certificate_body()}},
                    {"total", 2}}
                   .dump()}});
    auto certificates = fixture.client.management().certificates();
    AXIAM_CHECK(!certificates.get(kUuid).user_id.has_value());
    const auto page = certificates.list();
    AXIAM_CHECK(page.size() == 2);
    AXIAM_CHECK(page.items[0].user_id == std::optional<std::string>(kUser));
    AXIAM_CHECK(!page.items[1].user_id.has_value());
}

}  // namespace
