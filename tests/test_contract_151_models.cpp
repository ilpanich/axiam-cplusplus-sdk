// CONTRACT.md §27.13 (contract 1.51) -- the model changes of the dogfooding remediation,
// pinned the way tests/contract_151_models_test.rs pins them for the Rust reference.
//
// The regenerated types pick up every new field for free (scripts/gen_management.py ran
// against the re-vendored openapi.json/management-registry.json). What a re-vendor does
// NOT pick up for free is whether the GENERATOR got the shape right, and C-1's EXECUTED
// block records that every generator ported so far got two things wrong on first try:
// `SubjectAltName` (an externally-tagged oneOf with no shared discriminator) rendered as
// an empty `{}`, and a role-side listing's REQUIRED `inherit` decoded absence the wrong
// way. This file pins both fixes, plus the pre-existing §27.11 rule 1 open-enum discipline
// applied to the new `CertificateType::Server` value's own open-enum successor.

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

constexpr const char* kUuid = "11111111-1111-4111-8111-111111111111";

// ---------------------------------------------------------------------------
// S-7 rule 2 -- CertificateType decodes an unknown value openly
// ---------------------------------------------------------------------------

std::string certificate_of_type(const std::string& cert_type) {
    return std::string(R"json({"cert_type":")json") + cert_type + R"json(",)json" +
           R"json("created_at":"2026-08-26T00:00:00Z","fingerprint":"aa:bb",)json" +
           R"json("id":")json" + kUuid + R"json(",)json" +
           R"json("issuer_ca_id":")json" + kUuid + R"json(","key_algorithm":"Ed25519",)json" +
           R"json("metadata":{},"not_after":"2027-08-26T00:00:00Z",)json" +
           R"json("not_before":"2026-08-26T00:00:00Z","public_cert_pem":"pem",)json" +
           R"json("status":"Active","subject":"device-001","tenant_id":")json" + kUuid +
           R"json("})json";
}

// One certificate of a type this SDK has never heard of must not take the whole
// `certificates.list` page down with it (CONTRACT.md §27.13 S-7 rule 2). Re-vendoring
// taught this enum `Server`; this is the rule for the value AFTER that -- the one no
// re-vendor will ever anticipate.
AXIAM_TEST("§27.13 S-7 rule 2: certificates.list survives a cert_type this SDK does not know") {
    const std::string body = std::string(R"json({"items":[)json") +
                             certificate_of_type("Device") + "," +
                             certificate_of_type("Server") + "," +
                             certificate_of_type("Gateway") + R"json(],"total":3})json";
    auto fixture = axtest::mgmt::signed_in(200, body);

    const auto page = fixture.client.management().certificates().list();

    AXIAM_CHECK(page.size() == 3);
    AXIAM_CHECK(page.items[0].cert_type == CertificateType::Device);
    // The Server value the re-vendor taught the enum -- decodes to its own enumerator,
    // not to Unknown.
    AXIAM_CHECK(page.items[1].cert_type == CertificateType::Server);
    // A value neither this SDK's copy of the spec nor its enumerator list has ever
    // named: kept as Unknown rather than failing the whole page or being silently
    // read as one of the known values (§27.11 rule 1's discipline, applied here).
    AXIAM_CHECK(page.items[2].cert_type == CertificateType::Unknown);
}

// ---------------------------------------------------------------------------
// S-10 rule 3 -- inherit absent on a subject-side listing means inherits
// ---------------------------------------------------------------------------

// §27.13 draws the line between the ROLE-side listings (`roles.list_users` /
// `list_groups` / `list_service_accounts`, `RoleUserAssignment` etc.) where a
// CONTRACT-1.51 server's `inherit` is REQUIRED, and the SUBJECT-side listings
// (`users.list_roles`, `groups.list_roles`, `service_accounts.list_roles`) which return
// `RoleAssignment`, where it is OPTIONAL and absence means inherits. This pins the
// subject side first, which is where the open-default decode actually has something to
// get wrong; the block below it (S-10 rule 3, role side) pins the same discipline for a
// server that PREDATES the field and so sends nothing on the role-side listings either,
// even though this SDK's copy of the spec marks the wire field required there.
const char* kRoleForAssignment =
    R"json({"created_at":"2026-08-26T00:00:00Z","description":"d",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","is_global":false,)json"
    R"json("name":"auditor","tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"})json";

// A row a server OLDER than contract 1.51 wrote, and a row a current server wrote for an
// inheritable (the default) assignment both omit `inherit` -- the wire is identical either
// way. §27.13 S-10 rule 3: absent MUST read as `true`, never as `false`, or every
// assignment ever made before the field existed turns non-inheritable on this SDK's side
// of the wire the moment it is decoded.
AXIAM_TEST("§27.13 S-10 rule 3: RoleAssignment.inherit absent decodes as inherits() == true") {
    const std::string body = std::string(R"json({"resource_id":null,"role":)json") +
                             kRoleForAssignment + "}";
    auto fixture = axtest::mgmt::signed_in(200, "[" + body + "]");

    const auto listed = fixture.client.management().users().list_roles(kUuid);

    AXIAM_CHECK(listed.size() == 1);
    // The optional itself is disengaged -- the server said nothing -- and reading it
    // any other way than `inherits()` is exactly the trap this pins.
    AXIAM_CHECK(!listed[0].inherit.has_value());
    AXIAM_CHECK(listed[0].inherits() == true);
}

// The explicit-`false` row must not be swallowed by the same default.
AXIAM_TEST("§27.13 S-10 rule 3: RoleAssignment.inherit=false decodes as inherits() == false") {
    const std::string body = std::string(R"json({"inherit":false,"resource_id":")json") +
                             kUuid + R"json(","role":)json" + kRoleForAssignment + "}";
    auto fixture = axtest::mgmt::signed_in(200, "[" + body + "]");

    const auto listed = fixture.client.management().users().list_roles(kUuid);

    AXIAM_CHECK(listed.size() == 1);
    AXIAM_CHECK(listed[0].inherit.has_value());
    AXIAM_CHECK(listed[0].inherits() == false);
}

// ---------------------------------------------------------------------------
// S-10 rule 3 -- inherit absent on a ROLE-side listing also means inherits
// ---------------------------------------------------------------------------

// C-12: `openapi.json` marks `inherit` REQUIRED on the three role-side listings below,
// because a contract-1.51 server always sends it. A server OLDER than 1.51 -- every
// server before it -- sends nothing, same as it always omitted `inherit` on the
// subject-side `RoleAssignment` above. Decoding a required field with `j.at("inherit")`
// throws `nlohmann::detail::out_of_range` on that absence, and `management_transport.hpp`
// surfaces it as a plain `NetworkError` -- so a role's ENTIRE group/user/service-account
// listing fails against a pre-1.51 server, not merely one row of it. §27.13 S-10 rule 3
// governs the role side exactly as it does the subject side: absent MUST read as
// `inherits() == true`.
const char* kGroupForAssignment =
    R"json({"created_at":"2026-08-26T00:00:00Z","description":"d","id":)json"
    R"json("11111111-1111-4111-8111-111111111111","metadata":{},"name":"ops",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"})json";
const char* kServiceAccountForAssignment =
    R"json({"client_id":"c","created_at":"2026-08-26T00:00:00Z","description":"d",)json"
    R"json("id":"11111111-1111-4111-8111-111111111111","name":"svc","status":"Active",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("updated_at":"2026-08-26T00:00:00Z"})json";
const char* kUserForAssignment =
    R"json({"created_at":"2026-08-26T00:00:00Z","email":"a@x","email_verified":true,)json"
    R"json("failed_login_attempts":0,"id":"11111111-1111-4111-8111-111111111111",)json"
    R"json("is_locked":false,"metadata":{},"mfa_enabled":false,"status":"Active",)json"
    R"json("tenant_id":"11111111-1111-4111-8111-111111111111","updated_at":)json"
    R"json("2026-08-26T00:00:00Z","username":"a"})json";

AXIAM_TEST("§27.13 S-10 rule 3: RoleGroupAssignment.inherit absent decodes as "
          "inherits() == true, and does not fail the listing") {
    const std::string body = std::string(R"json({"group":)json") + kGroupForAssignment + "}";
    auto fixture = axtest::mgmt::signed_in(200, "[" + body + "]");

    // Before the fix this threw NetworkError (management_transport.hpp) and never
    // reached the assertions below -- the whole listing failed on one absent field.
    const auto listed = fixture.client.management().roles().list_groups(kUuid);

    AXIAM_CHECK(listed.size() == 1);
    AXIAM_CHECK(!listed[0].inherit.has_value());
    AXIAM_CHECK(listed[0].inherits() == true);
}

AXIAM_TEST("§27.13 S-10 rule 3: RoleGroupAssignment.inherit=false/true decode as stated "
          "(the I4 twin)") {
    {
        const std::string body = std::string(R"json({"group":)json") + kGroupForAssignment +
                                 R"json(,"inherit":false})json";
        auto fixture = axtest::mgmt::signed_in(200, "[" + body + "]");
        const auto listed = fixture.client.management().roles().list_groups(kUuid);
        AXIAM_CHECK(listed.size() == 1);
        AXIAM_CHECK(listed[0].inherit.has_value());
        AXIAM_CHECK(listed[0].inherits() == false);
    }
    {
        const std::string body = std::string(R"json({"group":)json") + kGroupForAssignment +
                                 R"json(,"inherit":true})json";
        auto fixture = axtest::mgmt::signed_in(200, "[" + body + "]");
        const auto listed = fixture.client.management().roles().list_groups(kUuid);
        AXIAM_CHECK(listed.size() == 1);
        AXIAM_CHECK(listed[0].inherit.has_value());
        AXIAM_CHECK(listed[0].inherits() == true);
    }
}

AXIAM_TEST("§27.13 S-10 rule 3: RoleUserAssignment.inherit absent decodes as "
          "inherits() == true, and does not fail the listing") {
    const std::string body = std::string(R"json({"user":)json") + kUserForAssignment + "}";
    auto fixture = axtest::mgmt::signed_in(200, "[" + body + "]");

    const auto listed = fixture.client.management().roles().list_users(kUuid);

    AXIAM_CHECK(listed.size() == 1);
    AXIAM_CHECK(!listed[0].inherit.has_value());
    AXIAM_CHECK(listed[0].inherits() == true);
}

AXIAM_TEST("§27.13 S-10 rule 3: RoleUserAssignment.inherit=false/true decode as stated "
          "(the I4 twin)") {
    {
        const std::string body = std::string(R"json({"user":)json") + kUserForAssignment +
                                 R"json(,"inherit":false})json";
        auto fixture = axtest::mgmt::signed_in(200, "[" + body + "]");
        const auto listed = fixture.client.management().roles().list_users(kUuid);
        AXIAM_CHECK(listed.size() == 1);
        AXIAM_CHECK(listed[0].inherit.has_value());
        AXIAM_CHECK(listed[0].inherits() == false);
    }
    {
        const std::string body = std::string(R"json({"user":)json") + kUserForAssignment +
                                 R"json(,"inherit":true})json";
        auto fixture = axtest::mgmt::signed_in(200, "[" + body + "]");
        const auto listed = fixture.client.management().roles().list_users(kUuid);
        AXIAM_CHECK(listed.size() == 1);
        AXIAM_CHECK(listed[0].inherit.has_value());
        AXIAM_CHECK(listed[0].inherits() == true);
    }
}

AXIAM_TEST("§27.13 S-10 rule 3: RoleServiceAccountAssignment.inherit absent decodes as "
          "inherits() == true, and does not fail the listing") {
    const std::string body =
        std::string(R"json({"service_account":)json") + kServiceAccountForAssignment + "}";
    auto fixture = axtest::mgmt::signed_in(200, "[" + body + "]");

    const auto listed = fixture.client.management().roles().list_service_accounts(kUuid);

    AXIAM_CHECK(listed.size() == 1);
    AXIAM_CHECK(!listed[0].inherit.has_value());
    AXIAM_CHECK(listed[0].inherits() == true);
}

AXIAM_TEST("§27.13 S-10 rule 3: RoleServiceAccountAssignment.inherit=false/true decode "
          "as stated (the I4 twin)") {
    {
        const std::string body = std::string(R"json({"service_account":)json") +
                                 kServiceAccountForAssignment + R"json(,"inherit":false})json";
        auto fixture = axtest::mgmt::signed_in(200, "[" + body + "]");
        const auto listed = fixture.client.management().roles().list_service_accounts(kUuid);
        AXIAM_CHECK(listed.size() == 1);
        AXIAM_CHECK(listed[0].inherit.has_value());
        AXIAM_CHECK(listed[0].inherits() == false);
    }
    {
        const std::string body = std::string(R"json({"service_account":)json") +
                                 kServiceAccountForAssignment + R"json(,"inherit":true})json";
        auto fixture = axtest::mgmt::signed_in(200, "[" + body + "]");
        const auto listed = fixture.client.management().roles().list_service_accounts(kUuid);
        AXIAM_CHECK(listed.size() == 1);
        AXIAM_CHECK(listed[0].inherit.has_value());
        AXIAM_CHECK(listed[0].inherits() == true);
    }
}

// ---------------------------------------------------------------------------
// S-7 rule 1 -- SubjectAltName serializes externally-tagged, never as {}
// ---------------------------------------------------------------------------

// `SubjectAltName` is `{oneOf: [{dns: string}, {ip: string}]}` with no shared
// discriminator field (CONTRACT.md §27.13 S-7 rule 1) -- the externally-tagged shape the
// server's `serde(untagged)` produces. A generator that does not recognise this shape
// either fails to define the type at all (an incomplete-type compile error, since
// `CreateCertificateRequest.subject_alt_names` is `std::vector<SubjectAltName>`) or emits
// an empty struct that serializes as `{}`, which the server rejects as neither a `dns`
// nor an `ip` entry.
AXIAM_TEST("§27.13 S-7 rule 1: SubjectAltName encodes as {\"dns\": ...} XOR {\"ip\": ...}, never {}") {
    SubjectAltName dns{};
    dns.dns = "api.lakeside.internal";
    const nlohmann::json dns_json = dns;
    AXIAM_CHECK(dns_json.size() == 1);
    AXIAM_CHECK(dns_json.at("dns") == "api.lakeside.internal");
    AXIAM_CHECK(dns_json.find("ip") == dns_json.end());

    SubjectAltName ip{};
    ip.ip = "10.0.0.5";
    const nlohmann::json ip_json = ip;
    AXIAM_CHECK(ip_json.size() == 1);
    AXIAM_CHECK(ip_json.at("ip") == "10.0.0.5");
    AXIAM_CHECK(ip_json.find("dns") == ip_json.end());

    // The failure mode this test exists for: an unset SubjectAltName must never reach
    // the wire as `{}` -- that is neither variant, and the server's externally-tagged
    // decoder has no arm for it.
    AXIAM_CHECK(dns_json != nlohmann::json::object());
    AXIAM_CHECK(ip_json != nlohmann::json::object());
}

// CONTRACT 1.52 N3 (C-12): "An SDK whose type can hold neither or both branches MUST
// refuse such a value client-side, before any request, with §27.4 rule 2's error."
// `SubjectAltName` is exactly that type -- two independent `std::optional` members --
// and before this fix `to_json()` silently emitted `{}` for neither and
// `{"dns":..., "ip":...}` for both, instead of refusing either.
AXIAM_TEST("§27.13 / C-12 N3: SubjectAltName with NEITHER dns nor ip is refused "
          "client-side, not serialized as {}") {
    SubjectAltName neither{};
    bool threw = false;
    try {
        const nlohmann::json j = neither;
        (void)j;
    } catch (const NetworkError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
}

AXIAM_TEST("§27.13 / C-12 N3: SubjectAltName with BOTH dns and ip is refused "
          "client-side, not serialized with both keys") {
    SubjectAltName both{};
    both.dns = "api.lakeside.internal";
    both.ip = "10.0.0.5";
    bool threw = false;
    try {
        const nlohmann::json j = both;
        (void)j;
    } catch (const NetworkError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
}

// Round-trips through the request the field actually lives on, exercising the real
// `std::vector<SubjectAltName>` path rather than the bare type alone.
std::string generated_certificate_of_type(const std::string& cert_type) {
    return std::string(R"json({"cert_type":")json") + cert_type + R"json(",)json" +
           R"json("created_at":"2026-08-26T00:00:00Z","fingerprint":"aa:bb",)json" +
           R"json("id":")json" + kUuid + R"json(",)json" +
           R"json("issuer_ca_id":")json" + kUuid + R"json(","key_algorithm":"Ed25519",)json" +
           R"json("metadata":{},"not_after":"2027-08-26T00:00:00Z",)json" +
           R"json("not_before":"2026-08-26T00:00:00Z","private_key_pem":"pem",)json" +
           R"json("public_cert_pem":"pem",)json" +
           R"json("status":"Active","subject":"device-001","tenant_id":")json" + kUuid +
           R"json("})json";
}

// The N3 refusal reached through the real vector<SubjectAltName> path a caller
// actually uses -- a malformed element must not be silently dropped from the list
// (C-12 N3's other clause) or let the request out with a bad element inside it.
AXIAM_TEST("§27.13 / C-12 N3: a malformed SubjectAltName inside "
          "subject_alt_names[] refuses the WHOLE request, zero wire calls") {
    auto fixture = axtest::mgmt::signed_in(200, generated_certificate_of_type("Server"));
    CreateCertificateRequest body{};
    body.cert_type = CertificateType::Server;
    body.issuer_ca_id = kUuid;
    body.key_algorithm = KeyAlgorithm::Ed25519;
    body.subject = "CN=api";
    SubjectAltName good{};
    good.dns = "api.lakeside.internal";
    SubjectAltName bad{};  // neither dns nor ip
    body.subject_alt_names = std::vector<SubjectAltName>{good, bad};

    const auto before = fixture.state->count();
    bool threw = false;
    try {
        fixture.client.management().certificates().generate(body);
    } catch (const NetworkError&) {
        threw = true;
    }
    AXIAM_CHECK(threw);
    AXIAM_CHECK(fixture.state->count() == before);  // never reached the wire
}

AXIAM_TEST("§27.13 S-7 rule 1: CreateCertificateRequest.subject_alt_names reaches the wire "
          "tagged, and is omitted when absent") {
    {
        auto fixture = axtest::mgmt::signed_in(
            200, generated_certificate_of_type("Server"));
        CreateCertificateRequest body{};
        body.cert_type = CertificateType::Server;
        body.issuer_ca_id = kUuid;
        body.key_algorithm = KeyAlgorithm::Ed25519;
        body.subject = "CN=api";
        SubjectAltName san{};
        san.dns = "api.lakeside.internal";
        body.subject_alt_names = std::vector<SubjectAltName>{san};
        fixture.client.management().certificates().generate(body);

        const auto sent = nlohmann::json::parse(fixture.state->last().body);
        AXIAM_CHECK(sent.contains("subject_alt_names"));
        AXIAM_CHECK(sent.at("subject_alt_names").is_array());
        AXIAM_CHECK(sent.at("subject_alt_names").size() == 1);
        const nlohmann::json expected_san = {{"dns", "api.lakeside.internal"}};
        AXIAM_CHECK(sent.at("subject_alt_names")[0] == expected_san);
    }
    // §27.13 S-7 rule 1: "An SDK SHOULD omit the key when it has no names rather than
    // send null or []." No SANs stated -> no key at all on the wire.
    {
        auto fixture = axtest::mgmt::signed_in(
            200, generated_certificate_of_type("Device"));
        CreateCertificateRequest body{};
        body.cert_type = CertificateType::Device;
        body.issuer_ca_id = kUuid;
        body.key_algorithm = KeyAlgorithm::Ed25519;
        body.subject = "CN=device-1";
        fixture.client.management().certificates().generate(body);

        const auto sent = nlohmann::json::parse(fixture.state->last().body);
        AXIAM_CHECK(!sent.contains("subject_alt_names"));
    }
    // C-12 N3: an ENGAGED but EMPTY vector -- built from a filtered collection with
    // nothing left in it, say -- is not "no SANs stated"; it is "state a zero-element
    // SAN list", which §27.13 defines no server meaning for. Before this fix, the
    // ordinary `if (value.subject_alt_names)` optional guard let an engaged empty
    // vector reach the wire as `"subject_alt_names":[]`.
    {
        auto fixture = axtest::mgmt::signed_in(
            200, generated_certificate_of_type("Device"));
        CreateCertificateRequest body{};
        body.cert_type = CertificateType::Device;
        body.issuer_ca_id = kUuid;
        body.key_algorithm = KeyAlgorithm::Ed25519;
        body.subject = "CN=device-2";
        body.subject_alt_names = std::vector<SubjectAltName>{};  // engaged, empty
        fixture.client.management().certificates().generate(body);

        const auto sent = nlohmann::json::parse(fixture.state->last().body);
        AXIAM_CHECK(!sent.contains("subject_alt_names"));
    }
}

}  // namespace
