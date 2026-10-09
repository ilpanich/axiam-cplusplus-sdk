// CONTRACT.md §29 (contract 1.55) — the `saml` management namespace: §29.8's
// eight required tests, against the management rig's fake transport.

#include <string>
#include <type_traits>

#include <nlohmann/json.hpp>

#include "assert.hpp"
#include "axiam/axiam.hpp"
#include "axiam/management.hpp"
#include "management_json.hpp"
#include "management_test_util.hpp"
#include "secret_util.hpp"

using namespace axiam;
using namespace axiam::management;
using nlohmann::json;

namespace {

const std::string kSaml = "/api/v1/tenants/11111111-1111-4111-8111-111111111111/saml";

json sp_body(const json& extra = json::object()) {
    json body = {{"id", "aaaaaaaa-1111-4111-8111-111111111111"},
                 {"tenant_id", "11111111-1111-4111-8111-111111111111"},
                 {"enabled", true},
                 {"display_name", "Payroll"},
                 {"entity_id", "https://payroll.example.com/sp"},
                 {"acs_urls",
                  {{{"url", "https://payroll.example.com/acs"}, {"binding", "http_post"},
                    {"index", 0}, {"is_default", true}}}},
                 {"slo_url", nullptr},
                 {"slo_binding", nullptr},
                 {"name_id_format", "persistent"},
                 {"sign_responses", true},
                 {"encrypt_assertions", false},
                 {"sp_signing_cert_pem", nullptr},
                 {"sp_encryption_cert_pem", nullptr},
                 {"want_authn_requests_signed", false},
                 {"allow_idp_initiated", false},
                 {"attribute_mappings",
                  {{{"saml_name", "email"}, {"name_format", nullptr}, {"source", "email"}}}},
                 {"allowed_groups", json::array()},
                 {"created_at", "2026-10-04T00:00:00Z"},
                 {"updated_at", "2026-10-04T00:00:00Z"}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

json credential_body(const char* status) {
    return {{"id", "cccccccc-1111-4111-8111-111111111111"},
            {"tenant_id", "11111111-1111-4111-8111-111111111111"},
            {"issuer_ca_id", "dddddddd-1111-4111-8111-111111111111"},
            {"certificate_pem", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"},
            {"serial", "0a1b"},
            {"fingerprint", "ab12"},
            {"not_before", "2026-10-01T00:00:00Z"},
            {"not_after", "2027-10-01T00:00:00Z"},
            {"status", status},
            {"created_at", "2026-10-01T00:00:00Z"},
            {"retired_at", nullptr}};
}

SamlServiceProviderInput input() {
    AcsEndpoint acs;
    acs.url = "https://payroll.example.com/acs";
    acs.binding = SamlBinding::HttpPost;
    acs.index = 0;
    return SamlServiceProviderInput("Payroll", "https://payroll.example.com/sp", {acs});
}

template <typename T, typename = void>
struct has_private_key_pem : std::false_type {};
template <typename T>
struct has_private_key_pem<T, std::void_t<decltype(std::declval<T>().private_key_pem)>>
    : std::true_type {};
template <typename T, typename = void>
struct has_sign_assertions : std::false_type {};
template <typename T>
struct has_sign_assertions<T, std::void_t<decltype(std::declval<T>().sign_assertions)>>
    : std::true_type {};

static_assert(!has_private_key_pem<SamlIdpCredential>::value, "§29.2: no key member");
static_assert(!has_sign_assertions<SamlServiceProvider>::value &&
                  !has_sign_assertions<SamlServiceProviderInput>::value,
              "§29.2: the assertion is signed always; there is no switch");

template <typename E, typename F>
std::string what_of(F&& f) {
    try {
        f();
    } catch (const E& e) {
        return std::string("caught:") + e.what();
    } catch (...) {
        return "other";
    }
    return "none";
}

// ── 1. Replacement ──────────────────────────────────────────────────────────

AXIAM_TEST("§29.8 (1): update_service_provider PUTs the whole registration and decodes the 200") {
    auto fixture = axtest::mgmt::signed_in(200, sp_body({{"display_name", "Payroll (EU)"}}).dump());
    auto body = sp_body().get<SamlServiceProvider>().to_input();
    body.display_name = "Payroll (EU)";
    const auto sp = fixture.client.saml().update_service_provider("sp-1", body);
    AXIAM_CHECK(sp.display_name == "Payroll (EU)");
    AXIAM_CHECK(fixture.state->last().method == "PUT");
    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == kSaml + "/service-providers/sp-1");
    const auto sent = json::parse(fixture.state->last().body);
    for (const char* member :
         {"acs_urls", "allow_idp_initiated", "allowed_groups", "attribute_mappings", "display_name",
          "enabled", "encrypt_assertions", "entity_id", "name_id_format", "sign_responses",
          "want_authn_requests_signed"}) {
        AXIAM_CHECK(sent.contains(member));
    }
    // The input cannot be built without display_name, entity_id and acs_urls (the
    // R-27 trait test below); built with them, all three are always serialized.
    const json bare = input();
    AXIAM_CHECK(bare.contains("display_name") && bare.contains("entity_id") && bare.contains("acs_urls"));
}

// ── 2. No signing switch, open decoding ─────────────────────────────────────

AXIAM_TEST("§29.8 (2): sign_assertions does not exist, and unknown members and values decode") {
    json body = sp_body({{"sign_assertions", false}, {"some_future_member", 1}});
    body["acs_urls"][0]["binding"] = "http_artifact";
    body["name_id_format"] = "transient";
    body["attribute_mappings"][0]["source"] = "department";
    auto fixture = axtest::mgmt::signed_in_two(200, body.dump(), 200, sp_body().dump());
    const auto sp = fixture.client.saml().get_service_provider("sp-1");
    AXIAM_CHECK(sp.acs_urls.at(0).binding == SamlBinding::Unknown);
    AXIAM_CHECK(sp.name_id_format == NameIdFormat::Unknown);
    AXIAM_CHECK(sp.attribute_mappings.at(0).source == AttributeSource::Unknown);

    // Written back, the unknown values are replaced first: this SDK never sends a
    // value it does not know (§29.2) — an Unknown would go out as "".
    auto update = sp.to_input();
    update.acs_urls[0].binding = SamlBinding::HttpPost;
    update.name_id_format = NameIdFormat::Persistent;
    update.attribute_mappings->at(0).source = AttributeSource::Email;
    fixture.client.saml().update_service_provider("sp-1", update);
    const auto sent = json::parse(fixture.state->last().body);
    AXIAM_CHECK(!sent.contains("sign_assertions") && !sent.contains("some_future_member"));
    AXIAM_CHECK(sent.at("acs_urls").at(0).at("binding") == "http_post");
}

// ── 3. Draft round trip ─────────────────────────────────────────────────────

AXIAM_TEST("§29.8 (3): parse_sp_metadata sends exactly one member, and the draft creates unchanged") {
    json draft = {{"service_provider", json::parse(json(input()).dump())},
                  {"signing_certificate_fingerprint", nullptr},
                  {"encryption_certificate_fingerprint", nullptr},
                  {"warnings", {"the metadata's signature was not evaluated"}}};
    draft["service_provider"]["want_authn_requests_signed"] = false;
    auto fixture = axtest::mgmt::signed_in_many(
        {{200, draft.dump()}, {200, draft.dump()}, {201, sp_body().dump()}});
    auto saml = fixture.client.saml();
    const auto before = fixture.state->count();

    // Both, or neither: refused locally, nothing sent.
    ParseSamlSpMetadata both = ParseSamlSpMetadata::from_url("https://sp.example.com/md");
    both.metadata_xml = "<EntityDescriptor/>";
    AXIAM_CHECK(what_of<std::invalid_argument>([&] { saml.parse_sp_metadata(both); })
                    .rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<std::invalid_argument>([&] { saml.parse_sp_metadata(ParseSamlSpMetadata{}); })
                    .rfind("caught:", 0) == 0);
    AXIAM_CHECK(fixture.state->count() == before);

    saml.parse_sp_metadata(ParseSamlSpMetadata::from_url("https://sp.example.com/md"));
    AXIAM_CHECK(json::parse(fixture.state->last().body) ==
                json({{"metadata_url", "https://sp.example.com/md"}}));
    const auto parsed = saml.parse_sp_metadata(ParseSamlSpMetadata::from_xml("<EntityDescriptor/>"));
    AXIAM_CHECK(json::parse(fixture.state->last().body) ==
                json({{"metadata_xml", "<EntityDescriptor/>"}}));
    AXIAM_CHECK(parsed.warnings.size() == 1 && !parsed.signing_certificate_fingerprint);

    saml.create_service_provider(parsed.service_provider);
    AXIAM_CHECK(fixture.state->last().method == "POST");
    AXIAM_CHECK(json::parse(fixture.state->last().body) == draft["service_provider"]);
}

// ── 4. Credentials carry no key ─────────────────────────────────────────────

AXIAM_TEST("§29.8 (4): a credential carries no key member, and a promotion may retire nothing") {
    const std::string leaked = axtest::random_secret("key-");
    json leaky = credential_body("active");
    leaky["private_key_pem"] = leaked;
    auto fixture = axtest::mgmt::signed_in_two(
        201, leaky.dump(), 200, json{{"active", credential_body("active")}, {"retired", nullptr}}.dump());
    IssueSamlIdpCredential issue;
    issue.issuer_ca_id = "dddddddd-1111-4111-8111-111111111111";
    issue.slot = SamlIdpSlot::Active;
    const auto credential = fixture.client.saml().issue_idp_credential(issue);
    const json rendered = credential;
    AXIAM_CHECK(axtest::no_fragment(rendered.dump(), leaked));
    AXIAM_CHECK(rendered.dump().find("private_key_pem") == std::string::npos);
    AXIAM_CHECK(credential.status == SamlIdpCredentialStatus::Active);

    const auto promotion = fixture.client.saml().promote_idp_credential("cred-1");
    AXIAM_CHECK(!promotion.retired.has_value());
    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) ==
                kSaml + "/idp-credentials/cred-1/promote");
}

// ── 5. Pagination ───────────────────────────────────────────────────────────

AXIAM_TEST("§29.8 (5): service providers page with search on every request; credentials are a plain list") {
    const auto page = [](int n) {
        json items = json::array();
        if (n > 0) items.push_back(sp_body());
        return json{{"items", items}, {"total", 2}, {"offset", 0}, {"limit", 1}}.dump();
    };
    auto fixture = axtest::mgmt::signed_in_many(
        {{200, page(1)}, {200, page(1)}, {200, page(0)},
         {200, json::array({credential_body("next"), credential_body("active")}).dump()}});
    auto saml = fixture.client.saml();
    PageRequest request;
    request.limit = 1;
    request.search = "payroll";
    std::size_t walked = 0;
    for (auto p = saml.list_service_providers(request);; p = saml.list_service_providers(p.next_request())) {
        AXIAM_CHECK(p.total == 2);
        AXIAM_CHECK(axtest::mgmt::query_of(fixture.state->last().url).find("search=payroll") !=
                    std::string::npos);
        if (p.empty()) break;
        walked += p.size();
    }
    AXIAM_CHECK(walked == 2);
    const std::vector<SamlIdpCredential> credentials = saml.list_idp_credentials();
    AXIAM_CHECK(credentials.size() == 2);
}

// ── 6. No retry ─────────────────────────────────────────────────────────────

AXIAM_TEST("§29.8 (6): none of the seven writes is retried on a 503") {
    std::vector<std::pair<long, std::string>> replies(7, {503, ""});
    auto fixture = axtest::mgmt::signed_in_many(replies);
    auto saml = fixture.client.saml();  // retry ENABLED
    IssueSamlIdpCredential issue;
    issue.slot = SamlIdpSlot::Next;
    const auto before = fixture.state->count();
    int network = 0;
    const auto count = [&](const std::string& outcome) { network += outcome.rfind("caught:", 0) == 0; };
    count(what_of<NetworkError>([&] { saml.create_service_provider(input()); }));
    count(what_of<NetworkError>([&] { saml.update_service_provider("sp-1", input()); }));
    count(what_of<NetworkError>([&] { saml.delete_service_provider("sp-1"); }));
    count(what_of<NetworkError>([&] { saml.parse_sp_metadata(ParseSamlSpMetadata::from_url("https://x")); }));
    count(what_of<NetworkError>([&] { saml.issue_idp_credential(issue); }));
    count(what_of<NetworkError>([&] { saml.promote_idp_credential("c-1"); }));
    count(what_of<NetworkError>([&] { saml.retire_idp_credential("c-1"); }));
    AXIAM_CHECK(network == 7);
    AXIAM_CHECK(fixture.state->count() - before == 7);
}

// ── 7. Errors ───────────────────────────────────────────────────────────────

AXIAM_TEST("§29.8 (7): statuses map per §2 and §27.4 rule 7") {
    auto fixture = axtest::mgmt::signed_in_many(
        {{400, R"({"error":"validation_error","message":"entity_id is immutable"})"},
         {409, R"({"error":"conflict","message":"entity_id"})"},
         {409, R"({"error":"conflict","message":"not next"})"},
         {404, R"({"error":"not_found","message":"none"})"},
         {503, R"({"error":"service_unavailable","message":"saml"})"}});
    auto s = fixture.client.saml();
    AXIAM_CHECK(what_of<ValidationError>([&] { s.update_service_provider("sp-1", input()); })
                    .find("immutable") != std::string::npos);
    AXIAM_CHECK(what_of<ConflictError>([&] { s.create_service_provider(input()); }).rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<ConflictError>([&] { s.promote_idp_credential("c-1"); }).rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<NotFoundError>([&] { s.get_service_provider("sp-1"); }).rfind("caught:", 0) == 0);
    bool plain_network = false;
    try {
        s.parse_sp_metadata(ParseSamlSpMetadata::from_url("https://x"));
    } catch (const ValidationError&) {
    } catch (const NetworkError&) {
        plain_network = true;
    }
    AXIAM_CHECK(plain_network);
}

// ── 8. Readiness is read, not cached ────────────────────────────────────────

AXIAM_TEST("§29.8 (8): get_idp keeps null apart from absent, is never cached, and uses the configured tenant") {
    const json info = {{"tenant_id", "11111111-1111-4111-8111-111111111111"},
                       {"saml_available", true},
                       {"saml_idp_enabled", false},
                       {"metadata_served", true},
                       {"entity_id", "https://iam.example.com/saml/v2/t"},
                       {"metadata_url", "https://iam.example.com/saml/v2/t/metadata"},
                       {"sso_url", "https://iam.example.com/saml/v2/t/sso"},
                       {"slo_url", "https://iam.example.com/saml/v2/t/slo"},
                       {"active_credential_id", "cccccccc-1111-4111-8111-111111111111"},
                       {"next_credential_id", nullptr}};
    json without = info;
    without.erase("next_credential_id");
    auto fixture = axtest::mgmt::signed_in_two(200, info.dump(), 200, without.dump());
    const auto first = fixture.client.saml().get_idp();  // no tenant argument
    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == kSaml + "/idp");
    AXIAM_CHECK(first.active_credential_id ==
                std::optional<std::optional<std::string>>("cccccccc-1111-4111-8111-111111111111"));
    AXIAM_CHECK(first.next_credential_id.has_value() && !first.next_credential_id->has_value());
    AXIAM_CHECK(first.saml_available && first.metadata_served && !first.saml_idp_enabled);
    AXIAM_CHECK(first.sso_url == "https://iam.example.com/saml/v2/t/sso");

    const auto before = fixture.state->count();
    const auto second = fixture.client.saml().get_idp();
    AXIAM_CHECK(fixture.state->count() - before == 1);  // two calls, two requests
    AXIAM_CHECK(!second.next_credential_id.has_value());  // absent stays absent

    // Re-encoding keeps the distinction too: null is written as null.
    const json encoded = first;
    AXIAM_CHECK(encoded.at("next_credential_id").is_null());
    AXIAM_CHECK(!json(second).contains("next_credential_id"));
}

// Contract 1.59 R-27: "the input cannot be built without" its required members is
// a compile-time property in C++ -- a constructor taking every required member, in
// the contract's order, and no public default constructor. Checked as traits so a
// regression reads as a failed check rather than as a test that no longer builds.
AXIAM_TEST("§29.8 (1) (R-27): SamlServiceProviderInput cannot be built without display_name, entity_id and acs_urls") {
    AXIAM_CHECK(!std::is_default_constructible<SamlServiceProviderInput>::value);
    AXIAM_CHECK((!std::is_constructible<SamlServiceProviderInput, std::string, std::string>::value));
    AXIAM_CHECK((std::is_constructible<SamlServiceProviderInput, std::string, std::string, std::vector<AcsEndpoint>>::value));
}

}  // namespace
