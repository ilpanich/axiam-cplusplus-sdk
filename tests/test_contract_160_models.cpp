// CONTRACT.md §27.15 (contract 1.60) -- the three additive members and the one
// normative update rule the 1.60 re-vendor brought to the §27 surface:
//
//   * note 1: `window_minutes` on the notification_rules models, passed through and
//     never clamped (the one required test of note 1);
//   * note 6: `allow_sha1_signatures` on the federation configuration models, sent only
//     when set, and read as `false` from a response that lacks it (an older server);
//   * note 7: `idp_metadata_signing_cert_pem`, an optional, nullable string on all three;
//   * note 8: the ten nullable members of `UpdateFederationConfigRequest` are tri-state,
//     "unset" distinct from "set to null", with §27.4 rule 5's exact key-set test.
//
// The generated suites round-trip every member; what they cannot say is which value a
// caller's omission becomes on the wire, which is what each case here pins.

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "assert.hpp"
#include "axiam/axiam.hpp"
#include "axiam/management.hpp"
#include "management_json.hpp"
#include "management_test_util.hpp"
#include "secret_util.hpp"

namespace {

using namespace axiam;
using namespace axiam::management;
using nlohmann::json;

constexpr const char* kUuid = "11111111-1111-4111-8111-111111111111";

// Not a real certificate: the SDK never parses it, the server does.
constexpr const char* kCertPem =
    "-----BEGIN CERTIFICATE-----\nMIIBfixturefixturefixture\n-----END CERTIFICATE-----\n";

json rule_body(const json& extra = json::object()) {
    json body = {{"id", kUuid},
                 {"tenant_id", kUuid},
                 {"name", "lockouts"},
                 {"description", "mail the on-call"},
                 {"enabled", true},
                 {"events", {"account_locked"}},
                 {"recipient_emails", {"oncall@example.com"}},
                 {"window_minutes", 15},
                 {"created_at", "2026-10-05T00:00:00Z"},
                 {"updated_at", "2026-10-05T00:00:00Z"}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

CreateNotificationRuleRequest rule_input() {
    CreateNotificationRuleRequest in;
    in.name = "lockouts";
    in.description = "mail the on-call";
    in.events = {NotificationEventType::AccountLocked};
    in.recipient_emails = {"oncall@example.com"};
    return in;
}

/// A FederationConfigResponse body carrying every required member BUT
/// `allow_sha1_signatures` -- what a server older than contract 1.60 sends.
json federation_body(const json& extra = json::object()) {
    json body = {{"id", kUuid},
                 {"tenant_id", kUuid},
                 {"provider", "corp-idp"},
                 {"protocol", "Saml"},
                 {"client_id", "axiam-sp"},
                 {"attribute_map", json::object()},
                 {"enabled", true},
                 {"token_exchange",
                  {{"accepted_audiences", json::array()}, {"enabled", false},
                   {"max_lifetime_secs", 300}, {"max_token_age_secs", 300},
                   {"scope_map", json::object()}, {"subject_mapping", "email"}}},
                 {"provider_kind", "generic_saml"},
                 {"allow_tenant_inheritance", false},
                 {"scopes", json::array()},
                 {"effective_scopes", json::array()},
                 {"allowed_issuer_tenants", json::array()},
                 {"allowed_algorithms", json::array()},
                 {"mints_client_secret", false},
                 {"pkce_required", false},
                 {"has_bundled_mark", false},
                 {"created_at", "2026-10-05T00:00:00Z"},
                 {"updated_at", "2026-10-05T00:00:00Z"}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

CreateFederationConfigRequest federation_input() {
    CreateFederationConfigRequest in;
    in.provider = "corp-idp";
    in.protocol = "Saml";
    in.client_id = "axiam-sp";
    in.client_secret = Sensitive<std::string>(axtest::random_secret("fed-"));
    return in;
}

using Member = std::optional<std::optional<std::string>> UpdateFederationConfigRequest::*;

/// The ten members §27.15 note 8 names, by wire name.
const std::vector<std::pair<const char*, Member>>& clearable() {
    static const std::vector<std::pair<const char*, Member>> members = {
        {"metadata_url", &UpdateFederationConfigRequest::metadata_url},
        {"idp_signing_cert_pem", &UpdateFederationConfigRequest::idp_signing_cert_pem},
        {"idp_metadata_signing_cert_pem",
         &UpdateFederationConfigRequest::idp_metadata_signing_cert_pem},
        {"provider_slug", &UpdateFederationConfigRequest::provider_slug},
        {"authorization_endpoint", &UpdateFederationConfigRequest::authorization_endpoint},
        {"token_endpoint", &UpdateFederationConfigRequest::token_endpoint},
        {"userinfo_endpoint", &UpdateFederationConfigRequest::userinfo_endpoint},
        {"apple_team_id", &UpdateFederationConfigRequest::apple_team_id},
        {"apple_key_id", &UpdateFederationConfigRequest::apple_key_id},
        {"button_icon", &UpdateFederationConfigRequest::button_icon},
    };
    return members;
}

// ── note 1: window_minutes ──────────────────────────────────────────────────

AXIAM_TEST("§27.15 note 1: create sends window_minutes as given, omits it when unset, and a response decodes it") {
    auto fixture = axtest::mgmt::signed_in_three(201, rule_body({{"window_minutes", 1441}}).dump(),
                                                 201, rule_body().dump(),
                                                 200, rule_body({{"window_minutes", 60}}).dump());
    auto rules = fixture.client.management().notification_rules();

    // Out of the server's 1 … 1440 range on purpose: the SDK does not clamp, the
    // server answers 400 for it (a clamp would be a silently different request).
    auto with = rule_input();
    with.window_minutes = 1441;
    const auto created = rules.create(with);
    AXIAM_CHECK(fixture.state->last().method == "POST");
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("window_minutes") == 1441);
    AXIAM_CHECK(created.window_minutes == 1441);

    rules.create(rule_input());
    AXIAM_CHECK(!json::parse(fixture.state->last().body).contains("window_minutes"));

    UpdateNotificationRuleRequest zero;
    zero.window_minutes = 0;
    const auto updated = rules.update("r-1", zero);
    AXIAM_CHECK(json::parse(fixture.state->last().body) == json({{"window_minutes", 0}}));
    AXIAM_CHECK(updated.window_minutes == 60);
}

// ── note 6: allow_sha1_signatures ───────────────────────────────────────────

AXIAM_TEST("§27.15 note 6: allow_sha1_signatures is sent only when set, an engaged false included") {
    auto fixture = axtest::mgmt::signed_in_three(201, federation_body().dump(), 201,
                                                 federation_body().dump(), 200,
                                                 federation_body().dump());
    auto federation = fixture.client.management().federation();

    federation.create_config(federation_input());
    AXIAM_CHECK(!json::parse(fixture.state->last().body).contains("allow_sha1_signatures"));

    auto sha1 = federation_input();
    sha1.allow_sha1_signatures = true;
    federation.create_config(sha1);
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("allow_sha1_signatures") == true);

    UpdateFederationConfigRequest off;
    off.allow_sha1_signatures = false;
    federation.update_config("f-1", off);
    AXIAM_CHECK(json::parse(fixture.state->last().body) == json({{"allow_sha1_signatures", false}}));
}

AXIAM_TEST("§27.15 note 6: a response without allow_sha1_signatures (an older server) decodes as false") {
    const auto older = federation_body().get<FederationConfigResponse>();
    AXIAM_CHECK(older.allow_sha1_signatures == false);
    const auto nulled = federation_body({{"allow_sha1_signatures", nullptr}}).get<FederationConfigResponse>();
    AXIAM_CHECK(nulled.allow_sha1_signatures == false);
    const auto on = federation_body({{"allow_sha1_signatures", true}}).get<FederationConfigResponse>();
    AXIAM_CHECK(on.allow_sha1_signatures == true);

    // Through the wire as well: get_config must not refuse the older server's body.
    auto fixture = axtest::mgmt::signed_in(200, federation_body().dump());
    AXIAM_CHECK(fixture.client.management().federation().get_config("f-1").allow_sha1_signatures == false);
}

// ── note 7: idp_metadata_signing_cert_pem ───────────────────────────────────

AXIAM_TEST("§27.15 note 7: idp_metadata_signing_cert_pem is sent when set and decodes null as absent") {
    auto fixture = axtest::mgmt::signed_in_two(201, federation_body().dump(), 201,
                                               federation_body().dump());
    auto federation = fixture.client.management().federation();

    federation.create_config(federation_input());
    AXIAM_CHECK(!json::parse(fixture.state->last().body).contains("idp_metadata_signing_cert_pem"));

    auto signed_metadata = federation_input();
    signed_metadata.idp_metadata_signing_cert_pem = kCertPem;
    federation.create_config(signed_metadata);
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("idp_metadata_signing_cert_pem") == kCertPem);

    const auto unset = federation_body({{"idp_metadata_signing_cert_pem", nullptr}})
                           .get<FederationConfigResponse>();
    AXIAM_CHECK(!unset.idp_metadata_signing_cert_pem.has_value());
    const auto set = federation_body({{"idp_metadata_signing_cert_pem", kCertPem}})
                         .get<FederationConfigResponse>();
    AXIAM_CHECK(set.idp_metadata_signing_cert_pem == std::optional<std::string>(kCertPem));
}

// ── note 8: explicit null clears ────────────────────────────────────────────

AXIAM_TEST("§27.15 note 8 / §27.4 rule 5: update_config clearing one member sends exactly that key as null") {
    auto fixture = axtest::mgmt::signed_in_three(200, federation_body().dump(), 200,
                                                 federation_body().dump(), 200,
                                                 federation_body().dump());
    auto federation = fixture.client.management().federation();

    // The exact key set: the cleared member and nothing else -- no other member
    // goes out as null, so nothing else is cleared.
    UpdateFederationConfigRequest clear;
    clear.idp_metadata_signing_cert_pem.emplace(std::nullopt);
    federation.update_config("f-1", clear);
    AXIAM_CHECK(fixture.state->last().method == "PUT");
    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == "/api/v1/federation-configs/f-1");
    AXIAM_CHECK(json::parse(fixture.state->last().body) == json({{"idp_metadata_signing_cert_pem", nullptr}}));

    // A value is a value; omission leaves every other member as stored.
    UpdateFederationConfigRequest move;
    move.metadata_url = std::optional<std::string>("https://idp.example.com/metadata");
    federation.update_config("f-1", move);
    AXIAM_CHECK(json::parse(fixture.state->last().body) ==
                json({{"metadata_url", "https://idp.example.com/metadata"}}));

    federation.update_config("f-1", UpdateFederationConfigRequest{});
    AXIAM_CHECK(json::parse(fixture.state->last().body) == json::object());
}

AXIAM_TEST("§27.15 note 8: each of the ten nullable members is tri-state, on the wire and decoding") {
    for (const auto& [wire, member] : clearable()) {
        UpdateFederationConfigRequest unset;
        AXIAM_CHECK(json(unset) == json::object());

        UpdateFederationConfigRequest cleared;
        (cleared.*member).emplace(std::nullopt);
        AXIAM_CHECK(json(cleared) == json({{wire, nullptr}}));

        UpdateFederationConfigRequest valued;
        (valued.*member).emplace("v");
        AXIAM_CHECK(json(valued) == json({{wire, "v"}}));

        // Decoding keeps the distinction a read-modify-write would otherwise lose.
        const auto from_null = json({{wire, nullptr}}).get<UpdateFederationConfigRequest>();
        AXIAM_CHECK((from_null.*member).has_value() && !(from_null.*member)->has_value());
        const auto from_absent = json::object().get<UpdateFederationConfigRequest>();
        AXIAM_CHECK(!(from_absent.*member).has_value());
    }

    // A member note 8 says cannot be cleared reads an explicit null as absent, and
    // is never sent as null.
    const auto not_clearable = json({{"client_id", nullptr}, {"enabled", nullptr}})
                                   .get<UpdateFederationConfigRequest>();
    AXIAM_CHECK(json(not_clearable) == json::object());
}

}  // namespace
