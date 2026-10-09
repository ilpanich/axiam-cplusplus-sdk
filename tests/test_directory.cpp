// CONTRACT.md §30 (contract 1.54) — the `directory` management namespace:
// §30.8's six required tests, plus the sync status, the read-modify-write
// helper and the explicit-null tri-state.
//
// The bind secret is generated at run time: a literal would be a credential in
// the repository and would let a redaction test pass by coincidence.

#include <sstream>
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

const std::string kDirectory = "/api/v1/tenants/11111111-1111-4111-8111-111111111111/directory";

json config_body() {
    return {{"id", "aaaaaaaa-1111-4111-8111-111111111111"},
            {"tenant_id", "11111111-1111-4111-8111-111111111111"},
            {"enabled", true},
            {"kind", "active_directory"},
            {"url", "ldaps://dc.corp.example"},
            {"start_tls", false},
            {"bind_dn", "cn=svc,dc=corp"},
            {"base_dn", "dc=corp"},
            {"user_filter", "(sAMAccountName={username})"},
            {"user_attribute_map",
             {{"username", "sAMAccountName"}, {"email", "mail"}, {"display_name", "displayName"},
              {"external_id", "objectGUID"}}},
            {"group_base_dn", nullptr},
            {"group_filter", nullptr},
            {"group_member_attribute", "member"},
            {"group_nesting_depth", 5},
            {"group_mappings", json::array()},
            {"sync_interval_secs", 3600},
            {"jit_provisioning", false},
            {"trust_anchors_pem", json::array()},
            {"created_at", "2026-10-04T00:00:00Z"},
            {"updated_at", "2026-10-04T00:00:00Z"}};
}

SetDirectoryConfig set_body(std::optional<std::string> secret) {
    SetDirectoryConfig s(/*enabled=*/true, DirectoryKind::ActiveDirectory, "ldaps://dc.corp.example",
                         /*start_tls=*/false, "cn=svc,dc=corp", "dc=corp",
                         "(sAMAccountName={username})");
    if (secret) s.bind_secret = Sensitive<std::string>(*secret);
    return s;
}

/// Detects a member named `bind_secret` — the response type must have none.
template <typename T, typename = void>
struct has_bind_secret : std::false_type {};
template <typename T>
struct has_bind_secret<T, std::void_t<decltype(std::declval<T>().bind_secret)>> : std::true_type {};

static_assert(!has_bind_secret<DirectoryConfig>::value,
              "§30.2: DirectoryConfig declares no secret member");
static_assert(has_bind_secret<SetDirectoryConfig>::value, "the write type carries it");

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

// ── 1. Redaction ────────────────────────────────────────────────────────────

AXIAM_TEST("§30.8 (1): the bind secret reaches the wire and no rendering") {
    const std::string secret = axtest::random_secret("bind-");
    const auto set = set_body(secret);
    UpdateDirectoryConfig update;
    update.bind_secret = Sensitive<std::string>(secret);

    std::ostringstream printed;
    printed << *set.bind_secret << ' ' << *update.bind_secret << ' ' << set.bind_secret->to_string();
    AXIAM_CHECK(axtest::no_fragment(printed.str(), secret));

    auto fixture = axtest::mgmt::signed_in(
        400, R"({"error":"validation_error","message":"url: plaintext LDAP is refused"})");
    const std::string err = what_of<ValidationError>([&] { fixture.client.directory().set(set); });
    AXIAM_CHECK(err.rfind("caught:", 0) == 0);
    AXIAM_CHECK(axtest::no_fragment(err, secret));
    // ...but it is on the wire.
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("bind_secret") == secret);
}

// ── 2. No secret on the response ────────────────────────────────────────────

AXIAM_TEST("§30.8 (2): a bind_secret in a response is dropped") {
    const std::string leaked = axtest::random_secret("bind-");
    json body = config_body();
    body["bind_secret"] = leaked;
    auto fixture = axtest::mgmt::signed_in(200, body.dump());
    const DirectoryConfig config = fixture.client.directory().get();
    AXIAM_CHECK(config.url == "ldaps://dc.corp.example");
    // Every rendering this SDK has for it: the log-serialization (its JSON hook)
    // and the read-modify-write body built from it. (No accessor: the
    // static_assert above.)
    const json rendered = config;
    AXIAM_CHECK(axtest::no_fragment(rendered.dump(), leaked));
    const json input = config.to_input();
    AXIAM_CHECK(axtest::no_fragment(input.dump(), leaked));
}

// ── 3. Sparse update ────────────────────────────────────────────────────────

AXIAM_TEST("§30.8 (3): update sends exactly the members it was given, and null clears") {
    auto fixture = axtest::mgmt::signed_in_three(200, config_body().dump(), 200,
                                                 config_body().dump(), 200, config_body().dump());
    const std::string secret = axtest::random_secret("bind-");
    auto directory = fixture.client.directory();

    UpdateDirectoryConfig disable;
    disable.enabled = false;
    directory.update(disable);
    AXIAM_CHECK(fixture.state->last().method == "PATCH");
    AXIAM_CHECK(json::parse(fixture.state->last().body) == json({{"enabled", false}}));

    UpdateDirectoryConfig move;
    move.url = "ldaps://dc2.corp.example";
    move.bind_secret = Sensitive<std::string>(secret);
    directory.update(move);
    const auto moved = json::parse(fixture.state->last().body);
    AXIAM_CHECK(moved.size() == 2);
    AXIAM_CHECK(moved.at("url") == "ldaps://dc2.corp.example" && moved.at("bind_secret") == secret);

    UpdateDirectoryConfig clear;
    clear.group_filter.emplace(std::nullopt);
    clear.group_base_dn = std::optional<std::string>("ou=groups,dc=corp");
    directory.update(clear);
    AXIAM_CHECK(json::parse(fixture.state->last().body) ==
                json({{"group_filter", nullptr}, {"group_base_dn", "ou=groups,dc=corp"}}));
    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == kDirectory);
}

AXIAM_TEST("§27.4 rule 5: an explicit null decodes distinct from an absent member") {
    const auto with_null = json::parse(R"({"group_filter":null})").get<UpdateDirectoryConfig>();
    AXIAM_CHECK(with_null.group_filter.has_value() && !with_null.group_filter->has_value());
    AXIAM_CHECK(!with_null.group_base_dn.has_value());
    const auto with_value = json::parse(R"({"group_base_dn":"ou=g"})").get<UpdateDirectoryConfig>();
    AXIAM_CHECK(with_value.group_base_dn == std::optional<std::optional<std::string>>("ou=g"));
}

// ── 4. Replacement ──────────────────────────────────────────────────────────

AXIAM_TEST("§30.8 (4): set sends every required member, and a 201 and a 200 both decode") {
    for (const long status : {201L, 200L}) {
        auto fixture = axtest::mgmt::signed_in(status, config_body().dump());
        const DirectoryConfig config = fixture.client.directory().set(set_body(std::nullopt));
        AXIAM_CHECK(config.enabled && config.kind == DirectoryKind::ActiveDirectory);
        AXIAM_CHECK(fixture.state->last().method == "PUT");
        const auto sent = json::parse(fixture.state->last().body);
        for (const char* required :
             {"enabled", "kind", "url", "start_tls", "bind_dn", "base_dn", "user_filter"}) {
            AXIAM_CHECK(sent.contains(required));
        }
        AXIAM_CHECK(!sent.contains("bind_secret"));  // absent keeps the stored secret
    }
    // The body cannot be built without its required members (the R-27 trait test
    // below); built with them, they are ALWAYS serialized, never omitted.
    const json bare = set_body(std::nullopt);
    for (const char* required :
         {"enabled", "kind", "url", "start_tls", "bind_dn", "base_dn", "user_filter"}) {
        AXIAM_CHECK(bare.contains(required));
    }
}

AXIAM_TEST("§27.4 rule 5: DirectoryConfig::to_input() is the read-modify-write body, without a secret") {
    const auto config = config_body().get<DirectoryConfig>();
    const SetDirectoryConfig body = config.to_input();
    AXIAM_CHECK(!body.bind_secret.has_value());
    AXIAM_CHECK(body.url == config.url && body.base_dn == config.base_dn);
    AXIAM_CHECK(body.group_nesting_depth == std::optional<std::int64_t>(5));
    AXIAM_CHECK(body.sync_interval_secs == std::optional<std::int64_t>(3600));
    AXIAM_CHECK(body.user_attribute_map->email == "mail");
    AXIAM_CHECK(!body.group_filter.has_value());
}

// ── 5. No retry ─────────────────────────────────────────────────────────────

AXIAM_TEST("§30.8 (5): set, update, delete and link_account are each sent once on a 503") {
    auto fixture = axtest::mgmt::signed_in_many({{503, ""}, {503, ""}, {503, ""}, {503, ""}});
    auto d = fixture.client.directory();  // the client is retry-ENABLED (the default)
    const auto before = fixture.state->count();
    AXIAM_CHECK(what_of<NetworkError>([&] { d.set(set_body(axtest::random_secret("bind-"))); })
                    .rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<NetworkError>([&] { d.update(UpdateDirectoryConfig{}); }).rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<NetworkError>([&] { d.delete_(); }).rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<NetworkError>([&] { d.link_account(LinkDirectoryAccount{"u-1"}); })
                    .rfind("caught:", 0) == 0);
    AXIAM_CHECK(fixture.state->count() - before == 4);  // exactly one request each
}

// ── 6. Errors and link_account ──────────────────────────────────────────────

AXIAM_TEST("§30.8 (6): 400 carries the message, 409 is a conflict, 404 not found, 401 an AuthError") {
    auto fixture = axtest::mgmt::signed_in_many(
        {{400, R"({"error":"validation_error","message":"url: changing the connection requires entering the bind secret again"})"},
         {409, R"({"error":"conflict","message":"opaque_mode"})"},
         {404, R"({"error":"not_found","message":"none"})"},
         {401, R"({"error":"unauthorized"})"}});
    auto d = fixture.client.directory();
    const std::string validation = what_of<ValidationError>([&] { d.set(set_body(std::nullopt)); });
    AXIAM_CHECK(validation.find("bind secret again") != std::string::npos);
    UpdateDirectoryConfig enable;
    enable.enabled = true;
    AXIAM_CHECK(what_of<ConflictError>([&] { d.update(enable); }).rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<NotFoundError>([&] { d.get(); }).rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<AuthError>([&] { d.get_sync_status(); }).rfind("caught:", 0) == 0);
}

AXIAM_TEST("§30.8 (6): link_account sends only the user id and decodes all five members") {
    auto fixture = axtest::mgmt::signed_in(
        200, R"({"user_id":"u-9","directory_external_id":"3f2a-objectguid",)"
             R"("webauthn_credentials_deleted":2,"certificates_revoked":1,"was_already_linked":false})");
    const auto result = fixture.client.directory().link_account(LinkDirectoryAccount{"u-9"});
    AXIAM_CHECK(json::parse(fixture.state->last().body) == json({{"user_id", "u-9"}}));
    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == kDirectory + "/links");
    AXIAM_CHECK(result.user_id == "u-9");
    AXIAM_CHECK(result.directory_external_id == "3f2a-objectguid");
    AXIAM_CHECK(result.webauthn_credentials_deleted == 2);
    AXIAM_CHECK(result.certificates_revoked == 1);
    AXIAM_CHECK(!result.was_already_linked);
}

AXIAM_TEST("§30.2: the sync status decodes an unknown result and the first run's nulls") {
    auto fixture = axtest::mgmt::signed_in(
        200, R"({"last_result":"something_new","last_attempt_at":null,"last_full_run_at":null,)"
             R"("full_required":true,"has_watermark":false})");
    const auto status = fixture.client.directory().get_sync_status();
    AXIAM_CHECK(status.last_result == std::optional<std::string>("something_new"));
    AXIAM_CHECK(status.full_required && !status.has_watermark && !status.last_attempt_at);
}

AXIAM_TEST("§30.1: a tenant override reaches the path; the configured tenant is the default") {
    auto fixture = axtest::mgmt::signed_in_two(200, config_body().dump(), 200, config_body().dump());
    fixture.client.directory().get();
    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == kDirectory);
    fixture.client.directory().for_tenant("22222222-2222-4222-8222-222222222222").get();
    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) ==
                "/api/v1/tenants/22222222-2222-4222-8222-222222222222/directory");
}

// Contract 1.59 R-27: "the input cannot be built without" its required members is
// a compile-time property in C++ -- a constructor taking every required member, in
// the contract's order, and no public default constructor. Checked as traits so a
// regression reads as a failed check rather than as a test that no longer builds.
AXIAM_TEST("§30.8 (4) (R-27): SetDirectoryConfig cannot be built without enabled, kind, url, start_tls, bind_dn, base_dn and user_filter") {
    AXIAM_CHECK(!std::is_default_constructible<SetDirectoryConfig>::value);
    AXIAM_CHECK((!std::is_constructible<SetDirectoryConfig, bool, DirectoryKind, std::string, bool, std::string, std::string>::value));
    AXIAM_CHECK((std::is_constructible<SetDirectoryConfig, bool, DirectoryKind, std::string, bool, std::string, std::string, std::string>::value));
}

}  // namespace
