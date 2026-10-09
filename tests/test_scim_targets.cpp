// CONTRACT.md §31 (contract 1.57) — the `scim_targets` management namespace:
// §31.8's six required tests, plus the read-modify-write helper and the open
// unions' refusal to send an unknown `type`. The credential is generated at
// run time.

#include <sstream>
#include <fstream>
#include <iterator>
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

const std::string kTargets = "/api/v1/scim-targets";

json target_body(const json& extra = json::object()) {
    json body = {{"id", "eeeeeeee-1111-4111-8111-111111111111"},
                 {"tenant_id", "11111111-1111-4111-8111-111111111111"},
                 {"name", "Downstream"},
                 {"base_url", "https://idp.example.com/scim/v2"},
                 {"enabled", true},
                 {"auth", {{"type", "bearer"}}},
                 {"scope", {{"type", "all_users"}}},
                 {"push_groups", false},
                 {"user_name_from", "username"},
                 {"deprovision", "deactivate"},
                 {"created_at", "2026-10-05T00:00:00Z"},
                 {"updated_at", "2026-10-05T00:00:00Z"},
                 {"state",
                  {{"last_success_at", nullptr}, {"last_failure_at", nullptr},
                   {"last_failure_reason", nullptr}, {"consecutive_failures", 0},
                   {"dead_lettered_total", 0}, {"last_reconciled_at", nullptr}}}};
    for (auto it = extra.begin(); it != extra.end(); ++it) body[it.key()] = it.value();
    return body;
}

ScimTargetInput input(std::optional<std::string> credential) {
    ScimTargetInput in("Downstream", "https://idp.example.com/scim/v2", ScimTargetAuth::bearer(),
                       ScimTargetScope::all_users());
    if (credential) in.credential = Sensitive<std::string>(*credential);
    return in;
}

template <typename T, typename = void>
struct has_credential : std::false_type {};
template <typename T>
struct has_credential<T, std::void_t<decltype(std::declval<T>().credential)>> : std::true_type {};
static_assert(!has_credential<ScimTargetResponse>::value, "§31.2: no credential on a response");
static_assert(!has_credential<ScimTargetAuth>::value, "§31.2: no variant has a credential member");

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

AXIAM_TEST("§31.8 (1): the credential is on the wire and in no rendering") {
    const std::string credential = axtest::random_secret("scim-");
    const auto body = input(credential);
    std::ostringstream printed;
    printed << *body.credential << ' ' << body.credential->to_string() << ' ' << body.auth.raw;
    AXIAM_CHECK(axtest::no_fragment(printed.str(), credential));

    auto fixture = axtest::mgmt::signed_in(
        400, R"({"error":"validation_error","message":"base_url: refused"})");
    const std::string err = what_of<ValidationError>([&] { fixture.client.scim_targets().create(body); });
    AXIAM_CHECK(err.find("base_url: refused") != std::string::npos);
    AXIAM_CHECK(axtest::no_fragment(err, credential));
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("credential") == credential);
}

// ── 2. No credential on the response ────────────────────────────────────────

AXIAM_TEST("§31.8 (2): a credential in a response is dropped, at the top level and in auth") {
    const std::string leaked = axtest::random_secret("scim-");
    auto fixture = axtest::mgmt::signed_in(
        200, target_body({{"credential", leaked},
                          {"credential_set", true},
                          {"auth", {{"type", "bearer"}, {"credential", leaked}}}})
                 .dump());
    const auto target = fixture.client.scim_targets().get("t-1");
    AXIAM_CHECK(target.name == "Downstream");
    const json rendered = target;
    AXIAM_CHECK(axtest::no_fragment(rendered.dump(), leaked));
    AXIAM_CHECK(axtest::no_fragment(target.auth.raw, leaked));
    AXIAM_CHECK(axtest::no_fragment(json(target.to_input()).dump(), leaked));
}

// ── 3. Replacement and the omitted credential ──────────────────────────────

AXIAM_TEST("§31.8 (3): update without a credential sends none; with one sends it; variants serialize exactly") {
    auto fixture = axtest::mgmt::signed_in_two(200, target_body().dump(), 200, target_body().dump());
    fixture.client.scim_targets().update("t-1", input(std::nullopt));
    AXIAM_CHECK(fixture.state->last().method == "PUT");
    AXIAM_CHECK(!json::parse(fixture.state->last().body).contains("credential"));
    const std::string credential = axtest::random_secret("scim-");
    fixture.client.scim_targets().update("t-1", input(credential));
    AXIAM_CHECK(json::parse(fixture.state->last().body).at("credential") == credential);

    AXIAM_CHECK(json(ScimTargetAuth::bearer()) == json({{"type", "bearer"}}));
    AXIAM_CHECK(json(ScimTargetAuth::oauth2_client_credentials("https://idp.example.com/token", "axiam"))
                == json({{"type", "oauth2_client_credentials"},
                         {"token_url", "https://idp.example.com/token"},
                         {"client_id", "axiam"}}));
    AXIAM_CHECK(json(ScimTargetAuth::oauth2_client_credentials("https://t", "c", "scim")).at("scope") ==
                "scim");
    AXIAM_CHECK(json(ScimTargetScope::all_users()) == json({{"type", "all_users"}}));
    AXIAM_CHECK(json(ScimTargetScope::groups({"g-1", "g-2"})) ==
                json({{"type", "groups"}, {"group_ids", {"g-1", "g-2"}}}));

    // The input cannot be built without name, base_url, auth and scope (the R-27
    // trait test below); built with a default-constructed (tag-less) union, it is
    // refused locally rather than sent.
    AXIAM_REQUIRE_THROWS_AS(json(ScimTargetInput("n", "https://h", ScimTargetAuth{}, ScimTargetScope{})),
                            NetworkError);
}

AXIAM_TEST("§31.2: an unknown auth or scope type decodes but is never sent") {
    auto fixture = axtest::mgmt::signed_in(
        200, target_body({{"auth", {{"type", "mutual_tls"}, {"cert_ref", "x"}}},
                          {"scope", {{"type", "department"}}}})
                 .dump());
    const auto target = fixture.client.scim_targets().get("t-1");
    AXIAM_CHECK(target.auth.type == "mutual_tls" && target.scope.type == "department");
    const auto before = fixture.state->count();
    auto body = target.to_input();
    AXIAM_CHECK(what_of<NetworkError>([&] { fixture.client.scim_targets().update("t-1", body); })
                    .rfind("caught:", 0) == 0);
    body.auth = ScimTargetAuth::bearer();
    AXIAM_CHECK(what_of<NetworkError>([&] { fixture.client.scim_targets().update("t-1", body); })
                    .rfind("caught:", 0) == 0);
    AXIAM_CHECK(fixture.state->count() == before);  // refused before any request
}

// ── 4. Open decoding and pagination ────────────────────────────────────────

AXIAM_TEST("§31.8 (4): unknown values and a null state decode; list pages with search on every request") {
    const auto odd = target_body({{"auth", {{"type", "something_new"}}},
                                  {"deprovision", "archive"},
                                  {"user_name_from", "upn"},
                                  {"state", nullptr}});
    json reason = target_body();
    reason["state"]["last_failure_reason"] = "a phrase this SDK has never seen";
    const auto page = [](json items) {
        return json{{"items", items}, {"total", 2}, {"offset", 0}, {"limit", 1}}.dump();
    };
    auto fixture = axtest::mgmt::signed_in_many(
        {{200, page(json::array({odd}))}, {200, page(json::array({reason}))}, {200, page(json::array())}});
    PageRequest request;
    request.limit = 1;
    request.search = "downstream";
    auto targets = fixture.client.scim_targets();
    const auto first = targets.list(request);
    AXIAM_REQUIRE(first.total == 2 && first.size() == 1);
    const auto& t = first.items[0];
    AXIAM_CHECK(t.auth.type == "something_new");
    AXIAM_CHECK(t.deprovision == DeprovisionPolicy::Unknown);
    AXIAM_CHECK(t.user_name_from == UserNameSource::Unknown);
    AXIAM_CHECK(!t.state.has_value());
    const auto second = targets.list(first.next_request());
    AXIAM_REQUIRE(second.size() == 1);
    AXIAM_CHECK(second.items[0].state->last_failure_reason ==
                std::optional<std::string>("a phrase this SDK has never seen"));
    const auto third = targets.list(second.next_request());
    AXIAM_CHECK(third.empty());
    std::lock_guard<std::mutex> lock(fixture.state->mtx);
    int pages = 0;
    for (const auto& r : fixture.state->requests) {
        if (axtest::mgmt::path_of(r.url) != kTargets) continue;
        ++pages;
        AXIAM_CHECK(axtest::mgmt::query_of(r.url).find("search=downstream") != std::string::npos);
    }
    AXIAM_CHECK(pages == 3);
}

// ── 5. No retry ─────────────────────────────────────────────────────────────

AXIAM_TEST("§31.8 (5): create, update, delete and reconcile are each sent once on a 503") {
    auto fixture = axtest::mgmt::signed_in_many({{503, ""}, {503, ""}, {503, ""}, {503, ""}});
    auto s = fixture.client.scim_targets();  // retry ENABLED
    const auto before = fixture.state->count();
    int network = 0;
    const auto count = [&](const std::string& o) { network += o.rfind("caught:", 0) == 0; };
    count(what_of<NetworkError>([&] { s.create(input(axtest::random_secret("scim-"))); }));
    count(what_of<NetworkError>([&] { s.update("t-1", input(std::nullopt)); }));
    count(what_of<NetworkError>([&] { s.delete_("t-1"); }));
    count(what_of<NetworkError>([&] { s.reconcile("t-1"); }));
    AXIAM_CHECK(network == 4);
    AXIAM_CHECK(fixture.state->count() - before == 4);
}

// ── 6. Errors and reconcile ─────────────────────────────────────────────────

AXIAM_TEST("§31.8 (6): the error mapping, and reconcile sends no body and decodes its 202") {
    auto fixture = axtest::mgmt::signed_in_many(
        {{400, R"({"error":"validation_error","message":"auth.token_url: needs the credential"})"},
         {409, R"({"error":"conflict","message":"changed since read"})"},
         {409, R"({"error":"conflict","message":"claim held"})"},
         {404, R"({"error":"not_found","message":"none"})"},
         {401, R"({"error":"unauthorized"})"},
         {202, R"({"target_id":"eeeeeeee-1111-4111-8111-111111111111","status":"started"})"}});
    auto s = fixture.client.scim_targets();
    AXIAM_CHECK(what_of<ValidationError>([&] { s.update("t-1", input(std::nullopt)); })
                    .find("needs the credential") != std::string::npos);
    AXIAM_CHECK(what_of<ConflictError>([&] { s.update("t-1", input(std::nullopt)); }).rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<ConflictError>([&] { s.reconcile("t-1"); }).rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<NotFoundError>([&] { s.get("t-1"); }).rfind("caught:", 0) == 0);
    AXIAM_CHECK(what_of<AuthError>([&] { s.get("t-1"); }).rfind("caught:", 0) == 0);

    const auto accepted = s.reconcile("t-1");
    AXIAM_CHECK(fixture.state->last().method == "POST");
    AXIAM_CHECK(fixture.state->last().body.empty());
    AXIAM_CHECK(axtest::mgmt::path_of(fixture.state->last().url) == kTargets + "/t-1/reconcile");
    AXIAM_CHECK(accepted.status == "started" &&
                accepted.target_id == "eeeeeeee-1111-4111-8111-111111111111");
}

AXIAM_TEST("§31: ScimTargetResponse::to_input() keeps every member but the credential") {
    const auto t = target_body({{"auth", {{"type", "oauth2_client_credentials"},
                                          {"token_url", "https://idp.example.com/token"},
                                          {"client_id", "axiam"}, {"scope", nullptr}}},
                                {"scope", {{"type", "groups"}, {"group_ids", {"g-1"}}}},
                                {"push_groups", true},
                                {"deprovision", "delete"}})
                       .get<ScimTargetResponse>();
    const auto in = t.to_input();
    AXIAM_CHECK(!in.credential.has_value());
    AXIAM_CHECK(in.push_groups == std::optional<bool>(true));
    AXIAM_CHECK(in.deprovision == std::optional<DeprovisionPolicy>(DeprovisionPolicy::Delete_));
    const json encoded = in;
    AXIAM_CHECK(encoded.at("auth").at("token_url") == "https://idp.example.com/token");
    AXIAM_CHECK(encoded.at("scope") == json({{"type", "groups"}, {"group_ids", {"g-1"}}}));
}

// Contract 1.59 R-27: "the input cannot be built without" its required members is
// a compile-time property in C++ -- a constructor taking every required member, in
// the contract's order, and no public default constructor. Checked as traits so a
// regression reads as a failed check rather than as a test that no longer builds.
AXIAM_TEST("§31.8 (3) (R-27): ScimTargetInput cannot be built without name, base_url, auth and scope") {
    AXIAM_CHECK(!std::is_default_constructible<ScimTargetInput>::value);
    AXIAM_CHECK((!std::is_constructible<ScimTargetInput, std::string, std::string, ScimTargetAuth>::value));
    AXIAM_CHECK((std::is_constructible<ScimTargetInput, std::string, std::string, ScimTargetAuth, ScimTargetScope>::value));
}

}  // namespace

// Contract 1.59 R-29: the call-site documentation the contract makes an SDK repeat,
// checked in the installed headers (generated from scripts/gen_management.py, so the
// generator is what this pins). §31.3 rule 2: "An SDK MUST document the rule at both
// call sites" -- create as well as update. §29.3 rule 2: the ECDSA/HTTP-POST-only note
// "where it documents the field", i.e. on `sp_signing_cert_pem` itself.
namespace {
std::string header_text(const char* rel) {
    std::ifstream in(std::string(AXIAM_REPO_ROOT) + "/include/axiam/" + rel, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

/// The `///` block immediately above the first line containing `marker` at or after `from`.
std::string doc_above(const std::string& text, const std::string& marker, std::size_t from = 0) {
    const auto at = text.find(marker, from);
    if (at == std::string::npos) return {};
    std::size_t line_start = text.rfind('\n', at);
    std::string block;
    while (line_start != std::string::npos && line_start > 0) {
        const auto prev = text.rfind('\n', line_start - 1);
        const std::string line = text.substr(prev + 1, line_start - prev - 1);
        if (line.find("///") == std::string::npos) break;
        block = line + "\n" + block;
        if (prev == std::string::npos) break;
        line_start = prev;
    }
    return block;
}
}  // namespace

AXIAM_TEST("§31.3 rule 2 / §29.3 rule 2 (R-29): the call-site and field documentation the contract requires") {
    const std::string api = header_text("management.hpp");
    const std::string create = doc_above(api, "ScimTargetResponse create(");
    AXIAM_CHECK(create.find("bound to its URL") != std::string::npos);
    AXIAM_CHECK(create.find("base_url") != std::string::npos);
    AXIAM_CHECK(create.find("auth.token_url") != std::string::npos);

    const std::string models = header_text("management_models.hpp");
    for (const char* owner : {"struct SamlServiceProviderInput {", "struct SamlServiceProvider {"}) {
        const auto start = models.find(owner);
        AXIAM_REQUIRE(start != std::string::npos);
        const std::string field = doc_above(models, " sp_signing_cert_pem = ", start);
        AXIAM_CHECK(field.find("HTTP-POST") != std::string::npos);
        AXIAM_CHECK(field.find("RSA-only") != std::string::npos);
    }
}

namespace {
}  // namespace
