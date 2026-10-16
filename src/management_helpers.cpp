// Hand-written members of generated §27 models (the generator's MODEL_MEMBERS
// table declares them; this file defines them), and the PRECHECKS the generated
// operations call. Kept out of the generated sources so the generator never has
// to know what they do — only that they exist.

#include <algorithm>
#include <stdexcept>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "axiam/management_models.hpp"
#include "management_checks.hpp"

namespace axiam::management {

// ---- §30 directory ---------------------------------------------------------

SetDirectoryConfig DirectoryConfig::to_input() const {
    // The read-modify-write form (§27.4 rule 5): every member the read carried,
    // so a replacement changes only what the caller then changes. `bind_secret`
    // is absent — "keep the stored secret" — because no read ever carries it
    // (§30.2); moving the connection still needs it set again (§30.3 rule 2).
    SetDirectoryConfig out(enabled, kind, url, start_tls, bind_dn, base_dn, user_filter);
    out.group_base_dn = group_base_dn;
    out.group_filter = group_filter;
    out.group_mappings = group_mappings;
    out.group_member_attribute = group_member_attribute;
    out.group_nesting_depth = group_nesting_depth;
    out.jit_provisioning = jit_provisioning;
    out.sync_interval_secs = sync_interval_secs;
    out.trust_anchors_pem = trust_anchors_pem;
    out.user_attribute_map = user_attribute_map;
    return out;
}

// ---- §29 saml ----------------------------------------------------------------

ParseSamlSpMetadata ParseSamlSpMetadata::from_url(std::string url) {
    ParseSamlSpMetadata out;
    out.metadata_url = std::move(url);
    return out;
}

ParseSamlSpMetadata ParseSamlSpMetadata::from_xml(std::string xml) {
    ParseSamlSpMetadata out;
    out.metadata_xml = std::move(xml);
    return out;
}

SamlServiceProviderInput SamlServiceProvider::to_input() const {
    // Every member, so the replacement changes only what the caller changes: on an
    // update an omitted member takes its DEFAULT, not its stored value (§29.2).
    SamlServiceProviderInput out(display_name, entity_id, acs_urls);
    out.allow_idp_initiated = allow_idp_initiated;
    out.allowed_groups = allowed_groups;
    out.attribute_mappings = attribute_mappings;
    out.enabled = enabled;
    out.encrypt_assertions = encrypt_assertions;
    out.name_id_format = name_id_format;
    out.sign_responses = sign_responses;
    out.slo_binding = slo_binding;
    out.slo_url = slo_url;
    out.sp_encryption_cert_pem = sp_encryption_cert_pem;
    out.sp_signing_cert_pem = sp_signing_cert_pem;
    out.want_authn_requests_signed = want_authn_requests_signed;
    return out;
}

// ---- §32 ssf -----------------------------------------------------------------

SsfStreamInput SsfStream::to_input() const {
    // `authorization_header` absent: no read carries it, and absent keeps the
    // stored one (§32.2). `clear_authorization_header` stays unset.
    SsfStreamInput out(receiver_client_id, audience, delivery_method, events_allowed);
    out.description = description;
    out.endpoint_url = endpoint_url;
    out.events_requested = events_requested;
    out.status = status;
    out.status_reason = status_reason;
    out.subject_format = subject_format;
    // §32.2 (contract 1.61): an edit sends the `events_requested` it read -- an empty
    // list stays an empty list, copied above and never omitted, because an absent member
    // resets the stream to every allowed event -- and the version it read, so a write
    // that landed since (the receiver's included) is a 409 instead of being reverted.
    out.expected_updated_at = updated_at;
    return out;
}

SsfStreamInput SsfStream::to_input(const SsfStreamChanges& changes) const {
    // The change-taking form (CONTRACT.md §32.2, contract 1.62): the plain converter's body --
    // `events_requested` and `expected_updated_at` as read -- with the caller's changes laid
    // over it, and the cut the plain converter leaves to its caller made here.
    SsfStreamInput out = to_input();

    if (changes.receiver_client_id) out.receiver_client_id = *changes.receiver_client_id;
    if (changes.audience) out.audience = *changes.audience;
    if (changes.delivery_method) out.delivery_method = *changes.delivery_method;
    if (changes.description) out.description = *changes.description;
    if (changes.endpoint_url) out.endpoint_url = *changes.endpoint_url;
    if (changes.status) out.status = *changes.status;
    if (changes.status_reason) out.status_reason = *changes.status_reason;
    if (changes.subject_format) out.subject_format = *changes.subject_format;
    if (changes.authorization_header) out.authorization_header = changes.authorization_header;
    if (changes.clear_authorization_header) {
        out.clear_authorization_header = changes.clear_authorization_header;
    }

    if (changes.events_allowed) {
        out.events_allowed = *changes.events_allowed;
        if (!changes.events_requested) {
            // Lowering the ceiling: the entries of the list that was read that are still
            // inside it, in their order -- a requested event outside `events_allowed` is a
            // 400, and leaving the member out would reset the stream to every allowed event
            // (the receiver's narrowing widened, §32.2). `{}` stays `{}`.
            std::vector<SsfEventType> cut;
            for (const auto& event : events_requested) {
                const auto& ceiling = *changes.events_allowed;
                if (std::find(ceiling.begin(), ceiling.end(), event) != ceiling.end()) {
                    cut.push_back(event);
                }
            }
            out.events_requested = std::move(cut);
        }
    }
    // Named by the caller: sent as given, `{}` included -- the server judges it.
    if (changes.events_requested) out.events_requested = *changes.events_requested;

    // §27.11 rule 5 / §32.2: an assigned null is "none". The member is optional on the input,
    // so a disengaged inner value is already "the key is omitted"; `null` has no spelling.
    if (changes.expected_updated_at) out.expected_updated_at = *changes.expected_updated_at;
    return out;
}

// ---- §31 scim_targets --------------------------------------------------------

ScimTargetInput ScimTargetResponse::to_input() const {
    // `credential` absent: no read carries it, and absent keeps the stored one.
    ScimTargetInput out(name, base_url, auth, scope);
    out.deprovision = deprovision;
    out.enabled = enabled;
    out.push_groups = push_groups;
    out.user_name_from = user_name_from;
    // §31.3 rule 4 (contract 1.60): the read-modify-write form sends the version it
    // read, so an administrator's write that landed since is a 409, not overwritten.
    out.expected_updated_at = updated_at;
    return out;
}

ScimTargetAuth ScimTargetAuth::bearer() {
    ScimTargetAuth out;
    out.type = "bearer";
    out.raw = nlohmann::json{{"type", out.type}}.dump();
    return out;
}

ScimTargetAuth ScimTargetAuth::oauth2_client_credentials(std::string token_url,
                                                         std::string client_id,
                                                         std::optional<std::string> scope) {
    ScimTargetAuth out;
    out.type = "oauth2_client_credentials";
    nlohmann::json j{{"type", out.type}, {"token_url", std::move(token_url)},
                     {"client_id", std::move(client_id)}};
    if (scope) j["scope"] = std::move(*scope);
    out.raw = j.dump();
    return out;
}

ScimTargetScope ScimTargetScope::all_users() {
    ScimTargetScope out;
    out.type = "all_users";
    out.raw = nlohmann::json{{"type", out.type}}.dump();
    return out;
}

ScimTargetScope ScimTargetScope::groups(std::vector<std::string> group_ids) {
    ScimTargetScope out;
    out.type = "groups";
    out.raw = nlohmann::json{{"type", out.type}, {"group_ids", std::move(group_ids)}}.dump();
    return out;
}

}  // namespace axiam::management

namespace axiam::management::checks {

void parse_sp_metadata_exactly_one(const ParseSamlSpMetadata& body) {
    if (body.metadata_url.has_value() != body.metadata_xml.has_value()) return;
    throw std::invalid_argument(
        "saml.parse_sp_metadata: set exactly one of metadata_xml and metadata_url — use "
        "ParseSamlSpMetadata::from_url() or from_xml() (CONTRACT.md §29.2); refused before "
        "any request");
}

}  // namespace axiam::management::checks
