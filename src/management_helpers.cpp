// Hand-written members of generated §27 models (the generator's MODEL_MEMBERS
// table declares them; this file defines them), and the PRECHECKS the generated
// operations call. Kept out of the generated sources so the generator never has
// to know what they do — only that they exist.

#include <stdexcept>

#include "axiam/management_models.hpp"
#include "management_checks.hpp"

namespace axiam::management {

// ---- §30 directory ---------------------------------------------------------

SetDirectoryConfig DirectoryConfig::to_input() const {
    // The read-modify-write form (§27.4 rule 5): every member the read carried,
    // so a replacement changes only what the caller then changes. `bind_secret`
    // is absent — "keep the stored secret" — because no read ever carries it
    // (§30.2); moving the connection still needs it set again (§30.3 rule 2).
    SetDirectoryConfig out;
    out.base_dn = base_dn;
    out.bind_dn = bind_dn;
    out.enabled = enabled;
    out.group_base_dn = group_base_dn;
    out.group_filter = group_filter;
    out.group_mappings = group_mappings;
    out.group_member_attribute = group_member_attribute;
    out.group_nesting_depth = group_nesting_depth;
    out.jit_provisioning = jit_provisioning;
    out.kind = kind;
    out.start_tls = start_tls;
    out.sync_interval_secs = sync_interval_secs;
    out.trust_anchors_pem = trust_anchors_pem;
    out.url = url;
    out.user_attribute_map = user_attribute_map;
    out.user_filter = user_filter;
    return out;
}

}  // namespace axiam::management
