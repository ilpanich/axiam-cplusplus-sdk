// Local checks a generated §27 operation runs before any I/O (the generator's
// PRECHECKS table names them). Internal; not installed.

#ifndef AXIAM_MANAGEMENT_CHECKS_HPP
#define AXIAM_MANAGEMENT_CHECKS_HPP

#include "axiam/management_models.hpp"

namespace axiam::management::checks {

/// CONTRACT.md §29.2: `ParseSamlSpMetadata` is `{ metadata_xml }` or
/// `{ metadata_url }` — exactly one. Both, or neither, is refused here with
/// std::invalid_argument (C++'s local ValidationError mapping, §28.7) before
/// any request, rather than sent for the server to refuse.
void parse_sp_metadata_exactly_one(const ParseSamlSpMetadata& body);

}  // namespace axiam::management::checks

#endif  // AXIAM_MANAGEMENT_CHECKS_HPP
