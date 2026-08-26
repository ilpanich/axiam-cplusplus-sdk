// Shared rig for the CONTRACT.md §27 management tests.
//
// The fake transport sits at the BOTTOM of the real client, exactly like every other
// test here -- not in place of it. That matters for §27.8: a test that stubbed the
// management transport would pass just as happily if the generated handles had quietly
// opened their own request path, which is the one thing §27.8 forbids.
#pragma once

#include <memory>
#include <vector>
#include <string>

#include "axiam/axiam.hpp"
#include "fake_transport.hpp"

namespace axtest::mgmt {

struct Fixture {
    std::shared_ptr<FakeState> state;
    axiam::Client client;
    /// Every §19 request-start path this client emitted -- for the rule 11 assertion.
    std::shared_ptr<std::vector<std::string>> paths;
};

/// The path part of a URL -- what a route assertion cares about. The host is the
/// fixture's and the query string has its own accessor.
inline std::string path_of(const std::string& url) {
    const auto scheme = url.find("://");
    const auto start = url.find('/', scheme == std::string::npos ? 0 : scheme + 3);
    if (start == std::string::npos) return {};
    const auto end = url.find('?', start);
    return url.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

/// The query string of a URL, or "" when it has none.
inline std::string query_of(const std::string& url) {
    const auto at = url.find('?');
    return at == std::string::npos ? std::string{} : url.substr(at + 1);
}

/// A client whose next management response is `status`/`body`.
///
/// The session comes from a real login through the same fake transport, so §27.4 rule 1's
/// "no session, no wire call" check sees a genuine authenticated client rather than a
/// flag poked into place.
Fixture signed_in(long status, const std::string& body);

/// As signed_in(), but the management call gets `first` then `second` -- for the
/// multi-request cases (retry, apply-stops-at-first-failure).
Fixture signed_in_two(long first_status, const std::string& first_body,
                      long second_status, const std::string& second_body);

/// A client that has NOT logged in -- for the rule 1 cases.
Fixture anonymous();

/// As signed_in_two(), with a third queued response.
Fixture signed_in_three(long a_status, const std::string& a_body,
                        long b_status, const std::string& b_body,
                        long c_status, const std::string& c_body);

/// As signed_in(), but with a §19 telemetry hook recording every request path.
Fixture signed_in_telemetry(long status, const std::string& body);

/// A signed-in client with a tenant SLUG and no org or tenant UUID, for the routes that
/// substitute an implicit identifier and must refuse without one.
Fixture unscoped();

}  // namespace axtest::mgmt
