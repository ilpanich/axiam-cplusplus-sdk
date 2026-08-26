// The one wire path every §27 management operation goes through (CONTRACT.md §27.8).
//
// Not installed; not part of the public ABI. The generated handles hold a
// shared_ptr<Transport> and nothing else, so §27.8's "the generated layer sits on the
// SDK's existing request path" is a property of the type rather than of 146 call sites
// each remembering to use it.

#ifndef AXIAM_MANAGEMENT_TRANSPORT_HPP
#define AXIAM_MANAGEMENT_TRANSPORT_HPP

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "axiam/client.hpp"
#include "axiam/management.hpp"
#include "client_impl.hpp"

namespace axiam::management {

/// One `{name}` -> value substitution for a path template.
struct PathValue {
    std::string name;
    std::string value;
};

/// One query parameter. A disengaged `value` is OMITTED, never sent empty.
struct QueryValue {
    std::string name;
    std::optional<std::string> value;
};

class Transport {
public:
    explicit Transport(std::shared_ptr<Client::Impl> impl) : impl_(std::move(impl)) {}

    /// The client's `{org_id}`, resolved through the scope (§27.4 rule 3).
    ///
    /// Throws when neither the scope nor the client has one: sending an empty path
    /// segment produces `/api/v1/organizations//tenants`, which is not a 404 anybody can
    /// act on but a route that does not exist, reported as if the object were missing.
    std::string org_id(const CallScope& scope) const;

    /// The client's `{tenant_id}`, resolved through the scope. This is the UUID, never
    /// the §5 tenant SLUG -- the two are not interchangeable in a path segment.
    std::string tenant_id(const CallScope& scope) const;

    /// Issue one management operation and return its decoded body.
    ///
    /// `path_template` is the `{placeholder}` form and is what telemetry sees;
    /// `values` are substituted into it and URL-encoded. Passing one string for both
    /// would compile and quietly put identifiers into metrics labels, so the template is
    /// never reconstructed from the concrete path.
    ///
    /// Adds exactly what §27 asks for on top of the shared request path:
    ///   rule 1  -- no session, no wire call, checked before the request is built;
    ///   rule 7  -- the status classification;
    ///   rule 8  -- only GET is retried, and never a rejected body;
    ///   rule 10 -- nothing is cached;
    ///   rule 11 -- telemetry carries the path TEMPLATE.
    nlohmann::json send(const std::string& operation,
                        const std::string& http_method,
                        const std::string& path_template,
                        const std::vector<PathValue>& values,
                        const std::vector<QueryValue>& query,
                        const std::optional<nlohmann::json>& body) const;

    /// Decode a response body into `T`, reporting a malformed one as an SDK error.
    ///
    /// nlohmann throws its own exception type when a field openapi.json marks required is
    /// absent. Left alone that escapes the §2 taxonomy entirely: a caller who wrote
    /// `catch (const AxiamError&)` around a management call would not catch it, and the
    /// message names neither the operation nor the fact that the SERVER sent something
    /// short. This is where that class of failure becomes a NetworkError -- which is
    /// accurate, since a truncated body IS a transport-level problem.
    template <typename T>
    static T decode(const nlohmann::json& j, const std::string& operation) {
        try {
            return j.get<T>();
        } catch (const nlohmann::json::exception& e) {
            throw NetworkError(operation + ": the server's response did not match the "
                               "expected shape (" + e.what() + ")");
        }
    }

    /// Decode a page envelope. `total` comes from the server's own count, never from
    /// `items.size()` -- the two differ on every page but the last (§27.4 rule 4).
    template <typename T>
    static Page<T> to_page(const nlohmann::json& j, const PageRequest& request,
                           const std::string& operation) {
        Page<T> page;
        page.request = request;
        const auto items = j.contains("items") ? j.at("items")
                         : (j.contains("data") ? j.at("data") : nlohmann::json::array());
        if (items.is_array()) {
            for (const auto& item : items) page.items.push_back(decode<T>(item, operation));
        }
        if (j.contains("total") && j.at("total").is_number()) {
            page.total = j.at("total").get<std::int64_t>();
        } else if (j.contains("total_count") && j.at("total_count").is_number()) {
            page.total = j.at("total_count").get<std::int64_t>();
        } else {
            page.total = static_cast<std::int64_t>(page.items.size());
        }
        return page;
    }

    /// The paging pair as query values.
    static std::vector<QueryValue> paging(const PageRequest& page);

private:
    std::shared_ptr<Client::Impl> impl_;
};

}  // namespace axiam::management

#endif  // AXIAM_MANAGEMENT_TRANSPORT_HPP
