// The one §27 wire path -- see management_transport.hpp.

#include "management_transport.hpp"

#include <cctype>
#include <chrono>
#include <cstdio>
#include <sstream>
#include <stdexcept>

namespace axiam::management {
namespace {

// Percent-encode a path segment. An identifier is caller-supplied, and a raw '/' or '?'
// in one would silently retarget the request at a different route.
std::string url_encode(const std::string& in) {
    static const char* kHex = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size());
    for (unsigned char ch : in) {
        const bool unreserved = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                                (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
                                ch == '.' || ch == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(ch));
        } else {
            out.push_back('%');
            out.push_back(kHex[ch >> 4]);
            out.push_back(kHex[ch & 0x0F]);
        }
    }
    return out;
}

std::string substitute(const std::string& tmpl, const std::vector<PathValue>& values) {
    std::string path = tmpl;
    for (const auto& v : values) {
        const std::string placeholder = "{" + v.name + "}";
        const auto at = path.find(placeholder);
        if (at == std::string::npos) continue;
        path.replace(at, placeholder.size(), url_encode(v.value));
    }
    return path;
}

std::string with_query(std::string path, const std::vector<QueryValue>& query) {
    bool first = true;
    for (const auto& q : query) {
        if (!q.value) continue;  // an unset optional query parameter is OMITTED
        path += first ? '?' : '&';
        path += q.name;
        path += '=';
        path += url_encode(*q.value);
        first = false;
    }
    return path;
}

// Resolution order: the per-call scope, then the client's configured id, then the one
// resolved from the access-token claims at login (D-14). Throwing rather than returning
// an empty string is deliberate: `/api/v1/organizations//tenants` is not a 404 anybody
// can act on, it is a route that does not exist reported as a missing object.
const std::string& first_nonempty(const std::optional<std::string>& a,
                                  const std::optional<std::string>& b,
                                  const std::optional<std::string>& c,
                                  const char* what) {
    if (a && !a->empty()) return *a;
    if (b && !b->empty()) return *b;
    if (c && !c->empty()) return *c;
    throw AxiamError(std::string("this operation needs ") + what +
                     ": construct the client with one, or scope the handle with "
                     "in_org()/for_tenant() (CONTRACT.md §27.4 rule 3)");
}

}  // namespace

PageRequest PageRequest::next() const {
    PageRequest out;
    out.limit = limit < 1 ? 50 : limit;
    out.offset = (offset < 0 ? 0 : offset) + out.limit;
    // §27.4 rule 4: the term is part of WHICH PAGE this is, so it travels with the walk.
    // Dropping it here would return the matches followed by the unfiltered tail, which
    // reads as a server bug from the caller's side.
    out.search = search;
    return out;
}

PageRequest PageRequest::matching(std::string term) const {
    PageRequest out = *this;
    out.search = std::move(term);
    return out;
}

std::string PageRequest::normalize_search(const std::string& term) {
    const auto is_space = [](unsigned char c) { return std::isspace(c) != 0; };
    auto begin = term.begin();
    while (begin != term.end() && is_space(static_cast<unsigned char>(*begin))) ++begin;
    auto end = term.end();
    while (end != begin && is_space(static_cast<unsigned char>(*(end - 1)))) --end;
    return std::string(begin, end);
}

std::vector<QueryValue> Transport::paging(const PageRequest& page) {
    const std::int64_t offset = page.offset < 0 ? 0 : page.offset;
    const std::int64_t limit = page.limit < 1 ? 50 : page.limit;
    std::vector<QueryValue> query{{"offset", std::to_string(offset)},
                                  {"limit", std::to_string(limit)}};
    // Absent and blank are the SAME request (§27.4 rule 4), so a term that normalises away
    // adds no key at all rather than an empty one: `?search=` is a filter matching nothing,
    // which is a different question from not filtering.
    if (auto term = PageRequest::normalize_search(page.search); !term.empty()) {
        query.push_back({"search", std::move(term)});
    }
    return query;
}

std::string Transport::org_id(const CallScope& scope) const {
    return first_nonempty(scope.org_id, impl_->org_id, impl_->resolved_org_id,
                          "an organization id");
}

std::string Transport::tenant_id(const CallScope& scope) const {
    return first_nonempty(scope.tenant_id, impl_->tenant_id, impl_->resolved_tenant_id,
                          "a tenant id");
}

nlohmann::json Transport::send(const std::string& operation,
                               const std::string& http_method,
                               const std::string& path_template,
                               const std::vector<PathValue>& values,
                               const std::vector<QueryValue>& query,
                               const std::optional<nlohmann::json>& body) const {
    impl_->ensure_open();

    // Rule 1: no session, no wire call. Checked before the request is built rather than
    // left to the server's 401 -- it costs the caller nothing, cannot be counted against
    // a rate limit, and the message names the operation.
    {
        std::lock_guard<std::mutex> lock(impl_->state_mtx);
        if (!impl_->session) {
            throw AuthError(operation +
                            ": no active session -- management operations require an "
                            "authenticated caller (CONTRACT.md §27.4 rule 1)");
        }
    }

    const std::string path = with_query(substitute(path_template, values), query);
    const std::string payload = body ? body->dump() : std::string{};

    // Rule 8: a GET is the only method §16 may replay. Everything else may already have
    // been applied server-side, and no client can tell from a transport failure. A 4xx is
    // never replayed either: it is a decisive answer, and re-sending it just spends the
    // caller's rate limit to be told the same thing again.
    const bool retryable = http_method == "GET";
    const int budget = (retryable && impl_->retry_enabled) ? 3 : 1;

    for (int attempt = 1;; ++attempt) {
        // Rule 11: the TEMPLATE, never the substituted path. A metrics label carrying a
        // user id is an unbounded-cardinality series and, on this surface, a slow
        // identifier leak into whatever consumes the telemetry.
        impl_->emit(RequestStartEvent{operation, http_method, path_template, attempt});
        const auto started = std::chrono::steady_clock::now();

        std::optional<HttpResponse> resp;
        std::exception_ptr thrown;
        std::optional<long> status;
        try {
            resp = impl_->send_raw(impl_->build_request(http_method, path, payload));
            status = resp->status;
        } catch (const NetworkError&) {
            thrown = std::current_exception();
        }

        const bool ok = status && *status >= 200 && *status < 300;
        impl_->emit(RequestEndEvent{operation, http_method, path_template, attempt, status,
                                    std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::steady_clock::now() - started),
                                    ok ? Outcome::kSuccess : Outcome::kFailure});

        if (ok) {
            if (resp->status == 204 || resp->body.empty()) return nlohmann::json();
            try {
                return nlohmann::json::parse(resp->body);
            } catch (const nlohmann::json::exception&) {
                throw NetworkError(operation +
                                   ": expected a JSON object or array in the response body");
            }
        }

        const bool worth_retrying = attempt < budget && (!status || *status >= 500);
        if (worth_retrying) {
            const auto wait = detail::retry_delay(attempt, std::nullopt, impl_->jitter());
            impl_->emit(RetryEvent{operation, attempt, wait,
                                   status ? "HTTP " + std::to_string(*status)
                                          : std::string("transport failure")});
            impl_->sleeper(wait);
            continue;
        }

        if (thrown) std::rethrow_exception(thrown);

        // Rule 7's classification. Three statuses get a sub-type INSIDE the §2 taxonomy;
        // everything else falls through to §2's own mapping, so the management surface
        // cannot drift from the rest of the SDK on 401, 403 or 5xx.
        const std::string where = operation + ": ";
        switch (resp->status) {
            case 404: throw NotFoundError(where + "not found (HTTP 404)");
            case 409: throw ConflictError(where + "conflict (HTTP 409)");
            case 400: throw ValidationError(where + "invalid request (HTTP 400)");
            case 422: throw ValidationError(where + "invalid request (HTTP 422)");
            default: break;
        }
        Client::Impl::raise_for_status(*resp);
    }
}

}  // namespace axiam::management
