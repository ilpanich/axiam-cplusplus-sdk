// In-memory fake transport for unit tests: records outgoing requests and returns
// canned responses via a user-supplied router. Lets the whole logic layer be
// exercised without any network.
#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "axiam/transport.hpp"

namespace axtest {

struct RecordedReq {
    std::string method;
    std::string url;
    std::string body;
    axiam::HeaderMap headers;
};

struct FakeState {
    std::mutex mtx;
    std::vector<RecordedReq> requests;
    // Router: (request, state) -> response. May inspect/mutate state.
    std::function<axiam::HttpResponse(const axiam::HttpRequest&, FakeState&)> router;

    std::size_t count() {
        std::lock_guard<std::mutex> lock(mtx);
        return requests.size();
    }
    RecordedReq last() {
        std::lock_guard<std::mutex> lock(mtx);
        return requests.back();
    }
    std::size_t count_path(const std::string& needle) {
        std::lock_guard<std::mutex> lock(mtx);
        std::size_t n = 0;
        for (const auto& r : requests) {
            if (r.url.find(needle) != std::string::npos) ++n;
        }
        return n;
    }
};

inline axiam::Transport make_fake(std::shared_ptr<FakeState> st) {
    return [st](const axiam::HttpRequest& req) -> axiam::HttpResponse {
        {
            std::lock_guard<std::mutex> lock(st->mtx);
            st->requests.push_back({req.method, req.url, req.body, req.headers});
        }
        return st->router(req, *st);
    };
}

inline axiam::HttpResponse json_response(long status, std::string body) {
    axiam::HttpResponse r;
    r.status = status;
    r.body = std::move(body);
    r.headers["Content-Type"] = "application/json";
    return r;
}

}  // namespace axtest
