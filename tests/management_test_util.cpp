// Implementation of the §27 test rig -- see management_test_util.hpp.

#include "management_test_util.hpp"

#include <mutex>
#include <vector>

namespace axtest::mgmt {
namespace {

constexpr const char* kUuid = "11111111-1111-4111-8111-111111111111";

const char* kLoginOk =
    R"({"session_id":"sess-1","expires_in":900,)"
    R"("user":{"id":"user-1","username":"admin","email":"admin@acme.test",)"
    R"("tenant_id":"11111111-1111-4111-8111-111111111111"}})";

struct Canned {
    long status;
    std::string body;
};

// The queued management responses, consumed in order. A router rather than a single
// canned reply because several §27 rules -- retry, apply-stops-at-first-failure -- are
// only observable across two requests.
struct Queue {
    std::mutex mtx;
    std::vector<Canned> replies;
    std::size_t served = 0;
};

axiam::Transport routed(std::shared_ptr<FakeState> st, std::shared_ptr<Queue> queue) {
    st->router = [queue](const axiam::HttpRequest& req, FakeState&) -> axiam::HttpResponse {
        axiam::HttpResponse resp;
        if (req.url.find("/auth/login") != std::string::npos) {
            resp.status = 200;
            resp.body = kLoginOk;
            resp.headers["X-CSRF-Token"] = "csrf-1";
            return resp;
        }
        std::lock_guard<std::mutex> lock(queue->mtx);
        if (queue->served < queue->replies.size()) {
            const auto& canned = queue->replies[queue->served++];
            resp.status = canned.status;
            resp.body = canned.body;
        } else {
            resp.status = 204;
        }
        return resp;
    };
    return axtest::make_fake(std::move(st));
}

Fixture make(std::vector<Canned> replies, bool sign_in, bool scoped,
             std::shared_ptr<std::vector<std::string>> paths = nullptr) {
    auto st = std::make_shared<FakeState>();
    auto queue = std::make_shared<Queue>();
    queue->replies = std::move(replies);

    auto builder = axiam::Client::builder()
                       .base_url("https://iam.example.com")
                       .transport(routed(st, queue));
    if (paths) {
        builder.telemetry_hook([paths](const axiam::TelemetryEvent& ev) {
            if (const auto* start = std::get_if<axiam::RequestStartEvent>(&ev)) {
                paths->push_back(start->path_template);
            }
        });
    }
    if (scoped) {
        builder.tenant_id(kUuid).org_id(kUuid);
    } else {
        // A slug is a valid §5 tenant identifier but is NOT a `{tenant_id}` path segment,
        // so this client can log in and still have no UUID for §27 to substitute.
        builder.tenant_slug("acme");
    }
    auto client = builder.build();
    if (sign_in) client.login("admin@acme.test", "correct horse");
    return Fixture{std::move(st), std::move(client), std::move(paths)};
}

}  // namespace

Fixture signed_in(long status, const std::string& body) {
    return make({{status, body}}, true, true);
}

Fixture signed_in_two(long first_status, const std::string& first_body,
                      long second_status, const std::string& second_body) {
    return make({{first_status, first_body}, {second_status, second_body}}, true, true);
}

Fixture signed_in_three(long a_status, const std::string& a_body,
                        long b_status, const std::string& b_body,
                        long c_status, const std::string& c_body) {
    return make({{a_status, a_body}, {b_status, b_body}, {c_status, c_body}}, true, true);
}

Fixture signed_in_telemetry(long status, const std::string& body) {
    return make({{status, body}}, true, true, std::make_shared<std::vector<std::string>>());
}

Fixture anonymous() { return make({}, false, true); }

Fixture unscoped() { return make({}, true, false); }

}  // namespace axtest::mgmt
