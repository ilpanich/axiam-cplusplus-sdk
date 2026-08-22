// reactor.cpp — an AXIAM Reactor built on the SDK's §22 protocol core, driven by
// a transport the caller supplies (CONTRACT.md §22, §22.11).
//
// WHAT CHANGED IN CONTRACT 1.28, AND WHY THIS FILE IS SHORTER THAN IT WAS.
//
// This used to be a hand-rolled reactor: eight hundred lines reimplementing the
// canonical serialization, the v2 HMAC, the freshness and nonce checks and the
// §22.5 allow-lists, because the SDK shipped none of it. §22.11 now says that
// split was cut one notch too wide — the part deferred for want of a DEPENDENCY
// was the transport, and the part every integrator was left to hand-roll from
// prose was the PROTOCOL, which is the half with the sharp edges and none of them
// AMQP-shaped.
//
// So all of that now lives in <axiam/reactor.hpp>, tested against the committed
// §22.13 vectors, and this file is what remains: a transport, a handler, and the
// §8b guard that has to run before either.
//
// WHAT THIS SDK STILL DOES NOT SHIP is an AMQP client. §22.11 keeps that
// deferral: there is no maintained client for these targets this project is
// willing to vendor. The transport below is where yours goes.
//
// Build:  cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
// Run:    ./build/examples/axiam_example_reactor
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "axiam/axiam.hpp"

namespace {

using json = nlohmann::json;

std::string env_or(const char* key, const std::string& fallback) {
    const char* v = std::getenv(key);
    return (v && *v) ? std::string(v) : fallback;
}

// ---------------------------------------------------------------------------
// The transport seam — the part this project does not fill for you
//
// Bind whichever AMQP client you already trust. Its obligations are §22.1's and
// §8b's, not this file's:
//
//   * connect over `amqps://` with a supplied CA bundle, no verification-skip
//     switch and no plaintext fallback — axiam::amqps_endpoint() below is the
//     check, and §22.11 rule 3 is why it is a function rather than a paragraph;
//   * consume axiam::reactor_queue_name(tenant_id, reactor_id) — the queue the
//     SERVER declared — with manual acknowledgement;
//   * DECLARE NOTHING. No exchange, no queue, no binding. §22.1 is a MUST NOT,
//     and note that this interface gives you no method with which to;
//   * publish the reply to the delivery's `reply_to` through the default
//     exchange, echoing its `correlation_id` property. What the server actually
//     authenticates is the `correlation_id` INSIDE the signed reply body — the
//     runtime copies it from the event, because copying it only into the AMQP
//     property produces a reply the server discards.
//
// Everything above the transport — verify, dispatch, sign, publish-or-abstain —
// is axiam::reactor_serve()'s, including the rule that a failure of its own
// publishes NOTHING.
// ---------------------------------------------------------------------------

/// A transport that replays the committed §22.13 event vectors and prints what
/// would go on the wire. Swap it for your AMQP client; nothing else moves.
class ReplayTransport final : public axiam::ReactorTransport {
public:
    explicit ReplayTransport(std::vector<std::string> bodies) : bodies_(std::move(bodies)) {}

    std::optional<axiam::ReactorDelivery> next_delivery() override {
        if (at_ >= bodies_.size()) return std::nullopt;
        axiam::ReactorDelivery delivery;
        delivery.body = bodies_[at_++];
        delivery.reply_to = "amq.rabbitmq.reply-to.example";
        return delivery;
    }

    void publish_reply(const std::string& destination, const std::string& correlation_id,
                       const std::string& body) override {
        ++published;
        std::cout << "  → publish to " << destination << " (correlation " << correlation_id
                  << ")\n    " << body << "\n";
    }

    int published = 0;

private:
    std::vector<std::string> bodies_;
    std::size_t at_ = 0;
};

std::string hex_to_bytes(const std::string& hex) {
    std::string out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<char>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

int failures = 0;
void check(bool ok, const std::string& what) {
    std::cout << (ok ? "  ok   " : "  FAIL ") << what << "\n";
    if (!ok) ++failures;
}

}  // namespace

int main(int argc, char** argv) {
    const std::string path = (argc > 1) ? argv[1] : AXIAM_REACTOR_VECTORS;
    std::ifstream file(path);
    if (!file) {
        std::cerr << "cannot open the §22.13 reference vectors at " << path << "\n";
        return 2;
    }
    const json vectors = json::parse(file, nullptr, false);
    if (vectors.is_discarded()) {
        std::cerr << "the §22.13 reference vectors at " << path << " are not valid JSON\n";
        return 2;
    }

    std::cout << "AXIAM reactor sample — CONTRACT.md §22.\n"
              << "The protocol core is the SDK's; the transport below is yours (§22.11).\n\n";

    // -----------------------------------------------------------------------
    // §8b rules 1–5, BEFORE anything opens a socket.
    //
    // This is the constructor §8b rule 7's second clause names: where an SDK
    // takes a caller-supplied connection, it must still ship the guard, and that
    // guard is what its README and examples show. Documenting the requirement
    // instead is precisely the failure contract 1.23 was written to stop — three
    // SDKs asserting `amqps://` in a doc comment above a call that accepted
    // anything.
    // -----------------------------------------------------------------------
    std::cout << "§8b — the broker URL, checked before a socket exists\n";
    const std::string broker_url = env_or("AXIAM_AMQP_URL", "amqps://broker.internal:5671/prod");
    try {
        const auto endpoint =
            axiam::amqps_endpoint(broker_url, env_or("AXIAM_AMQP_CA_PEM", ""));
        std::cout << "  ok   " << endpoint.host << ":" << endpoint.port << " vhost "
                  << endpoint.virtual_host << "\n";
    } catch (const axiam::AxiamError& e) {
        std::cerr << "  refused: " << e.what() << "\n";
        return 1;
    }
    // And there is no loopback exception (§8b rule 8): §6's `http://localhost`
    // dev carve-out does not extend to the broker, and the server has no
    // plaintext listener for such an exception to reach.
    const std::string plaintext = "amqp://localhost:5672";  // refused below — §8b rules 1 and 8
    try {
        axiam::amqps_endpoint(plaintext);
        check(false, "plaintext localhost must be refused");
    } catch (const axiam::AxiamError&) {
        check(true, "amqp://localhost is refused — no loopback exception");
    }

    // -----------------------------------------------------------------------
    // §22.14 — bind one handler per event.
    //
    // The alternative is a dispatch on `event.event` with a `default:` arm, and
    // that arm is where the second of §22.14's two defects lives: it answers on
    // behalf of code that never ran, defeating an operator's `fail_closed`
    // setting from a file they never read. Here an unbound event ABSTAINS.
    // -----------------------------------------------------------------------
    axiam::ReactorRouter router;
    router
        .on(axiam::kReactorEventLoginPostAuth,
            [](const axiam::ReactorEvent& event) -> axiam::ReactorAnswer {
                // The payload arrives as JSON TEXT — parse it with whatever your
                // service already uses.
                const json payload = json::parse(event.payload_json, nullptr, false);
                const std::string ip =
                    payload.is_object() ? payload.value("ip", std::string{}) : std::string{};
                if (ip.rfind("203.0.113.", 0) == 0) {
                    // `allow` + require_mfa on login.post_auth means "proceed
                    // only after step-up". It is not a fourth decision value, and
                    // on the federated paths there is no step-up branch — answer
                    // deny there and drive enrolment out of band (§22.5).
                    return axiam::ReactorDecision::allow_with_step_up();
                }
                return axiam::ReactorDecision::allow();
            })
        .on(axiam::kReactorEventTokenPreIssue,
            [](const axiam::ReactorEvent&) -> axiam::ReactorAnswer {
                // `ext.` is the complete allow-list for this event: no standard
                // claim begins with it, so `sub`, `aud` and the rest are
                // unreachable — a hook that could rewrite `sub` is a hook that
                // could mint a token for anyone.
                return axiam::ReactorDecision::mutate({{"ext.department", "engineering"}});
            });

    std::cout << "\n§22.8 — this reactor's strictest-wins default: "
              << axiam::reactor_default_failure_policy(router.bound_events()) << "\n";
    std::cout << "§22.1 — the queue the SERVER declared and this reactor consumes: "
              << axiam::reactor_queue_name(vectors.at("tenant_id").get<std::string>(),
                                           vectors.at("reactor_id").get<std::string>())
              << "\n";

    // -----------------------------------------------------------------------
    // §22.10 — the runtime, over the transport above.
    // -----------------------------------------------------------------------
    std::vector<std::string> bodies;
    for (const auto& [name, vector] : vectors.at("server_to_reactor").items()) {
        (void)name;
        bodies.push_back(vector.at("message").dump());
    }
    // One delivery for an event nobody bound, to show what abstention looks like
    // from the outside: no reply at all.
    ReplayTransport transport(bodies);

    axiam::ReactorConfig config;
    config.tenant_id = vectors.at("tenant_id").get<std::string>();
    config.reactor_id = vectors.at("reactor_id").get<std::string>();
    config.signing_key = axiam::Sensitive<std::string>(
        hex_to_bytes(vectors.at("hkdf").at("derived_subkey_hex").get<std::string>()));
    // Pinned so this sample is reproducible; in production both default to the
    // real clock and a CSPRNG, and neither is a knob anyone should reach for.
    config.clock = [&vectors] {
        std::tm tm{};
        ::strptime(vectors.at("verified_at").get<std::string>().c_str(), "%Y-%m-%dT%H:%M:%SZ",
                   &tm);
        return static_cast<std::int64_t>(::timegm(&tm));
    };
    config.nonce_source = [] { return std::string("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"); };

    std::cout << "\n§22.3/§22.10 — verify, dispatch, sign, publish\n";
    axiam::reactor_serve(config, transport, router.build());
    check(transport.published == static_cast<int>(bodies.size()),
          "every verified event produced exactly one signed reply");

    // -----------------------------------------------------------------------
    // The two refusals worth seeing from the outside: both produce NO REPLY, and
    // the registration's failure_policy decides (§22.10 rule 2).
    // -----------------------------------------------------------------------
    std::cout << "\nrefusals produce no reply, never a synthesized allow\n";
    {
        json tampered = vectors.at("server_to_reactor").at("login_post_auth").at("message");
        tampered["payload"]["sub"] = "mallory";
        ReplayTransport tampered_transport({tampered.dump()});
        axiam::reactor_serve(config, tampered_transport, router.build());
        check(tampered_transport.published == 0, "a tampered event is never answered");
    }
    {
        ReplayTransport throwing_transport(
            {vectors.at("server_to_reactor").at("login_post_auth").at("message").dump()});
        axiam::reactor_serve(config, throwing_transport,
                             [](const axiam::ReactorEvent&) -> axiam::ReactorAnswer {
                                 throw std::runtime_error("handler blew up");
                             });
        check(throwing_transport.published == 0, "a handler that throws is never answered");
    }

    std::cout << "\n" << (failures == 0 ? "all checks passed" : "CHECKS FAILED") << "\n";
    return failures == 0 ? 0 : 1;
}
