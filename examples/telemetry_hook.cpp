// Telemetry hooks (CONTRACT.md §19): wiring metrics to an AXIAM client
// WITHOUT this library depending on any metrics package.
//
// The sink below aggregates in-process so the example builds with no extra
// dependencies; the comment at the bottom shows the exact mapping onto
// OpenTelemetry / Prometheus, which is a drop-in replacement for the body.
// Uses ONLY public headers.
//
// Build: cmake -S . -B build -DAXIAM_BUILD_EXAMPLES=ON && cmake --build build
// Run:   AXIAM_BASE_URL=https://iam.example.com AXIAM_TENANT=acme \
//            ./build/examples/axiam_example_telemetry_hook

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <variant>

#include "axiam/axiam.hpp"

namespace {

struct Metrics {
    std::mutex mtx;
    // Keyed by "operation/outcome" — one entry per WIRE call, not per logical
    // operation, which is what §19.2 rule 5's per-attempt pairing buys you.
    std::map<std::string, std::pair<long, long>> requests;  // count, total ms
    std::map<std::string, long> retries;
    long refreshes = 0;
};

Metrics g_metrics;

void sink(const axiam::TelemetryEvent& event) {
    std::lock_guard<std::mutex> lock(g_metrics.mtx);

    if (const auto* e = std::get_if<axiam::RequestEndEvent>(&event)) {
        // One pair per ATTEMPT (§19.2 rule 5), so counting these gives the real
        // number of wire calls — including the ones a retry made on your behalf.
        const std::string key =
            e->operation + "/" +
            (e->outcome == axiam::Outcome::kSuccess ? "success" : "failure");
        auto& stat = g_metrics.requests[key];
        stat.first += 1;
        stat.second += e->duration.count();

    } else if (const auto* e = std::get_if<axiam::RetryEvent>(&event)) {
        // §16.5 — the reason this event exists. A retried-then-succeeded
        // operation is otherwise invisible: the caller sees a slow success and
        // no signal that the server is failing. Alert on THIS rate, not on the
        // error rate, or a degrading server looks healthy right up until the
        // retries stop being enough.
        g_metrics.retries[e->operation] += 1;

    } else if (std::holds_alternative<axiam::RefreshEvent>(event)) {
        g_metrics.refreshes += 1;

    } else if (const auto* e = std::get_if<axiam::ConfigClampedEvent>(&event)) {
        // §19.2 rule 6 — fired at most once per clamped setting, at
        // construction. Worth logging loudly rather than counting: it means a
        // value in your configuration is not the value in force, and the gap is
        // silent everywhere else.
        std::cerr << "WARN: " << e->setting << "=" << e->requested
                  << " was clamped to " << e->effective << " (" << e->contract_reference
                  << ")\n";
    }
    // RequestStartEvent is deliberately unhandled here: RequestEndEvent carries
    // the same identity plus the outcome, so counting both would double-count.
}

const char* env_or_null(const char* name) {
    const char* v = std::getenv(name);
    return (v && *v) ? v : nullptr;
}

}  // namespace

int main() {
    const char* base = env_or_null("AXIAM_BASE_URL");
    const char* tenant = env_or_null("AXIAM_TENANT");
    if (!base || !tenant) {
        std::cerr << "set AXIAM_BASE_URL and AXIAM_TENANT\n";
        return 2;
    }

    try {
        auto client = axiam::Client::builder()
                          .base_url(base)
                          .tenant_slug(tenant)
                          .telemetry_hook(sink)
                          // Deliberately above the §17.1 rule 2 ceiling, so the
                          // run demonstrates the config_clamped warning above
                          // rather than leaving it theoretical.
                          .decision_memo_ttl(std::chrono::seconds(60))
                          .build();

        try {
            const auto decision = client.check_access("read", "doc-1");
            std::cout << "allowed=" << decision.allowed << " reason_code="
                      << decision.reason_code.value_or("(absent)") << "\n";
        } catch (const axiam::AxiamError& e) {
            std::cout << "check failed: " << e.what() << "\n";
        }

        {
            std::lock_guard<std::mutex> lock(g_metrics.mtx);
            std::cout << "--- telemetry ---\n";
            for (const auto& [key, stat] : g_metrics.requests) {
                std::cout << "  " << key << ": count=" << stat.first
                          << " mean=" << (stat.first ? stat.second / stat.first : 0) << "ms\n";
            }
            if (g_metrics.retries.empty()) {
                std::cout << "  retries: (none)\n";
            }
            for (const auto& [op, n] : g_metrics.retries) {
                std::cout << "  retries " << op << ": " << n << "\n";
            }
            std::cout << "  refreshes: " << g_metrics.refreshes << "\n";
        }

        // §18: releases the transport and the cookie jar without issuing a
        // request. It does NOT log out — the server-side session outlives this
        // process. The destructor would release it anyway; calling close()
        // explicitly is how you choose *when*.
        client.close();
    } catch (const std::exception& e) {
        std::cerr << "client construction failed: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

/*
 * Mapping onto a real backend — replace sink()'s body, nothing else:
 *
 *   RequestEndEvent    → histogram "axiam.request.duration"
 *                        labels: operation, path_template, status, outcome, attempt
 *   RetryEvent         → counter   "axiam.request.retries"   labels: operation
 *   RefreshEvent       → counter   "axiam.token.refresh"     labels: role
 *   ConfigClampedEvent → a log line at WARN, not a metric: it fires once at
 *                        construction and its whole value is being READ.
 *
 * Label with `path_template`, never with the request URL: a metric label
 * carrying a UUID is a cardinality bomb. The hook runs on the calling thread,
 * so it must not block — every mature metrics library already buffers, which is
 * why §19.2 rule 4 leaves that choice to you rather than making it here.
 */
