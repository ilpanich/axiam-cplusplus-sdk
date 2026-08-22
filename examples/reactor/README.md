# An AXIAM Reactor — CONTRACT.md §22

**The protocol core is the SDK's. The transport is yours.**

Until contract 1.28 this directory held a *hand-rolled* reactor: eight hundred
lines reimplementing the canonical serialization, the v2 HMAC, the freshness and
nonce checks and the §22.5 allow-lists, because the SDK shipped none of them.

[`CONTRACT.md`](../../CONTRACT.md) **§22.11** now says that split was cut one
notch too wide:

> the convenience that genuinely needed a vendored dependency was the
> **connection**, and the runtime around it needed none.

So §22.1–§22.8 and §22.14 are in the library — `<axiam/reactor.hpp>`,
[tested against the committed §22.13 vectors](../../tests/test_reactor.cpp) —
and [`reactor.cpp`](reactor.cpp) is what remains: a transport, a handler, and
the §8b guard that runs before either.

**What is still deferred is the AMQP client**, and only that. There is no
maintained client for these targets this project is willing to vendor, which is
the same reason §8 has never listed C++ among the SDKs that speak AMQP.

## What the SDK gives you

| Rule | Where |
|---|---|
| §22.2 — the MAC runs in **both** directions under one tenant subkey | `reactor_verify_event`, `reactor_build_reply` |
| §22.2 — `hmac_signature` is serialized as **`null`** inside the signed bytes, *not* omitted as §8's own two message types omit it | `reactor_canonical_reply` |
| §22.2 — declared field order, and the omission of `reason`/`patch` when absent and `require_mfa` when false | `reactor_canonical_reply` |
| §22.3 — key version, then MAC, then freshness, then nonce; **only then** the payload | `reactor_verify_event` |
| §22.3 — freshness is two-sided; a future timestamp is not "extra fresh" | `reactor_verify_event` |
| §22.4 — a patch is sent **unfiltered**; `allow` + `patch` has no representation | `ReactorDecision` |
| §22.5 — the registry and its namespace-prefix allow-list rule | `reactor_patch_field_allowed` |
| §22.7 — the hot-path decision operations appear in no constant and no list | (by absence — `reactor_event_names()`) |
| §22.8 — the **strictest** default failure policy wins, in either array order | `reactor_default_failure_policy` |
| §22.10 — verify, dispatch, sign, publish; fail closed on its own errors | `reactor_serve` |
| §22.11 — the transport interface carries no declare or bind method | `ReactorTransport` |
| §22.14 — one handler per event; an unbound event **abstains** | `ReactorRouter` |
| §8b rules 1–5 — the broker URL, checked before a socket exists | `amqps_endpoint` |

## What you still have to supply

**The AMQP client.** `rabbitmq-c`, `SimpleAmqpClient` and `AMQP-CPP` are all
commonly used; whichever you choose, implement `axiam::ReactorTransport` over it.
The interface has exactly two methods, and the absences are the point:

- **§8b** — connect over `amqps://` with a supplied CA bundle. `amqps_endpoint()`
  is the check, and §22.11 rule 3 is why it is a *function* rather than a
  paragraph: a requirement that reads as enforced and is not is worse than one
  that is plainly absent. There is no verification-skip switch, no plaintext
  fallback, and **no loopback exception** — §6's `http://localhost` dev carve-out
  does not extend to the broker, and the server has no plaintext listener for
  such an exception to reach.
- **§22.1** — consume `axiam::reactor_queue_name(tenant_id, reactor_id)`, the
  queue the **server** declared, with manual acknowledgement, and **declare
  nothing**. No exchange, no queue, no binding. A reactor that can bind is a
  reactor that can bind itself to `*.token.pre_issue` and read another tenant's
  issuance events — which is why `ReactorTransport` gives you no method with
  which to.
- **§22.1** — publish the reply to the delivery's `reply_to` through the default
  exchange, echoing its `correlation_id` property. What the server authenticates
  is the `correlation_id` *inside the signed reply body*; the runtime copies it
  from the event for you, because copying it only into the AMQP property
  produces a reply the server discards.

Everything above the transport — verify, dispatch, sign, publish-or-abstain — is
`reactor_serve()`'s, including the rule that a failure of its own publishes
**nothing**: a handler that throws, a body it cannot verify, or a window that has
closed all produce no reply, and the registration's `failure_policy` decides. A
synthesized `allow` would override an operator's `fail_closed` from inside the
library.

## Writing the handler

`reactor_serve()` takes one function from a verified event to one answer, which
is the right shape for the wire and the wrong shape for the code. Use
`ReactorRouter` (§22.14) instead: it binds one handler per event, refuses an
unregistered name **at bind time** rather than as an event that silently never
fires, and makes an unbound event *abstain* rather than answering `allow` from a
`default:` arm in a file nobody reads.

The event's `payload_json` is JSON **text**, not a parsed model — this SDK's
public headers carry no JSON type, and handing back the bytes leaves you free to
use whatever parser your service already has. `_reactor_patch`, when present, is
the patch accumulated by earlier reactors in the chain: read-only context.
Echoing it back inside your own patch is not how a field is preserved; the server
merges (§22.6).

**Do not log the payload at info level by default** (§22.12). The signing key is
a credential and must not appear at any level, including in a reconnect
diagnostic; `Sensitive<std::string>` renders it as `[SENSITIVE]` whatever the
content.

## Build and run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DAXIAM_BUILD_EXAMPLES=ON
cmake --build build -j
./build/examples/axiam_example_reactor
```

It needs no broker, no server and no network: it runs the §8b guard, drives the
runtime over a transport that replays the committed §22.13 event vectors, and
exits non-zero if a reply it produced differs from what the server signed.
