# CTFZone possible improvements

Status: Deferred ideas outside the current implementation scope
Last updated: 2026-08-12

This document records improvements that may become useful as CTFZone grows.
Items listed here are not required by the current architecture and must not be
treated as committed release work.

## Deferred configuration capabilities

The 1.0 administration catalog restores settings only when the Rust API
implements and validates their behavior. Preserved legacy rows are not a promise
that an older CTFd feature is active. The current semantics and complete
deferred list are documented in [`CONFIGURATION.md`](CONFIGURATION.md).

Possible future modules include object-storage-backed event branding, locale
and legal-content management, team capacity policies, social share pages,
automatic verification delivery during registration, other account email
workflows, and hardened archive or CSV transfer jobs. Each should add an
API-owned typed setting only alongside its domain behavior, authorization,
validation, and recovery tests. Raw theme HTML injection and a switch that
disables sanitization should not return; reviewed player frontend packages and
mandatory content sanitization are deliberate security boundaries.

## Server-Sent Events for live pages

**Decision:** postponed.

The current implementation should use normal page loads, explicit refreshes,
and bounded status checks following a user action. It must not continuously
poll instance or scoreboard endpoints once per second.

Server-Sent Events (SSE) may later provide live updates for:

- an instance changing from `starting` to `ready`;
- King of the Hill ownership and score changes;
- attack/defense rounds and service status;
- speedrun finishes;
- scheduled-event transitions and announcements.

The intended boundary is:

```text
Browser -- one authenticated SSE connection --> Python backend
Python backend -- internal event stream ------> Rust API
Rust API <---- PostgreSQL facts/projections and wake notifications
```

The browser must not connect to the Rust API or controller. The controller
continues to write observed state and history through PostgreSQL; it does not
hold participant connections or publish browser events.

### Why it is postponed

- Classic challenges and private-instance actions work with bounded refreshes.
- SSE is an optimization for live presentation, not part of scoring or runtime
  correctness.
- The current synchronous Flask/Gunicorn backend would reserve a worker thread
  for every open stream.
- Implementing replay, backpressure, authorization, and deployment timeouts
  correctly is unnecessary until a live event page needs them.

### Conditions for reconsidering it

Reconsider SSE when at least one of these is true:

- a KOTH, attack/defense, or speedrun page requires updates while it remains
  open;
- bounded refresh traffic becomes a measured source of material API or
  PostgreSQL load;
- organizers require event updates to appear without participant interaction;
- the Python backend has moved to an asynchronous serving model.

### Requirements for a future implementation

1. Keep the public endpoint in the Python backend and the Rust stream internal.
2. Authenticate and authorize the stream before sending event data.
3. Use page-scoped event vocabularies rather than exposing database
   notifications directly.
4. Assign monotonic event identifiers and support `Last-Event-ID` replay after
   reconnecting.
5. Bound per-client queues and disconnect slow consumers instead of allowing
   unbounded memory growth.
6. Send occasional heartbeats so Caddy and other intermediaries can detect a
   healthy idle stream.
7. Run the Python backend with an ASGI-compatible asynchronous server before
   supporting large numbers of simultaneous streams.
8. Preserve ordinary HTTP commands for browser-to-server actions; SSE remains
   server-to-browser only.
9. Test reconnects, missed-event replay, authorization changes, slow clients,
   proxy timeouts, and multi-replica behavior.

WebSockets are not the default alternative. CTFZone's anticipated live pages
mainly need server-to-browser updates, while submissions and control actions
remain ordinary authenticated HTTP requests.

## Production object-storage topology

The bundled SeaweedFS `mini` service is a convenient single-host baseline, not
an HA storage cluster. A larger or high-availability deployment should retain
the same PostgreSQL metadata and signed-transfer protocol while replacing the
byte store with a redundant S3-compatible service, versioned backups, capacity
alerts, and tested coordinated restore procedures.

Separate least-privilege credentials for API grant/promotion operations and
controller cleanup operations are also desirable. The 1.0 Compose topology
shares one storage credential between those two trusted services to keep the
first deployment understandable.

## Remote tenant networking and diagnostics

The 1.0 helper gives each instance its own bridge and random published host
port. A hardened multi-tenant runtime pool should additionally provide an
explicit per-challenge egress policy and an authenticated ingress/firewall
layer, instead of relying on a broadly reachable host-published port. Some
challenges legitimately require outbound access, so this needs a policy field
and enforceable network profiles rather than one global switch.

Controller SSH responses and database-outage journal recovery should eventually
gain streaming byte caps, bounded batches, and prompt shutdown cancellation.
The current helper emits small bounded JSON, but defense in depth should not
assume that a faulty or compromised runtime host follows that contract.

## Controller throughput and capacity reservations

The 1.0 runtime worker executes remote lifecycle commands serially. This keeps
placement, retries, per-instance ordering, and recovery easy to reason about,
and it does not affect deadline safety because every workload also has its
independent host-side timer. It can, however, create queueing latency during a
large simultaneous challenge launch.

Increase concurrency only after measuring that queue. A safe implementation
must reserve server CPU, memory, and instance capacity atomically in PostgreSQL;
serialize commands for the same instance; retain claim-token fencing; bound
global and per-host parallelism; and release reservations on every terminal or
recovery path. Simply spawning one task per command could overbook a host and
reorder start, extend, and terminate operations.
