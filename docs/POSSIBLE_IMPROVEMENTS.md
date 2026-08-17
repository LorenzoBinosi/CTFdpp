# CTFZone possible improvements

Status: Deferred ideas outside the current implementation scope
Last updated: 2026-08-12

This document records improvements that may become useful as CTFZone grows.
Items listed here are not required by the current architecture and must not be
treated as committed release work.

## Deferred configuration capabilities

The 1.0 administration catalog exposes settings only when the Rust API
implements and validates their behavior. Unknown keys are rejected rather than
kept as inert compatibility data. The current semantics and complete
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
poll status or scoreboard endpoints once per second.

Server-Sent Events (SSE) may later provide live updates for:

- an asynchronous job changing from `queued` to `ready`;
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

The browser must not connect to the Rust API or controller. The controller does
not hold participant connections or publish browser events.

### Why it is postponed

- Classic challenges and ordinary administration work with bounded refreshes.
- SSE is an optimization for live presentation, not part of scoring
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
