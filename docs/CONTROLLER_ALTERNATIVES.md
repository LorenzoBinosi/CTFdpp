# CTFZone Controller: Three Alternative Configurations

Status: Alternative 1 selected and implemented for CTFZone 1.0.0
Last updated: 2026-08-12

All three configurations keep four core long-running CTFZone services:

1. Python backend.
2. Rust API.
3. PostgreSQL.
4. Controller.

Caddy and S3-compatible storage are supporting infrastructure. Caddy's portal
origin routes only to Python; Python calls the private Rust API with a service
credential. Caddy's separate storage origin accepts only short-lived signed S3
transfers. Challenge workloads run on remote hosts and are not additional
CTFZone platform services.

## Shared requirements

Every configuration must preserve these rules:

- The Rust API owns users, teams, challenges, authorization, and scoring.
- PostgreSQL enforces one active instance per user.
- The database stores instance creator, challenge, state, expiry, IP, port,
  endpoint, timestamps, and complete history.
- Only challenges with an enabled `managed` runtime profile use the controller.
- A static challenge never wakes the controller.
- The controller does not poll the API or remote hosts every second.
- Existing deadlines and cleanup continue as far as possible during control-plane
  outages.
- New launches fail closed when ownership or configuration cannot be verified.

The alternatives differ primarily in how commands reach the controller and how
runtime results return to PostgreSQL.

## Alternative 1: PostgreSQL-coordinated controller

This is the architecture implemented in 1.0.0.

### Topology

```text
Browser ──► Caddy ──► Python BFF ──► Rust API ──transaction──► PostgreSQL
                                          │
                                          │ LISTEN/NOTIFY
                                          ▼
                                      Controller
                                          │
                                          ▼
                                      Remote host

Controller ──restricted SQL──► PostgreSQL
```

### Command flow

1. Caddy routes an activation, termination, or extension request to Python.
2. Python validates its browser session, same-origin and CSRF boundary, then
   calls Rust with its service credential and opaque user session. The API
   authorizes the operation.
3. In one transaction, the API updates desired state, appends history, inserts a
   durable `runtime_commands` row, and calls `pg_notify`.
4. The controller receives the notification and claims the command with
   `FOR UPDATE SKIP LOCKED`.
5. The controller performs the remote operation.
6. The controller transactionally updates observed state, endpoint, IP, port,
   expiry acknowledgement, command status, and history.

### State ownership

| Data | Writer |
|---|---|
| Users, challenges, policies, scores | Rust API |
| Instance owner and desired state | Rust API |
| Durable commands | Rust API creates; controller claims/completes |
| Observed phase, container ID, IP, port, endpoint | Controller |
| Active-slot release after cleanup | Controller |
| History | Both append permitted event types |

The services use one database in 1.0.0. Handler authorization and transaction
structure enforce writer boundaries; distinct restricted database roles remain
an optional hardening step.

### Challenge configuration

The controller listens to:

```sql
LISTEN ctfzone_runtime_commands;
LISTEN ctfzone_settings_changed;
LISTEN ctfzone_challenge_runtime_changed;
```

It remains dormant when no managed challenge is eligible and no instance needs
cleanup.

### Failure behavior

- Lost notifications do not lose work because the command table is durable.
- Controller restart performs a pending-command and active-instance scan.
- PostgreSQL outage prevents new launches.
- The controller uses a local operational journal and remote labels/timers to
  finish known expiry or cleanup operations during the outage.
- Results are synchronized to PostgreSQL after recovery.

### Advantages

- Launch reservation, command creation, and history are atomic.
- No extra broker or dispatcher is required.
- Recovery state is easy to query and audit.
- The controller can update runtime state without another network hop.
- PostgreSQL naturally enforces one active instance per user.

### Disadvantages

- The controller knows the runtime database schema.
- Two services write different parts of the same tables.
- Database grants and migrations require careful ownership rules.
- A PostgreSQL outage closes the launch path.
- `LISTEN/NOTIFY` requires reconnection and recovery logic.

### Best fit

Choose this when operational simplicity and strong transactional behavior are
more important than strict service/database isolation.

## Alternative 2: Persistent API-to-controller stream

The controller never accesses PostgreSQL. It maintains a persistent internal
bidirectional stream to the Rust API using gRPC, WebSocket, or HTTP/2.

### Topology

```text
Browser ──► Caddy ──► Python BFF ──► Rust API ◄═══ persistent stream ═══► Controller
                 │                                                  │
                 ▼                                                  ▼
            PostgreSQL                                         Remote host
```

### Command flow

1. Caddy routes the action to Python, which validates the browser boundary and
   calls the private Rust API.
2. The API authorizes it and commits desired state, history, and an outbox command
   to PostgreSQL.
3. After commit, the API dispatcher sends the command through the persistent
   stream.
4. The controller durably journals the command locally and acknowledges receipt.
5. The controller performs the remote operation.
6. It sends progress and results back on the same stream.
7. The API validates the event and writes observed state and history to
   PostgreSQL.
8. The API marks the outbox command delivered/completed.

The stream is push-based; it is not per-second polling.

### Reconnection

Each message contains:

```text
command_id
instance_id
generation
master_setting_revision
challenge_runtime_revision
sequence
```

When the stream reconnects:

1. The controller presents the last command sequence it durably acknowledged.
2. The API replays every later pending command from PostgreSQL.
3. The controller sends locally journaled results that the API has not
   acknowledged.
4. Both sides deduplicate by command/event ID.

### State ownership

| Data | Writer |
|---|---|
| All PostgreSQL tables | Rust API only |
| Remote execution journal | Controller local storage |
| Remote workload state | Controller |

The API becomes the only database writer. The controller receives immutable
deployment snapshots rather than reading challenge tables.

### Challenge configuration

When a managed challenge is enabled or disabled, the API pushes a versioned
configuration event through the stream. The controller still verifies the
revisions attached to every start command.

If no managed challenge or active instance exists, the stream remains connected
but idle. It consumes negligible resources.

### Failure behavior

- API down: no new commands; controller continues known deadlines and cleanup.
- Controller down: commands accumulate in the API outbox and replay later.
- PostgreSQL down: API cannot commit new commands; controller continues existing
  operations from its journal.
- Stream partition: neither side assumes delivery; replay occurs on reconnect.
- API crash after DB commit but before send: the outbox dispatcher resends.
- Controller crash after remote action but before result: its local journal and
  remote labels support reconciliation and result replay.

### Advantages

- Controller has no PostgreSQL credentials or schema coupling.
- Rust API is the only authoritative database writer.
- Service boundaries are explicit and easy to secure.
- Commands and events can use versioned Protobuf schemas.
- The persistent stream provides immediate push in both directions.

### Disadvantages

- The API now contains an outbox dispatcher and stream server.
- Stream replay, acknowledgement, backpressure, and ordering must be implemented.
- Every runtime update passes through the API.
- The controller needs a durable local journal.
- More protocol code is required than `LISTEN/NOTIFY`.

### Best fit

Choose this when strict service isolation and keeping the controller away from
PostgreSQL are worth the additional protocol complexity.

## Alternative 3: Controller-orchestrated instance API

The backend sends instance-specific actions to the controller. Before performing
anything, the controller asks the Rust API to authorize and reserve the action.
The controller still never receives arbitrary user-selected runtime parameters.

### Topology

```text
Browser ──► Caddy ──► Python BFF ──┬──► Rust API ──► PostgreSQL
                                      │        ▲
                                      └──► Controller ──► Remote host
                                         instance operations/results
```

The browser still sees only Caddy and Python. The BFF chooses its internal
target:

- Normal CTFZone operation → Rust API.
- Instance status/activate/terminate/extend → Controller.

### Activation flow

1. The backend forwards the user's activation intent to the controller.
2. The controller sends the user identity proof, challenge ID, and idempotency key
   to an internal Rust API authorization endpoint.
3. The API transactionally verifies policy, reserves the user's active slot,
   creates the instance row, and returns a signed immutable execution lease.
4. The lease contains the instance ID, deployment snapshot, deadlines, and
   configuration revisions.
5. The controller journals the lease and starts the remote workload.
6. It sends progress/results to the API, which writes PostgreSQL.

Termination and extension use the same pattern: the controller first obtains an
authorized, versioned operation lease from the API.

### Status flow

The controller can return its live local observation immediately. Historical and
authoritative ownership information remains in the API/database. The backend may
combine both when rendering the page.

### State ownership

| Data | Authority |
|---|---|
| User authorization and active-slot reservation | Rust API/PostgreSQL |
| Live operational state | Controller local journal |
| Historical runtime projection | Rust API/PostgreSQL |
| Remote workload | Controller |

### Failure behavior

- API unavailable: controller cannot obtain a new execution lease, so activation,
  extension, and user-requested termination fail closed. Expiry and emergency
  cleanup continue locally.
- Controller unavailable: all instance operations are unavailable even if the API
  and database are healthy.
- Controller result callback fails: results remain in its local journal and retry.
- Controller loses local storage: it rebuilds operational state from PostgreSQL
  and remote labels, but live state may temporarily be unknown.
- API commits a lease but controller crashes before launch: the reservation
  remains pending until reconciliation releases or executes it.

### Advantages

- The controller has a clear instance-specific API.
- The Rust API remains the authorization and reservation authority.
- Controller does not need direct PostgreSQL access.
- Live status does not require a database round trip.
- Backend routing makes the architecture explicit.

### Disadvantages

- Controller becomes part of every instance request path.
- Live operational state and database state can temporarily diverge.
- Status may require combining API and controller responses.
- Controller local persistence becomes more important.
- There are more partial-failure cases around leases and callbacks.
- This is the most complex option for preserving complete history.

### Best fit

Choose this when the controller must present a rich independent lifecycle API and
very fresh operational status is more important than a simple consistency model.

## Comparison

| Property | 1. PostgreSQL coordinated | 2. API stream | 3. Controller orchestrated |
|---|---|---|---|
| Controller accesses DB | Yes, restricted | No | No |
| Only API writes DB | No | Yes | Yes |
| Browser-facing entry | Caddy → Python BFF | Caddy → Python BFF | Caddy → Python BFF |
| Durable command source | PostgreSQL command table | API outbox in PostgreSQL | API reservation/lease |
| Normal command delivery | PostgreSQL `NOTIFY` | Persistent API stream | Backend request to controller |
| Runtime result path | Controller → DB | Controller → API → DB | Controller → API → DB |
| New launch during DB outage | No | No | No |
| Existing expiry during DB outage | Local journal/remote timer | Local journal/remote timer | Local journal/remote timer |
| Protocol complexity | Low | Medium/high | High |
| Database coupling | Medium | Low | Low |
| Runtime/database consistency | Strongest | Strong | Eventually consistent |
| Controller request-path criticality | Low | Low | High |

## Recommendation

CTFZone 1.0.0 uses **Alternative 1: PostgreSQL-coordinated controller**.

It provides the shortest reliable path with the four-service restriction:

```text
API transaction → durable DB command → NOTIFY → controller → DB result
```

Its database coupling is acceptable if PostgreSQL permissions clearly separate
API-owned desired fields from controller-owned observed fields. It also makes
one-active-instance enforcement and complete history straightforward.

If controller database access later becomes an unacceptable security or schema
boundary, migrate the command/result transport to **Alternative 2** without
changing the browser/Caddy contract or remote execution model.

Alternative 3 should be selected only if a controller-owned lifecycle API is an
explicit product requirement.
