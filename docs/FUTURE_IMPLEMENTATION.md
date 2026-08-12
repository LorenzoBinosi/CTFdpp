# CTFZone future implementation

Status: Proposed roadmap beyond the 1.0.0 private-instance and object-storage baseline
Last updated: 2026-08-12

This document summarizes the planned architecture for scheduled events, King of
the Hill, attack/defense simulations, and speedrun challenges. It extends the
implemented controller architecture without adding another central CTFZone
service.

## 1. Architectural decision

CTFZone keeps four central service types behind Caddy:

1. Python backend for page rendering.
2. Rust API for authentication, event management, submissions, scoring, and
   artifact authorization.
3. PostgreSQL as the authoritative state and history store.
4. Rust controller for remote orchestration.

There will not be a controller process or container for every challenge. There
will be one **controller service** with several bounded asynchronous worker
pools. Development may use one controller replica; important production events
should run two or more identical replicas for availability. Multiple replicas
remain one architectural service and coordinate through PostgreSQL leases,
generations, and `FOR UPDATE SKIP LOCKED`.

The controller is a low-frequency orchestration plane. It must not carry player
traffic, score updates, PCAP bodies, game ticks, or live browser subscriptions.

```text
Browser -- portal --> Caddy site --> Python BFF --> private Rust API --> PostgreSQL
   `-- signed PUT/GET --> Caddy storage --> S3-compatible object store

PostgreSQL -- durable work --> Controller --> remote agent --> arenas and judges
future machine facts -- scoped integration ingress --> private Rust API
```

## 2. Responsibility boundaries

| Responsibility | Owner |
|---|---|
| Pages, descriptions, rules, and planned-event views | Python backend |
| Authentication, registration, and authorization | Rust API |
| Event and challenge configuration | Rust API and PostgreSQL |
| Score calculation and leaderboard projections | Rust API |
| Runtime placement and lifecycle | Controller |
| Arena, judge, and patch execution | Remote host/agent |
| Challenge observations and results | Remote agent to Rust API |
| PCAP generation | Remote host |
| Artifact and PCAP metadata/authorization | Rust API and PostgreSQL |
| Artifact and PCAP bytes | S3-compatible object storage data plane |
| Live page updates | Initially explicit/bounded refresh; SSE is a postponed improvement |

Participants continue to use the Caddy site origin and Python BFF for every
portal/API action. The only narrow exception is a short-lived signed transfer to
the separate Caddy storage origin. There is no public generic Rust `/api/v1` or
`/files` route. Participants never connect to the controller and cannot select
images, hosts, commands, limits, storage keys, or deployment operations.

## 3. Controller shape

The controller service will contain these logical workers:

```text
controller
|-- personal runtime reconciler
|-- shared arena reconciler
|-- execution-job dispatcher
|-- patch deployment worker
|-- exact-deadline scheduler
`-- reconciliation worker
```

Each arena, instance, or job has a durable state machine in PostgreSQL. A Tokio
task handles it only while work exists; no permanent in-memory worker is needed
per challenge.

The existing remote vocabulary will grow to typed, idempotent operations such
as:

```text
ensure-arena             stop-arena
inspect-arena            ensure-participant-slot
dispatch-job             cancel-job
deploy-patch             rollback-patch
start-run                stop-run
```

Worker pools will enforce global, remote-pool, and per-host concurrency limits.
Commands retain immutable configuration snapshots, idempotency keys, attempts,
leases, generations, retry backoff, and append-only history.

## 4. Remote execution boundary

Long-running and asynchronous modes need one restricted CTFZone agent per
remote host or external challenge platform, not one agent per challenge. A
platform that implements the integration protocol directly does not need an
additional agent.

The remote agent will:

- perform only fixed, typed controller operations;
- manage local arenas, jobs, participant slots, and deadlines;
- keep a disk-backed outbox for unacknowledged facts and results;
- push signed observations directly to the Rust API;
- obtain scoped object grants and upload artifacts such as judge output and
  PCAPs without proxying bodies through Python;
- enforce host-local expiry when CTFZone is unavailable.

Expensive and continuous work stays remote. The controller only dispatches,
reconciles, records placement, and requests cleanup.

## 5. Event domain

Challenge definitions remain reusable content. Their use in a scheduled event
is represented separately.

Planned core entities are:

- `events`: description, publication and registration windows, start/end,
  capacity, participant mode, visibility, and lifecycle state;
- `event_challenges`: challenge binding, mode, schedule overrides, scoring and
  runtime snapshots, and remote integration;
- `event_participants`: user/team registration, approval state, and frozen team
  roster;
- `event_rounds`: A/D ticks, KOTH sampling periods, or speedrun heats;
- `arena_runs`: shared event runtime state, placement, generation, and hard
  deadline;
- `arena_participant_slots`: participant network identity, endpoints, services,
  and remote resources.

The event lifecycle is:

```text
draft -> published -> registration_open -> scheduled
      -> starting -> live -> finished -> archived
                              \-> cancelled
```

The controller sleeps until the nearest event/runtime boundary or PostgreSQL
notification. If it restarts after a boundary, reconciliation performs the
overdue start or cleanup. Remote host timers remain the final termination guard.

Personal private instances keep their current one-active-instance rule. Event
arenas and attempts use event-scoped concurrency rules, such as one active
speedrun attempt per participant and event.

## 6. Signed remote facts

Remote systems will push observations to a versioned Rust ingestion endpoint.
That requires a deliberately exposed, machine-authenticated integration ingress
(for example private networking or an mTLS-only Caddy route); it must not expose
the generic private API used by the BFF. An event envelope includes:

```text
schema version
integration, event, arena, and challenge identifiers
globally unique fact identifier
monotonic source sequence
fact type and payload
occurrence timestamp
remote signature
```

Each remote integration has a pinned Ed25519 key or mTLS identity, an allowed
fact vocabulary, rate and size limits, and revocation state. PostgreSQL stores
facts immutably and deduplicates them by source and fact identifier. The remote
outbox retries until the API acknowledges the batch.

Examples include `flag_captured`, `service_checked`, `ownership_changed`,
`metric_observed`, `judge_completed`, `patch_deployed`, and `run_finished`.
The remote reports facts or raw metrics; the Rust API normally calculates the
score. Direct trusted score observations must be explicitly allowed by the
integration profile and can never come from a participant.

## 7. Scoring model

Classic CTF scoring may continue to use solves and awards. Event modes require
an immutable score ledger:

```text
score_events
  event, event challenge, round, participant
  source fact and scoring-policy version
  signed positive/negative delta, reason, metadata, timestamp

score_totals
  leaderboard scope, participant, current total
  tie-break data and last applied score-event sequence
```

Scoring policies are built-in deterministic algorithms with versioned
parameters, not administrator-supplied executable code. Corrections use
compensating ledger entries. Stored raw facts make a deterministic replay and a
new projection possible after a scoring bug or policy revision.

CTFZone will expose distinct global, event, per-challenge, per-round/heat, and
lifetime-best leaderboards. Event results affect the global classic scoreboard
only through an explicit final conversion or award.

## 8. Artifacts and execution jobs

Programs, Git diffs, build results, logs, and PCAPs use the implemented immutable
object model: PostgreSQL owns SHA-256, size, ownership, purpose, retention,
authorization, lifecycle, and audit metadata, while an S3-compatible service
stores bytes. Neither presigned URLs nor storage credentials are durable domain
records.

The browser transfer protocol remains the baseline for future artifact types:

1. The browser sends filename, size, content type, required SHA-256, purpose,
   and owning entity through Python's CSRF-protected BFF.
2. Rust inserts a `pending` object record and returns a short-lived signed PUT
   for a staging key on `CADDY_STORAGE_ADDRESS`.
3. The browser sends bytes directly to that URL with the exact signed headers;
   Python and Rust never buffer the object body.
4. The browser posts the returned completion path through the BFF. Rust verifies
   storage metadata and checksum, promotes the staged body to its immutable
   final key, then atomically marks metadata `ready` and associates it with the
   domain record.
5. Downloads begin at Python `/downloads/<object-id>`. Rust reauthorizes the
   ready object and Python redirects only to a short-lived URL on the configured
   storage origin.

The durable `object_operations` queue lets the controller reconcile expired
pending uploads and process idempotent deletion/cleanup after restarts. The
default maintenance scan is bounded to 30 seconds; database rows are claimed
with leases rather than relying on in-memory timers. Backup and restore must
treat PostgreSQL metadata and S3 objects as one recovery set.

The initial admin browser uses WebCrypto's whole-buffer digest and therefore
caps each selected file at 64 MiB. Supporting larger interactive uploads is a
future UI improvement that requires a reviewed incremental/streaming SHA-256
implementation (preferably off the main thread); the higher API-side object
limit must not be used to justify unbounded browser memory.

Asynchronous work uses durable execution jobs, separate from personal runtime
commands:

```text
judge-submission
validate-patch
build-patch
deploy-patch
start-speedrun
stop-speedrun
```

The API creates and authorizes jobs. The controller dispatches them. Remote
agents push completion facts and artifacts back to the API. Retrying dispatch
must never duplicate a score or deployment.

## 9. King of the Hill

Two KOTH models share the same fact and scoring pipeline.

### Submitted program

1. The participant uploads an immutable program artifact.
2. The API creates a sandboxed judge job.
3. The controller dispatches it to a remote judge pool.
4. The judge returns raw metrics or results through signed facts.
5. The API applies the versioned KOTH scoring policy.

Participant programs run without platform secrets, with hard CPU, memory,
network, storage, PID, and execution limits.

### Live remote challenge

The API issues a short-lived event/challenge credential. The remote challenge
uses it to identify the participant and pushes ownership, objective, sampling,
or metric facts. The API updates the challenge and event leaderboards.

## 10. Attack/defense simulations

An A/D event adds services, service slots, flag issuances/captures, health
checks, patches, deployments, and PCAP artifacts. A shared arena belongs to an
event challenge; participant slots represent each defending environment.

The remote game engine drops flags and reports round facts. The API produces
ledger entries such as:

```text
initial event balance             +5000
successful capture                +configured attacker value
flag lost                         -configured defender value
service availability              policy-defined delta
penalty/disqualification          explicit score event
```

Bot, participant-versus-participant, mixed, and passive flag-dropping events use
the same model and differ only by event configuration.

Patch submissions contain a unified Git diff, exact base revision, service,
owner, and artifact digest. The API and controller never apply untrusted patches
locally. A sandboxed remote job validates paths and size, runs
`git apply --check`, builds and tests a pinned image, and deploys it at a defined
round boundary with a rollback revision.

Remote collectors create PCAPs by participant, service, round, and time window.
PostgreSQL stores metadata only. Downloads are restricted to the defending
participant/team and administrators, with configurable availability delay,
quota, and retention.

## 11. Speedrun

Speedrun attempts record the event challenge, participant, immutable challenge
revision/seed, remote start and finish times, duration, penalties, state, and
source result fact. The remote agent is the authoritative clock; browser time is
never trusted.

The same model supports practice attempts, personal bests, attempt limits,
scheduled simultaneous heats, event standings, penalties, invalidation, seeded
variants, and hard attempt deadlines. Duration remains the primary metric;
points are an optional projection.

## 12. Credentials and live updates

The existing global participant token is not suitable as a remote arena
credential. The API will issue short-lived, asymmetrically signed credentials
scoped to participant, event, challenge, arena, permissions, and expiry. Remote
integration credentials are separate from participant credentials.

The design does not require one-second polling:

- PostgreSQL notifications wake controller queues;
- exact timers wake scheduled event and expiry work;
- remote agents push fact/result batches and occasional heartbeats;
- pages use explicit refreshes and bounded transition checks where needed.

Page-scoped Server-Sent Events are deliberately outside the current delivery
scope. Their proposed Python-to-Rust relay, replay, and scaling requirements are
recorded in [`POSSIBLE_IMPROVEMENTS.md`](POSSIBLE_IMPROVEMENTS.md).

## 13. Failure behavior

- Controller unavailable: running remote work continues; commands wait in
  PostgreSQL and host-local deadlines still fire.
- API unavailable: remote agents journal facts and resend them after recovery.
- PostgreSQL unavailable: no new authorized jobs or registrations; existing
  remote execution and deadlines continue.
- Remote host unavailable: the arena becomes degraded and no score is invented.
- Duplicate or out-of-order facts: database idempotency and source sequences
  prevent duplicate scoring and support ordered processing.
- Controller restart after an event end: reconciliation immediately requests
  idempotent cleanup.
- Controller replica failure: another replica reclaims the expired command
  lease and continues.

## 14. Delivery order

1. Event, participant, challenge-kind, and event-page foundations.
2. Scoped participant credentials and signed remote fact ingestion.
3. Immutable fact store, score ledger, projections, and event scoreboards.
4. Extend the implemented object-storage baseline with event retention policies
   and a generic execution-job queue.
5. Submitted-program and live KOTH support.
6. Speedrun attempts, personal bests, and scheduled heats.
7. Shared arenas, rounds, services, flags, and A/D scoring.
8. Patch validation/build/deployment and authorized PCAP delivery.
9. Multiple controller replicas, load testing, outage drills, and operational
   alerting before production multiplayer events.

KOTH is the preferred first vertical slice because it validates both remote fact
ingestion and asynchronous judging. A/D is intentionally last because it
combines shared arenas, networking, rounds, patching, artifacts, dynamic
scoring, and recovery behavior.
