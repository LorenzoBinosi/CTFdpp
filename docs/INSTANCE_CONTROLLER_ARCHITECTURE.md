# CTFZone managed-instance controller

Status: Implemented 1.0.0 baseline
Last updated: 2026-08-11

This document describes the controller implemented in this repository. It is
the selected PostgreSQL-coordinated design from
[`CONTROLLER_ALTERNATIVES.md`](CONTROLLER_ALTERNATIVES.md).

## 1. Boundary and topology

CTFZone has four core services and one edge proxy:

```text
                                      PostgreSQL
                                    /      |      \
                                   /       |       \
Browser -- HTTPS --> Caddy --> Python BFF --> Rust API   Rust controller
                           pages + UI API       |              |
API clients -- HTTPS --> Caddy -----------------^              | SSH
                                                               |
                                                      remote runtime host
                                                      + host expiry timer
```

- Caddy is the only public listener and owns certificates.
- Python renders HTML, templates, and private Markdown/challenge fragments, and
  forwards browser UI actions through its constrained `/bff` boundary.
- Rust owns the public `/api/v1` behavior, authorization, domain rules, and
  browser session mutations.
- PostgreSQL is the only authoritative platform database.
- The controller is an internal worker. A participant cannot connect to it or
  send it arbitrary container instructions.
- Remote hosts run challenge workloads and are not additional CTFZone platform
  services.

The browser uses one origin. Human-facing pages and their JavaScript actions
reach Python through Caddy; Python forwards those actions to Rust without
implementing domain behavior. External API clients may call `/api/v1` through
Caddy directly. The controller is never part of the user authentication
boundary.

## 2. Why the controller stays running

`private_challenges` is data in PostgreSQL, not a deployment toggle. Therefore
Compose always starts the controller. Once connected, it derives one of these
modes:

| Mode | Meaning |
|---|---|
| `starting` | Database connection or initial reconciliation is incomplete |
| `enabled` | Master setting is on and at least one managed profile is enabled |
| `draining` | Launches are disabled but an active instance still needs cleanup |
| `dormant` | No managed launch is eligible and no active instance remains |
| `degraded` | PostgreSQL is unavailable; journal-based recovery is active |

Dormant means sleeping, not stopped. This is important because a later database
setting change must wake the same process, and an instance created before a
setting change may still require termination.

The internal endpoints `GET /healthz`, `GET /readyz`, and `GET /status` expose
this state only on the private Docker network. Dormant is ready. Starting and
degraded are not ready.

## 3. State and ownership

### Platform state

The native API owns users, teams, sessions, tokens, challenges, flags, hints,
submissions, solves, fails, awards, scoreboard rules, configuration, files,
pages, notifications, and exports in the same PostgreSQL database.

### Runtime policy

`ctfzone.runtime_settings` contains the authoritative master switch and a
monotonically increasing revision:

```text
key = private_challenges
enabled
revision
updated_at
updated_by_user_id
```

`ctfzone.challenge_runtime_configs` contains a versioned profile per challenge:

```text
challenge_id, runtime_mode, enabled, revision
image_digest, protocol, container_port
default_ttl_seconds, maximum_ttl_seconds
allow_extension, maximum_extensions
cpu_limit, memory_limit_bytes, pid_limit, storage_limit_bytes
healthcheck, remote_pool
```

A challenge is controller-managed only when the master setting is enabled and
its profile has `runtime_mode=managed` and `enabled=true`. Managed images must be
pinned as `repository@sha256:<64 lowercase hex characters>`.

### Instance record

`ctfzone.runtime_instances` is the current state plus permanent instance history.
The important fields are:

```text
identity: id, owner_user_id, created_by_user_id, team_id, challenge_id
snapshot: deployment_snapshot, policy/profile revisions
intent: desired_state, desired_expires_at, maximum_expires_at, generation
observation: observed_state, observed_generation, observed_expires_at
placement: remote_server_id, remote_container_id
connection: remote_ip, container_port, published_ip, published_port,
            protocol, public_hostname, endpoint_url
history times: created_at, activated_at, ready_at, last_observed_at,
               stopped_at
outcome: active, failure_code, failure_message
```

The deployment snapshot is immutable for that instance. Later edits to a
challenge profile do not silently change the image or limits of an operation
already in flight.

PostgreSQL enforces one active instance per user:

```sql
CREATE UNIQUE INDEX runtime_instances_one_active_per_user
ON ctfzone.runtime_instances(owner_user_id)
WHERE active;
```

This is the final concurrency guard; API pre-checks only provide a clearer error.
A stopped instance remains in the table, so account and administrator history is
never lost.

### Durable commands and events

`ctfzone.runtime_commands` is the durable queue. A command contains:

```text
id, instance_id, kind, generation
setting_revision, challenge_runtime_revision
payload, status, attempts, available_at
requested_by_user_id, idempotency_key
created_at, claimed_at, completed_at, last_error
```

Kinds are `start`, `terminate`, `extend`, `inspect`, and `reconcile`. Status is
`pending`, `claimed`, `completed`, `failed`, or `cancelled`.

`ctfzone.runtime_instance_events` is the append-only audit stream. Each row has a
global sequence, UUID, instance, event type, source (`api`, `controller`, or
`remote`), optional user actor, JSON payload, and timestamp.

## 4. Exchanges between browser, API, database, and controller

### Participant endpoints

| Intent | API request |
|---|---|
| Read the current challenge instance | `GET /api/v1/challenges/{challenge_id}/instance` |
| Ensure/start an instance | `POST /api/v1/challenges/{challenge_id}/instance` |
| Stop it | `DELETE /api/v1/challenges/{challenge_id}/instance` |
| List account instance history | `GET /api/v1/instances` |
| Read one historical/current instance | `GET /api/v1/instances/{instance_id}` |
| Read complete lifecycle history | `GET /api/v1/instances/{instance_id}/events` |
| Request termination by instance ID | `POST /api/v1/instances/{instance_id}/terminate` |
| Request an extension | `POST /api/v1/instances/{instance_id}/extend` |

Activation accepts optional `ttl_seconds` and `idempotency_key`. Extension accepts
optional `additional_seconds` and `idempotency_key`; the `Idempotency-Key` header
can be used instead. Keys are scoped to the authenticated user and operation.

The participant can request desired behavior but cannot choose the image,
command, runtime host, port, resource limits, or helper operation. Those values
come from the administrator-controlled, revisioned deployment snapshot.

### Administrator endpoints

| Intent | API request |
|---|---|
| Read/change the master setting | `GET/PATCH /api/v1/admin/runtime/settings/private-challenges` |
| Read/replace a challenge profile | `GET/PUT /api/v1/admin/challenges/{challenge_id}/runtime` |
| List/create runtime hosts | `GET/POST /api/v1/admin/runtime/servers` |
| Read/update/disable a runtime host | `GET/PATCH/DELETE /api/v1/admin/runtime/servers/{server_id}` |
| Search all instances | `GET /api/v1/admin/runtime/instances` |
| Request a remote inspection | `POST /api/v1/admin/runtime/instances/{instance_id}/reconcile` |

Changing the master setting or a challenge profile increments its revision,
commits the new value, and emits a PostgreSQL notification. Disabling policy does
not simply turn the worker off: it causes active affected instances to drain.

## 5. Activation transaction

For `POST /api/v1/challenges/{challenge_id}/instance` the API:

1. Authenticates the browser session or API token.
2. Verifies challenge visibility, CTF time, account verification, and team rules.
3. Reads the master setting and managed profile.
4. Validates the requested TTL against the profile.
5. Locks the user row and checks for an active instance.
6. Returns the existing instance if it belongs to the same challenge; returns
   `409 Conflict` if another challenge occupies the user's slot.
7. Inserts `runtime_instances` with desired `running`, observed `requested`, an
   absolute expiry, maximum expiry, and immutable deployment snapshot.
8. Appends `instance.requested` to history.
9. Inserts a `start` command with the exact setting/profile revisions.
10. Calls `pg_notify('ctfzone_runtime_commands', command_id)`.
11. Commits all rows atomically and returns `202 Accepted`.

The notification is delivered only after commit. If delivery is lost, the
pending command still exists and startup/periodic reconciliation will find it.

## 6. Controller wake and command processing

The controller maintains a PostgreSQL listener for:

```sql
LISTEN ctfzone_runtime_commands;
LISTEN ctfzone_settings_changed;
LISTEN ctfzone_challenge_runtime_changed;
```

On any wake it:

1. Queues termination for expired instances.
2. Queues termination for instances made ineligible by a setting/profile change.
3. Claims available commands transactionally with `FOR UPDATE SKIP LOCKED`.
4. Revalidates active state, generation, and policy/profile revisions.
5. Writes the intended remote operation to a local fsynced JSONL journal.
6. Executes one fixed helper operation through the selected driver.
7. Stores the remote result in the journal.
8. Updates observed state, endpoint/deadline fields, command status, and history
   in PostgreSQL.
9. Marks the journal operation database-acknowledged.

Failures increment `attempts`, record a bounded error, and make the command
available again with backoff until `MAX_COMMAND_ATTEMPTS`. Generation checks
prevent a late start result from reviving an instance that was terminated while
the remote call was running.

### No one-second polling

After draining available work, the controller computes the next wake time from:

- the nearest active instance expiry;
- the nearest delayed command retry;
- `RECONCILIATION_INTERVAL_SECONDS`, five minutes by default.

It waits for the earliest timer or PostgreSQL notification. It does not query
the API or inspect every runtime host once per second. The bounded reconciliation
timer exists to recover a lost notification or manually repaired row; exact
expiry uses the specific instance deadline.

## 7. Activities on a remote host

In production the controller uses OpenSSH with:

- no user SSH configuration (`-F /dev/null`);
- batch and identities-only mode;
- strict host-key checking against the mounted pinned `known_hosts`;
- a dedicated identity;
- validated hostname, username, helper path, port, and host-key alias;
- no shell interpolation of API or participant data.

The remote account's authorized key is restricted to
`ctfzone-runtime-helper ssh-dispatch`. The helper accepts JSON on standard input
and only four operations:

| Operation | Effect |
|---|---|
| `ensure-instance` | Idempotently create or find the exact labelled workload |
| `inspect-instance` | Return its observed container and network state |
| `update-deadline` | Replace the independent host expiry timer if generation is current |
| `stop-instance` | Idempotently remove the workload and expiry unit |

For a start, the helper:

1. Validates the instance ID, generation, digest-pinned image, limits, port, and
   absolute deadline.
2. Uses a dedicated rootless Podman account.
3. creates/fetches the private challenge network;
4. starts the image with no added capabilities, `no-new-privileges`, and the
   configured CPU, memory, PID, and storage limits;
5. publishes a random host port rather than accepting one from the participant;
6. labels the workload with instance and generation metadata;
7. writes fsynced local generation/deadline state;
8. installs a transient systemd timer on the runtime host for the absolute
   deadline;
9. returns container ID, internal/published IP and port, protocol, endpoint, and
   effective expiry as JSON.

The helper is idempotent. Repeating `ensure-instance` for the same generation
returns the existing workload. `stop-instance` succeeds when it is already
absent. A stale timer cannot kill a newer generation.

The controller never receives a Docker or Podman socket and the remote SSH user
must not belong to privileged groups.

## 8. State transitions

The normal activation path is:

```text
requested -> starting -> ready
```

The normal termination path is:

```text
ready/requested/starting -> stopping -> terminated or expired
                                             -> cleanup_completed event
```

`expired` is used when the deadline caused cleanup; `terminated` is used for an
explicit user/admin/policy stop. Recoverable remote failures can pass through
`cleanup_pending`; unrecoverable command failures use `failed`. Inspection may
record `unknown` when the database expects a workload the host cannot confirm.

`active` remains true until the controller has completed the idempotent remote
stop. Only then is the partial unique slot released. This avoids letting a user
start a second workload while the first may still exist remotely.

## 9. What happens when a participant revisits a challenge

Suppose a container was activated five minutes earlier:

1. Python renders the challenge page.
2. Its private renderer reads the native runtime summary supplied by the Rust
   API/database and displays the current state, endpoint, and absolute expiry.
3. If activation is requested again for the same challenge, the API returns the
   existing active instance instead of creating another command or container.
4. If the user has an instance for another challenge, the API reports the
   blocking challenge with `409 Conflict`.

The controller is normally asleep during this visit unless a command,
configuration notification, retry, or deadline wakes it. Reading status does not
require waking or contacting the controller because current and historical state
is already in PostgreSQL.

There is no controller-to-browser SSE endpoint in 1.0.0. The page reads state on
load, explicit user actions return the newly committed desired state, and the UI
may perform a short bounded refresh while a `202 Accepted` operation moves from
`requested`/`starting` to `ready`. It must not poll indefinitely every second.

## 10. Termination and extension

Termination is idempotent. The API locks the instance, authorizes owner or admin,
sets desired state to `stopped`, increments generation, appends history, inserts
a durable `terminate` command, notifies, and returns `202`. The controller marks
`stopping`, invokes `stop-instance`, persists the outcome, clears `active`, and
appends final cleanup history.

Extension is permitted only for an active `ready` instance before its expiry and
within both the extension-count and maximum-lifetime limits. The API calculates
the new absolute deadline, increments generation and extension count, inserts an
`extend` command, and appends history. The helper updates the host timer before
the controller acknowledges the new observed expiry.

## 11. Settings changed on or off

### Off to on

The API increments the master revision and notifies the controller. The
controller wakes and becomes `enabled` only if at least one challenge profile is
also enabled and managed. Existing static challenges remain unaffected. New
launches carry the new setting revision.

### On to off

The API commits `enabled=false`, increments the revision, and notifies. New
launches immediately fail at the API gate. The controller scans all active
instances, inserts termination commands for those now disallowed, and reports
`draining` until cleanup releases every active slot. It then reports `dormant`.

If the controller is down during the change, the rows remain authoritative.
Startup reconciliation observes the disabled setting and drains the instances;
correctness does not depend on receiving the original notification.

## 12. Outages and recovery

### Complete platform outage before expiry

Example: an instance starts at 12:00, expires at 12:30, and the CTFZone platform
goes offline at 12:10.

- The remote container continues running until 12:30.
- Its host-local systemd timer calls the fixed helper and removes it at 12:30,
  even though the API, database, and controller are unavailable.
- When CTFZone returns at 13:00, Docker restarts the controller automatically.
- Startup reconciliation finds the database row overdue, issues an idempotent
  stop/inspect path, and records the final expired/cleanup state.
- No participant has to return and no page visit is required.

The remote timer is essential. A database deadline alone cannot kill a remote
container while the whole control plane is off.

### Controller outage only

Commands accumulate in PostgreSQL. On restart the controller recovers claims
older than `STALE_CLAIM_AFTER_SECONDS`, queues overdue/policy cleanup, and drains
pending work. Remote timers still enforce already-installed expiries.

### PostgreSQL outage while controller stays up

The controller enters `degraded` and reconnects with bounded exponential delay.
Its fsynced journal retains in-flight intent and remote results. It attempts
overdue cleanup for journaled operations without the database. New launches fail
closed because the API cannot atomically reserve a user slot.

### API or Python outage

No new user intent is accepted through that unavailable component. Existing
controller deadlines, PostgreSQL commands, the local journal, and remote timers
continue independently. Restart does not create a second instance because the
database unique index remains authoritative.

### Lost PostgreSQL notification

No work is lost. Notifications are wake-up hints, not queue entries. Pending
commands are found by the next deadline/retry/reconciliation wake or after a
controller reconnect.

### Remote host unavailable

The controller records the error and retries with backoff. The user slot remains
active while cleanup is uncertain. After the configured attempt limit the
command and instance expose failure data for an administrator, who can repair the
host and request reconciliation.

## 13. Security invariants

- Caddy is the only public service.
- All runtime mutations require normal API authentication and ownership/admin
  authorization.
- Session cookies are signed; server-side session rows support revocation.
- Participant input never becomes an image name, shell command, host, or
  published port.
- Images are immutable digest references.
- The API snapshots policies and the controller verifies their revisions.
- PostgreSQL atomically enforces one active instance per user.
- SSH host keys are pinned and forwarding is disabled by the authorized-key
  restriction.
- The remote helper exposes a fixed operation vocabulary and idempotent behavior.
- Workloads run rootless with constrained resources and independent absolute
  expiry.
- Instance events retain actor, source, payload, and order for audit/history.

## 14. Operational checklist

Before enabling private challenges:

1. Confirm PostgreSQL and upload backups.
2. Confirm the controller `readyz` endpoint is ready, not degraded.
3. Install the helper on every runtime host under a dedicated rootless account.
4. Restrict the controller public key to `ssh-dispatch` and disable forwarding.
5. Pin every host key in `secrets/known_hosts`.
6. Register host capacity and pool through the admin runtime API.
7. Configure each managed challenge with a digest, port, TTL, maximum TTL, and
   explicit resource limits.
8. Test start, extension, explicit stop, automatic expiry, controller restart,
   and a runtime-host failure before a live event.
9. Alert on controller degraded state, commands exhausting retries, instances in
   cleanup pending, and active rows past expiry.

The database history endpoints should be used for support and audit. Direct
controller status is operational telemetry, not a participant control API.
