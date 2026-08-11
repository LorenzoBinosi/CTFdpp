# CTFZone 1.0.0

This directory contains the runnable CTFZone stack. The browser experience is a
replaceable Python web channel; all platform rules and state live behind the
native Rust API.

## Topology

| Component | Technology | Responsibility |
|---|---|---|
| `caddy` | Caddy 2 | Public HTTP/HTTPS origin, certificates, compression, request routing |
| `backend` | Python/Flask | Replaceable web/BFF adapter: HTML, CSS, JavaScript, Markdown presentation, and browser-to-API forwarding |
| `api` | Rust/Axum | Authentication, users, teams, challenges, scoring, administration, files, exports, sessions, and runtime intent |
| `controller` | Rust/Axum + Tokio | Durable command processing, deadline scheduling, recovery, remote execution |
| `db` | PostgreSQL 16 | One authoritative platform and runtime database |

The four core roles are backend, API, controller, and database. Caddy is edge
infrastructure. Remote challenge containers are workloads, not platform
services.

The public routing boundary is:

```text
/api/v1/*                        -> Rust API
/files/*                         -> Rust API
all human-facing routes         -> Python BFF
/bff/*                           -> Python BFF -> Rust API
```

Unknown API routes terminate with a Rust `404`; there is no Python API fallback.
The BFF has no database credentials, session signing key, upload volume, or
platform business logic. A future web UI can replace it while continuing to use
the same Rust API. Large uploads use the same-origin Rust `/api/v1/files`
endpoint directly; the general BFF proxy is intentionally capped at 16 MiB so it
cannot buffer multi-gigabyte bodies in Python worker memory.

## Database model

CTFZone starts with a fresh PostgreSQL volume. Versioned SQL in `db/init` creates
the complete 1.0.0 portal and managed-runtime schema before the API starts. The
Rust API and controller share that single authoritative database; the Python BFF
never connects to it. Instance ownership can therefore be correlated with users,
scores, and lifecycle history without a second source of truth.

The runtime schema enforces one active instance per user with a partial unique
index. `runtime_instances` stores the immutable owner/creator/challenge snapshot,
desired and observed state, absolute deadlines, remote placement, container ID,
IP, port, endpoint, and timestamps. `runtime_instance_events` is append-only
history; `runtime_commands` is the durable API-to-controller queue.

Version 1.0.0 intentionally contains no import or in-place upgrade path from
earlier platform prototypes. Deleting the PostgreSQL volume irreversibly removes
the authoritative platform records; the separate upload volume may then contain
orphaned files and must be handled according to the same backup and retention
policy.

## Local development

```console
cp .env.example .env
docker compose -f compose.yml -f compose.local.yml up --build
```

The override uses plain HTTP at `http://localhost`. Select isolated host ports
without changing internal ports:

```console
PUBLIC_BASE_URL=http://127.0.0.1:18180 \
HTTP_PORT=18180 HTTPS_PORT=18543 \
CONTROLLER_REMOTE_DRIVER=mock \
docker compose -p ctfzone-dev -f compose.yml -f compose.local.yml up --build -d
```

The mock driver exercises the complete API/database/controller state machine but
does not start a real container.

## Production

1. Copy `.env.example` to `.env`.
2. Set `SITE_ADDRESS` to the hostname Caddy should obtain a certificate for.
3. Set `PUBLIC_BASE_URL` to its exact `https://` origin.
4. Generate long, independent values for `SECRET_KEY`, `SETUP_TOKEN`, and
   `POSTGRES_PASSWORD`. The first administrator must enter `SETUP_TOKEN` on
   `/setup`; do not send it in a URL or reuse it as another credential.
5. Leave `CONTROLLER_REMOTE_DRIVER=ssh`.
6. Put the dedicated private key and pinned host keys in `secrets/` as documented
   in `secrets/README.md`.
7. Install the fixed remote helper on every challenge host and register each host
   through the admin runtime API.
8. Back up the PostgreSQL and upload volumes before upgrades or maintenance.

Start CTFZone with:

```console
docker compose -f compose.yml up --build -d
```

Only ports 80/443 are public. Ports 8000, 8080, 8090, and 5432 are internal and
must not be published by an override or firewall rule.

## Runtime behavior

The controller opens PostgreSQL `LISTEN` connections for command, setting, and
challenge-profile notifications. A notification is only a wake-up hint; the
command table is durable. Between notifications it sleeps until the nearest
instance deadline, delayed retry, or five-minute reconciliation bound. It does
not poll remote hosts once per second.

At startup or after reconnecting, the controller recovers stale claims, queues
terminations for expired or disabled instances, processes all pending commands,
and then reports ready. Disabling private challenges rejects new activation and
places existing instances into draining cleanup. With no eligible managed
challenge and no active instance, the process stays up but reports `dormant`.

The SSH helper creates an independent host-side systemd expiry timer for every
container. Therefore an already-running workload still expires if Caddy, the
API, PostgreSQL, and the controller are all offline. When the control plane
returns, startup reconciliation repairs the database history and retries cleanup.

See [the complete controller architecture](docs/INSTANCE_CONTROLLER_ARCHITECTURE.md)
for exchanges, state transitions, failure cases, and remote-host activities.

Additional project documentation:

- [Future competitive-mode implementation](docs/FUTURE_IMPLEMENTATION.md)
- [Controller alternatives](docs/CONTROLLER_ALTERNATIVES.md)
- [Security policy](docs/SECURITY.md)
- [Contributing](docs/CONTRIBUTING.md)
- [Changelog](docs/CHANGELOG.md)

## Health and metadata

Internal endpoints:

- Backend: `GET /healthz` on port 8000.
- API: `GET /healthz` and `GET /readyz` on port 8080.
- Controller: `GET /healthz`, `GET /readyz`, and `GET /status` on port 8090.

Public product metadata is available at `GET /api/v1/ctfzone`; the reported API
status is `native` and `compatibility_backend` is `false`.

## Verification

```console
make check
```

For a running deployment:

```console
docker compose -f compose.yml ps
docker compose -f compose.yml logs api controller
curl --fail https://your-host.example/api/v1/ctfzone
```

The controller must reach `readyz` before managed challenge execution is treated
as available. A dormant controller is healthy and ready; it simply has no
currently eligible managed work. Readiness does not probe SSH while the
controller is dormant, so validate the UID `10002` secret mounts and the
restricted remote helper separately before enabling managed execution.
