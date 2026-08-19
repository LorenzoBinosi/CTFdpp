# CTFZone 1.0.0

This directory contains the runnable CTFZone stack. The browser experience is a
replaceable Python web channel; all platform rules and state live behind the
native Rust API.

## Topology

| Component | Technology | Responsibility |
|---|---|---|
| `caddy` | Caddy 2 | Public site and storage origins, certificates, compression, and strict boundary routing |
| `backend` | Python/Flask | Replaceable web/BFF adapter: HTML, CSS, JavaScript, browser sessions/CSRF, and trusted calls to the private API |
| `api` | Rust/Axum | Authentication, users, teams, challenges, scoring, administration, object authorization, exports, and sessions |
| `controller` | Rust/Axum + Tokio | Durable private-instance orchestration plus object-storage cleanup and recovery |
| `ssh-gateway` | Rust/Axum + OpenSSH | Isolated browser-terminal WebSocket bridge and SSH client-key custody |
| `db` | PostgreSQL 16 | Authoritative platform and object-lifecycle database |
| `storage` | S3-compatible object storage | Bulk challenge files and future artifacts; reached only through signed data-plane requests |

The core platform roles are backend, API, controller, SSH gateway, and database.
Caddy is edge infrastructure.

Storage and Caddy are supporting infrastructure rather than additional owners of
platform rules. The two public origins have deliberately different jobs:

```text
CADDY_SITE_ADDRESS
  Browser ---- portal routes and /bff/api/* -----------> Python BFF
  Python BFF -- service token + opaque session header --> private Rust API
  Rust API <---- durable state/commands ----> PostgreSQL <----> controller -- restricted SSH --> runtime host
  Browser ---- /bff/ssh/terminal WebSocket ------------> SSH gateway -- SSH --> registered host

CADDY_STORAGE_ADDRESS
  Browser ---- short-lived, signed S3 PUT/GET only -----> object storage
```

There is no public Rust `/api/v1` or `/files` route. A browser request for those
paths reaches the Python site and is not forwarded automatically. Browser API
actions use the explicit same-origin `/bff/api/v1/...` channel; the BFF validates
same-origin and CSRF, then replaces browser credentials with its private service
credential and opaque Rust session identifier. The Rust port remains on an
internal Docker network.

The BFF owns only its signed browser cookie and presentation concerns. It has no
database or storage credentials and no platform business logic. A future web UI
can replace it while preserving the private Rust contract. For uploads, the
browser computes SHA-256, sends JSON metadata through the BFF, PUTs bytes
directly to the signed staging URL, and confirms completion through the BFF.
Downloads begin at a same-origin `/downloads/<object-id>` authorization route
and use a short-lived
redirect to the configured storage origin. The general BFF proxy remains capped
so Python workers do not buffer large artifact bodies.

Interactive SSH is deliberately outside Flask and the storage-maintenance
controller. The browser renders a locally bundled terminal and exchanges PTY
bytes with the isolated gateway over a same-origin WebSocket. The API issues a
short-lived one-use ticket and stores host/audit metadata; only the gateway can
read its dedicated SSH private-key volume. See
[Browser SSH console](docs/SSH_CONSOLE.md).

The web package also keeps the neutral administration frontend separate from
player frontends. PostgreSQL stores the selected `player_frontend` identifier;
Python resolves it through a registry of installed packages and safely falls
back to the bundled `terminal` frontend when necessary. The configured
`ctf_name`, rather than a hard-coded product mark, is shown as the event identity.
See [Frontend architecture](docs/FRONTEND_ARCHITECTURE.md) for the package and
manifest contract.

Administrators can change a user's participant/administrator role and public
visibility from **Administration -> Users**. Email verification is deliberately
not an administrative control: each signed-in user requests a short-lived,
single-use link from their own profile, and only successful confirmation marks
the account verified. Administrators verify their own addresses through that
same profile flow. This also applies to the first setup administrator:
possession of the setup token authorizes account creation but does not prove
ownership of the email address. Role changes revoke that user's browser sessions
and API tokens so an old participant credential cannot inherit administrator
authority.

Normal portal forms and JSON are capped at 6 MiB and buffered by Caddy before
the Python upstream is opened. A deliberately slow request body therefore does
not occupy the BFF's finite worker pool. Object bytes use the separate storage
origin and are not subject to the small portal cap.

## Database model

CTFZone starts with a fresh PostgreSQL volume. Ordered SQL in `db/init` creates
the complete 1.0.0 schema before the API starts. The Rust API and controller
share that single authoritative database; the Python BFF never connects to it.
Private-instance intent, immutable deployment snapshots, commands,
observations, and history are stored alongside portal and object-lifecycle
state.

PostgreSQL also stores object ownership, purpose, expected/actual metadata,
status, retention, audit events, and durable maintenance operations. Object
bytes live in the S3-compatible store; presigned URLs and storage credentials do
not live in PostgreSQL. An upload starts as `pending`, becomes `ready` only after
the API verifies its required SHA-256 and metadata and promotes the staging body
to its immutable final key, and is exposed to challenge views only when ready.
The controller reconciles abandoned uploads and queued deletion/cleanup work
from the durable object-operation table on a bounded maintenance interval
(30 seconds by default).

The current admin UI hashes with WebCrypto's non-streaming `digest` operation,
so it limits each browser upload to 64 MiB to bound memory use. The API/storage
ceiling may be higher for future workers; raising the browser limit first
requires a reviewed streaming or incremental SHA-256 implementation.
Untrusted uploads are additionally bounded per user or team by pending-object,
pending-byte, retained-byte, and hourly initiation quotas. Their defaults are
listed in `.env.example` and can be tuned without changing the storage protocol.
Caddy also enforces `OBJECT_STORAGE_MAX_UPLOAD_DURATION_SECONDS`; the controller
performs terminal staging cleanup only after the signed grant has expired and
that maximum in-flight window has elapsed. This prevents a slow PUT from
finishing after cleanup and recreating an orphaned staging body.

Version 1.0.0 intentionally contains no import or in-place upgrade path from
earlier platform prototypes. Deleting PostgreSQL irreversibly removes the
authorization and lifecycle source of truth even if object bytes remain.
PostgreSQL and the S3 bucket therefore need coordinated, tested backups; restoring
only one side can leave missing bodies or unauthorized orphaned objects.

## Local development

```console
cp .env.example .env
./run-local.sh
```

Replace every example secret in `.env`, then use the local override. It fixes the
plain-HTTP portal at `http://localhost` and the signed storage data plane at
`http://files.localhost`; keep host ports 80 and 443 free because Caddy owns the
standard edge bindings and these exact origins are also embedded in signed URLs
and CORS policy. Local containers use the isolated `ctfzone-local` Compose
project. `run-local.sh` rebuilds without cache and deletes that project's named
volumes before every start, so each run gets the current v1 schema and empty
local data. Use `./stop-local.sh` to stop it without immediately deleting the
volumes; the next local run will reset them. Local and production projects use
the same host ports, so stop an existing `ctfzone` project once with `./stop.sh`
before starting `ctfzone-local`; the script detects this conflict and refuses
to stop the other project automatically.

## Production

1. Copy `.env.example` to `.env`.
2. Point two distinct DNS names at Caddy. Set `CADDY_SITE_ADDRESS` to the exact
   portal origin (for example `https://ctf.example.org`) and
   `CADDY_STORAGE_ADDRESS` to the exact storage origin (for example
   `https://files.ctf.example.org`). Neither value may contain credentials, a
   path, query, or fragment. `PUBLIC_BASE_URL` and `SITE_ADDRESS` are not used.
3. Generate long, independent values for `SECRET_KEY`,
   `BACKEND_SERVICE_TOKEN`, `API_SIGNING_KEY`, `SETUP_TOKEN`,
   `POSTGRES_PASSWORD`, `OBJECT_STORAGE_ACCESS_KEY`, and
   `OBJECT_STORAGE_SECRET_KEY`; their distinct roles are described below.
   Generate `POSTGRES_PASSWORD` from a URL-safe alphabet (hex is recommended,
   for example `openssl rand -hex 32`) because Compose places it in the internal
   PostgreSQL connection URI. Leave `POSTGRES_USER` and `POSTGRES_DB` at their
   defaults or keep custom values URL-safe for the same reason.
4. Configure the browser SSH destination allowlists and gateway service secret.
5. Treat this as a pre-release environment. Starting it with `run.sh` deletes
   and recreates PostgreSQL, object storage, journals, Caddy data, and both SSH
   identity volumes.

Start CTFZone with:

```console
./run.sh
```

`run.sh` pulls and rebuilds images without cache, removes every named project
volume, and starts from the current `db/init` schema. Use `./stop.sh` to stop
the deployment without deleting its current volumes; the next `./run.sh`
invocation still resets them.

Only ports 80/443 are public. Ports 8000, 8080, 8090, 8091, 8333, and 5432 are
internal and must not be published by an override or firewall rule.

### Secret roles

- `SECRET_KEY` is used only by Python to sign the HttpOnly browser session
  cookie and its CSRF state. Rotating it signs users out; it is not the Rust API
  signing key.
- `BACKEND_SERVICE_TOKEN` authenticates Python as the trusted caller of every
  Rust application/auth endpoint. It is shared only by backend and API and must
  never reach browser JavaScript or logs.
- `API_SIGNING_KEY` is Rust-only key material for API-generated signed values
  such as team invitations and destructive-transition previews. Keep it independent from the
  browser cookie key and service token.
- `SETUP_TOKEN` authorizes creation of the first administrator through the
  Python `/setup` page. Do not put it in a URL or reuse it. Setup remains closed
  after the durable database marker is written.
- `EMAIL_VERIFICATION_TTL_SECONDS` is not a secret. It bounds self-requested
  verification links (30 minutes by default; accepted range 5 minutes
  to 24 hours). Links use `CADDY_SITE_ADDRESS` as their origin.
- `OBJECT_STORAGE_ACCESS_KEY` and `OBJECT_STORAGE_SECRET_KEY` let the API sign
  short-lived S3 operations and let the controller perform maintenance. The
  browser receives only scoped presigned URLs, never these credentials.

## Background maintenance

The controller runs two independent durable workers. The private-instance
worker claims PostgreSQL runtime commands and dispatches a fixed operation
vocabulary over restricted SSH to the remote runtime helper. The object worker
reconciles expired staging uploads and revision-fenced deletion work. Both use
PostgreSQL state and bounded reconciliation so recovery is independent of one
process lifetime. The controller is not involved in browser terminals.

The SSH gateway independently claims key-generation/deletion operations through
the private Rust API and bridges authorized browser WebSockets to registered SSH
hosts. It has no database credentials and does not manage challenge workloads.

Additional project documentation:

- [Configuration](docs/CONFIGURATION.md)
- [Jeopardy challenge authoring](docs/JEOPARDY_AUTHORING.md)
- [Pages and player navigation](docs/PAGES.md)
- [Private-instance controller](docs/INSTANCE_CONTROLLER_ARCHITECTURE.md)
- [Remote runtime helper](remote-helper/README.md)
- [Frontend architecture](docs/FRONTEND_ARCHITECTURE.md)
- [Future competitive-mode implementation](docs/FUTURE_IMPLEMENTATION.md)
- [Possible improvements](docs/POSSIBLE_IMPROVEMENTS.md)
- [Security policy](docs/SECURITY.md)
- [Contributing](docs/CONTRIBUTING.md)

## Health and metadata

Internal endpoints:

- Backend: `GET /healthz` on port 8000.
- API: `GET /healthz` and `GET /readyz` on port 8080.
- Controller: `GET /healthz`, `GET /readyz`, and `GET /status` on port 8090.
- SSH gateway: `GET /healthz` and `GET /readyz` on port 8091.

Product metadata is available internally at API `GET /api/v1/ctfzone` when the
caller supplies the backend service credential; it is intentionally not a
public Caddy route. The reported API status is `native` and
`compatibility_backend` is `false`.

## Verification

```console
make check
```

For a running deployment:

```console
docker compose -f compose.yml ps
docker compose -f compose.yml logs backend api controller ssh-gateway storage
curl --fail https://ctf.example.org/healthz
docker compose -f compose.yml exec api curl --fail --silent http://127.0.0.1:8080/readyz
```

The controller must reach `readyz` before private-instance orchestration and
object-maintenance recovery are treated as available. SSH gateway health and
readiness are independent from controller readiness. Caddy deliberately does
not make the whole portal depend on SSH
gateway startup; when the gateway is unavailable, the terminal route fails
closed while ordinary portal pages remain available.
