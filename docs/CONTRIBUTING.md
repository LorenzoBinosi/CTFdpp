# Contributing to CTFZone

Thank you for improving CTFZone. Keep changes focused, explain the operational
impact, and include verification proportional to the risk.

Security vulnerabilities must not be reported in a public issue. Follow
[`SECURITY.md`](SECURITY.md) instead.

## Architecture boundaries

Contributions must preserve these ownership rules:

- Caddy is the public edge. `CADDY_SITE_ADDRESS` routes exclusively to Python;
  the distinct `CADDY_STORAGE_ADDRESS` carries only short-lived signed S3
  transfers. Do not add a public generic Rust `/api/v1` or `/files` route.
- The Python backend is a replaceable page renderer and browser-facing BFF. It
  owns the signed browser cookie, same-origin checks, and CSRF, but must not
  connect to PostgreSQL, hold storage credentials, or acquire platform business
  logic.
- The administration frontend is a fixed, neutral control-plane surface.
  Player frontends live in separate manifest-backed packages under
  `backend/ctfzone_web/frontends/player/`; do not make administration templates
  or assets depend on the selected player package. Shared browser code is
  limited to presentation-independent BFF/storage protocol helpers. See
  [`FRONTEND_ARCHITECTURE.md`](FRONTEND_ARCHITECTURE.md).
- The Rust API owns authentication, authorization, platform behavior, scoring,
  administration, object metadata/grants, and runtime intent. Private
  application calls require `BACKEND_SERVICE_TOKEN` and use an opaque internal
  session header when authenticated.
- The Rust controller owns asynchronous runtime execution, recovery, deadlines,
  remote-host reconciliation, and durable object cleanup. Notifications are
  wake-up hints; durable work remains in PostgreSQL.
- PostgreSQL is the single authoritative store for portal, runtime, and object
  ownership/lifecycle metadata. S3-compatible storage holds object bytes, not
  authorization state.

Browser actions must use the same-origin BFF boundary. Browser credentials,
Origin, CSRF, Fetch Metadata, and Authorization headers must not be blindly
forwarded to Rust. External integrations currently have no public generic API;
a future machine ingress must be explicitly scoped and authenticated rather than
publishing the private API port.

## Development setup

Run development commands from the repository root.

```console
cp .env.example .env
docker compose -f compose.yml -f compose.local.yml up --build
```

Replace every example secret in `.env`. Use
`CONTROLLER_REMOTE_DRIVER=mock` unless you intentionally provisioned the
restricted SSH helper and test hosts. The local override serves the portal at
`http://localhost` and signed object transfers at `http://files.localhost`.

For host-side checks, install Python 3.12 and Rust 1.85 or newer, then prepare
the BFF dependencies and Rust cache:

```console
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --requirement backend/requirements.txt
cargo fetch --locked
make check
```

`make check` runs Rust formatting, compilation, tests, strict Clippy, the Python
BFF tests, remote-helper syntax checks, and Compose validation.

## Testing individual components

Run the Rust workspace checks from the repository root:

```console
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Run BFF tests from `backend/`:

```console
python -m pip install --requirement requirements.txt
python -m unittest discover -s tests -v
```

Validate both deployment variants from the repository root:

```console
make compose-check
```

The target supplies non-production dummy values for every required Compose
variable: both Caddy origins, PostgreSQL, Python's browser-cookie key, the
backend-to-API service token, Rust's signing key, first-boot token, and S3 access
and secret keys.

Never point tests at a production database or real challenge host.

## Pull requests

Before opening a pull request:

1. Rebase or merge the current target branch and resolve unrelated changes.
2. Add tests for behavior changes and failure recovery, not only the happy path.
3. Run the relevant component checks and record the exact commands in the pull
   request.
4. Update configuration examples and documentation when behavior or operational
   requirements change.
5. Confirm that no flags, passwords, setup tokens, session cookies, API tokens,
   private keys, host inventories, packet captures, or participant data are in
   the diff.

Keep pull requests scoped to one coherent outcome. Pure refactors should not
silently change API contracts, schema invariants, controller state transitions,
or security boundaries.

## Database and runtime changes

CTFZone 1.0 currently targets fresh installations. Keep `db/init/`
deterministic and ensure a new PostgreSQL volume reaches the finalized 1.0.0
schema before the API becomes ready. Do not introduce a second runtime database
or direct BFF database access.

Changes to object storage must preserve the split source of truth: PostgreSQL
owns authorization, association, status, retention, events, and durable
operations; the S3-compatible service owns bytes. Uploads must stay `pending`
until required SHA-256 and metadata are verified and the staged object is
promoted, after which it becomes `ready`. Test expired-upload reconciliation,
idempotent deletion, lease recovery, and coordinated database/bucket restores.
Never proxy large object bodies through Python or publish storage credentials;
use the grant → direct transfer → completion protocol.

Changes to runtime commands or instance states must document:

- who writes the desired state;
- how the controller claims and retries the work;
- how duplicate delivery remains idempotent;
- what happens across API, controller, database, and remote-host outages;
- how absolute expiry is enforced if the control plane is unavailable.

## Reporting ordinary bugs

Search existing issues first. A useful report includes the version or commit,
deployment method, affected component, expected and observed behavior, minimal
reproduction, and sanitized logs. Use the repository issue template and remove
all secrets and participant data before posting.
