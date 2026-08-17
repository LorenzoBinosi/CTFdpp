# Security policy

## Supported versions

CTFZone is in its initial 1.0 release line.

| Version | Security updates |
|---|---|
| 1.0.x | Supported |
| Pre-1.0 prototypes | Not supported |

## Reporting a vulnerability

Do not open a public issue, discussion, or pull request for a suspected
vulnerability.

Use GitHub's private vulnerability reporting for this repository: open the
repository's **Security** tab and choose **Report a vulnerability**. If private
reporting is unavailable, contact the repository maintainers privately through
an address published by the repository owner. Do not send reports to an address
copied from an unrelated upstream project.

Include:

- the affected CTFZone version or commit and component;
- the deployment topology and relevant non-secret configuration;
- reproducible steps or a minimal proof of concept;
- the security impact and prerequisites;
- sanitized logs, requests, or database records;
- any suggested mitigation or disclosure constraints.

Never include live flags, passwords, `SECRET_KEY`, `BACKEND_SERVICE_TOKEN`,
`API_SIGNING_KEY`, `SETUP_TOKEN`, object-storage credentials, session cookies,
API tokens, SSH keys, presigned storage URLs, packet captures containing
participant traffic, or personal data. Ask the maintainers for a secure exchange
method if sensitive artifacts are essential to reproduce the issue.

Maintainers will validate the report, coordinate a fix and release when needed,
and agree on disclosure timing with the reporter. Please allow time for a fix to
reach supported deployments before publishing technical details.

## Security-sensitive areas

Reports are especially useful for:

- authentication, authorization, sessions, CSRF, Fetch Metadata, and first-boot
  setup;
- challenge visibility, scoring integrity, flag handling, and account isolation;
- BFF proxy boundaries, file upload/download authorization, Markdown rendering,
  redirects, and browser security headers;
- controller runtime-command and object-operation claiming, idempotency,
  generation fencing, expiry, and reconciliation;
- browser SSH ticketing, destination policy, host-key validation, terminal
  isolation, or secret mounts;
- PostgreSQL constraints, query authorization, data exposure, and backup safety;
- Caddy site/storage-origin routing, TLS, signed S3 requests, storage CORS, or
  unintended exposure of internal services.

## Deployment guidance

- Generate long, independent values for every credential in `.env`; never
  retain the example values. In particular, do not reuse any of these keys:

  - `SECRET_KEY` signs Python's HttpOnly browser cookie and CSRF state. It must
    exist only in the backend; rotation invalidates browser sessions.
  - `BACKEND_SERVICE_TOKEN` authenticates Python to every private Rust
    application endpoint. It belongs only in backend and API processes.
  - `API_SIGNING_KEY` is Rust-only HMAC material for API-generated signed
    values. It is not a browser cookie key or a storage credential.
  - `SETUP_TOKEN` authorizes only first-administrator setup.
  - `OBJECT_STORAGE_ACCESS_KEY` and `OBJECT_STORAGE_SECRET_KEY` sign S3
    operations for the API and authorize controller maintenance. They must
    never be exposed to a browser; a presigned URL is itself a temporary bearer
    credential and must not be logged or shared.

  Generate `POSTGRES_PASSWORD` with a URL-safe alphabet, such as
  `openssl rand -hex 32`. Compose uses the same literal value to initialize
  PostgreSQL and inside the private connection URI, so reserved URI characters
  must not be used. Custom `POSTGRES_USER` and `POSTGRES_DB` values must also be
  URL-safe.

- Treat `SETUP_TOKEN` as a one-time bootstrap secret. Enter it only on the
  same-origin `/setup` form. After the first administrator exists, rotate it to
  a new random value and retain that value for API restarts; the closed setup
  invariant makes it unusable for creating another administrator.
- Publish only Caddy's two intended origins. `CADDY_SITE_ADDRESS` is the portal
  origin and routes exclusively to Python; `CADDY_STORAGE_ADDRESS` is a
  distinct object-data origin that accepts only short-lived signed S3
  operations. Keep backend, Rust API, controller, PostgreSQL, and the storage
  administration/internal endpoints on private networks. There is no public
  generic `/api/v1` or `/files` route.
- Use HTTPS in production. Configure both Caddy values as exact origins without
  credentials, path, query, or fragment. Restrict storage CORS to the site
  origin and the methods/headers required by signed uploads.
- Keep browser session IDs opaque and usable only together with the private
  backend service token. Python must consume browser cookies, Origin, CSRF, and
  Fetch Metadata itself rather than forwarding those credentials to Rust.
- Treat email-verification links as short-lived bearer credentials. CTFZone
  places the raw token in the URL fragment so it does not reach edge access
  logs, removes that fragment from browser history before submission, and stores
  only a SHA-256 hash in PostgreSQL. Changing an email or issuing a replacement
  invalidates prior links. Every account, including the first setup administrator,
  starts unverified; only successful token confirmation may set `verified=true`.
  Verification messages are self-requested from the authenticated account's own
  profile and can only target that account's current email address.
  Changing a user's role revokes that user's browser sessions and user API tokens
  before the new role becomes usable.
- Treat upload initiation and completion as separate authorization steps. An
  object remains `pending` while bytes are uploaded to a staging key; completion
  must verify the required SHA-256 and object metadata before promoting the
  immutable object and marking it `ready`. Never expose pending, failed, or
  quarantined objects in challenge/download responses. Keep Caddy's finite
  upload-body timeout and the controller's staging-quiescence setting equal; a
  final staging deletion is durable only after every accepted PUT is unable to
  remain in flight.
- Keep the portal body cap and Caddy request buffering enabled. Browser-facing
  forms and JSON are small; bulk bytes belong on the signed storage origin.
  Buffering the bounded portal body before proxying prevents a slow client from
  tying up a Python worker. Keep the backend's storage-completion timeout below
  its Gunicorn worker timeout so verified promotion has a deterministic budget.
- Run the controller as its unprivileged user. Its storage credentials are for
  bounded reconciliation/deletion work, not general storage administration.
  Mount its SSH identity and pinned `known_hosts` read-only. On every runtime
  host, force that key through `ctfzone-runtime-helper ssh-dispatch`, disable
  forwarding, and keep the dedicated account out of privileged groups. The
  controller must never receive a Docker or Podman socket.
- Treat the browser SSH console as full access to the registered Unix account,
  not as a read-only viewer. Keep its keys confined to the gateway. The
  browser receives only a 30-second one-use ticket; only the isolated SSH
  gateway may read `ssh_gateway_identities`, open outbound SSH, or carry PTY
  bytes. Require an exact, independently confirmed SSH host key before issuing
  terminal tickets, reject private/control-plane destinations, disable every
  form of forwarding, and bound session lifetime, idle time, dimensions, and
  buffering. Never log tickets, terminal input/output, commands, private keys,
  or environment contents. Deleting a portal record does not revoke the remote
  `authorized_keys` entry; remove that line on the host as well.
- PostgreSQL is the source of truth for object ownership, authorization,
  lifecycle, and history; the S3-compatible store holds only bytes. Back up and
  restore the database and bucket as a coordinated set, test recovery, and
  protect both backups as production secrets. The controller should reconcile
  expired pending uploads and durable deletion work after outages.
- Treat competition-mode changes as destructive transitions. Use only the
  signed preview and typed-confirmation workflow; do not edit `user_mode`
  directly in PostgreSQL. Take a coordinated database/object-store backup and
  review the fresh affected-row
  counts before confirming. Preview tokens are short-lived and bound to the
  administrator, source and target modes, and database snapshot; a stale or
  replayed preview must be rejected. The transition retains audit metadata while
  removing competition records and queuing participant- and team-owned
  competition-byte cleanup. Previously issued presigned object URLs remain
  bearer credentials until their bounded expiry (at most the configured
  `PRESIGNED_URL_TTL_SECONDS`), so wait for storage cleanup when strict
  byte-level revocation is required.
  Active private instances block the transition; terminate them first so team
  ownership and participant credentials cannot change beneath a live workload.
- Keep container images, Rust and Python dependencies, PostgreSQL, Caddy, and
  challenge hosts patched.
- Review logs and exports before sharing them; they can contain IP addresses,
  submissions, session metadata, and other participant data.
