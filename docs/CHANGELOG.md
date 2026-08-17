# Changelog

This file records user-visible CTFZone changes. The project begins a new release
line at 1.0.0; historical changelogs from earlier repository prototypes are not
part of the CTFZone compatibility contract.

## [1.0.0] - 2026-08-12

CTFZone 1.0.0 is the first fresh-install release.

### Architecture

- Split the platform into five core roles: a replaceable Python backend/BFF, a
  native Rust API, a private-instance/object-maintenance Rust controller, an
  isolated browser SSH gateway, and one authoritative PostgreSQL database.
- Put Caddy at the public edge with distinct portal and storage origins. The
  portal routes only to Python; the storage origin accepts short-lived signed S3
  transfers. Rust API, controller, PostgreSQL, and storage internals remain
  private.
- Keep platform behavior, authentication, scoring, and administration in the
  Rust API. The Python backend has no database credentials or
  domain-model dependency.
- Store portal and object-lifecycle records in one PostgreSQL schema without a
  second source of truth.

### Platform API

- Add private native endpoints for setup, authentication, users, teams,
  challenges, static and dynamic scoring, submissions, scoreboard data,
  content, object authorization, configuration, exports, sessions, and
  administrator operations. Every application call requires the backend
  service credential; Caddy publishes no generic `/api/v1` or `/files` route.
- Add a compact bootstrap endpoint for site, authentication, setup, and
  current-user state. Python independently owns the browser cookie and CSRF.
- Add public user and team profiles and stable scoreboard account links.
- Add structured challenge responses with Markdown source, file metadata, and
  hint state.
- Add participant-token and browser-session auditing support.
- Add an atomic five-step Jeopardy creation contract with reusable challenge
  categories, public or private exposure, Markdown attribution, sanitized
  Markdown/HTML descriptions, optional free-form connection information,
  exact/regex/generated flags, dynamic scoring, and replay-safe administrator
  create requests.

### Private challenge instances

- Add revisioned per-challenge runtime profiles, immutable deployment
  snapshots, one-active-instance enforcement, durable runtime commands, and
  append-only lifecycle events.
- Add participant start, stop, extension, endpoint, expiry, and bounded status
  controls without exposing runtime host or image selection to the browser.
- Dispatch only fixed, typed operations over pinned, restricted SSH to the
  rootless remote runtime helper. Host-local timers and fsynced tombstones keep
  expiry and stop idempotent across controller or network outages.
- Keep the controller running as the internal reconciler while omitting a
  dedicated administrator “Managed instances” page from the 1.0 interface.
- Materialize stable per-user generated flags at first private-instance
  activation. Templates may use one `{{RANDOM_TOKEN}}`, bounded leet
  variations, or both; optional cross-user acceptance records durable sharing
  provenance. The raw assigned flag is redacted from API events and controller
  journals and reaches the container only as `CTFZONE_FLAG`.

### Object storage

- Add an S3-compatible data plane for challenge files and future artifacts.
  PostgreSQL remains authoritative for object ownership, purpose, status,
  expected/actual metadata, retention, events, and durable maintenance work.
- Add a required SHA-256 upload protocol: authorize JSON metadata through the
  BFF, PUT bytes directly to a signed staging URL, then complete through the BFF
  so Rust can verify and promote the object before `pending` becomes `ready`.
- Add same-origin `/downloads/<object-id>` authorization and short-lived signed
  GET redirects restricted to `CADDY_STORAGE_ADDRESS`. Storage credentials
  never reach the browser, and object bodies never pass through Python workers.
- Add controller-owned reconciliation for expired pending uploads and durable,
  idempotent storage cleanup/deletion after restarts. Bound upload duration at
  Caddy and defer terminal staging cleanup through the corresponding quiescence
  window so a slow in-flight PUT cannot recreate an orphan after deletion.
- Buffer and tightly cap normal portal request bodies at Caddy while retaining
  the longer, bounded edge read window required by direct signed object
  transfers; storage completion has a matching synchronous worker budget.

### Web experience

- Replace the legacy renderer with a standalone Flask BFF serving responsive
  challenge, scoreboard, team, rules, authentication, setup, and profile pages.
- Separate the neutral administration/first-boot frontend from manifest-backed
  player frontends. Persist the selected player frontend in platform
  configuration, resolve it through Python's installed registry, and display
  the configured event name in both shells.
- Add a lightweight administrator shell with challenge CRUD, configuration,
  SSH connections, and read-only user, team, submission, and session views.
- Replace the single-page challenge form with a responsive five-step Jeopardy
  wizard: type, availability, details, flag, and connection. Attack/Defense,
  Speed run, and King of the hill remain visible but disabled as future formats.
- Apply the task-oriented steel-blue administration design across every admin
  module, first-boot setup, and administrator sign-in, with contextual
  navigation, responsive off-canvas controls, accessible SVG icons, and
  section-based configuration navigation.
- Show actual Rust API routes in administrator session activity instead of
  synthetic Python request markers, and add safe per-session and per-account
  browser-session termination controls backed by non-credential management
  identifiers.
- Add a dedicated user editor for participant/administrator roles and public
  visibility, plus profile-owned, expiring single-use email verification for
  every account type. Role changes revoke existing browser sessions and user API
  tokens atomically.
- Restore an API-owned typed configuration catalog with synthesized defaults,
  atomic section updates, redacted keep/replace/clear secret handling, explicit
  registration admission modes, a searchable email allowlist, and explicit
  SMTP/Mailgun provider selection. Reject unknown configuration keys.
- Route browser mutations through same-origin BFF endpoints. Python validates
  Origin, CSRF, and Fetch Metadata, then sends only its backend service token and
  opaque Rust session header over the trusted internal hop.
- Sanitize Markdown and external profile links, authorize object downloads
  before redirecting to signed storage URLs, apply restrictive response headers,
  and disable HTML response caching.
- Require the API's one-time `SETUP_TOKEN` before creating the first
  administrator.

### Browser SSH console

- Add an administrator-only SSH host inventory and browser terminal without
  exposing SSH private keys to Python, JavaScript, or PostgreSQL.
- Generate one gateway-owned Ed25519 identity per host, display only the
  restricted `authorized_keys` line, and require explicit host-key pinning
  before a terminal can open.
- Use 30-second one-use tickets and a same-origin WebSocket bridge with bounded
  sessions, destination allowlists, forwarding disabled, and revocation on
  logout or host removal.

### Deployment and operations

- Provide PostgreSQL 16, S3-compatible storage, Caddy, API, backend,
  controller, and SSH-gateway Compose services with internal network
  separation and health checks.
- Provide a local HTTP override and production HTTPS defaults.
- Provide numbered SQL initialization scripts for the complete 1.0.0 schema.
- Add health, readiness, and product metadata endpoints.
- Add a minimal CI pipeline for Rust formatting, compilation, tests, strict
  Clippy, Python BFF tests, fresh-schema initialization, and Compose validation.

### Compatibility boundaries

- Version 1.0.0 supports fresh PostgreSQL installations only. It does not define
  an in-place upgrade or data-import path from pre-CTFZone prototypes.
- King-of-the-hill, attack/defense, speedrun, and scheduled event engines remain
  future modules. Their planned boundaries are documented in
  `docs/FUTURE_IMPLEMENTATION.md`.
