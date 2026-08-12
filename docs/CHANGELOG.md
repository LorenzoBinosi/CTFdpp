# Changelog

This file records user-visible CTFZone changes. The project begins a new release
line at 1.0.0; historical changelogs from earlier repository prototypes are not
part of the CTFZone compatibility contract.

## [1.0.0] - 2026-08-12

CTFZone 1.0.0 is the first fresh-install release.

### Architecture

- Split the platform into four core roles: a replaceable Python backend/BFF, a
  native Rust API, an event-driven Rust controller, and one authoritative
  PostgreSQL database.
- Put Caddy at the public edge with distinct portal and storage origins. The
  portal routes only to Python; the storage origin accepts short-lived signed S3
  transfers. Rust API, controller, PostgreSQL, and storage internals remain
  private.
- Keep platform behavior, authentication, scoring, administration, and runtime
  intent in the Rust API. The Python backend has no database credentials or
  domain-model dependency.
- Store portal records and managed-instance state in the same PostgreSQL schema,
  preserving user ownership, the one-active-instance invariant, deadlines, and
  lifecycle history without a second database.

### Platform API

- Add private native endpoints for setup, authentication, users, teams,
  challenges, static and dynamic scoring, submissions, scoreboard data,
  content, object authorization, configuration, exports, sessions, and
  administrator operations. Every application call requires the backend
  service credential; Caddy publishes no generic `/api/v1` or `/files` route.
- Add a compact bootstrap endpoint for site, authentication, setup, and
  current-user state. Python independently owns the browser cookie and CSRF.
- Add public user and team profiles and stable scoreboard account links.
- Add structured challenge responses with Markdown source, file metadata, hint
  state, and managed-runtime availability.
- Add participant-token and browser-session auditing support.

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

### Managed challenge runtimes

- Add durable desired/observed instance state, runtime commands, append-only
  instance events, absolute expiry deadlines, retry metadata, and remote server
  placement.
- Enforce at most one active private challenge instance per user.
- Wake the controller with PostgreSQL notifications while retaining the command
  table as the durable source of work.
- Reconcile pending commands, stale claims, disabled settings, expired
  instances, and remote outcomes after restarts or database reconnects.
- Add mock and SSH remote drivers plus a restricted host helper with independent
  host-side expiry timers.
- Keep the controller dormant, healthy, and ready when private runtimes are not
  enabled or no managed challenge is eligible.

### Web experience

- Replace the legacy renderer with a standalone Flask BFF serving responsive
  challenge, scoreboard, team, rules, authentication, setup, and profile pages.
- Separate the neutral administration/first-boot frontend from manifest-backed
  player frontends. Persist the selected player frontend in platform
  configuration, resolve it through Python's installed registry, and display
  the configured event name in both shells.
- Add a lightweight administrator shell with challenge CRUD, configuration,
  runtime operations, and read-only user, team, submission, and session views.
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
  SMTP/Mailgun provider selection. Preserve unknown older rows under a clearly
  inert advanced section instead of silently discarding them.
- Route browser mutations through same-origin BFF endpoints. Python validates
  Origin, CSRF, and Fetch Metadata, then sends only its backend service token and
  opaque Rust session header over the trusted internal hop.
- Sanitize Markdown and external profile links, authorize object downloads
  before redirecting to signed storage URLs, apply restrictive response headers,
  and disable HTML response caching.
- Require the API's one-time `SETUP_TOKEN` before creating the first
  administrator.

### Deployment and operations

- Provide PostgreSQL 16, S3-compatible storage, Caddy, API, backend, and
  controller Compose services with internal network separation and health
  checks.
- Provide a local HTTP override and production HTTPS defaults.
- Provide numbered SQL initialization scripts for the complete 1.0.0 schema.
- Add health, readiness, and product metadata endpoints.
- Add a minimal CI pipeline for Rust formatting, compilation, tests, strict
  Clippy, Python BFF tests, helper checks, and Compose validation.

### Compatibility boundaries

- Version 1.0.0 supports fresh PostgreSQL installations only. It does not define
  an in-place upgrade or data-import path from pre-CTFZone prototypes.
- King-of-the-hill, attack/defense, speedrun, and scheduled event engines remain
  future modules. Their planned boundaries are documented in
  `docs/FUTURE_IMPLEMENTATION.md`.
