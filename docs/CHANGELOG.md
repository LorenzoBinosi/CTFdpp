# Changelog

This file records user-visible CTFZone changes. The project begins a new release
line at 1.0.0; historical changelogs from earlier repository prototypes are not
part of the CTFZone compatibility contract.

## [1.0.0] - 2026-08-11

CTFZone 1.0.0 is the first fresh-install release.

### Architecture

- Split the platform into four core roles: a replaceable Python backend/BFF, a
  native Rust API, an event-driven Rust controller, and one authoritative
  PostgreSQL database.
- Put Caddy at the public edge for automatic TLS, compression, and explicit
  routing between human-facing pages and the machine API.
- Keep platform behavior, authentication, scoring, administration, and runtime
  intent in the Rust API. The Python backend has no database credentials or
  domain-model dependency.
- Store portal records and managed-instance state in the same PostgreSQL schema,
  preserving user ownership, the one-active-instance invariant, deadlines, and
  lifecycle history without a second database.

### Platform API

- Add native endpoints for setup, authentication, users, teams, challenges,
  static and dynamic scoring, submissions, scoreboard data, content, files,
  configuration, exports, sessions, and administrator operations.
- Add a compact bootstrap endpoint for site, authentication, CSRF, setup, and
  current-user state.
- Add public user and team profiles and stable scoreboard account links.
- Add structured challenge responses with Markdown source, file metadata, hint
  state, and managed-runtime availability.
- Add participant-token and browser-session auditing support.

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
- Add a lightweight administrator shell with challenge CRUD, configuration,
  runtime operations, and read-only user, team, submission, and session views.
- Route browser mutations through same-origin BFF endpoints with CSRF and Fetch
  Metadata preserved across the trusted API hop.
- Sanitize Markdown and external profile links, stream authorized downloads,
  apply restrictive response headers, and disable HTML response caching.
- Require the API's one-time `SETUP_TOKEN` before creating the first
  administrator.

### Deployment and operations

- Provide PostgreSQL 16, Caddy, API, backend, and controller Compose services
  with internal network separation and health checks.
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
