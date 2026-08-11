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

Never include live flags, passwords, `SETUP_TOKEN`, `SECRET_KEY`, session
cookies, API tokens, SSH keys, packet captures containing participant traffic,
or personal data. Ask the maintainers for a secure exchange method if sensitive
artifacts are essential to reproduce the issue.

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
- controller command claiming, idempotency, expiry, reconciliation, and remote
  execution;
- SSH helper restrictions, container escape, host-key validation, or secret
  mounts;
- PostgreSQL constraints, query authorization, data exposure, and backup safety;
- Caddy routing, TLS, or unintended exposure of internal services.

## Deployment guidance

- Generate long, independent values for `SECRET_KEY`, `SETUP_TOKEN`, and
  `POSTGRES_PASSWORD`; never retain the example values.
- Treat `SETUP_TOKEN` as a one-time bootstrap secret. Enter it only on the
  same-origin `/setup` form. After the first administrator exists, rotate it to
  a new random value and retain that value for API restarts; the closed setup
  invariant makes it unusable for creating another administrator.
- Publish only Caddy. Keep the backend, API, controller, PostgreSQL, and
  controller health endpoints on private networks.
- Use HTTPS in production and set `PUBLIC_BASE_URL` to the exact public origin.
- Run the controller as its unprivileged user with a dedicated key, pinned host
  keys, and the restricted remote helper. Do not give it a general-purpose root
  shell.
- Back up and test recovery of PostgreSQL and uploads. Protect backups as
  production secrets.
- Keep container images, Rust and Python dependencies, PostgreSQL, Caddy, and
  challenge hosts patched.
- Review logs and exports before sharing them; they can contain IP addresses,
  submissions, session metadata, and other participant data.
