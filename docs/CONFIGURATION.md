# CTFZone configuration

Status: Implemented 1.0.0 baseline  
Last updated: 2026-08-17

CTFZone's administration configuration page is driven by a typed catalog from
the private Rust API. Python renders that catalog and forwards browser changes;
it does not duplicate configuration defaults or platform rules.

```text
Browser -> Python /admin/config -> Rust configuration catalog -> PostgreSQL
Browser -> Python /bff/...      -> Rust validated update       -> PostgreSQL
```

Only administrators can read or change the catalog. The Rust API is not exposed
by Caddy, so browser code always reaches it through Python's authenticated,
same-origin BFF boundary.

## Sections and behavior

The catalog defines six logical sections.

| Section | Active settings |
| --- | --- |
| Site & interface | `ctf_name`, `ctf_description`, `player_frontend` |
| Visibility & access | `challenge_visibility`, `score_visibility`, `account_visibility` |
| Schedule | `start`, `end`, `freeze`, `paused`, `view_after_ctf` |
| Accounts & registration | `num_users`, `password_min_length`, `name_changes`, `verify_emails`, `user_mode`, `team_creation`, `team_size`, `num_teams`, `team_disbanding`, `registration_visibility`, `registration_access_mode`, `registration_code`, `domain_whitelist`, `domain_blacklist` |
| Challenges & scoring | `incorrect_submissions_per_min`, `max_attempts_behavior`, `max_attempts_timeout`, `challenge_ratings`, `hints_free_public_access`, `view_self_submissions` |
| Email delivery | `mail_provider`, `mail_server`, `mail_port`, `mail_username`, `mail_password`, `mail_ssl`, `mail_tls`, `mailfrom_addr`, `user_creation_email_subject`, `mailgun_base_url`, `mailgun_api_key` |

The combined account section has four API-owned presentation groups, in order:
**Participant accounts**, **Account type**, **Team accounts**, and
**Registration access**. Policies shared by every participant are shown first;
the account-type selector then controls the team-only group. Admission controls
remain last so the relational email allowlist can follow the settings form
directly.

The API supplies field types, select options, dependencies, presentation-group
metadata, help text, warnings, and read-only state. It normalizes booleans,
integers, timestamps, selections, and text, then validates the complete
proposed configuration. Important cross-field checks include:

- the event end must be later than its start and a freeze must be inside that
  window;
- implicit SMTP TLS and STARTTLS cannot both be enabled;
- access-code registration requires a configured code;
- explicitly selected SMTP or Mailgun providers require their corresponding
  connection settings;
- ordinary configuration mutations cannot change competition mode. The
  dedicated transition described below previews and confirms every destructive
  consequence before changing it.

The browser sends only fields changed in one section. Rust applies that patch in
one database transaction, so either every field in the save succeeds or none of
them do.

## Competition mode transition

Changing between individual-user and team scoring is a destructive account-mode
transition, not an ordinary configuration edit. The administration panel first
requests a short-lived, signed preview containing the source and target modes,
the initiating administrator, exact affected-record counts, blockers, and the
required confirmation phrase. Confirmation is rejected when that preview has
expired or the database has changed, so the administrator must review fresh
counts rather than approving a stale estimate.

Both directions delete submissions and solves, awards, purchased unlocks, and
challenge-open tracking, then restore dynamic challenge values to their
configured initial values. Participant identities, passwords, profiles,
verification state, ratings, challenge definitions and assets, registration
policies, email invitations, and audit history remain. Participant browser
sessions and API tokens are revoked and participant credentials are rotated so
clients cannot continue silently under a different scoring principal.
Participant-owned competition objects (`submission`, `patch`, `program`,
`pcap`, and `result`) are made unavailable and queued for revision-fenced
storage cleanup in both directions. Their metadata and lifecycle events remain
as audit history. The preview counts all matching retained object records,
including records already deleting or deleted; only objects still in a live
lifecycle state are newly queued. Export objects and challenge, page, and
solution assets are preserved.

Both transitions remove every existing or stale membership, team,
team-targeted notification, team profile entry, and team comment. Switching to
team mode therefore preserves every participant as an unassigned user; each
must subsequently create or join a new team. Existing object-lifecycle triggers
immediately make team-owned objects unavailable and enqueue revision-fenced
storage cleanup while retaining their metadata and event history.

Challenges configured with team-specific logic are not rewritten automatically
when switching to individual mode; the preview reports them for administrator
review.

Any active private challenge instance blocks either account-mode transition.
Terminate active instances first so runtime ownership, credentials, and team
references cannot change underneath a live remote workload.

The confirmation endpoint performs the reset, mode update, and durable
transition audit record in one PostgreSQL transaction under the exclusive
configuration fence. Mode-sensitive writers take the shared side of that fence,
preventing a request begun under the old mode from committing after the reset.
The UI requires the API-provided phrase (for example `SWITCH TO TEAMS`) and
requires a coordinated PostgreSQL and object-storage backup before continuing.

Registration-access changes are deliberately different: switching among open,
domain-rule, access-code, and email-allowlist admission affects future
registrations only. It never deletes accounts, invitations, stored codes, or
domain rules.

Fresh databases create the transition audit and browser-SSH control-plane schema
through the ordered files in `db/init`.
PostgreSQL runs those files only when it creates an empty data directory;
restarting or rebuilding containers does **not** rerun them for an existing
volume.

CTFZone 1.0.0 is a fresh-install contract. Pre-release prototype databases are
not supported and there is no incremental migration directory. During
development, recreate the PostgreSQL volume when the schema changes; never do
that to a database whose contents must be retained. Production upgrade scripts
will begin with the first post-1.0 schema change.

After the SSH gateway has generated console identities, include its
`ssh_gateway_identities` volume with PostgreSQL and object storage in the same
coordinated encrypted backup set.

Transition requests use bounded API phases: authentication is capped at 4
seconds, the complete preview or destructive pre-commit phase at 45 seconds,
PostgreSQL COMMIT at 8 seconds, and post-handler activity recording at 2
seconds. The BFF therefore uses a 65-second HTTPX read-phase budget, while the
Gunicorn timeout setting defaults to 75 seconds as an additional deployment
safety margin. HTTP transport phases and Gunicorn worker-heartbeat semantics
mean those two values are not strict end-to-end wall-clock deadlines. Backend
startup nevertheless rejects overrides that leave less than five seconds of
configured headroom between the API bound, BFF budget, and worker setting; keep
`BACKEND_TRANSITION_API_TIMEOUT_SECONDS` and
`BACKEND_WORKER_TIMEOUT_SECONDS` aligned when customizing them.

## Defaults and database overrides

Defaults belong to the Rust catalog. They are synthesized on reads and are not
backfilled into `ctfzone.config` merely because an administrator opens the page.
For every known setting, the catalog distinguishes:

- `default`: the API-owned baseline;
- `stored`: an explicit PostgreSQL override, when one exists;
- `effective`: the value currently presented and enforced;
- `configured`: whether a non-empty database value exists.

An absent row therefore means "use the current API default," while a validated
row overrides that default. Saving a changed field upserts its explicit value.
Known settings cannot be deleted to create ambiguous behavior; change them
through the typed control instead. Do not modify configuration rows directly,
because that bypasses type, range, dependency, and transition checks.
Fresh installations persist the core account and team defaults during setup so
operators can also inspect a complete initial policy directly in PostgreSQL.

The principal 1.0 defaults are `CTFZone` with the `terminal` player frontend,
individual-user mode, private challenge visibility, public accounts, scores,
and registration, no event time window, open registration with no participant
or password-length limit, participant team creation enabled, unlimited team
size and team count, inactive-only team disbanding, and unpaused submissions.
Incorrect submissions default to 10 per minute;
maximum challenge attempts use permanent lockout (with a 300-second timeout
value ready if timeout mode is selected); ratings are public; guest free hints
and participant submission history are disabled. Email defaults to `auto` on
SMTP port 587, with no provider credentials or sender configured.

Fresh setup stores `registration_access_mode` explicitly. If it is absent or
invalid, reads fail closed to `open`; access codes and domain rules do not
silently change the selected policy.

## Secret settings

The API never returns secret values. It reports only whether a secret is
configured. This applies to `registration_code`, `mail_password`, and
`mailgun_api_key`, and defensively to keys ending in `_password`,
`_secret`, `_token`, or `_api_key` (case-insensitive).

Secret updates have three explicit meanings:

| Admin action | API value | Result |
| --- | --- | --- |
| Keep | field omitted, or an empty string | Preserve the stored secret |
| Replace | non-empty string | Store the replacement |
| Clear | JSON `null` | Store an empty value |

The admin UI requires a separate choice for replace or clear, and asks for
confirmation before clearing. This prevents an empty password control from
silently erasing an existing credential.

## Player frontend selection

PostgreSQL stores `player_frontend` as an identifier, not a template path. Rust
validates it as a bounded safe slug. Python discovers installed frontend
manifests at startup, converts the field into a selector, and resolves the value
through its immutable registry.

If the stored identifier is no longer installed, Python uses the bundled
`terminal` frontend, shows a warning to the administrator, and marks the field
for repair on the next save. Selecting a player frontend never changes the
neutral administration or setup frontend. See
[Frontend architecture](FRONTEND_ARCHITECTURE.md) for the package contract.

## Registration access and email allowlist

`registration_visibility` opens or closes the registration route.
`registration_access_mode` adds one admission policy while registration is
open:

- `open`: no additional admission check;
- `domain_rules`: apply the comma-separated allow and deny domain rules;
- `access_code`: require the configured secret code;
- `email_allowlist`: require an exact, case-insensitive email entry.

Changing this policy affects future registration attempts only. Existing
accounts are not modified, and inactive access codes, domain rules, and email
invitations remain stored for later reuse. In email-allowlist mode, only exact
invited addresses may register and those invitations deliberately bypass the
general participant limit.

Domain rules are normalized to lowercase. A rule must be either an exact DNS
domain (`example.org`) or a wildcard subdomain suffix (`*.example.org`); a bare
`*`, URL, partial wildcard, and malformed DNS label are rejected. When both
lists are populated, the address must match the allow rules and must not match
any deny rule.

The email allowlist is normalized relational data in
`ctfzone.registration_email_allowlist`, not a comma-separated configuration
value. The admin page supports individual additions, search, pagination,
removal, and CSV import. An import must be at most 5 MiB and contain an `email`
header; duplicates and administrator addresses are skipped. A registered entry
is labelled as such and cannot be removed until its participant account is
deleted. Registration locks the matching reservation through account creation,
so a concurrent administrator removal cannot admit an address after its entry
has disappeared. Deleting a participant removes its reservation in the same
transaction. Changing a reserved participant's email moves that reservation;
changing an unreserved participant from open, domain, or code registration does
not silently add one. Participant-to-administrator changes remove the entry,
while administrator-to-participant changes create one. Allowlist mode
deliberately bypasses `num_users`, because the list itself is the admission
capacity decision. Stored allowlist addresses are case-insensitively unique.

Registration also holds a shared configuration lock from policy loading through
account creation. Configuration saves take the corresponding exclusive lock,
so visibility, access mode, code or domains, participant limit, password
minimum, and account mode cannot change midway through one registration.
Capacity-limited non-allowlist registrations take a second transaction lock
before recounting active visible accounts, preventing concurrent registrations
from both claiming the final place.

In team mode, `team_creation` controls participant self-service creation without
disabling invite-based joining. `team_size` limits participant joins and
`num_teams` limits participant-created active visible teams; zero means
unlimited for either setting. Lowering a limit does not remove existing teams
or memberships. Administrator management remains available independently of
participant self-service policy. Captains issue signed, team-bound invite codes
that expire after 24 hours. An invite may admit multiple otherwise-unassigned
participants during that window, subject to the current team-size policy;
changing the team's password invalidates outstanding codes.

## Email provider selection

`mail_provider` makes delivery selection explicit:

- `disabled` rejects send attempts;
- `smtp` requires `mail_server` and uses the SMTP port, optional credentials,
  and at most one of implicit TLS or STARTTLS;
- `mailgun` requires both `mailgun_base_url` and `mailgun_api_key`;
- `auto` prefers a complete Mailgun configuration, then a configured SMTP
  server.

`mailfrom_addr` is required when a message is sent. The current implementation
sends administrator-authored messages to users; the configurable subject may
use `{ctf_name}`. Each signed-in user, including an administrator, can request a
verification message from their own profile. Enabling `verify_emails` requires a
configured sender and usable SMTP or Mailgun selection; unverified participants
are then denied challenge access until they follow the delivered single-use link.
Automatic registration delivery and password-reset messages are not
implemented yet.

## Deferred settings

Only settings in the typed catalog are accepted. Unknown keys are rejected
rather than stored as inert compatibility data. The following capabilities are
intentionally not active configuration in 1.0.0:

- database-selected themes, logo/favicon uploads, color controls, and raw
  header/footer/theme injection; CTFZone uses reviewed, manifest-backed player
  frontend packages instead;
- locale selection, editable legal/terms/privacy pages, and `robots.txt`;
- bracket administration and custom-field administration in this configuration
  page;
- social share templates and solve-share pages;
- MajorLeagueCyber OAuth and plugin-defined configuration panels;
- automatic registration delivery, account-details, and password-reset email
  bodies/subjects; self-service verification uses a fixed safe message today
  rather than an editable template;
- `mail_useauth`, which is replaced by the presence of an SMTP username and
  password;
- a switch that permits unsafe HTML. Rendered participant content remains
  sanitized by design;
- reset, archive import/export, and arbitrary table CSV controls as
  configuration-page operations.

`verify_emails` is editable. Enabling it is rejected unless the sender and
selected provider are configured. Verification tokens are random, expire after
`EMAIL_VERIFICATION_TTL_SECONDS`, are single-use, and are bound to the user's
current email address; PostgreSQL stores only their SHA-256 hashes. Sending a
replacement or changing the address invalidates outstanding links.

Potential implementations for these deferred areas are tracked in
[Possible improvements](POSSIBLE_IMPROVEMENTS.md). A capability must gain Rust
domain behavior and tests before it becomes a configuration key.
