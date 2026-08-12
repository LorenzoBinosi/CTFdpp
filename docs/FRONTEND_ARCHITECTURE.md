# Frontend Architecture

CTFZone ships two deliberately separate web surfaces:

- the **administration frontend** is a stable, neutral control-plane UI;
- a **player frontend** is selected by an administrator and presents the event
  to participants.

Changing the player frontend must not change the administration or first-boot
experience. Participants and administrators share the selected player
frontend's `/login` page. Both surfaces are served by the Python BFF; neither
talks directly to PostgreSQL or the private Rust API.

## Filesystem layout

```text
backend/ctfzone_web/frontends/
├── admin/
│   ├── templates/
│   └── static/
├── player/
│   └── terminal/
│       ├── manifest.json
│       ├── templates/
│       └── static/
└── shared/
    └── static/
```

`terminal` is the bundled player frontend. Additional player frontends are
siblings of that directory. Administration templates and assets never resolve
through the player selection.

The shared directory is limited to presentation-independent browser protocol
code, such as the constrained BFF client and direct object-storage upload
helper. Player-specific layout, styling, and behavior stay within the selected
player directory.

## Selection and safety

PostgreSQL stores the selected frontend in the `player_frontend` configuration
key. The Rust API treats its value as an opaque, bounded slug and includes it in
the existing bootstrap response. It does not know which frontend packages are
installed.

At process startup, Python discovers the bundled manifests and constructs an
immutable registry of identifiers and fixed template/static roots. A database
value is resolved only through that registry; it is never concatenated into a
filesystem path. If the configured frontend is absent, Python safely falls back
to `terminal` and the administration screen reports the configured and effective
values. Startup also verifies the fixed administration/shared contract and every
template and declared entry asset of each player package; incomplete packages
are never offered for selection.

The browser receives namespaced assets:

```text
/assets/admin/...
/assets/player/<frontend-id>/...
/assets/shared/...
```

Unknown frontend identifiers and paths outside a registered static root return
404.

## Manifest contract

Each player frontend has a `manifest.json` similar to:

```json
{
  "id": "terminal",
  "name": "Terminal",
  "description": "Compact three-pane competition interface",
  "version": "1.0.0",
  "assets": [
    "css/player.css",
    "js/app.js",
    "js/challenges.js",
    "js/scoreboard.js"
  ]
}
```

The `id` must match the directory name and use lowercase ASCII letters,
numbers, hyphens, or underscores. A frontend package is trusted application
code, not an untrusted archive: adding one requires a reviewed source change,
an image rebuild, and a backend restart.

`assets` lists every theme entry asset referenced by its templates or modules.
The backend validates those paths and files at startup, so an incomplete theme
cannot appear as selectable and then fail with missing CSS or JavaScript.

## First boot and branding

`GET /` consults bootstrap state. A fresh installation is sent to `/setup`,
which is rendered by the neutral administration frontend. Setup records the
event name, selected player frontend, and first administrator in one database
transaction, then opens `/admin`.

The configured `ctf_name` is the visible event name in the top-left corner of
both surfaces. `CTFZone` remains the platform/product name, not a hard-coded
replacement for an organizer's event identity.

## Adding another player frontend

1. Add `frontends/player/<id>/manifest.json`.
2. Provide the required templates and theme-local assets under that directory.
3. Keep BFF/API/storage calls on the existing shared browser contract.
4. Add contract, responsive, accessibility, and browser-render tests.
5. Rebuild/restart the backend, then select the frontend in **Administration →
   Configuration**.

Selection takes effect on the next page request. Asset URLs contain the
frontend identifier, so cached files from different frontends cannot be mixed.

### Player template contract

Every installed player frontend must provide these templates:

```text
base.html
login.html
register.html
confirm.html
challenges.html
scoreboard.html
team.html
profile.html
rules.html
partials/challenge_panel.html
```

Player templates receive three frontend-specific helpers/values:

| Name | Contract |
| --- | --- |
| `player_template(name)` | Returns the safely prefixed name for an `extends` or `include`. |
| `player_asset(name)` | Returns the namespaced URL of an asset in the active frontend. |
| `player_frontend_manifest` | Contains the active frontend's public `id`, `name`, `description`, and `version`. |

`profile.html` owns email verification for the signed-in account. When the
displayed user is the current user, it must show that account's verification
state and provide a same-origin BFF action that forwards to the private
`POST /api/v1/users/me/verification-email` endpoint. The action never accepts a
user ID or email address. This applies equally to participant and administrator
accounts; verification is not an administration-user-editor operation.

`base.html` must expose `player_frontend_manifest.id` on the rendered document
as `data-player-frontend`. Challenge UI code must send that identifier as the
`frontend` query parameter when requesting
`/bff/fragments/challenges/<challenge-id>`. This makes the fragment use the
same frontend as the already-rendered page even if an administrator changes
the configured frontend while another browser tab remains open.

`confirm.html` must support the fragment-token contract. Verification links use
`/confirm#<token>` so the raw bearer token is not sent in an HTTP URL or access
log. Theme JavaScript must remove the fragment from browser history, then submit
the token through the same-origin confirmation form. The bundled `terminal`
frontend declares `js/confirm.js` for this purpose.
