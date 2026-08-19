# Pages and player navigation

The player header is backed by the page catalog in **Administration → Pages**.
Its order and labels are returned with bootstrap data; the Python frontend does
not keep a second navigation list.

## Permanent pages

Every fresh database contains three protected records:

| Page | Endpoint | Editable fields |
| --- | --- | --- |
| Home | `/` | label and HTML content |
| Challenges | `/challenges` | visibility and navigation order |
| Scoreboard | `/scoreboard` | visibility and navigation order |

Home is always public, always occupies the root endpoint, and cannot be moved
or deleted. The event logo in the top-left corner always links to it.
Challenges and Scoreboard keep their endpoint, label, implementation, and
identity. They cannot be deleted or replaced with custom content.

## Custom pages

A custom page has a navigation label, a unique lowercase endpoint, an order,
a visibility policy, and an HTML body. Nested endpoints such as
`guides/beginners` are supported. Application-owned prefixes such as `admin`,
`api`, `assets`, `bff`, `challenges`, `scoreboard`, and account routes are
reserved.

Visibility is explicit:

- **Public**: appears in navigation and is readable without signing in.
- **Private**: appears only after sign-in and redirects unauthenticated readers
  to login.
- **Invisible**: does not appear in player navigation and returns 404 to every
  non-administrator. Administrators can still preview it directly.

Deleting a custom page also queues deletion of objects attached to that page.
Create requests are idempotent, and edits use a record revision so one
administrator cannot silently overwrite another administrator's newer edit.

## HTML safety

Page content is limited to 256 KiB and does not execute JavaScript. The bundled
frontend reconstructs an allowlist of structural tags (`h1`–`h4`, paragraphs,
lists, tables, code, details, and similar text structure). Links retain only a
safe HTTP(S), root-relative, or fragment destination. Scripts, styles, event
handlers, iframes, media, unknown tags, and unsafe URL schemes remain escaped
text.

Pages receive the complete player canvas. Authors can compose responsive
layouts with the allowlisted `row`, `col-md-1` through `col-md-12`,
`offset-md-0` through `offset-md-11`, `text-start`, `text-center`, `text-end`,
`align-items-*`, `page-section`, `display-1`, `lead`, and `page-actions`
classes. Unknown classes are removed, so page HTML cannot borrow privileged
application-shell styles. For example:

```html
<div class="row">
  <div class="col-md-6 offset-md-3">
    <h1 class="text-center">CTFZone</h1>
  </div>
</div>
```

Adding executable behavior requires a reviewed player-frontend source
change and image rebuild, not a database page edit.

Because this is a fresh-schema 1.0 baseline, changing the page table requires a
fresh local database through `./run-local.sh`; there is no migration path for a
pre-release database.
