# Jeopardy challenge authoring

Status: Implemented 1.0.0 baseline
Last updated: 2026-08-19

This page is the operator contract for **Administration -> Challenges -> New
challenge**. The 1.0 wizard creates Jeopardy challenges only. **Attack / Defense
(A/D), Speed run, and King of the hill are visible but disabled future
formats**; they cannot be selected or created through this contract.

## Before authoring

Every challenge must reference a category that already exists. Manage the
catalog under **Competition -> Categories**. A category always has a name and
may use one of the semantic logo keys `web`, `pwn`, `crypto`, `rev`, `misc`,
`coding`, or `forensics`. Each player frontend supplies its own visual design
for those meanings, and the administrator chooses the built-in logo color.
Choose **Name only** when the written category name should be the compact
marker; this mode does not require or validate an image file.

Administrators may instead attach a custom exact 128 by 128 pixel PNG or a
square SVG, with a 256 KiB maximum. SVG is parsed and admitted only from a small
static drawing allowlist; scripts, event handlers, CSS, links, external
references, DTD/entities, text, metadata, animation, and unsupported elements
or attributes are rejected before the object becomes public. Challenge
authoring also offers **Create category** as a name-only shortcut; choose a
built-in logo/color or upload a custom one later from the Categories page.

Selecting a category stores its stable ID on the challenge. The challenge
therefore inherits later name, built-in-logo, and custom-logo changes
automatically. A category cannot be deleted while any challenge uses it;
reassign those challenges first. Filters and administrator selectors always
show the category name even when its compact marker is a logo.

For a private challenge, provision at least one eligible runtime host and its
restricted remote helper before expecting launches to succeed. See the
[private-instance controller](INSTANCE_CONTROLLER_ARCHITECTURE.md) and
[remote runtime helper](../remote-helper/README.md). For challenge files,
configure the separate object-storage origin; otherwise file selection is
disabled.

## The five steps

### 1. Challenge type

Select **Jeopardy**. It represents an independent challenge solved by submitting
a flag. A/D, Speed run, and King of the hill remain disabled placeholders for
future development.

### 2. Availability

Choose one exposure model:

| Choice | Participant access | Controller involvement |
| --- | --- | --- |
| Public challenge | Participants use shared files, page content, or an external service. Optional connection information is added in the final step. | None. CTFZone does not provision a service. |
| Private instance | A participant activates a dedicated instance and receives its resulting endpoint. | The controller creates, observes, expires, and removes the container through the restricted remote helper. |

A public challenge has no managed-runtime profile. An SSH host registered for
the browser console is not, by itself, a private challenge runtime host.

### 3. Details, scoring, and files

Supply the participant-facing name, select a pre-created category, and add
optional **Author(s) / attribution**. Attribution supports Markdown, so it can
contain several author names, team names, and source links; it appears as the
challenge byline.

The description supports Markdown and a sanitized subset of inline and block
HTML. Active content, unsafe URLs, event handlers, and unsupported tags or
attributes are escaped instead of executed. Connection commands do not need to
be forced into the description: the final step provides a separate optional
connection field.

Choose scoring, visibility, maximum attempts, and board position. Fixed scoring
uses one non-negative value. Dynamic scoring uses a linear or logarithmic curve
with `initial >= minimum >= 0` and positive decay; its scoring type is fixed
after creation. A blank maximum-attempt value means unlimited attempts. Files
selected here upload directly to object storage after the challenge definition
is saved.

### 4. Flag validation

Public and private challenges support these shared validators:

- **Exact match** compares a literal flag. The case-sensitive option controls
  whether letter case must match.
- **Regular expression** is compiled by the Rust API and anchored to the whole
  submission. The wizard's regex is case-sensitive. Random tokens and leet
  personalization do not apply to regex flags.

A private exact flag becomes a **generated** flag automatically when its
template contains the random-token marker, leet variation is enabled, or both.
Without either option it remains one shared exact flag. Generated flags are
available only to private, controller-managed challenges and are case-sensitive
in the 1.0 wizard.

#### Random-token marker

The only supported marker is the exact, uppercase string
`{{RANDOM_TOKEN}}`. It may appear zero or one time. At a participant's first
accepted instance allocation, CTFZone replaces it with a canonical 36-character
UUIDv4, for example:

```text
flag{account:{{RANDOM_TOKEN}}}
flag{account:bb8a8d4e-b8cd-4dbc-b9f6-a80577be5d2c}
```

Similar spellings, additional brace placeholders, and a second marker are
rejected. The rendered flag must be at most 512 UTF-8 bytes; remember that UUID
replacement makes this marker 20 bytes longer.

#### Leet variation

Leet variation changes a non-empty subset of eligible letters with this fixed
map (uppercase letters use the same digit):

| Letter | Replacement |
| --- | --- |
| `a` | `4` |
| `e` | `3` |
| `i` | `1` |
| `o` | `0` |
| `s` | `5` |
| `t` | `7` |

For a wrapped value such as `flag{this_is_a_flag}`, only the text between the
first opening and last closing brace that are not part of the random-token
marker is eligible. The `flag` prefix and the marker itself are preserved. If
there is no such outer wrapper, the whole literal is eligible, excluding the
marker.

A template must have between 1 and 62 eligible positions when leet variation
is enabled. A leet-only template has `2^n - 1` unique assignments for `n`
eligible positions: the unchanged original is excluded, and activation is
refused after that finite space is exhausted. Combining leet variation with a
UUID marker keeps the leet effect while the UUID supplies per-participant
uniqueness.

#### Assignment stability and sharing evidence

The first accepted private-instance allocation persists the participant's UUID
and leet mask. Later activations render the same flag; CTFZone does not silently
rotate it. Assignments are unique within the challenge, and a flag-definition
revision change cannot silently regenerate an existing assignment.

**Accept another participant's generated flag** controls scoring, not evidence
collection. Whenever a submitted generated flag belongs to a different user,
CTFZone records durable provenance containing the submission, challenge, flag,
submitting user, source user, team snapshot, protected match tag, timestamp, and
whether policy accepted it. With the option disabled the submission is rejected
but the sharing event is still recorded; with it enabled the submission may
solve the challenge and the same evidence remains available for review.

### 5. Connection

**Connection information** is optional free-form text, not a required challenge
URL. It can be an HTTP(S) link, hostname, command such as `nc host 31337` or
`ssh user@host`, or short access instructions. Leave it blank when the
description already contains everything participants need. Public challenges
show the same value to everyone. Private challenges receive their generated
endpoint on activation, so this field should contain only additional shared
instructions.

For a private challenge, define the managed-runtime profile in this final step:

- an immutable image reference of the form
  `repository@sha256:<64 lowercase hexadecimal characters>`;
- protocol (`tcp`, `http`, or `https`) and container port (`1` through `65535`);
- default lifetime (up to 24 hours) and maximum lifetime (up to 7 days), with
  the maximum not shorter than the default;
- whether extensions are allowed and their maximum count;
- an optional remote pool and positive memory, PID, and storage limits;
- an optional finite CPU limit from `0.01` through `256`.

The API stores a revisioned profile, and every instance receives an immutable
deployment snapshot. Editing the challenge later does not rewrite an instance
already in flight.

The final definition save is atomic: the core challenge, category reference,
initial flag, optional private-runtime profile, and any requested global-gate
enablement either commit together or do not commit. File transfer is the
deliberate post-save exception described below.

## Private drafts and the global launch gate

The `private_challenges` setting is a global launch gate, not a per-challenge
checkbox. When it is off, an operator may save a fully configured private
challenge as a **Hidden draft** without changing the gate. Creating or updating
that challenge to **Visible** or **Locked** requires both its managed runtime to
be enabled and the global gate to be enabled.

The wizard and private-challenge edit page offer an explicit gate-enable action
when publishing. Enabling it affects every otherwise eligible private
challenge. Keeping the draft hidden leaves the global policy unchanged.

## File staging and publication

Selected files are not included in the atomic challenge-definition request.
The browser first creates the challenge, then for each file it obtains a scoped
upload authorization, sends bytes directly to object storage, completes the
upload so the API can verify its SHA-256 and promote it from staging, and
finally attaches the ready object to the challenge. The current browser limit
is 64 MiB per file.

If files were selected for a challenge requested as Visible or Locked, the
wizard initially saves it as Hidden. It applies the requested state only after
every selected file is ready and attached. If upload or final publication
fails, the challenge remains hidden for an operator to inspect and retry;
participants never see the partially staged definition.

## Generated-flag secret handling

Only generated private flags are handed to a workload. At launch the controller
sends the assigned value to the restricted helper, which exposes it to the new
container only as `CTFZONE_FLAG`. The value itself is not placed in the
container-engine command line. Challenge entrypoints should read that variable
and must not print it to application logs.

The raw value is redacted from controller operation-journal payloads and API
lifecycle events. The helper's state file retains only a SHA-256 fingerprint so
an idempotent retry can detect mismatched secret material without persisting the
flag there; helper command failures also redact the value. PostgreSQL remains
the authoritative, secret-bearing control plane for assignments and immutable
deployment snapshots, so protect and encrypt its backups accordingly.
