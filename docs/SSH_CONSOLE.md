# Browser SSH console

The administration **System → SSH connections** page provides an interactive
terminal for an existing SSH account. It does not schedule, create, stop, or
remove challenge containers.

## Trust and privilege model

The terminal is a real login shell. It has exactly the permissions of the Unix
account registered for the host; it is not inherently read-only. Use a
dedicated, non-root account with only the permissions administrators should
have through the portal. Do not register `root`, `toor`, a sudo-capable account,
or an account with access to a container-engine socket.

CTFZone generates one Ed25519 client key per SSH host. The private half belongs
only to the isolated SSH gateway volume. PostgreSQL, the Rust API, Python, and
the browser receive only the public half and its fingerprint. Install the exact
`restrict,pty ...` line displayed by the page in the existing account's
`authorized_keys` file. OpenSSH's `restrict` option disables agent, TCP, and X11
forwarding, PTY allocation, and SSH user startup files; the following `pty`
option re-enables only PTY allocation so an interactive shell can work. The
gateway itself never
offers port forwarding, file transfer, agent forwarding, or an arbitrary
one-shot command API.

An SSH client key proves CTFZone's identity to the remote host; it does not
prove the remote host's identity to CTFZone. Before **Connect** becomes
available, request a host-key probe, compare the displayed SHA-256 fingerprint
with the host's SSH key through a separate trusted channel, and explicitly pin
it. A changed host key fails closed and must be reviewed again. First-use trust
is never automatic.

## Connection path

```text
browser -- HTTPS --> Caddy --> Python BFF --> Rust API --> PostgreSQL
browser -- WSS ----> Caddy --> SSH gateway -- TCP/SSH --> registered host
                                      |
                                      +--> private Rust API (tickets/audit)
```

The browser owns only terminal presentation, keyboard/paste input, and resize
events. Browsers cannot open arbitrary TCP SSH connections, and sending a
private key to JavaScript would make it extractable. The small Rust SSH gateway
therefore performs the SSH handshake and streams a PTY over a same-origin
WebSocket. It has no PostgreSQL, object-storage, or challenge-controller
credentials.

For each connection the Rust API issues a random 30-second, one-use ticket
bound to the current administrator session and host. Only a SHA-256 digest is
stored. The browser sends the ticket in the first WebSocket frame, never in a
URL. The gateway atomically consumes it through a separately authenticated
private API route, pins the approved host key, requests a PTY shell, and reports
only session timing and byte counts. Terminal input, output, commands, and
environment data are not logged or stored.

Sessions have bounded input, output buffering, dimensions, idle time, total
duration, and per-host/per-administrator concurrency. Deleting or disabling a
host revokes unconsumed tickets and causes active sessions to close. Removing a
host from CTFZone cannot edit the remote filesystem; remove its public-key line
from `authorized_keys` as a separate revocation step.

## Control-plane polling and heartbeats

Key generation and deletion are durable API jobs, but delivery is currently
poll-based: the gateway asks the private API for one job at a time. An empty
queue is checked again after three seconds; an API error backs off for five
seconds. PostgreSQL notifications do not push work directly to the gateway, and
the administration page does not continuously poll for completion, so refresh
the page if a newly registered host still shows a pending key.

While a terminal is open, the gateway reports byte counts and revalidates the
administrator session, host revision, enabled state, and pinned host key with
the API every 15 seconds by default. Logout, role changes, host edits, and host
deletion therefore close the SSH session on the next successful heartbeat;
after two consecutive heartbeat failures the gateway closes it fail-closed.
The API does not run a separate periodic SSH-session sweeper. If a gateway dies
without sending its close report, a later terminal-ticket consume for that host
marks connecting rows older than 30 seconds and active rows without a heartbeat
for 45 seconds as closed.

## Network policy

`SSH_ALLOWED_CIDRS` and `SSH_ALLOWED_PORTS` define where the gateway may
connect. Configure the narrowest operator networks possible. Even when a broad
public CIDR is configured, the gateway rejects loopback, unspecified,
link-local, multicast, cloud-metadata, Docker, and CTFZone control-plane
destinations. DNS is resolved for each attempt and every returned address must
pass the policy. Apply an equivalent outbound firewall policy in production;
application validation is not a substitute for network enforcement.

## Backups and replicas

Back up PostgreSQL and the `ssh_gateway_identities` volume as one encrypted,
coordinated set. Losing the volume does not disclose a credential, but every
affected host must receive a newly generated public key. Do not use
`docker compose down -v` on a deployment because it deletes this volume.

Version 1 supports one active SSH-gateway identity worker. A replacement must
mount the same durable identity volume and validate it before processing jobs.
