# CTFZone remote runtime helper

This helper is the only command the controller may execute on a challenge host. It accepts a bounded JSON request on stdin and supports four idempotent operations: `ensure-instance`, `inspect-instance`, `update-deadline`, and `stop-instance`.

It runs challenge images with a dedicated rootless Podman account, drops all Linux capabilities, enables `no-new-privileges`, applies configured CPU/memory/PID/storage limits, creates a separate bridge network for every instance, and assigns a random host port. `CTFZONE_NETWORK` is the network-name prefix (at most 30 characters), not a shared bridge. Images must be pinned as `repository@sha256:<64 hex characters>`.

For personalized private challenges, the controller may supply one optional
`deployment.flag_value`. The helper accepts a non-empty UTF-8 value of at most
512 bytes with no NUL character and exposes it to the new container only as
`CTFZONE_FLAG`. Arbitrary environment maps are rejected. The raw value is not
written to the controller operation journal or the helper state file; helper
state retains only a SHA-256 fingerprint so an idempotent retry cannot silently
reuse a container with different flag material.

Every launch also creates a generation-specific host-side systemd timer for the
absolute expiry time. The timer removes the container without involving
CTFZone. Extending an instance installs the new timer before retiring the old
one and increments a generation stored in a fsynced local state file; a stale
timer cannot kill a newer generation.

Stopping or expiring an instance writes a permanent, fsynced UUID tombstone
before removing the workload. Instance UUIDs are never reused, so a delayed SSH
request from an older controller claim cannot recreate a workload after its
database slot was released.

The helper waits for the container to be running and, when configured, healthy
before reporting it ready. Its default startup wait is 45 seconds. Any explicit
`startup_timeout_seconds` must leave at least five seconds inside the
controller's `REMOTE_OPERATION_TIMEOUT_SECONDS`, or the controller rejects the
launch before contacting the host.

The installer additionally enables a persistent system-level sweep every
minute. It reconstructs missing per-instance timers from trustworthy fsynced
state, retries overdue removals, and removes orphaned per-instance networks. If
state is missing or corrupt, immutable creation labels are not sufficient to
recover a possibly extended deadline or health policy: the sweep fails closed
by tombstoning the UUID and removing the workload. `sweep-instances` is
local-only and is deliberately not accepted by the forced SSH command
dispatcher.

## Install

On a systemd host with rootless Podman and Python 3:

```sh
sudo ./install.sh
sudoedit /etc/ctfzone/runtime-helper.env
systemctl status ctfzone-runtime-sweep.timer
```

Install the controller public key for `ctfzone_runtime`. Restrict it to the helper and disable every SSH forwarding feature:

```text
restrict,command="/usr/local/libexec/ctfzone-runtime-helper ssh-dispatch" ssh-ed25519 AAAA... ctfzone-controller
```

Add the host key to the controller's mounted `known_hosts`, configure the private identity path on the corresponding `remote_servers` row, and keep the SSH account out of privileged groups. The controller never receives a Docker/Podman socket.

After changing the helper or its configuration, verify both layers of expiry:

```sh
sudo -u ctfzone_runtime \
  CTFZONE_HELPER_CONFIG=/etc/ctfzone/runtime-helper.env \
  /usr/local/libexec/ctfzone-runtime-helper sweep-instances
systemctl list-timers ctfzone-runtime-sweep.timer
```

Use one routable hostname per runtime host in `CTFZONE_PUBLIC_HOSTNAME`. Caddy
serves the Python portal boundary; challenge ports are published by the runtime
host itself. The Rust API remains private.
