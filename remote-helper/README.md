# CTFZone remote runtime helper

This helper is the only command the controller may execute on a challenge host. It accepts a bounded JSON request on stdin and supports four idempotent operations: `ensure-instance`, `inspect-instance`, `update-deadline`, and `stop-instance`.

It runs challenge images with a dedicated rootless Podman account, drops all Linux capabilities, enables `no-new-privileges`, applies configured CPU/memory/PID/storage limits, uses a private challenge network, and assigns a random host port. Images must be pinned as `repository@sha256:<64 hex characters>`.

Every launch also creates a host-side transient systemd timer for the absolute expiry time. The timer removes the container without involving CTFZone. Extending an instance replaces the timer and increments a generation stored in a fsynced local state file; a stale timer cannot kill a newer generation.

## Install

On a systemd host with rootless Podman and Python 3:

```sh
sudo ./install.sh
sudoedit /etc/ctfzone/runtime-helper.env
```

Install the controller public key for `ctfzone_runtime`. Restrict it to the helper and disable every SSH forwarding feature:

```text
restrict,command="/usr/local/libexec/ctfzone-runtime-helper ssh-dispatch" ssh-ed25519 AAAA... ctfzone-controller
```

Add the host key to the controller's mounted `ssh_known_hosts`, configure the private identity path on the corresponding `remote_servers` row, and keep the SSH account out of privileged groups. The controller never receives a Docker/Podman socket.

Use one routable hostname per runtime host in `CTFZONE_PUBLIC_HOSTNAME`. Caddy serves the portal and API; challenge ports are published by the runtime host itself.
