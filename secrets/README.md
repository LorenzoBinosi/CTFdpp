# Controller SSH material

Production deployments using `CONTROLLER_REMOTE_DRIVER=ssh` must place these
two files in this directory:

- `known_hosts`: pinned OpenSSH host keys for every configured runtime host.
- `id_ed25519`: the controller's unencrypted, dedicated private key, readable
  by the controller process and no other untrusted account.

The controller runs as numeric UID `10002`. On a native Linux Docker host, bind
mounts preserve numeric ownership and mode bits: a host-owned `0600` key is
therefore usually **not** readable inside the container. Install the files for
the container identity before starting the production driver, for example:

```console
sudo install -o 10002 -m 0600 /secure/source/id_ed25519 ./secrets/id_ed25519
sudo install -o 10002 -m 0644 /secure/source/known_hosts ./secrets/known_hosts
docker compose exec -T controller sh -c \
  'test -r /etc/ctfzone/ssh/id_ed25519 && test -r /etc/ctfzone/ssh/known_hosts'
```

Docker Desktop and user-namespace-remapped installations may map ownership
differently; the in-container readability check above is authoritative.

`GET /readyz` proves that PostgreSQL and the signed object-storage data plane are
connected and that initial runtime and storage reconciliation completed. A
dormant controller intentionally remains ready, so readiness does not open an
SSH connection and does not validate an unused key.
Before enabling a managed challenge, verify file readability and perform an SSH
call to the restricted helper using the same identity and pinned host entry.

The public key on each runtime host must be restricted to the fixed helper as
described in [`../remote-helper/README.md`](../remote-helper/README.md). Never
commit either production file.
