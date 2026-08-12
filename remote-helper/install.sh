#!/bin/sh
set -eu

script_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
helper_source=${1:-$script_directory/ctfzone-runtime-helper}
runtime_user=${CTFZONE_RUNTIME_USER:-ctfzone_runtime}

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root" >&2
    exit 1
fi

if ! id "$runtime_user" >/dev/null 2>&1; then
    useradd --create-home --shell /bin/bash "$runtime_user"
fi

install -d -m 0755 /usr/local/libexec /etc/ctfzone
install -d -o "$runtime_user" -g "$runtime_user" -m 0700 /var/lib/ctfzone-runtime
install -o root -g root -m 0755 "$helper_source" /usr/local/libexec/ctfzone-runtime-helper

if [ ! -f /etc/ctfzone/runtime-helper.env ]; then
    install -o root -g "$runtime_user" -m 0640 "$script_directory/runtime-helper.env.example" /etc/ctfzone/runtime-helper.env
fi

loginctl enable-linger "$runtime_user"
runtime_uid=$(id -u "$runtime_user")
runtime_group=$(id -gn "$runtime_user")
runtime_home=$(getent passwd "$runtime_user" | cut -d: -f6)
if [ -z "$runtime_home" ]; then
    echo "Unable to determine the runtime user's home directory" >&2
    exit 1
fi

service_file=$(mktemp)
trap 'rm -f "$service_file"' EXIT HUP INT TERM
sed \
    -e "s|@RUNTIME_USER@|$runtime_user|g" \
    -e "s|@RUNTIME_GROUP@|$runtime_group|g" \
    -e "s|@RUNTIME_HOME@|$runtime_home|g" \
    -e "s|@RUNTIME_UID@|$runtime_uid|g" \
    "$script_directory/ctfzone-runtime-sweep.service.in" >"$service_file"
install -o root -g root -m 0644 "$service_file" /etc/systemd/system/ctfzone-runtime-sweep.service
install -o root -g root -m 0644 \
    "$script_directory/ctfzone-runtime-sweep.timer" \
    /etc/systemd/system/ctfzone-runtime-sweep.timer
systemctl daemon-reload
systemctl enable --now ctfzone-runtime-sweep.timer

echo "Installed. Add the controller public key to $runtime_home/.ssh/authorized_keys using the forced-command example in README.md."
