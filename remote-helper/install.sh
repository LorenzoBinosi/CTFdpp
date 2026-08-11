#!/bin/sh
set -eu

helper_source=${1:-./ctfzone-runtime-helper}
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
    install -o root -g "$runtime_user" -m 0640 ./runtime-helper.env.example /etc/ctfzone/runtime-helper.env
fi

loginctl enable-linger "$runtime_user"
echo "Installed. Add the controller public key to /home/$runtime_user/.ssh/authorized_keys using the forced-command example in README.md."
