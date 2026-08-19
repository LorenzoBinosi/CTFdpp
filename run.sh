#!/bin/sh
set -eu

repository_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$repository_directory"

if [ ! -f "$repository_directory/.env" ]; then
    echo "error: $repository_directory/.env does not exist; copy .env.example and replace every example secret" >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    echo "error: Docker with the Compose plugin is required" >&2
    exit 1
fi

start_timeout=${CTFZONE_START_TIMEOUT_SECONDS:-300}
case "$start_timeout" in
    ''|*[!0-9]*)
        echo "error: CTFZONE_START_TIMEOUT_SECONDS must be a positive integer" >&2
        exit 1
        ;;
esac
if [ "$start_timeout" -eq 0 ]; then
    echo "error: CTFZONE_START_TIMEOUT_SECONDS must be greater than zero" >&2
    exit 1
fi

compose() {
    docker compose \
        --project-name ctfzone \
        --project-directory "$repository_directory" \
        --env-file "$repository_directory/.env" \
        -f "$repository_directory/compose.yml" \
        "$@"
}

if docker ps --quiet --filter label=com.docker.compose.project=ctfzone-local | grep -q .; then
    echo "error: the local project 'ctfzone-local' is running and owns the same host ports" >&2
    echo "stop it with ./stop-local.sh before starting the production project" >&2
    exit 1
fi

echo "Validating the production Compose configuration..."
compose config --quiet

echo "Pulling external images and rebuilding every application image without cache..."
compose pull --policy always --ignore-buildable
compose build --pull --no-cache

echo "Resetting the pre-release production project, including every named volume..."
echo "WARNING: this deletes PostgreSQL data, stored objects, journals, certificates, and SSH identities."
compose down --volumes --remove-orphans

echo "Starting fresh production containers..."
compose up \
    --detach \
    --force-recreate \
    --renew-anon-volumes \
    --remove-orphans \
    --wait \
    --wait-timeout "$start_timeout"

compose ps
echo "CTFZone production containers are ready at the CADDY_SITE_ADDRESS configured in .env."
echo "Every future ./run.sh invocation recreates the database and all other named volumes from zero."
