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
        --project-name ctfzone-local \
        --project-directory "$repository_directory" \
        --env-file "$repository_directory/.env" \
        -f "$repository_directory/compose.yml" \
        -f "$repository_directory/compose.local.yml" \
        "$@"
}

if docker ps --quiet --filter label=com.docker.compose.project=ctfzone | grep -q .; then
    echo "error: the production project 'ctfzone' is running and owns the same host ports" >&2
    echo "stop it with ./stop.sh before starting the isolated local project" >&2
    exit 1
fi

echo "Validating the local Compose configuration..."
compose config --quiet

echo "Pulling external images and rebuilding every application image without cache..."
compose pull --policy always --ignore-buildable
compose build --pull --no-cache

echo "Resetting the isolated local project, including all ctfzone-local volumes..."
compose down --volumes --remove-orphans

echo "Starting fresh local containers..."
compose up \
    --detach \
    --force-recreate \
    --renew-anon-volumes \
    --remove-orphans \
    --wait \
    --wait-timeout "$start_timeout"

compose ps
echo "Local CTFZone is ready at http://localhost"
echo "Every future ./run-local.sh invocation resets the isolated local database, objects, journals, and SSH identities."
