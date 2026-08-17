#!/bin/sh
set -eu

repository_directory=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$repository_directory"

if [ ! -f "$repository_directory/.env" ]; then
    echo "error: $repository_directory/.env does not exist" >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    echo "error: Docker with the Compose plugin is required" >&2
    exit 1
fi

docker compose \
    --project-name ctfzone \
    --project-directory "$repository_directory" \
    --env-file "$repository_directory/.env" \
    -f "$repository_directory/compose.yml" \
    down --remove-orphans

echo "Production containers are stopped. All named data volumes were preserved."
