#!/bin/bash
set -euo pipefail

WORKERS=${WORKERS:-1}
WORKER_CLASS=${WORKER_CLASS:-gevent}
ACCESS_LOG=${ACCESS_LOG:--}
ERROR_LOG=${ERROR_LOG:--}
WORKER_TEMP_DIR=${WORKER_TEMP_DIR:-/dev/shm}
SECRET_KEY=${SECRET_KEY:-}

# Check that a .ctfdpp_secret_key file or SECRET_KEY envvar is set
if [ ! -f .ctfdpp_secret_key ] && [ -z "$SECRET_KEY" ]; then
    if [ $WORKERS -gt 1 ]; then
        echo "[ ERROR ] You are configured to use more than 1 worker."
        echo "[ ERROR ] To do this, you must define the SECRET_KEY environment variable or create a .ctfdpp_secret_key file."
        echo "[ ERROR ] Exiting..."
        exit 1
    fi
fi

# Initialize database. Compose gates this container on the db healthcheck
# (see docker-compose.yml), so the database is already accepting connections.
flask db upgrade

# Start CTFd++
echo "Starting CTFd++"
exec gunicorn 'CTFdpp:create_app()' \
    --bind '0.0.0.0:8000' \
    --workers $WORKERS \
    --worker-tmp-dir "$WORKER_TEMP_DIR" \
    --worker-class "$WORKER_CLASS" \
    --access-logfile "$ACCESS_LOG" \
    --error-logfile "$ERROR_LOG"
