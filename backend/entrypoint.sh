#!/bin/sh
set -eu

workers="${WORKERS:-2}"
threads="${THREADS:-4}"
access_log="${ACCESS_LOG:--}"
error_log="${ERROR_LOG:--}"

exec gunicorn 'ctfzone_web:create_app()' \
    --bind '0.0.0.0:8000' \
    --workers "$workers" \
    --threads "$threads" \
    --worker-class gthread \
    --worker-tmp-dir /dev/shm \
    --access-logfile "$access_log" \
    --error-logfile "$error_log" \
    --capture-output
