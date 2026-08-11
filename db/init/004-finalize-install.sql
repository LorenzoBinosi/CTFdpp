-- This marker is deliberately written by the last fresh-install script.
-- Readiness must never infer a complete database from tables that may have
-- been committed before an interrupted initialization finished.
BEGIN;

DO $$
BEGIN
    IF to_regclass('ctfzone.users') IS NULL
        OR to_regclass('ctfzone.challenges') IS NULL
        OR to_regclass('ctfzone.runtime_settings') IS NULL
        OR to_regclass('ctfzone.challenge_runtime_configs') IS NULL
        OR to_regclass('ctfzone.remote_servers') IS NULL
        OR to_regclass('ctfzone.runtime_instances') IS NULL
        OR to_regclass('ctfzone.runtime_commands') IS NULL
        OR to_regclass('ctfzone.runtime_instance_events') IS NULL
    THEN
        RAISE EXCEPTION 'CTFZone schema cannot be finalized because required tables are missing';
    END IF;
END
$$;

INSERT INTO ctfzone.release_metadata (key, value)
VALUES ('install_complete', '1.0.0')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

COMMIT;
