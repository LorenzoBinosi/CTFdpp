CREATE SCHEMA IF NOT EXISTS ctfzone;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;

DO $$
BEGIN
    EXECUTE format(
        'ALTER ROLE %I SET search_path TO ctfzone, public',
        current_user
    );
END
$$;

SET search_path TO ctfzone, public;

CREATE TABLE IF NOT EXISTS ctfzone.release_metadata (
    key text PRIMARY KEY,
    value text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO ctfzone.release_metadata (key, value)
VALUES
    ('product', 'CTFZone'),
    ('schema_version', '1.0.0')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

COMMENT ON SCHEMA ctfzone IS
    'Native CTFZone schema. Version 1.0.0 starts from a fresh PostgreSQL database.';
