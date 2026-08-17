-- Applied after the complete portal schema so runtime ownership identifiers
-- can share the same authoritative PostgreSQL namespace.
SET search_path TO ctfzone, public;

CREATE TABLE IF NOT EXISTS ctfzone.runtime_settings (
    key text PRIMARY KEY,
    enabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_user_id integer
);

INSERT INTO ctfzone.runtime_settings (key, enabled, revision)
VALUES ('private_challenges', false, 1)
ON CONFLICT (key) DO NOTHING;

CREATE TABLE IF NOT EXISTS ctfzone.challenge_runtime_configs (
    challenge_id integer PRIMARY KEY
        REFERENCES ctfzone.challenges(id) ON DELETE CASCADE,
    runtime_mode text NOT NULL DEFAULT 'static'
        CHECK (runtime_mode IN ('static', 'managed')),
    enabled boolean NOT NULL DEFAULT false,
    image_digest text,
    protocol text NOT NULL DEFAULT 'tcp'
        CHECK (protocol IN ('tcp', 'http', 'https')),
    container_port integer CHECK (container_port BETWEEN 1 AND 65535),
    default_ttl_seconds integer NOT NULL DEFAULT 1800
        CHECK (default_ttl_seconds BETWEEN 60 AND 86400),
    maximum_ttl_seconds integer NOT NULL DEFAULT 3600
        CHECK (maximum_ttl_seconds BETWEEN default_ttl_seconds AND 604800),
    allow_extension boolean NOT NULL DEFAULT true,
    maximum_extensions integer NOT NULL DEFAULT 2 CHECK (maximum_extensions >= 0),
    cpu_limit text,
    memory_limit_bytes bigint CHECK (memory_limit_bytes > 0),
    pid_limit integer CHECK (pid_limit > 0),
    storage_limit_bytes bigint CHECK (storage_limit_bytes > 0),
    healthcheck jsonb NOT NULL DEFAULT '{}'::jsonb,
    remote_pool text,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by_user_id integer,
    CHECK (
        runtime_mode = 'static'
        OR (
            image_digest IS NOT NULL
            AND image_digest <> ''
            AND container_port IS NOT NULL
        )
    )
);

CREATE TABLE IF NOT EXISTS ctfzone.remote_servers (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL UNIQUE,
    hostname text NOT NULL,
    ssh_port integer NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
    ssh_user text NOT NULL,
    helper_path text NOT NULL DEFAULT '/usr/local/libexec/ctfzone-runtime-helper',
    identity_file text,
    host_key_alias text,
    pool text,
    capacity integer NOT NULL DEFAULT 100 CHECK (capacity > 0),
    enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ctfzone.runtime_instances (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id integer NOT NULL,
    created_by_user_id integer NOT NULL,
    team_id integer,
    challenge_id integer NOT NULL,
    deployment_revision bigint NOT NULL DEFAULT 1,
    private_challenges_revision bigint NOT NULL,
    challenge_runtime_revision bigint NOT NULL,
    deployment_snapshot jsonb NOT NULL,
    active boolean NOT NULL DEFAULT true,
    desired_state text NOT NULL DEFAULT 'running'
        CHECK (desired_state IN ('running', 'stopped')),
    observed_state text NOT NULL DEFAULT 'requested'
        CHECK (observed_state IN (
            'requested', 'starting', 'ready', 'stopping', 'cleanup_pending',
            'terminated', 'expired', 'failed', 'unknown'
        )),
    desired_expires_at timestamptz NOT NULL,
    maximum_expires_at timestamptz NOT NULL,
    observed_expires_at timestamptz,
    expires_at timestamptz NOT NULL,
    -- Runtime hosts are durable audit identities. Disable retired hosts; do
    -- not delete a row while any instance history or cleanup still references it.
    remote_server_id uuid REFERENCES ctfzone.remote_servers(id) ON DELETE RESTRICT,
    remote_container_id text,
    remote_ip inet,
    container_port integer CHECK (container_port BETWEEN 1 AND 65535),
    published_ip inet,
    published_port integer CHECK (published_port BETWEEN 1 AND 65535),
    protocol text CHECK (protocol IN ('tcp', 'http', 'https')),
    public_hostname text,
    endpoint_url text,
    generation bigint NOT NULL DEFAULT 1 CHECK (generation > 0),
    observed_generation bigint NOT NULL DEFAULT 0 CHECK (observed_generation >= 0),
    extension_count integer NOT NULL DEFAULT 0 CHECK (extension_count >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    activated_at timestamptz,
    ready_at timestamptz,
    last_observed_at timestamptz,
    stopped_at timestamptz,
    failure_code text,
    failure_message text,
    CHECK (maximum_expires_at >= desired_expires_at),
    CHECK (expires_at <= maximum_expires_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS runtime_instances_one_active_per_user
    ON ctfzone.runtime_instances (owner_user_id)
    WHERE active;
CREATE INDEX IF NOT EXISTS runtime_instances_active_deadline
    ON ctfzone.runtime_instances (expires_at)
    WHERE active;
CREATE INDEX IF NOT EXISTS runtime_instances_challenge_history
    ON ctfzone.runtime_instances (challenge_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS runtime_instances_owner_history
    ON ctfzone.runtime_instances (owner_user_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS runtime_instances_created_history
    ON ctfzone.runtime_instances (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS runtime_instances_active_remote_server
    ON ctfzone.runtime_instances (remote_server_id)
    WHERE active AND remote_server_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS runtime_instances_active_observation
    ON ctfzone.runtime_instances (last_observed_at NULLS FIRST, created_at, id)
    WHERE active AND remote_server_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS ctfzone.runtime_commands (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id uuid NOT NULL REFERENCES ctfzone.runtime_instances(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('start', 'terminate', 'extend', 'inspect', 'reconcile')),
    generation bigint NOT NULL CHECK (generation > 0),
    setting_revision bigint NOT NULL CHECK (setting_revision > 0),
    challenge_runtime_revision bigint NOT NULL CHECK (challenge_runtime_revision > 0),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'claimed', 'completed', 'failed', 'cancelled')),
    requested_by_user_id integer,
    idempotency_key text,
    available_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    claimed_at timestamptz,
    claim_token uuid,
    completed_at timestamptz,
    last_error text,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    CONSTRAINT runtime_commands_claim_metadata CHECK (
        (status = 'claimed' AND claimed_at IS NOT NULL AND claim_token IS NOT NULL)
        OR (status <> 'claimed' AND claimed_at IS NULL AND claim_token IS NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS runtime_commands_idempotency
    ON ctfzone.runtime_commands (requested_by_user_id, idempotency_key, kind)
    WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS runtime_commands_one_open_kind_generation
    ON ctfzone.runtime_commands (instance_id, kind, generation)
    WHERE status IN ('pending', 'claimed');
CREATE INDEX IF NOT EXISTS runtime_commands_claim_queue
    ON ctfzone.runtime_commands (available_at, created_at)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS runtime_commands_stale_claims
    ON ctfzone.runtime_commands (claimed_at)
    WHERE status = 'claimed';
CREATE INDEX IF NOT EXISTS runtime_commands_failed_cleanup
    ON ctfzone.runtime_commands (instance_id, completed_at DESC)
    WHERE kind = 'terminate' AND status = 'failed';

CREATE TABLE IF NOT EXISTS ctfzone.runtime_instance_events (
    sequence bigserial PRIMARY KEY,
    event_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    instance_id uuid NOT NULL REFERENCES ctfzone.runtime_instances(id) ON DELETE CASCADE,
    event_type text NOT NULL,
    source text NOT NULL CHECK (source IN ('api', 'controller', 'remote')),
    actor_user_id integer,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS runtime_instance_events_instance_sequence
    ON ctfzone.runtime_instance_events (instance_id, sequence);

COMMENT ON TABLE ctfzone.runtime_instances IS
    'Authoritative current state and immutable historical ownership for managed challenge instances.';
COMMENT ON TABLE ctfzone.runtime_commands IS
    'Durable API-to-controller work queue. PostgreSQL notifications are wake-up signals only.';
COMMENT ON TABLE ctfzone.runtime_instance_events IS
    'Append-only managed-instance lifecycle and audit history.';
