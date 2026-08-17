-- Dedicated browser-SSH host inventory and gateway work queues.

CREATE TABLE IF NOT EXISTS ctfzone.ssh_hosts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- In the first-party enrollment flow the supplied name is the exact
    -- existing remote Unix account. Keep both columns explicit so target
    -- snapshots and gateway payloads remain unambiguous.
    name text NOT NULL,
    hostname text NOT NULL,
    ssh_port integer NOT NULL DEFAULT 22 CHECK (ssh_port BETWEEN 1 AND 65535),
    ssh_user text NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    identity_state text NOT NULL DEFAULT 'pending'
        CHECK (identity_state IN ('pending', 'ready', 'failed')),
    ssh_public_key text,
    ssh_key_fingerprint text,
    key_generated_at timestamptz,
    identity_error_code text,
    trusted_host_public_key text,
    trusted_host_key_fingerprint text,
    host_key_trusted_at timestamptz,
    -- Historical attribution deliberately has no user foreign key: deleting
    -- an administrator must not erase or invalidate an established trust pin.
    host_key_trusted_by_user_id integer,
    authorized_key_cleanup_required boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by_user_id integer REFERENCES ctfzone.users(id) ON DELETE SET NULL,
    updated_by_user_id integer REFERENCES ctfzone.users(id) ON DELETE SET NULL,
    deleted_by_user_id integer REFERENCES ctfzone.users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    CONSTRAINT ssh_hosts_existing_user_check CHECK (
        name = ssh_user
        AND ssh_user ~ '^[a-z_][a-z0-9_-]{0,31}$'
        AND ssh_user NOT IN ('root', 'toor')
    ),
    CONSTRAINT ssh_hosts_hostname_check CHECK (
        length(hostname) BETWEEN 1 AND 253
        -- Values are resolved as data before OpenSSH receives only an IP, so
        -- underscores, trailing dots, and doubled dots are safe to preserve.
        AND hostname ~ '^[A-Za-z0-9._:-]+$'
        AND hostname !~ '^-'
    ),
    CONSTRAINT ssh_hosts_identity_error_code_check CHECK (
        identity_error_code IS NULL
        OR identity_error_code ~ '^[a-z0-9_.-]{1,64}$'
    ),
    CONSTRAINT ssh_hosts_identity_metadata_check CHECK (
        (
            identity_state = 'ready'
            AND ssh_public_key IS NOT NULL
            AND ssh_key_fingerprint IS NOT NULL
            AND key_generated_at IS NOT NULL
            AND identity_error_code IS NULL
        )
        OR (
            identity_state = 'pending'
            AND ssh_public_key IS NULL
            AND ssh_key_fingerprint IS NULL
            AND key_generated_at IS NULL
            AND identity_error_code IS NULL
        )
        OR (
            identity_state = 'failed'
            AND ssh_public_key IS NULL
            AND ssh_key_fingerprint IS NULL
            AND key_generated_at IS NULL
            AND identity_error_code IS NOT NULL
        )
    ),
    CONSTRAINT ssh_hosts_trusted_host_key_check CHECK (
        (trusted_host_public_key IS NULL) = (trusted_host_key_fingerprint IS NULL)
        AND (trusted_host_public_key IS NULL) = (host_key_trusted_at IS NULL)
        AND (trusted_host_public_key IS NULL) = (host_key_trusted_by_user_id IS NULL)
    ),
    CONSTRAINT ssh_hosts_enabled_check CHECK (
        NOT enabled
        OR (
            deleted_at IS NULL
            AND identity_state = 'ready'
            AND trusted_host_public_key IS NOT NULL
            AND trusted_host_key_fingerprint IS NOT NULL
        )
    ),
    CONSTRAINT ssh_hosts_deleted_check CHECK (deleted_at IS NULL OR NOT enabled)
);

CREATE UNIQUE INDEX IF NOT EXISTS ssh_hosts_active_target_key
    ON ctfzone.ssh_hosts (lower(hostname), ssh_port, ssh_user)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ssh_hosts_visible_order
    ON ctfzone.ssh_hosts (lower(name), id)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS ctfzone.ssh_host_events (
    sequence bigserial PRIMARY KEY,
    event_id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    ssh_host_id uuid NOT NULL,
    event_type text NOT NULL,
    source text NOT NULL CHECK (source IN ('api', 'gateway')),
    actor_user_id integer,
    host_revision bigint NOT NULL CHECK (host_revision > 0),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(payload) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ssh_host_events_host_sequence
    ON ctfzone.ssh_host_events (ssh_host_id, sequence DESC);
CREATE INDEX IF NOT EXISTS ssh_host_events_created
    ON ctfzone.ssh_host_events (created_at DESC, sequence DESC);

CREATE OR REPLACE FUNCTION ctfzone.reject_ssh_host_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23000',
        MESSAGE = 'ssh_host_events is append-only';
END
$$;

DROP TRIGGER IF EXISTS ssh_host_events_append_only ON ctfzone.ssh_host_events;
CREATE TRIGGER ssh_host_events_append_only
BEFORE UPDATE OR DELETE ON ctfzone.ssh_host_events
FOR EACH ROW EXECUTE FUNCTION ctfzone.reject_ssh_host_event_mutation();

CREATE TABLE IF NOT EXISTS ctfzone.ssh_host_identity_operations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ssh_host_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('generate', 'delete')),
    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'claimed', 'completed', 'failed', 'cancelled')),
    host_snapshot jsonb NOT NULL CHECK (jsonb_typeof(host_snapshot) = 'object'),
    available_at timestamptz NOT NULL DEFAULT now(),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    claimed_at timestamptz,
    claim_expires_at timestamptz,
    claim_token uuid,
    claimed_by_gateway text,
    completed_at timestamptz,
    last_error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ssh_host_identity_operations_claim_check CHECK (
        (
            state = 'claimed'
            AND claimed_at IS NOT NULL
            AND claim_expires_at IS NOT NULL
            AND claim_token IS NOT NULL
            AND claimed_by_gateway IS NOT NULL
        )
        OR (
            state <> 'claimed'
            AND claimed_at IS NULL
            AND claim_expires_at IS NULL
            AND claim_token IS NULL
            AND claimed_by_gateway IS NULL
        )
    ),
    CONSTRAINT ssh_host_identity_operations_completion_check CHECK (
        (state = 'completed') = (completed_at IS NOT NULL)
    ),
    CONSTRAINT ssh_host_identity_operations_error_check CHECK (
        state NOT IN ('failed', 'cancelled') OR last_error IS NOT NULL
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS ssh_host_identity_operations_one_open_kind
    ON ctfzone.ssh_host_identity_operations (ssh_host_id, kind)
    WHERE state IN ('pending', 'claimed');
CREATE INDEX IF NOT EXISTS ssh_host_identity_operations_claim_queue
    ON ctfzone.ssh_host_identity_operations (available_at, created_at, id)
    WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS ssh_host_identity_operations_stale_claims
    ON ctfzone.ssh_host_identity_operations (claim_expires_at, id)
    WHERE state = 'claimed';

CREATE TABLE IF NOT EXISTS ctfzone.ssh_host_tickets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ssh_host_id uuid NOT NULL REFERENCES ctfzone.ssh_hosts(id) ON DELETE RESTRICT,
    purpose text NOT NULL CHECK (purpose IN ('probe', 'terminal')),
    token_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(token_sha256) = 32),
    issued_to_user_id integer NOT NULL,
    browser_session_id text NOT NULL,
    request_ip text NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT (now() + INTERVAL '30 seconds'),
    consumed_at timestamptz,
    consumed_by_gateway text,
    revoked_at timestamptz,
    revocation_reason text,
    CONSTRAINT ssh_host_tickets_exact_ttl_check CHECK (
        expires_at = issued_at + INTERVAL '30 seconds'
    ),
    CONSTRAINT ssh_host_tickets_consumption_check CHECK (
        (consumed_at IS NULL) = (consumed_by_gateway IS NULL)
    ),
    CONSTRAINT ssh_host_tickets_revocation_check CHECK (
        (revoked_at IS NULL) = (revocation_reason IS NULL)
    )
);

CREATE INDEX IF NOT EXISTS ssh_host_tickets_issue_rate
    ON ctfzone.ssh_host_tickets (issued_to_user_id, issued_at DESC);
CREATE INDEX IF NOT EXISTS ssh_host_tickets_host_open
    ON ctfzone.ssh_host_tickets (ssh_host_id, expires_at)
    WHERE consumed_at IS NULL AND revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS ctfzone.ssh_host_key_candidates (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ssh_host_id uuid NOT NULL REFERENCES ctfzone.ssh_hosts(id) ON DELETE RESTRICT,
    ticket_id uuid NOT NULL REFERENCES ctfzone.ssh_host_tickets(id) ON DELETE RESTRICT,
    public_key text NOT NULL,
    fingerprint text NOT NULL,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    observation_count integer NOT NULL DEFAULT 1 CHECK (observation_count > 0),
    reported_by_gateway text NOT NULL,
    trusted_at timestamptz,
    -- Preserve the numeric audit fact if the administrator is later removed.
    trusted_by_user_id integer,
    CONSTRAINT ssh_host_key_candidates_trust_check CHECK (
        (trusted_at IS NULL) = (trusted_by_user_id IS NULL)
    ),
    UNIQUE (ssh_host_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS ssh_host_key_candidates_host_seen
    ON ctfzone.ssh_host_key_candidates (ssh_host_id, last_seen_at DESC, id);

CREATE TABLE IF NOT EXISTS ctfzone.ssh_terminal_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    ticket_id uuid NOT NULL UNIQUE REFERENCES ctfzone.ssh_host_tickets(id) ON DELETE RESTRICT,
    ssh_host_id uuid NOT NULL REFERENCES ctfzone.ssh_hosts(id) ON DELETE RESTRICT,
    admin_user_id integer NOT NULL,
    browser_session_id text NOT NULL,
    gateway_instance_id text NOT NULL,
    host_revision bigint NOT NULL CHECK (host_revision > 0),
    trusted_host_key_fingerprint text NOT NULL,
    state text NOT NULL DEFAULT 'connecting'
        CHECK (state IN ('connecting', 'active', 'closed')),
    connected_at timestamptz,
    last_heartbeat_at timestamptz,
    closed_at timestamptz,
    close_reason text,
    exit_code integer CHECK (exit_code BETWEEN -1 AND 255),
    bytes_from_browser bigint NOT NULL DEFAULT 0 CHECK (bytes_from_browser >= 0),
    bytes_to_browser bigint NOT NULL DEFAULT 0 CHECK (bytes_to_browser >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ssh_terminal_sessions_lifecycle_check CHECK (
        (
            state = 'connecting'
            AND connected_at IS NULL
            AND closed_at IS NULL
            AND close_reason IS NULL
        )
        OR (
            state = 'active'
            AND connected_at IS NOT NULL
            AND closed_at IS NULL
            AND close_reason IS NULL
        )
        OR (
            state = 'closed'
            AND closed_at IS NOT NULL
            AND close_reason IS NOT NULL
        )
    )
);

CREATE INDEX IF NOT EXISTS ssh_terminal_sessions_host_state
    ON ctfzone.ssh_terminal_sessions (ssh_host_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS ssh_terminal_sessions_stale
    ON ctfzone.ssh_terminal_sessions (last_heartbeat_at NULLS FIRST, created_at)
    WHERE state IN ('connecting', 'active');

COMMENT ON TABLE ctfzone.ssh_hosts IS
    'Interactive SSH targets and public trust metadata; private identities are gateway-owned and never stored in PostgreSQL.';
COMMENT ON TABLE ctfzone.ssh_host_events IS
    'Append-only interactive SSH host and session audit metadata; terminal input and output are never recorded.';
COMMENT ON TABLE ctfzone.ssh_host_identity_operations IS
    'Durable generate/delete work queue for gateway-owned interactive SSH identities.';
COMMENT ON TABLE ctfzone.ssh_host_tickets IS
    'Thirty-second, single-use probe/terminal grants stored only as SHA-256 digests.';
