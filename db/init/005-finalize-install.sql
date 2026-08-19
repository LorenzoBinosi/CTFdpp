-- This marker is deliberately written by the last fresh-install script.
-- Readiness must never infer a complete database from tables that may have
-- been committed before an interrupted initialization finished.
BEGIN;

-- Email-verification bearer tokens are single-use and short lived. Only their
-- SHA-256 hashes are persisted; the raw token exists solely in the email.
CREATE TABLE IF NOT EXISTS ctfzone.email_verification_tokens (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE,
    user_id integer NOT NULL REFERENCES ctfzone.users(id) ON DELETE CASCADE,
    email character varying(128) NOT NULL,
    requested_by_user_id integer REFERENCES ctfzone.users(id) ON DELETE SET NULL,
    requested_by_ip character varying(46) NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    used_at timestamp with time zone,
    invalidated_at timestamp with time zone,
    CONSTRAINT email_verification_token_hash_check CHECK (octet_length(token_hash) = 32),
    CONSTRAINT email_verification_email_check CHECK (
        length(email) BETWEEN 3 AND 128 AND email !~ '[[:cntrl:]]'
    ),
    CONSTRAINT email_verification_request_ip_check CHECK (
        length(requested_by_ip) BETWEEN 1 AND 46 AND requested_by_ip !~ '[[:cntrl:]]'
    ),
    CONSTRAINT email_verification_expiry_check CHECK (expires_at > created_at),
    CONSTRAINT email_verification_use_time_check CHECK (
        used_at IS NULL OR (used_at >= created_at AND used_at < expires_at)
    ),
    CONSTRAINT email_verification_terminal_state_check CHECK (
        NOT (used_at IS NOT NULL AND invalidated_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS idx_email_verification_user_created
    ON ctfzone.email_verification_tokens (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_verification_ip_created
    ON ctfzone.email_verification_tokens (requested_by_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_verification_created
    ON ctfzone.email_verification_tokens (created_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_email_verification_active_user
    ON ctfzone.email_verification_tokens (user_id)
    WHERE used_at IS NULL AND invalidated_at IS NULL;

-- Competition-mode changes deliberately destroy score ownership, every team
-- identity, and every membership in both directions. Keep the
-- operator-approved snapshot in a durable audit record committed with the
-- destructive reset. The API exposes no mutation route for this history.
CREATE TABLE IF NOT EXISTS ctfzone.user_mode_transitions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_user_id integer REFERENCES ctfzone.users(id) ON DELETE SET NULL,
    source_mode text NOT NULL CHECK (source_mode IN ('users', 'teams')),
    target_mode text NOT NULL CHECK (target_mode IN ('users', 'teams')),
    affected jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT user_mode_transition_changes_mode CHECK (source_mode <> target_mode),
    CONSTRAINT user_mode_transition_affected_object CHECK (jsonb_typeof(affected) = 'object')
);

CREATE INDEX IF NOT EXISTS idx_user_mode_transitions_created
    ON ctfzone.user_mode_transitions (created_at DESC, id DESC);

-- `users.verified` is proof that the current address completed the token flow,
-- not an administrative account flag. Keep the invariant in PostgreSQL too so
-- a future write path cannot silently bypass the mail confirmation endpoint.
CREATE OR REPLACE FUNCTION ctfzone.require_email_verification_proof()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.verified THEN
            RAISE EXCEPTION 'new accounts cannot start with a verified email'
                USING ERRCODE = '23514';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.verified
       AND (
           NOT OLD.verified
           OR NEW.email IS DISTINCT FROM OLD.email
       )
       AND NOT EXISTS (
           SELECT 1
           FROM ctfzone.email_verification_tokens AS token
           WHERE token.user_id = NEW.id
             AND token.email = NEW.email
             AND token.used_at IS NOT NULL
             AND token.used_at >= token.created_at
             AND token.used_at < token.expires_at
             AND token.invalidated_at IS NULL
       )
    THEN
        RAISE EXCEPTION 'verified email requires a consumed verification token for the current address'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS users_require_email_verification_proof ON ctfzone.users;
CREATE TRIGGER users_require_email_verification_proof
BEFORE INSERT OR UPDATE OF email, verified ON ctfzone.users
FOR EACH ROW EXECUTE FUNCTION ctfzone.require_email_verification_proof();

-- Object contents live in an S3-compatible service. PostgreSQL remains the
-- source of truth for ownership, authorization, lifecycle, and audit history;
-- it deliberately never stores pre-signed URLs or storage credentials.
CREATE TABLE ctfzone.stored_objects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    bucket text NOT NULL,
    object_key text NOT NULL,
    upload_key text NOT NULL,
    purpose text NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    authorization_scope text NOT NULL,
    owner_user_id integer REFERENCES ctfzone.users(id) ON DELETE SET NULL,
    owner_team_id integer REFERENCES ctfzone.teams(id) ON DELETE SET NULL,
    idempotency_key text,
    category_id integer REFERENCES ctfzone.challenge_categories(id) ON DELETE SET NULL,
    challenge_id integer REFERENCES ctfzone.challenges(id) ON DELETE SET NULL,
    page_id integer REFERENCES ctfzone.pages(id) ON DELETE SET NULL,
    solution_id integer REFERENCES ctfzone.solutions(id) ON DELETE SET NULL,
    original_filename text NOT NULL,
    content_type text NOT NULL,
    expected_size bigint NOT NULL,
    actual_size bigint,
    checksum_algorithm text NOT NULL DEFAULT 'sha256',
    expected_checksum text NOT NULL,
    actual_checksum text,
    etag text,
    retention_class text NOT NULL DEFAULT 'standard',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    upload_expires_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    ready_at timestamp with time zone,
    deleted_at timestamp with time zone,
    revision bigint NOT NULL DEFAULT 1,
    CONSTRAINT stored_objects_bucket_key_key UNIQUE (bucket, object_key),
    CONSTRAINT stored_objects_bucket_upload_key_key UNIQUE (bucket, upload_key),
    CONSTRAINT stored_objects_id_category_key UNIQUE (id, category_id),
    CONSTRAINT stored_objects_purpose_check CHECK (
        purpose IN ('category_icon', 'challenge_asset', 'page_asset', 'solution_asset',
                    'submission', 'patch', 'program', 'pcap', 'result', 'export')
    ),
    CONSTRAINT stored_objects_status_check CHECK (
        status IN ('pending', 'ready', 'quarantined', 'deleting', 'deleted', 'failed')
    ),
    CONSTRAINT stored_objects_authorization_scope_check CHECK (
        authorization_scope IN ('target', 'user', 'team')
    ),
    CONSTRAINT stored_objects_target_check CHECK (
        status IN ('deleting', 'deleted')
        OR (purpose = 'category_icon' AND category_id IS NOT NULL
            AND challenge_id IS NULL AND page_id IS NULL AND solution_id IS NULL)
        OR (purpose = 'challenge_asset' AND challenge_id IS NOT NULL
            AND category_id IS NULL AND page_id IS NULL AND solution_id IS NULL)
        OR (purpose = 'page_asset' AND page_id IS NOT NULL
            AND category_id IS NULL AND challenge_id IS NULL AND solution_id IS NULL)
        OR (purpose = 'solution_asset' AND challenge_id IS NOT NULL
            AND solution_id IS NOT NULL AND category_id IS NULL AND page_id IS NULL)
        OR (purpose IN ('submission', 'patch', 'program') AND challenge_id IS NOT NULL
            AND category_id IS NULL AND page_id IS NULL AND solution_id IS NULL)
        OR (purpose IN ('pcap', 'result', 'export')
            AND category_id IS NULL AND challenge_id IS NULL
            AND page_id IS NULL AND solution_id IS NULL)
    ),
    CONSTRAINT stored_objects_scope_purpose_check CHECK (
        (purpose IN ('category_icon', 'challenge_asset', 'page_asset', 'solution_asset')
            AND authorization_scope = 'target')
        OR (purpose NOT IN ('category_icon', 'challenge_asset', 'page_asset', 'solution_asset')
            AND authorization_scope IN ('user', 'team'))
    ),
    CONSTRAINT stored_objects_category_icon_check CHECK (
        purpose <> 'category_icon'
        OR (
            content_type IN ('image/png', 'image/svg+xml')
            AND expected_size BETWEEN 1 AND 262144
            AND (actual_size IS NULL OR actual_size BETWEEN 1 AND 262144)
        )
    ),
    CONSTRAINT stored_objects_category_icon_ready_check CHECK (
        purpose <> 'category_icon'
        OR status <> 'ready'
        OR ((
            jsonb_typeof(metadata->'format') = 'string'
            AND (
                (content_type = 'image/png' AND metadata->'format' = '"png"'::jsonb)
                OR (
                    content_type = 'image/svg+xml'
                    AND metadata->'format' = '"svg"'::jsonb
                    AND metadata->'sanitized' = 'true'::jsonb
                )
            )
            AND jsonb_typeof(metadata->'width') = 'number'
            AND metadata->'width' = '128'::jsonb
            AND jsonb_typeof(metadata->'height') = 'number'
            AND metadata->'height' = '128'::jsonb
            AND jsonb_typeof(metadata->'animated') = 'boolean'
            AND metadata->'animated' = 'false'::jsonb
        ) IS TRUE)
    ),
    CONSTRAINT stored_objects_size_check CHECK (
        expected_size >= 0 AND (actual_size IS NULL OR actual_size >= 0)
    ),
    CONSTRAINT stored_objects_checksum_check CHECK (
        checksum_algorithm = 'sha256'
        AND expected_checksum ~ '^[0-9a-f]{64}$'
        AND (actual_checksum IS NULL OR actual_checksum ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT stored_objects_retention_check CHECK (
        retention_class IN ('ephemeral', 'standard', 'event', 'archive')
    ),
    CONSTRAINT stored_objects_revision_check CHECK (revision > 0),
    CONSTRAINT stored_objects_ready_metadata_check CHECK (
        status <> 'ready'
        OR (actual_size IS NOT NULL AND actual_checksum IS NOT NULL AND ready_at IS NOT NULL)
    ),
    CONSTRAINT stored_objects_lifecycle_timestamps_check CHECK (
        upload_expires_at > created_at
        AND (ready_at IS NULL OR ready_at >= created_at)
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    CONSTRAINT stored_objects_idempotency_key_check CHECK (
        idempotency_key IS NULL
        OR (length(idempotency_key) BETWEEN 1 AND 128
            AND idempotency_key !~ '[[:cntrl:]]')
    )
);

CREATE INDEX idx_stored_objects_owner_user
    ON ctfzone.stored_objects (owner_user_id, created_at DESC)
    WHERE owner_user_id IS NOT NULL;
CREATE INDEX idx_stored_objects_owner_team
    ON ctfzone.stored_objects (owner_team_id, created_at DESC)
    WHERE owner_team_id IS NOT NULL;
CREATE INDEX idx_stored_objects_category
    ON ctfzone.stored_objects (category_id, created_at DESC)
    WHERE category_id IS NOT NULL;
CREATE INDEX idx_stored_objects_challenge
    ON ctfzone.stored_objects (challenge_id, created_at DESC)
    WHERE challenge_id IS NOT NULL;
CREATE INDEX idx_stored_objects_page
    ON ctfzone.stored_objects (page_id, created_at DESC)
    WHERE page_id IS NOT NULL;
CREATE INDEX idx_stored_objects_solution
    ON ctfzone.stored_objects (solution_id, created_at DESC)
    WHERE solution_id IS NOT NULL;
CREATE INDEX idx_stored_objects_lifecycle
    ON ctfzone.stored_objects (status, expires_at, created_at);
CREATE INDEX idx_stored_objects_stale_uploads
    ON ctfzone.stored_objects (upload_expires_at)
    WHERE status = 'pending';
CREATE UNIQUE INDEX uq_stored_objects_user_idempotency
    ON ctfzone.stored_objects (owner_user_id, idempotency_key)
    WHERE owner_user_id IS NOT NULL AND idempotency_key IS NOT NULL;
CREATE INDEX idx_stored_objects_principal_quota
    ON ctfzone.stored_objects
       (authorization_scope, owner_user_id, owner_team_id, status, created_at);

ALTER TABLE ctfzone.challenge_categories
    ADD CONSTRAINT challenge_categories_icon_object_id_fkey
    FOREIGN KEY (icon_object_id, id)
    REFERENCES ctfzone.stored_objects(id, category_id) ON DELETE RESTRICT;

CREATE UNIQUE INDEX uq_challenge_categories_icon_object
    ON ctfzone.challenge_categories (icon_object_id)
    WHERE icon_object_id IS NOT NULL;

CREATE FUNCTION ctfzone.validate_challenge_category_icon()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.icon_object_id IS NOT NULL THEN
        -- SHARE conflicts with every status/metadata/target UPDATE mode. Holding
        -- it through the category-pointer transaction closes the attach-vs-drift
        -- race that a plain MVCC read (or KEY SHARE) would leave open.
        PERFORM 1
        FROM ctfzone.stored_objects object
        WHERE object.id = NEW.icon_object_id
          AND object.category_id = NEW.id
          AND object.purpose = 'category_icon'
          AND object.status = 'ready'
          AND object.content_type IN ('image/png', 'image/svg+xml')
          AND (
              (object.content_type = 'image/png' AND object.metadata->'format' = '"png"'::jsonb)
              OR (
                  object.content_type = 'image/svg+xml'
                  AND object.metadata->'format' = '"svg"'::jsonb
                  AND object.metadata->'sanitized' = 'true'::jsonb
              )
          )
          AND object.metadata->'width' = '128'::jsonb
          AND object.metadata->'height' = '128'::jsonb
          AND object.metadata->'animated' = 'false'::jsonb
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'category icon must reference its validated ready PNG or SVG object'
                USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER challenge_categories_validate_icon
BEFORE INSERT OR UPDATE OF icon_object_id ON ctfzone.challenge_categories
FOR EACH ROW EXECUTE FUNCTION ctfzone.validate_challenge_category_icon();

-- Attachment validation must remain true after the pointer is installed too.
-- Deferring this check permits the API and parent-delete trigger to detach the
-- category and retire the old object in one transaction, while making direct
-- status/target drift fail closed at commit.
CREATE FUNCTION ctfzone.validate_attached_challenge_category_icon()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_object_id uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        checked_object_id := OLD.id;
    ELSE
        checked_object_id := NEW.id;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM ctfzone.challenge_categories category
        LEFT JOIN ctfzone.stored_objects object
          ON object.id = category.icon_object_id
         AND object.category_id = category.id
        WHERE category.icon_object_id = checked_object_id
          AND (
              object.id IS NULL
              OR object.purpose IS DISTINCT FROM 'category_icon'
              OR object.status IS DISTINCT FROM 'ready'
              OR object.content_type NOT IN ('image/png', 'image/svg+xml')
              OR (
                  (object.content_type = 'image/png' AND object.metadata->'format' = '"png"'::jsonb)
                  OR (
                      object.content_type = 'image/svg+xml'
                      AND object.metadata->'format' = '"svg"'::jsonb
                      AND object.metadata->'sanitized' = 'true'::jsonb
                  )
              ) IS NOT TRUE
              OR object.metadata->'width' IS DISTINCT FROM '128'::jsonb
              OR object.metadata->'height' IS DISTINCT FROM '128'::jsonb
              OR object.metadata->'animated' IS DISTINCT FROM 'false'::jsonb
          )
    ) THEN
        RAISE EXCEPTION 'attached category icon must remain a validated ready PNG or SVG object'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END
$$;

CREATE CONSTRAINT TRIGGER stored_objects_validate_attached_category_icon
AFTER INSERT OR UPDATE OR DELETE ON ctfzone.stored_objects
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION ctfzone.validate_attached_challenge_category_icon();

CREATE TABLE ctfzone.stored_object_events (
    id bigserial PRIMARY KEY,
    object_id uuid NOT NULL REFERENCES ctfzone.stored_objects(id) ON DELETE RESTRICT,
    event_type text NOT NULL,
    source text NOT NULL,
    actor_user_id integer REFERENCES ctfzone.users(id) ON DELETE SET NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX idx_stored_object_events_object_time
    ON ctfzone.stored_object_events (object_id, created_at DESC, id DESC);

-- Durable maintenance queue. Workers claim rows with FOR UPDATE SKIP LOCKED;
-- retries survive API/controller restarts and multiple workers are safe.
CREATE TABLE ctfzone.object_operations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    object_id uuid NOT NULL REFERENCES ctfzone.stored_objects(id) ON DELETE RESTRICT,
    operation text NOT NULL,
    object_revision bigint NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0,
    available_at timestamp with time zone NOT NULL DEFAULT now(),
    claimed_at timestamp with time zone,
    claimed_by text,
    last_error text,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    completed_at timestamp with time zone,
    CONSTRAINT object_operations_operation_check CHECK (
        operation IN ('verify_upload', 'delete', 'delete_upload', 'reconcile')
    ),
    CONSTRAINT object_operations_status_check CHECK (
        status IN ('pending', 'claimed', 'completed', 'failed', 'cancelled')
    ),
    CONSTRAINT object_operations_attempts_check CHECK (attempts >= 0),
    CONSTRAINT object_operations_revision_check CHECK (object_revision > 0)
);

CREATE UNIQUE INDEX uq_object_operations_open_kind
    ON ctfzone.object_operations (object_id, operation)
    WHERE status IN ('pending', 'claimed');
CREATE INDEX idx_object_operations_claim
    ON ctfzone.object_operations (available_at, created_at)
    WHERE status = 'pending';
CREATE INDEX idx_object_operations_stale_claim
    ON ctfzone.object_operations (claimed_at)
    WHERE status = 'claimed';
CREATE INDEX idx_object_operations_object_history
    ON ctfzone.object_operations
       (object_id, operation, status, object_revision, completed_at DESC);

-- A target or owning principal must not disappear while its object bytes remain
-- authorized and detached from the lifecycle queue. Parent deletion first locks
-- every linked object in a stable order and revision-fences cleanup before the
-- parent foreign keys become NULL.
CREATE FUNCTION ctfzone.schedule_linked_object_deletion()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    association_column text := TG_ARGV[0];
    parent_kind text := TG_ARGV[1];
    required_scope text := NULLIF(TG_ARGV[2], '');
    association_filter text;
    locked_object record;
    object_row record;
    effective_revision bigint;
    lifecycle_changed boolean;
BEGIN
    IF NOT (
        (association_column = 'challenge_id' AND parent_kind = 'challenge'
            AND required_scope IS NULL)
        OR (association_column = 'category_id' AND parent_kind = 'category'
            AND required_scope IS NULL)
        OR (association_column = 'page_id' AND parent_kind = 'page'
            AND required_scope IS NULL)
        OR (association_column = 'solution_id' AND parent_kind = 'solution'
            AND required_scope IS NULL)
        OR (association_column = 'owner_user_id' AND parent_kind = 'user'
            AND required_scope = 'user')
        OR (association_column = 'owner_team_id' AND parent_kind = 'team'
            AND required_scope = 'team')
    )
    THEN
        RAISE EXCEPTION 'invalid linked-object deletion trigger arguments';
    END IF;

    association_filter := format('%I = $1', association_column);
    IF required_scope IS NOT NULL THEN
        association_filter := association_filter
            || format(' AND authorization_scope = %L', required_scope);
    END IF;

    -- Acquire all object locks before changing any of them. Ordering by UUID
    -- gives concurrent parent deletions the same lock order.
    FOR locked_object IN EXECUTE format(
        'SELECT id FROM ctfzone.stored_objects '
        'WHERE %s ORDER BY id FOR UPDATE',
        association_filter
    ) USING OLD.id
    LOOP
        NULL;
    END LOOP;

    FOR object_row IN EXECUTE format(
        'SELECT id,status,revision,upload_expires_at '
        'FROM ctfzone.stored_objects WHERE %s ORDER BY id',
        association_filter
    ) USING OLD.id
    LOOP
        effective_revision := object_row.revision;
        lifecycle_changed := false;

        -- Repeated/cascading target deletes are idempotent. Objects already in
        -- deleting have revision-fenced work, and deleted objects need no work.
        IF object_row.status NOT IN ('deleting', 'deleted') THEN
            UPDATE ctfzone.stored_objects
            SET status = 'deleting', revision = revision + 1
            WHERE id = object_row.id
              AND revision = object_row.revision
            RETURNING revision INTO effective_revision;

            lifecycle_changed := true;

            UPDATE ctfzone.object_operations
            SET status = 'cancelled',
                completed_at = COALESCE(completed_at, now()),
                last_error = COALESCE(
                    last_error,
                    format('%s %s was deleted', parent_kind, OLD.id)
                )
            WHERE object_id = object_row.id
              AND status IN ('pending', 'claimed');

            INSERT INTO ctfzone.object_operations
                (object_id,operation,object_revision,status,available_at)
            VALUES
                (
                    object_row.id,
                    'delete_upload',
                    effective_revision,
                    'pending',
                    object_row.upload_expires_at + interval '5 seconds'
                ),
                (
                    object_row.id,
                    'delete',
                    effective_revision,
                    'pending',
                    now()
                )
            ON CONFLICT DO NOTHING;
        END IF;

        INSERT INTO ctfzone.stored_object_events
            (object_id,event_type,source,actor_user_id,details)
        VALUES (
            object_row.id,
            'parent_delete_requested',
            'database_trigger',
            NULL,
            jsonb_build_object(
                'parent_type', parent_kind,
                'parent_id', OLD.id,
                'previous_status', object_row.status,
                'object_revision', effective_revision,
                'lifecycle_changed', lifecycle_changed
            )
        );
    END LOOP;

    RETURN OLD;
END
$$;

CREATE TRIGGER challenges_schedule_stored_object_deletion
BEFORE DELETE ON ctfzone.challenges
FOR EACH ROW
EXECUTE FUNCTION ctfzone.schedule_linked_object_deletion('challenge_id', 'challenge', '');

CREATE TRIGGER challenge_categories_schedule_stored_object_deletion
BEFORE DELETE ON ctfzone.challenge_categories
FOR EACH ROW
EXECUTE FUNCTION ctfzone.schedule_linked_object_deletion('category_id', 'category', '');

CREATE TRIGGER pages_schedule_stored_object_deletion
BEFORE DELETE ON ctfzone.pages
FOR EACH ROW
EXECUTE FUNCTION ctfzone.schedule_linked_object_deletion('page_id', 'page', '');

CREATE TRIGGER solutions_schedule_stored_object_deletion
BEFORE DELETE ON ctfzone.solutions
FOR EACH ROW
EXECUTE FUNCTION ctfzone.schedule_linked_object_deletion('solution_id', 'solution', '');

CREATE TRIGGER users_schedule_stored_object_deletion
BEFORE DELETE ON ctfzone.users
FOR EACH ROW
EXECUTE FUNCTION ctfzone.schedule_linked_object_deletion('owner_user_id', 'user', 'user');

CREATE TRIGGER teams_schedule_stored_object_deletion
BEFORE DELETE ON ctfzone.teams
FOR EACH ROW
EXECUTE FUNCTION ctfzone.schedule_linked_object_deletion('owner_team_id', 'team', 'team');

-- The player navigation is data-driven from its first boot. Home is the
-- permanent root document; the two system pages retain fixed endpoints and
-- implementation while administrators control only their visibility/order.
INSERT INTO ctfzone.pages
    (label, endpoint, content, page_type, system_key, visibility, navigation_order)
VALUES
    ('Home', '', '<div class="row page-section align-items-center"><div class="col-md-8 offset-md-1"><h1 class="display-1">Built for curious minds.</h1><p class="lead">Practice real security skills, solve challenges at your own pace, and compete for a place on the scoreboard.</p><p class="page-actions"><a href="/challenges">Browse challenges</a><a href="/scoreboard">View scoreboard</a></p></div></div>',
     'home', 'home', 'public', 0),
    ('Challenges', 'challenges', '', 'system', 'challenges', 'private', 10),
    ('Scoreboard', 'scoreboard', '', 'system', 'scoreboard', 'public', 20)
ON CONFLICT (endpoint) DO NOTHING;

DO $$
BEGIN
    IF to_regclass('ctfzone.users') IS NULL
        OR to_regclass('ctfzone.challenges') IS NULL
        OR to_regclass('ctfzone.flags') IS NULL
        OR to_regclass('ctfzone.pages') IS NULL
        OR NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'pages_system_identity_check'
              AND conrelid = 'ctfzone.pages'::regclass
        )
        OR NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'pages_visibility_check'
              AND conrelid = 'ctfzone.pages'::regclass
        )
        OR (SELECT count(*) FROM ctfzone.pages WHERE system_key IN ('home', 'challenges', 'scoreboard')) <> 3
        OR to_regclass('ctfzone.challenge_categories') IS NULL
        OR (
            SELECT count(*) <> 3
            FROM information_schema.columns
            WHERE table_schema = 'ctfzone'
              AND table_name = 'challenge_categories'
              AND column_name IN ('logo_key', 'logo_color', 'icon_object_id')
        )
        OR NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'challenge_categories_logo_key_check'
              AND conrelid = 'ctfzone.challenge_categories'::regclass
        )
        OR NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'challenge_categories_logo_color_check'
              AND conrelid = 'ctfzone.challenge_categories'::regclass
        )
        OR NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'challenge_categories_icon_object_id_fkey'
              AND conrelid = 'ctfzone.challenge_categories'::regclass
        )
        OR NOT EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = 'stored_objects_category_icon_ready_check'
              AND conrelid = 'ctfzone.stored_objects'::regclass
        )
        OR to_regclass('ctfzone.admin_create_idempotency') IS NULL
        OR to_regclass('ctfzone.user_challenge_flags') IS NULL
        OR to_regclass('ctfzone.flag_sharing_events') IS NULL
        OR to_regclass('ctfzone.user_mode_transitions') IS NULL
        OR to_regclass('ctfzone.runtime_settings') IS NULL
        OR to_regclass('ctfzone.challenge_runtime_configs') IS NULL
        OR to_regclass('ctfzone.remote_servers') IS NULL
        OR to_regclass('ctfzone.runtime_instances') IS NULL
        OR to_regclass('ctfzone.runtime_commands') IS NULL
        OR to_regclass('ctfzone.runtime_instance_events') IS NULL
        OR to_regclass('ctfzone.email_verification_tokens') IS NULL
        OR to_regclass('ctfzone.stored_objects') IS NULL
        OR (
            SELECT count(*) <> 2
            FROM information_schema.columns
            WHERE table_schema = 'ctfzone'
              AND table_name = 'stored_objects'
              AND column_name IN ('category_id', 'metadata')
        )
        OR NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname = 'challenge_categories_schedule_stored_object_deletion'
              AND tgrelid = 'ctfzone.challenge_categories'::regclass
              AND NOT tgisinternal
        )
        OR NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname = 'challenge_categories_validate_icon'
              AND tgrelid = 'ctfzone.challenge_categories'::regclass
              AND NOT tgisinternal
        )
        OR NOT EXISTS (
            SELECT 1 FROM pg_trigger
            WHERE tgname = 'stored_objects_validate_attached_category_icon'
              AND tgrelid = 'ctfzone.stored_objects'::regclass
              AND NOT tgisinternal
        )
        OR to_regclass('ctfzone.stored_object_events') IS NULL
        OR to_regclass('ctfzone.object_operations') IS NULL
    THEN
        RAISE EXCEPTION 'CTFZone schema cannot be finalized because required tables are missing';
    END IF;
END
$$;

INSERT INTO ctfzone.release_metadata (key, value)
VALUES ('install_complete', '1.0.0')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

COMMIT;
