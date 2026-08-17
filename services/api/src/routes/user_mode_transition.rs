use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, SecondsFormat, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, Postgres, Transaction};
use std::time::Duration as StdDuration;

use crate::{AppState, auth::CurrentUser, error::ApiError, routes::Success};

type HmacSha256 = Hmac<Sha256>;

pub(crate) const CONFIGURATION_LOCK_KEY: i64 = 0x4354_465A;
const PREVIEW_TOKEN_VERSION: u8 = 1;
const PREVIEW_TOKEN_TTL_MINUTES: i64 = 5;
const PREVIEW_TOKEN_MAX_LENGTH: usize = 16_384;
const PREVIEW_TOKEN_CONTEXT: &[u8] = b"ctfzone/user-mode-transition-preview/v1";
const AUDIT_TABLE: &str = "ctfzone.user_mode_transitions";
const PRECOMMIT_TIMEOUT_SECONDS: u64 = 45;
const PRECOMMIT_STATEMENT_TIMEOUT_SECONDS: u64 = 40;
const PREVIEW_TIMEOUT_SECONDS: u64 = 45;
const PREVIEW_STATEMENT_TIMEOUT_SECONDS: u64 = 40;
const TRANSITION_LOCK_TIMEOUT_SECONDS: u64 = 8;
const COMMIT_STATEMENT_TIMEOUT_SECONDS: u64 = 8;
#[cfg(test)]
const BFF_TRANSITION_TIMEOUT_SECONDS: u64 = 65;
#[cfg(test)]
const GUNICORN_WORKER_TIMEOUT_SECONDS: u64 = 75;
#[cfg(test)]
const REQUIRED_PROXY_HEADROOM_SECONDS: u64 = 5;

pub(crate) fn is_transition_route(path: &str) -> bool {
    matches!(
        path,
        "/api/v1/views/admin/user-mode-transition" | "/api/v1/configs/user-mode-transition"
    )
}

#[derive(Deserialize)]
pub(super) struct PreviewQuery {
    target: String,
}

#[derive(Deserialize)]
pub(super) struct TransitionRequest {
    target_mode: String,
    confirmation: String,
    preview_token: String,
}

#[derive(Clone, Debug, Deserialize, Eq, FromRow, PartialEq, Serialize)]
pub(super) struct AffectedCounts {
    participants: i64,
    teams: i64,
    memberships: i64,
    active_runtimes: i64,
    generated_flags: i64,
    shared_flag_events: i64,
    submissions: i64,
    solves: i64,
    awards: i64,
    unlocks: i64,
    tracking: i64,
    dynamic_challenges: i64,
    team_logic_challenges: i64,
    team_notifications: i64,
    team_field_entries: i64,
    team_comments: i64,
    team_objects: i64,
    user_objects: i64,
    sessions: i64,
    api_tokens: i64,
}

#[derive(FromRow)]
struct SnapshotRow {
    source_mode: String,
    participants: i64,
    teams: i64,
    memberships: i64,
    active_runtimes: i64,
    generated_flags: i64,
    shared_flag_events: i64,
    submissions: i64,
    solves: i64,
    awards: i64,
    unlocks: i64,
    tracking: i64,
    dynamic_challenges: i64,
    team_logic_challenges: i64,
    team_notifications: i64,
    team_field_entries: i64,
    team_comments: i64,
    team_objects: i64,
    user_objects: i64,
    sessions: i64,
    api_tokens: i64,
    audit_ready: bool,
    snapshot_fingerprint: String,
}

impl SnapshotRow {
    fn affected(&self, _target_mode: &str) -> AffectedCounts {
        AffectedCounts {
            participants: self.participants,
            teams: self.teams,
            memberships: self.memberships,
            active_runtimes: self.active_runtimes,
            generated_flags: self.generated_flags,
            shared_flag_events: self.shared_flag_events,
            submissions: self.submissions,
            solves: self.solves,
            awards: self.awards,
            unlocks: self.unlocks,
            tracking: self.tracking,
            dynamic_challenges: self.dynamic_challenges,
            team_logic_challenges: self.team_logic_challenges,
            team_notifications: self.team_notifications,
            team_field_entries: self.team_field_entries,
            team_comments: self.team_comments,
            team_objects: self.team_objects,
            user_objects: self.user_objects,
            sessions: self.sessions,
            api_tokens: self.api_tokens,
        }
    }
}

#[derive(Serialize)]
struct PreviewData {
    source_mode: String,
    target_mode: String,
    confirmation_phrase: String,
    preview_token: Option<String>,
    expires_at: Option<String>,
    blocked: bool,
    blockers: Vec<Consequence>,
    warnings: Vec<Consequence>,
    affected: AffectedCounts,
}

#[derive(Serialize)]
struct TransitionData {
    source_mode: String,
    target_mode: String,
    affected: AffectedCounts,
    sessions_revoked: u64,
    api_tokens_revoked: u64,
    participant_credentials_rotated: u64,
}

#[derive(Debug, Serialize)]
struct Consequence {
    code: &'static str,
    message: String,
    count: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct PreviewTokenClaims {
    version: u8,
    actor_user_id: i32,
    source_mode: String,
    target_mode: String,
    affected: AffectedCounts,
    snapshot: AffectedCounts,
    snapshot_fingerprint: String,
    issued_at: i64,
    expires_at: i64,
}

pub(super) async fn preview(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<PreviewQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let target_mode = parse_mode(&query.target)?;
    let snapshot = tokio::time::timeout(
        StdDuration::from_secs(PREVIEW_TIMEOUT_SECONDS),
        preview_snapshot(&state),
    )
    .await
    .map_err(|_| {
        ApiError::service_unavailable(
            "The transition preview exceeded its safe time window; retry the preview",
        )
    })??;
    let source_mode = snapshot.source_mode.clone();
    let affected = snapshot.affected(target_mode);
    let (blockers, warnings) = consequences(&snapshot, target_mode);
    let blocked = !blockers.is_empty();

    let (preview_token, expires_at) = if blocked {
        (None, None)
    } else {
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::minutes(PREVIEW_TOKEN_TTL_MINUTES);
        let claims = PreviewTokenClaims {
            version: PREVIEW_TOKEN_VERSION,
            actor_user_id: user.id,
            source_mode: source_mode.clone(),
            target_mode: target_mode.to_owned(),
            affected: affected.clone(),
            snapshot: snapshot.affected("users"),
            snapshot_fingerprint: snapshot.snapshot_fingerprint.clone(),
            issued_at: issued_at.timestamp(),
            expires_at: expires_at.timestamp(),
        };
        (
            Some(sign_preview_token(&state.auth.secret_key, &claims)?),
            Some(expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)),
        )
    };

    Ok(no_store(
        Json(Success::new(PreviewData {
            source_mode,
            target_mode: target_mode.to_owned(),
            confirmation_phrase: confirmation_phrase(target_mode),
            preview_token,
            expires_at,
            blocked,
            blockers,
            warnings,
            affected,
        }))
        .into_response(),
    ))
}

pub(super) async fn execute(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<TransitionRequest>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let target_mode = parse_mode(&request.target_mode)?;
    if request.confirmation.trim() != confirmation_phrase(target_mode) {
        return Err(ApiError::bad_request(format!(
            "Type {} to confirm this destructive transition",
            confirmation_phrase(target_mode)
        )));
    }

    let claims = verify_preview_token(&state.auth.secret_key, &request.preview_token)?;
    if claims.actor_user_id != user.id || claims.target_mode != target_mode {
        return Err(invalid_preview_token());
    }

    // Pool acquisition, transaction setup, every destructive statement, the
    // audit insert, and rollback-on-error all share one cancellable pre-commit
    // budget. A timeout can only drop an uncommitted transaction.
    let precommit = async {
        let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
        let data =
            match prepare_transition(&mut transaction, &state, &user, target_mode, &claims).await {
                Ok(data) => data,
                Err(error) => {
                    transaction
                        .rollback()
                        .await
                        .map_err(map_transition_database_error)?;
                    return Err(error);
                }
            };
        if let Err(error) = set_local_timeout(
            &mut transaction,
            "statement_timeout",
            COMMIT_STATEMENT_TIMEOUT_SECONDS,
        )
        .await
        {
            transaction
                .rollback()
                .await
                .map_err(map_transition_database_error)?;
            return Err(error);
        }
        Ok::<_, ApiError>((transaction, data))
    };
    let (transaction, data) = match tokio::time::timeout(
        StdDuration::from_secs(PRECOMMIT_TIMEOUT_SECONDS),
        precommit,
    )
    .await
    {
        Ok(Ok(prepared)) => prepared,
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            return Err(ApiError::service_unavailable(
                "The transition exceeded its safe pre-commit window; no mode change was committed",
            ));
        }
    };
    // Do not put a client-side cancellation boundary around COMMIT: losing the
    // future after PostgreSQL receives COMMIT would make the outcome ambiguous.
    // PostgreSQL itself caps this statement with the timeout installed above.
    transaction
        .commit()
        .await
        .map_err(map_transition_database_error)?;

    Ok(no_store(Json(Success::new(data)).into_response()))
}

async fn prepare_transition(
    transaction: &mut Transaction<'_, Postgres>,
    state: &AppState,
    user: &CurrentUser,
    target_mode: &str,
    claims: &PreviewTokenClaims,
) -> Result<TransitionData, ApiError> {
    set_transition_timeouts(transaction).await?;
    lock_configuration_exclusive(transaction).await?;
    crate::auth::revalidate_current_credential(
        transaction,
        user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    ensure_audit_table(transaction).await?;
    if claims.expires_at <= Utc::now().timestamp() {
        return Err(invalid_preview_token());
    }

    let snapshot = load_snapshot(transaction).await?;
    let affected = snapshot.affected(target_mode);
    if snapshot.active_runtimes != 0 {
        return Err(ApiError::conflict(
            "Terminate every active challenge runtime before changing competition mode",
        ));
    }
    if snapshot.source_mode == target_mode {
        return Err(ApiError::conflict(
            "The requested competition mode is already active",
        ));
    }
    if snapshot.source_mode != claims.source_mode
        || affected != claims.affected
        || snapshot.affected("users") != claims.snapshot
        || snapshot.snapshot_fingerprint != claims.snapshot_fingerprint
    {
        return Err(ApiError::conflict(
            "Competition data changed after the preview; review the transition again",
        ));
    }
    let sessions_revoked = revoke_participant_sessions(transaction, user.id).await?;
    let api_tokens_revoked = revoke_participant_api_tokens(transaction).await?;
    let participant_credentials_rotated = rotate_participant_credentials(transaction).await?;

    schedule_user_competition_object_deletion(
        transaction,
        user.id,
        &snapshot.source_mode,
        target_mode,
    )
    .await?;
    clear_competition_state(transaction).await?;
    remove_teams(transaction).await?;
    set_user_mode(transaction, target_mode).await?;
    insert_audit_event(
        transaction,
        user.id,
        &snapshot.source_mode,
        target_mode,
        &affected,
    )
    .await?;

    Ok(TransitionData {
        source_mode: snapshot.source_mode,
        target_mode: target_mode.to_owned(),
        affected,
        sessions_revoked,
        api_tokens_revoked,
        participant_credentials_rotated,
    })
}

pub(crate) async fn lock_configuration_shared(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(CONFIGURATION_LOCK_KEY)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    Ok(())
}

pub(crate) async fn transaction_user_mode(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<String, ApiError> {
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM ctfzone.config WHERE key='user_mode' LIMIT 1",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .flatten()
    .filter(|value| !value.trim().is_empty())
    .unwrap_or_else(|| "users".to_owned()))
}

async fn lock_configuration_exclusive(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(CONFIGURATION_LOCK_KEY)
        .execute(&mut **transaction)
        .await
        .map_err(map_transition_database_error)?;
    Ok(())
}

async fn set_transition_timeouts(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    set_local_timeout(transaction, "lock_timeout", TRANSITION_LOCK_TIMEOUT_SECONDS).await?;
    set_local_timeout(
        transaction,
        "statement_timeout",
        PRECOMMIT_STATEMENT_TIMEOUT_SECONDS,
    )
    .await?;
    Ok(())
}

async fn set_local_timeout(
    transaction: &mut Transaction<'_, Postgres>,
    setting: &str,
    seconds: u64,
) -> Result<(), ApiError> {
    sqlx::query("SELECT set_config($1,$2,true)")
        .bind(setting)
        .bind(format!("{seconds}s"))
        .execute(&mut **transaction)
        .await
        .map_err(map_transition_database_error)?;
    Ok(())
}

async fn ensure_audit_table(transaction: &mut Transaction<'_, Postgres>) -> Result<(), ApiError> {
    let ready = sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
        .bind(AUDIT_TABLE)
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_transition_database_error)?;
    if ready {
        Ok(())
    } else {
        Err(ApiError::service_unavailable(
            "The user-mode transition audit schema is unavailable",
        ))
    }
}

async fn preview_snapshot(state: &AppState) -> Result<SnapshotRow, ApiError> {
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    set_local_timeout(
        &mut transaction,
        "statement_timeout",
        PREVIEW_STATEMENT_TIMEOUT_SECONDS,
    )
    .await?;
    let snapshot = load_snapshot(&mut transaction).await?;
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(snapshot)
}

async fn load_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<SnapshotRow, ApiError> {
    let mut snapshot = sqlx::query_as::<_, SnapshotRow>(
        r#"
        SELECT
            COALESCE(
                NULLIF(TRIM((SELECT value FROM ctfzone.config WHERE key='user_mode')), ''),
                'users'
            ) AS source_mode,
            (SELECT COUNT(*) FROM ctfzone.users
                WHERE COALESCE(type, 'user') <> 'admin') AS participants,
            (SELECT COUNT(*) FROM ctfzone.teams) AS teams,
            (SELECT COUNT(*) FROM ctfzone.users WHERE team_id IS NOT NULL) AS memberships,
            (SELECT COUNT(*) FROM ctfzone.runtime_instances WHERE active) AS active_runtimes,
            (SELECT COUNT(*) FROM ctfzone.user_challenge_flags) AS generated_flags,
            (SELECT COUNT(*) FROM ctfzone.flag_sharing_events) AS shared_flag_events,
            (SELECT COUNT(*) FROM ctfzone.submissions) AS submissions,
            (SELECT COUNT(*) FROM ctfzone.solves) AS solves,
            (SELECT COUNT(*) FROM ctfzone.awards) AS awards,
            (SELECT COUNT(*) FROM ctfzone.unlocks) AS unlocks,
            (SELECT COUNT(*) FROM ctfzone.tracking) AS tracking,
            (SELECT COUNT(*) FROM ctfzone.challenges WHERE type='dynamic') AS dynamic_challenges,
            (SELECT COUNT(*) FROM ctfzone.challenges WHERE logic='team') AS team_logic_challenges,
            (SELECT COUNT(*) FROM ctfzone.notifications WHERE team_id IS NOT NULL)
                AS team_notifications,
            (SELECT COUNT(*) FROM ctfzone.field_entries WHERE team_id IS NOT NULL)
                AS team_field_entries,
            (SELECT COUNT(*) FROM ctfzone.comments WHERE team_id IS NOT NULL)
                AS team_comments,
            (SELECT COUNT(*) FROM ctfzone.stored_objects WHERE owner_team_id IS NOT NULL)
                AS team_objects,
            (
                SELECT COUNT(*)
                FROM ctfzone.stored_objects AS object
                JOIN ctfzone.users AS owner ON owner.id=object.owner_user_id
                WHERE object.authorization_scope='user'
                  AND object.purpose IN ('submission','patch','program','pcap','result')
                  AND COALESCE(owner.type, 'user') <> 'admin'
            ) AS user_objects,
            (
                SELECT COUNT(*)
                FROM ctfzone.user_sessions AS session
                JOIN ctfzone.users AS account ON account.id=session.user_id
                WHERE session.revoked_at IS NULL
                  AND COALESCE(account.type, 'user') <> 'admin'
            ) AS sessions,
            (
                SELECT COUNT(*)
                FROM ctfzone.tokens AS token
                JOIN ctfzone.users AS account ON account.id=token.user_id
                WHERE COALESCE(account.type, 'user') <> 'admin'
            ) AS api_tokens,
            to_regclass('ctfzone.user_mode_transitions') IS NOT NULL AS audit_ready,
            concat_ws('|',
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(id,COALESCE(type, ''),team_id)::text, 101
                    )), 0)::text FROM ctfzone.users
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(id,captain_id)::text, 103
                    )), 0)::text FROM ctfzone.teams
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(id,generation,desired_state,observed_state)::text, 105
                    )), 0)::text
                    FROM ctfzone.runtime_instances
                    WHERE active
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(flag_id,challenge_id,user_id,definition_revision,
                            encode(match_tag,'hex'),random_token,leet_mask)::text, 106
                    )), 0)::text FROM ctfzone.user_challenge_flags
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(id,submission_id,challenge_id,flag_id,submitting_user_id,
                            source_user_id,team_id_snapshot,accepted)::text, 108
                    )), 0)::text FROM ctfzone.flag_sharing_events
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        id::text, 107
                    )), 0)::text FROM ctfzone.submissions
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        id::text, 109
                    )), 0)::text FROM ctfzone.solves
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        id::text, 113
                    )), 0)::text FROM ctfzone.awards
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        id::text, 127
                    )), 0)::text FROM ctfzone.unlocks
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        id::text, 131
                    )), 0)::text FROM ctfzone.tracking
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(challenge.id,challenge.type,challenge.logic,challenge.value,
                            challenge.initial,dynamic.dynamic_initial,dynamic.dynamic_minimum,
                            dynamic.dynamic_decay,dynamic.dynamic_function)::text,
                        137
                    )), 0)::text
                    FROM ctfzone.challenges AS challenge
                    LEFT JOIN ctfzone.dynamic_challenge AS dynamic ON dynamic.id=challenge.id
                    WHERE challenge.type='dynamic' OR challenge.logic='team'
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(id,team_id)::text, 139
                    )), 0)::text FROM ctfzone.notifications WHERE team_id IS NOT NULL
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(id,team_id)::text, 149
                    )), 0)::text FROM ctfzone.field_entries WHERE team_id IS NOT NULL
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(id,team_id)::text, 151
                    )), 0)::text FROM ctfzone.comments WHERE team_id IS NOT NULL
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(id,owner_team_id)::text, 157
                    )), 0)::text FROM ctfzone.stored_objects WHERE owner_team_id IS NOT NULL
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(object.id,object.owner_user_id,object.purpose)::text, 159
                    )), 0)::text
                    FROM ctfzone.stored_objects AS object
                    JOIN ctfzone.users AS owner ON owner.id=object.owner_user_id
                    WHERE object.authorization_scope='user'
                      AND object.purpose IN ('submission','patch','program','pcap','result')
                      AND COALESCE(owner.type, 'user') <> 'admin'
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(session.id,session.user_id)::text, 163
                    )), 0)::text
                    FROM ctfzone.user_sessions AS session
                    JOIN ctfzone.users AS account ON account.id=session.user_id
                    WHERE session.revoked_at IS NULL
                      AND COALESCE(account.type, 'user') <> 'admin'
                ),
                (
                    SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                        ROW(token.id,token.user_id)::text, 167
                    )), 0)::text
                    FROM ctfzone.tokens AS token
                    JOIN ctfzone.users AS account ON account.id=token.user_id
                    WHERE COALESCE(account.type, 'user') <> 'admin'
                )
            ) AS snapshot_fingerprint
        "#,
    )
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?;
    let audit_marker = if snapshot.audit_ready {
        sqlx::query_scalar::<_, String>(
            r#"
            SELECT COUNT(*)::text || ':' || COALESCE(bit_xor(hashtextextended(
                id::text, 179
            )), 0)::text
            FROM ctfzone.user_mode_transitions
            "#,
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_transition_database_error)?
    } else {
        "missing".to_owned()
    };
    snapshot.snapshot_fingerprint = hex::encode(Sha256::digest(format!(
        "{}|audit:{audit_marker}",
        snapshot.snapshot_fingerprint
    )));
    Ok(snapshot)
}

fn consequences(snapshot: &SnapshotRow, target_mode: &str) -> (Vec<Consequence>, Vec<Consequence>) {
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();
    if !matches!(snapshot.source_mode.as_str(), "users" | "teams") {
        blockers.push(Consequence {
            code: "invalid_source_mode",
            message: format!(
                "The stored competition mode ({}) is invalid",
                snapshot.source_mode
            ),
            count: 1,
        });
    } else if snapshot.source_mode == target_mode {
        blockers.push(Consequence {
            code: "already_active",
            message: format!("{} mode is already active", mode_label(target_mode)),
            count: 1,
        });
    }
    if !snapshot.audit_ready {
        blockers.push(Consequence {
            code: "transition_schema_unavailable",
            message: "The user-mode transition audit schema is unavailable".to_owned(),
            count: 1,
        });
    }
    if snapshot.active_runtimes != 0 {
        blockers.push(Consequence {
            code: "active_runtimes",
            message: "Terminate every active challenge runtime before continuing".to_owned(),
            count: snapshot.active_runtimes,
        });
    }
    if target_mode == "users" && snapshot.team_logic_challenges != 0 {
        warnings.push(Consequence {
            code: "team_logic_challenges",
            message: "Review challenges with team-specific solve logic after this transition"
                .to_owned(),
            count: snapshot.team_logic_challenges,
        });
    }
    (blockers, warnings)
}

async fn revoke_participant_sessions(
    transaction: &mut Transaction<'_, Postgres>,
    actor_user_id: i32,
) -> Result<u64, ApiError> {
    Ok(sqlx::query(
        r#"
        UPDATE ctfzone.user_sessions AS session
        SET revoked_at=CURRENT_TIMESTAMP AT TIME ZONE 'UTC', revoked_by_user_id=$1
        FROM ctfzone.users AS account
        WHERE account.id=session.user_id
          AND COALESCE(account.type, 'user') <> 'admin'
          AND session.revoked_at IS NULL
        "#,
    )
    .bind(actor_user_id)
    .execute(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?
    .rows_affected())
}

async fn revoke_participant_api_tokens(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<u64, ApiError> {
    Ok(sqlx::query(
        r#"
        DELETE FROM ctfzone.tokens AS token
        USING ctfzone.users AS account
        WHERE account.id=token.user_id
          AND COALESCE(account.type, 'user') <> 'admin'
        "#,
    )
    .execute(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?
    .rows_affected())
}

async fn rotate_participant_credentials(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<u64, ApiError> {
    Ok(sqlx::query(
        r#"
        UPDATE ctfzone.users
        SET participant_token=gen_random_uuid()::text,
            participant_token_last_rotated=CURRENT_TIMESTAMP AT TIME ZONE 'UTC'
        WHERE COALESCE(type, 'user') <> 'admin'
        "#,
    )
    .execute(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?
    .rows_affected())
}

async fn schedule_user_competition_object_deletion(
    transaction: &mut Transaction<'_, Postgres>,
    actor_user_id: i32,
    source_mode: &str,
    target_mode: &str,
) -> Result<(), ApiError> {
    // The configuration fence prevents new participant objects or ownership
    // changes. Lock existing objects in UUID order to match the storage worker
    // and parent-deletion trigger lock order.
    let object_ids = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"
        SELECT object.id
        FROM ctfzone.stored_objects AS object
        JOIN ctfzone.users AS owner ON owner.id=object.owner_user_id
        WHERE object.authorization_scope='user'
          AND object.purpose IN ('submission','patch','program','pcap','result')
          AND COALESCE(owner.type, 'user') <> 'admin'
        ORDER BY object.id
        FOR UPDATE OF object
        "#,
    )
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?;
    if object_ids.is_empty() {
        return Ok(());
    }

    let changed_ids = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"
        UPDATE ctfzone.stored_objects
        SET status='deleting',revision=revision+1
        WHERE id=ANY($1) AND status NOT IN ('deleting','deleted')
        RETURNING id
        "#,
    )
    .bind(&object_ids)
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?;
    if changed_ids.is_empty() {
        return Ok(());
    }

    sqlx::query(
        r#"
        UPDATE ctfzone.object_operations
        SET status='cancelled',
            completed_at=COALESCE(completed_at,now()),
            last_error=COALESCE(last_error,'competition mode changed')
        WHERE object_id=ANY($1) AND status IN ('pending','claimed')
        "#,
    )
    .bind(&changed_ids)
    .execute(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?;
    sqlx::query(
        r#"
        INSERT INTO ctfzone.object_operations
            (object_id,operation,object_revision,status,available_at)
        SELECT
            object.id,
            operation.kind,
            object.revision,
            'pending',
            CASE operation.kind
                WHEN 'delete_upload' THEN object.upload_expires_at + interval '5 seconds'
                ELSE now()
            END
        FROM ctfzone.stored_objects AS object
        CROSS JOIN (VALUES ('delete_upload'),('delete')) AS operation(kind)
        WHERE object.id=ANY($1)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(&changed_ids)
    .execute(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?;
    sqlx::query(
        r#"
        INSERT INTO ctfzone.stored_object_events
            (object_id,event_type,source,actor_user_id,details)
        SELECT
            id,
            'mode_transition_delete_requested',
            'api',
            $2,
            jsonb_build_object('source_mode',$3::text,'target_mode',$4::text)
        FROM unnest($1::uuid[]) AS id
        "#,
    )
    .bind(&changed_ids)
    .bind(actor_user_id)
    .bind(source_mode)
    .bind(target_mode)
    .execute(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?;
    Ok(())
}

async fn clear_competition_state(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    // Solves are submission subtypes and cascade when their parent submissions are removed.
    for statement in [
        "DELETE FROM ctfzone.flag_sharing_events",
        "DELETE FROM ctfzone.user_challenge_flags",
        "DELETE FROM ctfzone.awards",
        "DELETE FROM ctfzone.unlocks",
        "DELETE FROM ctfzone.tracking",
        "DELETE FROM ctfzone.submissions",
    ] {
        sqlx::query(statement)
            .execute(&mut **transaction)
            .await
            .map_err(map_transition_database_error)?;
    }
    sqlx::query(
        r#"
        UPDATE ctfzone.challenges AS challenge
        SET value=COALESCE(
            (
                SELECT dynamic.dynamic_initial
                FROM ctfzone.dynamic_challenge AS dynamic
                WHERE dynamic.id=challenge.id
            ),
            challenge.initial,
            challenge.value
        )
        WHERE challenge.type='dynamic'
        "#,
    )
    .execute(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?;
    Ok(())
}

async fn remove_teams(transaction: &mut Transaction<'_, Postgres>) -> Result<(), ApiError> {
    // Team notifications must be deleted explicitly: nulling team_id would make them broadcasts.
    sqlx::query("DELETE FROM ctfzone.notifications WHERE team_id IS NOT NULL")
        .execute(&mut **transaction)
        .await
        .map_err(map_transition_database_error)?;
    sqlx::query("UPDATE ctfzone.users SET team_id=NULL WHERE team_id IS NOT NULL")
        .execute(&mut **transaction)
        .await
        .map_err(map_transition_database_error)?;
    sqlx::query("DELETE FROM ctfzone.teams")
        .execute(&mut **transaction)
        .await
        .map_err(map_transition_database_error)?;
    Ok(())
}

async fn set_user_mode(
    transaction: &mut Transaction<'_, Postgres>,
    target_mode: &str,
) -> Result<(), ApiError> {
    sqlx::query(
        r#"
        INSERT INTO ctfzone.config (key,value)
        VALUES ('user_mode',$1)
        ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value
        "#,
    )
    .bind(target_mode)
    .execute(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?;
    Ok(())
}

async fn insert_audit_event(
    transaction: &mut Transaction<'_, Postgres>,
    actor_user_id: i32,
    source_mode: &str,
    target_mode: &str,
    affected: &AffectedCounts,
) -> Result<(), ApiError> {
    let affected = serde_json::to_value(affected)
        .map_err(|_| ApiError::service_unavailable("Transition audit serialization failed"))?;
    sqlx::query(
        r#"
        INSERT INTO ctfzone.user_mode_transitions
            (actor_user_id,source_mode,target_mode,affected)
        VALUES ($1,$2,$3,$4)
        "#,
    )
    .bind(actor_user_id)
    .bind(source_mode)
    .bind(target_mode)
    .bind(affected)
    .execute(&mut **transaction)
    .await
    .map_err(map_transition_database_error)?;
    Ok(())
}

fn parse_mode(value: &str) -> Result<&'static str, ApiError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "users" => Ok("users"),
        "teams" => Ok("teams"),
        _ => Err(ApiError::bad_request(
            "Target mode must be either users or teams",
        )),
    }
}

fn confirmation_phrase(target_mode: &str) -> String {
    format!("SWITCH TO {}", target_mode.to_ascii_uppercase())
}

fn mode_label(mode: &str) -> &'static str {
    if mode == "teams" { "Team" } else { "User" }
}

fn sign_preview_token(secret_key: &str, claims: &PreviewTokenClaims) -> Result<String, ApiError> {
    let payload = serde_json::to_vec(claims)
        .map_err(|_| ApiError::service_unavailable("Transition preview signing failed"))?;
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let mut signer = HmacSha256::new_from_slice(secret_key.as_bytes())
        .map_err(|_| ApiError::service_unavailable("Transition preview signing failed"))?;
    signer.update(PREVIEW_TOKEN_CONTEXT);
    signer.update(b".");
    signer.update(payload.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(signer.finalize().into_bytes());
    Ok(format!("{payload}.{signature}"))
}

fn verify_preview_token(secret_key: &str, token: &str) -> Result<PreviewTokenClaims, ApiError> {
    let token = token.trim();
    if token.is_empty() || token.len() > PREVIEW_TOKEN_MAX_LENGTH {
        return Err(invalid_preview_token());
    }
    let mut segments = token.split('.');
    let (Some(payload), Some(signature), None) =
        (segments.next(), segments.next(), segments.next())
    else {
        return Err(invalid_preview_token());
    };
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid_preview_token())?;
    if URL_SAFE_NO_PAD.encode(&payload_bytes) != payload {
        return Err(invalid_preview_token());
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| invalid_preview_token())?;
    if URL_SAFE_NO_PAD.encode(&signature_bytes) != signature {
        return Err(invalid_preview_token());
    }
    let mut verifier =
        HmacSha256::new_from_slice(secret_key.as_bytes()).map_err(|_| invalid_preview_token())?;
    verifier.update(PREVIEW_TOKEN_CONTEXT);
    verifier.update(b".");
    verifier.update(payload.as_bytes());
    verifier
        .verify_slice(&signature_bytes)
        .map_err(|_| invalid_preview_token())?;

    let claims = serde_json::from_slice::<PreviewTokenClaims>(&payload_bytes)
        .map_err(|_| invalid_preview_token())?;
    let now = Utc::now().timestamp();
    if claims.version != PREVIEW_TOKEN_VERSION
        || !matches!(claims.source_mode.as_str(), "users" | "teams")
        || !matches!(claims.target_mode.as_str(), "users" | "teams")
        || claims.source_mode == claims.target_mode
        || claims.snapshot_fingerprint.len() != 64
        || !claims
            .snapshot_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || claims.issued_at > now + 30
        || claims.expires_at <= now
        || claims.expires_at <= claims.issued_at
        || claims.expires_at - claims.issued_at
            > Duration::minutes(PREVIEW_TOKEN_TTL_MINUTES).num_seconds()
    {
        return Err(invalid_preview_token());
    }
    Ok(claims)
}

fn invalid_preview_token() -> ApiError {
    ApiError::bad_request("The transition preview token is invalid or expired")
}

fn map_transition_database_error(error: sqlx::Error) -> ApiError {
    match error
        .as_database_error()
        .and_then(|database| database.code())
        .as_deref()
    {
        Some("55P03") => ApiError::conflict(
            "The transition could not obtain an exclusive database window; retry the preview",
        ),
        Some("57014") => ApiError::service_unavailable(
            "The transition exceeded its database statement window; refresh before retrying",
        ),
        _ => ApiError::database(error),
    }
}

fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response
}

fn require_admin(user: &CurrentUser) -> Result<(), ApiError> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(ApiError::forbidden("Administrator access is required"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts() -> AffectedCounts {
        AffectedCounts {
            participants: 12,
            teams: 3,
            memberships: 7,
            active_runtimes: 0,
            generated_flags: 6,
            shared_flag_events: 2,
            submissions: 40,
            solves: 5,
            awards: 2,
            unlocks: 8,
            tracking: 10,
            dynamic_challenges: 4,
            team_logic_challenges: 1,
            team_notifications: 2,
            team_field_entries: 4,
            team_comments: 3,
            team_objects: 1,
            user_objects: 2,
            sessions: 6,
            api_tokens: 2,
        }
    }

    fn claims() -> PreviewTokenClaims {
        let now = Utc::now().timestamp();
        PreviewTokenClaims {
            version: PREVIEW_TOKEN_VERSION,
            actor_user_id: 7,
            source_mode: "teams".to_owned(),
            target_mode: "users".to_owned(),
            affected: counts(),
            snapshot: counts(),
            snapshot_fingerprint: "a".repeat(64),
            issued_at: now,
            expires_at: now + 60,
        }
    }

    #[test]
    fn preview_token_round_trip_binds_every_claim() {
        let expected = claims();
        let token = sign_preview_token("test-secret", &expected).unwrap();
        let actual = verify_preview_token("test-secret", &token).unwrap();
        assert_eq!(actual.actor_user_id, expected.actor_user_id);
        assert_eq!(actual.source_mode, expected.source_mode);
        assert_eq!(actual.target_mode, expected.target_mode);
        assert_eq!(actual.affected, expected.affected);
        assert_eq!(actual.snapshot_fingerprint, expected.snapshot_fingerprint);
        assert_eq!(actual.expires_at, expected.expires_at);
    }

    #[test]
    fn preview_token_rejects_signature_or_payload_tampering() {
        let token = sign_preview_token("test-secret", &claims()).unwrap();
        assert!(verify_preview_token("other-secret", &token).is_err());
        let mut bytes = token.into_bytes();
        bytes[0] = if bytes[0] == b'A' { b'B' } else { b'A' };
        assert!(verify_preview_token("test-secret", &String::from_utf8(bytes).unwrap()).is_err());
    }

    #[test]
    fn preview_token_rejects_expired_claims() {
        let mut expired = claims();
        expired.issued_at = Utc::now().timestamp() - 120;
        expired.expires_at = Utc::now().timestamp() - 60;
        let token = sign_preview_token("test-secret", &expired).unwrap();
        assert!(verify_preview_token("test-secret", &token).is_err());
    }

    #[test]
    fn mode_and_confirmation_are_canonical() {
        assert_eq!(parse_mode(" TEAMS ").unwrap(), "teams");
        assert_eq!(confirmation_phrase("users"), "SWITCH TO USERS");
        assert!(parse_mode("individuals").is_err());
    }

    #[test]
    fn database_and_bff_time_budgets_leave_commit_headroom() {
        let authentication = std::hint::black_box(crate::auth::TRANSITION_AUTH_TIMEOUT_SECONDS);
        let activity = std::hint::black_box(crate::auth::TRANSITION_ACTIVITY_TIMEOUT_SECONDS);
        let precommit_statement = std::hint::black_box(PRECOMMIT_STATEMENT_TIMEOUT_SECONDS);
        let precommit = std::hint::black_box(PRECOMMIT_TIMEOUT_SECONDS);
        let preview_statement = std::hint::black_box(PREVIEW_STATEMENT_TIMEOUT_SECONDS);
        let preview = std::hint::black_box(PREVIEW_TIMEOUT_SECONDS);
        let lock = std::hint::black_box(TRANSITION_LOCK_TIMEOUT_SECONDS);
        let commit = std::hint::black_box(COMMIT_STATEMENT_TIMEOUT_SECONDS);
        let bff = std::hint::black_box(BFF_TRANSITION_TIMEOUT_SECONDS);
        let gunicorn = std::hint::black_box(GUNICORN_WORKER_TIMEOUT_SECONDS);
        let headroom = std::hint::black_box(REQUIRED_PROXY_HEADROOM_SECONDS);
        let preview_route_max = authentication + preview + activity;
        let execute_route_max = authentication + precommit + commit + activity;
        let api_route_max = preview_route_max.max(execute_route_max);

        assert!(precommit_statement < precommit);
        assert!(preview_statement < preview);
        assert!(lock < precommit);
        assert_eq!(preview_route_max, 51);
        assert_eq!(execute_route_max, 59);
        assert_eq!(api_route_max, 59);
        assert!(bff >= api_route_max + headroom);
        assert!(gunicorn >= bff + headroom);
    }

    #[test]
    fn transition_route_budget_covers_both_endpoints() {
        assert!(is_transition_route(
            "/api/v1/views/admin/user-mode-transition"
        ));
        assert!(is_transition_route("/api/v1/configs/user-mode-transition"));
        assert!(!is_transition_route("/api/v1/configs"));
    }

    #[test]
    fn token_bearing_responses_are_never_cacheable() {
        let response = no_store(Json(Success::new(())).into_response());
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );
    }

    #[test]
    fn switching_to_teams_reports_existing_team_cleanup() {
        let row = SnapshotRow {
            source_mode: "users".to_owned(),
            participants: 12,
            teams: 3,
            memberships: 7,
            active_runtimes: 0,
            generated_flags: 6,
            shared_flag_events: 2,
            submissions: 40,
            solves: 5,
            awards: 2,
            unlocks: 8,
            tracking: 10,
            dynamic_challenges: 4,
            team_logic_challenges: 1,
            team_notifications: 2,
            team_field_entries: 4,
            team_comments: 3,
            team_objects: 1,
            user_objects: 2,
            sessions: 6,
            api_tokens: 2,
            audit_ready: true,
            snapshot_fingerprint: "a".repeat(64),
        };
        let affected = row.affected("teams");
        assert_eq!(affected.teams, 3);
        assert_eq!(affected.memberships, 7);
        assert_eq!(affected.team_notifications, 2);
        assert_eq!(affected.team_objects, 1);
        assert_eq!(affected.user_objects, 2);
        assert_eq!(affected.submissions, 40);
        assert!(consequences(&row, "teams").0.is_empty());
    }

    #[test]
    fn active_runtimes_block_competition_mode_transitions() {
        let mut row = SnapshotRow {
            source_mode: "users".to_owned(),
            participants: 12,
            teams: 3,
            memberships: 7,
            active_runtimes: 1,
            generated_flags: 6,
            shared_flag_events: 2,
            submissions: 40,
            solves: 5,
            awards: 2,
            unlocks: 8,
            tracking: 10,
            dynamic_challenges: 4,
            team_logic_challenges: 1,
            team_notifications: 2,
            team_field_entries: 4,
            team_comments: 3,
            team_objects: 1,
            user_objects: 2,
            sessions: 6,
            api_tokens: 2,
            audit_ready: true,
            snapshot_fingerprint: "a".repeat(64),
        };
        let (blockers, _) = consequences(&row, "teams");
        assert_eq!(blockers.len(), 1);
        assert_eq!(blockers[0].code, "active_runtimes");
        assert_eq!(blockers[0].count, 1);

        row.active_runtimes = 0;
        assert!(consequences(&row, "teams").0.is_empty());
    }
}
