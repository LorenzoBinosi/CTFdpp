use sqlx::{PgPool, Postgres, Transaction};

use crate::error::ApiError;

pub(crate) const COMPLETED_MARKER_KEY: &str = "setup";

const SETUP_STATE_SQL: &str = r#"
    SELECT
        EXISTS(SELECT 1 FROM ctfzone.users WHERE type = 'admin'),
        EXISTS(
            SELECT 1
            FROM ctfzone.config
            WHERE key = 'setup'
              AND lower(btrim(COALESCE(value, ''))) IN ('1', 'true', 'yes', 'on')
        )
"#;

// Shared by first-install and administrator-invariant mutations so concurrent API
// replicas cannot both remove the final active administrator.
const SETUP_INVARIANT_LOCK: i64 = 0x0043_5446_5A4F_4E45_i64;

pub(crate) async fn is_complete(database: &PgPool) -> Result<bool, ApiError> {
    let (admin_exists, marker_exists) = sqlx::query_as::<_, (bool, bool)>(SETUP_STATE_SQL)
        .fetch_one(database)
        .await
        .map_err(ApiError::database)?;
    Ok(completion_state(admin_exists, marker_exists))
}

pub(crate) async fn is_complete_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<bool, ApiError> {
    let (admin_exists, marker_exists) = sqlx::query_as::<_, (bool, bool)>(SETUP_STATE_SQL)
        .fetch_one(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    Ok(completion_state(admin_exists, marker_exists))
}

pub(crate) async fn lock_invariant(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(SETUP_INVARIANT_LOCK)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    Ok(())
}

pub(crate) async fn mark_complete(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO ctfzone.config (key,value) VALUES ($1,'true') \
         ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
    )
    .bind(COMPLETED_MARKER_KEY)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    Ok(())
}

pub(crate) async fn guard_admin_update(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i32,
    requested_type: Option<&str>,
    requested_banned: Option<bool>,
) -> Result<(), ApiError> {
    lock_invariant(transaction).await?;
    let current = sqlx::query_as::<_, (Option<String>, bool)>(
        "SELECT type,COALESCE(banned,false) FROM ctfzone.users WHERE id=$1",
    )
    .bind(user_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?;

    let Some((current_type, current_banned)) = current else {
        return Ok(());
    };
    if would_deactivate_admin(
        current_type.as_deref(),
        current_banned,
        requested_type,
        requested_banned,
    ) {
        require_another_active_admin(transaction, user_id).await?;
    }
    Ok(())
}

pub(crate) async fn guard_admin_delete(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: i32,
) -> Result<(), ApiError> {
    lock_invariant(transaction).await?;
    let is_active_admin = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM ctfzone.users
            WHERE id=$1 AND type='admin' AND NOT COALESCE(banned,false)
        )
        "#,
    )
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    if is_active_admin {
        require_another_active_admin(transaction, user_id).await?;
    }
    Ok(())
}

async fn require_another_active_admin(
    transaction: &mut Transaction<'_, Postgres>,
    excluded_user_id: i32,
) -> Result<(), ApiError> {
    let another_exists = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM ctfzone.users
            WHERE id<>$1 AND type='admin' AND NOT COALESCE(banned,false)
        )
        "#,
    )
    .bind(excluded_user_id)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    if !another_exists {
        return Err(ApiError::conflict(
            "At least one active administrator is required",
        ));
    }
    Ok(())
}

fn completion_state(admin_exists: bool, marker_exists: bool) -> bool {
    admin_exists || marker_exists
}

fn would_deactivate_admin(
    current_type: Option<&str>,
    current_banned: bool,
    requested_type: Option<&str>,
    requested_banned: Option<bool>,
) -> bool {
    let currently_active = current_type == Some("admin") && !current_banned;
    let resulting_type = requested_type.or(current_type);
    let resulting_banned = requested_banned.unwrap_or(current_banned);
    currently_active && (resulting_type != Some("admin") || resulting_banned)
}

pub(crate) fn is_required(setup_complete: bool) -> bool {
    !setup_complete
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_marker_keeps_setup_closed_without_an_administrator() {
        assert!(!is_required(completion_state(false, true)));
        assert!(!is_required(completion_state(true, false)));
        assert!(!is_required(completion_state(true, true)));
        assert!(is_required(completion_state(false, false)));
        assert!(SETUP_STATE_SQL.contains("ctfzone.config"));
    }

    #[test]
    fn detects_only_active_admin_deactivation() {
        assert!(would_deactivate_admin(
            Some("admin"),
            false,
            Some("user"),
            None
        ));
        assert!(would_deactivate_admin(
            Some("admin"),
            false,
            None,
            Some(true)
        ));
        assert!(!would_deactivate_admin(
            Some("admin"),
            false,
            None,
            Some(false)
        ));
        assert!(!would_deactivate_admin(
            Some("admin"),
            true,
            Some("user"),
            None
        ));
        assert!(!would_deactivate_admin(
            Some("user"),
            false,
            None,
            Some(true)
        ));
    }
}
