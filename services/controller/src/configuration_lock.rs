use anyhow::Result;
use sqlx::{PgPool, Postgres, Transaction};

/// Shared with the API's destructive user-mode transition. Runtime state
/// transactions take the shared lock before row locks or writes; the transition
/// takes the exclusive form so neither side can observe a half-transitioned
/// configuration.
pub(crate) const CONFIGURATION_LOCK_KEY: i64 = 0x4354_465A;

pub(crate) async fn begin_configuration_shared_transaction(
    pool: &PgPool,
) -> Result<Transaction<'_, Postgres>> {
    let mut transaction = pool.begin().await?;
    lock_configuration_shared(&mut transaction).await?;
    Ok(transaction)
}

pub(crate) async fn lock_configuration_shared(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock_shared($1)")
        .bind(CONFIGURATION_LOCK_KEY)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_key_matches_the_api_configuration_fence() {
        assert_eq!(CONFIGURATION_LOCK_KEY, 0x4354_465A);
    }
}
