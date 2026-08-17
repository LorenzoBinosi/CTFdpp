use axum::http::HeaderMap;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Transaction};

use crate::error::ApiError;

pub(super) const CATEGORY_CREATE: &str = "challenge-category.create";
pub(super) const CHALLENGE_CREATE: &str = "challenge.create";

pub(super) struct CreateRequest {
    actor_user_id: i32,
    operation: &'static str,
    key: String,
    request_sha256: [u8; 32],
}

impl CreateRequest {
    pub(super) async fn lock_and_replay(
        transaction: &mut Transaction<'_, Postgres>,
        headers: &HeaderMap,
        actor_user_id: i32,
        operation: &'static str,
        request: &Value,
    ) -> Result<(Self, Option<Value>), ApiError> {
        let key = required_key(headers)?;
        let request_sha256 = canonical_digest(request);
        let lock_key = advisory_key(actor_user_id, operation, &key);
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut **transaction)
            .await
            .map_err(ApiError::database)?;

        let stored = sqlx::query_as::<_, (Vec<u8>, Value)>(
            r#"
            SELECT request_sha256,response_data
            FROM ctfzone.admin_create_idempotency
            WHERE actor_user_id=$1 AND operation=$2 AND idempotency_key=$3
            "#,
        )
        .bind(actor_user_id)
        .bind(operation)
        .bind(&key)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
        let replay = if let Some((stored_sha256, response_data)) = stored {
            if stored_sha256.as_slice() != request_sha256 {
                return Err(ApiError::conflict(
                    "Idempotency-Key was already used for different create data",
                ));
            }
            Some(response_data)
        } else {
            None
        };
        Ok((
            Self {
                actor_user_id,
                operation,
                key,
                request_sha256,
            },
            replay,
        ))
    }

    pub(super) async fn complete(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        resource_id: i32,
        response_data: &Value,
    ) -> Result<(), ApiError> {
        sqlx::query(
            r#"
            INSERT INTO ctfzone.admin_create_idempotency
                (actor_user_id,operation,idempotency_key,request_sha256,resource_id,response_data)
            VALUES ($1,$2,$3,$4,$5,$6)
            "#,
        )
        .bind(self.actor_user_id)
        .bind(self.operation)
        .bind(&self.key)
        .bind(self.request_sha256.as_slice())
        .bind(resource_id)
        .bind(response_data)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
        Ok(())
    }
}

pub(super) async fn forget_resource(
    transaction: &mut Transaction<'_, Postgres>,
    operation: &'static str,
    resource_id: i32,
) -> Result<(), ApiError> {
    sqlx::query(
        "DELETE FROM ctfzone.admin_create_idempotency WHERE operation=$1 AND resource_id=$2",
    )
    .bind(operation)
    .bind(resource_id)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    Ok(())
}

fn required_key(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers
        .get("idempotency-key")
        .ok_or_else(|| ApiError::bad_request("Idempotency-Key header is required"))?
        .to_str()
        .map_err(|_| ApiError::bad_request("Invalid Idempotency-Key header"))?
        .trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(ApiError::bad_request("Invalid Idempotency-Key header"));
    }
    Ok(value.to_owned())
}

fn advisory_key(actor_user_id: i32, operation: &str, key: &str) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(b"ctfzone/admin-create-idempotency-lock/v1");
    hasher.update(actor_user_id.to_be_bytes());
    hasher.update(operation.as_bytes());
    hasher.update([0]);
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    i64::from_be_bytes(digest[..8].try_into().expect("SHA-256 has eight bytes"))
}

fn canonical_digest(value: &Value) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ctfzone/admin-create-request/v1");
    hash_value(&mut hasher, value);
    hasher.finalize().into()
}

fn hash_value(hasher: &mut Sha256, value: &Value) {
    match value {
        Value::Null => hasher.update([0]),
        Value::Bool(value) => hasher.update([1, u8::from(*value)]),
        Value::Number(value) => {
            hasher.update([2]);
            hash_bytes(hasher, value.to_string().as_bytes());
        }
        Value::String(value) => {
            hasher.update([3]);
            hash_bytes(hasher, value.as_bytes());
        }
        Value::Array(values) => {
            hasher.update([4]);
            hasher.update((values.len() as u64).to_be_bytes());
            for value in values {
                hash_value(hasher, value);
            }
        }
        Value::Object(values) => {
            hasher.update([5]);
            hasher.update((values.len() as u64).to_be_bytes());
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for key in keys {
                hash_bytes(hasher, key.as_bytes());
                hash_value(hasher, &values[key]);
            }
        }
    }
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use serde_json::json;

    use super::*;

    #[test]
    fn request_hash_is_canonical_for_object_key_order() {
        assert_eq!(
            canonical_digest(&json!({"name":"x","flag":{"type":"static","content":"f"}})),
            canonical_digest(
                &serde_json::from_str(r#"{"flag":{"content":"f","type":"static"},"name":"x"}"#)
                    .unwrap()
            )
        );
        assert_ne!(
            canonical_digest(&json!({"name":"x"})),
            canonical_digest(&json!({"name":"y"}))
        );
    }

    #[test]
    fn create_key_is_required_and_bounded() {
        let mut headers = HeaderMap::new();
        assert!(required_key(&headers).is_err());
        headers.insert("idempotency-key", HeaderValue::from_static("create-1"));
        assert_eq!(required_key(&headers).unwrap(), "create-1");
        headers.insert(
            "idempotency-key",
            HeaderValue::from_str(&"x".repeat(129)).unwrap(),
        );
        assert!(required_key(&headers).is_err());
    }

    #[test]
    fn advertised_create_headers_are_consumed_before_writes() {
        let categories = include_str!("administration.rs");
        let category = categories
            .split_once("pub(super) async fn create_challenge_category(")
            .unwrap()
            .1
            .split_once("pub(super) async fn delete_challenge_category(")
            .unwrap()
            .0;
        let challenges = include_str!("challenges.rs");
        let challenge = challenges
            .split_once("pub(super) async fn create(")
            .unwrap()
            .1
            .split_once("pub(super) async fn detail(")
            .unwrap()
            .0;
        for (segment, write) in [
            (category, "INSERT INTO ctfzone.challenge_categories"),
            (challenge, "INSERT INTO ctfzone.challenges"),
        ] {
            let replay = segment.find("lock_and_replay").unwrap();
            let write = segment.find(write).unwrap();
            let complete = segment.find(".complete(").unwrap();
            let commit = segment.rfind("transaction.commit()").unwrap();
            assert!(replay < write && write < complete && complete < commit);
        }
    }
}
