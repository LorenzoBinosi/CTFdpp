use axum::{
    Json,
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use chrono::{Duration, NaiveDate, NaiveDateTime, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::FromRow;

use crate::{
    AppState,
    auth::{CurrentUser, require_verified_email},
    error::ApiError,
    routes::Success,
};

#[derive(FromRow, Serialize)]
pub(super) struct TokenListItem {
    id: i32,
    #[serde(rename = "type")]
    token_type: Option<String>,
    expiration: Option<NaiveDateTime>,
}

#[derive(FromRow)]
struct TokenRow {
    id: i32,
    token_type: Option<String>,
    user_id: Option<i32>,
    created: Option<NaiveDateTime>,
    expiration: Option<NaiveDateTime>,
    description: Option<String>,
    value: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct CreateTokenRequest {
    expiration: Option<String>,
    description: Option<String>,
}

#[derive(Serialize)]
pub(super) struct SimpleSuccess {
    success: bool,
}

pub(super) async fn list_tokens(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Success<Vec<TokenListItem>>>, ApiError> {
    require_verified_email(&state.database, &user).await?;

    let tokens = sqlx::query_as::<_, TokenListItem>(
        r#"
        SELECT id, type AS token_type, expiration
        FROM ctfzone.tokens
        WHERE user_id = $1
        ORDER BY id
        "#,
    )
    .bind(user.id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;

    Ok(Json(Success::new(tokens)))
}

pub(super) async fn create_token(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<CreateTokenRequest>,
) -> Result<Response, ApiError> {
    require_verified_email(&state.database, &user).await?;

    let expiration = match request.expiration {
        Some(value) => NaiveDate::parse_from_str(&value, "%Y-%m-%d")
            .map_err(|_| ApiError::bad_request("expiration must use YYYY-MM-DD"))?
            .and_hms_opt(0, 0, 0)
            .ok_or_else(|| ApiError::bad_request("expiration is invalid"))?,
        None => Utc::now().naive_utc() + Duration::days(30),
    };

    let mut random = [0_u8; 32];
    OsRng.fill_bytes(&mut random);
    let value = format!("ctfzone_{}", hex::encode(random));

    let token = sqlx::query_as::<_, TokenRow>(
        r#"
        INSERT INTO ctfzone.tokens (type, user_id, created, expiration, description, value)
        VALUES ('user', $1, CURRENT_TIMESTAMP AT TIME ZONE 'UTC', $2, $3, $4)
        RETURNING
            id,
            type AS token_type,
            user_id,
            created,
            expiration,
            description,
            value
        "#,
    )
    .bind(user.id)
    .bind(expiration)
    .bind(request.description)
    .bind(value)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;

    Ok(Json(Success::new(admin_view(&token))).into_response())
}

pub(super) async fn get_token(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(token_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_verified_email(&state.database, &user).await?;
    let token = find_visible_token(&state, &user, token_id).await?;

    let data = if user.is_admin() {
        admin_view(&token)
    } else {
        user_view(&token)
    };
    Ok(Json(Success::new(data)).into_response())
}

pub(super) async fn delete_token(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(token_id): Path<i32>,
) -> Result<Json<SimpleSuccess>, ApiError> {
    require_verified_email(&state.database, &user).await?;
    let token = find_visible_token(&state, &user, token_id).await?;

    sqlx::query("DELETE FROM ctfzone.tokens WHERE id = $1")
        .bind(token.id)
        .execute(&state.database)
        .await
        .map_err(ApiError::database)?;

    Ok(Json(SimpleSuccess { success: true }))
}

async fn find_visible_token(
    state: &AppState,
    user: &CurrentUser,
    token_id: i32,
) -> Result<TokenRow, ApiError> {
    sqlx::query_as::<_, TokenRow>(
        r#"
        SELECT
            id,
            type AS token_type,
            user_id,
            created,
            expiration,
            description,
            value
        FROM ctfzone.tokens
        WHERE id = $1
          AND ($2 OR user_id = $3)
        "#,
    )
    .bind(token_id)
    .bind(user.is_admin())
    .bind(user.id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Token not found"))
}

fn admin_view(token: &TokenRow) -> serde_json::Value {
    json!({
        "id": token.id,
        "type": token.token_type,
        "user_id": token.user_id,
        "created": token.created,
        "expiration": token.expiration,
        "description": token.description,
        "value": token.value,
    })
}

fn user_view(token: &TokenRow) -> serde_json::Value {
    json!({
        "id": token.id,
        "type": token.token_type,
        "created": token.created,
        "expiration": token.expiration,
        "description": token.description,
    })
}
