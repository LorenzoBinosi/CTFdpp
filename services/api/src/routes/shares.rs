use axum::{
    Json,
    extract::State,
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha1::Sha1;

use crate::{AppState, auth::CurrentUser, error::ApiError, routes::Success};

#[derive(Deserialize)]
pub(super) struct ShareInput {
    #[serde(rename = "type")]
    share_type: String,
    challenge_id: i32,
    user_id: Option<i32>,
}

pub(super) async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<ShareInput>,
) -> Result<Response, ApiError> {
    if request.share_type != "solve" || request.challenge_id <= 0 {
        return Err(ApiError::bad_request("Unsupported share type"));
    }
    if request.user_id.is_some_and(|user_id| user_id != user.id) {
        return Err(ApiError::forbidden("A user can only share their own solve"));
    }
    let social_shares = sqlx::query_scalar::<_, String>(
        "SELECT value FROM ctfzone.config WHERE key='social_shares' ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .is_none_or(|value| {
        !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "false" | "0" | "off"
        )
    });
    if !social_shares {
        return Err(ApiError::forbidden("Social sharing is disabled"));
    }
    let team_mode = super::challenges::is_team_mode(&state).await?;
    let solved = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM ctfzone.submissions s
            JOIN ctfzone.solves solved ON solved.id=s.id
            WHERE s.challenge_id=$1
              AND (($2 AND s.team_id=$3) OR (NOT $2 AND s.user_id=$4))
        )
        "#,
    )
    .bind(request.challenge_id)
    .bind(team_mode)
    .bind(user.team_id)
    .bind(user.id)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    if !solved {
        return Err(ApiError::not_found("Solve not found"));
    }

    let message = format!("solve-{}-{}", user.id, request.challenge_id);
    let mut signer = Hmac::<Sha1>::new_from_slice(state.auth.secret_key.as_bytes())
        .map_err(|_| ApiError::upstream("Share signing is unavailable"))?;
    signer.update(message.as_bytes());
    let mac = hex::encode(signer.finalize().into_bytes());
    let mut url = state.public_base_url.clone();
    url.set_path("/share/solve");
    url.set_query(None);
    url.query_pairs_mut()
        .append_pair("user_id", &user.id.to_string())
        .append_pair("challenge_id", &request.challenge_id.to_string())
        .append_pair("mac", &mac);
    Ok(Json(Success::new(json!({"url": url.as_str()}))).into_response())
}
