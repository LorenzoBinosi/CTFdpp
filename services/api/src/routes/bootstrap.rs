use std::collections::HashMap;

use axum::{Json, extract::State};
use serde::Serialize;

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
    routes::Success,
};

const PUBLIC_CONFIG_KEYS: &[&str] = &[
    "ctf_name",
    "ctf_description",
    "user_mode",
    "start",
    "end",
    "paused",
    "challenge_visibility",
    "score_visibility",
    "account_visibility",
    "registration_visibility",
];

#[derive(Serialize)]
pub(super) struct BootstrapData {
    setup_required: bool,
    authenticated: bool,
    csrf_token: Option<String>,
    user: Option<BootstrapUser>,
    site: SiteConfig,
}

#[derive(Serialize)]
struct BootstrapUser {
    id: i32,
    name: Option<String>,
    email: Option<String>,
    #[serde(rename = "type")]
    user_type: String,
    team_id: Option<i32>,
    verified: bool,
}

#[derive(Serialize)]
struct SiteConfig {
    name: String,
    description: String,
    user_mode: String,
    start: Option<String>,
    end: Option<String>,
    paused: bool,
    challenge_visibility: String,
    score_visibility: String,
    account_visibility: String,
    registration_visibility: String,
}

pub(super) async fn get(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
) -> Result<Json<Success<BootstrapData>>, ApiError> {
    let setup_required =
        crate::setup::is_required(crate::setup::is_complete(&state.database).await?);

    let keys = PUBLIC_CONFIG_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect::<Vec<_>>();
    let rows = sqlx::query_as::<_, (Option<String>, Option<String>)>(
        "SELECT key,value FROM ctfzone.config WHERE key=ANY($1) ORDER BY id",
    )
    .bind(keys)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    let mut configs = HashMap::new();
    for (key, value) in rows {
        if let Some(key) = key {
            configs.entry(key).or_insert(value.unwrap_or_default());
        }
    }

    let authenticated = user.is_some();
    let csrf_token = user
        .as_ref()
        .and_then(CurrentUser::csrf_token)
        .map(str::to_owned);
    let user = user.map(|user| BootstrapUser {
        id: user.id,
        name: user.name,
        email: user.email,
        user_type: user.user_type,
        team_id: user.team_id,
        verified: user.verified,
    });

    Ok(Json(Success::new(BootstrapData {
        setup_required,
        authenticated,
        csrf_token,
        user,
        site: SiteConfig {
            name: config(&configs, "ctf_name", "CTFZone"),
            description: config(&configs, "ctf_description", ""),
            user_mode: config(&configs, "user_mode", "users"),
            start: optional_config(&configs, "start"),
            end: optional_config(&configs, "end"),
            paused: config_bool(&configs, "paused", false),
            challenge_visibility: config(&configs, "challenge_visibility", "private"),
            score_visibility: config(&configs, "score_visibility", "public"),
            account_visibility: config(&configs, "account_visibility", "public"),
            registration_visibility: config(&configs, "registration_visibility", "public"),
        },
    })))
}

fn config(configs: &HashMap<String, String>, key: &str, default: &str) -> String {
    configs
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| default.to_owned())
}

fn optional_config(configs: &HashMap<String, String>, key: &str) -> Option<String> {
    configs.get(key).filter(|value| !value.is_empty()).cloned()
}

fn config_bool(configs: &HashMap<String, String>, key: &str, default: bool) -> bool {
    configs
        .get(key)
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_config_defaults_are_stable() {
        let configs = HashMap::new();
        assert_eq!(config(&configs, "ctf_name", "CTFZone"), "CTFZone");
        assert!(!config_bool(&configs, "paused", false));
        assert_eq!(optional_config(&configs, "start"), None);
    }
}
