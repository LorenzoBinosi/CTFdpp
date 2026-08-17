use std::collections::HashMap;

use axum::{Json, extract::State};
use serde::Serialize;

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
    routes::Success,
};

const BOOTSTRAP_CONFIG_KEYS: &[&str] = &[
    "ctf_name",
    "ctf_description",
    "player_frontend",
    "user_mode",
    "team_creation",
    "team_size",
    "num_teams",
    "start",
    "end",
    "paused",
    "challenge_visibility",
    "score_visibility",
    "account_visibility",
    "registration_visibility",
    "registration_access_mode",
];

#[derive(Serialize)]
pub(super) struct BootstrapData {
    setup_required: bool,
    authenticated: bool,
    user: Option<BootstrapUser>,
    site: SiteConfig,
}

#[derive(Serialize)]
pub(super) struct BootstrapUser {
    id: i32,
    name: Option<String>,
    email: Option<String>,
    #[serde(rename = "type")]
    user_type: String,
    team_id: Option<i32>,
    verified: bool,
    score: i64,
    place: Option<String>,
}

#[derive(Serialize)]
pub(super) struct SiteConfig {
    name: String,
    description: String,
    player_frontend: String,
    user_mode: String,
    team_creation: bool,
    team_size: i64,
    num_teams: i64,
    start: Option<String>,
    end: Option<String>,
    paused: bool,
    challenge_visibility: String,
    score_visibility: String,
    account_visibility: String,
    registration_visibility: String,
    registration_access_mode: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScoreAccount {
    User(i32),
    Team(i32),
}

pub(super) async fn get(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
) -> Result<Json<Success<BootstrapData>>, ApiError> {
    Ok(Json(Success::new(data(&state, user).await?)))
}

pub(super) async fn data(
    state: &AppState,
    user: Option<CurrentUser>,
) -> Result<BootstrapData, ApiError> {
    let setup_required =
        crate::setup::is_required(crate::setup::is_complete(&state.database).await?);

    let keys = BOOTSTRAP_CONFIG_KEYS
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

    let user_mode = config(&configs, "user_mode", "users");
    let registration_access_mode = crate::browser_auth::effective_registration_access_mode(
        configs.get("registration_access_mode").map(String::as_str),
    )
    .to_owned();
    let authenticated = user.is_some();
    let user = if let Some(user) = user {
        let score = current_score(state, score_account(&user_mode, user.id, user.team_id)).await?;
        Some(BootstrapUser {
            id: user.id,
            name: user.name,
            email: user.email,
            user_type: user.user_type,
            team_id: user.team_id,
            verified: user.verified,
            score,
            place: None,
        })
    } else {
        None
    };

    Ok(BootstrapData {
        setup_required,
        authenticated,
        user,
        site: SiteConfig {
            name: config(&configs, "ctf_name", crate::browser_auth::DEFAULT_CTF_NAME),
            description: config(&configs, "ctf_description", ""),
            player_frontend: config(
                &configs,
                "player_frontend",
                crate::browser_auth::DEFAULT_PLAYER_FRONTEND,
            ),
            user_mode,
            team_creation: config_bool(&configs, "team_creation", true),
            team_size: config_i64(&configs, "team_size", 0),
            num_teams: config_i64(&configs, "num_teams", 0),
            start: optional_config(&configs, "start"),
            end: optional_config(&configs, "end"),
            paused: config_bool(&configs, "paused", false),
            challenge_visibility: config(&configs, "challenge_visibility", "private"),
            score_visibility: config(&configs, "score_visibility", "public"),
            account_visibility: config(&configs, "account_visibility", "public"),
            registration_visibility: config(&configs, "registration_visibility", "public"),
            registration_access_mode,
        },
    })
}

fn score_account(user_mode: &str, user_id: i32, team_id: Option<i32>) -> Option<ScoreAccount> {
    if user_mode == "teams" {
        team_id.map(ScoreAccount::Team)
    } else {
        Some(ScoreAccount::User(user_id))
    }
}

async fn current_score(state: &AppState, account: Option<ScoreAccount>) -> Result<i64, ApiError> {
    let Some(account) = account else {
        return Ok(0);
    };
    let (column, account_id) = match account {
        ScoreAccount::User(id) => ("user_id", id),
        ScoreAccount::Team(id) => ("team_id", id),
    };
    let query = format!(
        r#"
        SELECT
            COALESCE((
                SELECT SUM(challenges.value)::bigint
                FROM ctfzone.solves
                JOIN ctfzone.challenges ON challenges.id = solves.challenge_id
                WHERE solves.{column} = $1
            ), 0)
            + COALESCE((
                SELECT SUM(awards.value)::bigint
                FROM ctfzone.awards
                WHERE awards.{column} = $1
            ), 0)
        "#
    );
    sqlx::query_scalar::<_, i64>(&query)
        .bind(account_id)
        .fetch_one(&state.database)
        .await
        .map_err(ApiError::database)
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

fn config_i64(configs: &HashMap<String, String>, key: &str, default: i64) -> i64 {
    configs
        .get(key)
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    #[test]
    fn bootstrap_contract_has_shell_score_but_no_csrf_token() {
        let value = serde_json::to_value(BootstrapData {
            setup_required: false,
            authenticated: true,
            user: Some(BootstrapUser {
                id: 1,
                name: Some("admin".to_owned()),
                email: Some("admin@example.test".to_owned()),
                user_type: "admin".to_owned(),
                team_id: None,
                verified: true,
                score: 42,
                place: None,
            }),
            site: SiteConfig {
                name: "CTFZone".to_owned(),
                description: String::new(),
                player_frontend: "terminal".to_owned(),
                user_mode: "users".to_owned(),
                team_creation: true,
                team_size: 0,
                num_teams: 0,
                start: None,
                end: None,
                paused: false,
                challenge_visibility: "private".to_owned(),
                score_visibility: "public".to_owned(),
                account_visibility: "public".to_owned(),
                registration_visibility: "public".to_owned(),
                registration_access_mode: "access_code".to_owned(),
            },
        })
        .expect("bootstrap serializes");
        assert!(value.get("csrf_token").is_none());
        assert_eq!(value["user"]["score"], 42);
        assert!(value["user"]["place"].is_null());
        assert_eq!(value["site"]["player_frontend"], "terminal");
        assert_eq!(value["site"]["registration_access_mode"], "access_code");
        assert_eq!(value["site"]["team_creation"], true);
        assert_eq!(value["site"]["team_size"], 0);
        assert_eq!(value["site"]["num_teams"], 0);
        assert!(value["site"].get("registration_code").is_none());
        assert!(value["site"].get("domain_whitelist").is_none());
        assert!(value["site"].get("domain_blacklist").is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_config_defaults_are_stable() {
        let configs = HashMap::new();
        assert_eq!(
            config(&configs, "ctf_name", crate::browser_auth::DEFAULT_CTF_NAME,),
            "CTFZone"
        );
        assert_eq!(
            config(
                &configs,
                "player_frontend",
                crate::browser_auth::DEFAULT_PLAYER_FRONTEND,
            ),
            "terminal"
        );
        assert!(!config_bool(&configs, "paused", false));
        assert!(config_bool(&configs, "team_creation", true));
        assert_eq!(config_i64(&configs, "team_size", 0), 0);
        assert_eq!(optional_config(&configs, "start"), None);
    }

    #[test]
    fn bootstrap_score_uses_the_active_account_mode() {
        assert_eq!(
            score_account("users", 7, Some(11)),
            Some(ScoreAccount::User(7))
        );
        assert_eq!(
            score_account("teams", 7, Some(11)),
            Some(ScoreAccount::Team(11))
        );
        assert_eq!(score_account("teams", 7, None), None);
    }
}
