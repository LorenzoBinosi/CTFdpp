use std::{
    collections::{HashMap, HashSet},
    time::Duration as StdDuration,
};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::{Duration, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::{FromRow, Postgres, QueryBuilder, Transaction};

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
    routes::Success,
};

#[derive(Deserialize, Default)]
pub(super) struct ChallengeListQuery {
    name: Option<String>,
    max_attempts: Option<i32>,
    value: Option<i32>,
    category: Option<String>,
    #[serde(rename = "type")]
    challenge_type: Option<String>,
    state: Option<String>,
    q: Option<String>,
    field: Option<String>,
    view: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct AttemptQuery {
    preview: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct AttemptRequest {
    challenge_id: i32,
    submission: String,
}

#[derive(FromRow)]
struct ChallengeListRow {
    id: i32,
    name: Option<String>,
    value: Option<i32>,
    category: Option<String>,
    challenge_type: Option<String>,
    position: i32,
    requirements: Option<Value>,
    runtime_available: bool,
}

#[derive(FromRow)]
struct ChallengeAttemptRow {
    id: i32,
    challenge_type: Option<String>,
    state: String,
    logic: String,
    max_attempts: Option<i32>,
    function: Option<String>,
    initial: Option<i32>,
    minimum: Option<i32>,
    decay: Option<i32>,
    requirements: Option<Value>,
}

#[derive(FromRow, Serialize)]
struct ChallengeDetailRow {
    id: i32,
    name: Option<String>,
    description: Option<String>,
    attribution: Option<String>,
    connection_info: Option<String>,
    next_id: Option<i32>,
    max_attempts: Option<i32>,
    value: Option<i32>,
    category: Option<String>,
    #[serde(rename = "type")]
    challenge_type: Option<String>,
    state: String,
    logic: String,
    initial: Option<i32>,
    minimum: Option<i32>,
    decay: Option<i32>,
    position: i32,
    function: Option<String>,
    requirements: Option<Value>,
}

#[derive(FromRow, Serialize)]
struct HintRenderRow {
    id: i32,
    title: Option<String>,
    cost: Option<i32>,
    content: Option<String>,
    unlocked: bool,
}

#[derive(FromRow)]
struct FileRenderRow {
    id: i32,
    location: Option<String>,
    sha1sum: Option<String>,
}

#[derive(Serialize)]
struct ChallengeFileView {
    id: i32,
    name: String,
    url: String,
    sha1sum: Option<String>,
}

#[derive(FromRow)]
struct FlagRow {
    id: i32,
    flag_type: Option<String>,
    content: Option<String>,
    data: Option<String>,
}

#[derive(Clone, Copy)]
enum Account {
    User(i32),
    Team(i32),
}

impl Account {
    fn id(self) -> i32 {
        match self {
            Self::User(id) | Self::Team(id) => id,
        }
    }
}

enum FlagResult {
    Correct,
    Partial,
    Incorrect(String),
}

pub(super) async fn list(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Query(query): Query<ChallengeListQuery>,
) -> Result<Response, ApiError> {
    require_challenge_visibility(&state, user.as_ref()).await?;
    require_ctf_time(&state, user.as_ref()).await?;
    require_verified(&state, user.as_ref()).await?;

    let admin_view =
        user.as_ref().is_some_and(CurrentUser::is_admin) && query.view.as_deref() == Some("admin");
    let team_mode = is_team_mode(&state).await?;
    if team_mode
        && user
            .as_ref()
            .is_some_and(|current| !current.is_admin() && current.team_id.is_none())
    {
        return Err(ApiError::forbidden("Join a team before viewing challenges"));
    }

    let mut builder = QueryBuilder::<Postgres>::new(
        r#"
        SELECT c.id, c.name, c.value, c.category, c.type AS challenge_type,
               c.position, c.requirements,
               COALESCE(runtime_setting.enabled, false)
                   AND COALESCE(runtime_config.enabled, false)
                   AND runtime_config.runtime_mode = 'managed' AS runtime_available
        FROM ctfzone.challenges c
        LEFT JOIN ctfzone.challenge_runtime_configs runtime_config
               ON runtime_config.challenge_id = c.id
        LEFT JOIN ctfzone.runtime_settings runtime_setting
               ON runtime_setting.key = 'private_challenges'
        WHERE TRUE
        "#,
    );
    if !admin_view {
        builder.push(" AND c.state = 'visible'");
    }
    if let Some(value) = query.name {
        builder.push(" AND c.name = ").push_bind(value);
    }
    if let Some(value) = query.max_attempts {
        builder.push(" AND c.max_attempts = ").push_bind(value);
    }
    if let Some(value) = query.value {
        builder.push(" AND c.value = ").push_bind(value);
    }
    if let Some(value) = query.category {
        builder.push(" AND c.category = ").push_bind(value);
    }
    if let Some(value) = query.challenge_type {
        builder.push(" AND c.type = ").push_bind(value);
    }
    if let Some(value) = query.state {
        builder.push(" AND c.state = ").push_bind(value);
    }
    if let Some(search) = query.q.filter(|value| !value.trim().is_empty()) {
        let pattern = format!("%{}%", search.trim());
        match query.field.as_deref().unwrap_or("name") {
            "name" => builder.push(" AND c.name ILIKE ").push_bind(pattern),
            "description" => builder.push(" AND c.description ILIKE ").push_bind(pattern),
            "category" => builder.push(" AND c.category ILIKE ").push_bind(pattern),
            "type" => builder.push(" AND c.type ILIKE ").push_bind(pattern),
            "state" => builder.push(" AND c.state ILIKE ").push_bind(pattern),
            _ => return Err(ApiError::bad_request("Unsupported challenge search field")),
        };
    }
    builder.push(" ORDER BY c.category, c.position, c.id");

    let rows = builder
        .build_query_as::<ChallengeListRow>()
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    let solved = solved_challenge_ids(&state, user.as_ref(), team_mode).await?;
    let scores_visible = scores_and_accounts_visible(&state, user.as_ref()).await?;
    let solve_counts = if scores_visible {
        solve_counts(&state, team_mode, admin_view).await?
    } else {
        HashMap::new()
    };

    let mut response = Vec::with_capacity(rows.len());
    for row in rows {
        let tags = tags_for_challenge(&state, row.id).await?;
        if !requirements_met(row.requirements.as_ref(), &solved) && !admin_view {
            let anonymize = row
                .requirements
                .as_ref()
                .and_then(|value| value.get("anonymize"));
            if anonymize.is_some() {
                let preview = anonymize.and_then(Value::as_str) == Some("preview");
                response.push(json!({
                    "id": row.id,
                    "type": "hidden",
                    "name": if preview { row.name } else { Some("???".to_owned()) },
                    "value": if preview { row.value } else { Some(0) },
                    "solves": Value::Null,
                    "solved_by_me": false,
                    "category": if preview { row.category } else { Some("???".to_owned()) },
                    "tags": if preview { json!(tags) } else { json!([]) },
                    "runtime_available": false,
                }));
            }
            continue;
        }
        let challenge_type = row.challenge_type.as_deref().unwrap_or("standard");
        if challenge_type != "standard" && challenge_type != "dynamic" {
            continue;
        }
        response.push(json!({
            "id": row.id,
            "type": challenge_type,
            "name": row.name,
            "value": row.value,
            "position": row.position,
            "solves": if scores_visible { solve_counts.get(&row.id).copied().unwrap_or(0).into() } else { Value::Null },
            "solved_by_me": solved.contains(&row.id),
            "category": row.category,
            "tags": tags,
            "runtime_available": row.runtime_available,
        }));
    }

    Ok(Json(Success::new(response)).into_response())
}

pub(super) async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(payload): Json<Value>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let object = payload
        .as_object()
        .ok_or_else(|| ApiError::bad_request("Challenge data must be an object"))?;
    let name = required_string(object, "name", 80)?;
    let category = required_string(object, "category", 80)?;
    let challenge_type = optional_string(object, "type").unwrap_or_else(|| "standard".to_owned());
    if challenge_type != "standard" && challenge_type != "dynamic" {
        return Err(ApiError::bad_request("Unsupported challenge type"));
    }

    let function = optional_string(object, "function").unwrap_or_else(|| {
        if challenge_type == "dynamic" {
            "logarithmic".to_owned()
        } else {
            "static".to_owned()
        }
    });
    if !matches!(function.as_str(), "static" | "linear" | "logarithmic") {
        return Err(ApiError::bad_request(
            "Unsupported challenge decay function",
        ));
    }
    let dynamic = function != "static";
    let initial = if dynamic {
        optional_i32(object, "initial")?.or(optional_i32(object, "value")?)
    } else {
        None
    };
    let minimum = optional_i32(object, "minimum")?;
    let decay = optional_i32(object, "decay")?;
    if dynamic && (initial.is_none() || minimum.is_none() || decay.is_none()) {
        return Err(ApiError::bad_request(
            "Dynamic challenges require initial, minimum, and decay",
        ));
    }
    if dynamic && decay == Some(0) {
        return Err(ApiError::bad_request(
            "Challenge decay must be greater than zero",
        ));
    }
    let value = if dynamic {
        initial
    } else {
        optional_i32(object, "value")?
    }
    .ok_or_else(|| ApiError::bad_request("Challenge value is required"))?;
    let position = optional_i32(object, "position")?.unwrap_or(0);
    if !(0..=32767).contains(&position) {
        return Err(ApiError::bad_request("Challenge position is invalid"));
    }
    let state_value = optional_string(object, "state").unwrap_or_else(|| "visible".to_owned());
    if !matches!(state_value.as_str(), "visible" | "hidden" | "locked") {
        return Err(ApiError::bad_request("Unsupported challenge state"));
    }
    let logic = optional_string(object, "logic").unwrap_or_else(|| "any".to_owned());
    if !matches!(logic.as_str(), "any" | "all" | "team") {
        return Err(ApiError::bad_request("Unsupported challenge logic"));
    }
    let requirements = object.get("requirements").cloned();
    validate_requirements(requirements.as_ref())?;

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let id = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO ctfzone.challenges (
            name, description, attribution, connection_info, next_id,
            max_attempts, value, category, type, state, logic, initial,
            minimum, decay, position, function, requirements
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
            $13, $14, $15, $16, $17
        ) RETURNING id
        "#,
    )
    .bind(&name)
    .bind(optional_string(object, "description"))
    .bind(optional_string(object, "attribution"))
    .bind(optional_string(object, "connection_info"))
    .bind(optional_i32(object, "next_id")?)
    .bind(optional_i32(object, "max_attempts")?.unwrap_or(0))
    .bind(value)
    .bind(&category)
    .bind(&challenge_type)
    .bind(&state_value)
    .bind(&logic)
    .bind(initial)
    .bind(minimum)
    .bind(decay)
    .bind(position)
    .bind(&function)
    .bind(requirements)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if challenge_type == "dynamic" {
        sqlx::query(
            r#"
            INSERT INTO ctfzone.dynamic_challenge
                (id,dynamic_initial,dynamic_minimum,dynamic_decay,dynamic_function)
            VALUES ($1,$2,$3,$4,$5)
            "#,
        )
        .bind(id)
        .bind(initial)
        .bind(minimum)
        .bind(decay)
        .bind(&function)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    }
    transaction.commit().await.map_err(ApiError::database)?;

    Ok(Json(Success::new(json!({
        "id": id,
        "name": name,
        "value": value,
        "description": optional_string(object, "description"),
        "attribution": optional_string(object, "attribution"),
        "connection_info": optional_string(object, "connection_info"),
        "next_id": optional_i32(object, "next_id")?,
        "category": category,
        "state": state_value,
        "max_attempts": optional_i32(object, "max_attempts")?.unwrap_or(0),
        "position": position,
        "logic": logic,
        "initial": initial,
        "decay": decay,
        "minimum": minimum,
        "function": function,
        "type": challenge_type,
    })))
    .into_response())
}

pub(super) async fn detail(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_challenge_visibility(&state, user.as_ref()).await?;
    require_ctf_time(&state, user.as_ref()).await?;
    require_verified(&state, user.as_ref()).await?;
    let admin = user.as_ref().is_some_and(CurrentUser::is_admin);
    let team_mode = is_team_mode(&state).await?;
    if team_mode
        && user
            .as_ref()
            .is_some_and(|current| !current.is_admin() && current.team_id.is_none())
    {
        return Err(ApiError::forbidden("Join a team before viewing challenges"));
    }

    let challenge = challenge_detail_by_id(&state, challenge_id).await?;
    if !admin && challenge.state != "visible" {
        return Err(ApiError::not_found("Challenge not found"));
    }
    let solved = solved_challenge_ids(&state, user.as_ref(), team_mode).await?;
    if !requirements_met(challenge.requirements.as_ref(), &solved) && !admin {
        let anonymize = challenge
            .requirements
            .as_ref()
            .and_then(|value| value.get("anonymize"));
        if anonymize.is_none() {
            return Err(ApiError::forbidden(
                "Challenge prerequisites are not satisfied",
            ));
        }
        let preview = anonymize.and_then(Value::as_str) == Some("preview");
        return Ok(Json(Success::new(json!({
            "id": challenge.id,
            "type": "hidden",
            "name": if preview { challenge.name } else { Some("???".to_owned()) },
            "value": if preview { challenge.value } else { Some(0) },
            "logic": Value::Null,
            "solves": Value::Null,
            "solved_by_me": false,
            "solution_id": Value::Null,
            "category": if preview { challenge.category } else { Some("???".to_owned()) },
            "tags": [],
        })))
        .into_response());
    }
    if !matches!(
        challenge.challenge_type.as_deref(),
        Some("standard" | "dynamic")
    ) {
        return Err(ApiError::upstream(
            "The challenge type is not installed in CTFZone",
        ));
    }

    let account = user.as_ref().and_then(|current| {
        if team_mode {
            current.team_id.map(Account::Team)
        } else {
            Some(Account::User(current.id))
        }
    });
    let scores_visible = scores_and_accounts_visible(&state, user.as_ref()).await?;
    let solve_count = if scores_visible {
        solve_count_for_challenge(&state, challenge.id, team_mode, admin).await?
    } else {
        0
    };
    let solved_by_me = solved.contains(&challenge.id);
    let max_behavior = config_string(&state, "max_attempts_behavior")
        .await?
        .unwrap_or_else(|| "lockout".to_owned());
    let max_timeout = config_i64(&state, "max_attempts_timeout", 300).await?;
    let attempts = if let Some(account) = account {
        challenge_attempt_count(
            &state,
            account,
            challenge.id,
            (max_behavior == "timeout").then_some(max_timeout),
        )
        .await?
    } else {
        0
    };

    let ended = ctf_ended(&state).await?;
    let unlocked_hints = if let Some(account) = account {
        unlocked_hint_ids(&state, account).await?
    } else {
        HashSet::new()
    };
    let mut hints = sqlx::query_as::<_, HintRenderRow>(
        "SELECT id,title,cost,content,false AS unlocked FROM ctfzone.hints WHERE challenge_id=$1 ORDER BY cost,id",
    )
    .bind(challenge.id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    for hint in &mut hints {
        if ended || unlocked_hints.contains(&hint.id) || admin {
            hint.unlocked = true;
        } else {
            hint.content = None;
        }
    }
    let file_rows = sqlx::query_as::<_, FileRenderRow>(
        "SELECT id,location,sha1sum FROM ctfzone.files WHERE type='challenge' AND challenge_id=$1 ORDER BY id",
    )
    .bind(challenge.id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    let files = file_rows
        .into_iter()
        .filter_map(challenge_file_view)
        .collect::<Vec<_>>();
    let tag_objects = tags_for_challenge(&state, challenge.id).await?;
    let tags = tag_objects
        .iter()
        .filter_map(|tag| tag.get("value").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();

    let rating_mode = config_string(&state, "challenge_ratings")
        .await?
        .unwrap_or_else(|| "public".to_owned());
    let rating = if rating_mode != "disabled" {
        if let Some(current) = user.as_ref() {
            sqlx::query_as::<_, (Option<i32>, Option<String>)>(
                "SELECT value,review FROM ctfzone.ratings WHERE user_id=$1 AND challenge_id=$2",
            )
            .bind(current.id)
            .bind(challenge.id)
            .fetch_optional(&state.database)
            .await
            .map_err(ApiError::database)?
            .map(|(value, review)| json!({"value": value, "review": review}))
        } else {
            None
        }
    } else {
        None
    };
    let ratings = if rating_mode == "public" {
        let (up, down, count) = sqlx::query_as::<_, (i64, i64, i64)>(
            r#"
            SELECT
                COALESCE(SUM(CASE WHEN value >= 0 THEN value ELSE 0 END),0)::bigint,
                ABS(COALESCE(SUM(CASE WHEN value < 0 THEN value ELSE 0 END),0))::bigint,
                COUNT(*)::bigint
            FROM ctfzone.ratings WHERE challenge_id=$1
            "#,
        )
        .bind(challenge.id)
        .fetch_one(&state.database)
        .await
        .map_err(ApiError::database)?;
        Some(json!({"up": up, "down": down, "count": count}))
    } else {
        None
    };
    let solution = sqlx::query_as::<_, (i32, String)>(
        "SELECT id,state FROM ctfzone.solutions WHERE challenge_id=$1",
    )
    .bind(challenge.id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?;
    let solution_state = solution
        .as_ref()
        .map(|(_, state)| state.clone())
        .unwrap_or_else(|| "hidden".to_owned());
    let solution_id = solution.and_then(|(id, state)| {
        (state == "visible" || (state == "solved" && solved_by_me)).then_some(id)
    });
    let runtime = super::runtimes::challenge_runtime_summary(
        &state,
        user.as_ref().map(|current| current.id),
        challenge.id,
    )
    .await?;

    let mut response = challenge_read_json(&challenge);
    response["solves"] = if scores_visible {
        json!(solve_count)
    } else {
        Value::Null
    };
    response["solved_by_me"] = json!(solved_by_me);
    response["attempts"] = json!(attempts);
    response["files"] = json!(files);
    response["tags"] = json!(tags);
    response["hints"] = json!(hints);
    response["rating"] = json!(rating);
    response["ratings"] = json!(ratings);
    response["solution_id"] = json!(solution_id);
    response["solution_state"] = json!(solution_state);
    response["description_format"] = json!("markdown");
    response["attribution_format"] = json!("markdown");
    response["runtime"] = runtime;

    if let Some(current) = user.as_ref().filter(|current| !current.is_admin()) {
        sqlx::query(
            r#"
            INSERT INTO ctfzone.tracking (type,ip,target,user_id,date)
            SELECT 'challenges.open',$1,$2,$3,timezone('utc',now())
            WHERE NOT EXISTS (
                SELECT 1 FROM ctfzone.tracking
                WHERE type='challenges.open' AND user_id=$3 AND target=$2
            )
            "#,
        )
        .bind(current.request_ip())
        .bind(challenge.id)
        .bind(current.id)
        .execute(&state.database)
        .await
        .map_err(ApiError::database)?;
    }

    Ok(Json(Success::new(response)).into_response())
}

pub(super) async fn update(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
    Json(payload): Json<Value>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let object = payload
        .as_object()
        .ok_or_else(|| ApiError::bad_request("Challenge data must be an object"))?;
    let current = challenge_detail_by_id(&state, challenge_id).await?;
    let dynamic_type = current.challenge_type.as_deref() == Some("dynamic");

    let name = patch_required_string(object, "name", current.name, 80)?;
    let category = patch_required_string(object, "category", current.category, 80)?;
    let description = patch_string(object, "description", current.description);
    let attribution = patch_string(object, "attribution", current.attribution);
    let connection_info = patch_string(object, "connection_info", current.connection_info);
    let next_id = patch_i32(object, "next_id", current.next_id)?;
    let max_attempts = patch_i32(object, "max_attempts", current.max_attempts)?.unwrap_or(0);
    let position = patch_i32(object, "position", Some(current.position))?.unwrap_or(0);
    if !(0..=32767).contains(&position) {
        return Err(ApiError::bad_request("Challenge position is invalid"));
    }
    let state_value = patch_required_string(object, "state", Some(current.state), 80)?;
    if !matches!(state_value.as_str(), "visible" | "hidden" | "locked") {
        return Err(ApiError::bad_request("Unsupported challenge state"));
    }
    let logic = patch_required_string(object, "logic", Some(current.logic), 80)?;
    if !matches!(logic.as_str(), "any" | "all" | "team") {
        return Err(ApiError::bad_request("Unsupported challenge logic"));
    }
    let function = patch_required_string(object, "function", current.function, 32)?;
    if !matches!(function.as_str(), "static" | "linear" | "logarithmic") {
        return Err(ApiError::bad_request(
            "Unsupported challenge decay function",
        ));
    }
    let dynamic = function != "static";
    let initial = if dynamic {
        patch_i32(object, "initial", current.initial)?
    } else {
        None
    };
    let minimum = if dynamic {
        patch_i32(object, "minimum", current.minimum)?
    } else {
        None
    };
    let decay = if dynamic {
        patch_i32(object, "decay", current.decay)?
    } else {
        None
    };
    if dynamic && (initial.is_none() || minimum.is_none() || decay.is_none()) {
        return Err(ApiError::bad_request(
            "Dynamic challenges require initial, minimum, and decay",
        ));
    }
    if dynamic && decay == Some(0) {
        return Err(ApiError::bad_request(
            "Challenge decay must be greater than zero",
        ));
    }
    let mut value = patch_i32(object, "value", current.value)?
        .ok_or_else(|| ApiError::bad_request("Challenge value is required"))?;
    if dynamic {
        value = initial.expect("validated above");
    }
    let requirements = if object.contains_key("requirements") {
        object
            .get("requirements")
            .cloned()
            .filter(|value| !value.is_null())
    } else {
        current.requirements
    };
    validate_requirements(requirements.as_ref())?;

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    sqlx::query(
        r#"
        UPDATE ctfzone.challenges SET
            name=$1,description=$2,attribution=$3,connection_info=$4,next_id=$5,
            max_attempts=$6,value=$7,category=$8,state=$9,logic=$10,initial=$11,
            minimum=$12,decay=$13,position=$14,function=$15,requirements=$16
        WHERE id=$17
        "#,
    )
    .bind(name)
    .bind(description)
    .bind(attribution)
    .bind(connection_info)
    .bind(next_id)
    .bind(max_attempts)
    .bind(value)
    .bind(category)
    .bind(state_value)
    .bind(logic)
    .bind(initial)
    .bind(minimum)
    .bind(decay)
    .bind(position)
    .bind(&function)
    .bind(requirements)
    .bind(challenge_id)
    .execute(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if dynamic_type {
        sqlx::query(
            r#"
            INSERT INTO ctfzone.dynamic_challenge
                (id,dynamic_initial,dynamic_minimum,dynamic_decay,dynamic_function)
            VALUES ($1,$2,$3,$4,$5)
            ON CONFLICT (id) DO UPDATE SET
                dynamic_initial=EXCLUDED.dynamic_initial,
                dynamic_minimum=EXCLUDED.dynamic_minimum,
                dynamic_decay=EXCLUDED.dynamic_decay,
                dynamic_function=EXCLUDED.dynamic_function
            "#,
        )
        .bind(challenge_id)
        .bind(initial)
        .bind(minimum)
        .bind(decay)
        .bind(&function)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    }
    if dynamic {
        let updated = challenge_attempt_by_id(&mut transaction, challenge_id).await?;
        recalculate_dynamic_value(&mut transaction, &updated, is_team_mode(&state).await?).await?;
    }
    transaction.commit().await.map_err(ApiError::database)?;
    let updated = challenge_detail_by_id(&state, challenge_id).await?;
    Ok(Json(Success::new(challenge_read_json(&updated))).into_response())
}

pub(super) async fn delete_challenge(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let result = sqlx::query("DELETE FROM ctfzone.challenges WHERE id=$1")
        .bind(challenge_id)
        .execute(&state.database)
        .await
        .map_err(ApiError::database)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Challenge not found"));
    }
    Ok(Json(json!({"success": true})).into_response())
}

pub(super) async fn attempt(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Query(query): Query<AttemptQuery>,
    Json(request): Json<AttemptRequest>,
) -> Result<Response, ApiError> {
    require_challenge_visibility(&state, user.as_ref()).await?;
    require_ctf_time(&state, user.as_ref()).await?;
    require_verified(&state, user.as_ref()).await?;
    let Some(user) = user else {
        return Ok(attempt_response(
            StatusCode::FORBIDDEN,
            "authentication_required",
            None,
        ));
    };
    if !state
        .rate_limiter
        .allow(
            "challenge_attempt",
            &user.id.to_string(),
            10,
            StdDuration::from_secs(5),
        )
        .await
    {
        return Ok(attempt_response(
            StatusCode::TOO_MANY_REQUESTS,
            "ratelimited",
            Some("Too many submissions; try again shortly".to_owned()),
        ));
    }

    let preview = user.is_admin() && query.preview.unwrap_or(false);
    if !preview && config_bool(&state, "paused", false).await? {
        let name = config_string(&state, "ctf_name")
            .await?
            .unwrap_or_else(|| "CTFZone".to_owned());
        return Ok(attempt_response(
            StatusCode::FORBIDDEN,
            "paused",
            Some(format!("{name} is paused")),
        ));
    }

    let team_mode = is_team_mode(&state).await?;
    if team_mode && user.team_id.is_none() {
        return Err(ApiError::forbidden("Join a team before submitting flags"));
    }
    let account = if team_mode {
        Account::Team(user.team_id.expect("checked above"))
    } else {
        Account::User(user.id)
    };
    let submission = request.submission.trim();
    if submission.is_empty() {
        return Err(ApiError::bad_request("A submission is required"));
    }

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let lock_key = ((i64::from(account.id())) << 32) ^ i64::from(request.challenge_id);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;

    let challenge = sqlx::query_as::<_, ChallengeAttemptRow>(
        r#"
        SELECT c.id, c.type AS challenge_type, c.state, c.logic, c.max_attempts,
               COALESCE(dc.dynamic_function,c.function) AS function,
               COALESCE(dc.dynamic_initial,c.initial) AS initial,
               COALESCE(dc.dynamic_minimum,c.minimum) AS minimum,
               COALESCE(dc.dynamic_decay,c.decay) AS decay,
               c.requirements
        FROM ctfzone.challenges c
        LEFT JOIN ctfzone.dynamic_challenge dc ON dc.id=c.id
        WHERE c.id=$1
        "#,
    )
    .bind(request.challenge_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Challenge not found"))?;

    if challenge.challenge_type.as_deref() != Some("standard")
        && challenge.challenge_type.as_deref() != Some("dynamic")
    {
        return Err(ApiError::bad_request("Unsupported challenge type"));
    }
    if !preview {
        match challenge.state.as_str() {
            "hidden" => return Err(ApiError::not_found("Challenge not found")),
            "locked" => return Err(ApiError::forbidden("Challenge is locked")),
            _ => {}
        }
        let solved = solved_ids_in_transaction(&mut transaction, account).await?;
        if !requirements_met(challenge.requirements.as_ref(), &solved) {
            return Err(ApiError::forbidden(
                "Challenge prerequisites are not satisfied",
            ));
        }
    }

    let flags = sqlx::query_as::<_, FlagRow>(
        "SELECT id, type AS flag_type, content, data FROM ctfzone.flags WHERE challenge_id=$1 ORDER BY id",
    )
    .bind(challenge.id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(ApiError::database)?;

    if preview {
        let outcome = compare_submission(
            &mut transaction,
            account,
            &challenge,
            &flags,
            submission,
            user.id,
            team_mode,
        )
        .await?;
        return Ok(flag_result_response(outcome));
    }

    let now = Utc::now().naive_utc();
    let incorrect_limit = config_i64(&state, "incorrect_submissions_per_min", 10).await?;
    let recent_incorrect = submission_count(
        &mut transaction,
        account,
        None,
        Some(now - Duration::seconds(60)),
        "incorrect",
    )
    .await?;
    let oldest_recent = oldest_submission(
        &mut transaction,
        account,
        None,
        Some(now - Duration::seconds(60)),
        "incorrect",
    )
    .await?;
    let wait_for_minute = seconds_remaining(oldest_recent, now, 60);

    let max_attempts = i64::from(challenge.max_attempts.unwrap_or(0));
    let max_behavior = config_string(&state, "max_attempts_behavior")
        .await?
        .unwrap_or_else(|| "lockout".to_owned());
    let max_timeout = config_i64(&state, "max_attempts_timeout", 300).await?;
    if max_attempts > 0 {
        let since = (max_behavior == "timeout").then_some(now - Duration::seconds(max_timeout));
        let fails = submission_count(
            &mut transaction,
            account,
            Some(challenge.id),
            since,
            "incorrect",
        )
        .await?;
        if fails >= max_attempts {
            let (code, message) = if max_behavior == "timeout" {
                let oldest = oldest_submission(
                    &mut transaction,
                    account,
                    Some(challenge.id),
                    since,
                    "incorrect",
                )
                .await?;
                let wait = seconds_remaining(oldest, now, max_timeout);
                insert_submission(
                    &mut transaction,
                    &user,
                    team_mode,
                    challenge.id,
                    submission,
                    "ratelimited",
                )
                .await?;
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    format!("Not accepted. Try again in {wait} seconds"),
                )
            } else {
                (
                    StatusCode::FORBIDDEN,
                    "Not accepted. You have 0 tries remaining".to_owned(),
                )
            };
            transaction.commit().await.map_err(ApiError::database)?;
            return Ok(attempt_response(code, "ratelimited", Some(message)));
        }
    }
    if recent_incorrect >= incorrect_limit {
        insert_submission(
            &mut transaction,
            &user,
            team_mode,
            challenge.id,
            submission,
            "ratelimited",
        )
        .await?;
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok(attempt_response(
            StatusCode::TOO_MANY_REQUESTS,
            "ratelimited",
            Some(format!(
                "You're submitting flags too fast. Try again in {wait_for_minute} seconds."
            )),
        ));
    }

    if has_solved(&mut transaction, account, challenge.id).await? {
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok(attempt_response(
            StatusCode::OK,
            "already_solved",
            Some("Correct but you already solved this".to_owned()),
        ));
    }

    let outcome = compare_submission(
        &mut transaction,
        account,
        &challenge,
        &flags,
        submission,
        user.id,
        team_mode,
    )
    .await?;
    let response = match outcome {
        FlagResult::Correct => {
            let submission_id = insert_submission(
                &mut transaction,
                &user,
                team_mode,
                challenge.id,
                submission,
                "correct",
            )
            .await?;
            sqlx::query(
                "INSERT INTO ctfzone.solves (id, challenge_id, user_id, team_id) VALUES ($1, $2, $3, $4)",
            )
            .bind(submission_id)
            .bind(challenge.id)
            .bind(user.id)
            .bind(if team_mode { user.team_id } else { None })
            .execute(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
            recalculate_dynamic_value(&mut transaction, &challenge, team_mode).await?;
            attempt_response(StatusCode::OK, "correct", Some("Correct".to_owned()))
        }
        FlagResult::Partial => {
            insert_submission(
                &mut transaction,
                &user,
                team_mode,
                challenge.id,
                submission,
                "partial",
            )
            .await?;
            let message = if challenge.logic == "team" && team_mode {
                "Correct but all team members must submit a flag"
            } else {
                "Correct but more flags are required"
            };
            attempt_response(StatusCode::OK, "partial", Some(message.to_owned()))
        }
        FlagResult::Incorrect(message) => {
            insert_submission(
                &mut transaction,
                &user,
                team_mode,
                challenge.id,
                submission,
                "incorrect",
            )
            .await?;
            attempt_response(StatusCode::OK, "incorrect", Some(message))
        }
    };
    transaction.commit().await.map_err(ApiError::database)?;
    Ok(response)
}

async fn challenge_detail_by_id(
    state: &AppState,
    challenge_id: i32,
) -> Result<ChallengeDetailRow, ApiError> {
    sqlx::query_as::<_, ChallengeDetailRow>(
        r#"
        SELECT c.id,c.name,c.description,c.attribution,c.connection_info,c.next_id,c.max_attempts,
               c.value,c.category,c.type AS challenge_type,c.state,c.logic,
               COALESCE(dc.dynamic_initial,c.initial) AS initial,
               COALESCE(dc.dynamic_minimum,c.minimum) AS minimum,
               COALESCE(dc.dynamic_decay,c.decay) AS decay,
               c.position,COALESCE(dc.dynamic_function,c.function) AS function,c.requirements
        FROM ctfzone.challenges c
        LEFT JOIN ctfzone.dynamic_challenge dc ON dc.id=c.id
        WHERE c.id=$1
        "#,
    )
    .bind(challenge_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Challenge not found"))
}

async fn challenge_attempt_by_id(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: i32,
) -> Result<ChallengeAttemptRow, ApiError> {
    sqlx::query_as::<_, ChallengeAttemptRow>(
        r#"
        SELECT c.id,c.type AS challenge_type,c.state,c.logic,c.max_attempts,
               COALESCE(dc.dynamic_function,c.function) AS function,
               COALESCE(dc.dynamic_initial,c.initial) AS initial,
               COALESCE(dc.dynamic_minimum,c.minimum) AS minimum,
               COALESCE(dc.dynamic_decay,c.decay) AS decay,
               c.requirements
        FROM ctfzone.challenges c
        LEFT JOIN ctfzone.dynamic_challenge dc ON dc.id=c.id
        WHERE c.id=$1
        "#,
    )
    .bind(challenge_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Challenge not found"))
}

fn challenge_read_json(challenge: &ChallengeDetailRow) -> Value {
    let function = challenge.function.as_deref().unwrap_or("static");
    let challenge_type = challenge.challenge_type.as_deref().unwrap_or("standard");
    json!({
        "id": challenge.id,
        "name": challenge.name,
        "value": challenge.value,
        "description": challenge.description,
        "attribution": challenge.attribution,
        "connection_info": challenge.connection_info,
        "next_id": challenge.next_id,
        "category": challenge.category,
        "state": challenge.state,
        "max_attempts": challenge.max_attempts.unwrap_or(0),
        "position": challenge.position,
        "logic": challenge.logic,
        "initial": if function == "static" { None } else { challenge.initial },
        "decay": if function == "static" { None } else { challenge.decay },
        "minimum": if function == "static" { None } else { challenge.minimum },
        "function": function,
        "type": challenge.challenge_type,
        "requirements": challenge.requirements,
        "type_data": {
            "id": challenge_type,
            "name": challenge_type,
            "capabilities": {
                "flag_submission": true,
                "dynamic_scoring": challenge_type == "dynamic",
            },
        },
    })
}

fn challenge_file_view(file: FileRenderRow) -> Option<ChallengeFileView> {
    let location = file.location?;
    let name = location.rsplit('/').next()?.to_owned();
    Some(ChallengeFileView {
        id: file.id,
        name,
        url: format!("/files/{}", encode_url_path(&location)),
        sha1sum: file.sha1sum,
    })
}

fn encode_url_path(path: &str) -> String {
    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    encoded
}

async fn solve_count_for_challenge(
    state: &AppState,
    challenge_id: i32,
    team_mode: bool,
    admin: bool,
) -> Result<i64, ApiError> {
    let account_table = if team_mode { "teams" } else { "users" };
    let account_column = if team_mode { "team_id" } else { "user_id" };
    let visibility = if admin {
        ""
    } else {
        " AND NOT COALESCE(a.hidden,false) AND NOT COALESCE(a.banned,false)"
    };
    let query = format!(
        "SELECT COUNT(*) FROM ctfzone.solves s JOIN ctfzone.{account_table} a ON a.id=s.{account_column} WHERE s.challenge_id=$1{visibility}"
    );
    sqlx::query_scalar::<_, i64>(&query)
        .bind(challenge_id)
        .fetch_one(&state.database)
        .await
        .map_err(ApiError::database)
}

async fn challenge_attempt_count(
    state: &AppState,
    account: Account,
    challenge_id: i32,
    timeout_seconds: Option<i64>,
) -> Result<i64, ApiError> {
    let mut builder = QueryBuilder::<Postgres>::new(
        "SELECT COUNT(*) FROM ctfzone.submissions WHERE challenge_id=",
    );
    builder.push_bind(challenge_id);
    match account {
        Account::User(id) => builder.push(" AND user_id=").push_bind(id),
        Account::Team(id) => builder.push(" AND team_id=").push_bind(id),
    };
    builder.push(" AND type NOT IN ('discard','ratelimited')");
    if let Some(timeout_seconds) = timeout_seconds {
        builder
            .push(" AND date >= ")
            .push_bind(Utc::now().naive_utc() - Duration::seconds(timeout_seconds));
    }
    builder
        .build_query_scalar::<i64>()
        .fetch_one(&state.database)
        .await
        .map_err(ApiError::database)
}

async fn unlocked_hint_ids(state: &AppState, account: Account) -> Result<HashSet<i32>, ApiError> {
    let query = match account {
        Account::User(_) => "SELECT target FROM ctfzone.unlocks WHERE type='hints' AND user_id=$1",
        Account::Team(_) => "SELECT target FROM ctfzone.unlocks WHERE type='hints' AND team_id=$1",
    };
    Ok(sqlx::query_scalar::<_, Option<i32>>(query)
        .bind(account.id())
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?
        .into_iter()
        .flatten()
        .collect())
}

async fn ctf_ended(state: &AppState) -> Result<bool, ApiError> {
    let end = config_i64(state, "end", 0).await?;
    Ok(end > 0 && Utc::now().timestamp() > end)
}

fn patch_required_string(
    object: &Map<String, Value>,
    key: &str,
    current: Option<String>,
    max: usize,
) -> Result<String, ApiError> {
    if object.contains_key(key) {
        required_string(object, key, max)
    } else {
        let current = current.unwrap_or_default();
        if current.trim().is_empty() {
            Err(ApiError::bad_request(format!(
                "Challenge {key} is required"
            )))
        } else {
            Ok(current)
        }
    }
}

fn patch_string(object: &Map<String, Value>, key: &str, current: Option<String>) -> Option<String> {
    if object.contains_key(key) {
        optional_string(object, key)
    } else {
        current
    }
}

fn patch_i32(
    object: &Map<String, Value>,
    key: &str,
    current: Option<i32>,
) -> Result<Option<i32>, ApiError> {
    if object.contains_key(key) {
        optional_i32(object, key)
    } else {
        Ok(current)
    }
}

async fn compare_submission(
    transaction: &mut Transaction<'_, Postgres>,
    account: Account,
    challenge: &ChallengeAttemptRow,
    flags: &[FlagRow],
    submission: &str,
    user_id: i32,
    team_mode: bool,
) -> Result<FlagResult, ApiError> {
    match challenge.logic.as_str() {
        "all" => {
            let mut provided = sqlx::query_scalar::<_, Option<String>>(
                match account {
                    Account::User(_) => "SELECT provided FROM ctfzone.submissions WHERE user_id=$1 AND challenge_id=$2 AND type='partial'",
                    Account::Team(_) => "SELECT provided FROM ctfzone.submissions WHERE team_id=$1 AND challenge_id=$2 AND type='partial'",
                },
            )
            .bind(account.id())
            .bind(challenge.id)
            .fetch_all(&mut **transaction)
            .await
            .map_err(ApiError::database)?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
            provided.push(submission.to_owned());
            let mut all_matched = true;
            for flag in flags {
                let mut matched = false;
                for candidate in &provided {
                    if flag_matches(transaction, flag, candidate).await? {
                        matched = true;
                        break;
                    }
                }
                if !matched {
                    all_matched = false;
                    break;
                }
            }
            if all_matched {
                Ok(FlagResult::Correct)
            } else {
                for flag in flags {
                    if flag_matches(transaction, flag, submission).await? {
                        return Ok(FlagResult::Partial);
                    }
                }
                Ok(FlagResult::Incorrect("Incorrect".to_owned()))
            }
        }
        "team" if team_mode => {
            let mut correct = false;
            for flag in flags {
                if flag_matches(transaction, flag, submission).await? {
                    correct = true;
                    break;
                }
            }
            if !correct {
                return Ok(FlagResult::Incorrect("Incorrect".to_owned()));
            }
            let submitters = sqlx::query_scalar::<_, Option<i32>>(
                "SELECT DISTINCT user_id FROM ctfzone.submissions WHERE team_id=$1 AND challenge_id=$2 AND type='partial'",
            )
            .bind(account.id())
            .bind(challenge.id)
            .fetch_all(&mut **transaction)
            .await
            .map_err(ApiError::database)?;
            let mut submitters = submitters.into_iter().flatten().collect::<HashSet<_>>();
            submitters.insert(user_id);
            let members =
                sqlx::query_scalar::<_, i32>("SELECT id FROM ctfzone.users WHERE team_id=$1")
                    .bind(account.id())
                    .fetch_all(&mut **transaction)
                    .await
                    .map_err(ApiError::database)?
                    .into_iter()
                    .collect::<HashSet<_>>();
            if submitters == members {
                Ok(FlagResult::Correct)
            } else {
                Ok(FlagResult::Partial)
            }
        }
        _ => {
            for flag in flags {
                if flag_matches(transaction, flag, submission).await? {
                    return Ok(FlagResult::Correct);
                }
            }
            Ok(FlagResult::Incorrect("Incorrect".to_owned()))
        }
    }
}

async fn flag_matches(
    transaction: &mut Transaction<'_, Postgres>,
    flag: &FlagRow,
    provided: &str,
) -> Result<bool, ApiError> {
    let saved = flag.content.as_deref().unwrap_or_default();
    let insensitive = flag.data.as_deref() == Some("case_insensitive");
    match flag.flag_type.as_deref().unwrap_or("static") {
        "static" => Ok(static_flag_matches(saved, provided, insensitive)),
        "regex" => {
            let pattern = format!("^(?:{saved})$");
            let query = if insensitive {
                "SELECT $1::text ~* $2::text"
            } else {
                "SELECT $1::text ~ $2::text"
            };
            sqlx::query_scalar::<_, bool>(query)
                .bind(provided)
                .bind(pattern)
                .fetch_one(&mut **transaction)
                .await
                .map_err(|error| match error {
                    sqlx::Error::Database(ref database)
                        if database.code().as_deref() == Some("2201B") =>
                    {
                        ApiError::bad_request("Regex parse error occurred")
                    }
                    error => ApiError::database(error),
                })
        }
        _ => Err(ApiError::bad_request(format!(
            "Unsupported flag type on flag {}",
            flag.id
        ))),
    }
}

fn static_flag_matches(saved: &str, provided: &str, insensitive: bool) -> bool {
    if insensitive {
        saved.to_lowercase() == provided.to_lowercase()
    } else {
        saved == provided
    }
}

async fn insert_submission(
    transaction: &mut Transaction<'_, Postgres>,
    user: &CurrentUser,
    team_mode: bool,
    challenge_id: i32,
    provided: &str,
    submission_type: &str,
) -> Result<i32, ApiError> {
    sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO ctfzone.submissions
            (challenge_id, user_id, team_id, ip, provided, type, date)
        VALUES ($1, $2, $3, $4, $5, $6, timezone('utc', now()))
        RETURNING id
        "#,
    )
    .bind(challenge_id)
    .bind(user.id)
    .bind(if team_mode { user.team_id } else { None })
    .bind(user.request_ip())
    .bind(provided)
    .bind(submission_type)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)
}

async fn submission_count(
    transaction: &mut Transaction<'_, Postgres>,
    account: Account,
    challenge_id: Option<i32>,
    since: Option<NaiveDateTime>,
    submission_type: &str,
) -> Result<i64, ApiError> {
    let mut builder =
        QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM ctfzone.submissions WHERE type=");
    builder.push_bind(submission_type);
    match account {
        Account::User(id) => builder.push(" AND user_id=").push_bind(id),
        Account::Team(id) => builder.push(" AND team_id=").push_bind(id),
    };
    if let Some(challenge_id) = challenge_id {
        builder.push(" AND challenge_id=").push_bind(challenge_id);
    }
    if let Some(since) = since {
        builder.push(" AND date >= ").push_bind(since);
    }
    builder
        .build_query_scalar::<i64>()
        .fetch_one(&mut **transaction)
        .await
        .map_err(ApiError::database)
}

async fn oldest_submission(
    transaction: &mut Transaction<'_, Postgres>,
    account: Account,
    challenge_id: Option<i32>,
    since: Option<NaiveDateTime>,
    submission_type: &str,
) -> Result<Option<NaiveDateTime>, ApiError> {
    let mut builder =
        QueryBuilder::<Postgres>::new("SELECT MIN(date) FROM ctfzone.submissions WHERE type=");
    builder.push_bind(submission_type);
    match account {
        Account::User(id) => builder.push(" AND user_id=").push_bind(id),
        Account::Team(id) => builder.push(" AND team_id=").push_bind(id),
    };
    if let Some(challenge_id) = challenge_id {
        builder.push(" AND challenge_id=").push_bind(challenge_id);
    }
    if let Some(since) = since {
        builder.push(" AND date >= ").push_bind(since);
    }
    builder
        .build_query_scalar::<Option<NaiveDateTime>>()
        .fetch_one(&mut **transaction)
        .await
        .map_err(ApiError::database)
}

fn seconds_remaining(oldest: Option<NaiveDateTime>, now: NaiveDateTime, window: i64) -> i64 {
    oldest
        .map(|date| (window - (now - date).num_seconds()).max(1))
        .unwrap_or(window)
}

async fn has_solved(
    transaction: &mut Transaction<'_, Postgres>,
    account: Account,
    challenge_id: i32,
) -> Result<bool, ApiError> {
    let query = match account {
        Account::User(_) => {
            "SELECT EXISTS(SELECT 1 FROM ctfzone.solves WHERE user_id=$1 AND challenge_id=$2)"
        }
        Account::Team(_) => {
            "SELECT EXISTS(SELECT 1 FROM ctfzone.solves WHERE team_id=$1 AND challenge_id=$2)"
        }
    };
    sqlx::query_scalar::<_, bool>(query)
        .bind(account.id())
        .bind(challenge_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(ApiError::database)
}

async fn solved_ids_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    account: Account,
) -> Result<HashSet<i32>, ApiError> {
    let query = match account {
        Account::User(_) => "SELECT challenge_id FROM ctfzone.solves WHERE user_id=$1",
        Account::Team(_) => "SELECT challenge_id FROM ctfzone.solves WHERE team_id=$1",
    };
    Ok(sqlx::query_scalar::<_, Option<i32>>(query)
        .bind(account.id())
        .fetch_all(&mut **transaction)
        .await
        .map_err(ApiError::database)?
        .into_iter()
        .flatten()
        .collect())
}

async fn recalculate_dynamic_value(
    transaction: &mut Transaction<'_, Postgres>,
    challenge: &ChallengeAttemptRow,
    team_mode: bool,
) -> Result<(), ApiError> {
    let function = challenge.function.as_deref().unwrap_or("static");
    if function == "static" {
        return Ok(());
    }
    let initial = challenge.initial.unwrap_or(0);
    let minimum = challenge.minimum.unwrap_or(0);
    let decay = challenge.decay.unwrap_or(1).max(1);
    let count_query = if team_mode {
        r#"SELECT COUNT(*) FROM ctfzone.solves s JOIN ctfzone.teams a ON a.id=s.team_id
           WHERE s.challenge_id=$1 AND NOT COALESCE(a.hidden,false) AND NOT COALESCE(a.banned,false)"#
    } else {
        r#"SELECT COUNT(*) FROM ctfzone.solves s JOIN ctfzone.users a ON a.id=s.user_id
           WHERE s.challenge_id=$1 AND NOT COALESCE(a.hidden,false) AND NOT COALESCE(a.banned,false)"#
    };
    let solve_count = sqlx::query_scalar::<_, i64>(count_query)
        .bind(challenge.id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    let adjusted = (solve_count - 1).max(0) as f64;
    let calculated = if function == "linear" {
        f64::from(initial) - f64::from(decay) * adjusted
    } else {
        ((f64::from(minimum - initial) / f64::from(decay).powi(2)) * adjusted.powi(2))
            + f64::from(initial)
    };
    let value = (calculated.ceil() as i32).max(minimum);
    sqlx::query("UPDATE ctfzone.challenges SET value=$1 WHERE id=$2")
        .bind(value)
        .bind(challenge.id)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
    Ok(())
}

async fn solved_challenge_ids(
    state: &AppState,
    user: Option<&CurrentUser>,
    team_mode: bool,
) -> Result<HashSet<i32>, ApiError> {
    let Some(user) = user else {
        return Ok(HashSet::new());
    };
    let (column, account_id) = if team_mode {
        ("team_id", user.team_id)
    } else {
        ("user_id", Some(user.id))
    };
    let Some(account_id) = account_id else {
        return Ok(HashSet::new());
    };
    let sql = format!("SELECT challenge_id FROM ctfzone.solves WHERE {column}=$1");
    Ok(sqlx::query_scalar::<_, Option<i32>>(&sql)
        .bind(account_id)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?
        .into_iter()
        .flatten()
        .collect())
}

async fn solve_counts(
    state: &AppState,
    team_mode: bool,
    admin_view: bool,
) -> Result<HashMap<i32, i64>, ApiError> {
    let account_table = if team_mode { "teams" } else { "users" };
    let account_column = if team_mode { "team_id" } else { "user_id" };
    let visibility = if admin_view {
        String::new()
    } else {
        " AND NOT COALESCE(a.hidden,false) AND NOT COALESCE(a.banned,false)".to_owned()
    };
    let sql = format!(
        "SELECT s.challenge_id, COUNT(*) FROM ctfzone.solves s JOIN ctfzone.{account_table} a ON a.id=s.{account_column} WHERE s.challenge_id IS NOT NULL{visibility} GROUP BY s.challenge_id"
    );
    Ok(sqlx::query_as::<_, (i32, i64)>(&sql)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?
        .into_iter()
        .collect())
}

async fn tags_for_challenge(state: &AppState, challenge_id: i32) -> Result<Vec<Value>, ApiError> {
    let rows = sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM ctfzone.tags WHERE challenge_id=$1 ORDER BY id",
    )
    .bind(challenge_id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(rows
        .into_iter()
        .flatten()
        .map(|value| json!({"value": value}))
        .collect())
}

fn requirements_met(requirements: Option<&Value>, solved: &HashSet<i32>) -> bool {
    requirements
        .and_then(|value| value.get("prerequisites"))
        .and_then(Value::as_array)
        .map(|prerequisites| {
            prerequisites
                .iter()
                .filter_map(|value| value.as_i64().and_then(|id| i32::try_from(id).ok()))
                .all(|id| solved.contains(&id))
        })
        .unwrap_or(true)
}

fn validate_requirements(requirements: Option<&Value>) -> Result<(), ApiError> {
    let Some(requirements) = requirements else {
        return Ok(());
    };
    let object = requirements
        .as_object()
        .ok_or_else(|| ApiError::bad_request("Challenge requirements must be an object"))?;
    if let Some(prerequisites) = object.get("prerequisites") {
        let values = prerequisites
            .as_array()
            .ok_or_else(|| ApiError::bad_request("Challenge prerequisites must be an array"))?;
        if values.iter().any(|value| value.as_i64().is_none()) {
            return Err(ApiError::bad_request(
                "Challenge prerequisites must contain integer IDs",
            ));
        }
    }
    Ok(())
}

fn required_string(object: &Map<String, Value>, key: &str, max: usize) -> Result<String, ApiError> {
    let value = optional_string(object, key).unwrap_or_default();
    let value = value.trim();
    if value.is_empty() {
        return Err(ApiError::bad_request(format!(
            "Challenge {key} is required"
        )));
    }
    if value.chars().count() > max {
        return Err(ApiError::bad_request(format!(
            "Challenge {key} is too long"
        )));
    }
    Ok(value.to_owned())
}

fn optional_string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(|value| match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    })
}

fn optional_i32(object: &Map<String, Value>, key: &str) -> Result<Option<i32>, ApiError> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    if value.is_null() || value.as_str().is_some_and(str::is_empty) {
        return Ok(None);
    }
    let parsed = value
        .as_i64()
        .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| ApiError::bad_request(format!("Challenge {key} must be an integer")))?;
    Ok(Some(parsed))
}

fn flag_result_response(result: FlagResult) -> Response {
    match result {
        FlagResult::Correct => {
            attempt_response(StatusCode::OK, "correct", Some("Correct".to_owned()))
        }
        FlagResult::Partial => attempt_response(
            StatusCode::OK,
            "partial",
            Some("Correct but more flags are required".to_owned()),
        ),
        FlagResult::Incorrect(message) => {
            attempt_response(StatusCode::OK, "incorrect", Some(message))
        }
    }
}

fn attempt_response(code: StatusCode, status: &str, message: Option<String>) -> Response {
    let mut data = json!({"status": status});
    if let Some(message) = message {
        data["message"] = Value::String(message);
    }
    (code, Json(Success::new(data))).into_response()
}

pub(super) async fn require_challenge_visibility(
    state: &AppState,
    user: Option<&CurrentUser>,
) -> Result<(), ApiError> {
    match config_string(state, "challenge_visibility")
        .await?
        .as_deref()
        .unwrap_or("private")
    {
        "public" => Ok(()),
        "private" if user.is_some() => Ok(()),
        "admins" if user.is_some_and(CurrentUser::is_admin) => Ok(()),
        _ => Err(ApiError::forbidden("Challenges are not available")),
    }
}

pub(super) async fn require_ctf_time(
    state: &AppState,
    user: Option<&CurrentUser>,
) -> Result<(), ApiError> {
    if user.is_some_and(CurrentUser::is_admin) {
        return Ok(());
    }
    let now = Utc::now().timestamp();
    let start = config_i64(state, "start", 0).await?;
    let end = config_i64(state, "end", 0).await?;
    let in_time = (start == 0 || start < now) && (end == 0 || now < end);
    if in_time || (end != 0 && now > end && config_bool(state, "view_after_ctf", false).await?) {
        Ok(())
    } else if start != 0 && now <= start {
        Err(ApiError::forbidden("CTFZone has not started yet"))
    } else {
        Err(ApiError::forbidden("CTFZone has ended"))
    }
}

pub(super) async fn require_verified(
    state: &AppState,
    user: Option<&CurrentUser>,
) -> Result<(), ApiError> {
    if config_bool(state, "verify_emails", false).await?
        && user.is_some_and(|user| !user.is_admin() && !user.verified)
    {
        Err(ApiError::forbidden(
            "Verify your email before viewing challenges",
        ))
    } else {
        Ok(())
    }
}

pub(super) async fn scores_and_accounts_visible(
    state: &AppState,
    user: Option<&CurrentUser>,
) -> Result<bool, ApiError> {
    let score = visibility_value(state, "score_visibility", user, "public").await?;
    let account = visibility_value(state, "account_visibility", user, "public").await?;
    Ok(score && account)
}

async fn visibility_value(
    state: &AppState,
    key: &str,
    user: Option<&CurrentUser>,
    default: &str,
) -> Result<bool, ApiError> {
    Ok(
        match config_string(state, key)
            .await?
            .as_deref()
            .unwrap_or(default)
        {
            "public" => true,
            "private" => user.is_some(),
            "admins" => user.is_some_and(CurrentUser::is_admin),
            "hidden" => false,
            _ => true,
        },
    )
}

pub(super) async fn is_team_mode(state: &AppState) -> Result<bool, ApiError> {
    Ok(config_string(state, "user_mode").await?.as_deref() == Some("teams"))
}

async fn config_string(state: &AppState, key: &str) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar::<_, Option<String>>("SELECT value FROM ctfzone.config WHERE key=$1 LIMIT 1")
        .bind(key)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)
        .map(Option::flatten)
}

async fn config_bool(state: &AppState, key: &str, default: bool) -> Result<bool, ApiError> {
    Ok(config_string(state, key)
        .await?
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(default))
}

async fn config_i64(state: &AppState, key: &str, default: i64) -> Result<i64, ApiError> {
    let value = config_string(state, key).await?;
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return Ok(default);
    };
    value
        .parse::<i64>()
        .map_err(|_| ApiError::bad_request(format!("Configuration {key} must be an integer")))
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

    #[test]
    fn compares_static_flags() {
        assert!(static_flag_matches("CTF{yes}", "CTF{yes}", false));
        assert!(!static_flag_matches("CTF{yes}", "ctf{yes}", false));
        assert!(static_flag_matches("CTF{yes}", "ctf{YES}", true));
    }

    #[test]
    fn checks_prerequisites() {
        let requirements = json!({"prerequisites": [1, 3]});
        assert!(requirements_met(
            Some(&requirements),
            &HashSet::from([1, 2, 3])
        ));
        assert!(!requirements_met(Some(&requirements), &HashSet::from([1])));
    }

    #[test]
    fn encodes_file_locations_as_url_paths() {
        assert_eq!(
            encode_url_path("challenge files/payload #1.zip"),
            "challenge%20files/payload%20%231.zip"
        );
    }
}
