use std::{
    collections::{HashMap, HashSet},
    time::Duration as StdDuration,
};

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use chrono::{Duration, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sqlx::{FromRow, PgConnection, Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
    routes::Success,
};

const DYNAMIC_SCORE_LOCK_NAMESPACE: i32 = 0x4354_465A;

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
    category_id: i32,
    challenge_kind: String,
    exposure: String,
    connection_info: Option<String>,
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
    category_id: i32,
    challenge_kind: String,
    exposure: String,
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

struct ChallengeAccessContext {
    challenge: ChallengeDetailRow,
    team_mode: bool,
    solved: HashSet<i32>,
    prerequisite_preview: Option<bool>,
}

#[derive(Debug, PartialEq, Eq)]
enum ChallengeRowAccess {
    Full,
    HiddenPreview(bool),
    NotFound,
    PrerequisitesDenied,
}

#[derive(Debug, PartialEq, Eq)]
enum CtfTimeAccess {
    Allowed,
    NotStarted,
    Ended,
}

#[derive(Deserialize, FromRow, Serialize)]
struct HintRenderRow {
    id: i32,
    title: Option<String>,
    cost: Option<i32>,
    content: Option<String>,
    unlocked: bool,
}

#[derive(Deserialize, FromRow)]
struct ObjectRenderRow {
    object_id: Uuid,
    name: String,
    content_type: String,
    size: i64,
    sha256: Option<String>,
}

#[derive(Serialize)]
struct ChallengeObjectView {
    object_id: Uuid,
    name: String,
    content_type: String,
    size: i64,
    sha256: Option<String>,
}

type FlagRow = super::flag_policy::StoredFlag;

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

#[derive(Clone, Copy)]
struct SharedFlagEvidence {
    flag_id: i32,
    source_user_id: i32,
    accepted: bool,
    match_tag: [u8; 32],
}

struct ComparisonResult {
    outcome: FlagResult,
    shared: Option<SharedFlagEvidence>,
}

struct SubmissionComparisonContext<'a> {
    user_id: i32,
    team_mode: bool,
    secret_key: &'a str,
}

pub(super) async fn list(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Query(query): Query<ChallengeListQuery>,
) -> Result<Response, ApiError> {
    Ok(Json(Success::new(list_data(state, user, query).await?)).into_response())
}

pub(super) async fn list_data(
    state: AppState,
    user: Option<CurrentUser>,
    query: ChallengeListQuery,
) -> Result<Vec<Value>, ApiError> {
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
        SELECT c.id, c.name, c.value, c.category, c.category_id,
               c.challenge_type AS challenge_kind,c.exposure,c.connection_info,
               c.type AS challenge_type,
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
    let challenge_ids = rows.iter().map(|row| row.id).collect::<Vec<_>>();
    let mut tags_by_challenge = tags_for_challenges(&state, &challenge_ids).await?;
    let solved = solved_challenge_ids(&state, user.as_ref(), team_mode).await?;
    let scores_visible = scores_and_accounts_visible(&state, user.as_ref()).await?;
    let solve_counts = if scores_visible {
        solve_counts(&state, team_mode, admin_view).await?
    } else {
        HashMap::new()
    };

    let mut response = Vec::with_capacity(rows.len());
    for row in rows {
        let tags = tags_by_challenge.remove(&row.id).unwrap_or_default();
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
            "category_id": row.category_id,
            "challenge_type": row.challenge_kind,
            "exposure": row.exposure,
            "connection_info": row.connection_info,
            "tags": tags,
            "runtime_available": row.runtime_available,
        }));
    }

    Ok(response)
}

async fn challenge_access_context(
    state: &AppState,
    user: Option<&CurrentUser>,
    challenge_id: i32,
) -> Result<ChallengeAccessContext, ApiError> {
    let mut connection = state.database.acquire().await.map_err(ApiError::database)?;
    challenge_access_context_on(&mut connection, user, challenge_id).await
}

async fn challenge_access_context_on(
    connection: &mut PgConnection,
    user: Option<&CurrentUser>,
    challenge_id: i32,
) -> Result<ChallengeAccessContext, ApiError> {
    require_challenge_visibility_on(connection, user).await?;
    require_ctf_time_on(connection, user).await?;
    require_verified_on(connection, user).await?;

    let admin = user.is_some_and(CurrentUser::is_admin);
    let team_mode = is_team_mode_on(connection).await?;
    let current_team_id = if team_mode {
        if let Some(current) = user {
            sqlx::query_scalar::<_, Option<i32>>("SELECT team_id FROM ctfzone.users WHERE id=$1")
                .bind(current.id)
                .fetch_optional(&mut *connection)
                .await
                .map_err(ApiError::database)?
                .flatten()
        } else {
            None
        }
    } else {
        None
    };
    if team_membership_missing(
        team_mode,
        user.map(|current| (current.is_admin(), current_team_id)),
    ) {
        return Err(ApiError::forbidden("Join a team before viewing challenges"));
    }

    let challenge = challenge_detail_by_id_on(connection, challenge_id).await?;
    let solved = solved_challenge_ids_for_identity_on(
        connection,
        user.map(|current| current.id),
        current_team_id,
        team_mode,
    )
    .await?;
    let prerequisite_preview = match challenge_row_access(&challenge, admin, &solved) {
        ChallengeRowAccess::Full => None,
        ChallengeRowAccess::HiddenPreview(preview) => Some(preview),
        ChallengeRowAccess::NotFound => {
            return Err(ApiError::not_found("Challenge not found"));
        }
        ChallengeRowAccess::PrerequisitesDenied => {
            return Err(ApiError::forbidden(
                "Challenge prerequisites are not satisfied",
            ));
        }
    };

    Ok(ChallengeAccessContext {
        challenge,
        team_mode,
        solved,
        prerequisite_preview,
    })
}

pub(super) async fn require_full_challenge_access(
    state: &AppState,
    user: Option<&CurrentUser>,
    challenge_id: i32,
) -> Result<(), ApiError> {
    let access = challenge_access_context(state, user, challenge_id).await?;
    require_unanonymized_access(&access)
}

pub(super) async fn require_full_challenge_access_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user: Option<&CurrentUser>,
    challenge_id: i32,
) -> Result<(), ApiError> {
    let access = challenge_access_context_on(transaction, user, challenge_id).await?;
    require_unanonymized_access(&access)
}

fn require_unanonymized_access(access: &ChallengeAccessContext) -> Result<(), ApiError> {
    if access.prerequisite_preview.is_some() {
        Err(ApiError::forbidden(
            "Challenge prerequisites are not satisfied",
        ))
    } else {
        Ok(())
    }
}

fn challenge_row_access(
    challenge: &ChallengeDetailRow,
    admin: bool,
    solved: &HashSet<i32>,
) -> ChallengeRowAccess {
    if admin {
        return ChallengeRowAccess::Full;
    }
    if challenge.state != "visible" {
        return ChallengeRowAccess::NotFound;
    }
    if requirements_met(challenge.requirements.as_ref(), solved) {
        return ChallengeRowAccess::Full;
    }
    match challenge
        .requirements
        .as_ref()
        .and_then(|value| value.get("anonymize"))
    {
        Some(value) => ChallengeRowAccess::HiddenPreview(value.as_str() == Some("preview")),
        None => ChallengeRowAccess::PrerequisitesDenied,
    }
}

fn team_membership_missing(team_mode: bool, identity: Option<(bool, Option<i32>)>) -> bool {
    team_mode && identity.is_some_and(|(admin, team_id)| !admin && team_id.is_none())
}

fn verification_missing(verification_enabled: bool, identity: Option<(bool, bool)>) -> bool {
    verification_enabled && identity.is_some_and(|(admin, verified)| !admin && !verified)
}

fn ctf_time_access(now: i64, start: i64, end: i64, view_after_ctf: bool) -> CtfTimeAccess {
    let in_time = (start == 0 || start < now) && (end == 0 || now < end);
    if in_time || (end != 0 && now > end && view_after_ctf) {
        CtfTimeAccess::Allowed
    } else if start != 0 && now <= start {
        CtfTimeAccess::NotStarted
    } else {
        CtfTimeAccess::Ended
    }
}

pub(super) async fn create(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let object = payload
        .as_object()
        .ok_or_else(|| ApiError::bad_request("Challenge data must be an object"))?;
    let name = required_string(object, "name", 80)?;
    let category_id = optional_i32(object, "category_id")?
        .ok_or_else(|| ApiError::bad_request("Challenge category_id is required"))?;
    let challenge_kind = required_string(object, "challenge_type", 32)?;
    if challenge_kind != "jeopardy" {
        return Err(ApiError::bad_request(
            "Only Jeopardy challenges are available in version 1.0",
        ));
    }
    let exposure = required_string(object, "exposure", 16)?;
    if !matches!(exposure.as_str(), "public" | "private") {
        return Err(ApiError::bad_request(
            "Challenge exposure must be public or private",
        ));
    }
    if object.contains_key("public_url") {
        return Err(ApiError::bad_request(
            "Challenge public_url is not supported; use optional connection_info",
        ));
    }
    let description = optional_text(object, "description", 65_536)?;
    let attribution = optional_text(object, "attribution", 2_048)?;
    let connection_info = optional_text(object, "connection_info", 4_096)?;
    let initial_flag = serde_json::from_value::<super::flag_policy::InitialFlagInput>(
        object
            .get("flag")
            .cloned()
            .ok_or_else(|| ApiError::bad_request("An initial flag is required"))?,
    )
    .map_err(|_| ApiError::bad_request("Initial flag data is invalid"))?;
    let (initial_flag_type, flag_content, flag_data) = super::flag_policy::normalize_definition(
        &initial_flag.flag_type,
        &initial_flag.content,
        initial_flag.data,
        &exposure,
    )?;
    let runtime = object
        .get("runtime")
        .cloned()
        .filter(|value| !value.is_null());
    let runtime = match (exposure.as_str(), runtime) {
        ("private", Some(value)) => {
            let runtime = serde_json::from_value::<super::runtimes::RuntimeConfigInput>(value)
                .map_err(|_| ApiError::bad_request("Private runtime data is invalid"))?;
            if runtime.runtime_mode != "managed" {
                return Err(ApiError::bad_request(
                    "Private challenges require a managed runtime",
                ));
            }
            Some(runtime)
        }
        ("private", None) => {
            return Err(ApiError::bad_request(
                "Private challenges require runtime configuration",
            ));
        }
        ("public", Some(_)) => {
            return Err(ApiError::bad_request(
                "Public challenges cannot define managed runtime configuration",
            ));
        }
        ("public", None) => None,
        _ => unreachable!(),
    };
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
    let dynamic = challenge_type == "dynamic";
    if (!dynamic && function != "static")
        || (dynamic && !matches!(function.as_str(), "linear" | "logarithmic"))
    {
        return Err(ApiError::bad_request(
            "Scoring type and decay function do not match",
        ));
    }
    let supplied_value = optional_i32(object, "value")?;
    let supplied_initial = optional_i32(object, "initial")?;
    let minimum = optional_i32(object, "minimum")?;
    let decay = optional_i32(object, "decay")?;
    if !dynamic && (supplied_initial.is_some() || minimum.is_some() || decay.is_some()) {
        return Err(ApiError::bad_request(
            "Standard scoring cannot define dynamic scoring fields",
        ));
    }
    if dynamic
        && supplied_initial
            .zip(supplied_value)
            .is_some_and(|(initial, value)| initial != value)
    {
        return Err(ApiError::bad_request(
            "Dynamic value must match the initial score",
        ));
    }
    let initial = dynamic
        .then(|| supplied_initial.or(supplied_value))
        .flatten();
    if dynamic && (initial.is_none() || minimum.is_none() || decay.is_none()) {
        return Err(ApiError::bad_request(
            "Dynamic challenges require initial, minimum, and decay",
        ));
    }
    if dynamic
        && (initial.is_some_and(|value| value < 0)
            || minimum.is_some_and(|value| value < 0)
            || initial
                .zip(minimum)
                .is_some_and(|(initial, minimum)| minimum > initial)
            || decay.is_some_and(|value| value <= 0))
    {
        return Err(ApiError::bad_request(
            "Dynamic scoring requires initial >= minimum >= 0 and decay > 0",
        ));
    }
    let value = if dynamic { initial } else { supplied_value }
        .ok_or_else(|| ApiError::bad_request("Challenge value is required"))?;
    if value < 0 {
        return Err(ApiError::bad_request("Challenge value cannot be negative"));
    }
    let max_attempts = validate_max_attempts(optional_i32(object, "max_attempts")?.unwrap_or(0))?;
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
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    let (idempotency, replay) = super::create_idempotency::CreateRequest::lock_and_replay(
        &mut transaction,
        &headers,
        user.id,
        super::create_idempotency::CHALLENGE_CREATE,
        &payload,
    )
    .await?;
    if let Some(response_data) = replay {
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok((StatusCode::CREATED, Json(Success::new(response_data))).into_response());
    }
    let category = sqlx::query_scalar::<_, String>(
        "SELECT name FROM ctfzone.challenge_categories WHERE id=$1 FOR KEY SHARE",
    )
    .bind(category_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::bad_request("Select an existing challenge category"))?;
    if let Some(runtime) = runtime.as_ref() {
        if state_value != "hidden" && !runtime.enabled {
            return Err(ApiError::conflict(
                "Visible private challenges require an enabled managed runtime",
            ));
        }
        let gate_enabled = super::runtimes::prepare_private_challenge_gate(
            &mut transaction,
            user.id,
            runtime.enable_global_gate,
        )
        .await?;
        if !gate_enabled && state_value != "hidden" {
            return Err(ApiError::conflict(
                "Enable private challenge launches globally or save this challenge as hidden",
            ));
        }
    }
    let id = sqlx::query_scalar::<_, i32>(
        r#"
        INSERT INTO ctfzone.challenges (
            name, description, attribution, connection_info, next_id,
            max_attempts, value, category, category_id, challenge_type, exposure,
            type, state, logic, initial, minimum, decay, position,
            function, requirements
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
            $12, $13, $14, $15, $16, $17, $18, $19, $20
        ) RETURNING id
        "#,
    )
    .bind(&name)
    .bind(&description)
    .bind(&attribution)
    .bind(&connection_info)
    .bind(optional_i32(object, "next_id")?)
    .bind(max_attempts)
    .bind(value)
    .bind(&category)
    .bind(category_id)
    .bind(&challenge_kind)
    .bind(&exposure)
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
    sqlx::query("INSERT INTO ctfzone.flags (challenge_id,type,content,data) VALUES ($1,$2,$3,$4)")
        .bind(id)
        .bind(&initial_flag_type)
        .bind(flag_content)
        .bind(flag_data)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    if let Some(runtime) = runtime {
        super::runtimes::upsert_runtime_config(&mut transaction, id, user.id, runtime).await?;
    }
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
    let response_data = json!({
        "id": id,
        "name": name,
        "value": value,
        "description": description,
        "attribution": attribution,
        "connection_info": connection_info,
        "next_id": optional_i32(object, "next_id")?,
        "category": category,
        "category_id": category_id,
        "challenge_type": challenge_kind,
        "exposure": exposure,
        "state": state_value,
        "max_attempts": max_attempts,
        "position": position,
        "logic": logic,
        "initial": initial,
        "decay": decay,
        "minimum": minimum,
        "function": function,
        "type": challenge_type,
    });
    idempotency
        .complete(&mut transaction, id, &response_data)
        .await?;
    transaction.commit().await.map_err(ApiError::database)?;

    Ok((StatusCode::CREATED, Json(Success::new(response_data))).into_response())
}

pub(super) async fn detail(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    Ok(Json(Success::new(detail_data(state, user, challenge_id).await?)).into_response())
}

pub(super) async fn detail_data(
    state: AppState,
    user: Option<CurrentUser>,
    challenge_id: i32,
) -> Result<Value, ApiError> {
    let admin = user.as_ref().is_some_and(CurrentUser::is_admin);
    let access = challenge_access_context(&state, user.as_ref(), challenge_id).await?;
    let ChallengeAccessContext {
        challenge,
        team_mode,
        solved,
        prerequisite_preview,
    } = access;
    if let Some(preview) = prerequisite_preview {
        return Ok(json!({
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
        }));
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
    let (hints_value, files_value, tags_value) = sqlx::query_as::<_, (Value, Value, Value)>(
        r#"
        SELECT
          COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
              'id',id,'title',title,'cost',cost,'content',content,'unlocked',false
            ) ORDER BY cost,id)
            FROM ctfzone.hints WHERE challenge_id=$1
          ),'[]'::jsonb),
          COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
              'object_id',stored_objects.id,
              'name',stored_objects.original_filename,
              'content_type',stored_objects.content_type,
              'size',COALESCE(stored_objects.actual_size,stored_objects.expected_size),
              'sha256',stored_objects.actual_checksum
            ) ORDER BY stored_objects.created_at,stored_objects.id)
            FROM ctfzone.stored_objects
            WHERE stored_objects.purpose='challenge_asset'
              AND stored_objects.challenge_id=$1
              AND stored_objects.status='ready'
          ),'[]'::jsonb),
          COALESCE((
            SELECT jsonb_agg(value ORDER BY id)
            FROM ctfzone.tags WHERE challenge_id=$1 AND value IS NOT NULL
          ),'[]'::jsonb)
        "#,
    )
    .bind(challenge.id)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    let mut hints = serde_json::from_value::<Vec<HintRenderRow>>(hints_value)
        .map_err(|_| ApiError::upstream("Challenge hints are invalid"))?;
    for hint in &mut hints {
        if ended || unlocked_hints.contains(&hint.id) || admin {
            hint.unlocked = true;
        } else {
            hint.content = None;
        }
    }
    let object_rows = serde_json::from_value::<Vec<ObjectRenderRow>>(files_value)
        .map_err(|_| ApiError::upstream("Challenge files are invalid"))?;
    let files = object_rows
        .into_iter()
        .map(challenge_object_view)
        .collect::<Vec<_>>();
    let tags = serde_json::from_value::<Vec<String>>(tags_value)
        .map_err(|_| ApiError::upstream("Challenge tags are invalid"))?;

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
        let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
        super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
        crate::auth::revalidate_current_credential(
            &mut transaction,
            current,
            state.auth.session_lifetime_seconds,
        )
        .await?;
        // Re-read the mode while holding CONFIG-S. Tracking is reset by a mode
        // transition, so this insert must be ordered before or after that reset.
        let _ = super::user_mode_transition::transaction_user_mode(&mut transaction).await?;
        sqlx::query(
            r#"
            INSERT INTO ctfzone.tracking (type,ip,target,user_id,date)
            VALUES ('challenges.open',$1,$2,$3,timezone('utc',now()))
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(current.request_ip())
        .bind(challenge.id)
        .bind(current.id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        transaction.commit().await.map_err(ApiError::database)?;
    }

    Ok(response)
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
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    super::flag_policy::lock_challenge_definition(&mut transaction, challenge_id).await?;
    let current = challenge_detail_by_id_for_update(&mut transaction, challenge_id).await?;
    let dynamic_type = current.challenge_type.as_deref() == Some("dynamic");
    if object.contains_key("type")
        && required_string(object, "type", 80)?
            != current
                .challenge_type
                .clone()
                .unwrap_or_else(|| "standard".to_owned())
    {
        return Err(ApiError::bad_request(
            "Challenge scoring type cannot be changed after creation",
        ));
    }

    let name = patch_required_string(object, "name", current.name, 80)?;
    if object.contains_key("category") {
        return Err(ApiError::bad_request(
            "Select challenge categories by category_id",
        ));
    }
    let category_id = if object.contains_key("category_id") {
        optional_i32(object, "category_id")?
            .ok_or_else(|| ApiError::bad_request("Challenge category_id is required"))?
    } else {
        current.category_id
    };
    let category = sqlx::query_scalar::<_, String>(
        "SELECT name FROM ctfzone.challenge_categories WHERE id=$1 FOR KEY SHARE",
    )
    .bind(category_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::bad_request("Select an existing challenge category"))?;
    if object.contains_key("challenge_type")
        && required_string(object, "challenge_type", 32)? != current.challenge_kind
    {
        return Err(ApiError::bad_request(
            "Challenge type cannot be changed after creation",
        ));
    }
    let exposure = if object.contains_key("exposure") {
        required_string(object, "exposure", 16)?
    } else {
        current.exposure.clone()
    };
    if !matches!(exposure.as_str(), "public" | "private") {
        return Err(ApiError::bad_request(
            "Challenge exposure must be public or private",
        ));
    }
    let enable_global_gate =
        private_gate_enable_requested(object, current.challenge_kind.as_str(), exposure.as_str())?;
    if exposure != current.exposure {
        let active = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM ctfzone.runtime_instances WHERE challenge_id=$1 AND active)",
        )
        .bind(challenge_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        if active {
            return Err(ApiError::conflict(
                "Stop the active challenge instances before changing exposure",
            ));
        }
        if exposure == "private" {
            let managed = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM ctfzone.challenge_runtime_configs WHERE challenge_id=$1 AND runtime_mode='managed')",
            )
            .bind(challenge_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
            if !managed {
                return Err(ApiError::conflict(
                    "Configure a managed runtime before making the challenge private",
                ));
            }
        } else {
            let generated = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM ctfzone.flags WHERE challenge_id=$1 AND type='generated')",
            )
            .bind(challenge_id)
            .fetch_one(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
            if generated {
                return Err(ApiError::conflict(
                    "Replace the generated flag before making the challenge public",
                ));
            }
            sqlx::query("DELETE FROM ctfzone.challenge_runtime_configs WHERE challenge_id=$1")
                .bind(challenge_id)
                .execute(&mut *transaction)
                .await
                .map_err(ApiError::database)?;
        }
    }
    if object.contains_key("public_url") {
        return Err(ApiError::bad_request(
            "Challenge public_url is not supported; use optional connection_info",
        ));
    }
    let description = patch_text(object, "description", current.description, 65_536)?;
    let attribution = patch_text(object, "attribution", current.attribution, 2_048)?;
    let connection_info = patch_text(object, "connection_info", current.connection_info, 4_096)?;
    let next_id = patch_i32(object, "next_id", current.next_id)?;
    let max_attempts = validate_max_attempts(
        patch_i32(object, "max_attempts", current.max_attempts)?.unwrap_or(0),
    )?;
    let position = patch_i32(object, "position", Some(current.position))?.unwrap_or(0);
    if !(0..=32767).contains(&position) {
        return Err(ApiError::bad_request("Challenge position is invalid"));
    }
    let state_value = patch_required_string(object, "state", Some(current.state), 80)?;
    if !matches!(state_value.as_str(), "visible" | "hidden" | "locked") {
        return Err(ApiError::bad_request("Unsupported challenge state"));
    }
    if enable_global_gate {
        super::runtimes::prepare_private_challenge_gate(&mut transaction, user.id, true).await?;
    }
    if exposure == "private" && state_value != "hidden" {
        let launchable = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM ctfzone.runtime_settings setting
                JOIN ctfzone.challenge_runtime_configs runtime ON runtime.challenge_id=$1
                WHERE setting.key='private_challenges' AND setting.enabled
                  AND runtime.enabled AND runtime.runtime_mode='managed'
            )
            "#,
        )
        .bind(challenge_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        if !launchable {
            return Err(ApiError::conflict(
                "Enable the private runtime and global launch gate before publishing",
            ));
        }
    }
    let logic = patch_required_string(object, "logic", Some(current.logic), 80)?;
    if !matches!(logic.as_str(), "any" | "all" | "team") {
        return Err(ApiError::bad_request("Unsupported challenge logic"));
    }
    let function = patch_required_string(object, "function", current.function, 32)?;
    if (!dynamic_type && function != "static")
        || (dynamic_type && !matches!(function.as_str(), "linear" | "logarithmic"))
    {
        return Err(ApiError::bad_request(
            "Scoring type and decay function do not match",
        ));
    }
    let dynamic = dynamic_type;
    if !dynamic
        && ["initial", "minimum", "decay"]
            .iter()
            .any(|field| object.contains_key(*field))
    {
        return Err(ApiError::bad_request(
            "Standard scoring cannot define dynamic scoring fields",
        ));
    }
    let initial = dynamic
        .then(|| patch_i32(object, "initial", current.initial))
        .transpose()?
        .flatten();
    let minimum = dynamic
        .then(|| patch_i32(object, "minimum", current.minimum))
        .transpose()?
        .flatten();
    let decay = dynamic
        .then(|| patch_i32(object, "decay", current.decay))
        .transpose()?
        .flatten();
    if dynamic && (initial.is_none() || minimum.is_none() || decay.is_none()) {
        return Err(ApiError::bad_request(
            "Dynamic challenges require initial, minimum, and decay",
        ));
    }
    if dynamic
        && (initial.is_some_and(|value| value < 0)
            || minimum.is_some_and(|value| value < 0)
            || initial
                .zip(minimum)
                .is_some_and(|(initial, minimum)| minimum > initial)
            || decay.is_some_and(|value| value <= 0))
    {
        return Err(ApiError::bad_request(
            "Dynamic scoring requires initial >= minimum >= 0 and decay > 0",
        ));
    }
    let supplied_value = object
        .contains_key("value")
        .then(|| patch_i32(object, "value", current.value))
        .transpose()?
        .flatten();
    if dynamic
        && supplied_value
            .zip(initial)
            .is_some_and(|(value, initial)| value != initial)
    {
        return Err(ApiError::bad_request(
            "Dynamic value must match the initial score",
        ));
    }
    let value = if dynamic {
        initial.expect("validated above")
    } else {
        patch_i32(object, "value", current.value)?
            .ok_or_else(|| ApiError::bad_request("Challenge value is required"))?
    };
    if value < 0 {
        return Err(ApiError::bad_request("Challenge value cannot be negative"));
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
    let team_mode = if dynamic {
        Some(super::user_mode_transition::transaction_user_mode(&mut transaction).await? == "teams")
    } else {
        None
    };
    sqlx::query(
        r#"
        UPDATE ctfzone.challenges SET
            name=$1,description=$2,attribution=$3,connection_info=$4,next_id=$5,
            max_attempts=$6,value=$7,category=$8,category_id=$9,state=$10,logic=$11,
            exposure=$12,initial=$13,minimum=$14,decay=$15,
            position=$16,function=$17,requirements=$18
        WHERE id=$19
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
    .bind(category_id)
    .bind(state_value)
    .bind(logic)
    .bind(exposure)
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
        recalculate_dynamic_value(
            &mut transaction,
            &updated,
            team_mode.expect("loaded for dynamic challenges"),
        )
        .await?;
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
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    super::flag_policy::lock_challenge_definition(&mut transaction, challenge_id).await?;
    let exists =
        sqlx::query_scalar::<_, i32>("SELECT id FROM ctfzone.challenges WHERE id=$1 FOR UPDATE")
            .bind(challenge_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(ApiError::database)?
            .is_some();
    if !exists {
        return Err(ApiError::not_found("Challenge not found"));
    }
    let (active, assignments) = sqlx::query_as::<_, (bool, bool)>(
        r#"
        SELECT
          EXISTS(SELECT 1 FROM ctfzone.runtime_instances WHERE challenge_id=$1 AND active),
          EXISTS(SELECT 1 FROM ctfzone.user_challenge_flags WHERE challenge_id=$1)
        "#,
    )
    .bind(challenge_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if active {
        return Err(ApiError::conflict(
            "Stop the active challenge instances before deleting the challenge",
        ));
    }
    if assignments {
        return Err(ApiError::conflict(
            "Challenges with allocated per-user flags cannot be deleted",
        ));
    }
    let result = sqlx::query("DELETE FROM ctfzone.challenges WHERE id=$1")
        .bind(challenge_id)
        .execute(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Challenge not found"));
    }
    super::create_idempotency::forget_resource(
        &mut transaction,
        super::create_idempotency::CHALLENGE_CREATE,
        challenge_id,
    )
    .await?;
    transaction.commit().await.map_err(ApiError::database)?;
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

    let submission = request.submission.trim();
    if submission.is_empty() || submission.len() > 4096 || submission.contains('\0') {
        return Err(ApiError::bad_request(
            "A submission between 1 and 4096 bytes is required",
        ));
    }
    let incorrect_limit = config_i64(&state, "incorrect_submissions_per_min", 10).await?;
    let max_behavior = config_string(&state, "max_attempts_behavior")
        .await?
        .unwrap_or_else(|| "lockout".to_owned());
    let max_timeout = config_i64(&state, "max_attempts_timeout", 300).await?;

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    super::user_mode_transition::lock_configuration_shared(&mut transaction).await?;
    crate::auth::revalidate_current_credential(
        &mut transaction,
        &user,
        state.auth.session_lifetime_seconds,
    )
    .await?;
    let team_mode =
        super::user_mode_transition::transaction_user_mode(&mut transaction).await? == "teams";
    let submission_team_id = if team_mode {
        super::team_accounts::lock_team_membership(&mut transaction).await?;
        Some(
            sqlx::query_scalar::<_, Option<i32>>(
                "SELECT team_id FROM ctfzone.users WHERE id=$1 AND type='user'",
            )
            .bind(user.id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(ApiError::database)?
            .flatten()
            .ok_or_else(|| ApiError::forbidden("Join a team before submitting flags"))?,
        )
    } else {
        None
    };
    let account = if let Some(team_id) = submission_team_id {
        Account::Team(team_id)
    } else {
        Account::User(user.id)
    };
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
        "SELECT id,type AS flag_type,content,data,revision FROM ctfzone.flags WHERE challenge_id=$1 ORDER BY id",
    )
    .bind(challenge.id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if flags.is_empty() {
        return Err(ApiError::upstream("The challenge has no flag definition"));
    }

    if preview {
        let outcome = compare_submission(
            &mut transaction,
            account,
            &challenge,
            &flags,
            submission,
            SubmissionComparisonContext {
                user_id: user.id,
                team_mode,
                secret_key: &state.auth.secret_key,
            },
        )
        .await?;
        return Ok(flag_result_response(outcome.outcome));
    }

    let now = Utc::now().naive_utc();
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
                    submission_team_id,
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
            submission_team_id,
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

    let comparison = compare_submission(
        &mut transaction,
        account,
        &challenge,
        &flags,
        submission,
        SubmissionComparisonContext {
            user_id: user.id,
            team_mode,
            secret_key: &state.auth.secret_key,
        },
    )
    .await?;

    if has_solved(&mut transaction, account, challenge.id).await? {
        let submission_id = insert_submission(
            &mut transaction,
            &user,
            submission_team_id,
            challenge.id,
            submission,
            "discard",
        )
        .await?;
        record_shared_flag_evidence(
            &mut transaction,
            submission_id,
            challenge.id,
            user.id,
            submission_team_id,
            comparison.shared,
        )
        .await?;
        transaction.commit().await.map_err(ApiError::database)?;
        return Ok(attempt_response(
            StatusCode::OK,
            "already_solved",
            Some("Correct but you already solved this".to_owned()),
        ));
    }

    let response = match comparison.outcome {
        FlagResult::Correct => {
            let submission_id = insert_submission(
                &mut transaction,
                &user,
                submission_team_id,
                challenge.id,
                submission,
                "correct",
            )
            .await?;
            record_shared_flag_evidence(
                &mut transaction,
                submission_id,
                challenge.id,
                user.id,
                submission_team_id,
                comparison.shared,
            )
            .await?;
            sqlx::query(
                "INSERT INTO ctfzone.solves (id, challenge_id, user_id, team_id) VALUES ($1, $2, $3, $4)",
            )
            .bind(submission_id)
            .bind(challenge.id)
            .bind(user.id)
            .bind(submission_team_id)
            .execute(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
            recalculate_dynamic_value(&mut transaction, &challenge, team_mode).await?;
            attempt_response(StatusCode::OK, "correct", Some("Correct".to_owned()))
        }
        FlagResult::Partial => {
            let submission_id = insert_submission(
                &mut transaction,
                &user,
                submission_team_id,
                challenge.id,
                submission,
                "partial",
            )
            .await?;
            record_shared_flag_evidence(
                &mut transaction,
                submission_id,
                challenge.id,
                user.id,
                submission_team_id,
                comparison.shared,
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
            let submission_id = insert_submission(
                &mut transaction,
                &user,
                submission_team_id,
                challenge.id,
                submission,
                "incorrect",
            )
            .await?;
            record_shared_flag_evidence(
                &mut transaction,
                submission_id,
                challenge.id,
                user.id,
                submission_team_id,
                comparison.shared,
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
    let mut connection = state.database.acquire().await.map_err(ApiError::database)?;
    challenge_detail_by_id_on(&mut connection, challenge_id).await
}

async fn challenge_detail_by_id_on(
    connection: &mut PgConnection,
    challenge_id: i32,
) -> Result<ChallengeDetailRow, ApiError> {
    sqlx::query_as::<_, ChallengeDetailRow>(
        r#"
        SELECT c.id,c.name,c.description,c.attribution,c.connection_info,c.next_id,c.max_attempts,
               c.value,c.category,c.category_id,c.challenge_type AS challenge_kind,
               c.exposure,c.type AS challenge_type,c.state,c.logic,
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
    .fetch_optional(&mut *connection)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Challenge not found"))
}

async fn challenge_detail_by_id_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    challenge_id: i32,
) -> Result<ChallengeDetailRow, ApiError> {
    sqlx::query_as::<_, ChallengeDetailRow>(
        r#"
        SELECT c.id,c.name,c.description,c.attribution,c.connection_info,c.next_id,c.max_attempts,
               c.value,c.category,c.category_id,c.challenge_type AS challenge_kind,
               c.exposure,c.type AS challenge_type,c.state,c.logic,
               COALESCE(dc.dynamic_initial,c.initial) AS initial,
               COALESCE(dc.dynamic_minimum,c.minimum) AS minimum,
               COALESCE(dc.dynamic_decay,c.decay) AS decay,
               c.position,COALESCE(dc.dynamic_function,c.function) AS function,c.requirements
        FROM ctfzone.challenges c
        LEFT JOIN ctfzone.dynamic_challenge dc ON dc.id=c.id
        WHERE c.id=$1
        FOR UPDATE OF c
        "#,
    )
    .bind(challenge_id)
    .fetch_optional(&mut **transaction)
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
        "category_id": challenge.category_id,
        "challenge_type": challenge.challenge_kind,
        "exposure": challenge.exposure,
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

fn challenge_object_view(object: ObjectRenderRow) -> ChallengeObjectView {
    ChallengeObjectView {
        object_id: object.object_id,
        name: object.name,
        content_type: object.content_type,
        size: object.size,
        sha256: object.sha256,
    }
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

fn patch_text(
    object: &Map<String, Value>,
    key: &str,
    current: Option<String>,
    max_bytes: usize,
) -> Result<Option<String>, ApiError> {
    if object.contains_key(key) {
        optional_text(object, key, max_bytes)
    } else {
        Ok(current)
    }
}

fn optional_text(
    object: &Map<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<String>, ApiError> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let value = match value {
        Value::Null => return Ok(None),
        Value::String(value) => value,
        _ => {
            return Err(ApiError::bad_request(format!(
                "Challenge {key} must be a string or null"
            )));
        }
    };
    if value.trim().is_empty() {
        return Ok(None);
    }
    if value.len() > max_bytes {
        return Err(ApiError::bad_request(format!(
            "Challenge {key} is too long"
        )));
    }
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(ApiError::bad_request(format!(
            "Challenge {key} contains unsupported control characters"
        )));
    }
    Ok(Some(value.clone()))
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
    context: SubmissionComparisonContext<'_>,
) -> Result<ComparisonResult, ApiError> {
    if flags.is_empty() {
        return Ok(ComparisonResult {
            outcome: FlagResult::Incorrect("Incorrect".to_owned()),
            shared: None,
        });
    }
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
            let current_index = provided.len() - 1;
            let mut shared = None;
            let mut all_matched = true;
            for flag in flags {
                let mut matched = false;
                for (index, candidate) in provided.iter().enumerate() {
                    let evaluation = flag_matches(
                        transaction,
                        flag,
                        candidate,
                        challenge.id,
                        context.user_id,
                        context.secret_key,
                    )
                    .await?;
                    if index == current_index && evaluation.shared.is_some() {
                        shared = evaluation.shared;
                    }
                    if evaluation.matched {
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
                Ok(ComparisonResult {
                    outcome: FlagResult::Correct,
                    shared,
                })
            } else {
                for flag in flags {
                    let evaluation = flag_matches(
                        transaction,
                        flag,
                        submission,
                        challenge.id,
                        context.user_id,
                        context.secret_key,
                    )
                    .await?;
                    if evaluation.shared.is_some() {
                        shared = evaluation.shared;
                    }
                    if evaluation.matched {
                        return Ok(ComparisonResult {
                            outcome: FlagResult::Partial,
                            shared,
                        });
                    }
                }
                Ok(ComparisonResult {
                    outcome: FlagResult::Incorrect("Incorrect".to_owned()),
                    shared,
                })
            }
        }
        "team" if context.team_mode => {
            let mut correct = false;
            let mut shared = None;
            for flag in flags {
                let evaluation = flag_matches(
                    transaction,
                    flag,
                    submission,
                    challenge.id,
                    context.user_id,
                    context.secret_key,
                )
                .await?;
                if evaluation.shared.is_some() {
                    shared = evaluation.shared;
                }
                if evaluation.matched {
                    correct = true;
                    break;
                }
            }
            if !correct {
                return Ok(ComparisonResult {
                    outcome: FlagResult::Incorrect("Incorrect".to_owned()),
                    shared,
                });
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
            submitters.insert(context.user_id);
            let members =
                sqlx::query_scalar::<_, i32>("SELECT id FROM ctfzone.users WHERE team_id=$1")
                    .bind(account.id())
                    .fetch_all(&mut **transaction)
                    .await
                    .map_err(ApiError::database)?
                    .into_iter()
                    .collect::<HashSet<_>>();
            if submitters == members {
                Ok(ComparisonResult {
                    outcome: FlagResult::Correct,
                    shared,
                })
            } else {
                Ok(ComparisonResult {
                    outcome: FlagResult::Partial,
                    shared,
                })
            }
        }
        _ => {
            let mut shared = None;
            for flag in flags {
                let evaluation = flag_matches(
                    transaction,
                    flag,
                    submission,
                    challenge.id,
                    context.user_id,
                    context.secret_key,
                )
                .await?;
                if evaluation.shared.is_some() {
                    shared = evaluation.shared;
                }
                if evaluation.matched {
                    return Ok(ComparisonResult {
                        outcome: FlagResult::Correct,
                        shared,
                    });
                }
            }
            Ok(ComparisonResult {
                outcome: FlagResult::Incorrect("Incorrect".to_owned()),
                shared,
            })
        }
    }
}

struct FlagEvaluation {
    matched: bool,
    shared: Option<SharedFlagEvidence>,
}

async fn flag_matches(
    transaction: &mut Transaction<'_, Postgres>,
    flag: &FlagRow,
    provided: &str,
    challenge_id: i32,
    user_id: i32,
    secret_key: &str,
) -> Result<FlagEvaluation, ApiError> {
    let policy = serde_json::from_value::<super::flag_policy::FlagPolicyData>(flag.data.clone())
        .map_err(|_| ApiError::upstream("Stored flag options are invalid"))?;
    match flag.flag_type.as_str() {
        "static" => Ok(FlagEvaluation {
            matched: super::flag_policy::flag_matches_literal(
                &flag.content,
                provided,
                policy.case_sensitive,
            ),
            shared: None,
        }),
        "regex" => Ok(FlagEvaluation {
            matched: super::flag_policy::flag_matches_regex(
                &flag.content,
                provided,
                policy.case_sensitive,
            )?,
            shared: None,
        }),
        "generated" => match super::flag_policy::generated_flag_match(
            transaction,
            flag,
            provided,
            user_id,
            challenge_id,
            secret_key,
        )
        .await?
        {
            super::flag_policy::FlagMatch::No => Ok(FlagEvaluation {
                matched: false,
                shared: None,
            }),
            super::flag_policy::FlagMatch::Own => Ok(FlagEvaluation {
                matched: true,
                shared: None,
            }),
            super::flag_policy::FlagMatch::Other {
                flag_id,
                source_user_id,
                accepted,
                match_tag,
            } => Ok(FlagEvaluation {
                matched: accepted,
                shared: Some(SharedFlagEvidence {
                    flag_id,
                    source_user_id,
                    accepted,
                    match_tag,
                }),
            }),
        },
        _ => Err(ApiError::bad_request(format!(
            "Unsupported flag type on flag {}",
            flag.id
        ))),
    }
}

async fn insert_submission(
    transaction: &mut Transaction<'_, Postgres>,
    user: &CurrentUser,
    team_id: Option<i32>,
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
    .bind(team_id)
    .bind(user.request_ip())
    .bind(provided)
    .bind(submission_type)
    .fetch_one(&mut **transaction)
    .await
    .map_err(ApiError::database)
}

async fn record_shared_flag_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    submission_id: i32,
    challenge_id: i32,
    submitting_user_id: i32,
    team_id_snapshot: Option<i32>,
    evidence: Option<SharedFlagEvidence>,
) -> Result<(), ApiError> {
    let Some(evidence) = evidence else {
        return Ok(());
    };
    sqlx::query(
        r#"
        INSERT INTO ctfzone.flag_sharing_events
            (submission_id,challenge_id,flag_id,submitting_user_id,source_user_id,
             team_id_snapshot,provided_match_tag,accepted)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        "#,
    )
    .bind(submission_id)
    .bind(challenge_id)
    .bind(evidence.flag_id)
    .bind(submitting_user_id)
    .bind(evidence.source_user_id)
    .bind(team_id_snapshot)
    .bind(evidence.match_tag.as_slice())
    .bind(evidence.accepted)
    .execute(&mut **transaction)
    .await
    .map_err(ApiError::database)?;
    Ok(())
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
    // Account locks prevent duplicate solves by one account; this lock serializes the dynamic
    // value transition across different accounts and administrator recalculations.
    sqlx::query("SELECT pg_advisory_xact_lock($1,$2)")
        .bind(DYNAMIC_SCORE_LOCK_NAMESPACE)
        .bind(challenge.id)
        .execute(&mut **transaction)
        .await
        .map_err(ApiError::database)?;
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
    let mut connection = state.database.acquire().await.map_err(ApiError::database)?;
    solved_challenge_ids_on(&mut connection, user, team_mode).await
}

async fn solved_challenge_ids_on(
    connection: &mut PgConnection,
    user: Option<&CurrentUser>,
    team_mode: bool,
) -> Result<HashSet<i32>, ApiError> {
    let Some(user) = user else {
        return Ok(HashSet::new());
    };
    let team_id = if team_mode {
        sqlx::query_scalar::<_, Option<i32>>("SELECT team_id FROM ctfzone.users WHERE id=$1")
            .bind(user.id)
            .fetch_optional(&mut *connection)
            .await
            .map_err(ApiError::database)?
            .flatten()
    } else {
        None
    };
    solved_challenge_ids_for_identity_on(connection, Some(user.id), team_id, team_mode).await
}

async fn solved_challenge_ids_for_identity_on(
    connection: &mut PgConnection,
    user_id: Option<i32>,
    team_id: Option<i32>,
    team_mode: bool,
) -> Result<HashSet<i32>, ApiError> {
    let (column, account_id) = if team_mode {
        ("team_id", team_id)
    } else {
        ("user_id", user_id)
    };
    let Some(account_id) = account_id else {
        return Ok(HashSet::new());
    };
    let sql = format!("SELECT challenge_id FROM ctfzone.solves WHERE {column}=$1");
    Ok(sqlx::query_scalar::<_, Option<i32>>(&sql)
        .bind(account_id)
        .fetch_all(&mut *connection)
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

async fn tags_for_challenges(
    state: &AppState,
    challenge_ids: &[i32],
) -> Result<HashMap<i32, Vec<Value>>, ApiError> {
    if challenge_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows = sqlx::query_as::<_, (i32, Option<String>)>(
        "SELECT challenge_id,value FROM ctfzone.tags WHERE challenge_id=ANY($1) ORDER BY challenge_id,id",
    )
    .bind(challenge_ids)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    let mut grouped = HashMap::<i32, Vec<Value>>::new();
    for (challenge_id, value) in rows {
        if let Some(value) = value {
            grouped
                .entry(challenge_id)
                .or_default()
                .push(json!({"value": value}));
        }
    }
    Ok(grouped)
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

fn private_gate_enable_requested(
    object: &Map<String, Value>,
    challenge_kind: &str,
    exposure: &str,
) -> Result<bool, ApiError> {
    let Some(value) = object.get("enable_global_gate") else {
        return Ok(false);
    };
    let enable = value
        .as_bool()
        .ok_or_else(|| ApiError::bad_request("Challenge enable_global_gate must be a boolean"))?;
    if challenge_kind != "jeopardy" {
        return Err(ApiError::bad_request(
            "enable_global_gate is available only for Jeopardy challenges",
        ));
    }
    if exposure != "private" {
        return Err(ApiError::bad_request(
            "enable_global_gate is available only for private challenges",
        ));
    }
    Ok(enable)
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

fn validate_max_attempts(value: i32) -> Result<i32, ApiError> {
    if value < 0 {
        Err(ApiError::bad_request(
            "Challenge max_attempts cannot be negative",
        ))
    } else {
        Ok(value)
    }
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
    let mut connection = state.database.acquire().await.map_err(ApiError::database)?;
    require_challenge_visibility_on(&mut connection, user).await
}

async fn require_challenge_visibility_on(
    connection: &mut PgConnection,
    user: Option<&CurrentUser>,
) -> Result<(), ApiError> {
    match config_string_on(connection, "challenge_visibility")
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
    let mut connection = state.database.acquire().await.map_err(ApiError::database)?;
    require_ctf_time_on(&mut connection, user).await
}

async fn require_ctf_time_on(
    connection: &mut PgConnection,
    user: Option<&CurrentUser>,
) -> Result<(), ApiError> {
    if user.is_some_and(CurrentUser::is_admin) {
        return Ok(());
    }
    let now = Utc::now().timestamp();
    let start = config_i64_on(connection, "start", 0).await?;
    let end = config_i64_on(connection, "end", 0).await?;
    let view_after_ctf =
        end != 0 && now > end && config_bool_on(connection, "view_after_ctf", false).await?;
    match ctf_time_access(now, start, end, view_after_ctf) {
        CtfTimeAccess::Allowed => Ok(()),
        CtfTimeAccess::NotStarted => Err(ApiError::forbidden("CTFZone has not started yet")),
        CtfTimeAccess::Ended => Err(ApiError::forbidden("CTFZone has ended")),
    }
}

pub(super) async fn require_verified(
    state: &AppState,
    user: Option<&CurrentUser>,
) -> Result<(), ApiError> {
    let mut connection = state.database.acquire().await.map_err(ApiError::database)?;
    require_verified_on(&mut connection, user).await
}

async fn require_verified_on(
    connection: &mut PgConnection,
    user: Option<&CurrentUser>,
) -> Result<(), ApiError> {
    let verification_enabled = config_bool_on(connection, "verify_emails", false).await?;
    if verification_missing(
        verification_enabled,
        user.map(|user| (user.is_admin(), user.verified)),
    ) {
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
    let mut connection = state.database.acquire().await.map_err(ApiError::database)?;
    is_team_mode_on(&mut connection).await
}

async fn is_team_mode_on(connection: &mut PgConnection) -> Result<bool, ApiError> {
    Ok(config_string_on(connection, "user_mode").await?.as_deref() == Some("teams"))
}

async fn config_string(state: &AppState, key: &str) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar::<_, Option<String>>("SELECT value FROM ctfzone.config WHERE key=$1 LIMIT 1")
        .bind(key)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)
        .map(Option::flatten)
}

async fn config_string_on(
    connection: &mut PgConnection,
    key: &str,
) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar::<_, Option<String>>("SELECT value FROM ctfzone.config WHERE key=$1 LIMIT 1")
        .bind(key)
        .fetch_optional(&mut *connection)
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

async fn config_bool_on(
    connection: &mut PgConnection,
    key: &str,
    default: bool,
) -> Result<bool, ApiError> {
    Ok(config_string_on(connection, key)
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

async fn config_i64_on(
    connection: &mut PgConnection,
    key: &str,
    default: i64,
) -> Result<i64, ApiError> {
    let value = config_string_on(connection, key).await?;
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
        assert!(super::super::flag_policy::flag_matches_literal(
            "CTF{yes}", "CTF{yes}", true
        ));
        assert!(!super::super::flag_policy::flag_matches_literal(
            "CTF{yes}", "ctf{yes}", true
        ));
        assert!(super::super::flag_policy::flag_matches_literal(
            "CTF{yes}", "ctf{YES}", false
        ));
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
    fn full_access_rejects_hidden_locked_and_unsatisfied_challenges() {
        let solved = HashSet::from([1]);
        let mut challenge = access_test_challenge("hidden", None);
        assert_eq!(
            challenge_row_access(&challenge, false, &solved),
            ChallengeRowAccess::NotFound
        );
        challenge.state = "locked".to_owned();
        assert_eq!(
            challenge_row_access(&challenge, false, &solved),
            ChallengeRowAccess::NotFound
        );
        challenge.state = "visible".to_owned();
        challenge.requirements = Some(json!({"prerequisites": [2]}));
        assert_eq!(
            challenge_row_access(&challenge, false, &solved),
            ChallengeRowAccess::PrerequisitesDenied
        );
        challenge.requirements = Some(json!({"prerequisites": [2], "anonymize": "preview"}));
        assert_eq!(
            challenge_row_access(&challenge, false, &solved),
            ChallengeRowAccess::HiddenPreview(true)
        );
        assert_eq!(
            challenge_row_access(&challenge, true, &solved),
            ChallengeRowAccess::Full
        );
    }

    #[test]
    fn full_access_rejects_unverified_teamless_and_prestart_users() {
        assert!(verification_missing(true, Some((false, false))));
        assert!(!verification_missing(true, Some((true, false))));
        assert!(!verification_missing(false, Some((false, false))));
        assert!(team_membership_missing(true, Some((false, None))));
        assert!(!team_membership_missing(true, Some((true, None))));
        assert!(!team_membership_missing(false, Some((false, None))));
        assert_eq!(
            ctf_time_access(100, 101, 0, false),
            CtfTimeAccess::NotStarted
        );
        assert_eq!(ctf_time_access(100, 0, 99, false), CtfTimeAccess::Ended);
        assert_eq!(ctf_time_access(100, 0, 99, true), CtfTimeAccess::Allowed);
    }

    #[test]
    fn private_gate_enable_request_is_boolean_and_private_jeopardy_only() {
        let enabled = json!({"enable_global_gate": true});
        let disabled = json!({"enable_global_gate": false});
        let missing = json!({});
        let invalid = json!({"enable_global_gate": "true"});

        assert!(matches!(
            private_gate_enable_requested(enabled.as_object().unwrap(), "jeopardy", "private"),
            Ok(true)
        ));
        assert!(matches!(
            private_gate_enable_requested(disabled.as_object().unwrap(), "jeopardy", "private"),
            Ok(false)
        ));
        assert!(matches!(
            private_gate_enable_requested(missing.as_object().unwrap(), "jeopardy", "private"),
            Ok(false)
        ));
        assert!(
            private_gate_enable_requested(invalid.as_object().unwrap(), "jeopardy", "private")
                .is_err()
        );
        assert!(
            private_gate_enable_requested(enabled.as_object().unwrap(), "jeopardy", "public")
                .is_err()
        );
        assert!(
            private_gate_enable_requested(
                enabled.as_object().unwrap(),
                "attack_defense",
                "private"
            )
            .is_err()
        );
    }

    #[test]
    fn max_attempts_uses_zero_as_unlimited_and_rejects_negative_values() {
        assert_eq!(validate_max_attempts(0).expect("zero is unlimited"), 0);
        assert_eq!(validate_max_attempts(1).expect("positive limit"), 1);
        assert!(validate_max_attempts(-1).is_err());
    }

    #[test]
    fn optional_authoring_text_is_typed_bounded_and_allows_multiline_commands() {
        let valid = json!({
            "connection_info": "nc challenge.example 31337\n# or open the link in the description",
            "attribution": "Alice, **Bob**",
        });
        let object = valid.as_object().unwrap();
        assert_eq!(
            optional_text(object, "connection_info", 4_096)
                .unwrap()
                .as_deref(),
            Some("nc challenge.example 31337\n# or open the link in the description")
        );
        assert_eq!(
            optional_text(object, "attribution", 2_048)
                .unwrap()
                .as_deref(),
            Some("Alice, **Bob**")
        );

        assert!(optional_text(json!({"value": 7}).as_object().unwrap(), "value", 8).is_err());
        assert!(
            optional_text(
                json!({"value": "bad\u{0000}"}).as_object().unwrap(),
                "value",
                8
            )
            .is_err()
        );
        assert!(
            optional_text(
                json!({"value": "123456789"}).as_object().unwrap(),
                "value",
                8
            )
            .is_err()
        );
        assert_eq!(
            optional_text(json!({"value": "  "}).as_object().unwrap(), "value", 8).unwrap(),
            None
        );
    }

    fn access_test_challenge(state: &str, requirements: Option<Value>) -> ChallengeDetailRow {
        ChallengeDetailRow {
            id: 1,
            name: Some("test".to_owned()),
            description: None,
            attribution: None,
            connection_info: None,
            next_id: None,
            max_attempts: None,
            value: Some(100),
            category: Some("test".to_owned()),
            category_id: 1,
            challenge_kind: "jeopardy".to_owned(),
            exposure: "public".to_owned(),
            challenge_type: Some("standard".to_owned()),
            state: state.to_owned(),
            logic: "any".to_owned(),
            initial: None,
            minimum: None,
            decay: None,
            position: 0,
            function: Some("static".to_owned()),
            requirements,
        }
    }
}
