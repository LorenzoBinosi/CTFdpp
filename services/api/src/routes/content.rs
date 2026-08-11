use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::{FromRow, Postgres, Transaction};

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
    routes::Success,
};

#[derive(Deserialize, Default)]
pub(super) struct PageQuery {
    page: Option<i64>,
    per_page: Option<i64>,
    challenge_id: Option<i32>,
    since_id: Option<i32>,
}

#[derive(Deserialize)]
pub(super) struct RatingInput {
    value: i32,
    #[serde(default)]
    review: String,
}

#[derive(Deserialize)]
pub(super) struct UnlockInput {
    target: i32,
    #[serde(rename = "type")]
    target_type: String,
}

#[derive(Deserialize)]
pub(super) struct HintInput {
    title: Option<String>,
    #[serde(rename = "type")]
    hint_type: Option<String>,
    challenge_id: i32,
    content: String,
    #[serde(default)]
    cost: i32,
    requirements: Option<Value>,
}

#[derive(Deserialize, Default)]
pub(super) struct HintPatch {
    title: Option<String>,
    #[serde(rename = "type")]
    hint_type: Option<String>,
    challenge_id: Option<i32>,
    content: Option<String>,
    cost: Option<i32>,
    requirements: Option<Value>,
}

#[derive(Deserialize)]
pub(super) struct SolutionInput {
    challenge_id: i32,
    content: String,
    state: Option<String>,
}

#[derive(Deserialize, Default)]
pub(super) struct SolutionPatch {
    challenge_id: Option<i32>,
    content: Option<String>,
    state: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct NotificationInput {
    title: String,
    content: String,
    user_id: Option<i32>,
    team_id: Option<i32>,
    #[serde(rename = "type")]
    notification_type: Option<String>,
    sound: Option<bool>,
}

#[derive(FromRow, Serialize)]
struct SolveView {
    account_id: i32,
    account_url: String,
    name: Option<String>,
    date: NaiveDateTime,
}

#[derive(Clone, FromRow, Serialize)]
struct HintView {
    id: i32,
    title: Option<String>,
    #[serde(rename = "type")]
    hint_type: Option<String>,
    challenge_id: Option<i32>,
    content: Option<String>,
    cost: Option<i32>,
    requirements: Option<Value>,
}

#[derive(Clone, FromRow, Serialize)]
struct SolutionView {
    id: i32,
    challenge_id: Option<i32>,
    content: Option<String>,
    state: String,
}

#[derive(FromRow, Serialize)]
struct RatingView {
    id: i32,
    user_id: Option<i32>,
    challenge_id: Option<i32>,
    value: Option<i32>,
    review: Option<String>,
    date: Option<NaiveDateTime>,
    name: Option<String>,
}

#[derive(FromRow, Serialize)]
struct NotificationView {
    id: i32,
    title: Option<String>,
    content: Option<String>,
    date: Option<NaiveDateTime>,
    user_id: Option<i32>,
    team_id: Option<i32>,
}

#[derive(FromRow, Serialize)]
struct UnlockView {
    id: i32,
    user_id: Option<i32>,
    team_id: Option<i32>,
    target: Option<i32>,
    date: Option<NaiveDateTime>,
    #[serde(rename = "type")]
    unlock_type: Option<String>,
}

pub(super) async fn challenge_types() -> Response {
    Json(Success::new(json!({
        "standard": {
            "id": "standard",
            "name": "standard",
            "capabilities": {"flag_submission": true, "dynamic_scoring": false}
        },
        "dynamic": {
            "id": "dynamic",
            "name": "dynamic",
            "capabilities": {"flag_submission": true, "dynamic_scoring": true}
        }
    })))
    .into_response()
}

pub(super) async fn challenge_solves(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    if !super::challenges::scores_and_accounts_visible(&state, user.as_ref()).await? {
        return Err(ApiError::forbidden("Solve information is not available"));
    }
    let team_mode = super::challenges::is_team_mode(&state).await?;
    let (account, table) = if team_mode {
        ("s.team_id", "teams")
    } else {
        ("s.user_id", "users")
    };
    let sql = format!(
        r#"
        SELECT {account} AS account_id,
               '/{table}/' || {account}::text AS account_url,
               a.name,s.date
        FROM ctfzone.submissions s
        JOIN ctfzone.solves solved ON solved.id=s.id
        JOIN ctfzone.{table} a ON a.id={account}
        WHERE s.challenge_id=$1 AND NOT COALESCE(a.hidden,false) AND NOT COALESCE(a.banned,false)
        ORDER BY s.date
        "#,
    );
    let rows = sqlx::query_as::<_, SolveView>(&sql)
        .bind(challenge_id)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn challenge_files(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let data = sqlx::query_as::<_, (i32, Option<String>, Option<String>, Option<String>)>(
        "SELECT id,type,location,sha1sum FROM ctfzone.files WHERE challenge_id=$1 ORDER BY id",
    )
    .bind(challenge_id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?
    .into_iter()
    .map(|(id, file_type, location, sha1sum)| {
        json!({"id": id, "type": file_type, "location": location, "sha1sum": sha1sum, "challenge_id": challenge_id})
    })
    .collect::<Vec<_>>();
    Ok(Json(Success::new(data)).into_response())
}

pub(super) async fn challenge_tags(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    simple_relation(&state, "tags", challenge_id).await
}

pub(super) async fn challenge_topics(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let data = sqlx::query_as::<_, (i32, i32, i32, Option<String>)>(
        r#"
        SELECT ct.id,ct.challenge_id,ct.topic_id,t.value
        FROM ctfzone.challenge_topics ct JOIN ctfzone.topics t ON t.id=ct.topic_id
        WHERE ct.challenge_id=$1 ORDER BY ct.id
        "#,
    )
    .bind(challenge_id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?
    .into_iter()
    .map(|(id, challenge_id, topic_id, value)| {
        json!({"id": id, "challenge_id": challenge_id, "topic_id": topic_id, "value": value})
    })
    .collect::<Vec<_>>();
    Ok(Json(Success::new(data)).into_response())
}

pub(super) async fn challenge_hints(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let rows = load_hints(&state, Some(challenge_id)).await?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn challenge_flags(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let data = sqlx::query_as::<_, (i32, Option<i32>, Option<String>, Option<String>, Option<String>)>(
        "SELECT id,challenge_id,type,content,data FROM ctfzone.flags WHERE challenge_id=$1 ORDER BY id",
    )
    .bind(challenge_id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?
    .into_iter()
    .map(|(id, challenge_id, flag_type, content, data)| json!({
        "id": id, "challenge_id": challenge_id, "type": flag_type, "content": content, "data": data
    }))
    .collect::<Vec<_>>();
    Ok(Json(Success::new(data)).into_response())
}

pub(super) async fn challenge_requirements(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let requirements = sqlx::query_scalar::<_, Option<Value>>(
        "SELECT requirements FROM ctfzone.challenges WHERE id=$1",
    )
    .bind(challenge_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Challenge not found"))?;
    Ok(Json(Success::new(requirements)).into_response())
}

pub(super) async fn challenge_ratings(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(50).clamp(1, 50);
    let ratings = sqlx::query_as::<_, RatingView>(
        r#"
        SELECT r.id,r.user_id,r.challenge_id,r.value,r.review,r.date,u.name
        FROM ctfzone.ratings r LEFT JOIN ctfzone.users u ON u.id=r.user_id
        WHERE r.challenge_id=$1 ORDER BY r.id DESC LIMIT $2 OFFSET $3
        "#,
    )
    .bind(challenge_id)
    .bind(per_page)
    .bind((page - 1) * per_page)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    let (up, down, total) = sqlx::query_as::<_, (i64, i64, i64)>(
        "SELECT COUNT(*) FILTER (WHERE value=1),COUNT(*) FILTER (WHERE value=-1),COUNT(*) FROM ctfzone.ratings WHERE challenge_id=$1",
    )
    .bind(challenge_id)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(json!({
        "success": true,
        "data": ratings,
        "meta": {"pagination": {"page": page, "per_page": per_page, "total": total}, "summary": {"up": up, "down": down, "count": total}}
    }))
    .into_response())
}

pub(super) async fn rate_challenge(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
    Json(request): Json<RatingInput>,
) -> Result<Response, ApiError> {
    super::challenges::require_challenge_visibility(&state, Some(&user)).await?;
    super::challenges::require_ctf_time(&state, Some(&user)).await?;
    super::challenges::require_verified(&state, Some(&user)).await?;
    if !matches!(request.value, -1 | 1) || request.review.len() > 2000 {
        return Err(ApiError::bad_request("Invalid rating value or review"));
    }
    let rating_mode = config_string(&state, "challenge_ratings").await?;
    if rating_mode.as_deref() == Some("disabled") {
        return Err(ApiError::forbidden("Challenge ratings are disabled"));
    }
    if !user.is_admin() && !user_solved_challenge(&state, &user, challenge_id).await? {
        return Err(ApiError::forbidden(
            "You must solve this challenge before rating it",
        ));
    }
    let rating = sqlx::query_as::<_, RatingView>(
        r#"
        INSERT INTO ctfzone.ratings (user_id,challenge_id,value,review,date)
        VALUES ($1,$2,$3,$4,timezone('utc',now()))
        ON CONFLICT (user_id,challenge_id) DO UPDATE SET
            value=EXCLUDED.value,review=EXCLUDED.review,date=EXCLUDED.date
        RETURNING id,user_id,challenge_id,value,review,date,NULL::text AS name
        "#,
    )
    .bind(user.id)
    .bind(challenge_id)
    .bind(request.value)
    .bind(request.review)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(rating)).into_response())
}

pub(super) async fn challenge_solution(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(challenge_id): Path<i32>,
) -> Result<Response, ApiError> {
    let solution = sqlx::query_as::<_, (i32, String)>(
        "SELECT id,state FROM ctfzone.solutions WHERE challenge_id=$1",
    )
    .bind(challenge_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?;
    let (id, solution_state) = solution
        .map(|(id, state)| (Some(id), state))
        .unwrap_or((None, "hidden".to_owned()));
    let visible_id = match solution_state.as_str() {
        "visible" => id,
        "solved"
            if user.is_admin() || user_solved_challenge(&state, &user, challenge_id).await? =>
        {
            id
        }
        _ if user.is_admin() => id,
        _ => None,
    };
    Ok(Json(Success::new(
        json!({"id": visible_id, "state": solution_state}),
    ))
    .into_response())
}

pub(super) async fn list_hints(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    Ok(Json(Success::new(load_hints(&state, query.challenge_id).await?)).into_response())
}

pub(super) async fn get_hint(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Path(hint_id): Path<i32>,
) -> Result<Response, ApiError> {
    super::challenges::require_challenge_visibility(&state, user.as_ref()).await?;
    super::challenges::require_ctf_time(&state, user.as_ref()).await?;
    let mut hint = load_hint(&state, hint_id).await?;
    let unlocked = if user.as_ref().is_some_and(CurrentUser::is_admin) {
        true
    } else if let Some(user) = user.as_ref() {
        has_unlock(&state, user, "hints", hint_id).await?
    } else {
        hint.cost.unwrap_or(0) == 0
            && config_bool(&state, "hints_free_public_access", false).await?
    };
    if !unlocked {
        hint.content = None;
    }
    let mut data = serde_json::to_value(hint).expect("hint is serializable");
    data["content_format"] = json!("markdown");
    Ok(Json(Success::new(data)).into_response())
}

pub(super) async fn create_hint(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<HintInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    validate_hint(request.cost, request.requirements.as_ref())?;
    let hint = sqlx::query_as::<_, HintView>(
        r#"
        INSERT INTO ctfzone.hints (title,type,challenge_id,content,cost,requirements)
        VALUES ($1,$2,$3,$4,$5,$6)
        RETURNING id,title,type AS hint_type,challenge_id,content,cost,requirements
        "#,
    )
    .bind(request.title)
    .bind(request.hint_type.unwrap_or_else(|| "standard".to_owned()))
    .bind(request.challenge_id)
    .bind(request.content)
    .bind(request.cost)
    .bind(request.requirements)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok((StatusCode::CREATED, Json(Success::new(hint))).into_response())
}

pub(super) async fn update_hint(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(hint_id): Path<i32>,
    Json(request): Json<HintPatch>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if request.cost.is_some_and(|cost| cost < 0) {
        return Err(ApiError::bad_request("Hint cost cannot be negative"));
    }
    let hint = sqlx::query_as::<_, HintView>(
        r#"
        UPDATE ctfzone.hints SET title=COALESCE($1,title),type=COALESCE($2,type),
            challenge_id=COALESCE($3,challenge_id),content=COALESCE($4,content),
            cost=COALESCE($5,cost),requirements=COALESCE($6,requirements)
        WHERE id=$7
        RETURNING id,title,type AS hint_type,challenge_id,content,cost,requirements
        "#,
    )
    .bind(request.title)
    .bind(request.hint_type)
    .bind(request.challenge_id)
    .bind(request.content)
    .bind(request.cost)
    .bind(request.requirements)
    .bind(hint_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Hint not found"))?;
    Ok(Json(Success::new(hint)).into_response())
}

pub(super) async fn delete_hint(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(hint_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_by_id(&state, "hints", hint_id).await
}

pub(super) async fn list_solutions(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let rows = sqlx::query_as::<_, SolutionView>(
        "SELECT id,challenge_id,content,state FROM ctfzone.solutions ORDER BY id",
    )
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn get_solution(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(solution_id): Path<i32>,
) -> Result<Response, ApiError> {
    let solution = load_solution(&state, solution_id).await?;
    if !user.is_admin() {
        let challenge_id = solution
            .challenge_id
            .ok_or_else(|| ApiError::not_found("Solution not found"))?;
        if solution.state == "hidden"
            || (solution.state == "solved"
                && !user_solved_challenge(&state, &user, challenge_id).await?)
        {
            return Err(ApiError::not_found("Solution not found"));
        }
    }
    let mut data = serde_json::to_value(solution).expect("solution is serializable");
    data["content_format"] = json!("markdown");
    Ok(Json(Success::new(data)).into_response())
}

pub(super) async fn create_solution(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<SolutionInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let solution_state = request.state.unwrap_or_else(|| "hidden".to_owned());
    validate_solution_state(&solution_state)?;
    let solution = sqlx::query_as::<_, SolutionView>(
        r#"
        INSERT INTO ctfzone.solutions (challenge_id,content,state) VALUES ($1,$2,$3)
        RETURNING id,challenge_id,content,state
        "#,
    )
    .bind(request.challenge_id)
    .bind(request.content)
    .bind(solution_state)
    .fetch_one(&state.database)
    .await
    .map_err(map_content_database_error)?;
    Ok((StatusCode::CREATED, Json(Success::new(solution))).into_response())
}

pub(super) async fn update_solution(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(solution_id): Path<i32>,
    Json(request): Json<SolutionPatch>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if let Some(solution_state) = request.state.as_deref() {
        validate_solution_state(solution_state)?;
    }
    let solution = sqlx::query_as::<_, SolutionView>(
        r#"
        UPDATE ctfzone.solutions SET challenge_id=COALESCE($1,challenge_id),
            content=COALESCE($2,content),state=COALESCE($3,state)
        WHERE id=$4 RETURNING id,challenge_id,content,state
        "#,
    )
    .bind(request.challenge_id)
    .bind(request.content)
    .bind(request.state)
    .bind(solution_id)
    .fetch_optional(&state.database)
    .await
    .map_err(map_content_database_error)?
    .ok_or_else(|| ApiError::not_found("Solution not found"))?;
    Ok(Json(Success::new(solution)).into_response())
}

pub(super) async fn delete_solution(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(solution_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_by_id(&state, "solutions", solution_id).await
}

pub(super) async fn list_unlocks(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let rows = sqlx::query_as::<_, UnlockView>(
        "SELECT id,user_id,team_id,target,date,type AS unlock_type FROM ctfzone.unlocks ORDER BY id",
    )
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn unlock(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<UnlockInput>,
) -> Result<Response, ApiError> {
    super::challenges::require_ctf_time(&state, Some(&user)).await?;
    super::challenges::require_verified(&state, Some(&user)).await?;
    if !matches!(request.target_type.as_str(), "hints" | "solutions") {
        return Err(ApiError::bad_request("Unsupported unlock type"));
    }
    let team_mode = super::challenges::is_team_mode(&state).await?;
    let account_id = if team_mode {
        user.team_id
            .ok_or_else(|| ApiError::forbidden("Join a team before unlocking content"))?
    } else {
        user.id
    };
    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let existing = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(SELECT 1 FROM ctfzone.unlocks
            WHERE target=$1 AND type=$2
              AND (($3 AND team_id=$4) OR (NOT $3 AND user_id=$5)))
        "#,
    )
    .bind(request.target)
    .bind(&request.target_type)
    .bind(team_mode)
    .bind(user.team_id)
    .bind(user.id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    if existing {
        return Err(ApiError::conflict("This content is already unlocked"));
    }
    let cost = if request.target_type == "hints" {
        let hint = sqlx::query_as::<_, (i32, Option<String>, Option<i32>)>(
            "SELECT challenge_id,title,cost FROM ctfzone.hints WHERE id=$1",
        )
        .bind(request.target)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("Hint not found"))?;
        let score = account_score(&mut transaction, team_mode, account_id).await?;
        let cost = hint.2.unwrap_or(0);
        if score < i64::from(cost) {
            return Err(ApiError::bad_request(
                "You do not have enough points to unlock this hint",
            ));
        }
        if cost > 0 {
            sqlx::query(
                r#"
                INSERT INTO ctfzone.awards
                    (user_id,team_id,type,name,description,date,value,category)
                VALUES ($1,$2,'standard',$3,$4,timezone('utc',now()),$5,'hints')
                "#,
            )
            .bind(user.id)
            .bind(user.team_id)
            .bind(hint.1.unwrap_or_else(|| format!("Hint {}", request.target)))
            .bind(format!("Hint for challenge {}", hint.0))
            .bind(-cost)
            .execute(&mut *transaction)
            .await
            .map_err(ApiError::database)?;
        }
        cost
    } else {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM ctfzone.solutions WHERE id=$1)",
        )
        .bind(request.target)
        .fetch_one(&mut *transaction)
        .await
        .map_err(ApiError::database)?;
        if !exists {
            return Err(ApiError::not_found("Solution not found"));
        }
        0
    };
    let unlock = sqlx::query_as::<_, UnlockView>(
        r#"
        INSERT INTO ctfzone.unlocks (user_id,team_id,target,date,type)
        VALUES ($1,$2,$3,timezone('utc',now()),$4)
        RETURNING id,user_id,team_id,target,date,type AS unlock_type
        "#,
    )
    .bind(user.id)
    .bind(user.team_id)
    .bind(request.target)
    .bind(request.target_type)
    .fetch_one(&mut *transaction)
    .await
    .map_err(ApiError::database)?;
    transaction.commit().await.map_err(ApiError::database)?;
    let mut data = serde_json::to_value(unlock).expect("unlock is serializable");
    data["cost"] = json!(cost);
    Ok(Json(Success::new(data)).into_response())
}

pub(super) async fn list_notifications(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Query(query): Query<PageQuery>,
) -> Result<Response, ApiError> {
    let user_id = user.as_ref().map(|user| user.id);
    let team_id = user.as_ref().and_then(|user| user.team_id);
    let admin = user.as_ref().is_some_and(CurrentUser::is_admin);
    let rows = sqlx::query_as::<_, NotificationView>(
        r#"
        SELECT id,title,content,date,user_id,team_id FROM ctfzone.notifications
        WHERE id > COALESCE($1,0)
          AND ($4 OR (user_id IS NULL AND team_id IS NULL) OR user_id=$2 OR team_id=$3)
        ORDER BY id
        "#,
    )
    .bind(query.since_id)
    .bind(user_id)
    .bind(team_id)
    .bind(admin)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    Ok(Json(Success::new(rows)).into_response())
}

pub(super) async fn get_notification(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Path(notification_id): Path<i32>,
) -> Result<Response, ApiError> {
    let notification = load_notification(&state, notification_id).await?;
    if !notification_visible(&notification, user.as_ref()) {
        return Err(ApiError::not_found("Notification not found"));
    }
    Ok(Json(Success::new(notification)).into_response())
}

pub(super) async fn create_notification(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<NotificationInput>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if request.title.trim().is_empty() || request.title.len() > 500 {
        return Err(ApiError::bad_request("Notification title is invalid"));
    }
    let notification = sqlx::query_as::<_, NotificationView>(
        r#"
        INSERT INTO ctfzone.notifications (title,content,date,user_id,team_id)
        VALUES ($1,$2,timezone('utc',now()),$3,$4)
        RETURNING id,title,content,date,user_id,team_id
        "#,
    )
    .bind(request.title)
    .bind(request.content)
    .bind(request.user_id)
    .bind(request.team_id)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)?;
    let mut data = serde_json::to_value(notification).expect("notification is serializable");
    data["type"] = json!(
        request
            .notification_type
            .unwrap_or_else(|| "alert".to_owned())
    );
    data["sound"] = json!(request.sound.unwrap_or(true));
    Ok((StatusCode::CREATED, Json(Success::new(data))).into_response())
}

pub(super) async fn delete_notification(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(notification_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    delete_by_id(&state, "notifications", notification_id).await
}

async fn simple_relation(
    state: &AppState,
    table: &str,
    challenge_id: i32,
) -> Result<Response, ApiError> {
    let sql = format!(
        "SELECT id,challenge_id,value FROM ctfzone.{table} WHERE challenge_id=$1 ORDER BY id"
    );
    let data = sqlx::query_as::<_, (i32, Option<i32>, Option<String>)>(&sql)
        .bind(challenge_id)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?
        .into_iter()
        .map(|(id, challenge_id, value)| json!({"id": id, "challenge_id": challenge_id, "value": value}))
        .collect::<Vec<_>>();
    Ok(Json(Success::new(data)).into_response())
}

async fn load_hints(
    state: &AppState,
    challenge_id: Option<i32>,
) -> Result<Vec<HintView>, ApiError> {
    sqlx::query_as::<_, HintView>(
        r#"
        SELECT id,title,type AS hint_type,challenge_id,content,cost,requirements
        FROM ctfzone.hints WHERE ($1::integer IS NULL OR challenge_id=$1) ORDER BY id
        "#,
    )
    .bind(challenge_id)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)
}

async fn load_hint(state: &AppState, hint_id: i32) -> Result<HintView, ApiError> {
    sqlx::query_as::<_, HintView>(
        "SELECT id,title,type AS hint_type,challenge_id,content,cost,requirements FROM ctfzone.hints WHERE id=$1",
    )
    .bind(hint_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Hint not found"))
}

async fn load_solution(state: &AppState, solution_id: i32) -> Result<SolutionView, ApiError> {
    sqlx::query_as::<_, SolutionView>(
        "SELECT id,challenge_id,content,state FROM ctfzone.solutions WHERE id=$1",
    )
    .bind(solution_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Solution not found"))
}

async fn load_notification(
    state: &AppState,
    notification_id: i32,
) -> Result<NotificationView, ApiError> {
    sqlx::query_as::<_, NotificationView>(
        "SELECT id,title,content,date,user_id,team_id FROM ctfzone.notifications WHERE id=$1",
    )
    .bind(notification_id)
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .ok_or_else(|| ApiError::not_found("Notification not found"))
}

async fn user_solved_challenge(
    state: &AppState,
    user: &CurrentUser,
    challenge_id: i32,
) -> Result<bool, ApiError> {
    let team_mode = super::challenges::is_team_mode(state).await?;
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM ctfzone.submissions s JOIN ctfzone.solves solved ON solved.id=s.id
            WHERE s.challenge_id=$1
              AND (($2 AND s.team_id=$3) OR (NOT $2 AND s.user_id=$4))
        )
        "#,
    )
    .bind(challenge_id)
    .bind(team_mode)
    .bind(user.team_id)
    .bind(user.id)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)
}

async fn has_unlock(
    state: &AppState,
    user: &CurrentUser,
    unlock_type: &str,
    target: i32,
) -> Result<bool, ApiError> {
    let team_mode = super::challenges::is_team_mode(state).await?;
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(SELECT 1 FROM ctfzone.unlocks
            WHERE type=$1 AND target=$2
              AND (($3 AND team_id=$4) OR (NOT $3 AND user_id=$5)))
        "#,
    )
    .bind(unlock_type)
    .bind(target)
    .bind(team_mode)
    .bind(user.team_id)
    .bind(user.id)
    .fetch_one(&state.database)
    .await
    .map_err(ApiError::database)
}

async fn account_score(
    transaction: &mut Transaction<'_, Postgres>,
    team_mode: bool,
    account_id: i32,
) -> Result<i64, ApiError> {
    let account = if team_mode { "team_id" } else { "user_id" };
    let sql = format!(
        r#"
        SELECT COALESCE((
            SELECT SUM(c.value)::bigint FROM ctfzone.submissions s
            JOIN ctfzone.solves solved ON solved.id=s.id
            JOIN ctfzone.challenges c ON c.id=s.challenge_id WHERE s.{account}=$1
        ),0) + COALESCE((SELECT SUM(value)::bigint FROM ctfzone.awards WHERE {account}=$1),0)
        "#,
    );
    sqlx::query_scalar::<_, i64>(&sql)
        .bind(account_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(ApiError::database)
}

async fn config_string(state: &AppState, key: &str) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar::<_, Option<String>>("SELECT value FROM ctfzone.config WHERE key=$1")
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

fn notification_visible(notification: &NotificationView, user: Option<&CurrentUser>) -> bool {
    notification.user_id.is_none() && notification.team_id.is_none()
        || user.is_some_and(|user| {
            user.is_admin()
                || notification.user_id == Some(user.id)
                || notification.team_id.is_some() && notification.team_id == user.team_id
        })
}

fn validate_hint(cost: i32, requirements: Option<&Value>) -> Result<(), ApiError> {
    if cost < 0 || requirements.is_some_and(|requirements| !requirements.is_object()) {
        return Err(ApiError::bad_request("Invalid hint cost or requirements"));
    }
    Ok(())
}

fn validate_solution_state(state: &str) -> Result<(), ApiError> {
    if matches!(state, "hidden" | "visible" | "solved") {
        Ok(())
    } else {
        Err(ApiError::bad_request("Invalid solution state"))
    }
}

async fn delete_by_id(state: &AppState, table: &str, id: i32) -> Result<Response, ApiError> {
    let allowed = ["hints", "solutions", "notifications"];
    if !allowed.contains(&table) {
        return Err(ApiError::bad_request("Unsupported content type"));
    }
    let result = sqlx::query(&format!("DELETE FROM ctfzone.{table} WHERE id=$1"))
        .bind(id)
        .execute(&state.database)
        .await
        .map_err(ApiError::database)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Content not found"));
    }
    Ok(Json(json!({"success": true})).into_response())
}

fn map_content_database_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(database_error) = &error {
        if database_error.is_unique_violation() {
            return ApiError::conflict("A record already exists for this challenge");
        }
    }
    ApiError::database(error)
}

fn require_admin(user: &CurrentUser) -> Result<(), ApiError> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(ApiError::forbidden("Administrator access is required"))
    }
}
