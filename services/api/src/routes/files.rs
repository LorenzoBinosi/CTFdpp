use std::path::{Component, Path as FilePath, PathBuf};

use axum::{
    Json,
    body::Body,
    extract::{Multipart, Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::json;
use sha1::{Digest, Sha1};
use sqlx::FromRow;
use tokio::{fs, io::AsyncWriteExt};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::{
    AppState,
    auth::{CurrentUser, OptionalCurrentUser},
    error::ApiError,
    routes::Success,
};

const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
pub(super) const MAX_UPLOAD_BODY_BYTES: usize = 513 * 1024 * 1024;

#[derive(Clone, FromRow, Serialize)]
struct FileView {
    id: i32,
    #[serde(rename = "type")]
    file_type: Option<String>,
    location: Option<String>,
    sha1sum: Option<String>,
    challenge_id: Option<i32>,
    page_id: Option<i32>,
    solution_id: Option<i32>,
}

struct PendingFile {
    temporary_path: PathBuf,
    filename: String,
    sha1sum: String,
}

pub(super) async fn list(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let files = sqlx::query_as::<_, FileView>(&file_select("ORDER BY id"))
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?;
    Ok(Json(Success::new(files)).into_response())
}

pub(super) async fn detail(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(file_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    Ok(Json(Success::new(load_file_by_id(&state, file_id).await?)).into_response())
}

pub(super) async fn upload(
    State(state): State<AppState>,
    user: CurrentUser,
    mut multipart: Multipart,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    fs::create_dir_all(&state.upload_folder)
        .await
        .map_err(|_| ApiError::upstream("Upload storage is unavailable"))?;
    let temporary_directory = state.upload_folder.join(".incoming");
    fs::create_dir_all(&temporary_directory)
        .await
        .map_err(|_| ApiError::upstream("Upload storage is unavailable"))?;

    let mut challenge_id = None;
    let mut page_id = None;
    let mut solution_id = None;
    let mut explicit_location = None;
    let mut pending = Vec::new();
    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::bad_request("Invalid multipart upload"))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        if name == "file" {
            let filename = safe_filename(field.file_name().unwrap_or("upload.bin"))?;
            let temporary_path = temporary_directory.join(Uuid::new_v4().to_string());
            let mut output = fs::File::create(&temporary_path)
                .await
                .map_err(|_| ApiError::upstream("Upload storage is unavailable"))?;
            let mut hasher = Sha1::new();
            let mut size = 0_u64;
            while let Some(chunk) = field
                .next()
                .await
                .transpose()
                .map_err(|_| ApiError::bad_request("Uploaded file is incomplete"))?
            {
                size = size.saturating_add(chunk.len() as u64);
                if size > MAX_FILE_BYTES {
                    fs::remove_file(&temporary_path).await.ok();
                    return Err(ApiError::bad_request(
                        "Uploaded files must be 512 MB or smaller",
                    ));
                }
                hasher.update(&chunk);
                output
                    .write_all(&chunk)
                    .await
                    .map_err(|_| ApiError::upstream("Upload storage write failed"))?;
            }
            output
                .sync_all()
                .await
                .map_err(|_| ApiError::upstream("Upload storage write failed"))?;
            pending.push(PendingFile {
                temporary_path,
                filename,
                sha1sum: hex::encode(hasher.finalize()),
            });
        } else {
            let value = field
                .text()
                .await
                .map_err(|_| ApiError::bad_request("Invalid multipart field"))?;
            match name.as_str() {
                "challenge" | "challenge_id" => challenge_id = parse_optional_id(&value)?,
                "page" | "page_id" => page_id = parse_optional_id(&value)?,
                "solution" | "solution_id" => solution_id = parse_optional_id(&value)?,
                "location" if !value.trim().is_empty() => {
                    explicit_location = Some(safe_location(value.trim())?)
                }
                "type" => {}
                _ => {}
            }
        }
    }
    if pending.is_empty() {
        return Err(ApiError::bad_request("At least one file is required"));
    }
    if pending.len() > 1 && explicit_location.is_some() {
        cleanup_pending(&pending).await;
        return Err(ApiError::bad_request(
            "Location cannot be specified for multiple files",
        ));
    }
    let target_count = [challenge_id, page_id, solution_id]
        .into_iter()
        .flatten()
        .count();
    if target_count != 1 {
        cleanup_pending(&pending).await;
        return Err(ApiError::bad_request(
            "Exactly one challenge, page, or solution target is required",
        ));
    }
    let file_type = if challenge_id.is_some() {
        "challenge"
    } else if page_id.is_some() {
        "page"
    } else {
        "solution"
    };

    let mut transaction = state.database.begin().await.map_err(ApiError::database)?;
    let mut created = Vec::new();
    let mut final_paths = Vec::new();
    for pending_file in &pending {
        let location = explicit_location
            .clone()
            .unwrap_or_else(|| format!("{}/{}", Uuid::new_v4(), pending_file.filename));
        let final_path = checked_storage_path(&state.upload_folder, &location)?;
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|_| ApiError::upstream("Upload storage is unavailable"))?;
        }
        if let Err(error) = fs::hard_link(&pending_file.temporary_path, &final_path).await {
            transaction.rollback().await.ok();
            cleanup_pending(&pending).await;
            cleanup_paths(&final_paths).await;
            return if error.kind() == std::io::ErrorKind::AlreadyExists {
                Err(ApiError::bad_request("File location already exists"))
            } else {
                Err(ApiError::upstream("Unable to finalize uploaded file"))
            };
        }
        fs::remove_file(&pending_file.temporary_path).await.ok();
        final_paths.push(final_path);
        let file = sqlx::query_as::<_, FileView>(
            r#"
            INSERT INTO ctfzone.files
                (type,location,sha1sum,challenge_id,page_id,solution_id)
            VALUES ($1,$2,$3,$4,$5,$6)
            RETURNING id,type AS file_type,location,sha1sum,challenge_id,page_id,solution_id
            "#,
        )
        .bind(file_type)
        .bind(location)
        .bind(&pending_file.sha1sum)
        .bind(challenge_id)
        .bind(page_id)
        .bind(solution_id)
        .fetch_one(&mut *transaction)
        .await;
        let file = match file {
            Ok(file) => file,
            Err(error) => {
                transaction.rollback().await.ok();
                cleanup_pending(&pending).await;
                cleanup_paths(&final_paths).await;
                return Err(ApiError::database(error));
            }
        };
        created.push(file);
    }
    if let Err(error) = transaction.commit().await {
        cleanup_paths(&final_paths).await;
        return Err(ApiError::database(error));
    }
    Ok((StatusCode::CREATED, Json(Success::new(created))).into_response())
}

pub(super) async fn delete(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(file_id): Path<i32>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    let file = load_file_by_id(&state, file_id).await?;
    let result = sqlx::query("DELETE FROM ctfzone.files WHERE id=$1")
        .bind(file_id)
        .execute(&state.database)
        .await
        .map_err(ApiError::database)?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("File not found"));
    }
    if let Some(location) = file.location {
        let path = checked_storage_path(&state.upload_folder, &location)?;
        fs::remove_file(path).await.ok();
    }
    Ok(Json(json!({"success": true})).into_response())
}

pub(super) async fn download(
    State(state): State<AppState>,
    OptionalCurrentUser(user): OptionalCurrentUser,
    Path(path): Path<String>,
) -> Result<Response, ApiError> {
    let location = safe_location(&path)?;
    let file = sqlx::query_as::<_, FileView>(&file_select("WHERE location=$1"))
        .bind(&location)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("File not found"))?;
    authorize_download(&state, user.as_ref(), &file).await?;
    let storage_path = checked_storage_path(&state.upload_folder, &location)?;
    let source = fs::File::open(&storage_path)
        .await
        .map_err(|_| ApiError::not_found("File not found"))?;
    let size = source
        .metadata()
        .await
        .map_err(|_| ApiError::not_found("File not found"))?
        .len();
    let filename = FilePath::new(&location)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("download.bin")
        .replace(['"', '\r', '\n'], "_");
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, size)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(Body::from_stream(ReaderStream::new(source)))
        .map_err(|_| ApiError::upstream("Unable to build file response"))
}

async fn authorize_download(
    state: &AppState,
    user: Option<&CurrentUser>,
    file: &FileView,
) -> Result<(), ApiError> {
    if user.is_some_and(CurrentUser::is_admin) {
        return Ok(());
    }
    if let Some(challenge_id) = file.challenge_id {
        let challenge_state =
            sqlx::query_scalar::<_, String>("SELECT state FROM ctfzone.challenges WHERE id=$1")
                .bind(challenge_id)
                .fetch_optional(&state.database)
                .await
                .map_err(ApiError::database)?
                .ok_or_else(|| ApiError::not_found("File not found"))?;
        if challenge_state != "visible" {
            return Err(ApiError::not_found("File not found"));
        }
        super::challenges::require_challenge_visibility(state, user).await?;
        super::challenges::require_ctf_time(state, user).await?;
        return Ok(());
    }
    if let Some(page_id) = file.page_id {
        let (draft, hidden, auth_required) = sqlx::query_as::<_, (bool, bool, bool)>(
            "SELECT COALESCE(draft,false),COALESCE(hidden,false),COALESCE(auth_required,false) FROM ctfzone.pages WHERE id=$1",
        )
        .bind(page_id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("File not found"))?;
        if draft || hidden || (auth_required && user.is_none()) {
            return Err(ApiError::not_found("File not found"));
        }
        return Ok(());
    }
    if let Some(solution_id) = file.solution_id {
        let (challenge_id, solution_state) = sqlx::query_as::<_, (i32, String)>(
            "SELECT challenge_id,state FROM ctfzone.solutions WHERE id=$1",
        )
        .bind(solution_id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("File not found"))?;
        let Some(user) = user else {
            return Err(ApiError::forbidden("Authentication required"));
        };
        if solution_state == "visible" {
            return Ok(());
        }
        let team_mode = super::challenges::is_team_mode(state).await?;
        let solved = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS(SELECT 1 FROM ctfzone.submissions s
                JOIN ctfzone.solves solved ON solved.id=s.id
                WHERE s.challenge_id=$1
                  AND (($2 AND s.team_id=$3) OR (NOT $2 AND s.user_id=$4)))
            "#,
        )
        .bind(challenge_id)
        .bind(team_mode)
        .bind(user.team_id)
        .bind(user.id)
        .fetch_one(&state.database)
        .await
        .map_err(ApiError::database)?;
        if solution_state == "solved" && solved {
            return Ok(());
        }
    }
    Err(ApiError::not_found("File not found"))
}

async fn load_file_by_id(state: &AppState, id: i32) -> Result<FileView, ApiError> {
    sqlx::query_as::<_, FileView>(&file_select("WHERE id=$1"))
        .bind(id)
        .fetch_optional(&state.database)
        .await
        .map_err(ApiError::database)?
        .ok_or_else(|| ApiError::not_found("File not found"))
}

fn file_select(suffix: &str) -> String {
    format!(
        "SELECT id,type AS file_type,location,sha1sum,challenge_id,page_id,solution_id FROM ctfzone.files {suffix}"
    )
}

fn safe_filename(value: &str) -> Result<String, ApiError> {
    let filename = FilePath::new(value)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("upload.bin")
        .trim();
    if filename.is_empty() || filename.len() > 255 || filename.chars().any(char::is_control) {
        return Err(ApiError::bad_request("Filename is invalid"));
    }
    Ok(filename.replace(['/', '\\'], "_"))
}

fn safe_location(value: &str) -> Result<String, ApiError> {
    let path = FilePath::new(value.trim_start_matches('/'));
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component
                    .as_os_str()
                    .to_str()
                    .is_none_or(|value| value.is_empty() || value.chars().any(char::is_control))
        })
    {
        return Err(ApiError::bad_request("File location is invalid"));
    }
    Ok(path.to_string_lossy().into_owned())
}

fn checked_storage_path(root: &FilePath, location: &str) -> Result<PathBuf, ApiError> {
    let location = safe_location(location)?;
    Ok(root.join(location))
}

fn parse_optional_id(value: &str) -> Result<Option<i32>, ApiError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    let id = value
        .parse::<i32>()
        .map_err(|_| ApiError::bad_request("File target ID is invalid"))?;
    if id <= 0 {
        return Err(ApiError::bad_request("File target ID is invalid"));
    }
    Ok(Some(id))
}

async fn cleanup_pending(files: &[PendingFile]) {
    for file in files {
        fs::remove_file(&file.temporary_path).await.ok();
    }
}

async fn cleanup_paths(paths: &[PathBuf]) {
    for path in paths {
        fs::remove_file(path).await.ok();
    }
}

fn require_admin(user: &CurrentUser) -> Result<(), ApiError> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(ApiError::forbidden("Administrator access is required"))
    }
}
