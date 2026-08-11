use std::{fs::File, io::Cursor, path::Path, time::Duration};

use axum::{
    Json,
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::Response,
};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::Row;
use zip::{ZipWriter, write::SimpleFileOptions};

use crate::{AppState, auth::CurrentUser, error::ApiError};

#[derive(Deserialize)]
pub(super) struct ExportRequest {
    #[serde(rename = "type", default = "default_export_type")]
    export_type: String,
    #[serde(default)]
    args: ExportArguments,
}

#[derive(Deserialize, Default)]
struct ExportArguments {
    table: Option<String>,
}

struct ExportTable {
    name: String,
    columns: Vec<String>,
    rows: Vec<Value>,
}

pub(super) async fn raw(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(request): Json<ExportRequest>,
) -> Result<Response, ApiError> {
    require_admin(&user)?;
    if !state
        .rate_limiter
        .allow("export", &user.id.to_string(), 10, Duration::from_secs(60))
        .await
    {
        return Err(ApiError::too_many_requests(
            "Too many exports; try again shortly",
        ));
    }
    let product_name = sqlx::query_scalar::<_, String>(
        "SELECT value FROM ctfzone.config WHERE key='ctf_name' ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(&state.database)
    .await
    .map_err(ApiError::database)?
    .unwrap_or_else(|| "CTFZone".to_owned());
    let timestamp = Utc::now().format("%Y-%m-%d_%H-%M-%S");
    if request.export_type == "csv" {
        let table = request
            .args
            .table
            .as_deref()
            .ok_or_else(|| ApiError::bad_request("Missing table to export"))?;
        let table = load_table(&state, table).await?;
        let bytes = csv_bytes(&table)?;
        return download_response(
            bytes,
            "text/csv; charset=utf-8",
            &format!(
                "{}-{}-{timestamp}.csv",
                safe_download_name(&product_name),
                table.name
            ),
        );
    }
    if !matches!(request.export_type.as_str(), "_" | "zip" | "backup") {
        return Err(ApiError::bad_request("Unsupported export type"));
    }

    let table_names = sqlx::query_scalar::<_, String>(
        r#"
        SELECT table_name FROM information_schema.tables
        WHERE table_schema='ctfzone' AND table_type='BASE TABLE'
        ORDER BY table_name
        "#,
    )
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    let mut tables = Vec::with_capacity(table_names.len());
    for table_name in table_names {
        tables.push(load_table(&state, &table_name).await?);
    }
    let upload_folder = state.upload_folder.clone();
    let bytes = tokio::task::spawn_blocking(move || build_archive(tables, &upload_folder))
        .await
        .map_err(|_| ApiError::upstream("Backup worker failed"))??;
    download_response(
        bytes,
        "application/zip",
        &format!("{}.{timestamp}.zip", safe_download_name(&product_name)),
    )
}

async fn load_table(state: &AppState, requested: &str) -> Result<ExportTable, ApiError> {
    if requested.is_empty()
        || !requested
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(ApiError::not_found("Export table not found"));
    }
    let columns = sqlx::query_scalar::<_, String>(
        r#"
        SELECT column_name FROM information_schema.columns
        WHERE table_schema='ctfzone' AND table_name=$1 ORDER BY ordinal_position
        "#,
    )
    .bind(requested)
    .fetch_all(&state.database)
    .await
    .map_err(ApiError::database)?;
    if columns.is_empty() {
        return Err(ApiError::not_found("Export table not found"));
    }
    let query =
        format!("SELECT to_jsonb(export_row) AS value FROM ctfzone.\"{requested}\" export_row");
    let rows = sqlx::query(&query)
        .fetch_all(&state.database)
        .await
        .map_err(ApiError::database)?
        .into_iter()
        .map(|row| row.get::<Value, _>("value"))
        .collect();
    Ok(ExportTable {
        name: requested.to_owned(),
        columns,
        rows,
    })
}

fn csv_bytes(table: &ExportTable) -> Result<Vec<u8>, ApiError> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record(&table.columns)
        .map_err(|_| ApiError::upstream("Unable to create CSV export"))?;
    for row in &table.rows {
        let object = row
            .as_object()
            .ok_or_else(|| ApiError::upstream("Database row cannot be exported"))?;
        let values = table
            .columns
            .iter()
            .map(|column| csv_value(object.get(column)))
            .collect::<Vec<_>>();
        writer
            .write_record(values)
            .map_err(|_| ApiError::upstream("Unable to create CSV export"))?;
    }
    writer
        .into_inner()
        .map_err(|_| ApiError::upstream("Unable to finalize CSV export"))
}

fn csv_value(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(value)) => value.clone(),
        Some(value) => value.to_string(),
    }
}

fn build_archive(tables: Vec<ExportTable>, upload_root: &Path) -> Result<Vec<u8>, ApiError> {
    let mut output = Cursor::new(Vec::new());
    {
        let mut archive = ZipWriter::new(&mut output);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated)
            .unix_permissions(0o600);
        for table in tables {
            archive
                .start_file(format!("db/{}.json", table.name), options)
                .map_err(|_| ApiError::upstream("Unable to create backup archive"))?;
            let document = json!({"count": table.rows.len(), "results": table.rows, "meta": {}});
            serde_json::to_writer(&mut archive, &document)
                .map_err(|_| ApiError::upstream("Unable to serialize backup data"))?;
        }
        if upload_root.is_dir() {
            add_upload_directory(&mut archive, upload_root, upload_root, options)?;
        }
        archive
            .finish()
            .map_err(|_| ApiError::upstream("Unable to finalize backup archive"))?;
    }
    Ok(output.into_inner())
}

fn add_upload_directory(
    archive: &mut ZipWriter<&mut Cursor<Vec<u8>>>,
    root: &Path,
    directory: &Path,
    options: SimpleFileOptions,
) -> Result<(), ApiError> {
    for entry in std::fs::read_dir(directory)
        .map_err(|_| ApiError::upstream("Unable to read upload storage"))?
    {
        let entry = entry.map_err(|_| ApiError::upstream("Unable to read upload storage"))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ApiError::upstream("Upload path is invalid"))?;
        if relative
            .components()
            .next()
            .is_some_and(|value| value.as_os_str() == ".incoming")
        {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|_| ApiError::upstream("Unable to inspect upload storage"))?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            add_upload_directory(archive, root, &path, options)?;
        } else if metadata.is_file() {
            let relative = zip_path(relative)?;
            archive
                .start_file(format!("uploads/{relative}"), options)
                .map_err(|_| ApiError::upstream("Unable to add an upload to the backup"))?;
            let mut source = File::open(&path)
                .map_err(|_| ApiError::upstream("Unable to read an uploaded file"))?;
            std::io::copy(&mut source, archive)
                .map_err(|_| ApiError::upstream("Unable to add an upload to the backup"))?;
        }
    }
    Ok(())
}

fn zip_path(path: &Path) -> Result<String, ApiError> {
    path.components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| ApiError::upstream("Upload filename is not valid UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|parts| parts.join("/"))
}

fn download_response(
    bytes: Vec<u8>,
    content_type: &str,
    filename: &str,
) -> Result<Response, ApiError> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, bytes.len())
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{}\"", safe_download_name(filename)),
        )
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(Body::from(bytes))
        .map_err(|_| ApiError::upstream("Unable to build export response"))
}

fn safe_download_name(value: &str) -> String {
    let value = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if value.is_empty() {
        "CTFZone".to_owned()
    } else {
        value
    }
}

fn default_export_type() -> String {
    "_".to_owned()
}

fn require_admin(user: &CurrentUser) -> Result<(), ApiError> {
    if user.is_admin() {
        Ok(())
    } else {
        Err(ApiError::forbidden("Administrator access is required"))
    }
}
