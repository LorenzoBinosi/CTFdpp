use std::time::Duration;

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};

use crate::config::ObjectStorageConfig;

const INTERNAL_REQUEST_TTL: Duration = Duration::from_secs(30);

/// S3 request signer. It is deliberately Sans-I/O: object bytes travel
/// directly between the browser (or a maintenance worker) and storage.
#[derive(Clone)]
pub(crate) struct ObjectStorage {
    bucket_name: String,
    credentials: Credentials,
    internal_bucket: Bucket,
    max_upload_bytes: i64,
    max_pending_bytes_per_principal: i64,
    max_pending_objects_per_principal: i64,
    max_retained_bytes_per_principal: i64,
    max_uploads_per_hour_per_principal: i64,
    presign_ttl: Duration,
    public_bucket: Bucket,
}

impl ObjectStorage {
    pub(crate) fn new(config: ObjectStorageConfig) -> Result<Self> {
        let internal_bucket = Bucket::new(
            config.internal_url,
            UrlStyle::Path,
            config.bucket.clone(),
            config.region.clone(),
        )
        .context("OBJECT_STORAGE_INTERNAL_URL cannot be used as an S3 endpoint")?;
        let public_bucket = Bucket::new(
            config.public_url,
            UrlStyle::Path,
            config.bucket.clone(),
            config.region,
        )
        .context("OBJECT_STORAGE_PUBLIC_URL cannot be used as an S3 endpoint")?;

        Ok(Self {
            bucket_name: config.bucket,
            credentials: Credentials::new(config.access_key, config.secret_key),
            internal_bucket,
            max_upload_bytes: config.max_upload_bytes,
            max_pending_bytes_per_principal: config.max_pending_bytes_per_principal,
            max_pending_objects_per_principal: config.max_pending_objects_per_principal,
            max_retained_bytes_per_principal: config.max_retained_bytes_per_principal,
            max_uploads_per_hour_per_principal: config.max_uploads_per_hour_per_principal,
            presign_ttl: Duration::from_secs(config.presign_ttl_seconds),
            public_bucket,
        })
    }

    pub(crate) fn bucket_name(&self) -> &str {
        &self.bucket_name
    }

    pub(crate) const fn max_upload_bytes(&self) -> i64 {
        self.max_upload_bytes
    }

    pub(crate) const fn max_pending_bytes_per_principal(&self) -> i64 {
        self.max_pending_bytes_per_principal
    }

    pub(crate) const fn max_pending_objects_per_principal(&self) -> i64 {
        self.max_pending_objects_per_principal
    }

    pub(crate) const fn max_retained_bytes_per_principal(&self) -> i64 {
        self.max_retained_bytes_per_principal
    }

    pub(crate) const fn max_uploads_per_hour_per_principal(&self) -> i64 {
        self.max_uploads_per_hour_per_principal
    }

    pub(crate) const fn presign_ttl(&self) -> Duration {
        self.presign_ttl
    }

    pub(crate) fn put_url(
        &self,
        upload_key: &str,
        content_type: &str,
        content_length: i64,
        checksum_hex: &str,
        ttl: Duration,
    ) -> Result<(String, String)> {
        let checksum = STANDARD.encode(
            hex::decode(checksum_hex).context("upload checksum must be hexadecimal SHA-256")?,
        );
        let mut action = self
            .public_bucket
            .put_object(Some(&self.credentials), upload_key);
        action
            .headers_mut()
            .insert("content-type", content_type.to_owned());
        action
            .headers_mut()
            .insert("content-length", content_length.to_string());
        action
            .headers_mut()
            .insert("x-amz-checksum-sha256", checksum.clone());
        Ok((action.sign(ttl).into(), checksum))
    }

    pub(crate) fn get_url(&self, object_key: &str, filename: &str, content_type: &str) -> String {
        let mut action = self
            .public_bucket
            .get_object(Some(&self.credentials), object_key);
        action.query_mut().insert(
            "response-content-disposition",
            format!(
                "attachment; filename=\"{}\"",
                safe_header_filename(filename)
            ),
        );
        action
            .query_mut()
            .insert("response-content-type", content_type.to_owned());
        action
            .query_mut()
            .insert("response-cache-control", "private, no-store");
        action.sign(self.presign_ttl).into()
    }

    pub(crate) fn inline_image_url(&self, object_key: &str, content_type: &str) -> String {
        debug_assert!(matches!(content_type, "image/png" | "image/svg+xml"));
        let mut action = self
            .public_bucket
            .get_object(Some(&self.credentials), object_key);
        action
            .query_mut()
            .insert("response-content-disposition", "inline".to_owned());
        action
            .query_mut()
            .insert("response-content-type", content_type.to_owned());
        action.query_mut().insert(
            "response-cache-control",
            "public, max-age=31536000, immutable".to_owned(),
        );
        action.sign(self.presign_ttl).into()
    }

    pub(crate) fn internal_head_url(&self, object_key: &str) -> String {
        self.internal_bucket
            .head_object(Some(&self.credentials), object_key)
            .sign(INTERNAL_REQUEST_TTL)
            .into()
    }

    pub(crate) fn internal_get_url(&self, object_key: &str) -> String {
        self.internal_bucket
            .get_object(Some(&self.credentials), object_key)
            .sign(INTERNAL_REQUEST_TTL)
            .into()
    }

    pub(crate) fn internal_copy_request(
        &self,
        upload_key: &str,
        object_key: &str,
    ) -> (String, String) {
        let copy_source = format!("/{}/{upload_key}", self.bucket_name);
        let mut action = self
            .internal_bucket
            .put_object(Some(&self.credentials), object_key);
        action
            .headers_mut()
            .insert("x-amz-copy-source", copy_source.clone());
        (action.sign(INTERNAL_REQUEST_TTL).into(), copy_source)
    }

    pub(crate) fn internal_bucket_head_url(&self) -> String {
        self.internal_bucket
            .head_bucket(Some(&self.credentials))
            .sign(INTERNAL_REQUEST_TTL)
            .into()
    }
}

fn safe_header_filename(filename: &str) -> String {
    filename
        .chars()
        .take_while(|character| !character.is_control())
        .map(|character| {
            if character.is_ascii_graphic() && !matches!(character, '"' | '\\' | ';') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Url;

    fn storage() -> ObjectStorage {
        ObjectStorage::new(ObjectStorageConfig {
            access_key: "access".to_owned(),
            bucket: "ctfzone".to_owned(),
            internal_url: Url::parse("http://storage:8333").unwrap(),
            max_upload_bytes: 512 * 1024 * 1024,
            max_pending_bytes_per_principal: 1024 * 1024 * 1024,
            max_pending_objects_per_principal: 8,
            max_retained_bytes_per_principal: 10 * 1024 * 1024 * 1024,
            max_uploads_per_hour_per_principal: 60,
            presign_ttl_seconds: 900,
            public_url: Url::parse("https://files.example.test").unwrap(),
            region: "us-east-1".to_owned(),
            secret_key: "secret".to_owned(),
        })
        .unwrap()
    }

    #[test]
    fn public_put_is_scoped_and_does_not_disclose_the_secret() {
        let checksum = "a".repeat(64);
        let (url, checksum_header) = storage()
            .put_url(
                "uploads/abc",
                "text/plain",
                5,
                &checksum,
                Duration::from_secs(900),
            )
            .unwrap();
        assert!(url.starts_with("https://files.example.test/ctfzone/uploads/abc?"));
        assert!(url.contains("X-Amz-Expires=900"));
        assert!(url.contains(
            "X-Amz-SignedHeaders=content-length%3Bcontent-type%3Bhost%3Bx-amz-checksum-sha256"
        ));
        assert_eq!(
            checksum_header,
            "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo="
        );
        assert!(!url.contains("secret"));
    }

    #[test]
    fn server_side_copy_is_bound_to_source_and_destination() {
        let (url, source) =
            storage().internal_copy_request("uploads/abc", "challenge/abc/file.txt");
        assert_eq!(source, "/ctfzone/uploads/abc");
        assert!(url.starts_with("http://storage:8333/ctfzone/challenge/abc/file.txt?"));
        assert!(url.contains("X-Amz-SignedHeaders=host%3Bx-amz-copy-source"));
    }

    #[test]
    fn download_filename_cannot_inject_a_response_header() {
        let url = storage().get_url("result/abc", "x\"; inline\r\nX-Evil: 1", "text/plain");
        assert!(!url.contains("X-Evil"));
        assert!(url.contains("response-content-disposition="));
    }

    #[test]
    fn category_icon_grant_is_inline_and_immutable() {
        let url = storage().inline_image_url("objects/category_icon/icon.svg", "image/svg+xml");
        assert!(url.contains("response-content-disposition=inline"));
        assert!(url.contains("response-content-type=image%2Fsvg%2Bxml"));
        assert!(url.contains("immutable"));
        assert!(!url.contains("attachment"));
    }
}
