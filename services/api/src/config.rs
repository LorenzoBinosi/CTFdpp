use std::{env, net::SocketAddr};

use anyhow::{Context, Result};
use reqwest::Url;

#[derive(Clone)]
pub struct Config {
    pub api_signing_key: String,
    pub backend_service_token: String,
    pub bind_address: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub object_storage: ObjectStorageConfig,
    pub setup_token: String,
    pub site_url: Url,
    pub email_verification_ttl_seconds: i64,
    pub session_lifetime_seconds: i64,
}

#[derive(Clone)]
pub struct ObjectStorageConfig {
    pub access_key: String,
    pub bucket: String,
    pub internal_url: Url,
    pub max_upload_bytes: i64,
    pub max_pending_bytes_per_principal: i64,
    pub max_pending_objects_per_principal: i64,
    pub max_retained_bytes_per_principal: i64,
    pub max_uploads_per_hour_per_principal: i64,
    pub presign_ttl_seconds: u64,
    pub public_url: Url,
    pub region: String,
    pub secret_key: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let backend_service_token = required_secret("BACKEND_SERVICE_TOKEN")?;
        let api_signing_key = required_secret("API_SIGNING_KEY")?;

        let bind_address = env::var("CTFZONE_API_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
            .parse()
            .context("CTFZONE_API_BIND must be a valid socket address")?;

        let database_url =
            env::var("DATABASE_URL").context("DATABASE_URL is required for the CTFZone API")?;

        let database_max_connections = env::var("DATABASE_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "10".to_owned())
            .parse()
            .context("DATABASE_MAX_CONNECTIONS must be a positive integer")?;

        let setup_token = required_secret("SETUP_TOKEN")?;

        let site_url = endpoint("CADDY_SITE_ADDRESS")?;
        let email_verification_ttl_seconds = env::var("EMAIL_VERIFICATION_TTL_SECONDS")
            .unwrap_or_else(|_| "1800".to_owned())
            .parse::<i64>()
            .context("EMAIL_VERIFICATION_TTL_SECONDS must be an integer")?;
        if !(300..=86_400).contains(&email_verification_ttl_seconds) {
            anyhow::bail!("EMAIL_VERIFICATION_TTL_SECONDS must be between 300 and 86400 seconds");
        }

        let session_lifetime_seconds = env::var("SESSION_LIFETIME_SECONDS")
            .unwrap_or_else(|_| "604800".to_owned())
            .parse::<i64>()
            .context("SESSION_LIFETIME_SECONDS must be a positive integer")?;
        if session_lifetime_seconds <= 0 {
            anyhow::bail!("SESSION_LIFETIME_SECONDS must be a positive integer");
        }

        let object_storage = ObjectStorageConfig::from_env()?;

        Ok(Self {
            api_signing_key,
            backend_service_token,
            bind_address,
            database_url,
            database_max_connections,
            object_storage,
            setup_token,
            site_url,
            email_verification_ttl_seconds,
            session_lifetime_seconds,
        })
    }
}

impl ObjectStorageConfig {
    fn from_env() -> Result<Self> {
        let access_key = required_secret("OBJECT_STORAGE_ACCESS_KEY")?;
        let secret_key = required_secret("OBJECT_STORAGE_SECRET_KEY")?;
        let bucket = env::var("OBJECT_STORAGE_BUCKET").unwrap_or_else(|_| "ctfzone".to_owned());
        validate_bucket(&bucket)?;
        let region = env::var("OBJECT_STORAGE_REGION").unwrap_or_else(|_| "us-east-1".to_owned());
        if region.trim().is_empty() {
            anyhow::bail!("OBJECT_STORAGE_REGION must not be empty");
        }
        let internal_url = endpoint("OBJECT_STORAGE_INTERNAL_URL")?;
        let public_url = endpoint("OBJECT_STORAGE_PUBLIC_URL")?;
        let presign_ttl_seconds = env::var("PRESIGNED_URL_TTL_SECONDS")
            .unwrap_or_else(|_| "900".to_owned())
            .parse::<u64>()
            .context("PRESIGNED_URL_TTL_SECONDS must be an integer")?;
        if !(60..=3600).contains(&presign_ttl_seconds) {
            anyhow::bail!("PRESIGNED_URL_TTL_SECONDS must be between 60 and 3600");
        }
        let max_upload_bytes = env::var("OBJECT_STORAGE_MAX_UPLOAD_BYTES")
            .unwrap_or_else(|_| (512_i64 * 1024 * 1024).to_string())
            .parse::<i64>()
            .context("OBJECT_STORAGE_MAX_UPLOAD_BYTES must be an integer")?;
        if max_upload_bytes <= 0 || max_upload_bytes > 512_i64 * 1024 * 1024 {
            anyhow::bail!("OBJECT_STORAGE_MAX_UPLOAD_BYTES must be between 1 byte and 512 MiB");
        }
        let max_pending_objects_per_principal =
            positive_i64_env("OBJECT_STORAGE_MAX_PENDING_OBJECTS_PER_PRINCIPAL", 8)?;
        let max_pending_bytes_per_principal = positive_i64_env(
            "OBJECT_STORAGE_MAX_PENDING_BYTES_PER_PRINCIPAL",
            1024_i64 * 1024 * 1024,
        )?;
        let max_retained_bytes_per_principal = positive_i64_env(
            "OBJECT_STORAGE_MAX_RETAINED_BYTES_PER_PRINCIPAL",
            10_i64 * 1024 * 1024 * 1024,
        )?;
        let max_uploads_per_hour_per_principal =
            positive_i64_env("OBJECT_STORAGE_MAX_UPLOADS_PER_HOUR_PER_PRINCIPAL", 60)?;

        Ok(Self {
            access_key,
            bucket,
            internal_url,
            max_upload_bytes,
            max_pending_bytes_per_principal,
            max_pending_objects_per_principal,
            max_retained_bytes_per_principal,
            max_uploads_per_hour_per_principal,
            presign_ttl_seconds,
            public_url,
            region,
            secret_key,
        })
    }
}

fn positive_i64_env(name: &str, default: i64) -> Result<i64> {
    let value = env::var(name)
        .ok()
        .map(|value| value.parse::<i64>())
        .transpose()
        .with_context(|| format!("{name} must be a positive integer"))?
        .unwrap_or(default);
    if value <= 0 {
        anyhow::bail!("{name} must be a positive integer");
    }
    Ok(value)
}

fn required_secret(name: &str) -> Result<String> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    if value.trim().is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    Ok(value)
}

fn endpoint(name: &str) -> Result<Url> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    let url = value
        .parse::<Url>()
        .with_context(|| format!("{name} must be a valid absolute URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        anyhow::bail!(
            "{name} must be an HTTP(S) origin without credentials, path, query, or fragment"
        );
    }
    Ok(url)
}

fn validate_bucket(value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    if !(3..=63).contains(&bytes.len())
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        || !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        || value.contains("..")
    {
        anyhow::bail!("OBJECT_STORAGE_BUCKET is not a valid S3 bucket name");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_validation_rejects_ambiguous_names() {
        for invalid in [
            "a",
            "CTFZone",
            "-ctfzone",
            "ctfzone-",
            "ctf..zone",
            "ctf_zone",
        ] {
            assert!(validate_bucket(invalid).is_err(), "{invalid}");
        }
        assert!(validate_bucket("ctfzone-assets-1").is_ok());
    }

    #[test]
    fn public_site_must_be_an_origin() {
        for invalid in [
            "ftp://ctf.example.org",
            "https://user@ctf.example.org",
            "https://ctf.example.org/path",
            "https://ctf.example.org?query=1",
            "https://ctf.example.org/#fragment",
        ] {
            let url = invalid.parse::<Url>().unwrap();
            assert!(
                !matches!(url.scheme(), "http" | "https")
                    || url.host().is_none()
                    || url.username() != ""
                    || url.password().is_some()
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || !matches!(url.path(), "" | "/"),
                "{invalid}"
            );
        }
    }
}
