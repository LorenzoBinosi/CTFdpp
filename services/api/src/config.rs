use std::{env, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result};
use reqwest::Url;

#[derive(Clone)]
pub struct Config {
    pub bind_address: SocketAddr,
    pub database_url: String,
    pub database_max_connections: u32,
    pub public_base_url: Url,
    pub secret_key: String,
    pub setup_token: String,
    pub session_cookie_name: String,
    pub session_lifetime_seconds: i64,
    pub upload_folder: PathBuf,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind_address = env::var("CTFZONE_API_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8080".to_owned())
            .parse()
            .context("CTFZONE_API_BIND must be a valid socket address")?;

        let database_url =
            env::var("DATABASE_URL").context("DATABASE_URL is required for the CTFZone API")?;

        let public_base_url = env::var("PUBLIC_BASE_URL")
            .unwrap_or_else(|_| "https://localhost".to_owned())
            .parse::<Url>()
            .context("PUBLIC_BASE_URL must be a valid absolute URL")?;
        if !matches!(public_base_url.scheme(), "http" | "https") || public_base_url.host().is_none()
        {
            anyhow::bail!("PUBLIC_BASE_URL must use HTTP or HTTPS and include a host");
        }

        let database_max_connections = env::var("DATABASE_MAX_CONNECTIONS")
            .unwrap_or_else(|_| "10".to_owned())
            .parse()
            .context("DATABASE_MAX_CONNECTIONS must be a positive integer")?;

        let secret_key =
            env::var("SECRET_KEY").context("SECRET_KEY is required for browser sessions")?;
        if secret_key.is_empty() {
            anyhow::bail!("SECRET_KEY must not be empty");
        }

        let setup_token = env::var("SETUP_TOKEN")
            .context("SETUP_TOKEN is required for first-install administration")?;
        if setup_token.is_empty() {
            anyhow::bail!("SETUP_TOKEN must not be empty");
        }

        let session_cookie_name =
            env::var("SESSION_COOKIE_NAME").unwrap_or_else(|_| "session".to_owned());
        if session_cookie_name.is_empty() {
            anyhow::bail!("SESSION_COOKIE_NAME must not be empty");
        }

        let session_lifetime_seconds = env::var("SESSION_LIFETIME_SECONDS")
            .unwrap_or_else(|_| "604800".to_owned())
            .parse::<i64>()
            .context("SESSION_LIFETIME_SECONDS must be a positive integer")?;
        if session_lifetime_seconds <= 0 {
            anyhow::bail!("SESSION_LIFETIME_SECONDS must be a positive integer");
        }

        let upload_folder = PathBuf::from(
            env::var("UPLOAD_FOLDER").unwrap_or_else(|_| "/var/lib/ctfzone/uploads".to_owned()),
        );
        if !upload_folder.is_absolute() {
            anyhow::bail!("UPLOAD_FOLDER must be an absolute path");
        }

        Ok(Self {
            bind_address,
            database_url,
            database_max_connections,
            public_base_url,
            secret_key,
            setup_token,
            session_cookie_name,
            session_lifetime_seconds,
            upload_folder,
        })
    }
}
