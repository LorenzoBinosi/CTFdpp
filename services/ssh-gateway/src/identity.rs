use std::{
    fs as std_fs,
    io::{ErrorKind, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use tokio::{
    fs,
    process::Command,
    time::{sleep, timeout},
};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    api::{ApiClient, IdentityOperation, IdentityOperationKind},
    config::Config,
};

const PRIVATE_KEY_NAME: &str = "id_ed25519";
const PUBLIC_KEY_NAME: &str = "id_ed25519.pub";
const PENDING_PRIVATE_KEY_NAME: &str = ".id_ed25519.pending";
const PENDING_PUBLIC_KEY_NAME: &str = ".id_ed25519.pending.pub";
const ROTATION_REQUIRED_NAME: &str = ".rotation-required";
const LOCK_DIRECTORY: &str = ".locks";
const KEYGEN_TIMEOUT: Duration = Duration::from_secs(10);
const LOCK_EXCLUSIVE: i32 = 2;
const LOCK_UNLOCK: i32 = 8;
const OPEN_NOFOLLOW: i32 = 0o400000;

unsafe extern "C" {
    #[link_name = "flock"]
    fn system_flock(file_descriptor: i32, operation: i32) -> i32;
}

struct IdentityLock(std_fs::File);

impl Drop for IdentityLock {
    fn drop(&mut self) {
        // SAFETY: this guard owns a live descriptor until drop completes.
        unsafe {
            system_flock(self.0.as_raw_fd(), LOCK_UNLOCK);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IdentityMaterial {
    pub(crate) public_key: String,
    pub(crate) fingerprint: String,
    pub(crate) authorized_keys_line: String,
}

#[derive(Debug)]
pub(crate) struct IdentityBindingFailure {
    error_code: &'static str,
    observed_fingerprint: Option<String>,
}

impl IdentityBindingFailure {
    pub(crate) fn error_code(&self) -> &'static str {
        self.error_code
    }

    pub(crate) fn observed_fingerprint(&self) -> Option<&str> {
        self.observed_fingerprint.as_deref()
    }
}

impl std::fmt::Display for IdentityBindingFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SSH identity binding validation failed")
    }
}

impl std::error::Error for IdentityBindingFailure {}

#[derive(Clone, Debug)]
pub(crate) struct IdentityPaths {
    pub(crate) directory: PathBuf,
    pub(crate) private_key: PathBuf,
    public_key: PathBuf,
    pending_private_key: PathBuf,
    pending_public_key: PathBuf,
    rotation_required: PathBuf,
}

impl IdentityPaths {
    pub(crate) fn new(root: &Path, host_id: Uuid) -> Self {
        let directory = root.join(host_id.hyphenated().to_string());
        Self {
            private_key: directory.join(PRIVATE_KEY_NAME),
            public_key: directory.join(PUBLIC_KEY_NAME),
            pending_private_key: directory.join(PENDING_PRIVATE_KEY_NAME),
            pending_public_key: directory.join(PENDING_PUBLIC_KEY_NAME),
            rotation_required: directory.join(ROTATION_REQUIRED_NAME),
            directory,
        }
    }
}

pub(crate) async fn prepare_root(root: &Path) -> Result<()> {
    fs::create_dir_all(root)
        .await
        .with_context(|| format!("failed to create identity root {}", root.display()))?;
    fs::set_permissions(root, std_fs::Permissions::from_mode(0o700))
        .await
        .with_context(|| format!("failed to protect identity root {}", root.display()))?;
    let locks = root.join(LOCK_DIRECTORY);
    fs::create_dir_all(&locks).await?;
    fs::set_permissions(&locks, std_fs::Permissions::from_mode(0o700)).await?;
    let sessions = root.join(".sessions");
    fs::create_dir_all(&sessions).await?;
    fs::set_permissions(&sessions, std_fs::Permissions::from_mode(0o700)).await?;
    fsync_directory(root).await?;
    Ok(())
}

pub(crate) async fn run(config: Config, api: ApiClient) -> Result<()> {
    loop {
        match api.claim_identity_operation().await {
            Ok(Some(operation)) => process_operation(&config, &api, operation).await,
            Ok(None) => sleep(Duration::from_secs(3)).await,
            Err(error) => {
                warn!(%error, "failed to claim SSH identity operation");
                sleep(Duration::from_secs(5)).await;
            }
        }
    }
}

async fn process_operation(config: &Config, api: &ApiClient, operation: IdentityOperation) {
    info!(
        operation_id = %operation.id,
        host_id = %operation.host_id,
        kind = ?operation.kind,
        attempt = operation.attempt,
        lease_expires_at = %operation.lease_expires_at,
        "claimed SSH identity operation"
    );
    let identity_lock = match acquire_lock_async(&config.identity_directory, operation.host_id)
        .await
    {
        Ok(lock) => lock,
        Err(error) => {
            warn!(operation_id = %operation.id, host_id = %operation.host_id, %error, "failed to acquire SSH identity lock");
            return;
        }
    };
    let authorized = match api.heartbeat_identity_operation(&operation).await {
        Ok(authorized) => authorized,
        Err(error) => {
            warn!(operation_id = %operation.id, host_id = %operation.host_id, %error, "failed to revalidate claimed SSH identity operation");
            return;
        }
    };
    if !authorized {
        info!(operation_id = %operation.id, host_id = %operation.host_id, "aborted stale SSH identity operation");
        return;
    }
    // Move the lock into the blocking filesystem task. Dropping/cancelling this
    // async future must not unlock while an uncancellable blocking task is
    // still writing the UUID-confined identity directory.
    let result = match operation.kind {
        IdentityOperationKind::Generate => {
            match generate_identity_locked(
                &config.identity_directory,
                operation.host_id,
                identity_lock,
            )
            .await
            {
                Ok(material) => {
                    api.complete_identity_generation(&operation, &material.public_key)
                        .await
                }
                Err(error) => Err(error),
            }
        }
        IdentityOperationKind::Delete => {
            match delete_identity_locked(
                &config.identity_directory,
                operation.host_id,
                identity_lock,
            )
            .await
            {
                Ok(()) => api.complete_identity_deletion(&operation).await,
                Err(error) => Err(error),
            }
        }
    };

    match result {
        Ok(()) => {
            info!(operation_id = %operation.id, host_id = %operation.host_id, kind = ?operation.kind, "completed SSH identity operation")
        }
        Err(error) => {
            error!(operation_id = %operation.id, host_id = %operation.host_id, kind = ?operation.kind, %error, "SSH identity operation failed");
            if let Err(report_error) = api
                .fail_identity_operation(&operation, operation_error_code(operation.kind))
                .await
            {
                warn!(operation_id = %operation.id, %report_error, "failed to report SSH identity operation failure");
            }
        }
    }
}

fn operation_error_code(kind: IdentityOperationKind) -> &'static str {
    match kind {
        IdentityOperationKind::Generate => "identity_generation_failed",
        IdentityOperationKind::Delete => "identity_deletion_failed",
    }
}

#[cfg(test)]
async fn generate_identity(root: &Path, host_id: Uuid) -> Result<IdentityMaterial> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let _lock = acquire_lock(&root, host_id)?;
        generate_identity_blocking(&root, host_id)
    })
    .await
    .context("SSH identity generation task panicked")?
}

async fn generate_identity_locked(
    root: &Path,
    host_id: Uuid,
    identity_lock: IdentityLock,
) -> Result<IdentityMaterial> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let _identity_lock = identity_lock;
        generate_identity_blocking(&root, host_id)
    })
    .await
    .context("SSH identity generation task panicked")?
}

fn generate_identity_blocking(root: &Path, host_id: Uuid) -> Result<IdentityMaterial> {
    let paths = IdentityPaths::new(root, host_id);
    ensure_private_directory(&paths.directory)?;

    let rotation_required = regular_file_exists(&paths.rotation_required)?;
    if path_entry_exists(&paths.private_key)? && !rotation_required {
        if let Ok(material) = validate_existing_identity(&paths, host_id) {
            return Ok(material);
        }
    }
    remove_file_entry_if_exists(&paths.private_key)?;
    remove_file_entry_if_exists(&paths.public_key)?;
    remove_if_exists(&paths.pending_private_key)?;
    remove_if_exists(&paths.pending_public_key)?;

    let mut command = std::process::Command::new("ssh-keygen");
    command
        .arg("-q")
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-C")
        .arg(format!("ctfzone-webssh:{host_id}"))
        .arg("-f")
        .arg(&paths.pending_private_key)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", "/nonexistent")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = command.spawn().context("failed to start ssh-keygen")?;
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("failed to wait for ssh-keygen")? {
            if !status.success() {
                remove_if_exists(&paths.pending_private_key)?;
                remove_if_exists(&paths.pending_public_key)?;
                bail!("ssh-keygen did not create an Ed25519 identity");
            }
            break;
        }
        if started.elapsed() >= KEYGEN_TIMEOUT {
            child.kill().ok();
            child.wait().ok();
            remove_if_exists(&paths.pending_private_key)?;
            remove_if_exists(&paths.pending_public_key)?;
            bail!("ssh-keygen timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    }

    protect_file(&paths.pending_private_key, 0o600)?;
    protect_file(&paths.pending_public_key, 0o600)?;
    fsync_file_blocking(&paths.pending_private_key)?;
    fsync_file_blocking(&paths.pending_public_key)?;
    std_fs::rename(&paths.pending_public_key, &paths.public_key)
        .context("failed to publish SSH public key")?;
    std_fs::rename(&paths.pending_private_key, &paths.private_key)
        .context("failed to publish SSH private key")?;
    fsync_directory_blocking(&paths.directory)?;
    let material = validate_existing_identity(&paths, host_id)?;
    remove_if_exists(&paths.rotation_required)?;
    fsync_directory_blocking(&paths.directory)?;
    Ok(material)
}

fn validate_existing_identity(paths: &IdentityPaths, host_id: Uuid) -> Result<IdentityMaterial> {
    protect_file(&paths.private_key, 0o600)?;
    let output = std::process::Command::new("ssh-keygen")
        .arg("-y")
        .arg("-f")
        .arg(&paths.private_key)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", "/nonexistent")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .context("failed to inspect SSH private key")?;
    if !output.status.success() || output.stdout.len() > 1024 {
        bail!("stored SSH private key is invalid");
    }
    let derived =
        String::from_utf8(output.stdout).context("ssh-keygen returned a non-UTF-8 public key")?;
    let canonical = canonical_public_key(&derived, host_id)?;
    let stored = read_bounded(&paths.public_key, 1024).ok();
    if stored
        .as_deref()
        .and_then(|value| canonical_public_key(value, host_id).ok())
        .as_deref()
        != Some(canonical.as_str())
    {
        std_fs::write(&paths.public_key, format!("{canonical}\n"))
            .context("failed to repair SSH public key file")?;
        protect_file(&paths.public_key, 0o600)?;
        fsync_file_blocking(&paths.public_key)?;
        fsync_directory_blocking(&paths.directory)?;
    }
    material(&canonical)
}

#[cfg(test)]
async fn delete_identity(root: &Path, host_id: Uuid) -> Result<()> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let _lock = acquire_lock(&root, host_id)?;
        delete_identity_blocking(&root, host_id)
    })
    .await
    .context("SSH identity deletion task panicked")?
}

async fn delete_identity_locked(
    root: &Path,
    host_id: Uuid,
    identity_lock: IdentityLock,
) -> Result<()> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let _identity_lock = identity_lock;
        delete_identity_blocking(&root, host_id)
    })
    .await
    .context("SSH identity deletion task panicked")?
}

fn delete_identity_blocking(root: &Path, host_id: Uuid) -> Result<()> {
    let paths = IdentityPaths::new(root, host_id);
    let metadata = match std_fs::symlink_metadata(&paths.directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("failed to inspect SSH identity directory"),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("SSH identity path is not a real directory");
    }
    for path in [
        &paths.private_key,
        &paths.public_key,
        &paths.pending_private_key,
        &paths.pending_public_key,
        &paths.rotation_required,
    ] {
        remove_regular_file_if_exists(path)?;
    }
    let mut entries = std_fs::read_dir(&paths.directory)?;
    if entries.next().transpose()?.is_some() {
        bail!("SSH identity directory contains an unexpected entry");
    }
    std_fs::remove_dir(&paths.directory).context("failed to remove SSH identity directory")?;
    fsync_directory_blocking(root)
}

fn canonical_public_key(value: &str, host_id: Uuid) -> Result<String> {
    let mut parts = value.split_whitespace();
    if parts.next() != Some("ssh-ed25519") {
        bail!("identity is not Ed25519");
    }
    let encoded = parts.next().context("public key body is missing")?;
    if parts.next().is_some() && parts.next().is_some() {
        bail!("public key has unexpected fields");
    }
    let decoded = STANDARD
        .decode(encoded)
        .context("public key body is not canonical base64")?;
    if decoded.len() != 51 || !decoded.starts_with(b"\0\0\0\x0bssh-ed25519\0\0\0\x20") {
        bail!("public key is not a canonical Ed25519 SSH blob");
    }
    Ok(format!("ssh-ed25519 {encoded} ctfzone-webssh:{host_id}"))
}

fn material(public_key: &str) -> Result<IdentityMaterial> {
    let encoded = public_key
        .split_whitespace()
        .nth(1)
        .context("public key body is missing")?;
    let decoded = STANDARD.decode(encoded)?;
    let fingerprint =
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(decoded));
    Ok(IdentityMaterial {
        public_key: public_key.to_owned(),
        fingerprint: format!("SHA256:{fingerprint}"),
        authorized_keys_line: format!("restrict,pty {public_key}"),
    })
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    match std_fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => bail!("SSH identity path is not a real directory"),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            std_fs::create_dir(path).context("failed to create SSH identity directory")?;
        }
        Err(error) => return Err(error).context("failed to inspect SSH identity directory"),
    }
    std_fs::set_permissions(path, std_fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn acquire_lock(root: &Path, host_id: Uuid) -> Result<IdentityLock> {
    let path = root
        .join(LOCK_DIRECTORY)
        .join(format!("{}.lock", host_id.hyphenated()));
    let file = std_fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(OPEN_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("failed to open identity lock {}", path.display()))?;
    // SAFETY: `file` owns a valid descriptor, and the call does not outlive it.
    if unsafe { system_flock(file.as_raw_fd(), LOCK_EXCLUSIVE) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to lock SSH identity");
    }
    Ok(IdentityLock(file))
}

async fn acquire_lock_async(root: &Path, host_id: Uuid) -> Result<IdentityLock> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || acquire_lock(&root, host_id))
        .await
        .context("identity lock task panicked")?
}

fn protect_file(path: &Path, mode: u32) -> Result<()> {
    let metadata = std_fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("SSH identity material is not a regular file");
    }
    std_fs::set_permissions(path, std_fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<String> {
    let file = std_fs::OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_NOFOLLOW)
        .open(path)?;
    if file.metadata()?.len() > maximum {
        bail!("SSH public key file is too large");
    }
    let mut value = String::new();
    file.take(maximum + 1).read_to_string(&mut value)?;
    if value.len() as u64 > maximum {
        bail!("SSH public key file is too large");
    }
    Ok(value)
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match std_fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn remove_regular_file_if_exists(path: &Path) -> Result<()> {
    match std_fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            std_fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => bail!("refusing to remove non-regular identity entry"),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn remove_file_entry_if_exists(path: &Path) -> Result<()> {
    match std_fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            std_fs::remove_file(path)?;
            Ok(())
        }
        Ok(_) => bail!("refusing to remove non-file identity entry"),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn path_entry_exists(path: &Path) -> Result<bool> {
    match std_fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn regular_file_exists(path: &Path) -> Result<bool> {
    match std_fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(true),
        Ok(_) => bail!("SSH identity rotation marker is not a regular file"),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn fsync_file_blocking(path: &Path) -> Result<()> {
    std_fs::OpenOptions::new()
        .read(true)
        .open(path)?
        .sync_all()?;
    Ok(())
}

fn fsync_directory_blocking(path: &Path) -> Result<()> {
    std_fs::File::open(path)?.sync_all()?;
    Ok(())
}

async fn fsync_directory(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || fsync_directory_blocking(&path))
        .await
        .context("directory fsync task panicked")?
}

pub(crate) async fn validate_identity_binding(
    root: &Path,
    host_id: Uuid,
    expected_public_key: &str,
    expected_fingerprint: &str,
) -> std::result::Result<PathBuf, IdentityBindingFailure> {
    let paths = IdentityPaths::new(root, host_id);
    let _identity_lock = acquire_lock_async(root, host_id)
        .await
        .map_err(|_| unmarked_binding_failure("private_key_invalid", None))?;
    let private_key = paths.private_key.clone();
    let metadata = match fs::symlink_metadata(&private_key).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(binding_failure(&paths, "private_key_missing", None));
        }
        Err(_) => return Err(binding_failure(&paths, "private_key_invalid", None)),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(binding_failure(&paths, "private_key_invalid", None));
    }
    let private_key_for_command = private_key.clone();
    let derived = match timeout(
        Duration::from_secs(5),
        Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&private_key_for_command)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("HOME", "/nonexistent")
            .env("SSH_ASKPASS_REQUIRE", "never")
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output(),
    )
    .await
    {
        Ok(Ok(output)) => output,
        Ok(Err(_)) | Err(_) => {
            return Err(binding_failure(&paths, "private_key_invalid", None));
        }
    };
    if !derived.status.success() || derived.stdout.len() > 1024 {
        return Err(binding_failure(&paths, "private_key_invalid", None));
    }
    let derived = String::from_utf8(derived.stdout)
        .map_err(|_| binding_failure(&paths, "private_key_invalid", None))?;
    let canonical = canonical_public_key(&derived, host_id)
        .map_err(|_| binding_failure(&paths, "private_key_invalid", None))?;
    let identity =
        material(&canonical).map_err(|_| binding_failure(&paths, "private_key_invalid", None))?;
    let observed_fingerprint = Some(identity.fingerprint.clone());
    let expected = canonical_public_key(expected_public_key, host_id)
        .map_err(|_| binding_failure(&paths, "identity_mismatch", observed_fingerprint.clone()))?;
    if canonical != expected || identity.fingerprint != expected_fingerprint {
        return Err(binding_failure(
            &paths,
            "identity_mismatch",
            observed_fingerprint,
        ));
    }
    Ok(private_key)
}

fn binding_failure(
    paths: &IdentityPaths,
    error_code: &'static str,
    observed_fingerprint: Option<String>,
) -> IdentityBindingFailure {
    if error_code != "private_key_missing" {
        let _ = write_rotation_marker(paths);
    }
    unmarked_binding_failure(error_code, observed_fingerprint)
}

fn unmarked_binding_failure(
    error_code: &'static str,
    observed_fingerprint: Option<String>,
) -> IdentityBindingFailure {
    IdentityBindingFailure {
        error_code,
        observed_fingerprint,
    }
}

pub(crate) async fn mark_identity_for_rotation(root: &Path, host_id: Uuid) -> Result<()> {
    let root = root.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let _lock = acquire_lock(&root, host_id)?;
        let paths = IdentityPaths::new(&root, host_id);
        match std_fs::symlink_metadata(&paths.directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                write_rotation_marker(&paths)
            }
            Ok(_) => bail!("SSH identity path is not a real directory"),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("failed to inspect SSH identity directory"),
        }
    })
    .await
    .context("SSH identity rotation marker task panicked")?
}

fn write_rotation_marker(paths: &IdentityPaths) -> Result<()> {
    let mut marker = std_fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .custom_flags(OPEN_NOFOLLOW)
        .open(&paths.rotation_required)
        .context("failed to write SSH identity rotation marker")?;
    marker.write_all(b"rotate\n")?;
    marker.sync_all()?;
    fsync_directory_blocking(&paths.directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn ssh_keygen_available() -> bool {
        matches!(
            timeout(
                Duration::from_secs(2),
                tokio::process::Command::new("ssh-keygen")
                    .arg("-?")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status(),
            )
            .await,
            Ok(Ok(_))
        )
    }

    #[test]
    fn authorized_line_allows_shell_but_disables_forwarding() {
        let host_id = Uuid::nil();
        let encoded =
            STANDARD.encode([b"\0\0\0\x0bssh-ed25519\0\0\0\x20".as_slice(), &[7_u8; 32]].concat());
        let public = canonical_public_key(&format!("ssh-ed25519 {encoded}"), host_id).unwrap();
        let identity = material(&public).unwrap();
        assert!(
            identity
                .authorized_keys_line
                .starts_with("restrict,pty ssh-ed25519 ")
        );
        assert!(!identity.authorized_keys_line.contains("command="));
        assert!(!identity.authorized_keys_line.contains("no-pty"));
    }

    #[tokio::test]
    async fn generation_is_idempotent_and_deletion_is_uuid_confined() {
        if !ssh_keygen_available().await {
            return;
        }
        let root = std::env::temp_dir().join(format!("ctfzone-gateway-test-{}", Uuid::new_v4()));
        prepare_root(&root).await.unwrap();
        let host_id = Uuid::new_v4();
        let first = generate_identity(&root, host_id).await.unwrap();
        let second = generate_identity(&root, host_id).await.unwrap();
        assert_eq!(first, second);
        assert!(IdentityPaths::new(&root, host_id).private_key.exists());
        delete_identity(&root, host_id).await.unwrap();
        assert!(!IdentityPaths::new(&root, host_id).directory.exists());
        std_fs::remove_dir_all(&root).unwrap();
    }

    #[tokio::test]
    async fn pending_generation_rotates_corrupt_and_mismatched_identities() {
        if !ssh_keygen_available().await {
            return;
        }
        let root = std::env::temp_dir().join(format!("ctfzone-gateway-test-{}", Uuid::new_v4()));
        prepare_root(&root).await.unwrap();
        let host_id = Uuid::new_v4();
        let first = generate_identity(&root, host_id).await.unwrap();
        let paths = IdentityPaths::new(&root, host_id);

        std_fs::write(&paths.private_key, b"not an SSH private key\n").unwrap();
        let after_corruption = generate_identity(&root, host_id).await.unwrap();
        assert_ne!(first.public_key, after_corruption.public_key);

        let other = generate_identity(&root, Uuid::new_v4()).await.unwrap();
        let mismatch =
            validate_identity_binding(&root, host_id, &other.public_key, &other.fingerprint)
                .await
                .unwrap_err();
        assert_eq!(mismatch.error_code(), "identity_mismatch");
        assert!(mismatch.observed_fingerprint().is_some());
        mark_identity_for_rotation(&root, host_id).await.unwrap();

        let after_mismatch = generate_identity(&root, host_id).await.unwrap();
        assert_ne!(after_corruption.public_key, after_mismatch.public_key);
        std_fs::remove_dir_all(&root).unwrap();
    }
}
