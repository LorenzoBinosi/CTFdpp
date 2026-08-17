use std::{
    fs as std_fs,
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use portable_pty::{Child, ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    time::timeout,
};
use uuid::Uuid;

use crate::{api::TicketGrant, config::Config};

const MAX_DIAGNOSTIC_BYTES: usize = 4096;
const OPEN_NOFOLLOW: i32 = 0o400000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostKey {
    pub(crate) public_key: String,
    pub(crate) fingerprint: String,
}

pub(crate) struct PtySession {
    master: Option<Box<dyn MasterPty + Send>>,
    reader: Option<Box<dyn Read + Send>>,
    writer: Option<Box<dyn Write + Send>>,
    child: Option<Box<dyn Child + Send + Sync>>,
    killer: Box<dyn ChildKiller + Send + Sync>,
    _known_hosts: SessionFiles,
    active: bool,
}

pub(crate) struct PtyParts {
    pub(crate) master: Box<dyn MasterPty + Send>,
    pub(crate) reader: Box<dyn Read + Send>,
    pub(crate) writer: Box<dyn Write + Send>,
}

impl PtySession {
    pub(crate) fn take_parts(&mut self) -> Result<PtyParts> {
        Ok(PtyParts {
            master: self
                .master
                .take()
                .context("SSH PTY master was unavailable")?,
            reader: self
                .reader
                .take()
                .context("SSH PTY reader was unavailable")?,
            writer: self
                .writer
                .take()
                .context("SSH PTY writer was unavailable")?,
        })
    }

    pub(crate) fn try_wait(&mut self) -> Result<Option<portable_pty::ExitStatus>> {
        Ok(self
            .child
            .as_mut()
            .context("SSH PTY child was unavailable")?
            .try_wait()?)
    }

    pub(crate) fn terminate(&mut self) {
        if !self.active {
            return;
        }
        if let Some(child) = self.child.as_mut() {
            if child.kill().is_ok() {
                let _ = child.wait();
                self.active = false;
            }
        } else if self.killer.kill().is_ok() {
            self.active = false;
        }
    }

    pub(crate) fn disarm_after_wait(&mut self) {
        self.active = false;
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        self.terminate();
    }
}

pub(crate) struct SessionFiles {
    directory: PathBuf,
    known_hosts: PathBuf,
}

impl Drop for SessionFiles {
    fn drop(&mut self) {
        let _ = std_fs::remove_file(&self.known_hosts);
        let _ = std_fs::remove_dir(&self.directory);
    }
}

pub(crate) async fn probe_host_key(config: &Config, address: SocketAddr) -> Result<HostKey> {
    let timeout_seconds = config.connect_timeout.as_secs().clamp(1, 60).to_string();
    let mut command = Command::new("ssh-keyscan");
    command
        .arg("-T")
        .arg(timeout_seconds)
        .arg("-t")
        .arg("ed25519")
        .arg("-p")
        .arg(address.port().to_string())
        .arg(address.ip().to_string())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", "/nonexistent")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .context("failed to start SSH host-key probe")?;
    let stdout = child
        .stdout
        .take()
        .context("SSH host-key probe stdout was unavailable")?;
    let stderr = child
        .stderr
        .take()
        .context("SSH host-key probe stderr was unavailable")?;
    let operation = async {
        let wait = async {
            child
                .wait()
                .await
                .context("failed to wait for SSH host-key probe")
        };
        tokio::try_join!(
            wait,
            read_bounded(stdout, MAX_DIAGNOSTIC_BYTES),
            read_bounded(stderr, MAX_DIAGNOSTIC_BYTES),
        )
    };
    let (status, stdout, _stderr) = timeout(
        config
            .connect_timeout
            .saturating_add(Duration::from_secs(2)),
        operation,
    )
    .await
    .context("SSH host-key probe timed out")??;
    if !status.success() {
        bail!("SSH host-key probe failed");
    }
    let output = String::from_utf8(stdout).context("SSH host-key probe was not UTF-8")?;
    let keys = output
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            fields.next()?;
            let algorithm = fields.next()?;
            let body = fields.next()?;
            (algorithm == "ssh-ed25519").then(|| format!("{algorithm} {body}"))
        })
        .map(|key| canonical_host_key(&key))
        .collect::<Result<Vec<_>>>()?;
    let Some(key) = keys.first() else {
        bail!("SSH server did not offer an Ed25519 host key");
    };
    if keys.iter().any(|candidate| candidate != key) {
        bail!("SSH host-key probe returned conflicting Ed25519 keys");
    }
    Ok(key.clone())
}

pub(crate) fn trusted_host_key(grant: &TicketGrant) -> Result<HostKey> {
    let public_key = grant
        .trusted_host_public_key
        .as_deref()
        .context("SSH host key has not been trusted")?;
    let key = canonical_host_key(public_key)?;
    if grant.trusted_host_key_fingerprint.as_deref() != Some(key.fingerprint.as_str()) {
        bail!("trusted SSH host-key fingerprint is inconsistent");
    }
    Ok(key)
}

pub(crate) async fn preflight(
    config: &Config,
    grant: &TicketGrant,
    address: SocketAddr,
    private_key: &Path,
    trusted_key: &HostKey,
    local_session_id: Uuid,
) -> Result<()> {
    validate_target(grant)?;
    let files = create_session_files(
        &config.identity_directory,
        local_session_id,
        &grant.host_key_alias,
        trusted_key,
    )?;
    let mut command = Command::new("ssh");
    for argument in ssh_arguments(config, grant, address, private_key, &files.known_hosts) {
        command.arg(argument);
    }
    command
        .arg("-T")
        .arg(address.ip().to_string())
        .arg("true")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", "/nonexistent")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = timeout(
        config
            .connect_timeout
            .saturating_add(Duration::from_secs(5)),
        command.status(),
    )
    .await
    .context("SSH public-key authentication timed out")??;
    drop(files);
    if !status.success() {
        bail!("SSH public-key authentication failed");
    }
    Ok(())
}

pub(crate) fn spawn_terminal(
    config: &Config,
    grant: &TicketGrant,
    address: SocketAddr,
    private_key: &Path,
    trusted_key: &HostKey,
    local_session_id: Uuid,
    pty_size: PtySize,
) -> Result<PtySession> {
    validate_target(grant)?;
    let files = create_session_files(
        &config.identity_directory,
        local_session_id,
        &grant.host_key_alias,
        trusted_key,
    )?;
    let pty_system = native_pty_system();
    let pair = pty_system.openpty(pty_size)?;
    let reader = pair.master.try_clone_reader()?;
    let writer = pair.master.take_writer()?;
    let mut command = CommandBuilder::new("/usr/bin/ssh");
    command.env_clear();
    command.env("PATH", "/usr/bin:/bin");
    command.env("LANG", "C.UTF-8");
    command.env("TERM", "xterm-256color");
    command.env("HOME", "/nonexistent");
    command.env("SSH_ASKPASS_REQUIRE", "never");
    // portable-pty otherwise derives the child's working directory from HOME.
    // HOME is deliberately nonexistent so OpenSSH cannot discover ambient user
    // configuration, while `/` is a guaranteed, read-only-safe working directory.
    command.cwd("/");
    for argument in ssh_arguments(config, grant, address, private_key, &files.known_hosts) {
        command.arg(argument);
    }
    command.arg("-tt");
    command.arg(address.ip().to_string());
    let child = pair.slave.spawn_command(command)?;
    let killer = child.clone_killer();
    drop(pair.slave);
    Ok(PtySession {
        master: Some(pair.master),
        reader: Some(reader),
        writer: Some(writer),
        child: Some(child),
        killer,
        _known_hosts: files,
        active: true,
    })
}

fn ssh_arguments(
    config: &Config,
    grant: &TicketGrant,
    address: SocketAddr,
    private_key: &Path,
    known_hosts: &Path,
) -> Vec<String> {
    vec![
        "-F".into(),
        "/dev/null".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        "PasswordAuthentication=no".into(),
        "-o".into(),
        "KbdInteractiveAuthentication=no".into(),
        "-o".into(),
        "PreferredAuthentications=publickey".into(),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o".into(),
        format!("HostKeyAlias={}", grant.host_key_alias),
        "-o".into(),
        "HostKeyAlgorithms=ssh-ed25519".into(),
        "-o".into(),
        "UpdateHostKeys=no".into(),
        "-o".into(),
        "ForwardAgent=no".into(),
        "-o".into(),
        "ForwardX11=no".into(),
        "-o".into(),
        "ForwardX11Trusted=no".into(),
        "-o".into(),
        "IdentityAgent=none".into(),
        "-o".into(),
        "Tunnel=no".into(),
        "-o".into(),
        "ClearAllForwardings=yes".into(),
        "-o".into(),
        "PermitLocalCommand=no".into(),
        "-o".into(),
        "LocalCommand=none".into(),
        "-o".into(),
        "ProxyCommand=none".into(),
        "-o".into(),
        "ProxyJump=none".into(),
        "-o".into(),
        "EscapeChar=none".into(),
        "-o".into(),
        "EnableEscapeCommandline=no".into(),
        "-o".into(),
        "VerifyHostKeyDNS=no".into(),
        "-e".into(),
        "none".into(),
        "-o".into(),
        "ConnectionAttempts=1".into(),
        "-o".into(),
        format!(
            "ConnectTimeout={}",
            config.connect_timeout.as_secs().clamp(1, 60)
        ),
        "-o".into(),
        "ServerAliveInterval=15".into(),
        "-o".into(),
        "ServerAliveCountMax=2".into(),
        "-o".into(),
        "LogLevel=ERROR".into(),
        "-i".into(),
        private_key.display().to_string(),
        "-p".into(),
        address.port().to_string(),
        "-l".into(),
        grant.ssh_user.clone(),
    ]
}

fn create_session_files(
    identity_root: &Path,
    local_session_id: Uuid,
    host_key_alias: &str,
    trusted_key: &HostKey,
) -> Result<SessionFiles> {
    if !safe_alias(host_key_alias) {
        bail!("API returned an unsafe SSH host-key alias");
    }
    let directory = identity_root
        .join(".sessions")
        .join(local_session_id.hyphenated().to_string());
    std_fs::create_dir(&directory).context("failed to create SSH session directory")?;
    std_fs::set_permissions(&directory, std_fs::Permissions::from_mode(0o700))?;
    let known_hosts = directory.join("known_hosts");
    let mut file = std_fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(OPEN_NOFOLLOW)
        .open(&known_hosts)
        .context("failed to create pinned known_hosts file")?;
    writeln!(file, "{host_key_alias} {}", trusted_key.public_key)?;
    file.sync_all()?;
    std_fs::File::open(&directory)?.sync_all()?;
    Ok(SessionFiles {
        directory,
        known_hosts,
    })
}

fn canonical_host_key(value: &str) -> Result<HostKey> {
    let mut fields = value.split_whitespace();
    if fields.next() != Some("ssh-ed25519") {
        bail!("only ssh-ed25519 host keys are supported in v1");
    }
    let encoded = fields.next().context("SSH host key body is missing")?;
    if fields.next().is_some() {
        bail!("SSH host key must not contain a comment");
    }
    let decoded = STANDARD
        .decode(encoded)
        .context("SSH host key is not base64")?;
    if decoded.len() != 51 || !decoded.starts_with(b"\0\0\0\x0bssh-ed25519\0\0\0\x20") {
        bail!("SSH host key is not a canonical Ed25519 key blob");
    }
    Ok(HostKey {
        public_key: format!("ssh-ed25519 {encoded}"),
        fingerprint: format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(decoded))),
    })
}

fn validate_target(grant: &TicketGrant) -> Result<()> {
    if !safe_user(&grant.ssh_user) || !safe_alias(&grant.host_key_alias) {
        bail!("API returned an unsafe SSH target");
    }
    Ok(())
}

fn safe_user(value: &str) -> bool {
    let mut characters = value.chars();
    let first = characters.next();
    !value.is_empty()
        && value.len() <= 32
        && value.is_ascii()
        && !matches!(value, "root" | "toor")
        && first.is_some_and(|character| character.is_ascii_lowercase() || character == '_')
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '-')
        })
}

async fn read_bounded(mut reader: impl AsyncRead + Unpin, maximum: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(count) > maximum {
            bail!("SSH child output exceeded its bound");
        }
        output.extend_from_slice(&buffer[..count]);
    }
}

fn safe_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.is_ascii()
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || ".:_-".contains(character))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_ed25519_host_key_has_openssh_fingerprint() {
        let encoded =
            STANDARD.encode([b"\0\0\0\x0bssh-ed25519\0\0\0\x20".as_slice(), &[3_u8; 32]].concat());
        let key = canonical_host_key(&format!("ssh-ed25519 {encoded}")).unwrap();
        assert!(key.fingerprint.starts_with("SHA256:"));
        assert_eq!(key.public_key, format!("ssh-ed25519 {encoded}"));
        assert!(canonical_host_key(&format!("ssh-rsa {encoded}")).is_err());
    }

    #[test]
    fn rejects_target_option_injection_and_root() {
        assert!(safe_user("tecnico"));
        for value in [
            "root",
            "ROOT",
            "toor",
            "Legacy.User",
            "9user",
            "-oProxyCommand=x",
            "bad@host",
        ] {
            assert!(!safe_user(value));
        }
        assert!(safe_alias("ctfzone-host:22"));
        assert!(!safe_alias("-oProxyCommand=x"));
    }

    #[test]
    fn ssh_arguments_fail_closed() {
        let source = include_str!("ssh.rs");
        for option in [
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
            "GlobalKnownHostsFile=/dev/null",
            "HostKeyAlgorithms=ssh-ed25519",
            "ClearAllForwardings=yes",
            "EscapeChar=none",
            "ProxyCommand=none",
            "LocalCommand=none",
            "IdentityAgent=none",
            "EnableEscapeCommandline=no",
            "VerifyHostKeyDNS=no",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
        ] {
            assert!(source.contains(option), "missing OpenSSH option {option}");
        }
        let unsafe_host_key_option = ["StrictHostKeyChecking", "no"].join("=");
        assert!(!source.contains(&unsafe_host_key_option));
        assert!(source.contains("impl Drop for PtySession"));
        assert!(source.contains("self.terminate()"));
        assert!(source.contains("command.cwd(\"/\")"));
    }
}
