use anyhow::{anyhow, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|s| !s.is_empty())
}

/// Resolve the default SSH private key path (`<ssh_dir>/bab_ed25519`), checking
/// `BAB_SSH_DIR` -> `VPSKIT_SSH_DIR` -> `SSH_DIR` -> `$HOME/.ssh`.
pub fn default_ssh_key_path() -> Result<PathBuf> {
    let dir = if let Some(d) = non_empty_env("BAB_SSH_DIR")
        .or_else(|| non_empty_env("VPSKIT_SSH_DIR"))
        .or_else(|| non_empty_env("SSH_DIR"))
    {
        PathBuf::from(d)
    } else {
        let home = non_empty_env("HOME")
            .ok_or_else(|| anyhow!("HOME environment variable is not set"))?;
        PathBuf::from(home).join(".ssh")
    };
    Ok(dir.join("bab_ed25519"))
}

fn public_key_path(key_path: &Path) -> PathBuf {
    let is_pub = key_path.extension().and_then(|e| e.to_str()) == Some("pub")
        || key_path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".pub"));
    if is_pub {
        key_path.to_path_buf()
    } else {
        let mut os = key_path.as_os_str().to_os_string();
        os.push(".pub");
        PathBuf::from(os)
    }
}

/// Read and trim an SSH public key from `key_path` (if it ends with `.pub`) or `<key_path>.pub`.
pub fn read_public_key(key_path: &Path) -> Result<String> {
    let pub_path = public_key_path(key_path);
    let content = fs::read_to_string(&pub_path)
        .map_err(|e| anyhow!("Failed to read public key {}: {}", pub_path.display(), e))?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Public key file {} is empty", pub_path.display()));
    }
    Ok(trimmed.to_string())
}

/// Ensure an Ed25519 SSH keypair exists at `key_path` (and `<key_path>.pub`), generating one if missing,
/// enforcing secure permissions, and returning the trimmed public key string.
pub fn ensure_ssh_keypair(key_path: &Path, comment: &str) -> Result<String> {
    let pub_path = public_key_path(key_path);
    if key_path.exists() && pub_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
        }
        return read_public_key(key_path);
    }

    if let Some(parent) = key_path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
    }

    let keygen_bin =
        non_empty_env("BAB_SSH_KEYGEN_BIN").unwrap_or_else(|| "ssh-keygen".to_string());
    let output = Command::new(&keygen_bin)
        .arg("-t")
        .arg("ed25519")
        .arg("-N")
        .arg("")
        .arg("-C")
        .arg(comment)
        .arg("-f")
        .arg(key_path)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| anyhow!("Failed to run {}: {}", keygen_bin, e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "{} failed with status {}: {}{}",
            keygen_bin,
            output.status,
            stderr.trim(),
            if stderr.trim().is_empty() {
                stdout.trim()
            } else {
                ""
            }
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o644))?;
    }

    read_public_key(key_path)
}

/// Validate whether a target string is a valid IPv4 address or a hostname.
pub fn is_valid_target(target: &str) -> bool {
    if target.is_empty() {
        return false;
    }

    // IPv4 check: exactly four dot-separated octets, 1..=3 ASCII digits each, 0..=255
    let parts: Vec<&str> = target.split('.').collect();
    if parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u8>().is_ok())
    {
        return true;
    }

    // Reject plain numeric dotted strings that are not valid IPv4 (e.g., "1.2.3", "999.1.1.1", "123")
    if target.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return false;
    }

    // Hostname / MagicDNS validation per RFC-1123:
    // Non-empty dot-separated labels, each starting/ending with ASCII alphanumeric,
    // containing only ASCII alphanumeric or '-'.
    for label in parts {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TransportMode {
    #[default]
    Tailscale,
    SshKey(PathBuf),
}

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub status_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status_code == 0
    }
}

#[derive(Debug, Clone)]
pub struct SshTransport {
    ssh_bin: PathBuf,
    scp_bin: PathBuf,
    mode: TransportMode,
}

impl SshTransport {
    pub fn from_env(mode: TransportMode) -> Self {
        let ssh_bin = non_empty_env("BAB_SSH_BIN")
            .or_else(|| non_empty_env("VPSKIT_SSH_BIN"))
            .unwrap_or_else(|| "ssh".to_string());
        let scp_bin = non_empty_env("BAB_SCP_BIN")
            .or_else(|| non_empty_env("VPSKIT_SCP_BIN"))
            .unwrap_or_else(|| "scp".to_string());
        Self {
            ssh_bin: PathBuf::from(ssh_bin),
            scp_bin: PathBuf::from(scp_bin),
            mode,
        }
    }

    pub fn new(mode: TransportMode) -> Self {
        Self::from_env(mode)
    }

    pub fn with_bins<I, J>(mode: TransportMode, ssh_bin: I, scp_bin: J) -> Self
    where
        I: Into<PathBuf>,
        J: Into<PathBuf>,
    {
        Self {
            ssh_bin: ssh_bin.into(),
            scp_bin: scp_bin.into(),
            mode,
        }
    }

    /// Build argument vector applying transport‑specific stripping/injection.
    pub fn build_args(&self, raw_args: &[String]) -> Vec<String> {
        let mut args: Vec<String> = Vec::new();
        let mut i = 0;
        let mut stripped_ts_key = false;
        while i < raw_args.len() {
            if raw_args[i] == "-i" && i + 1 < raw_args.len() {
                let val = &raw_args[i + 1];
                if val == "tailscale" || val.is_empty() {
                    stripped_ts_key = true;
                } else {
                    args.push(raw_args[i].clone());
                    args.push(val.clone());
                }
                i += 2;
                continue;
            }
            // preserve argument
            args.push(raw_args[i].clone());
            i += 1;
        }
        // If we stripped a tailscale key or the mode is Tailscale, prepend strict host checking.
        if stripped_ts_key || matches!(self.mode, TransportMode::Tailscale) {
            let mut prefixed = vec!["-o".to_string(), "StrictHostKeyChecking=accept-new".to_string()];
            prefixed.extend(args);
            prefixed
        } else {
            args
        }
    }

    fn mode_base_args(&self) -> Vec<String> {
        match &self.mode {
            TransportMode::Tailscale => self.build_args(&[]),
            TransportMode::SshKey(key_path) => {
                let mut args = self.build_args(&[
                    "-i".to_string(),
                    key_path.to_string_lossy().into_owned(),
                ]);
                let has_strict = args
                    .windows(2)
                    .any(|w| w[0] == "-o" && w[1] == "StrictHostKeyChecking=accept-new");
                if !has_strict {
                    let mut prefixed =
                        vec!["-o".to_string(), "StrictHostKeyChecking=accept-new".to_string()];
                    prefixed.extend(args);
                    args = prefixed;
                }
                args
            }
        }
    }

    fn run_cmd(&self, bin: &Path, args: &[String]) -> Result<CommandOutput> {
        let mut attempts = 0;
        let output = loop {
            match Command::new(bin).args(args).output() {
                Ok(out) => break out,
                // Retry transient ETXTBSY (os error 26) caused by concurrent test fork windows on Linux.
                Err(e) if e.raw_os_error() == Some(26) && attempts < 10 => {
                    attempts += 1;
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => return Err(anyhow::anyhow!(e)),
            }
        };
        Ok(CommandOutput {
            status_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    pub fn exec(&self, user: &str, host: &str, remote_cmd: &str) -> Result<CommandOutput> {
        if !is_valid_target(host) {
            return Err(anyhow::anyhow!("invalid target"));
        }
        let mut args = self.mode_base_args();
        args.push("-o".to_string());
        args.push("BatchMode=yes".to_string());
        args.push(format!("{}@{}", user, host));
        args.push(remote_cmd.to_string());
        self.run_cmd(&self.ssh_bin, &args)
    }

    pub fn exec_raw(&self, args: &[String]) -> Result<CommandOutput> {
        let args = self.build_args(args);
        self.run_cmd(&self.ssh_bin, &args)
    }

    pub fn scp_upload(
        &self,
        local_path: &Path,
        user: &str,
        host: &str,
        remote_path: &str,
    ) -> Result<CommandOutput> {
        if !is_valid_target(host) {
            return Err(anyhow::anyhow!("invalid target"));
        }
        let mut args = self.mode_base_args();
        args.push(local_path.to_string_lossy().to_string());
        args.push(format!("{}@{}:{}", user, host, remote_path));
        self.run_cmd(&self.scp_bin, &args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn new(keys: &[&str]) -> Self {
            let saved = keys
                .iter()
                .map(|k| ((*k).to_string(), env::var(k).ok()))
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => env::set_var(&k, val),
                    None => env::remove_var(&k),
                }
            }
        }
    }

    fn write_arg_logger_mock(dir: &Path, name: &str, log_path: &Path) -> Result<PathBuf> {
        let mock_path = dir.join(name);
        {
            let mut f = File::create(&mock_path)?;
            writeln!(f, "#!/usr/bin/env bash")?;
            writeln!(f, "printf '%s\\n' \"$@\" > \"{}\"", log_path.display())?;
        }
        fs::set_permissions(&mock_path, fs::Permissions::from_mode(0o755))?;
        Ok(mock_path)
    }

    #[test]
    fn test_is_valid_target_ipv4() {
        assert!(is_valid_target("192.168.0.1"));
        assert!(is_valid_target("192.0.2.10"));
        assert!(is_valid_target("100.64.0.1"));
        assert!(!is_valid_target("256.0.0.1"));
        assert!(!is_valid_target("999.1.1.1"));
        assert!(!is_valid_target("1.2.3"));
        assert!(!is_valid_target("1.2.3.4.5"));
        assert!(!is_valid_target("123"));
        assert!(!is_valid_target("+1.2.3.4"));
    }

    #[test]
    fn test_is_valid_target_hostname() {
        assert!(is_valid_target("example.com"));
        assert!(is_valid_target("vps.tail123.ts.net"));
        assert!(is_valid_target("my-vps"));
        assert!(is_valid_target(&"my-host_123".replace('_', "-")));
        assert!(!is_valid_target("my-host_123"));
        assert!(!is_valid_target(""));
        assert!(!is_valid_target("-bad.com"));
        assert!(!is_valid_target("-leading-dash"));
        assert!(!is_valid_target("bad-.com"));
        assert!(!is_valid_target("bad.-com"));
        assert!(!is_valid_target("bad..com"));
        assert!(!is_valid_target("bad..host"));
        assert!(!is_valid_target("bad.."));
        assert!(!is_valid_target("bad com"));
    }

    #[test]
    fn test_build_args_stripping() {
        let transport = SshTransport::with_bins(TransportMode::Tailscale, "/bin/true", "/bin/true");
        let raw = vec!["-i".to_string(), "tailscale".to_string(), "-v".to_string()];
        let args = transport.build_args(&raw);
        assert_eq!(args, vec!["-o", "StrictHostKeyChecking=accept-new", "-v"]);

        let ssh_mode = SshTransport::with_bins(
            TransportMode::SshKey(PathBuf::from("/tmp/key")),
            "/bin/true",
            "/bin/true",
        );
        let raw_empty_i = vec!["-i".to_string(), "".to_string(), "-v".to_string()];
        assert_eq!(
            ssh_mode.build_args(&raw_empty_i),
            vec!["-o", "StrictHostKeyChecking=accept-new", "-v"]
        );
    }

    #[test]
    fn test_build_args_preserve_other_i() {
        let transport = SshTransport::with_bins(
            TransportMode::SshKey(PathBuf::from("/tmp/key")),
            "/bin/true",
            "/bin/true",
        );
        let raw = vec!["-i".to_string(), "/path/to/key".to_string(), "-v".to_string()];
        let args = transport.build_args(&raw);
        assert_eq!(args, vec!["-i", "/path/to/key", "-v"]);
    }

    #[test]
    fn test_exec_uses_mock_binary() -> Result<()> {
        let dir = tempdir()?;
        let log_path = dir.path().join("out.txt");
        let mock_path = write_arg_logger_mock(dir.path(), "ssh_mock", &log_path)?;
        let transport = SshTransport::with_bins(TransportMode::Tailscale, &mock_path, &mock_path);
        let out = transport.exec("user", "example.com", "echo hi")?;
        assert!(out.success());
        let recorded: Vec<String> = fs::read_to_string(&log_path)?
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(
            recorded,
            vec![
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "BatchMode=yes",
                "user@example.com",
                "echo hi",
            ]
        );
        Ok(())
    }

    #[test]
    fn test_exec_raw_and_scp_with_ssh_key() -> Result<()> {
        let dir = tempdir()?;
        let ssh_log = dir.path().join("ssh.txt");
        let scp_log = dir.path().join("scp.txt");
        let ssh_mock = write_arg_logger_mock(dir.path(), "ssh_mock", &ssh_log)?;
        let scp_mock = write_arg_logger_mock(dir.path(), "scp_mock", &scp_log)?;

        let ts = SshTransport::with_bins(TransportMode::Tailscale, &ssh_mock, &scp_mock);
        let out = ts.exec_raw(&[
            "-i".to_string(),
            "tailscale".to_string(),
            "deploy@100.64.0.1".to_string(),
            "uptime".to_string(),
        ])?;
        assert!(out.success());
        let recorded: Vec<String> = fs::read_to_string(&ssh_log)?
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(
            recorded,
            vec![
                "-o",
                "StrictHostKeyChecking=accept-new",
                "deploy@100.64.0.1",
                "uptime",
            ]
        );

        let key_transport = SshTransport::with_bins(
            TransportMode::SshKey(PathBuf::from("/tmp/id_ed25519")),
            &ssh_mock,
            &scp_mock,
        );
        let local_file = dir.path().join("payload.txt");
        fs::write(&local_file, "hello")?;
        let scp_out = key_transport.scp_upload(&local_file, "deploy", "203.0.113.10", "/tmp/p")?;
        assert!(scp_out.success());
        let scp_recorded: Vec<String> = fs::read_to_string(&scp_log)?
            .lines()
            .map(String::from)
            .collect();
        assert_eq!(
            scp_recorded,
            vec![
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-i",
                "/tmp/id_ed25519",
                local_file.to_string_lossy().as_ref(),
                "deploy@203.0.113.10:/tmp/p",
            ]
        );

        // Empty SshKey path triggers build_args stripping; mode_base_args must not duplicate StrictHostKeyChecking.
        let empty_key_transport = SshTransport::with_bins(
            TransportMode::SshKey(PathBuf::from("")),
            &ssh_mock,
            &scp_mock,
        );
        assert_eq!(
            empty_key_transport.mode_base_args(),
            vec!["-o", "StrictHostKeyChecking=accept-new"]
        );
        Ok(())
    }

    #[test]
    fn env_var_overrides_binaries() {
        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "BAB_SSH_BIN",
            "BAB_SCP_BIN",
            "VPSKIT_SSH_BIN",
            "VPSKIT_SCP_BIN",
        ]);

        // BAB_* takes precedence over VPSKIT_*.
        env::set_var("BAB_SSH_BIN", "/bab/ssh");
        env::set_var("BAB_SCP_BIN", "/bab/scp");
        env::set_var("VPSKIT_SSH_BIN", "/vpskit/ssh");
        env::set_var("VPSKIT_SCP_BIN", "/vpskit/scp");
        let t_bab = SshTransport::from_env(TransportMode::Tailscale);
        assert_eq!(t_bab.ssh_bin, PathBuf::from("/bab/ssh"));
        assert_eq!(t_bab.scp_bin, PathBuf::from("/bab/scp"));

        // Fallback to VPSKIT_* when BAB_* is empty or unset.
        env::set_var("BAB_SSH_BIN", "");
        env::remove_var("BAB_SCP_BIN");
        let t_fallback = SshTransport::from_env(TransportMode::Tailscale);
        assert_eq!(t_fallback.ssh_bin, PathBuf::from("/vpskit/ssh"));
        assert_eq!(t_fallback.scp_bin, PathBuf::from("/vpskit/scp"));

        // Default to "ssh" / "scp" when both are empty or unset.
        env::set_var("VPSKIT_SSH_BIN", "");
        env::remove_var("VPSKIT_SCP_BIN");
        let t_default = SshTransport::new(TransportMode::Tailscale);
        assert_eq!(t_default.ssh_bin, PathBuf::from("ssh"));
        assert_eq!(t_default.scp_bin, PathBuf::from("scp"));
    }

    #[test]
    fn test_default_ssh_key_path_precedence() -> Result<()> {
        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&["BAB_SSH_DIR", "VPSKIT_SSH_DIR", "SSH_DIR", "HOME"]);
        for k in ["BAB_SSH_DIR", "VPSKIT_SSH_DIR", "SSH_DIR"] {
            env::remove_var(k);
        }

        env::set_var("HOME", "/tmp/bab-home");
        assert_eq!(
            default_ssh_key_path()?,
            PathBuf::from("/tmp/bab-home/.ssh/bab_ed25519")
        );

        env::set_var("SSH_DIR", "/tmp/ssh-dir");
        assert_eq!(
            default_ssh_key_path()?,
            PathBuf::from("/tmp/ssh-dir/bab_ed25519")
        );

        env::set_var("VPSKIT_SSH_DIR", "/tmp/vpskit-ssh-dir");
        assert_eq!(
            default_ssh_key_path()?,
            PathBuf::from("/tmp/vpskit-ssh-dir/bab_ed25519")
        );

        env::set_var("BAB_SSH_DIR", "/tmp/bab-ssh-dir");
        assert_eq!(
            default_ssh_key_path()?,
            PathBuf::from("/tmp/bab-ssh-dir/bab_ed25519")
        );

        // Empty BAB_SSH_DIR falls back to VPSKIT_SSH_DIR.
        env::set_var("BAB_SSH_DIR", "");
        assert_eq!(
            default_ssh_key_path()?,
            PathBuf::from("/tmp/vpskit-ssh-dir/bab_ed25519")
        );

        Ok(())
    }

    #[test]
    fn test_read_public_key_behavior() -> Result<()> {
        let dir = tempdir()?;
        let priv_path = dir.path().join("my_key");
        let pub_path = dir.path().join("my_key.pub");

        // Missing file errors cleanly.
        assert!(read_public_key(&priv_path).is_err());

        // Empty file errors cleanly.
        fs::write(&pub_path, "   \n\t  ")?;
        assert!(read_public_key(&priv_path).is_err());

        // Reads and trims when passed private path or .pub path.
        fs::write(&pub_path, "  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host \n")?;
        assert_eq!(
            read_public_key(&priv_path)?,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host"
        );
        assert_eq!(
            read_public_key(&pub_path)?,
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host"
        );
        Ok(())
    }

    #[test]
    fn test_ensure_ssh_keypair_generates_and_is_idempotent() -> Result<()> {
        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&["BAB_SSH_KEYGEN_BIN"]);
        env::remove_var("BAB_SSH_KEYGEN_BIN");

        let dir = tempdir()?;
        let ssh_dir = dir.path().join("nested_ssh");
        let key_path = ssh_dir.join("bab_ed25519");
        let pub_path = ssh_dir.join("bab_ed25519.pub");

        let pub1 = ensure_ssh_keypair(&key_path, "bab@test")?;
        assert!(
            pub1.starts_with("ssh-ed25519 "),
            "unexpected pubkey: {}",
            pub1
        );
        assert!(key_path.exists());
        assert!(pub_path.exists());

        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&ssh_dir)?.permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&key_path)?.permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&pub_path)?.permissions().mode() & 0o777,
                0o644
            );

            // Loosen private key permissions and ensure second call fixes them and preserves key.
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))?;
        }

        let pub2 = ensure_ssh_keypair(&key_path, "bab@different-comment")?;
        assert_eq!(pub1, pub2);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&key_path)?.permissions().mode() & 0o777,
            0o600
        );

        Ok(())
    }
}
