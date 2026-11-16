use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use rand::Rng;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static MASTER_KEY_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

const ENC_V1_PREFIX: &str = "enc:v1:";
const MASTER_KEY_LEN: usize = 32;

/// Maximum log file size retained by [`LogStore`] (10 MiB).
pub const MAX_LOG_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Default length for generated random sudo passwords.
pub const SUDO_PASSWORD_LEN: usize = 10;

/// Generate a random ASCII alphanumeric password of exact length `len`.
pub fn generate_random_password(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn sanitize_box_key_part(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let sanitized: String = trimmed
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Some(sanitized)
}

/// Environment variable names for API keys supported by `Settings`.
pub const API_KEY_ENV_NAMES: [&str; 7] = [
    "TAILSCALE_API_KEY",
    "VULTR_API_KEY",
    "UPCLOUD_API_TOKEN",
    "LINODE_API_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ACCOUNT_ID",
    "GITHUB_TOKEN",
];

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

/// Resolve the default configuration directory (`BAB_CONFIG_DIR` -> `BAB_SSH_DIR` ->
/// `VPSKIT_SSH_DIR` -> `SSH_DIR` -> `$HOME/.config/bab`), creating it with `0o700`
/// permissions if missing.
pub fn default_config_dir() -> Result<PathBuf> {
    let dir = if let Some(p) = non_empty_env("BAB_CONFIG_DIR")
        .or_else(|| non_empty_env("BAB_SSH_DIR"))
        .or_else(|| non_empty_env("VPSKIT_SSH_DIR"))
        .or_else(|| non_empty_env("SSH_DIR"))
    {
        PathBuf::from(p)
    } else {
        let home = non_empty_env("HOME")
            .ok_or_else(|| anyhow!("HOME environment variable is not set"))?;
        PathBuf::from(home).join(".config").join("bab")
    };
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    #[cfg(unix)]
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn resolve_state_path(file_vars: &[&str], default_filename: &str) -> Result<PathBuf> {
    for var in file_vars {
        if let Some(p) = non_empty_env(var) {
            return Ok(PathBuf::from(p));
        }
    }
    Ok(default_config_dir()?.join(default_filename))
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)?;
            // chmod 0o700 on the directory
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

fn atomic_write<F>(path: &Path, write_fn: F) -> Result<()>
where
    F: FnOnce(&mut File) -> Result<()>,
{
    ensure_parent_dir(path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let base_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("state");
    let pid = std::process::id();

    let (mut tmp_file, tmp_path) = loop {
        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!("{}.tmp.{}.{}", base_name, pid, seq));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(f) => break (f, candidate),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    };

    let write_result = (|| -> Result<()> {
        write_fn(&mut tmp_file)?;
        tmp_file.sync_all()?;
        drop(tmp_file);
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
        fs::rename(&tmp_path, path)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_result
}

/// Format the current UTC wall-clock time as `[YYYY-MM-DDTHH:MM:SSZ]`.
pub fn format_utc_timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_utc_timestamp_from_secs(secs)
}

fn format_utc_timestamp_from_secs(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let hour = sod / 3_600;
    let minute = (sod % 3_600) / 60;
    let second = sod % 60;

    // Howard Hinnant's civil-from-days integer arithmetic (days since 1970-01-01).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = y + if month <= 2 { 1 } else { 0 };

    format!(
        "[{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z]",
        year, month, day, hour, minute, second
    )
}

/// Represents a file storing KEY="value" lines.
#[derive(Debug, Clone)]
pub struct StateFile {
    path: PathBuf,
}

impl StateFile {
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        StateFile { path: path.into() }
    }

    /// Read the first matching KEY line, return the value without surrounding quotes.
    pub fn read_var(&self, key: &str) -> Result<Option<String>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        for line_res in reader.lines() {
            let line = line_res?;
            if let Some(rest) = line.strip_prefix(&format!("{}=", key)) {
                // Strip optional surrounding double quotes
                let value = rest.trim();
                let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
                return Ok(Some(value.to_string()));
            }
        }
        Ok(None)
    }

    /// Write a KEY="value" line, preserving other lines, removing any existing entries for the key.
    pub fn write_var(&self, key: &str, value: &str) -> Result<()> {
        ensure_parent_dir(&self.path)?;
        let prefix = format!("{}=", key);
        let mut lines = if self.path.exists() {
            let file = File::open(&self.path)?;
            BufReader::new(file)
                .lines()
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };
        // Remove existing entries for the key
        lines.retain(|l| !l.starts_with(&prefix));
        // Append new line
        lines.push(format!("{}=\"{}\"", key, value));
        self.write_lines_atomic(&lines)
    }

    /// Remove a KEY line entirely.
    pub fn remove_var(&self, key: &str) -> Result<()> {
        if !self.path.exists() {
            return Ok(());
        }
        let prefix = format!("{}=", key);
        let file = File::open(&self.path)?;
        let lines: Vec<String> = BufReader::new(file)
            .lines()
            .collect::<Result<Vec<_>, _>>()?;
        let orig_len = lines.len();
        let filtered: Vec<String> = lines
            .into_iter()
            .filter(|l| !l.starts_with(&prefix))
            .collect();
        if filtered.len() == orig_len {
            return Ok(());
        }
        self.write_lines_atomic(&filtered)
    }

    fn write_lines_atomic(&self, lines: &[String]) -> Result<()> {
        atomic_write(&self.path, |tmp_file| {
            for l in lines {
                writeln!(tmp_file, "{}", l)?;
            }
            Ok(())
        })
    }

    /// Read all KEY="value" pairs into a BTreeMap.
    pub fn read_all(&self) -> Result<BTreeMap<String, String>> {
        let mut map = BTreeMap::new();
        if !self.path.exists() {
            return Ok(map);
        }
        let file = File::open(&self.path)?;
        for line_res in BufReader::new(file).lines() {
            let line = line_res?;
            if let Some(idx) = line.find('=') {
                let key = &line[..idx];
                let mut val = line[idx + 1..].trim();
                if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
                    val = &val[1..val.len() - 1];
                }
                map.insert(key.to_string(), val.to_string());
            }
        }
        Ok(map)
    }
}

/// High‑level settings stored in a StateFile.
#[derive(Debug, Clone)]
pub struct Settings {
    state: StateFile,
}

impl Settings {
    /// Resolve default settings file path.
    pub fn default_path() -> Result<PathBuf> {
        resolve_state_path(
            &["BAB_SETTINGS_FILE", "VPSKIT_SETTINGS_FILE", "SETTINGS_FILE"],
            "credentials.enc",
        )
    }

    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Settings {
            state: StateFile::new(path),
        }
    }

    pub fn load_default() -> Result<Self> {
        let path = Self::default_path()?;
        let settings = Self::new(path);
        settings.auto_save_env_keys()?;
        Ok(settings)
    }

    pub fn path(&self) -> &Path {
        &self.state.path
    }

    pub fn key_file_path(&self) -> PathBuf {
        if let Some(p) = non_empty_env("BAB_MASTER_KEY_FILE") {
            return PathBuf::from(p);
        }
        if let Some(parent) = self
            .state
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            return parent.join("master.key");
        }
        default_config_dir()
            .map(|d| d.join("master.key"))
            .unwrap_or_else(|_| PathBuf::from("master.key"))
    }

    fn read_master_key_file(key_path: &Path) -> Result<[u8; MASTER_KEY_LEN]> {
        let raw = fs::read_to_string(key_path).map_err(|e| {
            anyhow!(
                "Failed to read master key file {}: {}",
                key_path.display(),
                e
            )
        })?;
        let decoded = BASE64_STANDARD.decode(raw.trim()).map_err(|e| {
            anyhow!(
                "Invalid base64 in master key file {}: {}",
                key_path.display(),
                e
            )
        })?;
        if decoded.len() != MASTER_KEY_LEN {
            return Err(anyhow!(
                "Master key file {} has invalid length {} (expected {})",
                key_path.display(),
                decoded.len(),
                MASTER_KEY_LEN
            ));
        }
        let mut key = [0u8; MASTER_KEY_LEN];
        key.copy_from_slice(&decoded);
        Ok(key)
    }

    fn load_master_key(&self, create_if_missing: bool) -> Result<[u8; MASTER_KEY_LEN]> {
        if let Some(passphrase) = non_empty_env("BAB_ENCRYPTION_KEY") {
            let d = digest(&SHA256, passphrase.as_bytes());
            let mut key = [0u8; MASTER_KEY_LEN];
            key.copy_from_slice(d.as_ref());
            return Ok(key);
        }

        let _guard = MASTER_KEY_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| anyhow!("Master key mutex poisoned"))?;

        let key_path = self.key_file_path();
        if key_path.exists() {
            return Self::read_master_key_file(&key_path);
        }
        if !create_if_missing {
            return Err(anyhow!(
                "Master key file {} does not exist",
                key_path.display()
            ));
        }

        if let Some(parent) = key_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
                #[cfg(unix)]
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }

        let rng = SystemRandom::new();
        let mut key = [0u8; MASTER_KEY_LEN];
        rng.fill(&mut key)
            .map_err(|_| anyhow!("Failed to generate master encryption key"))?;
        let encoded = BASE64_STANDARD.encode(key);

        let parent = key_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let pid = std::process::id();
        let seq = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path = parent.join(format!(".master.key.tmp.{}.{}", pid, seq));

        let write_res = (|| -> Result<bool> {
            let mut tmp_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?;
            writeln!(tmp_file, "{}", encoded)?;
            tmp_file.sync_all()?;
            drop(tmp_file);
            #[cfg(unix)]
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
            match fs::hard_link(&tmp_path, &key_path) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(false),
                Err(e) => Err(e.into()),
            }
        })();
        let _ = fs::remove_file(&tmp_path);

        match write_res {
            Ok(true) => Ok(key),
            Ok(false) => Self::read_master_key_file(&key_path),
            Err(e) => Err(e),
        }
    }

    fn open(&self, key: &str, raw: &str) -> Result<String> {
        let Some(b64) = raw.strip_prefix(ENC_V1_PREFIX) else {
            // Backward compatibility for unprefixed legacy plaintext entries
            return Ok(raw.to_string());
        };
        let bytes = BASE64_STANDARD.decode(b64).map_err(|e| {
            anyhow!("Corrupt encrypted value for '{}': invalid base64: {}", key, e)
        })?;
        if bytes.len() < NONCE_LEN + CHACHA20_POLY1305.tag_len() {
            return Err(anyhow!(
                "Corrupt encrypted value for '{}': ciphertext too short",
                key
            ));
        }
        let (nonce_bytes, ciphertext) = bytes.split_at(NONCE_LEN);
        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_arr);
        let key_bytes = self.load_master_key(false)?;
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| anyhow!("Invalid encryption key for '{}'", key))?;
        let opening_key = LessSafeKey::new(unbound);
        let mut in_out = ciphertext.to_vec();
        let plaintext = opening_key
            .open_in_place(nonce, Aad::from(key.as_bytes()), &mut in_out)
            .map_err(|_| {
                anyhow!(
                    "Failed to decrypt setting '{}' (wrong key or tampered ciphertext)",
                    key
                )
            })?;
        String::from_utf8(plaintext.to_vec()).map_err(|e| {
            anyhow!("Decrypted value for '{}' is not valid UTF-8: {}", key, e)
        })
    }

    fn seal(&self, key: &str, value: &str) -> Result<String> {
        let key_bytes = self.load_master_key(true)?;
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| anyhow!("Invalid encryption key for '{}'", key))?;
        let sealing_key = LessSafeKey::new(unbound);

        let rng = SystemRandom::new();
        let mut nonce_arr = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_arr)
            .map_err(|_| anyhow!("Failed to generate random nonce"))?;
        let nonce = Nonce::assume_unique_for_key(nonce_arr);

        let mut in_out = value.as_bytes().to_vec();
        sealing_key
            .seal_in_place_append_tag(nonce, Aad::from(key.as_bytes()), &mut in_out)
            .map_err(|_| anyhow!("Failed to encrypt setting '{}'", key))?;

        let mut payload = Vec::with_capacity(NONCE_LEN + in_out.len());
        payload.extend_from_slice(&nonce_arr);
        payload.extend_from_slice(&in_out);
        Ok(format!("{}{}", ENC_V1_PREFIX, BASE64_STANDARD.encode(&payload)))
    }

    /// Get a variable, preferring environment variable if set and non‑empty.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        if let Some(val) = non_empty_env(key) {
            return Ok(Some(val));
        }
        let Some(raw) = self.state.read_var(key)? else {
            return Ok(None);
        };
        self.open(key, &raw).map(Some)
    }

    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        let encoded = self.seal(key, value)?;
        self.state.write_var(key, &encoded)
    }

    /// Remove a variable from `credentials.enc` atomically, preserving other keys.
    pub fn remove(&self, key: &str) -> Result<()> {
        self.state.remove_var(key)
    }

    /// Persist any non-empty API key environment variables into `credentials.enc`
    /// using ChaCha20-Poly1305 encryption, returning the number of keys written.
    pub fn auto_save_env_keys(&self) -> Result<usize> {
        let mut saved = 0usize;
        for key in API_KEY_ENV_NAMES {
            let Some(env_val) = non_empty_env(key) else {
                continue;
            };
            let already_encrypted_match = match self.state.read_var(key)? {
                Some(raw) if raw.starts_with(ENC_V1_PREFIX) => {
                    matches!(self.open(key, &raw), Ok(ref stored) if stored == &env_val)
                }
                _ => false,
            };
            if !already_encrypted_match {
                self.set(key, &env_val)?;
                saved += 1;
            }
        }
        Ok(saved)
    }

    // Convenience methods for known keys
    pub fn tailscale_api_key(&self) -> Result<Option<String>> {
        self.get("TAILSCALE_API_KEY")
    }
    pub fn set_tailscale_api_key(&self, v: &str) -> Result<()> {
        self.set("TAILSCALE_API_KEY", v)
    }
    pub fn vultr_api_key(&self) -> Result<Option<String>> {
        self.get("VULTR_API_KEY")
    }
    pub fn set_vultr_api_key(&self, v: &str) -> Result<()> {
        self.set("VULTR_API_KEY", v)
    }
    pub fn upcloud_api_token(&self) -> Result<Option<String>> {
        self.get("UPCLOUD_API_TOKEN")
    }
    pub fn set_upcloud_api_token(&self, v: &str) -> Result<()> {
        self.set("UPCLOUD_API_TOKEN", v)
    }
    pub fn linode_api_token(&self) -> Result<Option<String>> {
        self.get("LINODE_API_TOKEN")
    }
    pub fn set_linode_api_token(&self, v: &str) -> Result<()> {
        self.set("LINODE_API_TOKEN", v)
    }
    pub fn cloudflare_api_token(&self) -> Result<Option<String>> {
        self.get("CLOUDFLARE_API_TOKEN")
    }
    pub fn set_cloudflare_api_token(&self, v: &str) -> Result<()> {
        self.set("CLOUDFLARE_API_TOKEN", v)
    }
    pub fn cloudflare_account_id(&self) -> Result<Option<String>> {
        self.get("CLOUDFLARE_ACCOUNT_ID")
    }
    pub fn set_cloudflare_account_id(&self, v: &str) -> Result<()> {
        self.set("CLOUDFLARE_ACCOUNT_ID", v)
    }
    pub fn github_token(&self) -> Result<Option<String>> {
        self.get("GITHUB_TOKEN")
    }
    pub fn set_github_token(&self, v: &str) -> Result<()> {
        self.set("GITHUB_TOKEN", v)
    }

    /// Record the sudo password encrypted in `credentials.enc` for the global
    /// fallback key and any non-empty instance identifiers (ID, hostname, IP).
    pub fn record_instance_password(
        &self,
        instance_id: Option<&str>,
        hostname: Option<&str>,
        public_ip: Option<&str>,
        password: &str,
    ) -> Result<()> {
        let pw = password.trim();
        if pw.is_empty() {
            return Ok(());
        }
        self.set("SUDO_PASSWORD", pw)?;
        if let Some(id) = instance_id.and_then(sanitize_box_key_part) {
            self.set(&format!("BOX_PASS_ID_{}", id), pw)?;
        }
        if let Some(host) = hostname.and_then(sanitize_box_key_part) {
            self.set(&format!("BOX_PASS_HOST_{}", host), pw)?;
        }
        if let Some(ip) = public_ip.and_then(sanitize_box_key_part) {
            self.set(&format!("BOX_PASS_IP_{}", ip), pw)?;
        }
        Ok(())
    }

    /// Look up a previously recorded encrypted per-box sudo password, checking
    /// instance ID, then public IP, then hostname.
    pub fn lookup_instance_password(
        &self,
        instance_id: Option<&str>,
        hostname: Option<&str>,
        public_ip: Option<&str>,
    ) -> Result<Option<String>> {
        let candidates = [
            instance_id
                .and_then(sanitize_box_key_part)
                .map(|id| format!("BOX_PASS_ID_{}", id)),
            public_ip
                .and_then(sanitize_box_key_part)
                .map(|ip| format!("BOX_PASS_IP_{}", ip)),
            hostname
                .and_then(sanitize_box_key_part)
                .map(|host| format!("BOX_PASS_HOST_{}", host)),
        ];
        for key in candidates.into_iter().flatten() {
            if let Some(val) = self.get(&key)? {
                if !val.trim().is_empty() {
                    return Ok(Some(val));
                }
            }
        }
        Ok(None)
    }
}

/// Session‑specific state.
#[derive(Debug, Clone)]
pub struct SessionState {
    state: StateFile,
}

impl SessionState {
    pub fn default_path() -> Result<PathBuf> {
        resolve_state_path(
            &[
                "BAB_STATE_FILE",
                "BAB_LOCAL_STATE",
                "VPSKIT_STATE_FILE",
                "VPSKIT_LOCAL_STATE",
                "LOCAL_STATE",
            ],
            "state.conf",
        )
    }

    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        SessionState {
            state: StateFile::new(path),
        }
    }

    pub fn load_default() -> Result<Self> {
        let path = Self::default_path()?;
        Ok(Self::new(path))
    }

    // Typed getters/setters using underlying StateFile
    fn get_var(&self, key: &str) -> Result<Option<String>> {
        self.state.read_var(key)
    }
    fn set_var(&self, key: &str, value: &str) -> Result<()> {
        self.state.write_var(key, value)
    }
    fn remove_var(&self, key: &str) -> Result<()> {
        self.state.remove_var(key)
    }

    pub fn vps_ip(&self) -> Result<Option<String>> {
        self.get_var("VPS_IP")
    }
    pub fn set_vps_ip(&self, v: &str) -> Result<()> {
        self.set_var("VPS_IP", v)
    }
    pub fn ssh_key(&self) -> Result<Option<String>> {
        self.get_var("SSH_KEY")
    }
    pub fn set_ssh_key(&self, v: &str) -> Result<()> {
        self.set_var("SSH_KEY", v)
    }
    pub fn username(&self) -> Result<Option<String>> {
        self.get_var("USERNAME")
    }
    pub fn set_username(&self, v: &str) -> Result<()> {
        self.set_var("USERNAME", v)
    }
    pub fn transport_mode(&self) -> Result<Option<String>> {
        self.get_var("TRANSPORT_MODE")
    }
    pub fn set_transport_mode(&self, v: &str) -> Result<()> {
        self.set_var("TRANSPORT_MODE", v)
    }
    pub fn vps_provider(&self) -> Result<Option<String>> {
        self.get_var("VPS_PROVIDER")
    }
    pub fn set_vps_provider(&self, v: &str) -> Result<()> {
        self.set_var("VPS_PROVIDER", v)
    }
    pub fn vps_instance_id(&self) -> Result<Option<String>> {
        self.get_var("VPS_INSTANCE_ID")
    }
    pub fn set_vps_instance_id(&self, v: &str) -> Result<()> {
        self.set_var("VPS_INSTANCE_ID", v)
    }
    pub fn tailscale_hostname(&self) -> Result<Option<String>> {
        self.get_var("TAILSCALE_HOSTNAME")
    }
    pub fn set_tailscale_hostname(&self, v: &str) -> Result<()> {
        self.set_var("TAILSCALE_HOSTNAME", v)
    }
    pub fn server_role(&self) -> Result<Option<String>> {
        self.get_var("SERVER_ROLE")
    }
    pub fn set_server_role(&self, v: &str) -> Result<()> {
        self.set_var("SERVER_ROLE", v)
    }
    pub fn vps_region(&self) -> Result<Option<String>> {
        self.get_var("VPS_REGION")
    }
    pub fn set_vps_region(&self, v: &str) -> Result<()> {
        self.set_var("VPS_REGION", v)
    }
    pub fn vps_plan(&self) -> Result<Option<String>> {
        self.get_var("VPS_PLAN")
    }
    pub fn set_vps_plan(&self, v: &str) -> Result<()> {
        self.set_var("VPS_PLAN", v)
    }
    pub fn vps_image(&self) -> Result<Option<String>> {
        self.get_var("VPS_IMAGE")
    }
    pub fn set_vps_image(&self, v: &str) -> Result<()> {
        self.set_var("VPS_IMAGE", v)
    }
    pub fn public_ip(&self) -> Result<Option<String>> {
        self.get_var("PUBLIC_IP")
    }
    pub fn set_public_ip(&self, v: &str) -> Result<()> {
        self.set_var("PUBLIC_IP", v)
    }
    pub fn tailscale_ip(&self) -> Result<Option<String>> {
        self.get_var("TAILSCALE_IP")
    }
    pub fn set_tailscale_ip(&self, v: &str) -> Result<()> {
        self.set_var("TAILSCALE_IP", v)
    }
    pub fn cf_zone(&self) -> Result<Option<String>> {
        self.get_var("CF_ZONE")
    }
    pub fn set_cf_zone(&self, v: &str) -> Result<()> {
        self.set_var("CF_ZONE", v)
    }
    pub fn cf_record(&self) -> Result<Option<String>> {
        self.get_var("CF_RECORD")
    }
    pub fn set_cf_record(&self, v: &str) -> Result<()> {
        self.set_var("CF_RECORD", v)
    }
    pub fn cf_proxied(&self) -> Result<Option<String>> {
        self.get_var("CF_PROXIED")
    }
    pub fn set_cf_proxied(&self, v: &str) -> Result<()> {
        self.set_var("CF_PROXIED", v)
    }
    pub fn cf_target(&self) -> Result<Option<String>> {
        self.get_var("CF_TARGET")
    }
    pub fn set_cf_target(&self, v: &str) -> Result<()> {
        self.set_var("CF_TARGET", v)
    }
    pub fn cf_enabled(&self) -> Result<Option<String>> {
        self.get_var("CF_ENABLED")
    }
    pub fn set_cf_enabled(&self, v: &str) -> Result<()> {
        self.set_var("CF_ENABLED", v)
    }
    pub fn github_repo(&self) -> Result<Option<String>> {
        self.get_var("GITHUB_REPO")
    }
    pub fn set_github_repo(&self, v: &str) -> Result<()> {
        self.set_var("GITHUB_REPO", v)
    }
    pub fn github_branch(&self) -> Result<Option<String>> {
        self.get_var("GITHUB_BRANCH")
    }
    pub fn set_github_branch(&self, v: &str) -> Result<()> {
        self.set_var("GITHUB_BRANCH", v)
    }
    pub fn github_deploy_path(&self) -> Result<Option<String>> {
        self.get_var("GITHUB_DEPLOY_PATH")
    }
    pub fn set_github_deploy_path(&self, v: &str) -> Result<()> {
        self.set_var("GITHUB_DEPLOY_PATH", v)
    }
    pub fn github_deploy_cmd(&self) -> Result<Option<String>> {
        self.get_var("GITHUB_DEPLOY_CMD")
    }
    pub fn set_github_deploy_cmd(&self, v: &str) -> Result<()> {
        self.set_var("GITHUB_DEPLOY_CMD", v)
    }
    pub fn github_enabled(&self) -> Result<Option<String>> {
        self.get_var("GITHUB_ENABLED")
    }
    pub fn set_github_enabled(&self, v: &str) -> Result<()> {
        self.set_var("GITHUB_ENABLED", v)
    }
    pub fn sudo_nopasswd(&self) -> Result<Option<String>> {
        self.get_var("SUDO_NOPASSWD")
    }
    pub fn set_sudo_nopasswd(&self, v: &str) -> Result<()> {
        self.set_var("SUDO_NOPASSWD", v)
    }
    pub fn sudo_password(&self) -> Result<Option<String>> {
        self.get_var("SUDO_PASSWORD")
    }
    pub fn set_sudo_password(&self, v: &str) -> Result<()> {
        self.set_var("SUDO_PASSWORD", v)
    }

    pub fn save_session(&self, data: &SessionData) -> Result<()> {
        // Helper to write or remove based on Option
        macro_rules! set_opt {
            ($key:expr, $opt:expr) => {
                if let Some(ref v) = $opt {
                    self.set_var($key, v)?;
                } else {
                    self.remove_var($key)?;
                }
            };
        }
        set_opt!("VPS_IP", data.vps_ip);
        set_opt!("SSH_KEY", data.ssh_key);
        set_opt!("USERNAME", data.username);
        set_opt!("TRANSPORT_MODE", data.transport_mode);
        set_opt!("VPS_PROVIDER", data.vps_provider);
        set_opt!("VPS_INSTANCE_ID", data.vps_instance_id);
        set_opt!("TAILSCALE_HOSTNAME", data.tailscale_hostname);
        set_opt!("SERVER_ROLE", data.server_role);
        set_opt!("VPS_REGION", data.vps_region);
        set_opt!("VPS_PLAN", data.vps_plan);
        set_opt!("VPS_IMAGE", data.vps_image);
        set_opt!("PUBLIC_IP", data.public_ip);
        set_opt!("TAILSCALE_IP", data.tailscale_ip);
        set_opt!("CF_ZONE", data.cf_zone);
        set_opt!("CF_RECORD", data.cf_record);
        set_opt!("CF_PROXIED", data.cf_proxied);
        set_opt!("CF_TARGET", data.cf_target);
        set_opt!("CF_ENABLED", data.cf_enabled);
        set_opt!("GITHUB_REPO", data.github_repo);
        set_opt!("GITHUB_BRANCH", data.github_branch);
        set_opt!("GITHUB_DEPLOY_PATH", data.github_deploy_path);
        set_opt!("GITHUB_DEPLOY_CMD", data.github_deploy_cmd);
        set_opt!("GITHUB_ENABLED", data.github_enabled);
        match data.sudo_nopasswd.as_deref() {
            Some(v) if !v.trim().is_empty() => self.set_var("SUDO_NOPASSWD", v)?,
            _ => self.remove_var("SUDO_NOPASSWD")?,
        }
        match data.sudo_password.as_deref() {
            Some(v) if !v.trim().is_empty() => self.set_var("SUDO_PASSWORD", v)?,
            _ => self.remove_var("SUDO_PASSWORD")?,
        }
        Ok(())
    }

    pub fn load_session(&self) -> Result<SessionData> {
        Ok(SessionData {
            vps_ip: self.vps_ip()?,
            ssh_key: self.ssh_key()?,
            username: self.username()?,
            transport_mode: self.transport_mode()?,
            vps_provider: self.vps_provider()?,
            vps_instance_id: self.vps_instance_id()?,
            tailscale_hostname: self.tailscale_hostname()?,
            server_role: self.server_role()?,
            vps_region: self.vps_region()?,
            vps_plan: self.vps_plan()?,
            vps_image: self.vps_image()?,
            public_ip: self.public_ip()?,
            tailscale_ip: self.tailscale_ip()?,
            cf_zone: self.cf_zone()?,
            cf_record: self.cf_record()?,
            cf_proxied: self.cf_proxied()?,
            cf_target: self.cf_target()?,
            cf_enabled: self.cf_enabled()?,
            github_repo: self.github_repo()?,
            github_branch: self.github_branch()?,
            github_deploy_path: self.github_deploy_path()?,
            github_deploy_cmd: self.github_deploy_cmd()?,
            github_enabled: self.github_enabled()?,
            sudo_nopasswd: self.sudo_nopasswd()?,
            sudo_password: self.sudo_password()?,
        })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SessionData {
    pub vps_ip: Option<String>,
    pub ssh_key: Option<String>,
    pub username: Option<String>,
    pub transport_mode: Option<String>,
    pub vps_provider: Option<String>,
    pub vps_instance_id: Option<String>,
    pub tailscale_hostname: Option<String>,
    pub server_role: Option<String>,
    pub vps_region: Option<String>,
    pub vps_plan: Option<String>,
    pub vps_image: Option<String>,
    pub public_ip: Option<String>,
    pub tailscale_ip: Option<String>,
    pub cf_zone: Option<String>,
    pub cf_record: Option<String>,
    pub cf_proxied: Option<String>,
    pub cf_target: Option<String>,
    pub cf_enabled: Option<String>,
    pub github_repo: Option<String>,
    pub github_branch: Option<String>,
    pub github_deploy_path: Option<String>,
    pub github_deploy_cmd: Option<String>,
    pub github_enabled: Option<String>,
    pub sudo_nopasswd: Option<String>,
    pub sudo_password: Option<String>,
}

/// Persistent append-only log store with a maximum retained byte cap.
#[derive(Debug, Clone)]
pub struct LogStore {
    path: PathBuf,
    max_bytes: u64,
}

impl LogStore {
    /// Create a [`LogStore`] at `path` using [`MAX_LOG_FILE_BYTES`].
    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Self::with_max_bytes(path, MAX_LOG_FILE_BYTES)
    }

    /// Create a [`LogStore`] at `path` with a custom `max_bytes` cap.
    pub fn with_max_bytes<P: Into<PathBuf>>(path: P, max_bytes: u64) -> Self {
        Self {
            path: path.into(),
            max_bytes,
        }
    }

    /// Resolve the default log file path (`BAB_LOG_FILE` or `<config_dir>/bab.log`).
    pub fn default_path() -> Result<PathBuf> {
        resolve_state_path(&["BAB_LOG_FILE"], "bab.log")
    }

    /// Open a [`LogStore`] at [`LogStore::default_path`].
    pub fn load_default() -> Result<Self> {
        Ok(Self::new(Self::default_path()?))
    }

    /// Return the path to the backing log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the configured maximum retained byte size.
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Return the current file size in bytes, or `0` if the file does not exist.
    pub fn file_size(&self) -> u64 {
        fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }

    /// Append a single line to the log file, enforcing `max_bytes`.
    pub fn append_line(&self, line: &str) -> Result<()> {
        self.append_lines_impl(std::iter::once(line))
    }

    /// Append lines to the log file, enforcing `max_bytes`. Empty slices are a no-op.
    pub fn append_lines(&self, lines: &[String]) -> Result<()> {
        if lines.is_empty() {
            return Ok(());
        }
        self.append_lines_impl(lines.iter().map(String::as_str))
    }

    fn append_lines_impl<'a, I>(&self, lines: I) -> Result<()>
    where
        I: IntoIterator<Item = &'a str>,
    {
        ensure_parent_dir(&self.path)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.path)?;
        for line in lines {
            let clean = line.trim_end_matches(['\r', '\n']);
            writeln!(file, "{}", clean)?;
        }
        file.flush()?;
        drop(file);
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        self.enforce_max_bytes()
    }

    fn enforce_max_bytes(&self) -> Result<()> {
        if self.file_size() <= self.max_bytes {
            return Ok(());
        }
        if self.max_bytes == 0 {
            return atomic_write(&self.path, |_| Ok(()));
        }
        let data = fs::read(&self.path)?;
        let max_bytes = self.max_bytes as usize;
        if data.len() <= max_bytes {
            return Ok(());
        }
        let start = data.len() - max_bytes;
        let cut = if start > 0 && data[start - 1] == b'\n' {
            start
        } else {
            match data[start..].iter().position(|&b| b == b'\n') {
                Some(nl_pos) if start + nl_pos + 1 < data.len() => start + nl_pos + 1,
                _ => {
                    let mut idx = start;
                    while idx < data.len() && (data[idx] & 0b1100_0000) == 0b1000_0000 {
                        idx += 1;
                    }
                    idx
                }
            }
        };
        atomic_write(&self.path, |tmp| {
            tmp.write_all(&data[cut..])?;
            Ok(())
        })
    }

    /// Append lines prefixed with `format_utc_timestamp()` (except empty lines).
    pub fn append_timestamped_lines(&self, lines: &[String]) -> Result<()> {
        if lines.is_empty() {
            return Ok(());
        }
        let ts = format_utc_timestamp();
        let stamped: Vec<String> = lines
            .iter()
            .map(|line| {
                let clean = line.trim_end_matches(['\r', '\n']);
                if clean.is_empty() {
                    String::new()
                } else {
                    format!("{} {}", ts, clean)
                }
            })
            .collect();
        self.append_lines(&stamped)
    }

    /// Read all lines from the log file, returning an empty vector if missing.
    pub fn read_lines(&self) -> Result<Vec<String>> {
        match fs::read(&self.path) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                Ok(text.lines().map(ToString::to_string).collect())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Atomically replace the log file with an empty `0o600` file (creating parent `0o700` dir if missing).
    pub fn clear(&self) -> Result<()> {
        atomic_write(&self.path, |_| Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::thread;
    use tempfile::{tempdir, NamedTempFile};

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

    #[test]
    fn round_trip_read_write() -> Result<()> {
        let tmp = NamedTempFile::new()?;
        let sf = StateFile::new(tmp.path());
        sf.write_var("FOO", "bar")?;
        assert_eq!(sf.read_var("FOO")?, Some("bar".to_string()));
        Ok(())
    }

    #[test]
    fn line_preservation_and_remove() -> Result<()> {
        let tmp = NamedTempFile::new()?;
        {
            let mut f = File::create(tmp.path())?;
            writeln!(f, "EXISTING=\"yes\"")?;
        }
        let sf = StateFile::new(tmp.path());
        sf.write_var("NEW", "val")?;
        let content = fs::read_to_string(tmp.path())?;
        assert!(content.contains("EXISTING=\"yes\""));
        assert!(content.contains("NEW=\"val\""));

        sf.remove_var("EXISTING")?;
        assert_eq!(sf.read_var("EXISTING")?, None);
        assert_eq!(sf.read_var("NEW")?, Some("val".to_string()));
        Ok(())
    }

    #[test]
    fn env_override_priority() -> Result<()> {
        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&["VPSKIT_TEST_ENV_KEY"]);
        env::set_var("VPSKIT_TEST_ENV_KEY", "envval");

        let tmp = NamedTempFile::new()?;
        let settings = Settings::new(tmp.path());
        settings.state.write_var("VPSKIT_TEST_ENV_KEY", "fileval")?;
        assert_eq!(
            settings.get("VPSKIT_TEST_ENV_KEY")?,
            Some("envval".to_string())
        );
        env::set_var("VPSKIT_TEST_ENV_KEY", "");
        assert_eq!(
            settings.get("VPSKIT_TEST_ENV_KEY")?,
            Some("fileval".to_string())
        );
        env::remove_var("VPSKIT_TEST_ENV_KEY");
        assert_eq!(
            settings.get("VPSKIT_TEST_ENV_KEY")?,
            Some("fileval".to_string())
        );
        Ok(())
    }

    #[test]
    fn default_path_resolution() -> Result<()> {
        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "BAB_SETTINGS_FILE",
            "VPSKIT_SETTINGS_FILE",
            "SETTINGS_FILE",
            "BAB_STATE_FILE",
            "BAB_LOCAL_STATE",
            "VPSKIT_STATE_FILE",
            "VPSKIT_LOCAL_STATE",
            "LOCAL_STATE",
            "BAB_CONFIG_DIR",
            "BAB_SSH_DIR",
            "VPSKIT_SSH_DIR",
            "SSH_DIR",
            "HOME",
        ]);
        for k in [
            "BAB_SETTINGS_FILE",
            "VPSKIT_SETTINGS_FILE",
            "SETTINGS_FILE",
            "BAB_STATE_FILE",
            "BAB_LOCAL_STATE",
            "VPSKIT_STATE_FILE",
            "VPSKIT_LOCAL_STATE",
            "LOCAL_STATE",
            "BAB_CONFIG_DIR",
            "BAB_SSH_DIR",
            "VPSKIT_SSH_DIR",
            "SSH_DIR",
        ] {
            env::remove_var(k);
        }

        let tmp = tempdir()?;
        let fake_home = tmp.path().join("home");
        fs::create_dir_all(&fake_home)?;
        env::set_var("HOME", &fake_home);

        let expected_cfg_dir = fake_home.join(".config").join("bab");
        assert_eq!(default_config_dir()?, expected_cfg_dir);
        assert!(expected_cfg_dir.is_dir());
        assert_eq!(
            fs::metadata(&expected_cfg_dir)?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            Settings::default_path()?,
            expected_cfg_dir.join("credentials.enc")
        );
        assert_eq!(
            SessionState::default_path()?,
            expected_cfg_dir.join("state.conf")
        );

        let custom_ssh = tmp.path().join("custom-ssh");
        env::set_var("SSH_DIR", &custom_ssh);
        assert_eq!(
            Settings::default_path()?,
            custom_ssh.join("credentials.enc")
        );
        assert_eq!(
            SessionState::default_path()?,
            custom_ssh.join("state.conf")
        );
        assert_eq!(
            fs::metadata(&custom_ssh)?.permissions().mode() & 0o777,
            0o700
        );

        let bab_ssh = tmp.path().join("bab-ssh");
        env::set_var("BAB_SSH_DIR", &bab_ssh);
        assert_eq!(
            Settings::default_path()?,
            bab_ssh.join("credentials.enc")
        );

        let bab_cfg = tmp.path().join("bab-cfg");
        env::set_var("BAB_CONFIG_DIR", &bab_cfg);
        assert_eq!(
            Settings::default_path()?,
            bab_cfg.join("credentials.enc")
        );
        assert_eq!(
            SessionState::default_path()?,
            bab_cfg.join("state.conf")
        );

        env::set_var("BAB_SETTINGS_FILE", "/tmp/explicit-settings");
        env::set_var("BAB_STATE_FILE", "/tmp/explicit-state");
        assert_eq!(
            Settings::default_path()?,
            PathBuf::from("/tmp/explicit-settings")
        );
        assert_eq!(
            SessionState::default_path()?,
            PathBuf::from("/tmp/explicit-state")
        );
        Ok(())
    }

    #[test]
    fn permissions_on_write() -> Result<()> {
        let tmp = NamedTempFile::new()?;
        let sf = StateFile::new(tmp.path());
        sf.write_var("SEC", "secret")?;
        let meta = fs::metadata(tmp.path())?;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn bash_compatibility() -> Result<()> {
        let tmp = NamedTempFile::new()?;
        let sf = StateFile::new(tmp.path());
        sf.write_var("COMPLEX", "a b c")?;
        let raw = fs::read_to_string(tmp.path())?;
        assert!(raw.contains("COMPLEX=\"a b c\""));
        Ok(())
    }

    #[test]
    fn settings_aead_encrypts_at_rest_and_enforces_permissions() -> Result<()> {
        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "BAB_ENCRYPTION_KEY",
            "BAB_MASTER_KEY_FILE",
            "CLOUDFLARE_API_TOKEN",
            "CLOUDFLARE_ACCOUNT_ID",
            "GITHUB_TOKEN",
        ]);
        env::remove_var("BAB_ENCRYPTION_KEY");
        env::remove_var("BAB_MASTER_KEY_FILE");
        env::remove_var("CLOUDFLARE_API_TOKEN");
        env::remove_var("CLOUDFLARE_ACCOUNT_ID");
        env::remove_var("GITHUB_TOKEN");

        let dir = tempdir()?;
        let creds_path = dir.path().join("credentials.enc");
        let settings = Settings::new(&creds_path);
        assert_eq!(settings.path(), creds_path.as_path());
        assert_eq!(settings.key_file_path(), dir.path().join("master.key"));

        settings.set_cloudflare_api_token("cf-secret-token-123")?;
        settings.set_cloudflare_account_id("cf-acct-999")?;
        settings.set_github_token("ghp_secret_token_456")?;

        // Raw file must store enc:v1: ciphertext, never plaintext secrets
        let raw = fs::read_to_string(&creds_path)?;
        assert!(raw.contains("CLOUDFLARE_API_TOKEN=\"enc:v1:"));
        assert!(raw.contains("CLOUDFLARE_ACCOUNT_ID=\"enc:v1:"));
        assert!(raw.contains("GITHUB_TOKEN=\"enc:v1:"));
        assert!(!raw.contains("cf-secret-token-123"));
        assert!(!raw.contains("cf-acct-999"));
        assert!(!raw.contains("ghp_secret_token_456"));

        // Permissions on credentials.enc and master.key must be 0o600
        assert_eq!(fs::metadata(&creds_path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(settings.key_file_path())?.permissions().mode() & 0o777,
            0o600
        );

        // Decryption round-trip
        assert_eq!(
            settings.cloudflare_api_token()?,
            Some("cf-secret-token-123".to_string())
        );
        assert_eq!(
            settings.cloudflare_account_id()?,
            Some("cf-acct-999".to_string())
        );
        assert_eq!(
            settings.github_token()?,
            Some("ghp_secret_token_456".to_string())
        );
        Ok(())
    }

    #[test]
    fn settings_rejects_tampered_ciphertext_and_wrong_key() -> Result<()> {
        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "BAB_ENCRYPTION_KEY",
            "BAB_MASTER_KEY_FILE",
            "VULTR_API_KEY",
        ]);
        env::remove_var("BAB_ENCRYPTION_KEY");
        env::remove_var("BAB_MASTER_KEY_FILE");
        env::remove_var("VULTR_API_KEY");

        let dir = tempdir()?;
        let creds_path = dir.path().join("credentials.enc");
        let settings = Settings::new(&creds_path);
        settings.set_vultr_api_key("vultr-top-secret")?;

        // Tamper with ciphertext byte
        let encrypted = settings.state.read_var("VULTR_API_KEY")?.unwrap();
        let b64 = encrypted.strip_prefix(ENC_V1_PREFIX).unwrap();
        let mut raw_bytes = BASE64_STANDARD.decode(b64)?;
        let last = raw_bytes.len() - 1;
        raw_bytes[last] ^= 0xff;
        let tampered = format!("{}{}", ENC_V1_PREFIX, BASE64_STANDARD.encode(raw_bytes));
        settings.state.write_var("VULTR_API_KEY", &tampered)?;

        let err = settings.vultr_api_key().unwrap_err();
        assert!(err.to_string().contains("Failed to decrypt"));

        // Re-encrypt cleanly, then switch master key -> wrong key must fail
        settings.set_vultr_api_key("vultr-top-secret")?;
        let wrong_key = BASE64_STANDARD.encode([0x42u8; MASTER_KEY_LEN]);
        fs::write(settings.key_file_path(), format!("{}\n", wrong_key))?;
        let err = settings.vultr_api_key().unwrap_err();
        assert!(err.to_string().contains("Failed to decrypt"));
        Ok(())
    }

    #[test]
    fn settings_bab_encryption_key_is_deterministic_and_supports_legacy_plaintext() -> Result<()> {
        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "BAB_ENCRYPTION_KEY",
            "BAB_MASTER_KEY_FILE",
            "TAILSCALE_API_KEY",
            "LINODE_API_TOKEN",
        ]);
        env::remove_var("BAB_MASTER_KEY_FILE");
        env::remove_var("TAILSCALE_API_KEY");
        env::remove_var("LINODE_API_TOKEN");

        let dir = tempdir()?;
        let creds_path = dir.path().join("credentials.enc");
        env::set_var("BAB_ENCRYPTION_KEY", "deterministic-passphrase");

        let s1 = Settings::new(&creds_path);
        s1.set_tailscale_api_key("tskey-auth-abc")?;
        // Should not create master.key when BAB_ENCRYPTION_KEY is used
        assert!(!s1.key_file_path().exists());

        // Separate Settings instance with same BAB_ENCRYPTION_KEY decrypts cleanly
        let s2 = Settings::new(&creds_path);
        assert_eq!(s2.tailscale_api_key()?, Some("tskey-auth-abc".to_string()));

        // Different BAB_ENCRYPTION_KEY fails
        env::set_var("BAB_ENCRYPTION_KEY", "wrong-passphrase");
        assert!(s2.tailscale_api_key().is_err());

        // Legacy unprefixed plaintext remains readable
        s2.state.write_var("LINODE_API_TOKEN", "legacy-linode-plain")?;
        assert_eq!(
            s2.linode_api_token()?,
            Some("legacy-linode-plain".to_string())
        );
        Ok(())
    }

    #[test]
    fn session_save_and_load() -> Result<()> {
        let tmp = NamedTempFile::new()?;
        let ss = SessionState::new(tmp.path());
        let data = SessionData {
            vps_ip: Some("100.64.0.1".to_string()),
            ssh_key: Some("tailscale".to_string()),
            username: Some("deploy".to_string()),
            transport_mode: Some("tailscale".to_string()),
            vps_provider: Some("vultr".to_string()),
            vps_instance_id: Some("inst-1".to_string()),
            tailscale_hostname: Some("vps.ts.net".to_string()),
            server_role: Some("caddy".to_string()),
            vps_region: Some("ewr".to_string()),
            vps_plan: Some("vc2-1c-2gb".to_string()),
            vps_image: Some("2284".to_string()),
            public_ip: Some("203.0.113.10".to_string()),
            tailscale_ip: Some("100.64.0.1".to_string()),
            cf_zone: Some("example.com".to_string()),
            cf_record: Some("@".to_string()),
            cf_proxied: Some("true".to_string()),
            cf_target: Some("203.0.113.10".to_string()),
            cf_enabled: Some("true".to_string()),
            github_repo: Some("owner/repo".to_string()),
            github_branch: Some("main".to_string()),
            github_deploy_path: Some("/home/deploy/apps/repo".to_string()),
            github_deploy_cmd: Some("docker compose up -d".to_string()),
            github_enabled: Some("true".to_string()),
            sudo_nopasswd: Some("true".to_string()),
            sudo_password: Some("Abc123Xyz9".to_string()),
        };
        ss.save_session(&data)?;
        assert_eq!(ss.load_session()?, data);

        // Verify typed setters/getters and None removal
        ss.set_cf_record("api.example.com")?;
        assert_eq!(ss.cf_record()?, Some("api.example.com".to_string()));
        ss.set_cf_enabled("false")?;
        assert_eq!(ss.cf_enabled()?, Some("false".to_string()));
        ss.set_github_enabled("false")?;
        assert_eq!(ss.github_enabled()?, Some("false".to_string()));
        ss.set_sudo_nopasswd("false")?;
        assert_eq!(ss.sudo_nopasswd()?, Some("false".to_string()));
        ss.set_sudo_password("NewPass123")?;
        assert_eq!(ss.sudo_password()?, Some("NewPass123".to_string()));
        let cleared = SessionData {
            cf_record: None,
            cf_enabled: None,
            github_deploy_cmd: None,
            github_enabled: None,
            sudo_nopasswd: None,
            sudo_password: None,
            ..data
        };
        ss.save_session(&cleared)?;
        assert_eq!(ss.load_session()?, cleared);
        Ok(())
    }

    #[test]
    fn session_sudo_nopasswd_round_trip_and_clear() -> Result<()> {
        let tmp = NamedTempFile::new()?;
        let ss = SessionState::new(tmp.path());

        // Initially unset -> None
        assert_eq!(ss.sudo_nopasswd()?, None);
        assert_eq!(ss.load_session()?.sudo_nopasswd, None);

        // Typed setter/getter round-trip
        ss.set_sudo_nopasswd("false")?;
        assert_eq!(ss.sudo_nopasswd()?, Some("false".to_string()));
        assert_eq!(ss.load_session()?.sudo_nopasswd, Some("false".to_string()));

        // save_session / load_session round-trip with "true" and "false"
        let enabled = SessionData {
            sudo_nopasswd: Some("true".to_string()),
            ..SessionData::default()
        };
        ss.save_session(&enabled)?;
        assert_eq!(ss.load_session()?.sudo_nopasswd, Some("true".to_string()));
        assert!(fs::read_to_string(tmp.path())?.contains("SUDO_NOPASSWD=\"true\""));

        let disabled = SessionData {
            sudo_nopasswd: Some("false".to_string()),
            ..SessionData::default()
        };
        ss.save_session(&disabled)?;
        assert_eq!(ss.load_session()?.sudo_nopasswd, Some("false".to_string()));
        assert!(fs::read_to_string(tmp.path())?.contains("SUDO_NOPASSWD=\"false\""));

        // Some("") and whitespace-only values remove the key and load back as None
        let empty = SessionData {
            sudo_nopasswd: Some(String::new()),
            ..SessionData::default()
        };
        ss.save_session(&empty)?;
        assert_eq!(ss.sudo_nopasswd()?, None);
        assert_eq!(ss.load_session()?.sudo_nopasswd, None);
        assert!(!fs::read_to_string(tmp.path())?.contains("SUDO_NOPASSWD="));

        ss.set_sudo_nopasswd("true")?;
        let whitespace = SessionData {
            sudo_nopasswd: Some("   ".to_string()),
            ..SessionData::default()
        };
        ss.save_session(&whitespace)?;
        assert_eq!(ss.sudo_nopasswd()?, None);
        assert_eq!(ss.load_session()?.sudo_nopasswd, None);
        assert!(!fs::read_to_string(tmp.path())?.contains("SUDO_NOPASSWD="));

        // None preserves unset / removes existing key
        ss.set_sudo_nopasswd("false")?;
        let unset = SessionData {
            sudo_nopasswd: None,
            ..SessionData::default()
        };
        ss.save_session(&unset)?;
        assert_eq!(ss.sudo_nopasswd()?, None);
        assert_eq!(ss.load_session()?.sudo_nopasswd, None);
        assert!(!fs::read_to_string(tmp.path())?.contains("SUDO_NOPASSWD="));

        Ok(())
    }

    #[test]
    fn concurrent_atomic_writes_leave_no_temp_files() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("concurrent.state");
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let p = path.clone();
                thread::spawn(move || -> Result<()> {
                    let sf = StateFile::new(p);
                    sf.write_var(&format!("KEY_{}", i), &format!("val_{}", i))
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap()?;
        }
        let meta = fs::metadata(&path)?;
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let leftovers: Vec<_> = fs::read_dir(dir.path())?
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "leftover tmp files: {:?}", leftovers);
        Ok(())
    }

    #[test]
    fn settings_remove_deletes_key_preserving_others() -> Result<()> {
        let _lock = crate::env_lock();
        let mut guard_keys = vec!["BAB_ENCRYPTION_KEY", "BAB_MASTER_KEY_FILE"];
        guard_keys.extend_from_slice(&API_KEY_ENV_NAMES);
        let _guard = EnvGuard::new(&guard_keys);
        for k in &guard_keys {
            env::remove_var(k);
        }

        let dir = tempdir()?;
        let creds_path = dir.path().join("credentials.enc");
        let settings = Settings::new(&creds_path);

        // Removing from a non-existent file is a no-op and does not create the file
        settings.remove("TAILSCALE_API_KEY")?;
        assert!(!creds_path.exists());

        settings.set_tailscale_api_key("tskey-1")?;
        settings.set_vultr_api_key("vultr-2")?;
        settings.set_github_token("ghp-3")?;

        // Removing an absent key is a no-op
        settings.remove("LINODE_API_TOKEN")?;

        // Removing an existing key deletes only that key
        settings.remove("VULTR_API_KEY")?;
        assert_eq!(settings.vultr_api_key()?, None);
        assert_eq!(settings.state.read_var("VULTR_API_KEY")?, None);
        assert_eq!(settings.tailscale_api_key()?, Some("tskey-1".to_string()));
        assert_eq!(settings.github_token()?, Some("ghp-3".to_string()));

        #[cfg(unix)]
        assert_eq!(fs::metadata(&creds_path)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn settings_auto_saves_env_keys_to_encrypted_file() -> Result<()> {
        let _lock = crate::env_lock();
        let mut guard_keys = vec![
            "BAB_SETTINGS_FILE",
            "VPSKIT_SETTINGS_FILE",
            "SETTINGS_FILE",
            "BAB_CONFIG_DIR",
            "BAB_SSH_DIR",
            "VPSKIT_SSH_DIR",
            "SSH_DIR",
            "BAB_MASTER_KEY_FILE",
            "BAB_ENCRYPTION_KEY",
            "HOME",
        ];
        guard_keys.extend_from_slice(&API_KEY_ENV_NAMES);
        let _guard = EnvGuard::new(&guard_keys);
        for k in &guard_keys {
            env::remove_var(k);
        }

        let dir = tempdir()?;
        let cfg_dir = dir.path().join("cfg");
        env::set_var("BAB_CONFIG_DIR", &cfg_dir);

        // No API key env vars (or only empty) must NOT create master.key or credentials.enc
        env::set_var("TAILSCALE_API_KEY", "");
        let settings = Settings::load_default()?;
        let creds_path = cfg_dir.join("credentials.enc");
        let key_path = cfg_dir.join("master.key");
        assert!(!creds_path.exists());
        assert!(!key_path.exists());
        assert_eq!(settings.auto_save_env_keys()?, 0);
        assert!(!creds_path.exists());
        assert!(!key_path.exists());

        // Set env keys and call Settings::load_default() -> auto-saves encrypted
        env::remove_var("TAILSCALE_API_KEY");
        env::set_var("CLOUDFLARE_API_TOKEN", "cf-auto-123");
        env::set_var("CLOUDFLARE_ACCOUNT_ID", "cf-acct-auto-789");
        env::set_var("GITHUB_TOKEN", "ghp-auto-456");

        let settings = Settings::load_default()?;
        assert!(creds_path.exists());
        assert!(key_path.exists());

        #[cfg(unix)]
        {
            assert_eq!(fs::metadata(&cfg_dir)?.permissions().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(&creds_path)?.permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(&key_path)?.permissions().mode() & 0o777, 0o600);
        }

        let raw_first = fs::read_to_string(&creds_path)?;
        assert!(raw_first.contains("CLOUDFLARE_API_TOKEN=\"enc:v1:"));
        assert!(raw_first.contains("CLOUDFLARE_ACCOUNT_ID=\"enc:v1:"));
        assert!(raw_first.contains("GITHUB_TOKEN=\"enc:v1:"));
        assert!(!raw_first.contains("cf-auto-123"));
        assert!(!raw_first.contains("cf-acct-auto-789"));
        assert!(!raw_first.contains("ghp-auto-456"));

        // Idempotent: repeated calls do not rewrite or churn nonces
        assert_eq!(settings.auto_save_env_keys()?, 0);
        let _ = Settings::load_default()?;
        assert_eq!(fs::read_to_string(&creds_path)?, raw_first);

        // Survives unsetting the environment variables
        env::remove_var("CLOUDFLARE_API_TOKEN");
        env::remove_var("CLOUDFLARE_ACCOUNT_ID");
        env::remove_var("GITHUB_TOKEN");
        assert_eq!(
            settings.cloudflare_api_token()?,
            Some("cf-auto-123".to_string())
        );
        assert_eq!(
            settings.cloudflare_account_id()?,
            Some("cf-acct-auto-789".to_string())
        );
        assert_eq!(settings.github_token()?, Some("ghp-auto-456".to_string()));

        // Legacy plaintext matching env value is upgraded to ciphertext
        settings.state.write_var("LINODE_API_TOKEN", "linode-plain")?;
        env::set_var("LINODE_API_TOKEN", "linode-plain");
        // Corrupt ciphertext is overwritten when env var is set
        settings.state.write_var("VULTR_API_KEY", "enc:v1:not-valid-b64!")?;
        env::set_var("VULTR_API_KEY", "vultr-recovered");
        // Changed env var updates stored ciphertext
        env::set_var("CLOUDFLARE_API_TOKEN", "cf-rotated-789");

        assert_eq!(settings.auto_save_env_keys()?, 3);
        env::remove_var("LINODE_API_TOKEN");
        env::remove_var("VULTR_API_KEY");
        env::remove_var("CLOUDFLARE_API_TOKEN");

        let raw_updated = fs::read_to_string(&creds_path)?;
        assert!(raw_updated.contains("LINODE_API_TOKEN=\"enc:v1:"));
        assert!(!raw_updated.contains("linode-plain"));
        assert_eq!(
            settings.linode_api_token()?,
            Some("linode-plain".to_string())
        );
        assert_eq!(
            settings.vultr_api_key()?,
            Some("vultr-recovered".to_string())
        );
        assert_eq!(
            settings.cloudflare_api_token()?,
            Some("cf-rotated-789".to_string())
        );
        Ok(())
    }

    #[test]
    fn log_store_default_path_honors_env_overrides() -> Result<()> {
        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "BAB_LOG_FILE",
            "BAB_CONFIG_DIR",
            "BAB_SSH_DIR",
            "VPSKIT_SSH_DIR",
            "SSH_DIR",
            "HOME",
        ]);
        for k in [
            "BAB_LOG_FILE",
            "BAB_CONFIG_DIR",
            "BAB_SSH_DIR",
            "VPSKIT_SSH_DIR",
            "SSH_DIR",
        ] {
            env::remove_var(k);
        }

        let dir = tempdir()?;
        let fake_home = dir.path().join("home");
        fs::create_dir_all(&fake_home)?;
        env::set_var("HOME", &fake_home);
        assert_eq!(
            LogStore::default_path()?,
            fake_home.join(".config").join("bab").join("bab.log")
        );

        let cfg_dir = dir.path().join("custom-cfg");
        env::set_var("BAB_CONFIG_DIR", &cfg_dir);
        assert_eq!(LogStore::default_path()?, cfg_dir.join("bab.log"));

        let explicit_log = dir.path().join("override").join("my.log");
        env::set_var("BAB_LOG_FILE", &explicit_log);
        assert_eq!(LogStore::default_path()?, explicit_log);

        let store = LogStore::load_default()?;
        assert_eq!(store.path(), explicit_log.as_path());
        assert_eq!(store.max_bytes(), MAX_LOG_FILE_BYTES);
        assert_eq!(MAX_LOG_FILE_BYTES, 10_485_760);
        Ok(())
    }

    #[test]
    fn log_store_append_creates_permissions_and_round_trips() -> Result<()> {
        let dir = tempdir()?;
        let log_dir = dir.path().join("nested").join("logs");
        let log_path = log_dir.join("bab.log");
        let store = LogStore::new(&log_path);

        assert_eq!(store.file_size(), 0);
        assert!(store.read_lines()?.is_empty());

        // Empty slice is a no-op and does not create files/dirs
        store.append_lines(&[])?;
        assert!(!log_path.exists());
        assert!(!log_dir.exists());

        store.append_line("first line\r\n")?;
        assert_eq!(fs::metadata(&log_dir)?.permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&log_path)?.permissions().mode() & 0o777, 0o600);

        store.append_lines(&["second line".to_string(), "third line\n".to_string()])?;
        assert_eq!(
            store.read_lines()?,
            vec![
                "first line".to_string(),
                "second line".to_string(),
                "third line".to_string(),
            ]
        );
        let expected_bytes = "first line\nsecond line\nthird line\n".len() as u64;
        assert_eq!(store.file_size(), expected_bytes);
        Ok(())
    }

    #[test]
    fn log_store_enforces_max_bytes_on_line_and_utf8_boundaries() -> Result<()> {
        let dir = tempdir()?;
        let log_path = dir.path().join("capped.log");
        let store = LogStore::with_max_bytes(&log_path, 14);

        store.append_line("alpha")?; // 6 bytes
        store.append_line("beta")?; // 5 bytes -> 11 bytes total
        assert_eq!(store.read_lines()?, vec!["alpha", "beta"]);

        // Adding "gamma\n" (6 bytes) -> 17 bytes > 14 -> drops "alpha\n" cleanly
        store.append_line("gamma")?;
        assert_eq!(store.read_lines()?, vec!["beta", "gamma"]);
        assert_eq!(store.file_size(), 11);

        // Exact-fit line boundary when oldest dropped leaves exact max_bytes
        let exact_path = dir.path().join("exact.log");
        let exact_store = LogStore::with_max_bytes(&exact_path, 12);
        exact_store.append_lines(&[
            "alpha".to_string(),
            "omega".to_string(),
            "theta".to_string(),
        ])?;
        assert_eq!(exact_store.read_lines()?, vec!["omega", "theta"]);
        assert_eq!(exact_store.file_size(), 12);

        // Oversized single UTF-8 multi-byte line must not split a codepoint
        let utf8_path = dir.path().join("utf8.log");
        let utf8_store = LogStore::with_max_bytes(&utf8_path, 10);
        utf8_store.append_line("😀😀😀😀😀")?; // 20 bytes + '\n' = 21 bytes
        let raw = fs::read_to_string(&utf8_path)?;
        assert!(raw.len() <= 10);
        assert_eq!(utf8_store.read_lines()?, vec!["😀😀"]);

        // Zero max_bytes keeps empty 0o600 file
        let zero_path = dir.path().join("zero.log");
        let zero_store = LogStore::with_max_bytes(&zero_path, 0);
        zero_store.append_line("discarded")?;
        assert_eq!(zero_store.file_size(), 0);
        assert!(zero_store.read_lines()?.is_empty());
        assert_eq!(fs::metadata(&zero_path)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn log_store_clear_empties_file_and_preserves_permissions() -> Result<()> {
        let dir = tempdir()?;
        let log_dir = dir.path().join("logs");
        let log_path = log_dir.join("bab.log");
        let store = LogStore::new(&log_path);

        store.append_lines(&["entry 1".to_string(), "entry 2".to_string()])?;
        assert!(store.file_size() > 0);

        store.clear()?;
        assert_eq!(store.file_size(), 0);
        assert!(store.read_lines()?.is_empty());
        assert_eq!(fs::metadata(&log_path)?.permissions().mode() & 0o777, 0o600);

        // Clear on a missing file creates 0o700 parent and empty 0o600 file
        let fresh_dir = dir.path().join("fresh");
        let fresh_path = fresh_dir.join("bab.log");
        let fresh_store = LogStore::new(&fresh_path);
        fresh_store.clear()?;
        assert_eq!(fs::metadata(&fresh_dir)?.permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&fresh_path)?.permissions().mode() & 0o777, 0o600);
        assert_eq!(fresh_store.file_size(), 0);
        Ok(())
    }

    #[test]
    fn format_utc_timestamp_and_append_timestamped_lines() -> Result<()> {
        assert_eq!(format_utc_timestamp_from_secs(0), "[1970-01-01T00:00:00Z]");
        // 2024-02-29T23:59:59Z
        assert_eq!(
            format_utc_timestamp_from_secs(1_709_251_199),
            "[2024-02-29T23:59:59Z]"
        );

        let now = format_utc_timestamp();
        assert_eq!(now.len(), 22);
        assert!(now.starts_with('['));
        assert!(now.ends_with("Z]"));

        let dir = tempdir()?;
        let store = LogStore::new(dir.path().join("stamped.log"));
        store.append_timestamped_lines(&[])?;
        assert!(!store.path().exists());

        store.append_timestamped_lines(&[
            "step one".to_string(),
            String::new(),
            "step two".to_string(),
        ])?;
        let lines = store.read_lines()?;
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with('[') && lines[0].ends_with("Z] step one"));
        assert_eq!(lines[1], "");
        assert!(lines[2].starts_with('[') && lines[2].ends_with("Z] step two"));
        Ok(())
    }

    #[test]
    fn generate_random_password_length_and_charset() {
        assert_eq!(SUDO_PASSWORD_LEN, 10);
        let pw = generate_random_password(SUDO_PASSWORD_LEN);
        assert_eq!(pw.len(), 10);
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));

        assert_eq!(generate_random_password(0), "");
        let pw2 = generate_random_password(SUDO_PASSWORD_LEN);
        assert_eq!(pw2.len(), 10);
        assert!(pw2.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn session_sudo_password_round_trip_and_clear() -> Result<()> {
        let tmp = NamedTempFile::new()?;
        let ss = SessionState::new(tmp.path());

        assert_eq!(ss.sudo_password()?, None);
        assert_eq!(ss.load_session()?.sudo_password, None);

        ss.set_sudo_password("Pass123456")?;
        assert_eq!(ss.sudo_password()?, Some("Pass123456".to_string()));
        assert_eq!(
            ss.load_session()?.sudo_password,
            Some("Pass123456".to_string())
        );

        let saved = SessionData {
            sudo_password: Some("AbCdEf1234".to_string()),
            ..SessionData::default()
        };
        ss.save_session(&saved)?;
        assert_eq!(
            ss.load_session()?.sudo_password,
            Some("AbCdEf1234".to_string())
        );
        assert!(fs::read_to_string(tmp.path())?.contains("SUDO_PASSWORD=\"AbCdEf1234\""));

        let empty = SessionData {
            sudo_password: Some(String::new()),
            ..SessionData::default()
        };
        ss.save_session(&empty)?;
        assert_eq!(ss.sudo_password()?, None);
        assert_eq!(ss.load_session()?.sudo_password, None);
        assert!(!fs::read_to_string(tmp.path())?.contains("SUDO_PASSWORD="));

        ss.set_sudo_password("TempPass99")?;
        let whitespace = SessionData {
            sudo_password: Some("   ".to_string()),
            ..SessionData::default()
        };
        ss.save_session(&whitespace)?;
        assert_eq!(ss.sudo_password()?, None);
        assert!(!fs::read_to_string(tmp.path())?.contains("SUDO_PASSWORD="));

        ss.set_sudo_password("TempPass99")?;
        let unset = SessionData {
            sudo_password: None,
            ..SessionData::default()
        };
        ss.save_session(&unset)?;
        assert_eq!(ss.sudo_password()?, None);
        assert!(!fs::read_to_string(tmp.path())?.contains("SUDO_PASSWORD="));
        Ok(())
    }

    #[test]
    fn settings_record_and_lookup_instance_password_encrypted_round_trip() -> Result<()> {
        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "BAB_ENCRYPTION_KEY",
            "BAB_MASTER_KEY_FILE",
            "SUDO_PASSWORD",
        ]);
        env::remove_var("BAB_ENCRYPTION_KEY");
        env::remove_var("BAB_MASTER_KEY_FILE");
        env::remove_var("SUDO_PASSWORD");

        let dir = tempdir()?;
        let creds_path = dir.path().join("credentials.enc");
        let settings = Settings::new(&creds_path);

        // Blank password is a no-op
        settings.record_instance_password(
            Some("inst-empty"),
            Some("empty.example.ts.net"),
            Some("203.0.113.1"),
            "   ",
        )?;
        assert!(!creds_path.exists());

        settings.record_instance_password(
            Some("inst-abc:123/xyz"),
            Some("my-vps.tailnet.ts.net"),
            Some("203.0.113.42"),
            "  SecRet1234  ",
        )?;

        let raw = fs::read_to_string(&creds_path)?;
        assert!(raw.contains("SUDO_PASSWORD=\"enc:v1:"));
        assert!(raw.contains("BOX_PASS_ID_inst_abc_123_xyz=\"enc:v1:"));
        assert!(raw.contains("BOX_PASS_HOST_my_vps_tailnet_ts_net=\"enc:v1:"));
        assert!(raw.contains("BOX_PASS_IP_203_0_113_42=\"enc:v1:"));
        assert!(!raw.contains("SecRet1234"));

        assert_eq!(
            settings.get("SUDO_PASSWORD")?,
            Some("SecRet1234".to_string())
        );

        // Lookup by ID, IP, and hostname individually
        assert_eq!(
            settings.lookup_instance_password(Some("inst-abc:123/xyz"), None, None)?,
            Some("SecRet1234".to_string())
        );
        assert_eq!(
            settings.lookup_instance_password(None, None, Some("203.0.113.42"))?,
            Some("SecRet1234".to_string())
        );
        assert_eq!(
            settings.lookup_instance_password(None, Some("my-vps.tailnet.ts.net"), None)?,
            Some("SecRet1234".to_string())
        );

        // Precedence: ID > IP > Host
        settings.record_instance_password(None, Some("shared.ts.net"), None, "HostPass11")?;
        settings.record_instance_password(None, None, Some("198.51.100.2"), "IpPass2222")?;
        assert_eq!(
            settings.lookup_instance_password(
                Some("missing-id"),
                Some("shared.ts.net"),
                Some("198.51.100.2")
            )?,
            Some("IpPass2222".to_string())
        );
        settings.record_instance_password(Some("id-first"), None, None, "IdPass3333")?;
        assert_eq!(
            settings.lookup_instance_password(
                Some("id-first"),
                Some("shared.ts.net"),
                Some("198.51.100.2")
            )?,
            Some("IdPass3333".to_string())
        );

        // Missing or whitespace-only identifiers return None
        assert_eq!(
            settings.lookup_instance_password(Some("   "), Some(""), None)?,
            None
        );
        Ok(())
    }
}
