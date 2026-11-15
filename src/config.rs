use anyhow::Result;
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn non_empty_env(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

fn resolve_state_path(file_vars: &[&str], default_filename: &str) -> Result<PathBuf> {
    for var in file_vars {
        if let Some(p) = non_empty_env(var) {
            return Ok(PathBuf::from(p));
        }
    }
    let dir = if let Some(p) = non_empty_env("BAB_SSH_DIR") {
        p
    } else if let Some(p) = non_empty_env("VPSKIT_SSH_DIR") {
        p
    } else if let Some(p) = non_empty_env("SSH_DIR") {
        p
    } else {
        let home = env::var("HOME")?;
        format!("{}/.ssh", home)
    };
    Ok(Path::new(&dir).join(default_filename))
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
        self.ensure_parent_dir()?;
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
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|l| !l.starts_with(&prefix))
            .collect();
        self.write_lines_atomic(&lines)
    }

    fn write_lines_atomic(&self, lines: &[String]) -> Result<()> {
        self.ensure_parent_dir()?;
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let base_name = self
            .path
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
            for l in lines {
                writeln!(tmp_file, "{}", l)?;
            }
            tmp_file.sync_all()?;
            drop(tmp_file);
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
            fs::rename(&tmp_path, &self.path)?;
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&tmp_path);
        }
        write_result
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

    fn ensure_parent_dir(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)?;
                // chmod 0o700 on the directory
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(())
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
            ".bab-settings",
        )
    }

    pub fn new<P: Into<PathBuf>>(path: P) -> Self {
        Settings {
            state: StateFile::new(path),
        }
    }

    pub fn load_default() -> Result<Self> {
        let path = Self::default_path()?;
        Ok(Self::new(path))
    }

    /// Get a variable, preferring environment variable if set and non‑empty.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        if let Ok(val) = env::var(key) {
            if !val.is_empty() {
                return Ok(Some(val));
            }
        }
        self.state.read_var(key)
    }

    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        self.state.write_var(key, value)
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
            ".bab-local",
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, OnceLock};
    use std::thread;
    use tempfile::{tempdir, NamedTempFile};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

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
        let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
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
        let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let _guard = EnvGuard::new(&[
            "BAB_SETTINGS_FILE",
            "VPSKIT_SETTINGS_FILE",
            "SETTINGS_FILE",
            "BAB_STATE_FILE",
            "BAB_LOCAL_STATE",
            "VPSKIT_STATE_FILE",
            "VPSKIT_LOCAL_STATE",
            "LOCAL_STATE",
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
            "BAB_SSH_DIR",
            "VPSKIT_SSH_DIR",
            "SSH_DIR",
        ] {
            env::remove_var(k);
        }
        env::set_var("HOME", "/tmp/testhome");
        assert_eq!(
            Settings::default_path()?,
            PathBuf::from("/tmp/testhome/.ssh/.bab-settings")
        );
        assert_eq!(
            SessionState::default_path()?,
            PathBuf::from("/tmp/testhome/.ssh/.bab-local")
        );

        env::set_var("SSH_DIR", "/tmp/custom-ssh");
        assert_eq!(
            Settings::default_path()?,
            PathBuf::from("/tmp/custom-ssh/.bab-settings")
        );
        assert_eq!(
            SessionState::default_path()?,
            PathBuf::from("/tmp/custom-ssh/.bab-local")
        );

        env::set_var("BAB_SSH_DIR", "/tmp/bab-ssh");
        assert_eq!(
            Settings::default_path()?,
            PathBuf::from("/tmp/bab-ssh/.bab-settings")
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
            server_role: None,
        };
        ss.save_session(&data)?;
        assert_eq!(ss.load_session()?, data);
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
}
