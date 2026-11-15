// src/providers/mod.rs
// Provider abstractions for bab.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;
use std::time::Duration;

use crate::config::{SessionData, SessionState};
use crate::tailscale::{generate_cloud_init, generate_ssh_cloud_init, TailscaleClient};

// Public sub-modules for concrete provider implementations.
pub mod vultr;
pub mod upcloud;
pub mod linode;

/// Enumerates supported providers and special modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderKind {
    Vultr,
    UpCloud,
    Linode,
    ExistingTailscale,
    ManualCloudInit,
}

impl ProviderKind {
    /// Returns the environment variable name for the provider's API key, if any.
    pub fn api_key_env_name(&self) -> Option<&'static str> {
        match self {
            ProviderKind::Vultr => Some("VULTR_API_KEY"),
            ProviderKind::UpCloud => Some("UPCLOUD_API_TOKEN"),
            ProviderKind::Linode => Some("LINODE_API_TOKEN"),
            ProviderKind::ExistingTailscale => None,
            ProviderKind::ManualCloudInit => None,
        }
    }

    /// Human‑readable label for the provider.
    pub fn label(&self) -> &'static str {
        match self {
            ProviderKind::Vultr => "Vultr",
            ProviderKind::UpCloud => "UpCloud",
            ProviderKind::Linode => "Linode",
            ProviderKind::ExistingTailscale => "Existing Tailscale",
            ProviderKind::ManualCloudInit => "Manual Cloud‑Init",
        }
    }
}

impl Display for ProviderKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = match self {
            ProviderKind::Vultr => "vultr",
            ProviderKind::UpCloud => "upcloud",
            ProviderKind::Linode => "linode",
            ProviderKind::ExistingTailscale => "existing_tailscale",
            ProviderKind::ManualCloudInit => "manual_cloud_init",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for ProviderKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "vultr" => Ok(ProviderKind::Vultr),
            "upcloud" => Ok(ProviderKind::UpCloud),
            "linode" | "akamai" => Ok(ProviderKind::Linode),
            "existing" | "existing_tailscale" => Ok(ProviderKind::ExistingTailscale),
            "manual" | "manual_cloud_init" => Ok(ProviderKind::ManualCloudInit),
            _ => Err(anyhow::anyhow!("Unknown provider: {}", s)),
        }
    }
}

/// Simple region description.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderRegion {
    pub id: String,
    pub name: String,
    pub country: String,
}

/// Simple plan description.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderPlan {
    pub id: String,
    pub summary: String,
}

/// Simple image description.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderImage {
    pub id: String,
    pub name: String,
    pub vendor: String,
}

/// Status of a provisioned instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceStatus {
    pub state: String,
    pub public_ipv4: Option<String>,
    pub ready: bool,
}

/// Request payload for creating a new instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateInstanceRequest {
    pub region: String,
    pub plan: String,
    pub image_id: String,
    pub hostname: String,
    pub user_data_raw: String,
}

/// Configuration used for the full provisioning flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionConfig {
    pub provider: ProviderKind,
    pub region: String,
    pub plan: String,
    pub image_id: String,
    pub hostname: String,
    pub username: String,
    pub role: String,
    pub tags: Vec<String>,
    pub provider_timeout: Duration,
    pub tailscale_timeout: Duration,
    pub poll_interval: Duration,
    pub tailscale_mode: bool,
    pub ssh_pubkey: Option<String>,
    pub ssh_key_path: Option<String>,
}

/// Result returned after a successful provisioning run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionResult {
    pub instance_id: String,
    pub ip: String,
    pub tailscale_ip: String,
    pub hostname: String,
    pub provider: String,
    pub username: String,
    pub role: String,
    pub tailscale_mode: bool,
}

/// Trait that concrete providers must implement.
pub trait VpsProvider {
    fn kind(&self) -> ProviderKind;
    fn validate_key(&self) -> Result<bool>;
    fn list_regions(&self) -> Result<Vec<ProviderRegion>>;
    fn list_plans(&self) -> Result<Vec<ProviderPlan>>;
    fn list_images(&self) -> Result<Vec<ProviderImage>>;
    fn create_instance(&self, req: &CreateInstanceRequest) -> Result<String>;
    fn get_instance_status(&self, instance_id: &str) -> Result<InstanceStatus>;
    fn wait_active(
        &self,
        instance_id: &str,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            let status = self.get_instance_status(instance_id)?;
            if status.ready {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                return Err(anyhow::anyhow!("Timed out waiting for instance {} to become ready", instance_id));
            }
            std::thread::sleep(poll_interval);
        }
    }
}

/// Executes the full provisioning flow (Tailscale or Standard SSH mode), waits for the VM to be ready, and records session data.
pub fn provision_full_flow(
    provider: &dyn VpsProvider,
    tailscale: Option<&TailscaleClient>,
    cfg: &ProvisionConfig,
    session: Option<&SessionState>,
) -> Result<ProvisionResult> {
    let cloud_init = if cfg.tailscale_mode {
        let ts = tailscale.ok_or_else(|| {
            anyhow!("Tailscale client is required when tailscale_mode is enabled")
        })?;
        let auth_key = ts.create_auth_key("bab-bootstrap", &cfg.tags, false, true, 3600)?;
        generate_cloud_init(&auth_key, &cfg.hostname, &cfg.username)
    } else {
        let ssh_pubkey = cfg
            .ssh_pubkey
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow!("SSH public key is required when tailscale_mode is disabled")
            })?;
        generate_ssh_cloud_init(ssh_pubkey, &cfg.hostname, &cfg.username)
    };

    let req = CreateInstanceRequest {
        region: cfg.region.clone(),
        plan: cfg.plan.clone(),
        image_id: cfg.image_id.clone(),
        hostname: cfg.hostname.clone(),
        user_data_raw: cloud_init,
    };
    let instance_id = provider.create_instance(&req)?;
    provider.wait_active(&instance_id, cfg.provider_timeout, cfg.poll_interval)?;

    let (ip, tailscale_ip, ssh_key, transport_mode) = if cfg.tailscale_mode {
        let ts = tailscale.expect("validated above");
        let ts_ip = ts.wait_for_device(&cfg.hostname, cfg.tailscale_timeout, cfg.poll_interval)?;
        (
            ts_ip.clone(),
            ts_ip,
            Some("tailscale".to_string()),
            "tailscale",
        )
    } else {
        let status = provider.get_instance_status(&instance_id)?;
        let public_ipv4 = status
            .public_ipv4
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "Instance {} became active without a public IPv4 address",
                    instance_id
                )
            })?;
        let ssh_key = cfg
            .ssh_key_path
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);
        (public_ipv4, String::new(), ssh_key, "ssh")
    };

    if let Some(ss) = session {
        let data = SessionData {
            vps_ip: Some(ip.clone()),
            ssh_key,
            username: Some(cfg.username.clone()),
            transport_mode: Some(transport_mode.to_string()),
            vps_provider: Some(provider.kind().to_string()),
            vps_instance_id: Some(instance_id.clone()),
            tailscale_hostname: Some(cfg.hostname.clone()),
            server_role: Some(cfg.role.clone()),
        };
        ss.save_session(&data)?;
    }

    Ok(ProvisionResult {
        instance_id,
        ip,
        tailscale_ip,
        hostname: cfg.hostname.clone(),
        provider: provider.kind().to_string(),
        username: cfg.username.clone(),
        role: cfg.role.clone(),
        tailscale_mode: cfg.tailscale_mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_kind_from_str_maps_akamai_to_linode() {
        assert_eq!("vultr".parse::<ProviderKind>().unwrap(), ProviderKind::Vultr);
        assert_eq!("upcloud".parse::<ProviderKind>().unwrap(), ProviderKind::UpCloud);
        assert_eq!("linode".parse::<ProviderKind>().unwrap(), ProviderKind::Linode);
        assert_eq!("akamai".parse::<ProviderKind>().unwrap(), ProviderKind::Linode);
        assert_eq!("Akamai".parse::<ProviderKind>().unwrap(), ProviderKind::Linode);
        assert_eq!(
            "existing_tailscale".parse::<ProviderKind>().unwrap(),
            ProviderKind::ExistingTailscale
        );
        assert_eq!(
            "manual_cloud_init".parse::<ProviderKind>().unwrap(),
            ProviderKind::ManualCloudInit
        );
        assert!("unknown".parse::<ProviderKind>().is_err());
    }

    #[test]
    fn provider_kind_display_roundtrip() {
        for kind in [
            ProviderKind::Vultr,
            ProviderKind::UpCloud,
            ProviderKind::Linode,
            ProviderKind::ExistingTailscale,
            ProviderKind::ManualCloudInit,
        ] {
            let parsed: ProviderKind = kind.to_string().parse().unwrap();
            assert_eq!(parsed, kind);
        }
    }

    struct MockProvider {
        public_ipv4: Option<String>,
        captured_user_data: std::sync::Mutex<Option<String>>,
    }

    impl MockProvider {
        fn new(public_ipv4: Option<&str>) -> Self {
            Self {
                public_ipv4: public_ipv4.map(String::from),
                captured_user_data: std::sync::Mutex::new(None),
            }
        }
    }

    impl VpsProvider for MockProvider {
        fn kind(&self) -> ProviderKind {
            ProviderKind::Vultr
        }
        fn validate_key(&self) -> Result<bool> {
            Ok(true)
        }
        fn list_regions(&self) -> Result<Vec<ProviderRegion>> {
            Ok(vec![])
        }
        fn list_plans(&self) -> Result<Vec<ProviderPlan>> {
            Ok(vec![])
        }
        fn list_images(&self) -> Result<Vec<ProviderImage>> {
            Ok(vec![])
        }
        fn create_instance(&self, req: &CreateInstanceRequest) -> Result<String> {
            *self.captured_user_data.lock().unwrap() = Some(req.user_data_raw.clone());
            Ok("inst-123".to_string())
        }
        fn get_instance_status(&self, _instance_id: &str) -> Result<InstanceStatus> {
            Ok(InstanceStatus {
                state: "active".to_string(),
                public_ipv4: self.public_ipv4.clone(),
                ready: true,
            })
        }
    }

    fn base_cfg(tailscale_mode: bool) -> ProvisionConfig {
        ProvisionConfig {
            provider: ProviderKind::Vultr,
            region: "ewr".to_string(),
            plan: "vc2-1c-1gb".to_string(),
            image_id: "2284".to_string(),
            hostname: "bab-vps".to_string(),
            username: "deploy".to_string(),
            role: "caddy".to_string(),
            tags: vec!["tag:bab".to_string()],
            provider_timeout: Duration::from_secs(5),
            tailscale_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(1),
            tailscale_mode,
            ssh_pubkey: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host".to_string()),
            ssh_key_path: Some("/tmp/bab_ed25519".to_string()),
        }
    }

    #[test]
    fn provision_full_flow_standard_ssh_mode_saves_session() -> Result<()> {
        let provider = MockProvider::new(Some("203.0.113.42"));
        let tmp = tempfile::NamedTempFile::new()?;
        let session = SessionState::new(tmp.path());
        let cfg = base_cfg(false);

        let res = provision_full_flow(&provider, None, &cfg, Some(&session))?;
        assert_eq!(res.instance_id, "inst-123");
        assert_eq!(res.ip, "203.0.113.42");
        assert_eq!(res.tailscale_ip, "");
        assert!(!res.tailscale_mode);

        let user_data = provider.captured_user_data.lock().unwrap().clone().unwrap();
        assert!(user_data.contains("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host"));
        assert!(!user_data.to_ascii_lowercase().contains("tailscale"));

        let loaded = session.load_session()?;
        assert_eq!(loaded.vps_ip.as_deref(), Some("203.0.113.42"));
        assert_eq!(loaded.ssh_key.as_deref(), Some("/tmp/bab_ed25519"));
        assert_eq!(loaded.transport_mode.as_deref(), Some("ssh"));
        assert_eq!(loaded.username.as_deref(), Some("deploy"));
        assert_eq!(loaded.vps_provider.as_deref(), Some("vultr"));
        assert_eq!(loaded.vps_instance_id.as_deref(), Some("inst-123"));
        assert_eq!(loaded.tailscale_hostname.as_deref(), Some("bab-vps"));
        assert_eq!(loaded.server_role.as_deref(), Some("caddy"));
        Ok(())
    }

    #[test]
    fn provision_full_flow_validates_ssh_mode_and_tailscale_client() {
        let provider = MockProvider::new(Some("203.0.113.42"));
        let mut cfg_no_key = base_cfg(false);
        cfg_no_key.ssh_pubkey = Some("   ".to_string());
        assert!(provision_full_flow(&provider, None, &cfg_no_key, None).is_err());

        let provider_no_ip = MockProvider::new(Some(""));
        let cfg_ssh = base_cfg(false);
        assert!(provision_full_flow(&provider_no_ip, None, &cfg_ssh, None).is_err());

        let cfg_ts = base_cfg(true);
        assert!(provision_full_flow(&provider, None, &cfg_ts, None).is_err());
    }

    #[test]
    fn provision_full_flow_tailscale_mode_saves_session() -> Result<()> {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || {
            let responses = [
                r#"{"key":"tskey-auth-bab"}"#,
                r#"{"devices":[{"id":"dev-1","hostname":"bab-vps","name":"bab-vps.tail1.ts.net","addresses":["100.64.1.2"],"os":"linux","online":true}]}"#,
            ];
            for body in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&stream);
                let mut req_line = String::new();
                reader.read_line(&mut req_line).unwrap();
                let mut content_len = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if content_len > 0 {
                    let mut buf = vec![0u8; content_len];
                    reader.read_exact(&mut buf).unwrap();
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        let ts = TailscaleClient::with_config("ts-api-key", format!("http://{}", addr), "-")?;
        let provider = MockProvider::new(Some("203.0.113.42"));
        let tmp = tempfile::NamedTempFile::new()?;
        let session = SessionState::new(tmp.path());
        let cfg = base_cfg(true);

        let res = provision_full_flow(&provider, Some(&ts), &cfg, Some(&session))?;
        handle.join().unwrap();

        assert_eq!(res.ip, "100.64.1.2");
        assert_eq!(res.tailscale_ip, "100.64.1.2");
        assert!(res.tailscale_mode);

        let user_data = provider.captured_user_data.lock().unwrap().clone().unwrap();
        assert!(user_data.contains("tailscale up --authkey='tskey-auth-bab'"));

        let loaded = session.load_session()?;
        assert_eq!(loaded.vps_ip.as_deref(), Some("100.64.1.2"));
        assert_eq!(loaded.ssh_key.as_deref(), Some("tailscale"));
        assert_eq!(loaded.transport_mode.as_deref(), Some("tailscale"));
        Ok(())
    }
}
