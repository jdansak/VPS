// src/providers/mod.rs
// Provider abstractions for bab.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;
use std::time::Duration;

use crate::config::{SessionData, SessionState, Settings};
use crate::tailscale::{
    generate_cloud_init_with_password, generate_ssh_cloud_init_with_password, TailscaleClient,
};

// Public sub-modules for concrete provider implementations.
pub mod vultr;
pub mod upcloud;
pub mod linode;

use self::linode::LinodeProvider;
use self::upcloud::UpCloudProvider;
use self::vultr::VultrProvider;

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

/// Curated default region presets for a given provider.
pub fn default_regions_for(kind: ProviderKind) -> Vec<ProviderRegion> {
    match kind {
        ProviderKind::Vultr => vec![
            ProviderRegion { id: "ewr".into(), name: "Newark, NJ".into(), country: "US".into() },
            ProviderRegion { id: "ord".into(), name: "Chicago, IL".into(), country: "US".into() },
            ProviderRegion { id: "lax".into(), name: "Los Angeles, CA".into(), country: "US".into() },
            ProviderRegion { id: "ams".into(), name: "Amsterdam".into(), country: "NL".into() },
            ProviderRegion { id: "fra".into(), name: "Frankfurt".into(), country: "DE".into() },
            ProviderRegion { id: "lhr".into(), name: "London".into(), country: "GB".into() },
            ProviderRegion { id: "sgp".into(), name: "Singapore".into(), country: "SG".into() },
            ProviderRegion { id: "nrt".into(), name: "Tokyo".into(), country: "JP".into() },
        ],
        ProviderKind::UpCloud => vec![
            ProviderRegion { id: "us-nyc1".into(), name: "New York".into(), country: "US".into() },
            ProviderRegion { id: "us-chi1".into(), name: "Chicago".into(), country: "US".into() },
            ProviderRegion { id: "nl-ams1".into(), name: "Amsterdam".into(), country: "NL".into() },
            ProviderRegion { id: "de-fra1".into(), name: "Frankfurt".into(), country: "DE".into() },
            ProviderRegion { id: "uk-lon1".into(), name: "London".into(), country: "GB".into() },
            ProviderRegion { id: "sg-sin1".into(), name: "Singapore".into(), country: "SG".into() },
        ],
        ProviderKind::Linode => vec![
            ProviderRegion { id: "us-east".into(), name: "Newark, NJ".into(), country: "US".into() },
            ProviderRegion { id: "us-central".into(), name: "Dallas, TX".into(), country: "US".into() },
            ProviderRegion { id: "us-west".into(), name: "Fremont, CA".into(), country: "US".into() },
            ProviderRegion { id: "eu-west".into(), name: "London".into(), country: "GB".into() },
            ProviderRegion { id: "eu-central".into(), name: "Frankfurt".into(), country: "DE".into() },
            ProviderRegion { id: "ap-south".into(), name: "Singapore".into(), country: "SG".into() },
        ],
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => Vec::new(),
    }
}

/// Curated default machine size (plan) presets for a given provider.
pub fn default_plans_for(kind: ProviderKind) -> Vec<ProviderPlan> {
    match kind {
        ProviderKind::Vultr => vec![
            ProviderPlan {
                id: "vc2-1c-1gb".into(),
                summary: "1 vCPU, 1024 MB RAM, 25 GB SSD ($5/mo)".into(),
            },
            ProviderPlan {
                id: "vc2-1c-2gb".into(),
                summary: "1 vCPU, 2048 MB RAM, 55 GB SSD ($10/mo)".into(),
            },
            ProviderPlan {
                id: "vc2-2c-4gb".into(),
                summary: "2 vCPU, 4096 MB RAM, 80 GB SSD ($20/mo)".into(),
            },
            ProviderPlan {
                id: "vc2-4c-8gb".into(),
                summary: "4 vCPU, 8192 MB RAM, 160 GB SSD ($40/mo)".into(),
            },
        ],
        ProviderKind::UpCloud => vec![
            ProviderPlan {
                id: "1xCPU-1GB".into(),
                summary: "1 vCPU, 1024 MB RAM, 25 GB SSD".into(),
            },
            ProviderPlan {
                id: "1xCPU-2GB".into(),
                summary: "1 vCPU, 2048 MB RAM, 50 GB SSD".into(),
            },
            ProviderPlan {
                id: "2xCPU-4GB".into(),
                summary: "2 vCPU, 4096 MB RAM, 80 GB SSD".into(),
            },
            ProviderPlan {
                id: "4xCPU-8GB".into(),
                summary: "4 vCPU, 8192 MB RAM, 160 GB SSD".into(),
            },
        ],
        ProviderKind::Linode => vec![
            ProviderPlan {
                id: "g6-nanode-1".into(),
                summary: "Nanode 1GB - 1 vCPU, 1024 MB RAM, 25 GB SSD ($5/mo)".into(),
            },
            ProviderPlan {
                id: "g6-standard-1".into(),
                summary: "Linode 2GB - 1 vCPU, 2048 MB RAM, 50 GB SSD ($12/mo)".into(),
            },
            ProviderPlan {
                id: "g6-standard-2".into(),
                summary: "Linode 4GB - 2 vCPU, 4096 MB RAM, 80 GB SSD ($24/mo)".into(),
            },
            ProviderPlan {
                id: "g6-standard-4".into(),
                summary: "Linode 8GB - 4 vCPU, 8192 MB RAM, 160 GB SSD ($48/mo)".into(),
            },
        ],
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => Vec::new(),
    }
}

/// Curated default OS image presets for a given provider.
pub fn default_images_for(kind: ProviderKind) -> Vec<ProviderImage> {
    match kind {
        ProviderKind::Vultr => vec![
            ProviderImage {
                id: "2284".into(),
                name: "Ubuntu 24.04 LTS x64".into(),
                vendor: "ubuntu".into(),
            },
            ProviderImage {
                id: "2136".into(),
                name: "Debian 12 x64 (bookworm)".into(),
                vendor: "debian".into(),
            },
        ],
        ProviderKind::UpCloud => vec![
            ProviderImage {
                id: "01000000-0000-4000-8000-000030240200".into(),
                name: "Ubuntu Server 24.04 LTS".into(),
                vendor: "upcloud".into(),
            },
            ProviderImage {
                id: "01000000-0000-4000-8000-000020060100".into(),
                name: "Debian GNU/Linux 12 (Bookworm)".into(),
                vendor: "upcloud".into(),
            },
        ],
        ProviderKind::Linode => vec![
            ProviderImage {
                id: "linode/ubuntu24.04".into(),
                name: "Ubuntu 24.04 LTS".into(),
                vendor: "Ubuntu".into(),
            },
            ProviderImage {
                id: "linode/debian12".into(),
                name: "Debian 12".into(),
                vendor: "Debian".into(),
            },
        ],
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => Vec::new(),
    }
}

/// Status of a provisioned instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceStatus {
    pub state: String,
    pub public_ipv4: Option<String>,
    pub ready: bool,
}

/// Summary of a cloud VPS instance returned by provider instance listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderInstance {
    pub provider: ProviderKind,
    pub id: String,
    pub name: String,
    pub status: String,
    pub public_ip: Option<String>,
    pub region: Option<String>,
    pub plan: Option<String>,
    pub created_at: Option<String>,
}

/// Per-provider status recorded while querying across cloud providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderQueryStatus {
    pub provider: ProviderKind,
    pub configured: bool,
    pub instance_count: usize,
    pub error: Option<String>,
}

/// Combined result of querying one or more cloud providers for instances.
#[derive(Debug, Clone, Default)]
pub struct MultiProviderQueryResult {
    pub instances: Vec<ProviderInstance>,
    pub provider_statuses: Vec<ProviderQueryStatus>,
}

/// Validate and trim a cloud instance ID to prevent URL path or query injection.
pub fn validate_instance_id(id: &str) -> Result<&str> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Instance ID must not be empty"));
    }
    if trimmed.contains("..") {
        return Err(anyhow!("Instance ID must not contain '..'"));
    }
    if trimmed.chars().any(|c| {
        c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '?' | '#' | '&')
    }) {
        return Err(anyhow!(
            "Instance ID '{}' contains invalid characters",
            trimmed
        ));
    }
    Ok(trimmed)
}

pub(crate) fn non_empty_trimmed(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .as_deref()
        .and_then(non_empty_trimmed)
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
    pub sudo_password: Option<String>,
}

/// Result returned after a successful provisioning run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionResult {
    pub instance_id: String,
    pub ip: String,
    pub tailscale_ip: String,
    pub public_ip: String,
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
    fn list_instances(&self) -> Result<Vec<ProviderInstance>>;
    fn destroy_instance(&self, instance_id: &str) -> Result<()>;
    fn wait_active(
        &self,
        instance_id: &str,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<InstanceStatus> {
        let start = std::time::Instant::now();
        loop {
            let status = self.get_instance_status(instance_id)?;
            if status.ready {
                return Ok(status);
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
    provision_full_flow_with_progress(provider, tailscale, cfg, session, |_| {})
}

/// Populates provisioning configuration metadata onto `SessionData`, preserving any existing
/// `sudo_password` when `cfg.sudo_password` is `None` or blank.
fn populate_provision_session_data(
    data: &mut SessionData,
    cfg: &ProvisionConfig,
    provider_kind: ProviderKind,
    instance_id: &str,
    transport_mode: &str,
) {
    data.vps_instance_id = Some(instance_id.to_string());
    data.vps_provider = Some(provider_kind.to_string());
    data.tailscale_hostname = Some(cfg.hostname.clone());
    data.username = Some(cfg.username.clone());
    data.transport_mode = Some(transport_mode.to_string());
    data.server_role = Some(cfg.role.clone());
    data.vps_region = Some(cfg.region.clone());
    data.vps_plan = Some(cfg.plan.clone());
    data.vps_image = Some(cfg.image_id.clone());
    if let Some(pw) = cfg.sudo_password.as_deref().and_then(non_empty_trimmed) {
        data.sudo_password = Some(pw);
    }
}

/// Loads `SessionData` (or defaults), applies `update`, and persists it when `session` is `Some`.
fn update_provision_session(
    session: Option<&SessionState>,
    update: impl FnOnce(&mut SessionData),
) -> Result<()> {
    let Some(ss) = session else {
        return Ok(());
    };
    let mut data = ss.load_session().unwrap_or_else(|_| SessionData::default());
    update(&mut data);
    ss.save_session(&data)
}

/// Executes the full provisioning flow while emitting human-readable progress updates via `on_progress`.
pub fn provision_full_flow_with_progress<F>(
    provider: &dyn VpsProvider,
    tailscale: Option<&TailscaleClient>,
    cfg: &ProvisionConfig,
    session: Option<&SessionState>,
    mut on_progress: F,
) -> Result<ProvisionResult>
where
    F: FnMut(&str),
{
    let cloud_init = if cfg.tailscale_mode {
        let ts = tailscale.ok_or_else(|| {
            anyhow!("Tailscale client is required when tailscale_mode is enabled")
        })?;
        on_progress("[PROVISION] Creating Tailscale auth key and cloud-init...");
        let auth_key = ts.create_auth_key("bab-bootstrap", &cfg.tags, false, true, 3600)?;
        generate_cloud_init_with_password(
            &auth_key,
            &cfg.hostname,
            &cfg.username,
            cfg.sudo_password.as_deref(),
        )
    } else {
        let ssh_pubkey = cfg
            .ssh_pubkey
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow!("SSH public key is required when tailscale_mode is disabled")
            })?;
        generate_ssh_cloud_init_with_password(
            ssh_pubkey,
            &cfg.hostname,
            &cfg.username,
            cfg.sudo_password.as_deref(),
        )
    };

    let req = CreateInstanceRequest {
        region: cfg.region.clone(),
        plan: cfg.plan.clone(),
        image_id: cfg.image_id.clone(),
        hostname: cfg.hostname.clone(),
        user_data_raw: cloud_init,
    };
    on_progress(&format!(
        "[PROVISION] Submitting {} create_instance request for '{}'...",
        provider.kind().label(),
        cfg.hostname
    ));
    let instance_id = provider.create_instance(&req)?;
    let transport_mode = if cfg.tailscale_mode { "tailscale" } else { "ssh" };
    update_provision_session(session, |data| {
        populate_provision_session_data(
            data,
            cfg,
            provider.kind(),
            &instance_id,
            transport_mode,
        );
        data.vps_ip = None;
        data.public_ip = None;
        data.tailscale_ip = None;
    })?;
    on_progress(&format!(
        "[PROVISION] Instance '{}' created; polling {} until active...",
        instance_id,
        provider.kind().label()
    ));

    let start = std::time::Instant::now();
    let status = loop {
        let status = provider.get_instance_status(&instance_id)?;
        if status.ready {
            break status;
        }
        on_progress(&format!(
            "[PROVISION] Polling VM '{}' (state={}, ip={}, elapsed={}s)...",
            instance_id,
            status.state,
            status.public_ipv4.as_deref().unwrap_or("pending"),
            start.elapsed().as_secs()
        ));
        if start.elapsed() >= cfg.provider_timeout {
            return Err(anyhow!(
                "Timed out waiting for instance {} to become ready",
                instance_id
            ));
        }
        std::thread::sleep(cfg.poll_interval);
    };

    let discovered_public_ip = status
        .public_ipv4
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    update_provision_session(session, |data| {
        data.public_ip = discovered_public_ip.clone();
    })?;

    let (ip, tailscale_ip, public_ip, session_tailscale_ip, session_public_ip, ssh_key) =
        if cfg.tailscale_mode {
            let ts = tailscale.expect("validated above");
            let ts_start = std::time::Instant::now();
            let ts_ip = loop {
                on_progress(&format!(
                    "[PROVISION] VM '{}' is active (public IP: {}); waiting for '{}' on Tailscale (elapsed={}s)...",
                    instance_id,
                    discovered_public_ip.as_deref().unwrap_or("none"),
                    cfg.hostname,
                    ts_start.elapsed().as_secs()
                ));
                if let Some(found) = ts.find_device_ip(&cfg.hostname)? {
                    break found;
                }
                if ts_start.elapsed() >= cfg.tailscale_timeout {
                    return Err(anyhow!("Timed out waiting for device {}", cfg.hostname));
                }
                std::thread::sleep(cfg.poll_interval);
            };
            let pub_ip_str = discovered_public_ip.clone().unwrap_or_default();
            (
                ts_ip.clone(),
                ts_ip.clone(),
                pub_ip_str,
                Some(ts_ip),
                discovered_public_ip,
                Some("tailscale".to_string()),
            )
        } else {
            let public_ip = discovered_public_ip.ok_or_else(|| {
                anyhow!(
                    "Instance {} became active without a public IPv4 address",
                    instance_id
                )
            })?;
            let ssh_key = cfg.ssh_key_path.as_deref().and_then(non_empty_trimmed);
            (
                public_ip.clone(),
                String::new(),
                public_ip.clone(),
                None,
                Some(public_ip),
                ssh_key,
            )
        };

    update_provision_session(session, |data| {
        populate_provision_session_data(
            data,
            cfg,
            provider.kind(),
            &instance_id,
            transport_mode,
        );
        data.vps_ip = Some(ip.clone());
        data.public_ip = session_public_ip;
        data.tailscale_ip = session_tailscale_ip;
        data.ssh_key = ssh_key;
    })?;

    Ok(ProvisionResult {
        instance_id,
        ip,
        tailscale_ip,
        public_ip,
        hostname: cfg.hostname.clone(),
        provider: provider.kind().to_string(),
        username: cfg.username.clone(),
        role: cfg.role.clone(),
        tailscale_mode: cfg.tailscale_mode,
    })
}

const CLOUD_PROVIDERS: [ProviderKind; 3] = [
    ProviderKind::Vultr,
    ProviderKind::UpCloud,
    ProviderKind::Linode,
];

/// Build a concrete cloud `VpsProvider` from an API key and optional base URL override.
/// When `base_url` is `None`, checks `VULTR_API_BASE_URL` / `UPCLOUD_API_BASE_URL` /
/// `LINODE_API_BASE_URL` before falling back to each provider's default constructor.
pub fn build_cloud_provider_with_key(
    kind: ProviderKind,
    api_key: &str,
    base_url: Option<&str>,
) -> Result<Box<dyn VpsProvider>> {
    let explicit_base = base_url.and_then(non_empty_trimmed);
    match kind {
        ProviderKind::Vultr => {
            let base = explicit_base.or_else(|| non_empty_env("VULTR_API_BASE_URL"));
            let provider = match base {
                Some(url) => VultrProvider::with_base_url(api_key, url)?,
                None => VultrProvider::new(api_key)?,
            };
            Ok(Box::new(provider))
        }
        ProviderKind::UpCloud => {
            let base = explicit_base.or_else(|| non_empty_env("UPCLOUD_API_BASE_URL"));
            let provider = match base {
                Some(url) => UpCloudProvider::with_base_url(api_key, url)?,
                None => UpCloudProvider::new(api_key)?,
            };
            Ok(Box::new(provider))
        }
        ProviderKind::Linode => {
            let base = explicit_base.or_else(|| non_empty_env("LINODE_API_BASE_URL"));
            let provider = match base {
                Some(url) => LinodeProvider::with_base_url(api_key, url)?,
                None => LinodeProvider::new(api_key)?,
            };
            Ok(Box::new(provider))
        }
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => Err(anyhow!(
            "{} does not use a cloud provider API client",
            kind.label()
        )),
    }
}

fn query_providers_with_resolver<F>(
    filter: Option<ProviderKind>,
    mut resolve_key: F,
) -> MultiProviderQueryResult
where
    F: FnMut(ProviderKind) -> Result<Option<String>>,
{
    let mut result = MultiProviderQueryResult::default();
    for kind in CLOUD_PROVIDERS {
        if let Some(target) = filter {
            if kind != target {
                continue;
            }
        }

        let key = match resolve_key(kind) {
            Ok(opt) => match opt.as_deref().and_then(non_empty_trimmed) {
                Some(k) => k,
                None => {
                    result.provider_statuses.push(ProviderQueryStatus {
                        provider: kind,
                        configured: false,
                        instance_count: 0,
                        error: None,
                    });
                    continue;
                }
            },
            Err(err) => {
                result.provider_statuses.push(ProviderQueryStatus {
                    provider: kind,
                    configured: true,
                    instance_count: 0,
                    error: Some(err.to_string()),
                });
                continue;
            }
        };

        let listed = build_cloud_provider_with_key(kind, &key, None)
            .and_then(|provider| provider.list_instances());

        match listed {
            Ok(mut items) => {
                let count = items.len();
                result.instances.append(&mut items);
                result.provider_statuses.push(ProviderQueryStatus {
                    provider: kind,
                    configured: true,
                    instance_count: count,
                    error: None,
                });
            }
            Err(err) => {
                result.provider_statuses.push(ProviderQueryStatus {
                    provider: kind,
                    configured: true,
                    instance_count: 0,
                    error: Some(err.to_string()),
                });
            }
        }
    }

    result.instances.sort_by(|a, b| {
        a.provider
            .label()
            .cmp(b.provider.label())
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.id.cmp(&b.id))
    });
    result
}

/// Query running/provisioned instances across Vultr, UpCloud, and Linode using explicit API keys.
/// Provider errors are isolated into `provider_statuses` so remaining providers still return results.
pub fn query_providers_with_keys(
    vultr_key: Option<&str>,
    upcloud_key: Option<&str>,
    linode_key: Option<&str>,
    filter: Option<ProviderKind>,
) -> MultiProviderQueryResult {
    query_providers_with_resolver(filter, |kind| {
        let key = match kind {
            ProviderKind::Vultr => vultr_key,
            ProviderKind::UpCloud => upcloud_key,
            ProviderKind::Linode => linode_key,
            ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => None,
        };
        Ok(key.map(String::from))
    })
}

/// Query running/provisioned instances across configured cloud providers in `Settings`.
pub fn query_all_providers(
    settings: &Settings,
    filter: Option<ProviderKind>,
) -> MultiProviderQueryResult {
    query_providers_with_resolver(filter, |kind| match kind {
        ProviderKind::Vultr => settings.vultr_api_key(),
        ProviderKind::UpCloud => settings.upcloud_api_token(),
        ProviderKind::Linode => settings.linode_api_token(),
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => Ok(None),
    })
}

/// Destroy an instance on the given cloud provider using an explicit API key and optional base URL.
pub fn destroy_provider_instance_with_key(
    kind: ProviderKind,
    api_key: &str,
    instance_id: &str,
    base_url: Option<&str>,
) -> Result<()> {
    let key = non_empty_trimmed(api_key)
        .ok_or_else(|| anyhow!("API key for {} is not configured", kind.label()))?;
    let validated_id = validate_instance_id(instance_id)?;
    let provider = build_cloud_provider_with_key(kind, &key, base_url)?;
    provider.destroy_instance(validated_id)
}

/// Destroy an instance on the given cloud provider using credentials from `Settings`.
pub fn destroy_provider_instance(
    settings: &Settings,
    kind: ProviderKind,
    instance_id: &str,
) -> Result<()> {
    let validated_id = validate_instance_id(instance_id)?;
    let key = match kind {
        ProviderKind::Vultr => settings
            .vultr_api_key()?
            .as_deref()
            .and_then(non_empty_trimmed)
            .ok_or_else(|| anyhow!("VULTR_API_KEY is not configured"))?,
        ProviderKind::UpCloud => settings
            .upcloud_api_token()?
            .as_deref()
            .and_then(non_empty_trimmed)
            .ok_or_else(|| anyhow!("UPCLOUD_API_TOKEN is not configured"))?,
        ProviderKind::Linode => settings
            .linode_api_token()?
            .as_deref()
            .and_then(non_empty_trimmed)
            .ok_or_else(|| anyhow!("LINODE_API_TOKEN is not configured"))?,
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => {
            return Err(anyhow!(
                "{} does not support destroying cloud instances",
                kind.label()
            ))
        }
    };
    destroy_provider_instance_with_key(kind, &key, validated_id, None)
}

/// Clear active VPS instance session fields if `SessionData.vps_instance_id` matches `instance_id`.
/// Returns `Ok(true)` when matching session state was cleared and saved, or `Ok(false)` otherwise.
pub fn clear_destroyed_session_if_matches(
    session: &SessionState,
    instance_id: &str,
) -> Result<bool> {
    let Some(target) = non_empty_trimmed(instance_id) else {
        return Ok(false);
    };
    let mut data = session.load_session()?;
    if data.vps_instance_id.as_deref().map(str::trim) != Some(target.as_str()) {
        return Ok(false);
    }
    data.vps_provider = None;
    data.vps_instance_id = None;
    data.vps_ip = None;
    data.public_ip = None;
    data.tailscale_ip = None;
    session.save_session(&data)?;
    Ok(true)
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
        instances: std::sync::Mutex<Vec<ProviderInstance>>,
        destroyed_ids: std::sync::Mutex<Vec<String>>,
    }

    impl MockProvider {
        fn new(public_ipv4: Option<&str>) -> Self {
            Self {
                public_ipv4: public_ipv4.map(String::from),
                captured_user_data: std::sync::Mutex::new(None),
                instances: std::sync::Mutex::new(vec![ProviderInstance {
                    provider: ProviderKind::Vultr,
                    id: "inst-123".to_string(),
                    name: "bab-vps".to_string(),
                    status: "active".to_string(),
                    public_ip: public_ipv4.map(String::from),
                    region: Some("ewr".to_string()),
                    plan: Some("vc2-1c-1gb".to_string()),
                    created_at: None,
                }]),
                destroyed_ids: std::sync::Mutex::new(Vec::new()),
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
        fn list_instances(&self) -> Result<Vec<ProviderInstance>> {
            Ok(self.instances.lock().unwrap().clone())
        }
        fn destroy_instance(&self, instance_id: &str) -> Result<()> {
            let id = validate_instance_id(instance_id)?.to_string();
            self.instances.lock().unwrap().retain(|i| i.id != id);
            self.destroyed_ids.lock().unwrap().push(id);
            Ok(())
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
            sudo_password: None,
        }
    }

    #[test]
    fn default_catalog_presets_cover_cloud_providers_and_empty_for_special() {
        let vultr_regions = default_regions_for(ProviderKind::Vultr);
        assert!(vultr_regions.iter().any(|r| r.id == "ewr"));
        assert!(vultr_regions.iter().any(|r| r.id == "nrt"));
        let upcloud_regions = default_regions_for(ProviderKind::UpCloud);
        assert!(upcloud_regions.iter().any(|r| r.id == "us-nyc1"));
        assert!(upcloud_regions.iter().any(|r| r.id == "sg-sin1"));
        let linode_regions = default_regions_for(ProviderKind::Linode);
        assert!(linode_regions.iter().any(|r| r.id == "us-east"));
        assert!(linode_regions.iter().any(|r| r.id == "eu-central"));

        let vultr_plans = default_plans_for(ProviderKind::Vultr);
        assert!(vultr_plans.iter().any(|p| p.id == "vc2-1c-1gb" && p.summary.contains("1024 MB")));
        assert!(vultr_plans.iter().any(|p| p.id == "vc2-4c-8gb" && p.summary.contains("8192 MB")));
        let upcloud_plans = default_plans_for(ProviderKind::UpCloud);
        assert!(upcloud_plans.iter().any(|p| p.id == "1xCPU-1GB" && p.summary.contains("1 vCPU")));
        assert!(upcloud_plans.iter().any(|p| p.id == "4xCPU-8GB" && p.summary.contains("8192 MB")));
        let linode_plans = default_plans_for(ProviderKind::Linode);
        assert!(linode_plans.iter().any(|p| p.id == "g6-nanode-1" && p.summary.contains("1024 MB")));
        assert!(linode_plans.iter().any(|p| p.id == "g6-standard-4" && p.summary.contains("8192 MB")));

        let vultr_images = default_images_for(ProviderKind::Vultr);
        assert!(vultr_images.iter().any(|i| i.id == "2284" && i.name.contains("Ubuntu 24.04")));
        assert!(vultr_images.iter().any(|i| i.name.contains("Debian 12")));
        let upcloud_images = default_images_for(ProviderKind::UpCloud);
        assert!(upcloud_images
            .iter()
            .any(|i| i.id == "01000000-0000-4000-8000-000030240200" && i.name.contains("Ubuntu")));
        assert!(upcloud_images.iter().any(|i| i.name.contains("Debian")));
        let linode_images = default_images_for(ProviderKind::Linode);
        assert!(linode_images.iter().any(|i| i.id == "linode/ubuntu24.04"));
        assert!(linode_images.iter().any(|i| i.id == "linode/debian12"));

        for special in [ProviderKind::ExistingTailscale, ProviderKind::ManualCloudInit] {
            assert!(default_regions_for(special).is_empty());
            assert!(default_plans_for(special).is_empty());
            assert!(default_images_for(special).is_empty());
        }
    }

    #[test]
    fn provision_full_flow_standard_ssh_mode_saves_session() -> Result<()> {
        let provider = MockProvider::new(Some("203.0.113.42"));
        let tmp = tempfile::NamedTempFile::new()?;
        let session = SessionState::new(tmp.path());
        // Seed a stale TAILSCALE_IP to ensure SSH mode clears it.
        session.set_tailscale_ip("100.64.9.9")?;
        let cfg = base_cfg(false);

        let res = provision_full_flow(&provider, None, &cfg, Some(&session))?;
        assert_eq!(res.instance_id, "inst-123");
        assert_eq!(res.ip, "203.0.113.42");
        assert_eq!(res.public_ip, "203.0.113.42");
        assert_eq!(res.tailscale_ip, "");
        assert!(!res.tailscale_mode);

        let user_data = provider.captured_user_data.lock().unwrap().clone().unwrap();
        assert!(user_data.contains("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host"));
        assert!(!user_data.to_ascii_lowercase().contains("tailscale"));

        let loaded = session.load_session()?;
        assert_eq!(loaded.vps_ip.as_deref(), Some("203.0.113.42"));
        assert_eq!(loaded.public_ip.as_deref(), Some("203.0.113.42"));
        assert_eq!(loaded.tailscale_ip, None);
        assert_eq!(loaded.ssh_key.as_deref(), Some("/tmp/bab_ed25519"));
        assert_eq!(loaded.transport_mode.as_deref(), Some("ssh"));
        assert_eq!(loaded.username.as_deref(), Some("deploy"));
        assert_eq!(loaded.vps_provider.as_deref(), Some("vultr"));
        assert_eq!(loaded.vps_instance_id.as_deref(), Some("inst-123"));
        assert_eq!(loaded.tailscale_hostname.as_deref(), Some("bab-vps"));
        assert_eq!(loaded.server_role.as_deref(), Some("caddy"));
        assert_eq!(loaded.vps_region.as_deref(), Some("ewr"));
        assert_eq!(loaded.vps_plan.as_deref(), Some("vc2-1c-1gb"));
        assert_eq!(loaded.vps_image.as_deref(), Some("2284"));
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
        assert_eq!(res.public_ip, "203.0.113.42");
        assert!(res.tailscale_mode);

        let user_data = provider.captured_user_data.lock().unwrap().clone().unwrap();
        assert!(user_data.contains("tailscale up --authkey='tskey-auth-bab'"));

        let loaded = session.load_session()?;
        assert_eq!(loaded.vps_ip.as_deref(), Some("100.64.1.2"));
        assert_eq!(loaded.public_ip.as_deref(), Some("203.0.113.42"));
        assert_eq!(loaded.tailscale_ip.as_deref(), Some("100.64.1.2"));
        assert_eq!(loaded.ssh_key.as_deref(), Some("tailscale"));
        assert_eq!(loaded.transport_mode.as_deref(), Some("tailscale"));
        assert_eq!(loaded.vps_region.as_deref(), Some("ewr"));
        assert_eq!(loaded.vps_plan.as_deref(), Some("vc2-1c-1gb"));
        assert_eq!(loaded.vps_image.as_deref(), Some("2284"));
        Ok(())
    }

    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn new(keys: &[&str]) -> Self {
            let saved = keys
                .iter()
                .map(|k| ((*k).to_string(), std::env::var(k).ok()))
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }

    #[test]
    fn validate_instance_id_accepts_safe_ids_and_rejects_injection() {
        assert_eq!(validate_instance_id("abc-123_XYZ.1").unwrap(), "abc-123_XYZ.1");
        assert_eq!(validate_instance_id("  12345  ").unwrap(), "12345");
        assert_eq!(
            validate_instance_id("00798b85-efdc-41ca-8021-f6ef457b8531").unwrap(),
            "00798b85-efdc-41ca-8021-f6ef457b8531"
        );

        for bad in [
            "",
            "   ",
            "id with space",
            "id\twith\ttab",
            "id\nnewline",
            "id\x00null",
            "foo/bar",
            "foo\\bar",
            "foo?bar=1",
            "foo#frag",
            "foo&bar=2",
            "../other",
            "a..b",
        ] {
            assert!(
                validate_instance_id(bad).is_err(),
                "expected {:?} to be rejected",
                bad
            );
        }
    }

    #[test]
    fn mock_provider_lists_and_destroys_instances() -> Result<()> {
        let provider = MockProvider::new(Some("203.0.113.10"));
        assert_eq!(provider.list_instances()?.len(), 1);
        assert!(provider.destroy_instance("../bad").is_err());
        provider.destroy_instance("  inst-123 ")?;
        assert!(provider.list_instances()?.is_empty());
        assert_eq!(
            *provider.destroyed_ids.lock().unwrap(),
            vec!["inst-123".to_string()]
        );
        Ok(())
    }

    #[test]
    fn query_providers_with_keys_isolates_failures_and_sorts_deterministically() -> Result<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "VULTR_API_BASE_URL",
            "UPCLOUD_API_BASE_URL",
            "LINODE_API_BASE_URL",
        ]);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            for stream_res in listener.incoming() {
                if stop_bg.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = stream_res else {
                    break;
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                    continue;
                }
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if line.trim().is_empty() {
                        break;
                    }
                }
                let path = req_line.split_whitespace().nth(1).unwrap_or("");
                let (status, body) = if path.starts_with("/vultr/instances") {
                    (
                        "200 OK",
                        r#"{"instances":[
                            {"id":"v-2","label":"zeta","status":"active","power_status":"running","main_ip":"203.0.113.2","region":"ewr","plan":"vc2-1c-1gb","date_created":"2025-01-02T00:00:00Z"},
                            {"id":"v-1","label":"alpha","status":"active","power_status":"running","main_ip":"203.0.113.1","region":"ord","plan":"vc2-1c-2gb","date_created":"2025-01-01T00:00:00Z"}
                        ],"meta":{"links":{"next":""}}}"#,
                    )
                } else if path.starts_with("/linode/linode/instances") {
                    ("500 Internal Server Error", r#"{"errors":[{"reason":"boom"}]}"#)
                } else {
                    ("404 Not Found", r#"{"error":"not found"}"#)
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });

        std::env::set_var("VULTR_API_BASE_URL", format!("http://{}/vultr", addr));
        std::env::remove_var("UPCLOUD_API_BASE_URL");
        std::env::set_var("LINODE_API_BASE_URL", format!("http://{}/linode", addr));

        let res = query_providers_with_keys(Some("vultr-key"), None, Some("linode-key"), None);

        stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(addr);
        handle.join().unwrap();

        assert_eq!(res.instances.len(), 2);
        assert_eq!(res.instances[0].id, "v-1");
        assert_eq!(res.instances[0].name, "alpha");
        assert_eq!(res.instances[1].id, "v-2");
        assert_eq!(res.instances[1].name, "zeta");

        assert_eq!(res.provider_statuses.len(), 3);
        let vultr_st = res
            .provider_statuses
            .iter()
            .find(|s| s.provider == ProviderKind::Vultr)
            .unwrap();
        assert_eq!(
            *vultr_st,
            ProviderQueryStatus {
                provider: ProviderKind::Vultr,
                configured: true,
                instance_count: 2,
                error: None,
            }
        );
        let upcloud_st = res
            .provider_statuses
            .iter()
            .find(|s| s.provider == ProviderKind::UpCloud)
            .unwrap();
        assert_eq!(
            *upcloud_st,
            ProviderQueryStatus {
                provider: ProviderKind::UpCloud,
                configured: false,
                instance_count: 0,
                error: None,
            }
        );
        let linode_st = res
            .provider_statuses
            .iter()
            .find(|s| s.provider == ProviderKind::Linode)
            .unwrap();
        assert!(linode_st.configured);
        assert_eq!(linode_st.instance_count, 0);
        assert!(linode_st.error.as_deref().unwrap().contains("500"));

        Ok(())
    }

    #[test]
    fn clear_destroyed_session_if_matches_clears_only_matching_instance() -> Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let session = SessionState::new(tmp.path());
        let seed = SessionData {
            vps_provider: Some("vultr".to_string()),
            vps_instance_id: Some("inst-42".to_string()),
            vps_ip: Some("100.64.0.42".to_string()),
            public_ip: Some("203.0.113.42".to_string()),
            tailscale_ip: Some("100.64.0.42".to_string()),
            username: Some("deploy".to_string()),
            server_role: Some("caddy".to_string()),
            ..SessionData::default()
        };
        session.save_session(&seed)?;

        assert!(!clear_destroyed_session_if_matches(&session, "")?);
        assert!(!clear_destroyed_session_if_matches(&session, "inst-other")?);
        let unchanged = session.load_session()?;
        assert_eq!(unchanged.vps_instance_id.as_deref(), Some("inst-42"));

        assert!(clear_destroyed_session_if_matches(&session, " inst-42 ")?);
        let cleared = session.load_session()?;
        assert_eq!(cleared.vps_provider, None);
        assert_eq!(cleared.vps_instance_id, None);
        assert_eq!(cleared.vps_ip, None);
        assert_eq!(cleared.public_ip, None);
        assert_eq!(cleared.tailscale_ip, None);
        // Unrelated fields remain intact.
        assert_eq!(cleared.username.as_deref(), Some("deploy"));
        assert_eq!(cleared.server_role.as_deref(), Some("caddy"));
        Ok(())
    }

    #[test]
    fn query_all_providers_and_destroy_via_settings() -> Result<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;

        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "VULTR_API_KEY",
            "UPCLOUD_API_TOKEN",
            "LINODE_API_TOKEN",
            "VULTR_API_BASE_URL",
        ]);
        std::env::remove_var("VULTR_API_KEY");
        std::env::remove_var("UPCLOUD_API_TOKEN");
        std::env::remove_var("LINODE_API_TOKEN");

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let handle = thread::spawn(move || {
            let mut seen = Vec::new();
            for step in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                reader.read_line(&mut req_line).unwrap();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                }
                seen.push(req_line.trim().to_string());
                let (status, body) = if step == 0 {
                    (
                        "200 OK",
                        r#"{"instances":[{"id":"v-99","label":"prod-box","status":"active","power_status":"running","main_ip":"203.0.113.99","region":"ewr","plan":"vc2-1c-1gb"}],"meta":{"links":{"next":""}}}"#,
                    )
                } else {
                    ("204 No Content", "")
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
            seen
        });

        let dir = tempfile::tempdir()?;
        let settings = Settings::new(dir.path().join("credentials.enc"));
        settings.set_vultr_api_key("vultr-secret")?;
        std::env::set_var("VULTR_API_BASE_URL", format!("http://{}/v2", addr));

        let queried = query_all_providers(&settings, Some(ProviderKind::Vultr));
        assert_eq!(queried.provider_statuses.len(), 1);
        assert!(queried.provider_statuses[0].configured);
        assert_eq!(queried.provider_statuses[0].instance_count, 1);
        assert_eq!(queried.instances.len(), 1);
        assert_eq!(queried.instances[0].id, "v-99");

        destroy_provider_instance(&settings, ProviderKind::Vultr, "v-99")?;

        let seen = handle.join().unwrap();
        assert!(seen[0].starts_with("GET /v2/instances?per_page=500 "));
        assert!(seen[1].starts_with("DELETE /v2/instances/v-99 "));

        assert!(build_cloud_provider_with_key(ProviderKind::ExistingTailscale, "k", None).is_err());
        assert!(destroy_provider_instance_with_key(ProviderKind::Vultr, "   ", "v-99", None).is_err());
        assert!(destroy_provider_instance(&settings, ProviderKind::Linode, "123").is_err());
        Ok(())
    }

    #[test]
    fn provision_full_flow_with_progress_emits_updates_and_preserves_or_sets_password() -> Result<()>
    {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        struct PollingMockProvider {
            polls: AtomicUsize,
            captured_user_data: std::sync::Mutex<Option<String>>,
        }

        impl VpsProvider for PollingMockProvider {
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
                Ok("inst-prog-1".to_string())
            }
            fn get_instance_status(&self, _instance_id: &str) -> Result<InstanceStatus> {
                let count = self.polls.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    Ok(InstanceStatus {
                        state: "pending".to_string(),
                        public_ipv4: None,
                        ready: false,
                    })
                } else {
                    Ok(InstanceStatus {
                        state: "active".to_string(),
                        public_ipv4: Some("203.0.113.77".to_string()),
                        ready: true,
                    })
                }
            }
            fn list_instances(&self) -> Result<Vec<ProviderInstance>> {
                Ok(vec![])
            }
            fn destroy_instance(&self, _instance_id: &str) -> Result<()> {
                Ok(())
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || {
            let responses = [
                r#"{"key":"tskey-auth-prog"}"#,
                r#"{"devices":[]}"#,
                r#"{"devices":[{"id":"dev-1","hostname":"bab-vps","name":"bab-vps.tail1.ts.net","addresses":["100.64.2.5"],"os":"linux","online":true}]}"#,
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
        let provider = PollingMockProvider {
            polls: AtomicUsize::new(0),
            captured_user_data: std::sync::Mutex::new(None),
        };
        let tmp = tempfile::NamedTempFile::new()?;
        let session = SessionState::new(tmp.path());
        let mut cfg = base_cfg(true);
        cfg.sudo_password = Some("Abc1234567".to_string());

        let mut progress = Vec::new();
        let res =
            provision_full_flow_with_progress(&provider, Some(&ts), &cfg, Some(&session), |msg| {
                progress.push(msg.to_string());
            })?;
        handle.join().unwrap();

        assert_eq!(res.instance_id, "inst-prog-1");
        assert_eq!(res.ip, "100.64.2.5");
        assert_eq!(res.public_ip, "203.0.113.77");

        let ud = provider.captured_user_data.lock().unwrap().clone().unwrap();
        assert!(ud.contains("chpasswd"));
        assert!(ud.contains("Abc1234567"));

        assert!(progress.iter().any(|m| m == "[PROVISION] Creating Tailscale auth key and cloud-init..."));
        assert!(progress.iter().any(|m| m == "[PROVISION] Submitting Vultr create_instance request for 'bab-vps'..."));
        assert!(progress.iter().any(|m| m == "[PROVISION] Instance 'inst-prog-1' created; polling Vultr until active..."));
        assert!(progress.iter().any(|m| m.starts_with("[PROVISION] Polling VM 'inst-prog-1' (state=pending, ip=pending, elapsed=")));
        assert_eq!(
            progress
                .iter()
                .filter(|m| m.starts_with("[PROVISION] VM 'inst-prog-1' is active (public IP: 203.0.113.77); waiting for 'bab-vps' on Tailscale (elapsed="))
                .count(),
            2
        );

        let loaded = session.load_session()?;
        assert_eq!(loaded.sudo_password.as_deref(), Some("Abc1234567"));

        // Verify cfg.sudo_password = None does NOT overwrite existing session.sudo_password.
        let ssh_provider = MockProvider::new(Some("203.0.113.88"));
        let mut ssh_cfg = base_cfg(false);
        ssh_cfg.sudo_password = None;
        provision_full_flow_with_progress(&ssh_provider, None, &ssh_cfg, Some(&session), |_| {})?;
        let after_none = session.load_session()?;
        assert_eq!(after_none.sudo_password.as_deref(), Some("Abc1234567"));

        Ok(())
    }

    #[test]
    fn provision_full_flow_with_progress_preserves_partial_session_on_tailscale_timeout(
    ) -> Result<()> {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            for stream_res in listener.incoming() {
                if stop_bg.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = stream_res else {
                    break;
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut content_len = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
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
                    let _ = reader.read_exact(&mut buf);
                }
                let path = req_line.split_whitespace().nth(1).unwrap_or("");
                let body = if path.ends_with("/keys") {
                    r#"{"key":"tskey-auth-timeout"}"#
                } else {
                    r#"{"devices":[]}"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });

        let ts = TailscaleClient::with_config("ts-api-key", format!("http://{}", addr), "-")?;
        let provider = MockProvider::new(Some("203.0.113.55"));
        let tmp = tempfile::NamedTempFile::new()?;
        let session = SessionState::new(tmp.path());
        session.save_session(&SessionData {
            vps_instance_id: Some("old-inst".to_string()),
            vps_provider: Some("linode".to_string()),
            tailscale_hostname: Some("old-host".to_string()),
            vps_ip: Some("100.64.9.9".to_string()),
            public_ip: Some("198.51.100.99".to_string()),
            tailscale_ip: Some("100.64.9.9".to_string()),
            sudo_password: Some("OldPass999".to_string()),
            ..SessionData::default()
        })?;

        let mut cfg = base_cfg(true);
        cfg.tailscale_timeout = Duration::from_millis(20);
        cfg.poll_interval = Duration::from_millis(2);
        cfg.sudo_password = Some("TimeoutPass1".to_string());

        let err = provision_full_flow_with_progress(&provider, Some(&ts), &cfg, Some(&session), |_| {})
            .unwrap_err();
        assert!(err.to_string().contains("Timed out waiting for device bab-vps"));

        let loaded = session.load_session()?;
        assert_eq!(loaded.vps_instance_id.as_deref(), Some("inst-123"));
        assert_eq!(loaded.public_ip.as_deref(), Some("203.0.113.55"));
        assert_eq!(loaded.vps_provider.as_deref(), Some("vultr"));
        assert_eq!(loaded.tailscale_hostname.as_deref(), Some("bab-vps"));
        assert_eq!(loaded.username.as_deref(), Some("deploy"));
        assert_eq!(loaded.transport_mode.as_deref(), Some("tailscale"));
        assert_eq!(loaded.server_role.as_deref(), Some("caddy"));
        assert_eq!(loaded.vps_region.as_deref(), Some("ewr"));
        assert_eq!(loaded.vps_plan.as_deref(), Some("vc2-1c-1gb"));
        assert_eq!(loaded.vps_image.as_deref(), Some("2284"));
        assert_eq!(loaded.sudo_password.as_deref(), Some("TimeoutPass1"));
        assert_eq!(loaded.vps_ip, None);
        assert_eq!(loaded.tailscale_ip, None);

        // Blank sudo_password on a subsequent timed-out run preserves existing sudo_password and clears stale IPs.
        session.set_vps_ip("100.64.8.8")?;
        session.set_tailscale_ip("100.64.8.8")?;
        session.set_public_ip("198.51.100.88")?;
        cfg.sudo_password = Some("   ".to_string());

        let err2 = provision_full_flow_with_progress(&provider, Some(&ts), &cfg, Some(&session), |_| {})
            .unwrap_err();
        assert!(err2.to_string().contains("Timed out waiting for device bab-vps"));

        stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(addr);
        handle.join().unwrap();

        let preserved = session.load_session()?;
        assert_eq!(preserved.vps_instance_id.as_deref(), Some("inst-123"));
        assert_eq!(preserved.public_ip.as_deref(), Some("203.0.113.55"));
        assert_eq!(preserved.vps_provider.as_deref(), Some("vultr"));
        assert_eq!(preserved.tailscale_hostname.as_deref(), Some("bab-vps"));
        assert_eq!(preserved.sudo_password.as_deref(), Some("TimeoutPass1"));
        assert_eq!(preserved.vps_ip, None);
        assert_eq!(preserved.tailscale_ip, None);

        Ok(())
    }
}
