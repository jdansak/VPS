use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Row, Table, TableState, Wrap,
};
use ratatui::{Frame, Terminal};
use std::cell::RefCell;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use crate::config::{
    default_config_dir, format_utc_timestamp, generate_random_password, LogStore, SessionData,
    SessionState, Settings, MAX_LOG_FILE_BYTES, SUDO_PASSWORD_LEN,
};
use crate::dns::{build_cloudflare_dns_stub_plan, CloudflareDnsConfig};
use crate::providers::{
    build_cloud_provider_with_key, clear_destroyed_session_if_matches, default_images_for,
    default_plans_for, default_regions_for, destroy_provider_instance_with_key,
    provision_full_flow_with_progress, query_providers_with_keys, ProviderInstance, ProviderKind,
    ProviderQueryStatus, ProvisionConfig, VpsProvider,
};
use crate::roles::ServerRole;
use crate::setup::{
    normalize_github_repo, GithubDeployConfig, SetupConfig, SetupRunner, SetupStepKind, StepReport,
};
use crate::tailscale::{
    generate_cloud_init_with_password, generate_ssh_cloud_init_with_password, TailscaleClient,
};
use crate::transport::{
    default_ssh_key_path, ensure_ssh_keypair, read_public_key, SshTransport, TransportMode,
};

const HEADER_TITLE: &str = "Build A Box (bab) - Multi-Provider VPS Provisioner";

const ALL_PROVIDERS: [ProviderKind; 5] = [
    ProviderKind::Vultr,
    ProviderKind::UpCloud,
    ProviderKind::Linode,
    ProviderKind::ExistingTailscale,
    ProviderKind::ManualCloudInit,
];

const HOME_MENU_ITEMS: [&str; 10] = [
    "Select Provider, Location & Size",
    "Select Server Role",
    "Access, User & Transport",
    "Cloudflare DNS",
    "GitHub Repo Deployment",
    "API Key Settings",
    "Build Box with Current Options",
    "Running Systems & Destroy",
    "View Log",
    "Quit",
];

const API_KEY_LABELS: [&str; 6] = [
    "TAILSCALE_API_KEY",
    "VULTR_API_KEY",
    "UPCLOUD_API_TOKEN",
    "LINODE_API_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    "GITHUB_TOKEN",
];

const ACCESS_FIELD_LABELS: [&str; 5] = [
    "Transport Mode",
    "Sudo Username",
    "SSH Key Path",
    "Hostname",
    "Passwordless Sudo",
];

const CF_DNS_FIELD_LABELS: [&str; 5] = [
    "Zone",
    "Record Name",
    "Target IP",
    "Proxied",
    "DNS Enabled",
];

const GITHUB_FIELD_LABELS: [&str; 5] = [
    "Repository",
    "Branch",
    "Deploy Path",
    "Deploy Command",
    "Deploy Enabled",
];

fn toggle_style(enabled: bool) -> Style {
    Style::default()
        .fg(if enabled {
            Color::LightGreen
        } else {
            Color::LightRed
        })
        .add_modifier(Modifier::BOLD)
}

fn default_ssh_key_path_string() -> String {
    default_ssh_key_path()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "~/.ssh/bab_ed25519".to_string())
}

fn provider_display_label(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::ManualCloudInit => "Manual Cloud-Init",
        _ => kind.label(),
    }
}

/// Active screen in the Build A Box (bab) TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Home,
    SelectProvider,
    SelectRole,
    AccessConfig,
    CloudflareDns,
    GithubDeploy,
    ApiKeys,
    BuildBox,
    RunningInstances,
    ViewLog,
}

enum ExistingInstanceOutcome {
    Reuse(String),
    Recreate,
    Abort,
}

/// Editable form state for access transport, sudo admin user, SSH key path, hostname, and passwordless sudo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessForm {
    pub tailscale_mode: bool,
    pub username: String,
    pub ssh_key_path: String,
    pub hostname: String,
    pub sudo_nopasswd: bool,
    pub sudo_password: String,
    pub active_field: usize,
    pub editing: bool,
}

impl Default for AccessForm {
    fn default() -> Self {
        Self {
            tailscale_mode: true,
            username: "deploy".to_string(),
            ssh_key_path: default_ssh_key_path_string(),
            hostname: "bab-node".to_string(),
            sudo_nopasswd: true,
            sudo_password: generate_random_password(SUDO_PASSWORD_LEN),
            active_field: 0,
            editing: false,
        }
    }
}

impl AccessForm {
    /// Initializes access settings from persisted `SessionData` with safe defaults.
    pub fn from_session(session: &SessionData) -> Self {
        let tailscale_mode = session
            .transport_mode
            .as_deref()
            .map(|m| !m.trim().eq_ignore_ascii_case("ssh"))
            .unwrap_or(true);
        let username = session
            .username
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("deploy")
            .to_string();
        let ssh_key_path = session
            .ssh_key
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("tailscale"))
            .map(ToOwned::to_owned)
            .unwrap_or_else(default_ssh_key_path_string);
        let hostname = session
            .tailscale_hostname
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("bab-node")
            .to_string();
        let sudo_nopasswd = match session
            .sudo_nopasswd
            .as_deref()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("false" | "0" | "no" | "off") => false,
            Some("true" | "1" | "yes" | "on") | None => true,
            Some(_) => true,
        };
        let sudo_password = session
            .sudo_password
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| generate_random_password(SUDO_PASSWORD_LEN));

        Self {
            tailscale_mode,
            username,
            ssh_key_path,
            hostname,
            sudo_nopasswd,
            sudo_password,
            active_field: 0,
            editing: false,
        }
    }

    fn transport_mode_str(&self) -> &'static str {
        if self.tailscale_mode {
            "tailscale"
        } else {
            "ssh"
        }
    }

    fn sudo_nopasswd_label(&self) -> &'static str {
        if self.sudo_nopasswd {
            "ON (NOPASSWD:ALL)"
        } else {
            "OFF (password required)"
        }
    }

    fn toggle_sudo_nopasswd(&mut self) {
        self.sudo_nopasswd = !self.sudo_nopasswd;
    }

    fn toggle_transport(&mut self) {
        self.tailscale_mode = !self.tailscale_mode;
        if !self.tailscale_mode
            && (self.ssh_key_path.trim().is_empty()
                || self.ssh_key_path.trim().eq_ignore_ascii_case("tailscale"))
        {
            self.ssh_key_path = default_ssh_key_path_string();
        }
    }

    fn active_text_mut(&mut self) -> Option<&mut String> {
        match self.active_field {
            1 => Some(&mut self.username),
            2 => Some(&mut self.ssh_key_path),
            3 => Some(&mut self.hostname),
            _ => None,
        }
    }
}

/// Editable form state for Cloudflare DNS configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareDnsForm {
    pub zone: String,
    pub record_name: String,
    pub target_mode: String,
    pub proxied: bool,
    pub enabled: bool,
    pub active_field: usize,
    pub editing: bool,
}

impl Default for CloudflareDnsForm {
    fn default() -> Self {
        Self {
            zone: String::new(),
            record_name: "@".to_string(),
            target_mode: "public".to_string(),
            proxied: false,
            enabled: false,
            active_field: 0,
            editing: false,
        }
    }
}

impl CloudflareDnsForm {
    /// Initializes Cloudflare DNS settings from `SessionData`.
    pub fn from_session(session: &SessionData) -> Self {
        let zone = session
            .cf_zone
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        let record_name = session
            .cf_record
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("@")
            .to_string();
        let target_mode = match session.cf_target.as_deref().map(str::trim) {
            Some(t) if t.eq_ignore_ascii_case("tailscale") => "tailscale".to_string(),
            Some(t) if t.eq_ignore_ascii_case("public") => "public".to_string(),
            Some(t)
                if !t.is_empty()
                    && session.tailscale_ip.as_deref().map(str::trim) == Some(t)
                    && session.public_ip.as_deref().map(str::trim) != Some(t) =>
            {
                "tailscale".to_string()
            }
            _ => "public".to_string(),
        };
        let proxied = session
            .cf_proxied
            .as_deref()
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
            .unwrap_or(false);
        let enabled = match session.cf_enabled.as_deref() {
            Some(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => true,
                "false" | "0" | "no" | "off" => false,
                _ => !zone.is_empty(),
            },
            None => !zone.is_empty(),
        };

        Self {
            zone,
            record_name,
            target_mode,
            proxied,
            enabled,
            active_field: 0,
            editing: false,
        }
    }

    fn toggle_target_mode(&mut self) {
        self.target_mode = if self.target_mode == "tailscale" {
            "public".to_string()
        } else {
            "tailscale".to_string()
        };
    }

    fn resolve_target_ip<'a>(&self, session: &'a SessionData) -> Option<&'a str> {
        let non_empty = |opt: &'a Option<String>| -> Option<&'a str> {
            opt.as_deref().map(str::trim).filter(|s| !s.is_empty())
        };
        if self.target_mode == "tailscale" {
            non_empty(&session.tailscale_ip).or_else(|| non_empty(&session.vps_ip))
        } else {
            non_empty(&session.public_ip).or_else(|| non_empty(&session.vps_ip))
        }
    }

    fn active_text_mut(&mut self) -> Option<&mut String> {
        match self.active_field {
            0 => Some(&mut self.zone),
            1 => Some(&mut self.record_name),
            _ => None,
        }
    }
}

/// Editable form state for GitHub repository deployment configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubDeployForm {
    pub repo: String,
    pub branch: String,
    pub deploy_path: String,
    pub deploy_cmd: String,
    pub enabled: bool,
    pub active_field: usize,
    pub editing: bool,
}

impl Default for GithubDeployForm {
    fn default() -> Self {
        Self {
            repo: String::new(),
            branch: "main".to_string(),
            deploy_path: String::new(),
            deploy_cmd: String::new(),
            enabled: false,
            active_field: 0,
            editing: false,
        }
    }
}

impl GithubDeployForm {
    /// Initializes GitHub deployment settings from `SessionData`.
    pub fn from_session(session: &SessionData) -> Self {
        let repo = session
            .github_repo
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        let branch = session
            .github_branch
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("main")
            .to_string();
        let deploy_path = session
            .github_deploy_path
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        let deploy_cmd = session
            .github_deploy_cmd
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .to_string();
        let enabled = match session.github_enabled.as_deref() {
            Some(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => true,
                "false" | "0" | "no" | "off" => false,
                _ => !repo.is_empty(),
            },
            None => !repo.is_empty(),
        };

        Self {
            repo,
            branch,
            deploy_path,
            deploy_cmd,
            enabled,
            active_field: 0,
            editing: false,
        }
    }

    fn active_text_mut(&mut self) -> Option<&mut String> {
        match self.active_field {
            0 => Some(&mut self.repo),
            1 => Some(&mut self.branch),
            2 => Some(&mut self.deploy_path),
            3 => Some(&mut self.deploy_cmd),
            _ => None,
        }
    }
}

/// Editable and masked form state for provider, Tailscale, Cloudflare, and GitHub API keys.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ApiKeyForm {
    pub tailscale: String,
    pub vultr: String,
    pub upcloud: String,
    pub linode: String,
    pub cloudflare: String,
    pub github: String,
    pub active_field: usize,
    pub editing: bool,
}

impl ApiKeyForm {
    /// Masks a secret key for safe on-screen display.
    pub fn mask_key(val: &str) -> String {
        if val.is_empty() {
            return "(not set)".to_string();
        }
        let chars: Vec<char> = val.chars().collect();
        if chars.len() <= 8 {
            return "*".repeat(chars.len());
        }
        let prefix: String = chars[..4].iter().collect();
        let suffix: String = chars[chars.len() - 4..].iter().collect();
        format!("{}****{}", prefix, suffix)
    }

    /// Loads API keys from `Settings`.
    pub fn from_settings(settings: &Settings) -> Result<Self> {
        Ok(Self {
            tailscale: settings
                .tailscale_api_key()?
                .filter(|s| !s.is_empty())
                .unwrap_or_default(),
            vultr: settings
                .vultr_api_key()?
                .filter(|s| !s.is_empty())
                .unwrap_or_default(),
            upcloud: settings
                .upcloud_api_token()?
                .filter(|s| !s.is_empty())
                .unwrap_or_default(),
            linode: settings
                .linode_api_token()?
                .filter(|s| !s.is_empty())
                .unwrap_or_default(),
            cloudflare: settings
                .cloudflare_api_token()?
                .filter(|s| !s.is_empty())
                .unwrap_or_default(),
            github: settings
                .github_token()?
                .filter(|s| !s.is_empty())
                .unwrap_or_default(),
            active_field: 0,
            editing: false,
        })
    }

    /// Saves non-empty API keys back to `Settings` and removes cleared keys.
    pub fn save_to_settings(&self, settings: &Settings) -> Result<()> {
        for (key, val) in [
            ("TAILSCALE_API_KEY", &self.tailscale),
            ("VULTR_API_KEY", &self.vultr),
            ("UPCLOUD_API_TOKEN", &self.upcloud),
            ("LINODE_API_TOKEN", &self.linode),
            ("CLOUDFLARE_API_TOKEN", &self.cloudflare),
            ("GITHUB_TOKEN", &self.github),
        ] {
            let trimmed = val.trim();
            if trimmed.is_empty() {
                settings.remove(key)?;
            } else {
                settings.set(key, trimmed)?;
            }
        }
        Ok(())
    }

    fn value_for(&self, idx: usize) -> &str {
        match idx {
            0 => &self.tailscale,
            1 => &self.vultr,
            2 => &self.upcloud,
            3 => &self.linode,
            4 => &self.cloudflare,
            _ => &self.github,
        }
    }

    fn active_value_mut(&mut self) -> &mut String {
        match self.active_field {
            0 => &mut self.tailscale,
            1 => &mut self.vultr,
            2 => &mut self.upcloud,
            3 => &mut self.linode,
            4 => &mut self.cloudflare,
            _ => &mut self.github,
        }
    }

    fn configured_count(&self) -> usize {
        [
            &self.tailscale,
            &self.vultr,
            &self.upcloud,
            &self.linode,
            &self.cloudflare,
            &self.github,
        ]
        .iter()
        .filter(|v| !v.is_empty())
        .count()
    }
}

/// Interactive state and renderer for the Build A Box (bab) terminal UI.
pub struct TuiApp {
    pub screen: Screen,
    pub should_quit: bool,
    pub home_index: usize,
    pub provider_index: usize,
    pub region_index: usize,
    pub plan_index: usize,
    pub image_index: usize,
    pub role_index: usize,
    pub selected_provider: ProviderKind,
    pub selected_region: Option<String>,
    pub selected_plan: Option<String>,
    pub selected_image: Option<String>,
    pub selected_role: ServerRole,
    pub session: SessionData,
    pub access: AccessForm,
    pub cf_dns: CloudflareDnsForm,
    pub github_deploy: GithubDeployForm,
    pub api_keys: ApiKeyForm,
    pub progress_steps: Vec<(SetupStepKind, Option<bool>)>,
    pub logs: Vec<String>,
    pub status_message: String,
    pub settings_path: Option<PathBuf>,
    pub state_path: Option<PathBuf>,
    pub log_path: Option<PathBuf>,
    pub log_view_lines: Vec<String>,
    pub log_scroll: usize,
    pub build_dry_run: bool,
    pub last_dry_run_target: Option<String>,
    pub running_instances: Vec<ProviderInstance>,
    pub running_statuses: Vec<ProviderQueryStatus>,
    pub running_index: usize,
    pub running_confirm_destroy: bool,
    pub show_password: bool,
}

impl TuiApp {
    /// Creates a new `TuiApp` from in-memory session data and API key form state.
    pub fn new(session: SessionData, api_keys: ApiKeyForm) -> Self {
        let selected_provider = session
            .vps_provider
            .as_deref()
            .and_then(|s| ProviderKind::from_str(s).ok())
            .unwrap_or(ProviderKind::Vultr);
        let provider_index = ALL_PROVIDERS
            .iter()
            .position(|&p| p == selected_provider)
            .unwrap_or(0);

        let regions = default_regions_for(selected_provider);
        let (region_index, selected_region) = match session
            .vps_region
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(r) => {
                let idx = regions.iter().position(|reg| reg.id == r).unwrap_or(0);
                (idx, Some(r.to_string()))
            }
            None => (0, regions.first().map(|reg| reg.id.clone())),
        };

        let plans = default_plans_for(selected_provider);
        let (plan_index, selected_plan) = match session
            .vps_plan
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(p) => {
                let idx = plans.iter().position(|pl| pl.id == p).unwrap_or(0);
                (idx, Some(p.to_string()))
            }
            None => (0, plans.first().map(|pl| pl.id.clone())),
        };

        let images = default_images_for(selected_provider);
        let (image_index, selected_image) = match session
            .vps_image
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(i) => {
                let idx = images.iter().position(|im| im.id == i).unwrap_or(0);
                (idx, Some(i.to_string()))
            }
            None => (0, images.first().map(|im| im.id.clone())),
        };

        let selected_role = session
            .server_role
            .as_deref()
            .and_then(|s| ServerRole::from_str(s).ok())
            .unwrap_or(ServerRole::Vanilla);
        let role_index = ServerRole::all()
            .iter()
            .position(|&r| r == selected_role)
            .unwrap_or(0);

        let access = AccessForm::from_session(&session);
        let cf_dns = CloudflareDnsForm::from_session(&session);
        let github_deploy = GithubDeployForm::from_session(&session);

        let progress_steps = SetupStepKind::all()
            .iter()
            .copied()
            .map(|step| (step, None))
            .collect();

        Self {
            screen: Screen::Home,
            should_quit: false,
            home_index: 0,
            provider_index,
            region_index,
            plan_index,
            image_index,
            role_index,
            selected_provider,
            selected_region,
            selected_plan,
            selected_image,
            selected_role,
            session,
            access,
            cf_dns,
            github_deploy,
            api_keys,
            progress_steps,
            logs: Vec::new(),
            status_message: "Ready".to_string(),
            settings_path: None,
            state_path: None,
            log_path: None,
            log_view_lines: Vec::new(),
            log_scroll: 0,
            build_dry_run: false,
            last_dry_run_target: None,
            running_instances: Vec::new(),
            running_statuses: Vec::new(),
            running_index: 0,
            running_confirm_destroy: false,
            show_password: false,
        }
    }

    /// Loads `Settings` and `SessionState` from explicit paths or default locations.
    pub fn from_paths(settings_path: Option<&Path>, state_path: Option<&Path>) -> Result<Self> {
        let resolved_settings_path = match settings_path {
            Some(p) => p.to_path_buf(),
            None => Settings::default_path()?,
        };
        let resolved_state_path = match state_path {
            Some(p) => p.to_path_buf(),
            None => SessionState::default_path()?,
        };
        let settings = Settings::new(&resolved_settings_path);
        settings.auto_save_env_keys()?;
        let state = SessionState::new(&resolved_state_path);

        let session = state.load_session()?;
        let api_keys = ApiKeyForm::from_settings(&settings)?;
        let resolved_log_path = match std::env::var("BAB_LOG_FILE") {
            Ok(v) if !v.trim().is_empty() => PathBuf::from(v.trim()),
            _ => {
                let from_state = resolved_state_path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(|p| p.join("bab.log"));
                let from_settings = resolved_settings_path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .map(|p| p.join("bab.log"));
                match from_state.or(from_settings) {
                    Some(p) => p,
                    None => LogStore::default_path()?,
                }
            }
        };

        let mut app = Self::new(session, api_keys);
        app.settings_path = Some(resolved_settings_path);
        app.state_path = Some(resolved_state_path);
        app.log_path = Some(resolved_log_path);
        app.reload_log_view();
        Ok(app)
    }

    /// Returns the resolved persistent log path string, or the default tilde path when unset.
    pub fn resolved_log_display(&self) -> String {
        self.log_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "~/.config/bab/bab.log".to_string())
    }

    fn append_persistent_lines(&mut self, lines: Vec<String>) {
        if lines.is_empty() {
            return;
        }
        if let Some(ref path) = self.log_path {
            let _ = LogStore::new(path).append_timestamped_lines(&lines);
        }
        let ts = format_utc_timestamp();
        for line in lines {
            let clean = line.trim_end_matches(['\r', '\n']);
            if clean.is_empty() {
                self.log_view_lines.push(String::new());
            } else {
                self.log_view_lines.push(format!("{} {}", ts, clean));
            }
        }
    }

    /// Appends a single timestamped line to the persistent log store and view buffer.
    pub fn append_persistent_log(&mut self, line: impl AsRef<str>) {
        let trimmed = line.as_ref().trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return;
        }
        self.append_persistent_lines(vec![trimmed.to_string()]);
    }

    /// Appends a header line and non-empty trimmed body lines to the persistent log store and view buffer.
    pub fn append_persistent_log_block(&mut self, header: &str, body: &str) {
        let mut lines = Vec::new();
        let clean_header = header.trim_end_matches(['\r', '\n']);
        if !clean_header.is_empty() {
            lines.push(clean_header.to_string());
        }
        for line in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
            lines.push(format!("  {}", line));
        }
        self.append_persistent_lines(lines);
    }

    fn push_log(&mut self, line: impl Into<String>) {
        let entry = line.into();
        self.append_persistent_log(&entry);
        self.logs.push(entry);
    }

    /// Reloads `log_view_lines` from disk (`bab.log`), falling back to in-memory `logs` when empty.
    pub fn reload_log_view(&mut self) {
        let loaded = match self.log_path {
            Some(ref path) => match LogStore::new(path).read_lines() {
                Ok(lines) if !lines.is_empty() => lines,
                Ok(_) if !self.logs.is_empty() => self.logs.clone(),
                Ok(lines) => lines,
                Err(_) => self.logs.clone(),
            },
            None => {
                if !self.logs.is_empty() {
                    self.logs.clone()
                } else {
                    self.log_view_lines.clone()
                }
            }
        };
        self.log_view_lines = loaded;
        self.log_scroll = self.log_view_lines.len().saturating_sub(1);
    }

    /// Records the outcome of a setup step into progress state and logs.
    pub fn record_step(&mut self, report: &StepReport) {
        if let Some((_, status)) = self
            .progress_steps
            .iter_mut()
            .find(|(step, _)| *step == report.step)
        {
            *status = Some(report.success);
        } else {
            self.progress_steps
                .push((report.step, Some(report.success)));
        }

        let tag = if report.dry_run {
            "DRY-RUN"
        } else if report.success {
            "OK"
        } else {
            "FAIL"
        };
        let header = if report.dry_run {
            format!("[DRY-RUN] {} (simulated)", report.step.title())
        } else {
            format!("[{}] {}", tag, report.step.title())
        };
        if report.dry_run {
            self.logs.push(header.clone());
        } else {
            self.logs.push(header.clone());
            let lines: Vec<&str> = report
                .output
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            let keep = if report.success { 2 } else { 3 };
            let skip = lines.len().saturating_sub(keep);
            for line in &lines[skip..] {
                self.logs.push(format!("  {}", line));
            }
        }
        self.append_persistent_log_block(&header, &report.output);
        self.status_message = format!("{}: {}", report.step.title(), tag);
    }

    /// Processes a single terminal key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
        self.handle_key_with_ui(key, |_| {});
    }

    /// Processes a single terminal key event, invoking `on_update` on UI progress milestones.
    pub fn handle_key_with_ui<F>(&mut self, key: KeyEvent, on_update: F)
    where
        F: FnMut(&Self),
    {
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            return;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
            self.should_quit = true;
            return;
        }

        if self.screen == Screen::ApiKeys && self.api_keys.editing {
            self.handle_api_key_edit(key);
            return;
        }

        if self.screen == Screen::AccessConfig && self.access.editing {
            self.handle_access_edit(key);
            return;
        }

        if self.screen == Screen::CloudflareDns && self.cf_dns.editing {
            self.handle_cf_dns_edit(key);
            return;
        }

        if self.screen == Screen::GithubDeploy && self.github_deploy.editing {
            self.handle_github_deploy_edit(key);
            return;
        }

        if self.screen == Screen::RunningInstances && self.running_confirm_destroy {
            self.handle_running_instances_key(key);
            return;
        }

        if matches!(key.code, KeyCode::Char('q')) {
            if self.screen == Screen::Home {
                self.should_quit = true;
            } else {
                if self.screen == Screen::ApiKeys {
                    self.auto_save_api_keys();
                }
                self.screen = Screen::Home;
            }
            return;
        }

        match self.screen {
            Screen::Home => self.handle_home_key(key),
            Screen::SelectProvider => self.handle_provider_key(key),
            Screen::SelectRole => self.handle_role_key(key),
            Screen::AccessConfig => self.handle_access_nav_key(key),
            Screen::CloudflareDns => self.handle_cf_dns_nav_key(key),
            Screen::GithubDeploy => self.handle_github_deploy_nav_key(key),
            Screen::ApiKeys => self.handle_api_keys_nav_key(key),
            Screen::BuildBox => self.handle_build_box_key_with_ui(key, on_update),
            Screen::RunningInstances => self.handle_running_instances_key(key),
            Screen::ViewLog => self.handle_view_log_key(key.code),
        }
    }

    fn activate_home_selection(&mut self) {
        match self.home_index {
            0 => self.screen = Screen::SelectProvider,
            1 => self.screen = Screen::SelectRole,
            2 => self.screen = Screen::AccessConfig,
            3 => self.screen = Screen::CloudflareDns,
            4 => self.screen = Screen::GithubDeploy,
            5 => self.screen = Screen::ApiKeys,
            6 => self.screen = Screen::BuildBox,
            7 => {
                self.screen = Screen::RunningInstances;
                self.refresh_running_instances();
            }
            8 => {
                self.reload_log_view();
                self.screen = Screen::ViewLog;
            }
            9 => self.should_quit = true,
            _ => {}
        }
    }

    fn handle_home_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.home_index = prev_index(self.home_index, HOME_MENU_ITEMS.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.home_index = next_index(self.home_index, HOME_MENU_ITEMS.len());
            }
            KeyCode::Enter => self.activate_home_selection(),
            KeyCode::Char(c @ '1'..='9') => {
                self.home_index = (c as usize) - ('1' as usize);
                self.activate_home_selection();
            }
            KeyCode::Char('0') => {
                self.home_index = 9;
                self.activate_home_selection();
            }
            _ => {}
        }
    }

    fn handle_view_log_key(&mut self, code: KeyCode) {
        let max_scroll = self.log_view_lines.len().saturating_sub(1);
        match code {
            KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('q') => {
                self.screen = Screen::Home;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.log_scroll = self.log_scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.log_scroll = (self.log_scroll + 1).min(max_scroll);
            }
            KeyCode::PageUp | KeyCode::Char('u') => {
                self.log_scroll = self.log_scroll.saturating_sub(15);
            }
            KeyCode::PageDown | KeyCode::Char('d') => {
                self.log_scroll = self.log_scroll.saturating_add(15).min(max_scroll);
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.log_scroll = 0;
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.log_scroll = max_scroll;
            }
            KeyCode::Char('r') => {
                self.reload_log_view();
                self.status_message = "Reloaded log file from disk".to_string();
            }
            KeyCode::Char('c') => {
                if let Some(ref path) = self.log_path {
                    let _ = LogStore::new(path).clear();
                }
                self.log_view_lines.clear();
                self.logs.clear();
                self.log_scroll = 0;
                self.status_message = "Cleared bab.log".to_string();
            }
            _ => {}
        }
    }

    fn handle_provider_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.provider_index = prev_index(self.provider_index, ALL_PROVIDERS.len());
                self.focus_provider_at(self.provider_index);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.provider_index = next_index(self.provider_index, ALL_PROVIDERS.len());
                self.focus_provider_at(self.provider_index);
            }
            KeyCode::Char(c @ '1'..='5') => {
                let idx = (c as usize) - ('1' as usize);
                self.provider_index = idx;
                self.focus_provider_at(idx);
                self.save_provider_selection();
            }
            KeyCode::Char('r') => {
                self.cycle_region();
            }
            KeyCode::Char('p') => {
                self.cycle_plan();
            }
            KeyCode::Char('i') => {
                self.cycle_image();
            }
            KeyCode::Char('s') => {
                self.save_provider_selection();
            }
            KeyCode::Enter => {
                self.save_provider_selection();
                self.screen = Screen::Home;
            }
            KeyCode::Esc | KeyCode::Char('b') => {
                self.screen = Screen::Home;
            }
            _ => {}
        }
    }

    fn handle_role_key(&mut self, key: KeyEvent) {
        let roles = ServerRole::all();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.role_index = prev_index(self.role_index, roles.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.role_index = next_index(self.role_index, roles.len());
            }
            KeyCode::Char(c @ '1'..='4') => {
                let idx = (c as usize) - ('1' as usize);
                if idx < roles.len() {
                    self.role_index = idx;
                    self.select_role_at(idx);
                }
            }
            KeyCode::Enter => {
                self.select_role_at(self.role_index);
                self.screen = Screen::Home;
            }
            KeyCode::Esc | KeyCode::Char('b') => {
                self.screen = Screen::Home;
            }
            _ => {}
        }
    }

    fn handle_access_nav_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.access.active_field =
                    prev_index(self.access.active_field, ACCESS_FIELD_LABELS.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.access.active_field =
                    next_index(self.access.active_field, ACCESS_FIELD_LABELS.len());
            }
            KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
                if self.access.active_field == 0 =>
            {
                self.access.toggle_transport();
                self.status_message = format!(
                    "Transport mode set to {} (press 's' to save)",
                    self.access.transport_mode_str()
                );
            }
            KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
                if self.access.active_field == 4 =>
            {
                self.access.toggle_sudo_nopasswd();
                self.status_message = format!(
                    "Passwordless sudo set to {} (press 's' to save)",
                    self.access.sudo_nopasswd_label()
                );
            }
            KeyCode::Char('p') => {
                self.access.toggle_sudo_nopasswd();
                self.status_message = format!(
                    "Passwordless sudo set to {} (press 's' to save)",
                    self.access.sudo_nopasswd_label()
                );
            }
            KeyCode::Char('w') => {
                self.toggle_show_password();
            }
            KeyCode::Enter => match self.access.active_field {
                0 => {
                    self.access.toggle_transport();
                    self.status_message = format!(
                        "Transport mode set to {} (press 's' to save)",
                        self.access.transport_mode_str()
                    );
                }
                4 => {
                    self.access.toggle_sudo_nopasswd();
                    self.status_message = format!(
                        "Passwordless sudo set to {} (press 's' to save)",
                        self.access.sudo_nopasswd_label()
                    );
                }
                idx if matches!(idx, 1..=3) => {
                    self.access.editing = true;
                    let label = ACCESS_FIELD_LABELS[idx];
                    self.status_message = format!("Editing {} (Enter/Esc to finish)", label);
                }
                _ => {}
            },
            KeyCode::Char('e') if matches!(self.access.active_field, 1..=3) => {
                self.access.editing = true;
                let label = ACCESS_FIELD_LABELS[self.access.active_field];
                self.status_message = format!("Editing {} (Enter/Esc to finish)", label);
            }
            KeyCode::Char('s') => {
                self.save_access_config();
            }
            KeyCode::Esc | KeyCode::Char('b') => {
                self.screen = Screen::Home;
            }
            _ => {}
        }
    }

    fn handle_access_edit(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.access.editing = false;
                let label = ACCESS_FIELD_LABELS[self.access.active_field];
                self.status_message = format!("Updated {} (press 's' to save)", label);
            }
            KeyCode::Backspace => {
                if let Some(buf) = self.access.active_text_mut() {
                    buf.pop();
                }
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if let Some(buf) = self.access.active_text_mut() {
                    buf.push(c);
                }
            }
            _ => {}
        }
    }

    fn handle_cf_dns_nav_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.cf_dns.active_field =
                    prev_index(self.cf_dns.active_field, CF_DNS_FIELD_LABELS.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.cf_dns.active_field =
                    next_index(self.cf_dns.active_field, CF_DNS_FIELD_LABELS.len());
            }
            KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
                if self.cf_dns.active_field == 2 =>
            {
                self.cf_dns.toggle_target_mode();
                self.status_message = format!(
                    "Cloudflare target set to {} (press 's' to save)",
                    self.cf_dns.target_mode
                );
            }
            KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
                if self.cf_dns.active_field == 3 =>
            {
                self.cf_dns.proxied = !self.cf_dns.proxied;
                self.status_message = format!(
                    "Cloudflare proxied set to {} (press 's' to save)",
                    self.cf_dns.proxied
                );
            }
            KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
                if self.cf_dns.active_field == 4 =>
            {
                self.cf_dns.enabled = !self.cf_dns.enabled;
                self.save_cf_dns();
            }
            KeyCode::Char('t') => {
                self.cf_dns.enabled = !self.cf_dns.enabled;
                self.save_cf_dns();
            }
            KeyCode::Enter => match self.cf_dns.active_field {
                2 => {
                    self.cf_dns.toggle_target_mode();
                    self.status_message = format!(
                        "Cloudflare target set to {} (press 's' to save)",
                        self.cf_dns.target_mode
                    );
                }
                3 => {
                    self.cf_dns.proxied = !self.cf_dns.proxied;
                    self.status_message = format!(
                        "Cloudflare proxied set to {} (press 's' to save)",
                        self.cf_dns.proxied
                    );
                }
                4 => {
                    self.cf_dns.enabled = !self.cf_dns.enabled;
                    self.save_cf_dns();
                }
                idx => {
                    self.cf_dns.editing = true;
                    let label = CF_DNS_FIELD_LABELS[idx];
                    self.status_message = format!("Editing {} (Enter/Esc to finish)", label);
                }
            },
            KeyCode::Char('e') if self.cf_dns.active_field < 2 => {
                self.cf_dns.editing = true;
                let label = CF_DNS_FIELD_LABELS[self.cf_dns.active_field];
                self.status_message = format!("Editing {} (Enter/Esc to finish)", label);
            }
            KeyCode::Char('s') => {
                self.save_cf_dns();
            }
            KeyCode::Esc | KeyCode::Char('b') => {
                self.screen = Screen::Home;
            }
            _ => {}
        }
    }

    fn handle_cf_dns_edit(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.cf_dns.editing = false;
                if self.cf_dns.active_field == 0
                    && !self.cf_dns.zone.trim().is_empty()
                    && self.session.cf_enabled.is_none()
                {
                    self.cf_dns.enabled = true;
                }
                let label = CF_DNS_FIELD_LABELS[self.cf_dns.active_field];
                self.status_message = format!("Updated {} (press 's' to save)", label);
            }
            KeyCode::Backspace => {
                if let Some(buf) = self.cf_dns.active_text_mut() {
                    buf.pop();
                }
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if let Some(buf) = self.cf_dns.active_text_mut() {
                    buf.push(c);
                }
            }
            _ => {}
        }
    }

    fn handle_github_deploy_nav_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.github_deploy.active_field =
                    prev_index(self.github_deploy.active_field, GITHUB_FIELD_LABELS.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.github_deploy.active_field =
                    next_index(self.github_deploy.active_field, GITHUB_FIELD_LABELS.len());
            }
            KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right
                if self.github_deploy.active_field == 4 =>
            {
                self.github_deploy.enabled = !self.github_deploy.enabled;
                self.save_github_deploy();
            }
            KeyCode::Char('t') => {
                self.github_deploy.enabled = !self.github_deploy.enabled;
                self.save_github_deploy();
            }
            KeyCode::Enter => {
                if self.github_deploy.active_field == 4 {
                    self.github_deploy.enabled = !self.github_deploy.enabled;
                    self.save_github_deploy();
                } else {
                    self.github_deploy.editing = true;
                    let label = GITHUB_FIELD_LABELS[self.github_deploy.active_field];
                    self.status_message = format!("Editing {} (Enter/Esc to finish)", label);
                }
            }
            KeyCode::Char('e') if self.github_deploy.active_field < 4 => {
                self.github_deploy.editing = true;
                let label = GITHUB_FIELD_LABELS[self.github_deploy.active_field];
                self.status_message = format!("Editing {} (Enter/Esc to finish)", label);
            }
            KeyCode::Char('s') => {
                self.save_github_deploy();
            }
            KeyCode::Esc | KeyCode::Char('b') => {
                self.screen = Screen::Home;
            }
            _ => {}
        }
    }

    fn handle_github_deploy_edit(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.github_deploy.editing = false;
                if self.github_deploy.active_field == 0
                    && !self.github_deploy.repo.trim().is_empty()
                    && self.session.github_enabled.is_none()
                {
                    self.github_deploy.enabled = true;
                }
                let label = GITHUB_FIELD_LABELS[self.github_deploy.active_field];
                self.status_message = format!("Updated {} (press 's' to save)", label);
            }
            KeyCode::Backspace => {
                if let Some(buf) = self.github_deploy.active_text_mut() {
                    buf.pop();
                }
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if let Some(buf) = self.github_deploy.active_text_mut() {
                    buf.push(c);
                }
            }
            _ => {}
        }
    }

    fn handle_api_keys_nav_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.api_keys.active_field =
                    prev_index(self.api_keys.active_field, API_KEY_LABELS.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.api_keys.active_field =
                    next_index(self.api_keys.active_field, API_KEY_LABELS.len());
            }
            KeyCode::Enter | KeyCode::Char('e') => {
                self.api_keys.editing = true;
                let label = API_KEY_LABELS[self.api_keys.active_field];
                self.status_message =
                    format!("Editing {} (auto-saves encrypted; Enter/Esc to finish)", label);
            }
            KeyCode::Char('s') => {
                self.save_api_keys();
            }
            KeyCode::Esc | KeyCode::Char('b') => {
                self.auto_save_api_keys();
                self.screen = Screen::Home;
            }
            _ => {}
        }
    }

    fn handle_api_key_edit(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.api_keys.editing = false;
                self.auto_save_api_keys();
                let label = API_KEY_LABELS[self.api_keys.active_field];
                self.status_message = format!("Saved {} (auto-encrypted)", label);
            }
            KeyCode::Backspace => {
                self.api_keys.active_value_mut().pop();
                self.auto_save_api_keys();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.api_keys.active_value_mut().push(c);
                self.auto_save_api_keys();
            }
            _ => {}
        }
    }

    fn handle_build_box_key_with_ui<F>(&mut self, key: KeyEvent, on_update: F)
    where
        F: FnMut(&Self),
    {
        match key.code {
            KeyCode::Char('d') | KeyCode::Char(' ') => {
                self.cf_dns.enabled = !self.cf_dns.enabled;
                self.save_cf_dns();
                self.status_message = format!(
                    "Cloudflare DNS toggled {}",
                    if self.cf_dns.enabled { "ON" } else { "OFF" }
                );
            }
            KeyCode::Char('g') => {
                self.github_deploy.enabled = !self.github_deploy.enabled;
                self.save_github_deploy();
                self.status_message = format!(
                    "GitHub Repo Deploy toggled {}",
                    if self.github_deploy.enabled {
                        "ON"
                    } else {
                        "OFF"
                    }
                );
            }
            KeyCode::Char('p') => {
                self.access.toggle_sudo_nopasswd();
                self.save_access_config();
                self.status_message = format!(
                    "Passwordless Sudo toggled {}",
                    self.access.sudo_nopasswd_label()
                );
            }
            KeyCode::Char('w') => {
                self.toggle_show_password();
            }
            KeyCode::Char('r') => {
                self.access.sudo_password = generate_random_password(SUDO_PASSWORD_LEN);
                self.save_access_config();
                if !self.status_message.starts_with("Failed to save") {
                    self.status_message = "Regenerated 10-char sudo password (saved)".to_string();
                }
            }
            KeyCode::Char('n') => {
                self.build_dry_run = !self.build_dry_run;
                self.status_message = format!(
                    "Dry-Run mode {}",
                    if self.build_dry_run {
                        "ON (simulated)"
                    } else {
                        "OFF (live)"
                    }
                );
            }
            KeyCode::Enter | KeyCode::Char('x') => {
                self.execute_build_with_ui(on_update);
            }
            KeyCode::Esc | KeyCode::Char('b') => {
                self.screen = Screen::Home;
            }
            _ => {}
        }
    }

    fn destroy_selected_instance(&mut self) {
        let Some(inst) = self.running_instances.get(self.running_index).cloned() else {
            return;
        };
        let api_key = match inst.provider {
            ProviderKind::Vultr => self.resolve_api_key(&self.api_keys.vultr, "VULTR_API_KEY"),
            ProviderKind::UpCloud => {
                self.resolve_api_key(&self.api_keys.upcloud, "UPCLOUD_API_TOKEN")
            }
            ProviderKind::Linode => {
                self.resolve_api_key(&self.api_keys.linode, "LINODE_API_TOKEN")
            }
            ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => None,
        };
        let Some(key_str) = api_key else {
            let msg = format!("API key for {} is not configured", inst.provider.label());
            self.push_log(format!("[ERROR] {}", msg));
            self.status_message = msg;
            return;
        };
        let matches_session = self
            .session
            .vps_instance_id
            .as_deref()
            .map(str::trim)
            == Some(inst.id.trim());
        let session_ts_host = self.session.tailscale_hostname.clone();
        let session_ts_ip = self.session.tailscale_ip.clone();
        match destroy_provider_instance_with_key(inst.provider, &key_str, &inst.id, None) {
            Ok(()) => {
                self.running_instances.remove(self.running_index);
                if self.running_index >= self.running_instances.len() {
                    self.running_index = self.running_instances.len().saturating_sub(1);
                }
                if let Some(ref path) = self.state_path {
                    let state = SessionState::new(path);
                    if let Err(err) = clear_destroyed_session_if_matches(&state, &inst.id) {
                        self.push_log(format!(
                            "[WARN] Failed to clear session state for {}: {}",
                            inst.id, err
                        ));
                    }
                }
                if matches_session {
                    self.session.vps_provider = None;
                    self.session.vps_instance_id = None;
                    self.session.vps_ip = None;
                    self.session.public_ip = None;
                    self.session.tailscale_ip = None;
                }

                let mut ts_queries: Vec<String> = Vec::new();
                let mut push_query = |raw: &str| {
                    let trimmed = raw.trim();
                    if !trimmed.is_empty()
                        && !ts_queries.iter().any(|q| q.eq_ignore_ascii_case(trimmed))
                    {
                        ts_queries.push(trimmed.to_string());
                    }
                };
                push_query(&inst.name);
                if matches_session {
                    if let Some(ref ts_host) = session_ts_host {
                        push_query(ts_host);
                    }
                    if let Some(ref ts_ip) = session_ts_ip {
                        push_query(ts_ip);
                    }
                }

                let mut removed_devices: Vec<String> = Vec::new();
                if let Some(ts_key) =
                    self.resolve_api_key(&self.api_keys.tailscale, "TAILSCALE_API_KEY")
                {
                    match TailscaleClient::new(ts_key) {
                        Ok(ts_client) => {
                            for query in &ts_queries {
                                match ts_client.delete_matching_devices(query) {
                                    Ok(deleted) => {
                                        for item in deleted {
                                            if !removed_devices.contains(&item) {
                                                removed_devices.push(item);
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        self.push_log(format!(
                                            "[WARN] Tailscale device removal failed for '{}': {}",
                                            query, err
                                        ));
                                        break;
                                    }
                                }
                            }
                        }
                        Err(err) => {
                            self.push_log(format!(
                                "[WARN] Tailscale client init failed during cleanup: {}",
                                err
                            ));
                        }
                    }
                }
                if !removed_devices.is_empty() {
                    self.push_log(format!(
                        "[TAILSCALE] Removed device(s) from tailnet: {}",
                        removed_devices.join(", ")
                    ));
                }

                let base_msg = format!(
                    "Destroyed {} instance {} ({})",
                    inst.provider.label(),
                    inst.name,
                    inst.id
                );
                self.push_log(format!("[DESTROY] {}", base_msg));
                self.status_message = if removed_devices.is_empty() {
                    base_msg
                } else {
                    format!(
                        "{}; removed Tailscale device(s): {}",
                        base_msg,
                        removed_devices.join(", ")
                    )
                };
            }
            Err(err) => {
                let msg = format!("Destroy failed for {}: {}", inst.id, err);
                self.push_log(format!("[ERROR] {}", msg));
                self.status_message = msg;
            }
        }
    }

    fn handle_running_instances_key(&mut self, key: KeyEvent) {
        if self.running_confirm_destroy {
            match key.code {
                KeyCode::Char('y') | KeyCode::Enter => {
                    self.running_confirm_destroy = false;
                    self.destroy_selected_instance();
                }
                KeyCode::Char('n') | KeyCode::Esc | KeyCode::Char('b') | KeyCode::Char('q') => {
                    self.running_confirm_destroy = false;
                    self.status_message = "Destroy cancelled".to_string();
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.running_index = prev_index(self.running_index, self.running_instances.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.running_index = next_index(self.running_index, self.running_instances.len());
            }
            KeyCode::Char('r') => {
                self.refresh_running_instances();
            }
            KeyCode::Char('w') => {
                self.toggle_show_password();
            }
            KeyCode::Char('d') | KeyCode::Char('x') | KeyCode::Delete => {
                if let Some(inst) = self.running_instances.get(self.running_index) {
                    self.running_confirm_destroy = true;
                    self.status_message = format!(
                        "Confirm destroy of {} {} ({})? Press y/Enter or n/Esc",
                        inst.provider.label(),
                        inst.name,
                        inst.id
                    );
                } else {
                    self.status_message = "No instances available to destroy".to_string();
                }
            }
            KeyCode::Esc | KeyCode::Char('b') => {
                self.screen = Screen::Home;
            }
            _ => {}
        }
    }

    fn sync_catalog_for_provider(&mut self, provider: ProviderKind) {
        let regions = default_regions_for(provider);
        if regions.is_empty() {
            self.region_index = 0;
            self.selected_region = None;
        } else if let Some(idx) = self
            .selected_region
            .as_deref()
            .and_then(|id| regions.iter().position(|r| r.id == id))
        {
            self.region_index = idx;
        } else {
            self.region_index = 0;
            self.selected_region = Some(regions[0].id.clone());
        }

        let plans = default_plans_for(provider);
        if plans.is_empty() {
            self.plan_index = 0;
            self.selected_plan = None;
        } else if let Some(idx) = self
            .selected_plan
            .as_deref()
            .and_then(|id| plans.iter().position(|p| p.id == id))
        {
            self.plan_index = idx;
        } else {
            self.plan_index = 0;
            self.selected_plan = Some(plans[0].id.clone());
        }

        let images = default_images_for(provider);
        if images.is_empty() {
            self.image_index = 0;
            self.selected_image = None;
        } else if let Some(idx) = self
            .selected_image
            .as_deref()
            .and_then(|id| images.iter().position(|i| i.id == id))
        {
            self.image_index = idx;
        } else {
            self.image_index = 0;
            self.selected_image = Some(images[0].id.clone());
        }
    }

    fn focus_provider_at(&mut self, idx: usize) {
        let provider = ALL_PROVIDERS[idx];
        let changed = provider != self.selected_provider;
        self.selected_provider = provider;
        if changed {
            self.sync_catalog_for_provider(provider);
        }
        self.status_message = format!(
            "Focused provider: {} (r: region, p: plan, i: image, Enter/s: save)",
            provider_display_label(provider)
        );
    }

    fn cycle_region(&mut self) {
        let regions = default_regions_for(self.selected_provider);
        if regions.is_empty() {
            self.region_index = 0;
            self.selected_region = None;
            self.status_message = format!(
                "{} has no region catalog",
                provider_display_label(self.selected_provider)
            );
            return;
        }
        self.region_index = next_index(self.region_index, regions.len());
        let reg = &regions[self.region_index];
        self.selected_region = Some(reg.id.clone());
        self.status_message = format!(
            "Region: {} ({}, {}) — press 's' or Enter to save",
            reg.id, reg.name, reg.country
        );
    }

    fn cycle_plan(&mut self) {
        let plans = default_plans_for(self.selected_provider);
        if plans.is_empty() {
            self.plan_index = 0;
            self.selected_plan = None;
            self.status_message = format!(
                "{} has no machine size catalog",
                provider_display_label(self.selected_provider)
            );
            return;
        }
        self.plan_index = next_index(self.plan_index, plans.len());
        let plan = &plans[self.plan_index];
        self.selected_plan = Some(plan.id.clone());
        self.status_message = format!(
            "Plan: {} ({}) — press 's' or Enter to save",
            plan.id, plan.summary
        );
    }

    fn cycle_image(&mut self) {
        let images = default_images_for(self.selected_provider);
        if images.is_empty() {
            self.image_index = 0;
            self.selected_image = None;
            self.status_message = format!(
                "{} has no OS image catalog",
                provider_display_label(self.selected_provider)
            );
            return;
        }
        self.image_index = next_index(self.image_index, images.len());
        let img = &images[self.image_index];
        self.selected_image = Some(img.id.clone());
        self.status_message = format!(
            "Image: {} ({}) — press 's' or Enter to save",
            img.id, img.name
        );
    }

    fn save_provider_selection(&mut self) {
        let provider = ALL_PROVIDERS[self.provider_index];
        if provider != self.selected_provider {
            self.selected_provider = provider;
            self.sync_catalog_for_provider(provider);
        } else {
            if default_regions_for(provider).is_empty() {
                self.region_index = 0;
                self.selected_region = None;
            }
            if default_plans_for(provider).is_empty() {
                self.plan_index = 0;
                self.selected_plan = None;
            }
            if default_images_for(provider).is_empty() {
                self.image_index = 0;
                self.selected_image = None;
            }
        }
        self.session.vps_provider = Some(provider.to_string());
        self.session.vps_region = self.selected_region.clone();
        self.session.vps_plan = self.selected_plan.clone();
        self.session.vps_image = self.selected_image.clone();

        if let Some(ref path) = self.state_path {
            let state = SessionState::new(path);
            if let Err(err) = state.save_session(&self.session) {
                self.status_message = format!("Failed to save provider selection: {}", err);
                return;
            }
        }
        self.status_message = format!(
            "Saved provider: {} (region: {}, plan: {}, image: {})",
            provider_display_label(provider),
            self.selected_region.as_deref().unwrap_or("-"),
            self.selected_plan.as_deref().unwrap_or("-"),
            self.selected_image.as_deref().unwrap_or("-"),
        );
    }

    fn select_role_at(&mut self, idx: usize) {
        let role = ServerRole::all()[idx];
        self.selected_role = role;
        self.session.server_role = Some(role.to_string());
        if let Some(ref path) = self.state_path {
            let state = SessionState::new(path);
            if let Err(err) = state.set_server_role(&role.to_string()) {
                self.status_message = format!("Failed to save role: {}", err);
                return;
            }
        }
        self.status_message = format!("Selected role: {}", role.label());
    }

    fn is_tailscale_mode(&self) -> bool {
        self.access.transport_mode_str() != "ssh"
    }

    /// Returns `pw` in plain text when `show_password` is active, otherwise a bullet mask.
    pub fn masked_or_plain_password(&self, pw: &str) -> String {
        if self.show_password {
            pw.to_string()
        } else {
            "•".repeat(pw.chars().count().max(10))
        }
    }

    /// Looks up the recorded encrypted per-box sudo password for `inst`, falling back
    /// to the active session/access password when `inst` matches the active box.
    pub fn password_for_instance(&self, inst: &ProviderInstance) -> Option<String> {
        let settings = self
            .settings_path
            .as_ref()
            .map(Settings::new)
            .or_else(|| Settings::load_default().ok());
        if let Some(settings) = settings {
            if let Ok(Some(pw)) = settings.lookup_instance_password(
                Some(&inst.id),
                Some(&inst.name),
                inst.public_ip.as_deref(),
            ) {
                let trimmed = pw.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }

        let id_matches = !inst.id.trim().is_empty()
            && self
                .session
                .vps_instance_id
                .as_deref()
                .map(str::trim)
                == Some(inst.id.trim());
        let host_matches = !inst.name.trim().is_empty()
            && inst
                .name
                .trim()
                .eq_ignore_ascii_case(self.access.hostname.trim());
        if id_matches || host_matches {
            return self
                .session
                .sudo_password
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToOwned::to_owned)
                .or_else(|| {
                    let pw = self.access.sudo_password.trim();
                    if pw.is_empty() {
                        None
                    } else {
                        Some(pw.to_string())
                    }
                });
        }
        None
    }

    fn toggle_show_password(&mut self) {
        self.show_password = !self.show_password;
        self.status_message = if self.show_password {
            "Sudo password visible".to_string()
        } else {
            "Sudo password hidden".to_string()
        };
    }

    fn ensure_sudo_password(&mut self) -> String {
        let trimmed = self.access.sudo_password.trim();
        if trimmed.is_empty() {
            let generated = generate_random_password(SUDO_PASSWORD_LEN);
            self.access.sudo_password = generated.clone();
            generated
        } else {
            let owned = trimmed.to_string();
            self.access.sudo_password = owned.clone();
            owned
        }
    }

    fn record_current_instance_password(
        &self,
        instance_id: Option<&str>,
        public_ip: Option<&str>,
    ) {
        if let Some(ref path) = self.settings_path {
            let _ = Settings::new(path).record_instance_password(
                instance_id,
                Some(&self.access.hostname),
                public_ip,
                &self.access.sudo_password,
            );
        }
    }

    fn save_access_config(&mut self) {
        let mode = self.access.transport_mode_str().to_string();

        let username = {
            let trimmed = self.access.username.trim();
            if trimmed.is_empty() {
                "deploy".to_string()
            } else {
                trimmed.to_string()
            }
        };
        self.access.username = username.clone();

        let hostname = {
            let trimmed = self.access.hostname.trim();
            if trimmed.is_empty() {
                "bab-node".to_string()
            } else {
                trimmed.to_string()
            }
        };
        self.access.hostname = hostname.clone();

        let ssh_key = if self.access.tailscale_mode {
            "tailscale".to_string()
        } else {
            let trimmed = self.access.ssh_key_path.trim().to_string();
            if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("tailscale") {
                let fallback = default_ssh_key_path_string();
                self.access.ssh_key_path = fallback.clone();
                fallback
            } else {
                self.access.ssh_key_path = trimmed.clone();
                trimmed
            }
        };

        let sudo_nopasswd_str = if self.access.sudo_nopasswd {
            "true"
        } else {
            "false"
        };
        let sudo_password = self.ensure_sudo_password();
        self.session.transport_mode = Some(mode.clone());
        self.session.username = Some(username.clone());
        self.session.ssh_key = Some(ssh_key.clone());
        self.session.tailscale_hostname = Some(hostname.clone());
        self.session.sudo_nopasswd = Some(sudo_nopasswd_str.to_string());
        self.session.sudo_password = Some(sudo_password.clone());

        if let Some(ref path) = self.state_path {
            let state = SessionState::new(path);
            let res = state
                .set_transport_mode(&mode)
                .and_then(|()| state.set_username(&username))
                .and_then(|()| state.set_ssh_key(&ssh_key))
                .and_then(|()| state.set_tailscale_hostname(&hostname))
                .and_then(|()| state.set_sudo_nopasswd(sudo_nopasswd_str))
                .and_then(|()| state.set_sudo_password(&sudo_password));
            if let Err(err) = res {
                self.status_message = format!("Failed to save access settings: {}", err);
                return;
            }
        }
        self.record_current_instance_password(
            self.session.vps_instance_id.as_deref(),
            self.session.public_ip.as_deref(),
        );

        self.status_message = format!(
            "Saved access settings (mode: {}, user: {}, host: {}, sudo_nopasswd: {})",
            mode, username, hostname, sudo_nopasswd_str
        );
    }

    fn save_cf_dns(&mut self) {
        let zone = self.cf_dns.zone.trim().to_string();
        self.cf_dns.zone = zone.clone();

        let record = {
            let trimmed = self.cf_dns.record_name.trim();
            if trimmed.is_empty() {
                "@".to_string()
            } else {
                trimmed.to_string()
            }
        };
        self.cf_dns.record_name = record.clone();

        let target = self.cf_dns.target_mode.clone();
        let proxied = if self.cf_dns.proxied {
            "true".to_string()
        } else {
            "false".to_string()
        };
        let enabled = if self.cf_dns.enabled {
            "true".to_string()
        } else {
            "false".to_string()
        };

        self.session.cf_zone = if zone.is_empty() {
            None
        } else {
            Some(zone.clone())
        };
        self.session.cf_record = Some(record.clone());
        self.session.cf_target = Some(target.clone());
        self.session.cf_proxied = Some(proxied.clone());
        self.session.cf_enabled = Some(enabled);

        if let Some(ref path) = self.state_path {
            let state = SessionState::new(path);
            if let Err(err) = state.save_session(&self.session) {
                self.status_message = format!("Failed to save Cloudflare DNS config: {}", err);
                return;
            }
        }

        self.status_message = format!(
            "Saved Cloudflare DNS (enabled: {}, zone: {}, record: {}, target: {}, proxied: {})",
            if self.cf_dns.enabled { "ON" } else { "OFF" },
            if zone.is_empty() { "(none)" } else { &zone },
            record,
            target,
            proxied
        );
    }

    fn save_github_deploy(&mut self) {
        let repo = self.github_deploy.repo.trim().to_string();
        self.github_deploy.repo = repo.clone();

        let branch = {
            let trimmed = self.github_deploy.branch.trim();
            if trimmed.is_empty() {
                "main".to_string()
            } else {
                trimmed.to_string()
            }
        };
        self.github_deploy.branch = branch.clone();

        let deploy_path = self.github_deploy.deploy_path.trim().to_string();
        self.github_deploy.deploy_path = deploy_path.clone();

        let deploy_cmd = self.github_deploy.deploy_cmd.trim().to_string();
        self.github_deploy.deploy_cmd = deploy_cmd.clone();

        let enabled = if self.github_deploy.enabled {
            "true".to_string()
        } else {
            "false".to_string()
        };

        self.session.github_repo = if repo.is_empty() {
            None
        } else {
            Some(repo.clone())
        };
        self.session.github_branch = Some(branch.clone());
        self.session.github_deploy_path = if deploy_path.is_empty() {
            None
        } else {
            Some(deploy_path.clone())
        };
        self.session.github_deploy_cmd = if deploy_cmd.is_empty() {
            None
        } else {
            Some(deploy_cmd.clone())
        };
        self.session.github_enabled = Some(enabled);

        if let Some(ref path) = self.state_path {
            let state = SessionState::new(path);
            if let Err(err) = state.save_session(&self.session) {
                self.status_message = format!("Failed to save GitHub deploy config: {}", err);
                return;
            }
        }

        self.status_message = format!(
            "Saved GitHub deploy (enabled: {}, repo: {}, branch: {})",
            if self.github_deploy.enabled { "ON" } else { "OFF" },
            if repo.is_empty() { "(none)" } else { &repo },
            branch
        );
    }

    fn save_api_keys(&mut self) {
        let settings_res = match self.settings_path {
            Some(ref p) => Ok(Settings::new(p)),
            None => Settings::load_default(),
        };
        match settings_res.and_then(|s| self.api_keys.save_to_settings(&s)) {
            Ok(()) => {
                self.status_message = "API keys encrypted & saved to credentials.enc".to_string();
            }
            Err(err) => {
                self.status_message = format!("Failed to save API keys: {}", err);
            }
        }
    }

    fn auto_save_api_keys(&mut self) {
        let Some(ref path) = self.settings_path else {
            return;
        };
        let settings = Settings::new(path);
        if let Err(err) = self.api_keys.save_to_settings(&settings) {
            self.status_message = format!("Failed to auto-save API keys: {}", err);
        }
    }

    fn resolve_api_key(&self, form_val: &str, env_name: &str) -> Option<String> {
        let trimmed = form_val.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
        if let Some(ref path) = self.settings_path {
            if let Ok(Some(v)) = Settings::new(path).get(env_name) {
                let t = v.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
            return None;
        }
        if let Ok(v) = std::env::var(env_name) {
            let t = v.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
        if let Ok(settings) = Settings::load_default() {
            if let Ok(Some(v)) = settings.get(env_name) {
                let t = v.trim();
                if !t.is_empty() {
                    return Some(t.to_string());
                }
            }
        }
        None
    }

    fn resolve_ssh_pubkey(&self) -> Result<(PathBuf, String)> {
        let trimmed = self.access.ssh_key_path.trim();
        let key_path = if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("tailscale") {
            PathBuf::from(trimmed)
        } else {
            default_ssh_key_path()?
        };

        match read_public_key(&key_path) {
            Ok(pubkey) => Ok((key_path, pubkey)),
            Err(_) if self.build_dry_run => Ok((
                key_path,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDryRunPlaceholderKey bab@dry-run"
                    .to_string(),
            )),
            Err(_) => {
                let comment = format!("bab@{}", self.access.hostname);
                let pubkey = ensure_ssh_keypair(&key_path, &comment)?;
                Ok((key_path, pubkey))
            }
        }
    }

    /// Queries running cloud VPS instances across Vultr, UpCloud, and Linode.
    pub fn refresh_running_instances(&mut self) {
        let vultr_key = Some(self.api_keys.vultr.as_str()).filter(|s| !s.trim().is_empty());
        let upcloud_key = Some(self.api_keys.upcloud.as_str()).filter(|s| !s.trim().is_empty());
        let linode_key = Some(self.api_keys.linode.as_str()).filter(|s| !s.trim().is_empty());
        let result = query_providers_with_keys(vultr_key, upcloud_key, linode_key, None);
        self.running_instances = result.instances;
        self.running_statuses = result.provider_statuses;
        self.running_confirm_destroy = false;
        if self.running_instances.is_empty() {
            self.running_index = 0;
        } else if self.running_index >= self.running_instances.len() {
            self.running_index = self.running_instances.len() - 1;
        }
        let msg = format!(
            "Found {} running instance(s) across configured providers",
            self.running_instances.len()
        );
        self.push_log(format!("[QUERY] {}", msg));
        self.status_message = msg;
    }

    /// Resolves an already-active provider VM matching `desired_hostname`:
    /// in Tailscale mode, reuses it if registered on Tailscale or destroys it so a fresh build can proceed.
    fn resolve_existing_instance_for_build<F>(
        &mut self,
        provider: &dyn VpsProvider,
        ts_client: Option<&TailscaleClient>,
        existing: ProviderInstance,
        tailscale_mode: bool,
        desired_hostname: &str,
        on_update: &mut F,
    ) -> ExistingInstanceOutcome
    where
        F: FnMut(&Self),
    {
        let existing_pub_ip = existing
            .public_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let resolved_ip = if tailscale_mode {
            match ts_client
                .expect("tailscale client")
                .find_device_ip(desired_hostname)
            {
                Ok(Some(ts_ip)) => {
                    self.session.tailscale_ip = Some(ts_ip.clone());
                    ts_ip
                }
                Ok(None) => {
                    self.push_log(format!(
                        "[PROVISION] Existing {} instance '{}' (id={}) is not on Tailscale; destroying stale instance before creating a fresh one...",
                        provider_display_label(self.selected_provider),
                        desired_hostname,
                        existing.id
                    ));
                    self.status_message = format!(
                        "Destroying stale instance '{}' ({})...",
                        desired_hostname, existing.id
                    );
                    on_update(self);

                    if let Err(err) = provider.destroy_instance(&existing.id) {
                        let msg = format!(
                            "Failed to destroy stale {} instance '{}' (id={}): {}",
                            provider_display_label(self.selected_provider),
                            desired_hostname,
                            existing.id,
                            err
                        );
                        self.push_log(format!("[ERROR] {}", msg));
                        self.status_message = msg;
                        on_update(self);
                        return ExistingInstanceOutcome::Abort;
                    }

                    if self
                        .session
                        .vps_instance_id
                        .as_deref()
                        .map(str::trim)
                        == Some(existing.id.trim())
                    {
                        self.session.vps_instance_id = None;
                        self.session.vps_ip = None;
                        self.session.public_ip = None;
                        self.session.tailscale_ip = None;
                        if let Some(ref path) = self.state_path {
                            let _ = SessionState::new(path).save_session(&self.session);
                        }
                    }
                    return ExistingInstanceOutcome::Recreate;
                }
                Err(err) => {
                    let msg = format!(
                        "Failed to check Tailscale for existing instance '{}': {}",
                        desired_hostname, err
                    );
                    self.push_log(format!("[ERROR] {}", msg));
                    self.status_message = msg;
                    on_update(self);
                    return ExistingInstanceOutcome::Abort;
                }
            }
        } else if let Some(pub_ip) = existing_pub_ip.clone() {
            pub_ip
        } else {
            let msg = format!(
                "Existing {} instance '{}' has no public IP",
                provider_display_label(self.selected_provider),
                desired_hostname
            );
            self.push_log(format!("[ERROR] {}", msg));
            self.status_message = msg;
            on_update(self);
            return ExistingInstanceOutcome::Abort;
        };

        self.session.vps_instance_id = Some(existing.id.clone());
        self.session.public_ip = existing_pub_ip.clone();
        self.session.vps_ip = Some(resolved_ip.clone());
        if let Some(ref path) = self.state_path {
            let _ = SessionState::new(path).save_session(&self.session);
        }
        self.record_current_instance_password(
            Some(&existing.id),
            self.session.public_ip.as_deref(),
        );
        self.push_log(format!(
            "[PROVISION] Reusing existing {} instance '{}' (id={}, public_ip={})",
            provider_display_label(self.selected_provider),
            desired_hostname,
            existing.id,
            existing_pub_ip.as_deref().unwrap_or("(none)")
        ));
        self.status_message = format!("Reusing existing instance '{}'...", desired_hostname);
        on_update(self);
        ExistingInstanceOutcome::Reuse(resolved_ip)
    }

    /// Executes the full provision + 6-step setup + optional Cloudflare DNS plan using current options.
    pub fn execute_build(&mut self) {
        self.execute_build_with_ui(|_| {});
    }

    /// Executes the build pipeline while invoking `on_update` after each progress milestone.
    pub fn execute_build_with_ui<F>(&mut self, mut on_update: F)
    where
        F: FnMut(&Self),
    {
        self.ensure_sudo_password();
        self.save_provider_selection();
        self.save_access_config();
        self.save_cf_dns();
        self.save_github_deploy();

        self.progress_steps = SetupStepKind::all()
            .iter()
            .copied()
            .map(|s| (s, None))
            .collect();
        self.last_dry_run_target = None;
        let mode_tag = if self.build_dry_run { "DRY-RUN" } else { "LIVE" };
        self.push_log(format!(
            "[BUILD] Starting {} build (provider={}, role={}, transport={}, sudo_nopasswd={}, dns={}, github={})",
            mode_tag,
            provider_display_label(self.selected_provider),
            self.selected_role,
            self.access.transport_mode_str(),
            if self.access.sudo_nopasswd { "ON" } else { "OFF" },
            if self.cf_dns.enabled { "ON" } else { "OFF" },
            if self.github_deploy.enabled { "ON" } else { "OFF" }
        ));
        self.status_message = format!("Starting {} build...", mode_tag);
        on_update(self);

        let tailscale_mode = self.is_tailscale_mode();
        let ssh_cred = if !tailscale_mode {
            match self.resolve_ssh_pubkey() {
                Ok(cred) => Some(cred),
                Err(err) => {
                    let msg = format!("Failed to resolve SSH key: {}", err);
                    self.push_log(format!("[ERROR] {}", msg));
                    self.status_message = msg;
                    on_update(self);
                    return;
                }
            }
        } else {
            None
        };

        if self.selected_provider == ProviderKind::ManualCloudInit {
            let script_res: Result<String> = if tailscale_mode {
                let auth_key = if self.build_dry_run {
                    "tskey-auth-DRYRUN".to_string()
                } else {
                    let Some(ts_key) = self.resolve_api_key(&self.api_keys.tailscale, "TAILSCALE_API_KEY")
                    else {
                        let msg = "TAILSCALE_API_KEY is not configured for Manual Cloud-Init".to_string();
                        self.push_log(format!("[ERROR] {}", msg));
                        self.status_message = msg;
                        on_update(self);
                        return;
                    };
                    match TailscaleClient::new(ts_key).and_then(|c| {
                        c.create_auth_key("bab-bootstrap", &["tag:bab".to_string()], false, true, 3600)
                    }) {
                        Ok(k) => k,
                        Err(err) => {
                            let msg = format!("Failed to create Tailscale auth key: {}", err);
                            self.push_log(format!("[ERROR] {}", msg));
                            self.status_message = msg;
                            on_update(self);
                            return;
                        }
                    }
                };
                Ok(generate_cloud_init_with_password(
                    &auth_key,
                    &self.access.hostname,
                    &self.access.username,
                    Some(&self.access.sudo_password),
                ))
            } else {
                let (_, ref pubkey) = ssh_cred.as_ref().expect("resolved above");
                Ok(generate_ssh_cloud_init_with_password(
                    pubkey,
                    &self.access.hostname,
                    &self.access.username,
                    Some(&self.access.sudo_password),
                ))
            };

            match script_res {
                Ok(script) => {
                    self.push_log(format!(
                        "[CLOUD-INIT] Generated cloud-init script ({} bytes)",
                        script.len()
                    ));
                    for line in script.lines().take(20) {
                        self.push_log(format!("  {}", line));
                    }
                    self.status_message = if self.build_dry_run {
                        "Dry-run cloud-init generated (see logs)".to_string()
                    } else {
                        "Cloud-init script generated (see logs)".to_string()
                    };
                }
                Err(err) => {
                    let msg = format!("Cloud-init generation failed: {}", err);
                    self.push_log(format!("[ERROR] {}", msg));
                    self.status_message = msg;
                }
            }
            on_update(self);
            return;
        }

        let target_ip = match self.selected_provider {
            ProviderKind::Vultr | ProviderKind::UpCloud | ProviderKind::Linode => {
                if self.build_dry_run {
                    let sim_ip = self
                        .session
                        .vps_ip
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .unwrap_or_else(|| {
                            if tailscale_mode {
                                "100.64.0.1".to_string()
                            } else {
                                "203.0.113.10".to_string()
                            }
                        });
                    self.last_dry_run_target = Some(sim_ip.clone());
                    self.push_log(format!(
                        "[DRY-RUN] Simulated {} provision -> {}",
                        provider_display_label(self.selected_provider),
                        sim_ip
                    ));
                    on_update(self);
                    sim_ip
                } else {
                    let env_name = self
                        .selected_provider
                        .api_key_env_name()
                        .expect("cloud provider has api key");
                    let form_val = match self.selected_provider {
                        ProviderKind::Vultr => &self.api_keys.vultr,
                        ProviderKind::UpCloud => &self.api_keys.upcloud,
                        ProviderKind::Linode => &self.api_keys.linode,
                        _ => "",
                    };
                    let Some(provider_key) = self.resolve_api_key(form_val, env_name) else {
                        let msg = format!("{} is not configured", env_name);
                        self.push_log(format!("[ERROR] {}", msg));
                        self.status_message = msg;
                        on_update(self);
                        return;
                    };
                    let provider = match build_cloud_provider_with_key(
                        self.selected_provider,
                        &provider_key,
                        None,
                    ) {
                        Ok(p) => p,
                        Err(err) => {
                            let msg = format!("Failed to initialize provider: {}", err);
                            self.push_log(format!("[ERROR] {}", msg));
                            self.status_message = msg;
                            on_update(self);
                            return;
                        }
                    };
                    let ts_client = if tailscale_mode {
                        let Some(ts_key) =
                            self.resolve_api_key(&self.api_keys.tailscale, "TAILSCALE_API_KEY")
                        else {
                            let msg = "TAILSCALE_API_KEY is not configured".to_string();
                            self.push_log(format!("[ERROR] {}", msg));
                            self.status_message = msg;
                            on_update(self);
                            return;
                        };
                        match TailscaleClient::new(ts_key) {
                            Ok(c) => Some(c),
                            Err(err) => {
                                let msg = format!("Failed to initialize Tailscale client: {}", err);
                                self.push_log(format!("[ERROR] {}", msg));
                                self.status_message = msg;
                                on_update(self);
                                return;
                            }
                        }
                    } else {
                        None
                    };

                    let desired_hostname = self.access.hostname.trim().to_string();
                    let existing_instance = match provider.list_instances() {
                        Ok(instances) => instances.into_iter().find(|inst| {
                            let st = inst.status.trim().to_ascii_lowercase();
                            let active = st.contains("active")
                                || st.contains("running")
                                || st.contains("started");
                            active && inst.name.trim().eq_ignore_ascii_case(&desired_hostname)
                        }),
                        Err(err) => {
                            self.push_log(format!(
                                "[PROVISION] Warning: failed to list existing {} instances ({}); creating new",
                                provider_display_label(self.selected_provider),
                                err
                            ));
                            on_update(self);
                            None
                        }
                    };

                    let reused_target_ip = if let Some(existing) = existing_instance {
                        match self.resolve_existing_instance_for_build(
                            provider.as_ref(),
                            ts_client.as_ref(),
                            existing,
                            tailscale_mode,
                            &desired_hostname,
                            &mut on_update,
                        ) {
                            ExistingInstanceOutcome::Reuse(ip) => Some(ip),
                            ExistingInstanceOutcome::Recreate => None,
                            ExistingInstanceOutcome::Abort => return,
                        }
                    } else {
                        None
                    };

                    if let Some(resolved_ip) = reused_target_ip {
                        resolved_ip
                    } else {
                        let region = self
                            .selected_region
                            .clone()
                            .or_else(|| {
                                default_regions_for(self.selected_provider)
                                    .into_iter()
                                    .next()
                                    .map(|r| r.id)
                            })
                            .unwrap_or_default();
                        let plan = self
                            .selected_plan
                            .clone()
                            .or_else(|| {
                                default_plans_for(self.selected_provider)
                                    .into_iter()
                                    .next()
                                    .map(|p| p.id)
                            })
                            .unwrap_or_default();
                        let image_id = self
                            .selected_image
                            .clone()
                            .or_else(|| {
                                default_images_for(self.selected_provider)
                                    .into_iter()
                                    .next()
                                    .map(|i| i.id)
                            })
                            .unwrap_or_default();

                        if tailscale_mode {
                            if let Some(ref ts) = ts_client {
                                match ts.delete_matching_offline_devices(&desired_hostname) {
                                    Ok(removed) if !removed.is_empty() => {
                                        self.push_log(format!(
                                            "[TAILSCALE] Removed stale offline device(s) for '{}': {}",
                                            desired_hostname,
                                            removed.join(", ")
                                        ));
                                        on_update(self);
                                    }
                                    Ok(_) => {}
                                    Err(err) => {
                                        self.push_log(format!(
                                            "[WARN] Failed to prune offline Tailscale devices for '{}': {}",
                                            desired_hostname, err
                                        ));
                                        on_update(self);
                                    }
                                }
                            }
                        }

                        self.push_log(format!(
                            "[PROVISION] Creating {} instance '{}' (region={}, plan={})...",
                            provider_display_label(self.selected_provider),
                            self.access.hostname,
                            region,
                            plan
                        ));
                        self.status_message = format!(
                            "Provisioning {} instance '{}'...",
                            provider_display_label(self.selected_provider),
                            self.access.hostname
                        );
                        on_update(self);

                        let prov_cfg = ProvisionConfig {
                            provider: self.selected_provider,
                            region,
                            plan,
                            image_id,
                            hostname: self.access.hostname.clone(),
                            username: self.access.username.clone(),
                            role: self.selected_role.to_string(),
                            tags: vec!["tag:bab".to_string()],
                            provider_timeout: Duration::from_secs(300),
                            tailscale_timeout: Duration::from_secs(300),
                            poll_interval: Duration::from_secs(5),
                            tailscale_mode,
                            ssh_pubkey: ssh_cred.as_ref().map(|(_, pk)| pk.clone()),
                            ssh_key_path: ssh_cred
                                .as_ref()
                                .map(|(p, _)| p.to_string_lossy().into_owned()),
                            sudo_password: Some(self.access.sudo_password.clone()),
                        };
                        let prov_state = self.state_path.as_ref().map(SessionState::new);
                        let prov_res = {
                            let mut progress_cb = |msg: &str| {
                                self.push_log(msg.to_string());
                                self.status_message = msg.to_string();
                                on_update(self);
                            };
                            provision_full_flow_with_progress(
                                provider.as_ref(),
                                ts_client.as_ref(),
                                &prov_cfg,
                                prov_state.as_ref(),
                                &mut progress_cb,
                            )
                        };
                        match prov_res {
                            Ok(res) => {
                                self.session.vps_instance_id = Some(res.instance_id.clone());
                                self.session.public_ip = if res.public_ip.is_empty() {
                                    None
                                } else {
                                    Some(res.public_ip.clone())
                                };
                                self.session.tailscale_ip = if res.tailscale_ip.is_empty() {
                                    None
                                } else {
                                    Some(res.tailscale_ip.clone())
                                };
                                self.session.vps_ip = Some(res.ip.clone());
                                self.record_current_instance_password(
                                    Some(&res.instance_id),
                                    self.session.public_ip.as_deref(),
                                );
                                self.push_log(format!(
                                    "[PROVISION] {} ready: instance={}, ip={}",
                                    provider_display_label(self.selected_provider),
                                    res.instance_id,
                                    res.ip
                                ));
                                on_update(self);
                                res.ip
                            }
                            Err(err) => {
                                if let Some(ref state) = prov_state {
                                    if let Ok(reloaded) = state.load_session() {
                                        self.session = reloaded;
                                    }
                                }
                                self.record_current_instance_password(
                                    self.session.vps_instance_id.as_deref(),
                                    self.session.public_ip.as_deref(),
                                );
                                let msg = format!("Provision failed: {}", err);
                                self.push_log(format!("[ERROR] {}", msg));
                                self.status_message = msg;
                                on_update(self);
                                return;
                            }
                        }
                    }
                }
            }
            ProviderKind::ExistingTailscale => {
                if let Some(ip) = self
                    .session
                    .vps_ip
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    ip.to_string()
                } else if self.build_dry_run {
                    let sim_ip = if tailscale_mode {
                        "100.64.0.1".to_string()
                    } else {
                        "203.0.113.10".to_string()
                    };
                    self.last_dry_run_target = Some(sim_ip.clone());
                    self.push_log(format!(
                        "[DRY-RUN] Simulated Existing Tailscale target -> {}",
                        sim_ip
                    ));
                    on_update(self);
                    sim_ip
                } else {
                    let msg = "No target IP (VPS_IP) configured for Existing Tailscale".to_string();
                    self.push_log(format!("[ERROR] {}", msg));
                    self.status_message = msg;
                    on_update(self);
                    return;
                }
            }
            ProviderKind::ManualCloudInit => unreachable!("handled above"),
        };

        let github_deploy = if self.github_deploy.enabled {
            let repo = self.github_deploy.repo.trim().to_string();
            if repo.is_empty() {
                self.push_log(
                    "[GITHUB] Warning: GitHub Deploy is ON but GITHUB_REPO is empty".to_string(),
                );
                None
            } else {
                let branch = {
                    let b = self.github_deploy.branch.trim();
                    if b.is_empty() {
                        "main".to_string()
                    } else {
                        b.to_string()
                    }
                };
                let deploy_path = {
                    let p = self.github_deploy.deploy_path.trim();
                    if p.is_empty() {
                        None
                    } else {
                        Some(p.to_string())
                    }
                };
                let deploy_cmd = {
                    let c = self.github_deploy.deploy_cmd.trim();
                    if c.is_empty() {
                        None
                    } else {
                        Some(c.to_string())
                    }
                };
                let github_token = self.resolve_api_key(&self.api_keys.github, "GITHUB_TOKEN");
                self.push_log(format!(
                    "[GITHUB] Deploying '{}' (branch: {})",
                    repo, branch
                ));
                Some(GithubDeployConfig {
                    repo,
                    branch,
                    deploy_path,
                    deploy_cmd,
                    github_token,
                    username: self.access.username.clone(),
                })
            }
        } else {
            self.push_log("[GITHUB] GitHub Repo Deploy is OFF (skipped)".to_string());
            None
        };

        let mut setup_cfg = SetupConfig {
            host: target_ip.clone(),
            ssh_user: "root".to_string(),
            new_username: self.access.username.clone(),
            hostname: self.access.hostname.clone(),
            role: self.selected_role,
            provider_name: self.selected_provider.to_string(),
            tailscale_mode,
            ssh_pubkey: ssh_cred.as_ref().map(|(_, pk)| pk.clone()),
            sudo_nopasswd: self.access.sudo_nopasswd,
            sudo_password: Some(self.access.sudo_password.clone()),
            dry_run: self.build_dry_run,
            github_deploy,
        };

        let transport_mode = if tailscale_mode {
            TransportMode::Tailscale
        } else {
            let key_path = ssh_cred
                .as_ref()
                .map(|(p, _)| p.clone())
                .unwrap_or_else(|| PathBuf::from(&self.access.ssh_key_path));
            TransportMode::SshKey(key_path)
        };
        let transport = SshTransport::from_env(transport_mode);
        let state_opt = if self.build_dry_run {
            None
        } else {
            self.state_path.as_ref().map(SessionState::new)
        };

        if !self.build_dry_run {
            let poll_ms = std::env::var("BAB_SSH_POLL_MS")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .filter(|&ms| ms > 0)
                .unwrap_or(3000);
            let timeout = Duration::from_secs(120);
            let poll_interval = Duration::from_millis(poll_ms);
            let max_attempts = ((timeout.as_millis() / poll_interval.as_millis().max(1)) as u64).max(1);
            let start = std::time::Instant::now();
            let mut attempt = 0u64;

            let mut candidates: Vec<String> = vec!["root".to_string()];
            let trimmed_user = self.access.username.trim().to_string();
            if !trimmed_user.is_empty() && trimmed_user != "root" {
                candidates.push(trimmed_user);
            }

            let connected_user = loop {
                attempt += 1;
                let elapsed_secs = start.elapsed().as_secs();
                let wait_msg = format!(
                    "[SSH] Waiting for SSH readiness on {} (attempt {}/{}, {}s elapsed)...",
                    target_ip, attempt, max_attempts, elapsed_secs
                );
                self.push_log(wait_msg.clone());
                self.status_message = wait_msg;
                on_update(self);

                let mut found: Option<String> = None;
                for user in &candidates {
                    let probe = if user == "root" {
                        "if [ -d /var/lib/cloud ]; then test -f /var/lib/cloud/instance/boot-finished; fi"
                    } else {
                        "sudo -n true && (test ! -d /var/lib/cloud || test -f /var/lib/cloud/instance/boot-finished)"
                    };
                    if let Ok(out) = transport.exec(user, &target_ip, probe) {
                        if out.success() {
                            found = Some(user.clone());
                            break;
                        }
                    }
                }
                if let Some(user) = found {
                    break user;
                }
                if start.elapsed() >= timeout {
                    let msg = format!(
                        "Timed out waiting for SSH readiness on {} (tried: {})",
                        target_ip,
                        candidates.join(", ")
                    );
                    self.push_log(format!("[ERROR] {}", msg));
                    self.status_message = msg;
                    on_update(self);
                    return;
                }
                std::thread::sleep(poll_interval);
            };

            self.push_log(format!(
                "[SSH] Connected to {}@{}",
                connected_user, target_ip
            ));
            setup_cfg.ssh_user = connected_user.clone();
            self.status_message = format!("SSH ready ({}@{})", connected_user, target_ip);
            on_update(self);
        }

        let runner = SetupRunner::new(&transport, state_opt.as_ref());
        let app_cell = RefCell::new((&mut *self, &mut on_update));
        if let Err(err) = runner.run_all_with_callbacks(
            &setup_cfg,
            |idx, total, step| {
                let mut guard = app_cell.borrow_mut();
                let (app, cb) = &mut *guard;
                let msg = format!(
                    "[STEP {}/{}] Running {} on {}...",
                    idx + 1,
                    total,
                    step.title(),
                    target_ip
                );
                app.push_log(msg.clone());
                app.status_message = msg;
                cb(app);
            },
            |report| {
                let mut guard = app_cell.borrow_mut();
                let (app, cb) = &mut *guard;
                app.record_step(report);
                cb(app);
            },
        ) {
            let msg = format!("Build failed: {}", err);
            self.push_log(format!("[ERROR] {}", msg));
            self.status_message = msg;
            on_update(self);
            return;
        }

        if self.cf_dns.enabled {
            let zone = self.cf_dns.zone.trim();
            if !zone.is_empty() {
                let resolved_ip = self
                    .cf_dns
                    .resolve_target_ip(&self.session)
                    .unwrap_or(target_ip.as_str())
                    .to_string();
                let record_name = {
                    let r = self.cf_dns.record_name.trim();
                    if r.is_empty() {
                        "@".to_string()
                    } else {
                        r.to_string()
                    }
                };
                let dns_cfg = CloudflareDnsConfig {
                    zone: zone.to_string(),
                    record_name,
                    target_ip: resolved_ip,
                    proxied: self.cf_dns.proxied,
                };
                let has_token = self
                    .resolve_api_key(&self.api_keys.cloudflare, "CLOUDFLARE_API_TOKEN")
                    .is_some();
                match build_cloudflare_dns_stub_plan(&dns_cfg, has_token) {
                    Ok(plan) => self.push_log(format!("[DNS] {}", plan)),
                    Err(err) => self.push_log(format!("[DNS] Error: {}", err)),
                }
            } else {
                self.push_log("[DNS] Warning: DNS is ON but CF_ZONE is empty".to_string());
            }
        } else {
            self.push_log("[DNS] Cloudflare DNS is OFF (skipped)".to_string());
        }

        if !self.build_dry_run {
            if let Some(ref st) = state_opt {
                if let Err(err) = st.save_session(&self.session) {
                    self.push_log(format!("[WARN] Failed to save session state: {}", err));
                }
            }
        }

        self.status_message = if self.build_dry_run {
            format!("Dry-run build complete (target: {})", target_ip)
        } else {
            format!("Build complete (target: {})", target_ip)
        };
        on_update(self);
    }

    /// Renders the active TUI screen into the given ratatui `Frame`.
    pub fn render_frame(&self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(9),
                Constraint::Length(9),
                Constraint::Length(3),
            ])
            .split(frame.area());

        self.render_header(frame, chunks[0]);
        match self.screen {
            Screen::Home => self.render_home(frame, chunks[1]),
            Screen::SelectProvider => self.render_select_provider(frame, chunks[1]),
            Screen::SelectRole => self.render_select_role(frame, chunks[1]),
            Screen::AccessConfig => self.render_access_config(frame, chunks[1]),
            Screen::CloudflareDns => self.render_cloudflare_dns(frame, chunks[1]),
            Screen::GithubDeploy => self.render_github_deploy(frame, chunks[1]),
            Screen::ApiKeys => self.render_api_keys(frame, chunks[1]),
            Screen::BuildBox => self.render_build_box(frame, chunks[1]),
            Screen::RunningInstances => self.render_running_instances(frame, chunks[1]),
            Screen::ViewLog => self.render_view_log(frame, chunks[1]),
        }
        self.render_bottom_pane(frame, chunks[2]);
        self.render_footer(frame, chunks[3]);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let screen_tag = match self.screen {
            Screen::Home => "Home",
            Screen::SelectProvider => "Provider, Location & Size",
            Screen::SelectRole => "Select Server Role",
            Screen::AccessConfig => "Access, User & Transport",
            Screen::CloudflareDns => "Cloudflare DNS",
            Screen::GithubDeploy => "GitHub Repo Deployment",
            Screen::ApiKeys => "API Key Settings",
            Screen::BuildBox => "Build Box with Current Options",
            Screen::RunningInstances => "Running Systems & Destroy",
            Screen::ViewLog => "View Log",
        };
        let header = Paragraph::new(Line::from(vec![
            Span::styled(
                HEADER_TITLE,
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("  |  "),
            Span::styled(screen_tag, Style::default().fg(Color::Yellow)),
        ]))
        .block(Block::default().borders(Borders::ALL));
        frame.render_widget(header, area);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let hints = match self.screen {
            Screen::Home => "Up/Down or j/k: Navigate | 1-9/0/Enter: Open | q: Quit",
            Screen::SelectProvider => {
                "Up/Down or j/k: Provider | r: Region | p: Plan | i: Image | 1-5/Enter/s: Save | Esc/b/q: Back"
            }
            Screen::SelectRole => {
                "Up/Down or j/k: Move | 1-4: Quick Select | Enter: Confirm | Esc/b/q: Back"
            }
            Screen::AccessConfig if self.access.editing => {
                "Type characters | Backspace: Delete | Enter/Esc: Finish Editing"
            }
            Screen::AccessConfig => {
                "Up/Down/j/k: Field | Space/Enter: Toggle/Edit | p: Sudo | w: Pass | s: Save | Esc/b/q: Back"
            }
            Screen::CloudflareDns if self.cf_dns.editing => {
                "Type characters | Backspace: Delete | Enter/Esc: Finish Editing"
            }
            Screen::CloudflareDns => {
                "Up/Down or j/k: Field | Space/Enter/Left/Right/t: Toggle/Edit | s: Save | Esc/b/q: Back"
            }
            Screen::GithubDeploy if self.github_deploy.editing => {
                "Type characters | Backspace: Delete | Enter/Esc: Finish Editing"
            }
            Screen::GithubDeploy => {
                "Up/Down or j/k: Field | Space/Enter/Left/Right/t: Toggle/Edit | s: Save | Esc/b/q: Back"
            }
            Screen::ApiKeys if self.api_keys.editing => {
                "Type characters | Backspace: Delete | Enter/Esc: Finish Editing (Auto-Saved)"
            }
            Screen::ApiKeys => {
                "Up/Down or j/k: Field | Enter/e: Edit (Auto-Saves) | s: Save | Esc/b/q: Back"
            }
            Screen::BuildBox => {
                "Enter/x: Build | d: DNS | g: GitHub | p: Sudo | w: Pass | r: New Pass | n: Dry | Esc/b/q: Back"
            }
            Screen::RunningInstances if self.running_confirm_destroy => {
                "y/Enter: Confirm Destroy | n/Esc/b/q: Cancel"
            }
            Screen::RunningInstances => {
                "Up/Down/j/k: Select | r: Refresh | w: Show/Hide Pass | d/x/Del: Destroy | Esc/b/q: Back"
            }
            Screen::ViewLog => {
                "Up/Down/j/k/PgUp/PgDn/g/G: Scroll | r: Reload | c: Clear Log | Esc/b/q: Back"
            }
        };
        let footer = Paragraph::new(vec![
            Line::from(Span::styled(hints, Style::default().fg(Color::Gray))),
            Line::from(Span::styled(
                format!("Status: {}", self.status_message),
                Style::default().fg(Color::Green),
            )),
        ])
        .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, area);
    }

    fn render_home(&self, frame: &mut Frame, area: Rect) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(area);

        let items: Vec<ListItem> = HOME_MENU_ITEMS
            .iter()
            .enumerate()
            .map(|(i, label)| {
                let key_num = if i == 9 { 0 } else { i + 1 };
                ListItem::new(format!("[{}] {}", key_num, label))
            })
            .collect();
        let menu = List::new(items)
            .block(
                Block::default()
                    .title("Navigation")
                    .borders(Borders::ALL),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        let mut state = ListState::default();
        state.select(Some(self.home_index));
        frame.render_stateful_widget(menu, cols[0], &mut state);

        let vps_ip = self.session.vps_ip.as_deref().unwrap_or("(not set)");
        let public_ip = self.session.public_ip.as_deref().unwrap_or("(not set)");
        let tailscale_ip = self.session.tailscale_ip.as_deref().unwrap_or("(not set)");
        let vps_provider = self
            .session
            .vps_provider
            .as_deref()
            .unwrap_or(provider_display_label(self.selected_provider));
        let region = self
            .session
            .vps_region
            .as_deref()
            .or(self.selected_region.as_deref())
            .unwrap_or("-");
        let plan = self
            .session
            .vps_plan
            .as_deref()
            .or(self.selected_plan.as_deref())
            .unwrap_or("-");
        let image = self
            .session
            .vps_image
            .as_deref()
            .or(self.selected_image.as_deref())
            .unwrap_or("-");
        let server_role = self
            .session
            .server_role
            .as_deref()
            .unwrap_or(self.selected_role.label());
        let transport_mode = self
            .session
            .transport_mode
            .as_deref()
            .unwrap_or(self.access.transport_mode_str());
        let username = self
            .session
            .username
            .as_deref()
            .unwrap_or(&self.access.username);
        let ssh_key = self
            .session
            .ssh_key
            .as_deref()
            .unwrap_or_else(|| {
                if self.is_tailscale_mode() {
                    "tailscale"
                } else {
                    self.access.ssh_key_path.as_str()
                }
            });
        let hostname = self
            .session
            .tailscale_hostname
            .as_deref()
            .unwrap_or(&self.access.hostname);
        let cf_zone = self
            .session
            .cf_zone
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("(not set)");
        let cf_record = self
            .session
            .cf_record
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.cf_dns.record_name);
        let github_repo = self
            .session
            .github_repo
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("(not set)");
        let github_branch = self
            .session
            .github_branch
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(&self.github_deploy.branch);
        let key_ready = format!(
            "{}/6 configured (TS:{}, V:{}, UC:{}, LN:{}, CF:{}, GH:{})",
            self.api_keys.configured_count(),
            yes_no(!self.api_keys.tailscale.is_empty()),
            yes_no(!self.api_keys.vultr.is_empty()),
            yes_no(!self.api_keys.upcloud.is_empty()),
            yes_no(!self.api_keys.linode.is_empty()),
            yes_no(!self.api_keys.cloudflare.is_empty()),
            yes_no(!self.api_keys.github.is_empty()),
        );

        let summary_lines = vec![
            Line::from(format!(
                "Provider: {} ({}) | Region: {} | Plan: {} | Image: {}",
                provider_display_label(self.selected_provider),
                vps_provider,
                region,
                plan,
                image
            )),
            Line::from(format!(
                "Role: {} ({})",
                self.selected_role.label(),
                server_role
            )),
            Line::from(format!(
                "Transport Mode: {} | Host: {}",
                transport_mode, hostname
            )),
            Line::from(vec![
                Span::raw(format!("Sudo User: {} (passwordless: ", username)),
                Span::styled(
                    if self.access.sudo_nopasswd { "ON" } else { "OFF" },
                    toggle_style(self.access.sudo_nopasswd),
                ),
                Span::raw(")"),
            ]),
            Line::from(format!("SSH Key (SSH_KEY): {}", ssh_key)),
            Line::from(format!(
                "Target IP: {} | Public IP: {} | Tailscale IP: {}",
                vps_ip, public_ip, tailscale_ip
            )),
            Line::from(vec![
                Span::raw(format!("Cloudflare DNS: {} / {} (enabled=", cf_zone, cf_record)),
                Span::styled(
                    if self.cf_dns.enabled { "ON" } else { "OFF" },
                    toggle_style(self.cf_dns.enabled),
                ),
                Span::raw(format!(
                    ", target={}, proxied={})",
                    self.cf_dns.target_mode, self.cf_dns.proxied
                )),
            ]),
            Line::from(vec![
                Span::raw(format!("GitHub Repo: {} (enabled=", github_repo)),
                Span::styled(
                    if self.github_deploy.enabled {
                        "ON"
                    } else {
                        "OFF"
                    },
                    toggle_style(self.github_deploy.enabled),
                ),
                Span::raw(format!(", branch={})", github_branch)),
            ]),
            Line::from(format!("API Keys: {}", key_ready)),
            Line::from(format!(
                "Log File: {} (max {} MB)",
                self.resolved_log_display(),
                MAX_LOG_FILE_BYTES / (1024 * 1024)
            )),
        ];
        let summary = Paragraph::new(summary_lines)
            .block(
                Block::default()
                    .title("Session Summary")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(summary, cols[1]);
    }

    fn render_select_provider(&self, frame: &mut Frame, area: Rect) {
        let cols = if area.width >= 96 {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(28), Constraint::Min(68)])
                .split(area)
        } else {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
                .split(area)
        };

        let left_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(7), Constraint::Min(5)])
            .split(cols[0]);

        let items: Vec<ListItem> = ALL_PROVIDERS
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let mark = if *p == self.selected_provider { "*" } else { " " };
                ListItem::new(format!("[{}] {} {}", i + 1, mark, provider_display_label(*p)))
            })
            .collect();
        let list = List::new(items)
            .block(
                Block::default()
                    .title("VPS Providers")
                    .borders(Borders::ALL),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        let mut state = ListState::default();
        state.select(Some(self.provider_index));
        frame.render_stateful_widget(list, left_rows[0], &mut state);

        let focused = ALL_PROVIDERS[self.provider_index];
        let api_env = focused.api_key_env_name().unwrap_or("None required");
        let meta = Paragraph::new(vec![
            Line::from(format!("Provider: {}", provider_display_label(focused))),
            Line::from(format!("Key ID: {}", focused)),
            Line::from(format!("API Token Var: {}", api_env)),
            Line::from(format!(
                "Selected: {} | {} | {}",
                self.selected_region.as_deref().unwrap_or("-"),
                self.selected_plan.as_deref().unwrap_or("-"),
                self.selected_image.as_deref().unwrap_or("-"),
            )),
            Line::from("Keys: r Region | p Plan | i Image | s/Enter Save"),
        ])
        .block(
            Block::default()
                .title("Provider Details")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(meta, left_rows[1]);

        let regions = default_regions_for(focused);
        let plans = default_plans_for(focused);
        let images = default_images_for(focused);

        let mut lines = Vec::new();
        if regions.is_empty() && plans.is_empty() && images.is_empty() {
            lines.push(Line::from(Span::styled(
                format!("{} does not require cloud catalog selection.", provider_display_label(focused)),
                Style::default().fg(Color::Yellow),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from("Press Enter or 's' to save this provider mode."));
        } else {
            lines.push(Line::from(Span::styled(
                "Regions (Location) [press 'r' to cycle]:",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));
            for pair in regions.chunks(2) {
                let left = {
                    let r = &pair[0];
                    let mark = if self.selected_region.as_deref() == Some(r.id.as_str()) {
                        "[*]"
                    } else {
                        "[ ]"
                    };
                    format!("{} {} ({}, {})", mark, r.id, r.name, r.country)
                };
                if pair.len() == 2 {
                    let r = &pair[1];
                    let mark = if self.selected_region.as_deref() == Some(r.id.as_str()) {
                        "[*]"
                    } else {
                        "[ ]"
                    };
                    let right = format!("{} {} ({}, {})", mark, r.id, r.name, r.country);
                    lines.push(Line::from(format!("{:<32} {}", left, right)));
                } else {
                    lines.push(Line::from(left));
                }
            }

            lines.push(Line::from(Span::styled(
                "Plans (Machine Size) [press 'p' to cycle]:",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));
            for p in &plans {
                let mark = if self.selected_plan.as_deref() == Some(p.id.as_str()) {
                    "[*]"
                } else {
                    "[ ]"
                };
                lines.push(Line::from(format!("{} {} - {}", mark, p.id, p.summary)));
            }

            lines.push(Line::from(Span::styled(
                "OS Images [press 'i' to cycle]:",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));
            for img in &images {
                let mark = if self.selected_image.as_deref() == Some(img.id.as_str()) {
                    "[*]"
                } else {
                    "[ ]"
                };
                lines.push(Line::from(format!(
                    "{} {} ({}) [{}]",
                    mark, img.name, img.vendor, img.id
                )));
            }
        }

        let catalog = Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Catalog: Location, Machine Size & OS Image")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(catalog, cols[1]);
    }

    fn render_select_role(&self, frame: &mut Frame, area: Rect) {
        let cols = if area.width >= 100 {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(44), Constraint::Min(56)])
                .split(area)
        } else {
            Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
                .split(area)
        };

        let roles = ServerRole::all();
        let items: Vec<ListItem> = roles
            .iter()
            .enumerate()
            .map(|(i, role)| {
                let item = ListItem::new(format!("[{}] {}", i + 1, role.label()));
                if *role == self.selected_role {
                    item.style(Style::default().fg(Color::Green))
                } else {
                    item
                }
            })
            .collect();
        let list = List::new(items)
            .block(
                Block::default()
                    .title("Server Roles")
                    .borders(Borders::ALL),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            );
        let mut state = ListState::default();
        state.select(Some(self.role_index));
        frame.render_stateful_widget(list, cols[0], &mut state);

        let role = roles[self.role_index];
        let is_tailscale_mode = self.is_tailscale_mode();
        let mut lines = vec![
            Line::from(Span::styled(
                role.label(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(format!("Identifier: {}", role)),
            Line::from(format!(
                "Transport Mode: {}",
                if is_tailscale_mode { "tailscale" } else { "ssh" }
            )),
            Line::from(""),
            Line::from(role.description()),
            Line::from(""),
            Line::from("Open Ports:"),
        ];
        for port in role.open_ports_for_mode(is_tailscale_mode) {
            lines.push(Line::from(format!("  - {}", port)));
        }
        lines.push(Line::from(""));
        if role.is_stub() {
            lines.push(Line::from(Span::styled(
                "Status: Placeholder stub (to be built in a later phase)",
                Style::default().fg(Color::Yellow),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "Status: Ready for provisioning",
                Style::default().fg(Color::Green),
            )));
        }
        lines.push(Line::from(format!(
            "Selected Role: {}",
            self.selected_role.label()
        )));

        let details_borders = if area.width >= 100 {
            Borders::TOP | Borders::BOTTOM | Borders::RIGHT
        } else {
            Borders::ALL
        };
        let details = Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Role Details")
                    .borders(details_borders),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(details, cols[1]);
    }

    fn render_access_config(&self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Min(7),
                Constraint::Length(6),
            ])
            .split(area);

        let help = Paragraph::new(vec![
            Line::from("Configure remote transport, sudo/wheel admin user, SSH key path, and hostname."),
            Line::from("Note: Sudo Username creates the non-root sudo (Debian/Ubuntu) / wheel (RHEL) admin user."),
        ])
        .block(
            Block::default()
                .title("Access, User & Transport Help")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(help, rows[0]);

        let transport_display = if self.access.tailscale_mode {
            "tailscale (Tailscale Mesh — press Space/Enter/Left/Right to toggle)"
        } else {
            "ssh (Standard SSH Key — press Space/Enter/Left/Right to toggle)"
        };
        let ssh_key_display = if self.access.tailscale_mode {
            format!(
                "{} (inactive in tailscale mode; saves SSH_KEY=\"tailscale\")",
                self.access.ssh_key_path
            )
        } else {
            self.access.ssh_key_path.clone()
        };

        let edit_tag = |idx: usize| -> &'static str {
            if self.access.editing && self.access.active_field == idx {
                " [EDITING]"
            } else {
                ""
            }
        };

        let items = vec![
            ListItem::new(format!(
                "{}: {}",
                ACCESS_FIELD_LABELS[0], transport_display
            )),
            ListItem::new(format!(
                "{} (USERNAME): {}{}",
                ACCESS_FIELD_LABELS[1],
                self.access.username,
                edit_tag(1)
            )),
            ListItem::new(format!(
                "{} (SSH_KEY): {}{}",
                ACCESS_FIELD_LABELS[2],
                ssh_key_display,
                edit_tag(2)
            )),
            ListItem::new(format!(
                "{} (TAILSCALE_HOSTNAME): {}{}",
                ACCESS_FIELD_LABELS[3],
                self.access.hostname,
                edit_tag(3)
            )),
            ListItem::new(Line::from(vec![
                Span::raw(format!("{} (SUDO_NOPASSWD): ", ACCESS_FIELD_LABELS[4])),
                Span::styled(
                    self.access.sudo_nopasswd_label(),
                    toggle_style(self.access.sudo_nopasswd),
                ),
                Span::raw(" (Space/Enter/Left/Right or 'p' to toggle)"),
            ])),
        ];

        let list = List::new(items)
            .block(
                Block::default()
                    .title("Access, User & Transport Settings")
                    .borders(Borders::ALL),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        let mut state = ListState::default();
        state.select(Some(self.access.active_field));
        frame.render_stateful_widget(list, rows[1], &mut state);

        let effective_ssh_key = if self.access.tailscale_mode {
            "tailscale"
        } else {
            self.access.ssh_key_path.as_str()
        };
        let preview = Paragraph::new(vec![
            Line::from(format!(
                "TRANSPORT_MODE: {}  |  TAILSCALE_HOSTNAME: {}",
                self.access.transport_mode_str(),
                self.access.hostname
            )),
            Line::from(format!(
                "USERNAME:       {}  |  SUDO_PASSWORD:  {} ('w': Show/Hide)",
                self.access.username,
                self.masked_or_plain_password(&self.access.sudo_password)
            )),
            Line::from(format!("SSH_KEY:        {}", effective_ssh_key)),
            Line::from(vec![
                Span::raw("SUDO_NOPASSWD:  "),
                Span::styled(
                    if self.access.sudo_nopasswd {
                        "true"
                    } else {
                        "false"
                    },
                    toggle_style(self.access.sudo_nopasswd),
                ),
            ]),
        ])
        .block(
            Block::default()
                .title("Values Saved on 's'")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(preview, rows[2]);
    }

    fn render_cloudflare_dns(&self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(7),
                Constraint::Length(7),
            ])
            .split(area);

        let help = Paragraph::new(
            "Configure Cloudflare DNS A-record settings (CF_ZONE, CF_RECORD, CF_TARGET, CF_PROXIED, CF_ENABLED).",
        )
        .block(
            Block::default()
                .title("Cloudflare DNS Help")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(help, rows[0]);

        let edit_tag = |idx: usize| -> &'static str {
            if self.cf_dns.editing && self.cf_dns.active_field == idx {
                " [EDITING]"
            } else {
                ""
            }
        };

        let resolved_ip = self.cf_dns.resolve_target_ip(&self.session);
        let target_display = format!(
            "{} (resolved: {}) — Space/Enter/Left/Right to toggle",
            self.cf_dns.target_mode,
            resolved_ip.unwrap_or("(no IP in session)")
        );
        let proxied_display = format!(
            "{} — Space/Enter/Left/Right to toggle",
            self.cf_dns.proxied
        );

        let items = vec![
            ListItem::new(format!(
                "{} (CF_ZONE): {}{}",
                CF_DNS_FIELD_LABELS[0],
                if self.cf_dns.zone.is_empty() {
                    "(not set)"
                } else {
                    self.cf_dns.zone.as_str()
                },
                edit_tag(0)
            )),
            ListItem::new(format!(
                "{} (CF_RECORD): {}{}",
                CF_DNS_FIELD_LABELS[1],
                self.cf_dns.record_name,
                edit_tag(1)
            )),
            ListItem::new(format!(
                "{} (CF_TARGET): {}",
                CF_DNS_FIELD_LABELS[2], target_display
            )),
            ListItem::new(format!(
                "{} (CF_PROXIED): {}",
                CF_DNS_FIELD_LABELS[3], proxied_display
            )),
            ListItem::new(Line::from(vec![
                Span::raw(format!("{} (CF_ENABLED): ", CF_DNS_FIELD_LABELS[4])),
                Span::styled(
                    if self.cf_dns.enabled { "ON" } else { "OFF" },
                    toggle_style(self.cf_dns.enabled),
                ),
                Span::raw(" — Space/Enter/Left/Right or 't' to toggle"),
            ])),
        ];

        let list = List::new(items)
            .block(
                Block::default()
                    .title("Cloudflare DNS Settings")
                    .borders(Borders::ALL),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        let mut state = ListState::default();
        state.select(Some(self.cf_dns.active_field));
        frame.render_stateful_widget(list, rows[1], &mut state);

        let effective_record = if self.cf_dns.record_name.trim().is_empty() {
            "@".to_string()
        } else {
            self.cf_dns.record_name.trim().to_string()
        };
        let cfg = CloudflareDnsConfig {
            zone: self.cf_dns.zone.trim().to_string(),
            record_name: effective_record,
            target_ip: resolved_ip.unwrap_or("").to_string(),
            proxied: self.cf_dns.proxied,
        };
        let has_token = !self.api_keys.cloudflare.is_empty();
        let preview_line = match build_cloudflare_dns_stub_plan(&cfg, has_token) {
            Ok(plan) => {
                let prefix = if self.cf_dns.enabled {
                    ""
                } else {
                    "[DNS OFF] "
                };
                Line::from(Span::styled(
                    format!("{}{}", prefix, plan),
                    Style::default().fg(if self.cf_dns.enabled {
                        Color::Green
                    } else {
                        Color::DarkGray
                    }),
                ))
            }
            Err(err) => Line::from(Span::styled(
                format!("Preview pending: {}", err),
                Style::default().fg(Color::Yellow),
            )),
        };

        let details = Paragraph::new(vec![
            Line::from(vec![
                Span::raw("CF_ENABLED="),
                Span::styled(
                    if self.cf_dns.enabled { "ON" } else { "OFF" },
                    toggle_style(self.cf_dns.enabled),
                ),
                Span::raw(format!(
                    " | CF_ZONE={} | CF_RECORD={} | CF_TARGET={} | CF_PROXIED={}",
                    if self.cf_dns.zone.trim().is_empty() {
                        "(not set)"
                    } else {
                        self.cf_dns.zone.trim()
                    },
                    cfg.record_name,
                    self.cf_dns.target_mode,
                    self.cf_dns.proxied
                )),
            ]),
            Line::from(format!(
                "CLOUDFLARE_API_TOKEN: {} | Resolved Target IP: {}",
                yes_no(has_token),
                resolved_ip.unwrap_or("(none)")
            )),
            preview_line,
        ])
        .block(
            Block::default()
                .title("Live Plan Preview (Saved on 's')")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(details, rows[2]);
    }

    fn render_github_deploy(&self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(6),
                Constraint::Length(7),
            ])
            .split(area);

        let help = Paragraph::new(
            "Configure GitHub repository deployment (owner/repo or URL, branch, optional path & command).",
        )
        .block(
            Block::default()
                .title("GitHub Repo Deployment Help")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(help, rows[0]);

        let edit_tag = |idx: usize| -> &'static str {
            if self.github_deploy.editing && self.github_deploy.active_field == idx {
                " [EDITING]"
            } else {
                ""
            }
        };

        let items = vec![
            ListItem::new(format!(
                "{} (GITHUB_REPO): {}{}",
                GITHUB_FIELD_LABELS[0],
                if self.github_deploy.repo.is_empty() {
                    "(not set)"
                } else {
                    self.github_deploy.repo.as_str()
                },
                edit_tag(0)
            )),
            ListItem::new(format!(
                "{} (GITHUB_BRANCH): {}{}",
                GITHUB_FIELD_LABELS[1],
                self.github_deploy.branch,
                edit_tag(1)
            )),
            ListItem::new(format!(
                "{} (GITHUB_DEPLOY_PATH): {}{}",
                GITHUB_FIELD_LABELS[2],
                if self.github_deploy.deploy_path.is_empty() {
                    "(auto: /home/<user>/apps/<repo>)"
                } else {
                    self.github_deploy.deploy_path.as_str()
                },
                edit_tag(2)
            )),
            ListItem::new(format!(
                "{} (GITHUB_DEPLOY_CMD): {}{}",
                GITHUB_FIELD_LABELS[3],
                if self.github_deploy.deploy_cmd.is_empty() {
                    "(auto-detect docker compose)"
                } else {
                    self.github_deploy.deploy_cmd.as_str()
                },
                edit_tag(3)
            )),
            ListItem::new(Line::from(vec![
                Span::raw(format!("{} (GITHUB_ENABLED): ", GITHUB_FIELD_LABELS[4])),
                Span::styled(
                    if self.github_deploy.enabled {
                        "ON"
                    } else {
                        "OFF"
                    },
                    toggle_style(self.github_deploy.enabled),
                ),
                Span::raw(" — Space/Enter/Left/Right or 't' to toggle"),
            ])),
        ];

        let list = List::new(items)
            .block(
                Block::default()
                    .title("GitHub Repo Deployment Settings")
                    .borders(Borders::ALL),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        let mut state = ListState::default();
        state.select(Some(self.github_deploy.active_field));
        frame.render_stateful_widget(list, rows[1], &mut state);

        let effective_branch = if self.github_deploy.branch.trim().is_empty() {
            "main"
        } else {
            self.github_deploy.branch.trim()
        };
        let repo_preview = if self.github_deploy.repo.trim().is_empty() {
            Line::from(Span::styled(
                "Repository not configured yet (press Enter/e to edit, 's' to save).",
                Style::default().fg(Color::Yellow),
            ))
        } else {
            match normalize_github_repo(&self.github_deploy.repo) {
                Ok((url, name)) => {
                    let target_path = if self.github_deploy.deploy_path.trim().is_empty() {
                        format!("/home/{}/apps/{}", self.access.username, name)
                    } else {
                        self.github_deploy.deploy_path.trim().to_string()
                    };
                    Line::from(Span::styled(
                        format!("Normalized: {} -> {} (branch: {})", url, target_path, effective_branch),
                        Style::default().fg(Color::Green),
                    ))
                }
                Err(err) => Line::from(Span::styled(
                    format!("Invalid repository: {}", err),
                    Style::default().fg(Color::Red),
                )),
            }
        };

        let preview = Paragraph::new(vec![
            Line::from(vec![
                Span::raw("GITHUB_ENABLED="),
                Span::styled(
                    if self.github_deploy.enabled {
                        "ON"
                    } else {
                        "OFF"
                    },
                    toggle_style(self.github_deploy.enabled),
                ),
                Span::raw(format!(
                    " | GITHUB_REPO={} | GITHUB_BRANCH={}",
                    if self.github_deploy.repo.trim().is_empty() {
                        "(not set)"
                    } else {
                        self.github_deploy.repo.trim()
                    },
                    effective_branch
                )),
            ]),
            Line::from(format!(
                "GITHUB_TOKEN: {} | Deploy Cmd: {}",
                yes_no(!self.api_keys.github.is_empty()),
                if self.github_deploy.deploy_cmd.trim().is_empty() {
                    "(auto)"
                } else {
                    self.github_deploy.deploy_cmd.trim()
                }
            )),
            repo_preview,
        ])
        .block(
            Block::default()
                .title("Deployment Preview (Saved on 's')")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(preview, rows[2]);
    }

    fn render_api_keys(&self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Min(8)])
            .split(area);

        let (settings_display, master_key_display, parent_dir_display) = {
            let settings_obj = match self.settings_path {
                Some(ref p) => Some(Settings::new(p)),
                None => Settings::load_default().ok(),
            };
            match settings_obj {
                Some(s) => {
                    let sp = s.path().display().to_string();
                    let mk = s.key_file_path().display().to_string();
                    let pd = s
                        .path()
                        .parent()
                        .filter(|p| !p.as_os_str().is_empty())
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| {
                            default_config_dir()
                                .map(|d| d.display().to_string())
                                .unwrap_or_else(|_| "~/.config/bab".to_string())
                        });
                    (sp, mk, pd)
                }
                None => (
                    "~/.config/bab/credentials.enc".to_string(),
                    "~/.config/bab/master.key".to_string(),
                    "~/.config/bab".to_string(),
                ),
            }
        };

        let storage_info = Paragraph::new(vec![
            Line::from(Span::styled(
                format!(
                    "Encryption: ChaCha20-Poly1305 AEAD (enc:v1:) | Config Dir: {} (0700)",
                    parent_dir_display
                ),
                Style::default().fg(Color::Yellow),
            )),
            Line::from(format!("Settings File (0600): {}", settings_display)),
            Line::from(format!(
                "Master Key (0600):    {} (or BAB_ENCRYPTION_KEY env)",
                master_key_display
            )),
            Line::from("Changes auto-save & encrypt immediately as you type (empty removes key)."),
        ])
        .block(
            Block::default()
                .title("Encrypted Credentials Storage")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(storage_info, rows[0]);

        let items: Vec<ListItem> = API_KEY_LABELS
            .iter()
            .enumerate()
            .map(|(i, label)| {
                let masked = ApiKeyForm::mask_key(self.api_keys.value_for(i));
                let suffix = if self.api_keys.editing && i == self.api_keys.active_field {
                    " [EDITING]"
                } else {
                    ""
                };
                ListItem::new(format!("{}: {}{}", label, masked, suffix))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .title("API Key Settings (Masked, Auto-Saved & ChaCha20-Poly1305 Encrypted)")
                    .borders(Borders::ALL),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");
        let mut state = ListState::default();
        state.select(Some(self.api_keys.active_field));
        frame.render_stateful_widget(list, rows[1], &mut state);
    }

    fn render_build_box(&self, frame: &mut Frame, area: Rect) {
        let actions_height = if area.width < 118 { 4 } else { 3 };
        let show_activity = area.height >= 21;
        let rows = if show_activity {
            let overview_height = if area.width < 96 { 15 } else { 12 };
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(overview_height),
                    Constraint::Min(5),
                    Constraint::Length(actions_height),
                ])
                .split(area)
        } else {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(10), Constraint::Length(actions_height)])
                .split(area)
        };

        let tailscale_mode = self.is_tailscale_mode();
        let ports = self
            .selected_role
            .open_ports_for_mode(tailscale_mode)
            .join(", ");
        let provider_line = if self.selected_provider == ProviderKind::ExistingTailscale {
            format!(
                "Provider: {} | Target IP: {}",
                provider_display_label(self.selected_provider),
                self.session
                    .vps_ip
                    .as_deref()
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or("(not set)")
            )
        } else {
            format!(
                "Provider: {} | Region: {} | Plan: {} | Image: {}",
                provider_display_label(self.selected_provider),
                self.selected_region.as_deref().unwrap_or("-"),
                self.selected_plan.as_deref().unwrap_or("-"),
                self.selected_image.as_deref().unwrap_or("-"),
            )
        };
        let ssh_key_display = if tailscale_mode {
            "tailscale".to_string()
        } else {
            self.access.ssh_key_path.clone()
        };
        let dns_state = if self.cf_dns.enabled { "ON" } else { "OFF" };
        let gh_state = if self.github_deploy.enabled {
            "ON"
        } else {
            "OFF"
        };
        let dns_zone = if self.cf_dns.zone.trim().is_empty() {
            "(not set)"
        } else {
            self.cf_dns.zone.trim()
        };
        let gh_repo = if self.github_deploy.repo.trim().is_empty() {
            "(none)".to_string()
        } else {
            format!(
                "{} (branch: {})",
                self.github_deploy.repo.trim(),
                if self.github_deploy.branch.trim().is_empty() {
                    "main"
                } else {
                    self.github_deploy.branch.trim()
                }
            )
        };
        let exec_mode = if self.build_dry_run {
            "Dry-Run: ON (simulated)"
        } else {
            "Dry-Run: OFF (live)"
        };

        let provider_key_ok = match self.selected_provider {
            ProviderKind::Vultr => !self.api_keys.vultr.trim().is_empty(),
            ProviderKind::UpCloud => !self.api_keys.upcloud.trim().is_empty(),
            ProviderKind::Linode => !self.api_keys.linode.trim().is_empty(),
            ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => true,
        };
        let ts_key_ok = !tailscale_mode || !self.api_keys.tailscale.trim().is_empty();
        let cf_key_ok = !self.cf_dns.enabled || !self.api_keys.cloudflare.trim().is_empty();
        let readiness = format!(
            "Provider Key: {} | Tailscale Key: {} | Cloudflare Token: {} | GitHub Token: {}",
            yes_no(provider_key_ok),
            yes_no(ts_key_ok),
            if self.cf_dns.enabled {
                yes_no(cf_key_ok)
            } else {
                "skipped"
            },
            if self.github_deploy.repo.trim().is_empty() {
                "optional"
            } else {
                yes_no(!self.api_keys.github.trim().is_empty())
            }
        );

        let lines = vec![
            Line::from(provider_line),
            Line::from(format!(
                "Server Role: {} | Open Ports: {}",
                self.selected_role.label(),
                ports
            )),
            Line::from(format!(
                "Transport Mode: {} | Sudo Username: {} | Hostname: {}",
                self.access.transport_mode_str(),
                self.access.username,
                self.access.hostname
            )),
            Line::from(format!("SSH Key Path: {}", ssh_key_display)),
            Line::from(format!(
                "Sudo Password: {} (random 10-char — 'w': Show/Hide, 'r': New Password)",
                self.masked_or_plain_password(&self.access.sudo_password)
            )),
            Line::from(vec![
                Span::raw("Passwordless Sudo: "),
                Span::styled(
                    self.access.sudo_nopasswd_label(),
                    toggle_style(self.access.sudo_nopasswd),
                ),
                Span::raw("  ['p': Toggle Passwordless Sudo]"),
            ]),
            Line::from(vec![
                Span::raw("Cloudflare DNS: "),
                Span::styled(dns_state, toggle_style(self.cf_dns.enabled)),
                Span::raw(format!(
                    " ({} / {}, target={}, proxied={})  ['d' or Space: Toggle DNS ON/OFF]",
                    dns_zone,
                    self.cf_dns.record_name,
                    self.cf_dns.target_mode,
                    self.cf_dns.proxied
                )),
            ]),
            Line::from(vec![
                Span::raw("GitHub Repo Deploy: "),
                Span::styled(gh_state, toggle_style(self.github_deploy.enabled)),
                Span::raw(format!(
                    " ({})  ['g': Toggle GitHub Deploy ON/OFF]",
                    gh_repo
                )),
            ]),
            Line::from(Span::styled(
                format!("Execution Mode: {}  ['n': Toggle Dry-Run]", exec_mode),
                Style::default().fg(if self.build_dry_run {
                    Color::Yellow
                } else {
                    Color::Green
                }),
            )),
            Line::from(format!("Credentials: {}", readiness)),
        ];

        let overview = Paragraph::new(lines)
            .block(
                Block::default()
                    .title("Build Box with Current Options")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(overview, rows[0]);

        let actions_area = if show_activity {
            let activity_block = Block::default()
                .title("Live Build Activity")
                .borders(Borders::ALL);
            let max_activity = activity_block
                .inner(rows[1])
                .height
                .clamp(1, 8) as usize;
            let activity_lines: Vec<Line> = if self.logs.is_empty() {
                vec![Line::from(Span::styled(
                    "(waiting to start — press Enter or 'x' to build)",
                    Style::default().fg(Color::DarkGray),
                ))]
            } else {
                let skip = self.logs.len().saturating_sub(max_activity);
                self.logs[skip..]
                    .iter()
                    .map(|l| Line::from(Span::styled(l.as_str(), style_log_line(l))))
                    .collect()
            };
            let activity = Paragraph::new(activity_lines)
                .block(activity_block)
                .wrap(Wrap { trim: false });
            frame.render_widget(activity, rows[1]);
            rows[2]
        } else {
            rows[1]
        };

        let actions = Paragraph::new(Line::from(Span::styled(
            "Enter/x: Build | d: DNS | g: GitHub | p: Sudo | w: Show/Hide Password | r: New Password | n: Dry-Run | Esc/b/q: Back",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )))
        .block(Block::default().borders(Borders::ALL))
        .wrap(Wrap { trim: true });
        frame.render_widget(actions, actions_area);
    }

    fn render_running_instances(&self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(5),
                Constraint::Min(6),
                Constraint::Length(4),
            ])
            .split(area);

        let status_lines: Vec<Line> = if self.running_statuses.is_empty() {
            vec![Line::from("No provider query run yet (press 'r' to refresh).")]
        } else {
            self.running_statuses
                .iter()
                .map(|st| {
                    if !st.configured {
                        Line::from(format!("{}: not configured", st.provider.label()))
                    } else if let Some(ref err) = st.error {
                        Line::from(Span::styled(
                            format!("{}: error ({})", st.provider.label(), err),
                            Style::default().fg(Color::Red),
                        ))
                    } else {
                        Line::from(Span::styled(
                            format!("{}: {} instance(s)", st.provider.label(), st.instance_count),
                            Style::default().fg(Color::Green),
                        ))
                    }
                })
                .collect()
        };
        let status_widget = Paragraph::new(status_lines)
            .block(
                Block::default()
                    .title("Provider Query Status")
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true });
        frame.render_widget(status_widget, rows[0]);

        if self.running_instances.is_empty() {
            let empty = Paragraph::new("(no running instances found; press 'r' to refresh)")
                .block(
                    Block::default()
                        .title("Running Instances")
                        .borders(Borders::ALL),
                );
            frame.render_widget(empty, rows[1]);
        } else {
            let header = Row::new([
                "PROVIDER",
                "NAME",
                "ID",
                "STATUS",
                "IP",
                "REGION",
                "PLAN",
                "SUDO PASS",
            ])
            .style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
            let table_rows: Vec<Row> = self
                .running_instances
                .iter()
                .map(|inst| {
                    let ip = inst.public_ip.as_deref().unwrap_or("-");
                    let region = inst.region.as_deref().unwrap_or("-");
                    let plan = inst.plan.as_deref().unwrap_or("-");
                    let pass_display = self
                        .password_for_instance(inst)
                        .map(|pw| self.masked_or_plain_password(&pw))
                        .unwrap_or_else(|| "-".to_string());
                    Row::new([
                        inst.provider.label().to_string(),
                        inst.name.clone(),
                        inst.id.clone(),
                        inst.status.clone(),
                        ip.to_string(),
                        region.to_string(),
                        plan.to_string(),
                        pass_display,
                    ])
                })
                .collect();
            let widths = [
                Constraint::Length(9),
                Constraint::Min(14),
                Constraint::Min(10),
                Constraint::Length(8),
                Constraint::Length(16),
                Constraint::Length(7),
                Constraint::Length(11),
                Constraint::Length(12),
            ];
            let table = Table::new(table_rows, widths)
                .header(header)
                .block(
                    Block::default()
                        .title("Running Instances")
                        .borders(Borders::ALL),
                )
                .row_highlight_style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("> ");
            let mut state = TableState::default();
            state.select(Some(self.running_index));
            frame.render_stateful_widget(table, rows[1], &mut state);
        }

        let banner = if self.running_confirm_destroy {
            if let Some(inst) = self.running_instances.get(self.running_index) {
                Paragraph::new(Line::from(Span::styled(
                    format!(
                        "CONFIRM DESTROY: {} {} ({})? Press 'y'/Enter to confirm or 'n'/Esc/'b'/'q' to cancel",
                        inst.provider.label(),
                        inst.name,
                        inst.id
                    ),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )))
            } else {
                Paragraph::new("Confirm destroy? y/Enter: Yes | n/Esc/b/q: Cancel")
            }
        } else {
            let selected_summary = if let Some(inst) = self.running_instances.get(self.running_index) {
                let pw_display = self
                    .password_for_instance(inst)
                    .map(|pw| self.masked_or_plain_password(&pw))
                    .unwrap_or_else(|| "-".to_string());
                format!(
                    "Selected: {} ({}) | Sudo Password: {}",
                    inst.name, inst.id, pw_display
                )
            } else {
                "Selected: (none)".to_string()
            };
            Paragraph::new(vec![
                Line::from(selected_summary),
                Line::from(
                    "r: Refresh | w: Show/Hide Pass | d/x/Del: Destroy Selected | Esc/b/q: Back",
                ),
            ])
        }
        .block(Block::default().borders(Borders::ALL));
        frame.render_widget(banner, rows[2]);
    }

    fn render_view_log(&self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(5), Constraint::Min(4)])
            .split(area);

        let viewport_block = Block::default()
            .title(" Log Contents (bab.log) ")
            .borders(Borders::ALL);
        let inner = viewport_block.inner(rows[1]);
        let visible_rows = inner.height.max(1) as usize;
        let total_lines = self.log_view_lines.len();
        let start = self
            .log_scroll
            .min(total_lines.saturating_sub(visible_rows));
        let end = (start + visible_rows).min(total_lines);

        let size_bytes = self
            .log_path
            .as_ref()
            .map(|p| LogStore::new(p).file_size())
            .unwrap_or(0);
        let max_mb = MAX_LOG_FILE_BYTES as f64 / (1024.0 * 1024.0);
        let summary_lines = vec![
            Line::from(format!(
                "Log File: {} (0600 permissions)",
                self.resolved_log_display()
            )),
            Line::from(format!(
                "Size: {} / {:.2} MB max (auto-trimmed)",
                format_log_bytes(size_bytes),
                max_mb
            )),
            Line::from(format!("Entries: {} lines | Offset: {}", total_lines, start)),
        ];
        let summary = Paragraph::new(summary_lines)
            .block(Block::default().title(" Log Summary ").borders(Borders::ALL))
            .wrap(Wrap { trim: true });
        frame.render_widget(summary, rows[0]);

        let content_lines: Vec<Line> = if self.log_view_lines.is_empty() {
            vec![Line::from(Span::styled(
                "No log entries recorded yet. Run a build or setup to populate bab.log.",
                Style::default().fg(Color::DarkGray),
            ))]
        } else {
            self.log_view_lines[start..end]
                .iter()
                .map(|line| Line::from(Span::styled(line.as_str(), style_log_line(line))))
                .collect()
        };
        let viewport = Paragraph::new(content_lines).block(viewport_block);
        frame.render_widget(viewport, rows[1]);
    }

    fn render_bottom_pane(&self, frame: &mut Frame, area: Rect) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(44), Constraint::Percentage(56)])
            .split(area);

        // Left half: Setup Progress & Logs
        let left_block = Block::default()
            .title("Setup Progress & Logs")
            .borders(Borders::ALL);
        let left_inner = left_block.inner(cols[0]);
        frame.render_widget(left_block, cols[0]);

        let left_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Length(2),
                Constraint::Min(1),
            ])
            .split(left_inner);

        let total = self.progress_steps.len().max(1);
        let completed = self
            .progress_steps
            .iter()
            .filter(|(_, status)| status.is_some())
            .count();
        let ratio = (completed as f64 / total as f64).clamp(0.0, 1.0);
        let gauge = Gauge::default()
            .gauge_style(Style::default().fg(Color::Cyan))
            .ratio(ratio)
            .label(format!("{}/{} steps", completed, total));
        frame.render_widget(gauge, left_rows[0]);

        let markers_text = self
            .progress_steps
            .iter()
            .map(|(step, status)| {
                let marker = match status {
                    None => "[ ]",
                    Some(true) => "[x]",
                    Some(false) => "[!]",
                };
                format!("{} {}", marker, step_short_label(*step))
            })
            .collect::<Vec<_>>()
            .join(" ");
        let markers = Paragraph::new(Line::from(markers_text)).wrap(Wrap { trim: true });
        frame.render_widget(markers, left_rows[1]);

        let max_logs = left_rows[2].height as usize;
        let log_lines: Vec<Line> = if self.logs.is_empty() {
            vec![Line::from(Span::styled(
                "(no setup logs yet)",
                Style::default().fg(Color::DarkGray),
            ))]
        } else {
            let skip = self.logs.len().saturating_sub(max_logs);
            self.logs[skip..]
                .iter()
                .map(|l| Line::from(l.as_str()))
                .collect()
        };
        let logs = Paragraph::new(log_lines).wrap(Wrap { trim: false });
        frame.render_widget(logs, left_rows[2]);

        // Right half: Box & Final Connection Info
        let dry_ip = self.last_dry_run_target.as_deref();
        let tailscale_mode = self.is_tailscale_mode();
        let public_ip = self
            .session
            .public_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| {
                if !tailscale_mode {
                    dry_ip.map(|ip| format!("{} (dry-run)", ip))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "(not set)".to_string());
        let tailscale_ip = self
            .session
            .tailscale_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| {
                if tailscale_mode {
                    dry_ip.map(|ip| format!("{} (dry-run)", ip))
                } else {
                    None
                }
            })
            .unwrap_or_else(|| "(not set)".to_string());
        let target_ip = self
            .session
            .vps_ip
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| dry_ip.map(|ip| format!("{} (dry-run)", ip)))
            .unwrap_or_else(|| "(not set)".to_string());
        let provider = self
            .session
            .vps_provider
            .as_deref()
            .unwrap_or(provider_display_label(self.selected_provider));
        let region = self
            .session
            .vps_region
            .as_deref()
            .or(self.selected_region.as_deref())
            .unwrap_or("-");
        let plan = self
            .session
            .vps_plan
            .as_deref()
            .or(self.selected_plan.as_deref())
            .unwrap_or("-");
        let role_short = self.selected_role.to_string();
        let role = self
            .session
            .server_role
            .as_deref()
            .unwrap_or(&role_short);
        let transport = self
            .session
            .transport_mode
            .as_deref()
            .unwrap_or(self.access.transport_mode_str());
        let username = self
            .session
            .username
            .as_deref()
            .unwrap_or(&self.access.username);
        let dns_zone = self
            .session
            .cf_zone
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("-");
        let repo = self
            .session
            .github_repo
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("-");
        let key_filename = self
            .settings_path
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("credentials.enc");

        let info_lines = vec![
            Line::from(format!("Public IP:     {} | Target: {}", public_ip, target_ip)),
            Line::from(format!("Tailscale IP:  {}", tailscale_ip)),
            Line::from(format!("Region/Plan:   {} / {} ({})", region, plan, provider)),
            Line::from(vec![
                Span::raw(format!("Role/Mode/Usr: {}/{}/{} (", role, transport, username)),
                Span::styled(
                    if self.access.sudo_nopasswd {
                        "nopasswd"
                    } else {
                        "passwd"
                    },
                    toggle_style(self.access.sudo_nopasswd),
                ),
                Span::raw(")"),
            ]),
            Line::from(format!(
                "Sudo Pass:     {} ('w': Show/Hide)",
                self.masked_or_plain_password(&self.access.sudo_password)
            )),
            Line::from(vec![
                Span::raw("DNS / Repo:    "),
                Span::styled(
                    if self.cf_dns.enabled { "ON" } else { "OFF" },
                    toggle_style(self.cf_dns.enabled),
                ),
                Span::raw(format!(" ({}) / ", dns_zone)),
                Span::styled(
                    if self.github_deploy.enabled {
                        "ON"
                    } else {
                        "OFF"
                    },
                    toggle_style(self.github_deploy.enabled),
                ),
                Span::raw(format!(" ({})", repo)),
            ]),
            Line::from(format!("Keys: {} [ChaCha20-Poly1305, 0600]", key_filename)),
        ];
        let info = Paragraph::new(info_lines).block(
            Block::default()
                .title("Box & Final Connection Info")
                .borders(Borders::ALL),
        );
        frame.render_widget(info, cols[1]);
    }
}

fn step_short_label(step: SetupStepKind) -> &'static str {
    match step {
        SetupStepKind::SystemUpdate => "Update",
        SetupStepKind::CreateUser => "User",
        SetupStepKind::HardenSsh => "SSH",
        SetupStepKind::ConfigureRole => "Role",
        SetupStepKind::Fail2banAndUpdates => "Fail2ban",
        SetupStepKind::ConfigureMotd => "MOTD",
    }
}

fn prev_index(current: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else if current == 0 {
        len - 1
    } else {
        current - 1
    }
}

fn next_index(current: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else {
        (current + 1) % len
    }
}

fn yes_no(val: bool) -> &'static str {
    if val {
        "ok"
    } else {
        "missing"
    }
}

fn format_log_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn style_log_line(line: &str) -> Style {
    if line.contains("[OK]") || line.contains("[DONE]") {
        Style::default().fg(Color::Green)
    } else if line.contains("[ERROR]") || line.contains("[FAIL]") {
        Style::default().fg(Color::Red)
    } else if line.contains("[DRY-RUN]") || line.contains("[WARN]") {
        Style::default().fg(Color::Yellow)
    } else if line.contains("[BUILD]")
        || line.contains("[PROVISION]")
        || line.contains("[SSH]")
        || line.contains("[STEP ")
        || line.contains("[TAILSCALE]")
        || line.contains("[GITHUB]")
        || line.contains("[DNS]")
        || line.contains("[DESTROY]")
        || line.contains("[QUERY]")
        || line.contains("[CLOUD-INIT]")
    {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default()
    }
}

struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl TerminalGuard {
    fn init() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(err.into());
        }
        let backend = CrosstermBackend::new(stdout);
        match Terminal::new(backend) {
            Ok(terminal) => Ok(Self { terminal }),
            Err(err) => {
                let mut out = io::stdout();
                let _ = execute!(out, LeaveAlternateScreen);
                let _ = disable_raw_mode();
                Err(err.into())
            }
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

fn drain_pending_events() -> Result<()> {
    while event::poll(Duration::ZERO)? {
        let _ = event::read()?;
    }
    Ok(())
}

/// Runs the interactive terminal UI, restoring terminal state on exit or panic.
pub fn run_tui(settings_path: Option<&Path>, state_path: Option<&Path>) -> Result<()> {
    let mut app = TuiApp::from_paths(settings_path, state_path)?;
    let mut guard = TerminalGuard::init()?;

    loop {
        guard.terminal.draw(|frame| app.render_frame(frame))?;
        if app.should_quit {
            break;
        }
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                app.handle_key_with_ui(key, |app_state| {
                    // Discard keys typed during blocking provision/SSH calls so they cannot quit afterward.
                    let _ = drain_pending_events();
                    let _ = guard.terminal.draw(|frame| app_state.render_frame(frame));
                });
                drain_pending_events()?;
                if app.should_quit {
                    break;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use tempfile::tempdir;

    fn render_to_buffer(app: &TuiApp) -> ratatui::buffer::Buffer {
        let backend = TestBackend::new(100, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.render_frame(frame)).unwrap();
        terminal.backend().buffer().clone()
    }

    fn render_to_string(app: &TuiApp) -> String {
        let buf = render_to_buffer(app);
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                if let Some(cell) = buf.cell((x, y)) {
                    out.push_str(cell.symbol());
                }
            }
            out.push('\n');
        }
        out
    }

    fn assert_token_fg_in_row(
        buf: &ratatui::buffer::Buffer,
        line_substr: &str,
        token: &str,
        expected_fg: Color,
    ) {
        let rel_idx = line_substr
            .find(token)
            .expect("token must be contained in line_substr");
        for y in 0..buf.area.height {
            let row_str: String = (0..buf.area.width)
                .map(|x| buf.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "))
                .collect();
            if let Some(line_idx) = row_str.find(line_substr) {
                let start_x = row_str[..line_idx].chars().count()
                    + line_substr[..rel_idx].chars().count();
                for offset in 0..token.chars().count() {
                    let cell = buf.cell(((start_x + offset) as u16, y)).unwrap();
                    assert_eq!(
                        cell.fg, expected_fg,
                        "Expected {:?} for '{}' in '{}' at ({}, {}), got {:?}",
                        expected_fg, token, line_substr, start_x + offset, y, cell.fg
                    );
                    assert!(
                        cell.modifier.contains(Modifier::BOLD),
                        "Expected BOLD modifier for '{}' in '{}' at ({}, {})",
                        token, line_substr, start_x + offset, y
                    );
                }
                return;
            }
        }
        panic!("Did not find '{}' in rendered TestBackend buffer", line_substr);
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn renders_home_with_session_summary_and_menu() {
        let session = SessionData {
            vps_ip: Some("100.64.1.10".to_string()),
            public_ip: Some("203.0.113.42".to_string()),
            tailscale_ip: Some("100.64.1.10".to_string()),
            ssh_key: Some("tailscale".to_string()),
            username: Some("deploy".to_string()),
            transport_mode: Some("tailscale".to_string()),
            vps_provider: Some("vultr".to_string()),
            vps_instance_id: Some("inst-42".to_string()),
            vps_region: Some("ewr".to_string()),
            vps_plan: Some("vc2-1c-1gb".to_string()),
            vps_image: Some("2284".to_string()),
            tailscale_hostname: Some("edge-vps".to_string()),
            server_role: Some("caddy".to_string()),
            ..Default::default()
        };
        let app = TuiApp::new(session, ApiKeyForm::default());
        let text = render_to_string(&app);

        assert!(text.contains("Build A Box (bab) - Multi-Provider VPS Provisioner"));
        assert!(text.contains("100.64.1.10"));
        assert!(text.contains("203.0.113.42"));
        assert!(text.contains("vultr"));
        assert!(text.contains("ewr"));
        assert!(text.contains("vc2-1c-1gb"));
        assert!(text.contains("edge-vps"));
        assert!(text.contains("caddy"));
        assert!(text.contains("tailscale"));
        assert!(text.contains("deploy"));
        assert!(text.contains("[1] Select Provider, Location & Size"));
        assert!(text.contains("[2] Select Server Role"));
        assert!(text.contains("[3] Access, User & Transport"));
        assert!(text.contains("[4] Cloudflare DNS"));
        assert!(text.contains("[5] GitHub Repo Deployment"));
        assert!(text.contains("[6] API Key Settings"));
        assert!(text.contains("[7] Build Box with Current Options"));
        assert!(text.contains("[8] Running Systems & Destroy"));
        assert!(text.contains("[9] View Log"));
        assert!(text.contains("[0] Quit"));
        assert!(text.contains("Log File: ~/.config/bab/bab.log (max 10 MB)"));
        assert!(!text.contains("Cloudflare DNS (Stub)"));
        assert!(!text.contains("API Key Settings (Encrypted)"));
        assert!(text.contains("Setup Progress & Logs"));
        assert!(text.contains("Box & Final Connection Info"));
    }

    #[test]
    fn renders_select_provider_with_all_five_variants_and_catalog() {
        let _lock = crate::env_lock();
        let mut app = TuiApp::new(SessionData::default(), ApiKeyForm::default());
        app.screen = Screen::SelectProvider;
        let text = render_to_string(&app);

        assert!(text.contains("Vultr"));
        assert!(text.contains("UpCloud"));
        assert!(text.contains("Linode"));
        assert!(text.contains("Existing Tailscale"));
        assert!(text.contains("Manual Cloud-Init"));
        assert!(text.contains("ewr"));
        assert!(text.contains("vc2-1c-1gb"));
        assert!(text.contains("1 vCPU, 1024 MB RAM, 25 GB SSD"));
        assert!(text.contains("Ubuntu 24.04 LTS x64"));
    }

    #[test]
    fn select_provider_cycles_region_plan_image_and_persists() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.screen = Screen::SelectProvider;

        // Defaults to Vultr first catalog items
        assert_eq!(app.selected_provider, ProviderKind::Vultr);
        assert_eq!(app.selected_region.as_deref(), Some("ewr"));
        assert_eq!(app.selected_plan.as_deref(), Some("vc2-1c-1gb"));
        assert_eq!(app.selected_image.as_deref(), Some("2284"));

        // Cycle region ('r'), plan ('p'), image ('i')
        app.handle_key(key(KeyCode::Char('r')));
        assert_eq!(app.selected_region.as_deref(), Some("ord"));
        app.handle_key(key(KeyCode::Char('p')));
        assert_eq!(app.selected_plan.as_deref(), Some("vc2-1c-2gb"));
        app.handle_key(key(KeyCode::Char('i')));
        assert_eq!(app.selected_image.as_deref(), Some("2136"));

        let vultr_rendered = render_to_string(&app);
        assert!(vultr_rendered.contains("[*] ord"));
        assert!(vultr_rendered.contains("[*] vc2-1c-2gb"));
        assert!(vultr_rendered.contains("[*] Debian 12 x64 (bookworm)"));
        assert!(vultr_rendered.contains("[2136]"));

        // Save with 's' and verify SessionState persistence
        app.handle_key(key(KeyCode::Char('s')));
        let state = SessionState::new(&state_path);
        assert_eq!(state.vps_provider()?, Some("vultr".to_string()));
        assert_eq!(state.vps_region()?, Some("ord".to_string()));
        assert_eq!(state.vps_plan()?, Some("vc2-1c-2gb".to_string()));
        assert_eq!(state.vps_image()?, Some("2136".to_string()));

        // Switch provider with Down -> UpCloud resets mismatched region/plan/image
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.selected_provider, ProviderKind::UpCloud);
        assert_eq!(app.selected_region.as_deref(), Some("us-nyc1"));
        assert_eq!(app.selected_plan.as_deref(), Some("1xCPU-1GB"));
        assert_eq!(
            app.selected_image.as_deref(),
            Some("01000000-0000-4000-8000-000030240200")
        );

        let upcloud_rendered = render_to_string(&app);
        assert!(upcloud_rendered.contains("us-nyc1"));
        assert!(upcloud_rendered.contains("1xCPU-1GB"));
        assert!(upcloud_rendered.contains("Ubuntu Server 24.04 LTS"));

        app.handle_key(key(KeyCode::Char('r')));
        app.handle_key(key(KeyCode::Char('p')));
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Home);
        assert_eq!(state.vps_provider()?, Some("upcloud".to_string()));
        assert_eq!(state.vps_region()?, Some("us-chi1".to_string()));
        assert_eq!(state.vps_plan()?, Some("1xCPU-2GB".to_string()));

        // Reload and verify selections restored
        let reloaded = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert_eq!(reloaded.selected_provider, ProviderKind::UpCloud);
        assert_eq!(reloaded.selected_region.as_deref(), Some("us-chi1"));
        assert_eq!(reloaded.selected_plan.as_deref(), Some("1xCPU-2GB"));

        // Selecting '4' (ExistingTailscale) clears cloud catalog fields
        let mut app2 = reloaded;
        app2.screen = Screen::SelectProvider;
        app2.handle_key(key(KeyCode::Char('4')));
        assert_eq!(app2.selected_provider, ProviderKind::ExistingTailscale);
        assert_eq!(app2.selected_region, None);
        assert_eq!(app2.selected_plan, None);
        assert_eq!(app2.selected_image, None);
        assert_eq!(state.vps_provider()?, Some("existing_tailscale".to_string()));
        assert_eq!(state.vps_region()?, None);
        assert_eq!(state.vps_plan()?, None);
        assert_eq!(state.vps_image()?, None);
        Ok(())
    }

    #[test]
    fn select_provider_preserves_custom_non_preset_catalog_ids_on_save_same_provider() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let state = SessionState::new(&state_path);
        state.save_session(&SessionData {
            vps_provider: Some("vultr".to_string()),
            vps_region: Some("nrt".to_string()),
            vps_plan: Some("vc2-2c-4gb".to_string()),
            vps_image: Some("1743".to_string()),
            ..SessionData::default()
        })?;

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert_eq!(app.selected_provider, ProviderKind::Vultr);
        assert_eq!(app.selected_region.as_deref(), Some("nrt"));
        assert_eq!(app.selected_plan.as_deref(), Some("vc2-2c-4gb"));
        assert_eq!(app.selected_image.as_deref(), Some("1743"));

        app.screen = Screen::SelectProvider;

        // Saving with 's' without changing provider or cycling keeps custom IDs.
        app.handle_key(key(KeyCode::Char('s')));
        assert_eq!(app.selected_region.as_deref(), Some("nrt"));
        assert_eq!(app.selected_plan.as_deref(), Some("vc2-2c-4gb"));
        assert_eq!(app.selected_image.as_deref(), Some("1743"));
        assert_eq!(state.vps_region()?.as_deref(), Some("nrt"));
        assert_eq!(state.vps_plan()?.as_deref(), Some("vc2-2c-4gb"));
        assert_eq!(state.vps_image()?.as_deref(), Some("1743"));

        // Pressing '1' (same provider) and Enter also preserves custom IDs.
        app.handle_key(key(KeyCode::Char('1')));
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::Home);
        assert_eq!(app.selected_region.as_deref(), Some("nrt"));
        assert_eq!(app.selected_plan.as_deref(), Some("vc2-2c-4gb"));
        assert_eq!(app.selected_image.as_deref(), Some("1743"));
        assert_eq!(state.vps_region()?.as_deref(), Some("nrt"));
        assert_eq!(state.vps_plan()?.as_deref(), Some("vc2-2c-4gb"));
        assert_eq!(state.vps_image()?.as_deref(), Some("1743"));

        // Switching to a different provider (UpCloud via '2') resets mismatched IDs.
        app.screen = Screen::SelectProvider;
        app.handle_key(key(KeyCode::Char('2')));
        assert_eq!(app.selected_provider, ProviderKind::UpCloud);
        assert_eq!(app.selected_region.as_deref(), Some("us-nyc1"));
        assert_eq!(app.selected_plan.as_deref(), Some("1xCPU-1GB"));
        assert_eq!(
            app.selected_image.as_deref(),
            Some("01000000-0000-4000-8000-000030240200")
        );
        Ok(())
    }

    #[test]
    fn select_role_shows_all_roles_shortcuts_and_stub_status() {
        let _lock = crate::env_lock();
        let mut app = TuiApp::new(SessionData::default(), ApiKeyForm::default());
        assert_eq!(app.selected_role, ServerRole::Vanilla);
        assert_eq!(app.role_index, 0);
        app.screen = Screen::SelectRole;

        let initial = render_to_string(&app);
        assert!(initial.contains("[1] Vanilla (Plain Hardened OS)"));
        assert!(initial.contains("[2] ReverseProxy (Caddy)"));
        assert!(initial.contains("[3] VPN Server (WireGuard)"));
        assert!(initial.contains("[4] Remote Browser Isolation (Build Later)"));
        assert!(initial.contains("41641/udp (Tailscale)"));
        assert!(initial.contains("Status: Ready for provisioning"));

        // Press '2' shortcut -> ReverseProxy (Caddy)
        app.handle_key(key(KeyCode::Char('2')));
        assert_eq!(app.selected_role, ServerRole::ReverseProxyCaddy);
        assert_eq!(app.role_index, 1);
        let caddy = render_to_string(&app);
        assert!(caddy.contains("443/tcp+udp (HTTPS/HTTP3)"));

        // Press '1' shortcut -> Vanilla
        app.handle_key(key(KeyCode::Char('1')));
        assert_eq!(app.selected_role, ServerRole::Vanilla);
        assert_eq!(app.role_index, 0);
        let vanilla = render_to_string(&app);
        assert!(vanilla.contains("Status: Ready for provisioning"));
        assert!(vanilla.contains("41641/udp (Tailscale)"));

        // Press '3' shortcut -> WireGuard
        app.handle_key(key(KeyCode::Char('3')));
        assert_eq!(app.selected_role, ServerRole::VpnWireguard);
        assert_eq!(app.role_index, 2);
        let wg = render_to_string(&app);
        assert!(wg.contains("51820/udp (WireGuard)"));

        // Press Down arrow to move to role 4 (Remote Browser Isolation stub)
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.role_index, 3);
        let rbi = render_to_string(&app);
        assert!(rbi.contains("Status: Placeholder stub (to be built in a later phase)"));

        // Press '2' shortcut -> ReverseProxy (Caddy)
        app.handle_key(key(KeyCode::Char('2')));
        assert_eq!(app.selected_role, ServerRole::ReverseProxyCaddy);
        assert_eq!(app.role_index, 1);

        // Press '4' shortcut -> Remote Browser Isolation
        app.handle_key(key(KeyCode::Char('4')));
        assert_eq!(app.selected_role, ServerRole::RemoteBrowserIsolation);
        assert_eq!(app.role_index, 3);
    }

    #[test]
    fn select_role_open_ports_reflect_transport_mode() {
        let _lock = crate::env_lock();
        let ts_session = SessionData {
            transport_mode: Some("tailscale".to_string()),
            server_role: Some("vanilla".to_string()),
            ..Default::default()
        };
        let mut ts_app = TuiApp::new(ts_session, ApiKeyForm::default());
        ts_app.screen = Screen::SelectRole;
        let ts_rendered = render_to_string(&ts_app);
        assert!(ts_rendered.contains("41641/udp (Tailscale)"));
        assert!(!ts_rendered.contains("22/tcp (SSH rate-limited)"));

        let ssh_session = SessionData {
            transport_mode: Some("ssh".to_string()),
            server_role: Some("vanilla".to_string()),
            ..Default::default()
        };
        let mut ssh_app = TuiApp::new(ssh_session, ApiKeyForm::default());
        ssh_app.screen = Screen::SelectRole;
        let ssh_rendered = render_to_string(&ssh_app);
        assert!(ssh_rendered.contains("22/tcp (SSH rate-limited)"));
        assert!(!ssh_rendered.contains("41641/udp (Tailscale)"));

        // Toggling transport in AccessConfig updates SelectRole immediately without pressing 's'
        ts_app.screen = Screen::AccessConfig;
        ts_app.handle_key(key(KeyCode::Char(' ')));
        assert!(!ts_app.access.tailscale_mode);
        assert!(!ts_app.is_tailscale_mode());
        ts_app.screen = Screen::SelectRole;
        let toggled_rendered = render_to_string(&ts_app);
        assert!(toggled_rendered.contains("22/tcp (SSH rate-limited)"));
        assert!(!toggled_rendered.contains("41641/udp (Tailscale)"));
    }

    #[test]
    fn access_config_defaults_toggle_edit_and_persist() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;

        // Check sensible defaults before visiting AccessConfig
        assert!(app.access.tailscale_mode);
        assert_eq!(app.access.username, "deploy");
        assert!(app.access.ssh_key_path.ends_with("bab_ed25519"));
        assert_eq!(app.access.hostname, "bab-node");

        // Open AccessConfig from Home using '3' shortcut
        app.handle_key(key(KeyCode::Char('3')));
        assert_eq!(app.screen, Screen::AccessConfig);
        assert_eq!(app.home_index, 2);

        let initial_view = render_to_string(&app);
        assert!(initial_view.contains("Access, User & Transport"));
        assert!(initial_view.contains("sudo"));
        assert!(initial_view.contains("wheel"));
        assert!(initial_view.contains("tailscale"));

        // Toggle transport via Space, Left, Right, Enter
        app.handle_key(key(KeyCode::Char(' ')));
        assert!(!app.access.tailscale_mode);
        app.handle_key(key(KeyCode::Left));
        assert!(app.access.tailscale_mode);
        app.handle_key(key(KeyCode::Right));
        assert!(!app.access.tailscale_mode);
        app.handle_key(key(KeyCode::Enter));
        assert!(app.access.tailscale_mode);
        // Set back to ssh mode via Space
        app.handle_key(key(KeyCode::Char(' ')));
        assert!(!app.access.tailscale_mode);

        // Move to Field 1 (Sudo Username) and edit it
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.access.active_field, 1);
        app.handle_key(key(KeyCode::Enter));
        assert!(app.access.editing);
        for _ in 0.."deploy".len() {
            app.handle_key(key(KeyCode::Backspace));
        }
        for c in "opsadmin".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        // 'q' while editing must append 'q', not quit
        app.handle_key(key(KeyCode::Char('q')));
        assert!(!app.should_quit);
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.access.username, "opsadmin");

        let editing_view = render_to_string(&app);
        assert!(editing_view.contains("Sudo Username (USERNAME): opsadmin [EDITING]"));
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.access.editing);

        // Move to Field 2 (SSH Key Path) and replace with custom path
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.access.active_field, 2);
        app.handle_key(key(KeyCode::Enter));
        assert!(app.access.editing);
        let prev_len = app.access.ssh_key_path.chars().count();
        for _ in 0..prev_len {
            app.handle_key(key(KeyCode::Backspace));
        }
        for c in "/tmp/custom_bab_key".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Esc));
        assert!(!app.access.editing);
        assert_eq!(app.access.ssh_key_path, "/tmp/custom_bab_key");

        // Move to Field 3 (Hostname) and update it
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.access.active_field, 3);
        app.handle_key(key(KeyCode::Enter));
        for _ in 0.."bab-node".len() {
            app.handle_key(key(KeyCode::Backspace));
        }
        for c in "prod-edge-01".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.access.hostname, "prod-edge-01");

        // Save with 's' and verify SessionState persistence in ssh mode
        app.handle_key(key(KeyCode::Char('s')));
        assert!(app.status_message.contains("Saved access settings"));

        let state = SessionState::new(&state_path);
        assert_eq!(state.transport_mode()?, Some("ssh".to_string()));
        assert_eq!(state.username()?, Some("opsadmin".to_string()));
        assert_eq!(state.ssh_key()?, Some("/tmp/custom_bab_key".to_string()));
        assert_eq!(state.tailscale_hostname()?, Some("prod-edge-01".to_string()));

        // Reload TuiApp from paths and verify SelectRole reflects SSH open ports
        let mut reloaded = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert!(!reloaded.access.tailscale_mode);
        assert_eq!(reloaded.access.username, "opsadmin");
        assert_eq!(reloaded.access.ssh_key_path, "/tmp/custom_bab_key");
        assert_eq!(reloaded.access.hostname, "prod-edge-01");

        reloaded.screen = Screen::SelectRole;
        let role_view = render_to_string(&reloaded);
        assert!(role_view.contains("22/tcp (SSH rate-limited)"));

        // Toggle back to Tailscale mode, save with 's', and verify SSH_KEY="tailscale"
        reloaded.screen = Screen::AccessConfig;
        reloaded.handle_key(key(KeyCode::Char(' ')));
        assert!(reloaded.access.tailscale_mode);
        reloaded.handle_key(key(KeyCode::Char('s')));
        assert_eq!(state.transport_mode()?, Some("tailscale".to_string()));
        assert_eq!(state.ssh_key()?, Some("tailscale".to_string()));

        // Return Home via 'b'
        reloaded.handle_key(key(KeyCode::Char('b')));
        assert_eq!(reloaded.screen, Screen::Home);
        Ok(())
    }

    #[test]
    fn cloudflare_dns_edit_toggle_preview_and_persist() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let state = SessionState::new(&state_path);
        state.save_session(&SessionData {
            public_ip: Some("203.0.113.50".to_string()),
            tailscale_ip: Some("100.64.8.8".to_string()),
            vps_ip: Some("100.64.8.8".to_string()),
            ..Default::default()
        })?;

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.handle_key(key(KeyCode::Char('4')));
        assert_eq!(app.screen, Screen::CloudflareDns);
        assert_eq!(app.cf_dns.record_name, "@");
        assert_eq!(app.cf_dns.target_mode, "public");
        assert!(!app.cf_dns.proxied);

        // Edit Zone (field 0)
        app.handle_key(key(KeyCode::Enter));
        assert!(app.cf_dns.editing);
        for c in "example.com".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        // 'q' while editing appends 'q', does not quit
        app.handle_key(key(KeyCode::Char('q')));
        assert!(!app.should_quit);
        app.handle_key(key(KeyCode::Backspace));
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.cf_dns.editing);
        assert_eq!(app.cf_dns.zone, "example.com");

        // Edit Record Name (field 1)
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Enter));
        app.handle_key(key(KeyCode::Backspace)); // remove '@'
        for c in "app".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.cf_dns.record_name, "app");

        // Preview in public mode uses public_ip (203.0.113.50)
        let public_view = render_to_string(&app);
        assert!(public_view.contains("[STUB] Cloudflare DNS: would upsert A record 'app' -> '203.0.113.50'"));

        // Toggle Target IP (field 2) -> tailscale (100.64.8.8)
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Char(' ')));
        assert_eq!(app.cf_dns.target_mode, "tailscale");

        // Toggle Proxied (field 3) -> true
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Enter));
        assert!(app.cf_dns.proxied);

        let ts_view = render_to_string(&app);
        assert!(ts_view.contains("[STUB] Cloudflare DNS: would upsert A record 'app' -> '100.64.8.8'"));
        assert!(ts_view.contains("proxied=true"));

        // Persist via 's'
        app.handle_key(key(KeyCode::Char('s')));
        assert_eq!(state.cf_zone()?, Some("example.com".to_string()));
        assert_eq!(state.cf_record()?, Some("app".to_string()));
        assert_eq!(state.cf_target()?, Some("tailscale".to_string()));
        assert_eq!(state.cf_proxied()?, Some("true".to_string()));

        let reloaded = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert_eq!(reloaded.cf_dns.zone, "example.com");
        assert_eq!(reloaded.cf_dns.record_name, "app");
        assert_eq!(reloaded.cf_dns.target_mode, "tailscale");
        assert!(reloaded.cf_dns.proxied);
        Ok(())
    }

    #[test]
    fn github_deploy_edit_preview_and_persist() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.handle_key(key(KeyCode::Char('5')));
        assert_eq!(app.screen, Screen::GithubDeploy);
        assert_eq!(app.github_deploy.branch, "main");

        // Edit Repository (field 0)
        app.handle_key(key(KeyCode::Enter));
        for c in "octocat/my-app".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Char('q')));
        assert!(!app.should_quit);
        app.handle_key(key(KeyCode::Backspace));
        app.handle_key(key(KeyCode::Enter));

        // Edit Branch (field 1)
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Enter));
        for _ in 0.."main".len() {
            app.handle_key(key(KeyCode::Backspace));
        }
        for c in "release".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));

        // Edit Deploy Path (field 2)
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Enter));
        for c in "/srv/my-app".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));

        // Edit Deploy Command (field 3)
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Enter));
        for c in "docker compose up -d".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));

        let view = render_to_string(&app);
        assert!(view.contains("https://github.com/octocat/my-app.git -> /srv/my-app (branch: release)"));

        // Save via 's'
        app.handle_key(key(KeyCode::Char('s')));
        let state = SessionState::new(&state_path);
        assert_eq!(state.github_repo()?, Some("octocat/my-app".to_string()));
        assert_eq!(state.github_branch()?, Some("release".to_string()));
        assert_eq!(state.github_deploy_path()?, Some("/srv/my-app".to_string()));
        assert_eq!(
            state.github_deploy_cmd()?,
            Some("docker compose up -d".to_string())
        );

        let reloaded = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert_eq!(reloaded.github_deploy.repo, "octocat/my-app");
        assert_eq!(reloaded.github_deploy.branch, "release");
        assert_eq!(reloaded.github_deploy.deploy_path, "/srv/my-app");
        assert_eq!(reloaded.github_deploy.deploy_cmd, "docker compose up -d");
        Ok(())
    }

    #[test]
    fn api_keys_masking_input_and_save() -> Result<()> {
        let _lock = crate::env_lock();
        assert_eq!(ApiKeyForm::mask_key(""), "(not set)");
        assert_eq!(ApiKeyForm::mask_key("short"), "*****");
        assert_eq!(
            ApiKeyForm::mask_key("tskey-auth-12345678"),
            "tske****5678"
        );

        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.screen = Screen::ApiKeys;

        // Verify all 6 labels and encrypted storage disclosure are rendered
        let initial_rendered = render_to_string(&app);
        assert!(initial_rendered.contains("TAILSCALE_API_KEY"));
        assert!(initial_rendered.contains("VULTR_API_KEY"));
        assert!(initial_rendered.contains("UPCLOUD_API_TOKEN"));
        assert!(initial_rendered.contains("LINODE_API_TOKEN"));
        assert!(initial_rendered.contains("CLOUDFLARE_API_TOKEN"));
        assert!(initial_rendered.contains("GITHUB_TOKEN"));
        assert!(initial_rendered.contains("ChaCha20-Poly1305"));
        assert!(initial_rendered.contains("credentials.enc"));
        assert!(initial_rendered.contains("master.key"));
        assert!(initial_rendered.contains("0600"));
        assert!(initial_rendered.contains("0700"));

        // Enter edit mode on TAILSCALE_API_KEY (field 0)
        app.handle_key(key(KeyCode::Enter));
        assert!(app.api_keys.editing);
        for c in "tskey-secret-abcd".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        // 'q' while editing must append 'q', not quit
        app.handle_key(key(KeyCode::Char('q')));
        assert!(!app.should_quit);
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.api_keys.tailscale, "tskey-secret-abcd");

        let rendered = render_to_string(&app);
        assert!(rendered.contains("TAILSCALE_API_KEY: tske****abcd [EDITING]"));
        assert!(!rendered.contains("tskey-secret-abcd"));
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.api_keys.editing);

        // Move to CLOUDFLARE_API_TOKEN (field 4) and edit
        for _ in 0..4 {
            app.handle_key(key(KeyCode::Down));
        }
        assert_eq!(app.api_keys.active_field, 4);
        app.handle_key(key(KeyCode::Enter));
        for c in "cf-token-12345678".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));

        // Move to GITHUB_TOKEN (field 5) and edit
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.api_keys.active_field, 5);
        app.handle_key(key(KeyCode::Enter));
        for c in "ghp_secret98765432".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));

        // Save with 's'
        app.handle_key(key(KeyCode::Char('s')));

        let settings = Settings::new(&settings_path);
        assert_eq!(
            settings.tailscale_api_key()?,
            Some("tskey-secret-abcd".to_string())
        );
        assert_eq!(
            settings.cloudflare_api_token()?,
            Some("cf-token-12345678".to_string())
        );
        assert_eq!(
            settings.github_token()?,
            Some("ghp_secret98765432".to_string())
        );

        // 'q' on ApiKeys returns to Home without quitting, then 'q' on Home quits
        app.handle_key(key(KeyCode::Char('q')));
        assert!(!app.should_quit);
        assert_eq!(app.screen, Screen::Home);
        app.handle_key(key(KeyCode::Char('q')));
        assert!(app.should_quit);
        Ok(())
    }

    #[test]
    fn persistent_bottom_pane_shows_progress_logs_and_connection_info_across_screens() {
        let _lock = crate::env_lock();
        let session = SessionData {
            vps_ip: Some("100.64.2.20".to_string()),
            public_ip: Some("198.51.100.20".to_string()),
            tailscale_ip: Some("100.64.2.20".to_string()),
            vps_provider: Some("linode".to_string()),
            vps_region: Some("us-east".to_string()),
            vps_plan: Some("g6-standard-2".to_string()),
            server_role: Some("caddy".to_string()),
            transport_mode: Some("tailscale".to_string()),
            username: Some("deploy".to_string()),
            cf_zone: Some("example.org".to_string()),
            github_repo: Some("org/web".to_string()),
            ..Default::default()
        };
        let mut app = TuiApp::new(session, ApiKeyForm::default());
        app.record_step(&StepReport {
            step: SetupStepKind::SystemUpdate,
            success: true,
            dry_run: false,
            output: "apt updated successfully".to_string(),
        });
        app.record_step(&StepReport {
            step: SetupStepKind::CreateUser,
            success: false,
            dry_run: false,
            output: "useradd error".to_string(),
        });

        for screen in [
            Screen::Home,
            Screen::SelectProvider,
            Screen::SelectRole,
            Screen::AccessConfig,
            Screen::CloudflareDns,
            Screen::GithubDeploy,
            Screen::ApiKeys,
            Screen::BuildBox,
            Screen::RunningInstances,
            Screen::ViewLog,
        ] {
            app.screen = screen;
            let text = render_to_string(&app);
            assert!(text.contains("2/6 steps"));
            assert!(text.contains("[x] Update"));
            assert!(text.contains("[!] User"));
            assert!(text.contains("[ ] SSH"));
            assert!(text.contains("apt updated successfully"));
            assert!(text.contains("useradd error"));
            assert!(text.contains("Public IP:"));
            assert!(text.contains("198.51.100.20"));
            assert!(text.contains("Tailscale IP:"));
            assert!(text.contains("100.64.2.20"));
            assert!(text.contains("us-east"));
            assert!(text.contains("g6-standard-2"));
            assert!(text.contains("credentials.enc [ChaCha20-Poly1305, 0600]"));
        }
    }

    #[test]
    fn ignores_key_release_events_and_handles_navigation() {
        let _lock = crate::env_lock();
        let mut app = TuiApp::new(SessionData::default(), ApiKeyForm::default());
        let mut release = key(KeyCode::Down);
        release.kind = KeyEventKind::Release;
        app.handle_key(release);
        assert_eq!(app.home_index, 0);

        let mut repeat = key(KeyCode::Char('j'));
        repeat.kind = KeyEventKind::Repeat;
        app.handle_key(repeat);
        assert_eq!(app.home_index, 1);

        // Enter on home_index 1 -> SelectRole, then 'b' back to Home
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::SelectRole);
        app.handle_key(key(KeyCode::Char('b')));
        assert_eq!(app.screen, Screen::Home);

        // Navigate to AccessConfig via Down + Enter, then Esc back to Home
        app.handle_key(key(KeyCode::Down));
        assert_eq!(app.home_index, 2);
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::AccessConfig);
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Home);

        // Shortcuts '4', '5', '6', '7' open CloudflareDns, GithubDeploy, ApiKeys, BuildBox
        app.handle_key(key(KeyCode::Char('4')));
        assert_eq!(app.screen, Screen::CloudflareDns);
        app.handle_key(key(KeyCode::Char('b')));
        app.handle_key(key(KeyCode::Char('5')));
        assert_eq!(app.screen, Screen::GithubDeploy);
        app.handle_key(key(KeyCode::Char('b')));
        app.handle_key(key(KeyCode::Char('6')));
        assert_eq!(app.screen, Screen::ApiKeys);
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Home);
        app.handle_key(key(KeyCode::Char('7')));
        assert_eq!(app.screen, Screen::BuildBox);
        app.handle_key(key(KeyCode::Esc));
        assert_eq!(app.screen, Screen::Home);

        // Navigate to SelectProvider and confirm with Enter
        app.home_index = 0;
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::SelectProvider);
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.selected_provider, ProviderKind::UpCloud);
        assert_eq!(app.screen, Screen::Home);

        // Shortcut '9' opens ViewLog and 'q' returns Home without quitting
        app.handle_key(key(KeyCode::Char('9')));
        assert_eq!(app.screen, Screen::ViewLog);
        assert!(!app.should_quit);
        app.handle_key(key(KeyCode::Char('q')));
        assert_eq!(app.screen, Screen::Home);
        assert!(!app.should_quit);

        // Shortcut '0' quits
        app.handle_key(key(KeyCode::Char('0')));
        assert!(app.should_quit);
    }

    #[test]
    fn submenu_q_returns_to_home_without_quitting_while_home_q_quits() {
        let _lock = crate::env_lock();
        let mut app = TuiApp::new(SessionData::default(), ApiKeyForm::default());

        for screen in [
            Screen::SelectProvider,
            Screen::SelectRole,
            Screen::AccessConfig,
            Screen::CloudflareDns,
            Screen::GithubDeploy,
            Screen::ApiKeys,
            Screen::BuildBox,
            Screen::RunningInstances,
            Screen::ViewLog,
        ] {
            app.screen = screen;
            let rendered = render_to_string(&app);
            assert!(
                rendered.contains("Esc/b/q: Back"),
                "Screen {:?} footer should advertise Esc/b/q: Back",
                screen
            );
            assert!(
                !rendered.contains("q: Quit"),
                "Screen {:?} footer must not say q: Quit",
                screen
            );

            app.handle_key(key(KeyCode::Char('q')));
            assert_eq!(app.screen, Screen::Home);
            assert!(!app.should_quit);
        }

        let home_rendered = render_to_string(&app);
        assert!(home_rendered.contains("1-9/0/Enter: Open | q: Quit"));

        app.handle_key(key(KeyCode::Char('q')));
        assert!(app.should_quit);
    }

    #[test]
    fn cloudflare_dns_toggle_and_build_box_dry_run_execute_build() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert!(!app.cf_dns.enabled);

        // Open CloudflareDns and set zone + toggle enabled field
        app.handle_key(key(KeyCode::Char('4')));
        assert_eq!(app.screen, Screen::CloudflareDns);
        app.handle_key(key(KeyCode::Enter));
        for c in "example.com".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));
        // Finishing zone edit when cf_enabled is None enables DNS automatically
        assert!(app.cf_dns.enabled);

        // Navigate to field 4 (DNS Enabled) and toggle OFF then ON with Space and 't'
        for _ in 0..4 {
            app.handle_key(key(KeyCode::Down));
        }
        assert_eq!(app.cf_dns.active_field, 4);
        app.handle_key(key(KeyCode::Char(' ')));
        assert!(!app.cf_dns.enabled);
        app.handle_key(key(KeyCode::Char('t')));
        assert!(app.cf_dns.enabled);
        app.handle_key(key(KeyCode::Char('s')));

        let state = SessionState::new(&state_path);
        assert_eq!(state.cf_enabled()?, Some("true".to_string()));

        // Navigate to BuildBox via 'q' -> '7'
        app.handle_key(key(KeyCode::Char('q')));
        assert_eq!(app.screen, Screen::Home);
        app.handle_key(key(KeyCode::Char('7')));
        assert_eq!(app.screen, Screen::BuildBox);

        let build_view = render_to_string(&app);
        assert!(build_view.contains("Build Box with Current Options"));
        assert!(build_view.contains("Cloudflare DNS: ON"));

        // Toggle DNS OFF on BuildBox using 'd'
        app.handle_key(key(KeyCode::Char('d')));
        assert!(!app.cf_dns.enabled);
        assert_eq!(state.cf_enabled()?, Some("false".to_string()));

        // Enable Dry-Run using 'n' and execute build with DNS OFF
        app.handle_key(key(KeyCode::Char('n')));
        assert!(app.build_dry_run);
        app.handle_key(key(KeyCode::Enter));

        assert!(app.progress_steps.iter().all(|(_, s)| *s == Some(true)));
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[DNS] Cloudflare DNS is OFF (skipped)")));
        // Dry-run must not persist fake VPS_IP into state.conf
        assert_eq!(state.vps_ip()?, None);

        // Toggle DNS back ON with Space and run again with 'x'
        app.handle_key(key(KeyCode::Char(' ')));
        assert!(app.cf_dns.enabled);
        app.handle_key(key(KeyCode::Char('x')));
        assert!(app.logs.iter().any(|l| {
            l.contains("[DNS] [STUB] Cloudflare DNS: would upsert A record '@' -> '100.64.0.1' in zone 'example.com'")
        }));
        assert_eq!(state.vps_ip()?, None);

        // ManualCloudInit dry-run also generates cloud-init into logs
        app.selected_provider = ProviderKind::ManualCloudInit;
        app.provider_index = 4;
        app.execute_build();
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[CLOUD-INIT] Generated cloud-init script")));
        Ok(())
    }

    #[test]
    fn api_keys_auto_save_without_s_and_removes_cleared_key() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.handle_key(key(KeyCode::Char('6')));
        assert_eq!(app.screen, Screen::ApiKeys);

        // Edit TAILSCALE_API_KEY without ever pressing 's'
        app.handle_key(key(KeyCode::Enter));
        for c in "tskey-auto-1234".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Enter));

        let settings = Settings::new(&settings_path);
        assert_eq!(
            settings.tailscale_api_key()?,
            Some("tskey-auto-1234".to_string())
        );

        // Clear TAILSCALE_API_KEY and verify it is removed from credentials.enc automatically
        app.handle_key(key(KeyCode::Enter));
        for _ in 0.."tskey-auto-1234".len() {
            app.handle_key(key(KeyCode::Backspace));
        }
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(settings.tailscale_api_key()?, None);
        Ok(())
    }

    #[test]
    fn running_instances_query_cancel_and_destroy_flow() -> Result<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        struct EnvGuard {
            saved: Vec<(String, Option<String>)>,
        }
        impl EnvGuard {
            fn new(keys: &[&str]) -> Self {
                Self {
                    saved: keys
                        .iter()
                        .map(|k| ((*k).to_string(), std::env::var(k).ok()))
                        .collect(),
                }
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
        let destroyed = Arc::new(AtomicBool::new(false));
        let destroyed_bg = Arc::clone(&destroyed);

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
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                let mut parts = req_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");
                let (status, body) = if method == "GET" && path.starts_with("/v2/instances") {
                    (
                        "200 OK",
                        r#"{"instances":[{"id":"vultr-101","label":"edge-box","status":"active","power_status":"running","main_ip":"203.0.113.77","region":"ewr","plan":"vc2-1c-1gb"}],"meta":{"links":{"next":""}}}"#,
                    )
                } else if method == "DELETE" && path == "/v2/instances/vultr-101" {
                    destroyed_bg.store(true, Ordering::SeqCst);
                    ("204 No Content", "")
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

        std::env::set_var("VULTR_API_BASE_URL", format!("http://{}/v2", addr));

        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let state = SessionState::new(&state_path);
        state.save_session(&SessionData {
            vps_provider: Some("vultr".to_string()),
            vps_instance_id: Some("vultr-101".to_string()),
            vps_ip: Some("203.0.113.77".to_string()),
            public_ip: Some("203.0.113.77".to_string()),
            username: Some("deploy".to_string()),
            ..Default::default()
        })?;

        let settings = Settings::new(&settings_path);
        settings.set_vultr_api_key("vultr-test-key")?;

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;

        // Press '8' on Home to open RunningInstances and trigger refresh
        app.handle_key(key(KeyCode::Char('8')));
        assert_eq!(app.screen, Screen::RunningInstances);
        assert_eq!(app.running_instances.len(), 1);
        assert_eq!(app.running_instances[0].id, "vultr-101");

        let list_view = render_to_string(&app);
        assert!(list_view.contains("edge-box"));
        assert!(list_view.contains("vultr-101"));
        assert!(list_view.contains("203.0.113.77"));

        // d -> n cancels confirmation without destroying or quitting
        app.handle_key(key(KeyCode::Char('d')));
        assert!(app.running_confirm_destroy);
        let confirm_view = render_to_string(&app);
        assert!(confirm_view.contains("CONFIRM DESTROY"));
        app.handle_key(key(KeyCode::Char('n')));
        assert!(!app.running_confirm_destroy);
        assert_eq!(app.running_instances.len(), 1);
        assert!(!destroyed.load(Ordering::SeqCst));

        // d -> q cancels confirmation without leaving screen or quitting
        app.handle_key(key(KeyCode::Char('d')));
        assert!(app.running_confirm_destroy);
        app.handle_key(key(KeyCode::Char('q')));
        assert!(!app.running_confirm_destroy);
        assert_eq!(app.screen, Screen::RunningInstances);
        assert!(!app.should_quit);

        // d -> y destroys instance, removes from list, and clears matching session
        app.handle_key(key(KeyCode::Char('d')));
        app.handle_key(key(KeyCode::Char('y')));
        assert!(!app.running_confirm_destroy);
        assert!(destroyed.load(Ordering::SeqCst));
        assert!(app.running_instances.is_empty());
        assert_eq!(app.session.vps_instance_id, None);
        assert_eq!(app.session.vps_ip, None);
        assert_eq!(app.session.public_ip, None);
        assert_eq!(state.vps_instance_id()?, None);
        assert_eq!(state.username()?, Some("deploy".to_string()));

        stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(addr);
        handle.join().unwrap();
        Ok(())
    }

    #[test]
    fn github_deploy_form_from_session_parses_enabled_variants() {
        for raw in ["true", " TRUE ", "1", "yes", "On"] {
            let form = GithubDeployForm::from_session(&SessionData {
                github_enabled: Some(raw.to_string()),
                ..Default::default()
            });
            assert!(form.enabled, "expected '{}' to enable github_deploy", raw);
        }
        for raw in ["false", " False ", "0", "no", "OFF"] {
            let form = GithubDeployForm::from_session(&SessionData {
                github_repo: Some("octocat/app".to_string()),
                github_enabled: Some(raw.to_string()),
                ..Default::default()
            });
            assert!(!form.enabled, "expected '{}' to disable github_deploy", raw);
        }
        let fallback_with_repo = GithubDeployForm::from_session(&SessionData {
            github_repo: Some("octocat/app".to_string()),
            github_enabled: Some("invalid".to_string()),
            ..Default::default()
        });
        assert!(fallback_with_repo.enabled);
        let fallback_empty = GithubDeployForm::from_session(&SessionData::default());
        assert!(!fallback_empty.enabled);
    }

    #[test]
    fn toggles_sync_bidirectionally_between_submenus_build_box_home_and_session() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");
        let state = SessionState::new(&state_path);

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert!(!app.cf_dns.enabled);
        assert!(!app.github_deploy.enabled);

        // 1. Toggle CF DNS in CloudflareDns (field 4 Space, then 't' from field 0) -> immediate sync
        app.handle_key(key(KeyCode::Char('4')));
        assert_eq!(app.screen, Screen::CloudflareDns);
        for _ in 0..4 {
            app.handle_key(key(KeyCode::Down));
        }
        assert_eq!(app.cf_dns.active_field, 4);
        app.handle_key(key(KeyCode::Char(' ')));
        assert!(app.cf_dns.enabled);
        assert_eq!(app.session.cf_enabled.as_deref(), Some("true"));
        assert_eq!(state.cf_enabled()?, Some("true".to_string()));

        app.handle_key(key(KeyCode::Down)); // wraps to field 0
        assert_eq!(app.cf_dns.active_field, 0);
        app.handle_key(key(KeyCode::Char('t')));
        assert!(!app.cf_dns.enabled);
        assert_eq!(app.session.cf_enabled.as_deref(), Some("false"));
        assert_eq!(state.cf_enabled()?, Some("false".to_string()));

        // 2. Toggle GitHub Deploy in GithubDeploy (field 4 guards 'e', toggles on Space/Enter/Left/Right, and 't' anywhere)
        app.handle_key(key(KeyCode::Char('b')));
        app.handle_key(key(KeyCode::Char('5')));
        assert_eq!(app.screen, Screen::GithubDeploy);
        for _ in 0..4 {
            app.handle_key(key(KeyCode::Down));
        }
        assert_eq!(app.github_deploy.active_field, 4);
        app.handle_key(key(KeyCode::Char('e')));
        assert!(!app.github_deploy.editing);

        app.handle_key(key(KeyCode::Char(' ')));
        assert!(app.github_deploy.enabled);
        assert_eq!(app.session.github_enabled.as_deref(), Some("true"));
        assert_eq!(state.github_enabled()?, Some("true".to_string()));

        app.handle_key(key(KeyCode::Right));
        assert!(!app.github_deploy.enabled);
        assert_eq!(state.github_enabled()?, Some("false".to_string()));

        app.handle_key(key(KeyCode::Left));
        assert!(app.github_deploy.enabled);
        assert_eq!(state.github_enabled()?, Some("true".to_string()));

        app.handle_key(key(KeyCode::Enter));
        assert!(!app.github_deploy.enabled);
        assert_eq!(state.github_enabled()?, Some("false".to_string()));

        app.handle_key(key(KeyCode::Down)); // wraps to field 0
        assert_eq!(app.github_deploy.active_field, 0);
        app.handle_key(key(KeyCode::Char('t')));
        assert!(app.github_deploy.enabled);
        assert_eq!(state.github_enabled()?, Some("true".to_string()));

        // 3. Toggle both from BuildBox ('d' / Space for DNS, 'g' for GitHub) and verify reverse sync
        app.handle_key(key(KeyCode::Esc));
        app.handle_key(key(KeyCode::Char('7')));
        assert_eq!(app.screen, Screen::BuildBox);

        app.handle_key(key(KeyCode::Char('d')));
        assert!(app.cf_dns.enabled);
        assert_eq!(state.cf_enabled()?, Some("true".to_string()));

        app.handle_key(key(KeyCode::Char('g')));
        assert!(!app.github_deploy.enabled);
        assert_eq!(state.github_enabled()?, Some("false".to_string()));
        assert!(app.status_message.contains("GitHub Repo Deploy toggled OFF"));

        // Verify Home and submenus reflect BuildBox toggles
        app.handle_key(key(KeyCode::Char('q')));
        let home_view = render_to_string(&app);
        assert!(home_view.contains("Cloudflare DNS: (not set) / @ (enabled=ON"));
        assert!(home_view.contains("GitHub Repo: (not set) (enabled=OFF"));

        app.handle_key(key(KeyCode::Char('4')));
        assert!(render_to_string(&app).contains("CF_ENABLED=ON"));
        app.handle_key(key(KeyCode::Char('q')));
        app.handle_key(key(KeyCode::Char('5')));
        assert!(render_to_string(&app).contains("GITHUB_ENABLED=OFF"));

        // Verify fresh reload from state.conf preserves both states
        let reloaded = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert!(reloaded.cf_dns.enabled);
        assert!(!reloaded.github_deploy.enabled);
        Ok(())
    }

    #[test]
    fn rendered_toggle_indicators_use_light_green_for_on_and_light_red_for_off() {
        let _lock = crate::env_lock();
        let mut app = TuiApp::new(
            SessionData {
                cf_zone: Some("example.com".to_string()),
                cf_enabled: Some("true".to_string()),
                github_repo: Some("octocat/my-app".to_string()),
                github_enabled: Some("false".to_string()),
                ..Default::default()
            },
            ApiKeyForm::default(),
        );

        // Home + bottom pane
        app.screen = Screen::Home;
        let home_buf = render_to_buffer(&app);
        assert_token_fg_in_row(&home_buf, "(enabled=ON,", "ON", Color::LightGreen);
        assert_token_fg_in_row(&home_buf, "(enabled=OFF,", "OFF", Color::LightRed);
        assert_token_fg_in_row(&home_buf, "DNS / Repo:    ON (example.com)", "ON", Color::LightGreen);
        assert_token_fg_in_row(&home_buf, "/ OFF (octocat", "OFF", Color::LightRed);

        // CloudflareDns (ON -> LightGreen)
        app.screen = Screen::CloudflareDns;
        app.cf_dns.active_field = 0;
        let cf_on_buf = render_to_buffer(&app);
        assert_token_fg_in_row(&cf_on_buf, "(CF_ENABLED): ON", "ON", Color::LightGreen);
        assert_token_fg_in_row(&cf_on_buf, "CF_ENABLED=ON", "ON", Color::LightGreen);

        // CloudflareDns (OFF -> LightRed)
        app.cf_dns.enabled = false;
        let cf_off_buf = render_to_buffer(&app);
        assert_token_fg_in_row(&cf_off_buf, "(CF_ENABLED): OFF", "OFF", Color::LightRed);
        assert_token_fg_in_row(&cf_off_buf, "CF_ENABLED=OFF", "OFF", Color::LightRed);

        // GithubDeploy (OFF -> LightRed, then ON -> LightGreen)
        app.screen = Screen::GithubDeploy;
        app.github_deploy.active_field = 0;
        let gh_off_buf = render_to_buffer(&app);
        assert_token_fg_in_row(&gh_off_buf, "(GITHUB_ENABLED): OFF", "OFF", Color::LightRed);
        assert_token_fg_in_row(&gh_off_buf, "GITHUB_ENABLED=OFF", "OFF", Color::LightRed);

        app.github_deploy.enabled = true;
        let gh_on_buf = render_to_buffer(&app);
        assert_token_fg_in_row(&gh_on_buf, "(GITHUB_ENABLED): ON", "ON", Color::LightGreen);
        assert_token_fg_in_row(&gh_on_buf, "GITHUB_ENABLED=ON", "ON", Color::LightGreen);

        // BuildBox (CF OFF -> LightRed, GH ON -> LightGreen, then flip both)
        app.screen = Screen::BuildBox;
        let bb_buf_1 = render_to_buffer(&app);
        assert_token_fg_in_row(&bb_buf_1, "Cloudflare DNS: OFF", "OFF", Color::LightRed);
        assert_token_fg_in_row(&bb_buf_1, "GitHub Repo Deploy: ON", "ON", Color::LightGreen);

        app.cf_dns.enabled = true;
        app.github_deploy.enabled = false;
        let bb_buf_2 = render_to_buffer(&app);
        assert_token_fg_in_row(&bb_buf_2, "Cloudflare DNS: ON", "ON", Color::LightGreen);
        assert_token_fg_in_row(&bb_buf_2, "GitHub Repo Deploy: OFF", "OFF", Color::LightRed);
    }

    #[test]
    fn execute_build_skips_github_when_off_warns_when_empty_and_runs_when_on() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.build_dry_run = true;
        app.github_deploy.repo = "octocat/my-app".to_string();
        app.github_deploy.enabled = false;

        // 1. GitHub OFF (even with repo configured) -> skipped
        app.execute_build();
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[BUILD] Starting DRY-RUN build") && l.contains("github=OFF")));
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[GITHUB] GitHub Repo Deploy is OFF (skipped)")));
        assert!(!app.logs.iter().any(|l| l.contains("REPO_URL=")));

        // 2. GitHub ON with empty repo -> warning logged
        app.logs.clear();
        app.github_deploy.enabled = true;
        app.github_deploy.repo.clear();
        app.execute_build();
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[BUILD] Starting DRY-RUN build") && l.contains("github=ON")));
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[GITHUB] Warning: GitHub Deploy is ON but GITHUB_REPO is empty")));
        assert!(!app.logs.iter().any(|l| l.contains("REPO_URL=")));

        // 3. GitHub ON with valid repo -> runs GitHub deploy in ConfigureRole
        app.logs.clear();
        app.github_deploy.repo = "octocat/my-app".to_string();
        app.execute_build();
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[BUILD] Starting DRY-RUN build") && l.contains("github=ON")));
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[GITHUB] Deploying 'octocat/my-app' (branch: main)")));
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[DRY-RUN] Configure Server Role (simulated)")));
        assert!(!app
            .logs
            .iter()
            .any(|l| l.contains("[GITHUB] GitHub Repo Deploy is OFF (skipped)")));
        let role_script = crate::setup::build_step_script(
            SetupStepKind::ConfigureRole,
            &SetupConfig {
                host: "100.64.0.1".to_string(),
                ssh_user: "root".to_string(),
                new_username: app.access.username.clone(),
                hostname: app.access.hostname.clone(),
                role: app.selected_role,
                provider_name: app.selected_provider.to_string(),
                tailscale_mode: true,
                ssh_pubkey: None,
                sudo_nopasswd: true,
                sudo_password: None,
                dry_run: true,
                github_deploy: Some(GithubDeployConfig {
                    repo: "octocat/my-app".to_string(),
                    branch: "main".to_string(),
                    deploy_path: None,
                    deploy_cmd: None,
                    github_token: None,
                    username: app.access.username.clone(),
                }),
            },
        );
        assert!(role_script.contains("REPO_URL='https://github.com/octocat/my-app.git'"));
        Ok(())
    }

    #[test]
    fn record_step_dry_run_and_live_summaries_and_bottom_pane_dry_run_target() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;

        // Dry-run record_step suppresses raw bash script lines
        app.record_step(&StepReport {
            step: SetupStepKind::ConfigureMotd,
            success: true,
            dry_run: true,
            output: "chmod +x /etc/profile.d/vps-dashboard.sh\n;;\nesac\n".to_string(),
        });
        assert_eq!(
            app.logs,
            vec!["[DRY-RUN] Configure MOTD Dashboard (simulated)".to_string()]
        );
        assert!(!app
            .logs
            .iter()
            .any(|l| l.contains("chmod +x /etc/profile.d/vps-dashboard.sh") || l.contains("esac")));

        // Live record_step keeps trailing 2 lines on success and trailing 3 lines on failure
        app.logs.clear();
        app.record_step(&StepReport {
            step: SetupStepKind::SystemUpdate,
            success: true,
            dry_run: false,
            output: "line 1\nline 2\nline 3\n\nline 4\n".to_string(),
        });
        assert_eq!(
            app.logs,
            vec![
                "[OK] System Update & Base Packages".to_string(),
                "  line 3".to_string(),
                "  line 4".to_string(),
            ]
        );

        app.logs.clear();
        app.record_step(&StepReport {
            step: SetupStepKind::CreateUser,
            success: false,
            dry_run: false,
            output: "err 1\nerr 2\nerr 3\nerr 4\n".to_string(),
        });
        assert_eq!(
            app.logs,
            vec![
                "[FAIL] Create Non-Root User & Sudo".to_string(),
                "  err 2".to_string(),
                "  err 3".to_string(),
                "  err 4".to_string(),
            ]
        );

        // Execute dry-run build and verify bottom pane shows (dry-run) IP while state.conf stays empty
        app.logs.clear();
        app.build_dry_run = true;
        app.execute_build();
        assert_eq!(app.last_dry_run_target, Some("100.64.0.1".to_string()));
        assert!(!app
            .logs
            .iter()
            .any(|l| l.contains("chmod +x /etc/profile.d/vps-dashboard.sh") || l.contains("esac")));
        let rendered = render_to_string(&app);
        assert!(rendered.contains("100.64.0.1 (dry-run)"));

        let state = SessionState::new(&state_path);
        assert_eq!(state.vps_ip()?, None);
        assert_eq!(state.tailscale_ip()?, None);
        assert_eq!(state.public_ip()?, None);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn execute_build_with_ui_progressive_updates_and_ssh_user_fallback_via_mock_ssh() -> Result<()> {
        use std::fs::{self, File};
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        struct EnvGuard {
            saved: Vec<(String, Option<String>)>,
        }
        impl EnvGuard {
            fn new(keys: &[&str]) -> Self {
                Self {
                    saved: keys
                        .iter()
                        .map(|k| ((*k).to_string(), std::env::var(k).ok()))
                        .collect(),
                }
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

        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&["BAB_SSH_BIN", "BAB_SSH_POLL_MS"]);

        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");
        let mock_ssh = dir.path().join("mock-ssh.sh");

        {
            let mut f = File::create(&mock_ssh)?;
            writeln!(
                f,
                r#"#!/bin/sh
cat >/dev/null
case "$*" in
  *root@*)
    echo 'tailnet policy does not permit you to SSH as user "root"' >&2
    exit 255
    ;;
  *deploy@*)
    echo "mock ok line 1"
    echo "mock ok line 2"
    echo "mock ok line 3"
    exit 0
    ;;
  *)
    echo "unexpected target: $*" >&2
    exit 1
    ;;
esac"#
            )?;
        }
        fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755))?;
        std::env::set_var("BAB_SSH_BIN", &mock_ssh);
        std::env::set_var("BAB_SSH_POLL_MS", "10");

        let state = SessionState::new(&state_path);
        state.save_session(&SessionData {
            vps_provider: Some("existing_tailscale".to_string()),
            vps_ip: Some("100.64.9.9".to_string()),
            tailscale_ip: Some("100.64.9.9".to_string()),
            username: Some("deploy".to_string()),
            transport_mode: Some("tailscale".to_string()),
            ..Default::default()
        })?;

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.build_dry_run = false;
        app.screen = Screen::BuildBox;

        let mut snapshots: Vec<(usize, String, Option<String>)> = Vec::new();
        app.handle_key_with_ui(key(KeyCode::Enter), |snapshot| {
            let completed = snapshot
                .progress_steps
                .iter()
                .filter(|(_, s)| s.is_some())
                .count();
            snapshots.push((
                completed,
                snapshot.status_message.clone(),
                snapshot.logs.last().cloned(),
            ));
        });

        // Verify progressive callbacks occurred before completion (0 completed -> 1..=6 completed)
        assert!(snapshots.len() >= 9, "expected >= 9 UI updates, got {}", snapshots.len());
        assert_eq!(snapshots[0].0, 0);
        assert!(snapshots.iter().any(|(c, _, _)| *c == 1));
        assert!(snapshots.iter().any(|(c, _, _)| *c == 3));
        assert_eq!(snapshots.last().unwrap().0, 6);

        assert!(app.progress_steps.iter().all(|(_, s)| *s == Some(true)));
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[SSH] Connected to deploy@100.64.9.9")));
        // Only trailing 2 summary lines per passing live step (line 1 omitted)
        assert!(app.logs.iter().any(|l| l == "  mock ok line 2"));
        assert!(app.logs.iter().any(|l| l == "  mock ok line 3"));
        assert!(!app.logs.iter().any(|l| l == "  mock ok line 1"));
        // Persistent log retains full step output including line 1
        let persisted = LogStore::new(app.log_path.as_ref().unwrap()).read_lines()?;
        assert!(persisted.iter().any(|l| l.contains("mock ok line 1")));
        Ok(())
    }

    #[test]
    fn from_paths_resolves_bab_log_file_env_and_sibling_fallback() -> Result<()> {
        struct EnvGuard(Option<String>);
        impl Drop for EnvGuard {
            fn drop(&mut self) {
                match self.0.take() {
                    Some(v) => std::env::set_var("BAB_LOG_FILE", v),
                    None => std::env::remove_var("BAB_LOG_FILE"),
                }
            }
        }

        let _lock = crate::env_lock();
        let _guard = EnvGuard(std::env::var("BAB_LOG_FILE").ok());
        std::env::remove_var("BAB_LOG_FILE");

        let in_mem = TuiApp::new(SessionData::default(), ApiKeyForm::default());
        assert_eq!(in_mem.log_path, None);
        assert_eq!(in_mem.resolved_log_display(), "~/.config/bab/bab.log");

        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let app_sibling = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert_eq!(app_sibling.log_path, Some(dir.path().join("bab.log")));

        let custom_log = dir.path().join("nested").join("custom.log");
        std::env::set_var("BAB_LOG_FILE", format!("  {}  ", custom_log.display()));
        let app_env = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert_eq!(app_env.log_path, Some(custom_log));
        Ok(())
    }

    #[test]
    fn view_log_persists_dry_run_build_reloads_scrolls_and_clears() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");
        let log_path = dir.path().join("bab.log");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert_eq!(app.log_path.as_ref(), Some(&log_path));

        // Open ViewLog before any entries and verify helpful empty message
        app.handle_key(key(KeyCode::Char('9')));
        assert_eq!(app.screen, Screen::ViewLog);
        let empty_view = render_to_string(&app);
        assert!(empty_view.contains("View Log"));
        assert!(empty_view.contains("Log Contents (bab.log)"));
        assert!(empty_view.contains("0600 permissions"));
        assert!(empty_view.contains("10.00 MB max (auto-trimmed)"));
        assert!(empty_view.contains("No log entries recorded yet."));
        app.handle_key(key(KeyCode::Char('q')));
        assert_eq!(app.screen, Screen::Home);
        assert!(!app.should_quit);

        // Run a dry-run build and verify bab.log persists entries on disk
        app.build_dry_run = true;
        app.execute_build();
        let disk_lines = LogStore::new(&log_path).read_lines()?;
        assert!(!disk_lines.is_empty());
        assert!(disk_lines.iter().any(|l| l.contains("[BUILD] Starting DRY-RUN build")));
        assert!(disk_lines.iter().any(|l| l.contains("[DRY-RUN] Simulated")));
        assert!(disk_lines.iter().any(|l| l.contains("[DRY-RUN] System Update & Base Packages")));
        assert!(disk_lines.iter().any(|l| l.contains("[DNS] Cloudflare DNS is OFF (skipped)")));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&log_path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        // Open ViewLog via '9' and verify contents + scrolling
        app.handle_key(key(KeyCode::Char('9')));
        assert_eq!(app.screen, Screen::ViewLog);
        assert_eq!(app.log_scroll, app.log_view_lines.len().saturating_sub(1));

        let view = render_to_string(&app);
        assert!(view.contains("Entries:"));
        assert!(view.contains("Log Contents (bab.log)"));

        // Home ('g'), Down ('j'), PageDown ('d'), PageUp ('u'), End ('G'), Up ('k')
        app.handle_key(key(KeyCode::Char('g')));
        assert_eq!(app.log_scroll, 0);
        let top_view = render_to_string(&app);
        assert!(top_view.contains("[BUILD] Starting DRY-RUN build"));
        assert!(top_view.contains("Offset: 0"));

        app.handle_key(key(KeyCode::Char('j')));
        assert_eq!(app.log_scroll, 1);
        app.handle_key(key(KeyCode::Char('k')));
        assert_eq!(app.log_scroll, 0);
        app.handle_key(key(KeyCode::Char('d')));
        assert!(app.log_scroll > 0);
        app.handle_key(key(KeyCode::Char('u')));
        assert_eq!(app.log_scroll, 0);
        app.handle_key(key(KeyCode::Char('G')));
        assert_eq!(app.log_scroll, app.log_view_lines.len().saturating_sub(1));

        // External write to bab.log + 'r' reloads it
        LogStore::new(&log_path).append_line("[2026-11-15T20:00:00Z] [OK] External reload marker")?;
        app.handle_key(key(KeyCode::Char('r')));
        assert!(app
            .log_view_lines
            .iter()
            .any(|l| l.contains("External reload marker")));
        assert_eq!(app.status_message, "Reloaded log file from disk");
        let reloaded_view = render_to_string(&app);
        assert!(reloaded_view.contains("External reload marker"));

        // 'c' clears bab.log, log_view_lines, and logs
        app.handle_key(key(KeyCode::Char('c')));
        assert!(app.log_view_lines.is_empty());
        assert!(app.logs.is_empty());
        assert_eq!(app.log_scroll, 0);
        assert_eq!(app.status_message, "Cleared bab.log");
        assert!(LogStore::new(&log_path).read_lines()?.is_empty());

        // 'b' returns to Home without quitting
        app.handle_key(key(KeyCode::Char('b')));
        assert_eq!(app.screen, Screen::Home);
        assert!(!app.should_quit);
        Ok(())
    }

    #[test]
    fn access_config_sudo_nopasswd_toggles_saves_and_reloads() -> Result<()> {
        let _lock = crate::env_lock();

        // AccessForm::from_session parsing variants
        for raw in ["false", " FALSE ", "0", "no", "OFF"] {
            let form = AccessForm::from_session(&SessionData {
                sudo_nopasswd: Some(raw.to_string()),
                ..Default::default()
            });
            assert!(
                !form.sudo_nopasswd,
                "expected '{}' to disable sudo_nopasswd",
                raw
            );
        }
        for raw in ["true", " TRUE ", "1", "yes", "On", "unrecognized"] {
            let form = AccessForm::from_session(&SessionData {
                sudo_nopasswd: Some(raw.to_string()),
                ..Default::default()
            });
            assert!(
                form.sudo_nopasswd,
                "expected '{}' to enable sudo_nopasswd",
                raw
            );
        }
        assert!(AccessForm::from_session(&SessionData::default()).sudo_nopasswd);

        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert!(app.access.sudo_nopasswd);

        app.handle_key(key(KeyCode::Char('3')));
        assert_eq!(app.screen, Screen::AccessConfig);
        assert_eq!(app.access.active_field, 0);

        // 'e' on field 0 (Transport Mode) must not enter text-editing mode
        app.handle_key(key(KeyCode::Char('e')));
        assert!(!app.access.editing);

        // 'p' from field 0 toggles sudo_nopasswd OFF and updates status_message
        app.handle_key(key(KeyCode::Char('p')));
        assert!(!app.access.sudo_nopasswd);
        assert!(app.status_message.contains("OFF (password required)"));

        // Navigate to field 4 (Passwordless Sudo)
        for _ in 0..4 {
            app.handle_key(key(KeyCode::Down));
        }
        assert_eq!(app.access.active_field, 4);

        // 'e' on field 4 must not enter text-editing mode
        app.handle_key(key(KeyCode::Char('e')));
        assert!(!app.access.editing);

        // Toggle via Space, Enter, Left, Right on field 4
        app.handle_key(key(KeyCode::Char(' ')));
        assert!(app.access.sudo_nopasswd);
        assert!(app.status_message.contains("ON (NOPASSWD:ALL)"));
        assert!(!app.access.editing);

        app.handle_key(key(KeyCode::Enter));
        assert!(!app.access.sudo_nopasswd);
        assert!(!app.access.editing);

        app.handle_key(key(KeyCode::Left));
        assert!(app.access.sudo_nopasswd);

        app.handle_key(key(KeyCode::Right));
        assert!(!app.access.sudo_nopasswd);

        // Preview pane shows SUDO_NOPASSWD:  false
        let preview_off = render_to_string(&app);
        assert!(preview_off.contains("SUDO_NOPASSWD:  false"));
        assert!(preview_off.contains("Passwordless Sudo (SUDO_NOPASSWD): OFF (password required)"));

        // Save with 's' -> persists SUDO_NOPASSWD="false"
        app.handle_key(key(KeyCode::Char('s')));
        let state = SessionState::new(&state_path);
        assert_eq!(state.sudo_nopasswd()?, Some("false".to_string()));
        assert_eq!(app.session.sudo_nopasswd.as_deref(), Some("false"));

        // Reload via from_paths and verify false is restored
        let mut reloaded = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert!(!reloaded.access.sudo_nopasswd);

        // Toggle back ON via 'p' and save -> persists SUDO_NOPASSWD="true"
        reloaded.screen = Screen::AccessConfig;
        reloaded.handle_key(key(KeyCode::Char('p')));
        assert!(reloaded.access.sudo_nopasswd);
        reloaded.handle_key(key(KeyCode::Char('s')));
        assert_eq!(state.sudo_nopasswd()?, Some("true".to_string()));

        let reloaded_on = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert!(reloaded_on.access.sudo_nopasswd);
        Ok(())
    }

    #[test]
    fn build_box_sudo_nopasswd_syncs_renders_colors_and_fits_sizes() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.screen = Screen::BuildBox;

        // Verify ON rendering & bright green color on BuildBox, AccessConfig, Home, and bottom pane
        let bb_on_buf = render_to_buffer(&app);
        assert_token_fg_in_row(
            &bb_on_buf,
            "Passwordless Sudo: ON (NOPASSWD:ALL)",
            "ON (NOPASSWD:ALL)",
            Color::LightGreen,
        );
        assert_token_fg_in_row(&bb_on_buf, "(nopasswd)", "nopasswd", Color::LightGreen);

        // Toggle OFF in BuildBox via 'p' -> persists immediately and syncs everywhere
        app.handle_key(key(KeyCode::Char('p')));
        assert!(!app.access.sudo_nopasswd);
        assert!(app.status_message.contains("OFF (password required)"));

        let state = SessionState::new(&state_path);
        assert_eq!(state.sudo_nopasswd()?, Some("false".to_string()));
        assert_eq!(app.session.sudo_nopasswd.as_deref(), Some("false"));

        let bb_off_buf = render_to_buffer(&app);
        assert_token_fg_in_row(
            &bb_off_buf,
            "Passwordless Sudo: OFF (password required)",
            "OFF (password required)",
            Color::LightRed,
        );
        assert_token_fg_in_row(&bb_off_buf, "(passwd)", "passwd", Color::LightRed);

        // AccessConfig reflects BuildBox toggle and uses LightRed / LightGreen
        app.screen = Screen::AccessConfig;
        let ac_off_buf = render_to_buffer(&app);
        assert_token_fg_in_row(
            &ac_off_buf,
            "Passwordless Sudo (SUDO_NOPASSWD): OFF (password required)",
            "OFF (password required)",
            Color::LightRed,
        );
        assert_token_fg_in_row(&ac_off_buf, "SUDO_NOPASSWD:  false", "false", Color::LightRed);

        app.access.toggle_sudo_nopasswd();
        let ac_on_buf = render_to_buffer(&app);
        assert_token_fg_in_row(
            &ac_on_buf,
            "Passwordless Sudo (SUDO_NOPASSWD): ON (NOPASSWD:ALL)",
            "ON (NOPASSWD:ALL)",
            Color::LightGreen,
        );
        assert_token_fg_in_row(&ac_on_buf, "SUDO_NOPASSWD:  true", "true", Color::LightGreen);
        app.access.toggle_sudo_nopasswd();

        // Home reflects OFF (LightRed) and ON (LightGreen)
        app.screen = Screen::Home;
        let home_off_buf = render_to_buffer(&app);
        assert_token_fg_in_row(&home_off_buf, "(passwordless: OFF)", "OFF", Color::LightRed);

        // Verify 120x40 frame and 80x24 render_build_box fit cleanly without clipping lines
        app.screen = Screen::BuildBox;
        let render_dims = |w: u16, h: u16, full_frame: bool| -> String {
            let backend = TestBackend::new(w, h);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| {
                    if full_frame {
                        app.render_frame(frame);
                    } else {
                        app.render_build_box(frame, frame.area());
                    }
                })
                .unwrap();
            let buf = terminal.backend().buffer().clone();
            let mut out = String::new();
            for y in 0..buf.area.height {
                for x in 0..buf.area.width {
                    if let Some(cell) = buf.cell((x, y)) {
                        out.push_str(cell.symbol());
                    }
                }
                out.push('\n');
            }
            out
        };

        let large = render_dims(120, 40, true);
        assert!(large.contains("Provider:"));
        assert!(large.contains("Passwordless Sudo: OFF (password required)"));
        assert!(large.contains("['p': Toggle Passwordless Sudo]"));
        assert!(large.contains("Credentials:"));
        assert!(large.contains("p: Sudo"));

        let small = render_dims(80, 24, false);
        assert!(small.contains("Provider:"));
        assert!(small.contains("Passwordless Sudo: OFF (password required)"));
        assert!(small.contains("Credentials:"));
        assert!(small.contains("p: Sudo"));
        Ok(())
    }

    #[test]
    fn dry_run_build_with_sudo_nopasswd_false_propagates_to_setup_config() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.build_dry_run = true;
        app.screen = Screen::BuildBox;
        app.handle_key(key(KeyCode::Char('p')));
        assert!(!app.access.sudo_nopasswd);

        let log_path = dir.path().join("bab.log");
        app.execute_build();

        assert!(app.progress_steps.iter().all(|(_, s)| *s == Some(true)));
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[BUILD] Starting DRY-RUN build") && l.contains("sudo_nopasswd=OFF")));

        // Verify persisted log (which records full dry-run scripts) contains CreateUser without
        // NOPASSWD:ALL and ConfigureMotd cleanup of /etc/sudoers.d/.
        let disk_log = LogStore::new(&log_path).read_lines()?.join("\n");
        assert!(!disk_log.contains("NOPASSWD:ALL"));
        assert!(disk_log.contains("rm -f \"/etc/sudoers.d/${NEW_USER}\""));

        // Also directly assert SetupConfig propagation semantics used by execute_build_with_ui
        let cfg = SetupConfig {
            host: "100.64.0.1".to_string(),
            ssh_user: "root".to_string(),
            new_username: app.access.username.clone(),
            hostname: app.access.hostname.clone(),
            role: app.selected_role,
            provider_name: app.selected_provider.to_string(),
            tailscale_mode: app.is_tailscale_mode(),
            ssh_pubkey: None,
            sudo_nopasswd: app.access.sudo_nopasswd,
            sudo_password: Some(app.access.sudo_password.clone()),
            dry_run: true,
            github_deploy: None,
        };
        let create_user_script = crate::setup::build_step_script(SetupStepKind::CreateUser, &cfg);
        assert!(!create_user_script.contains("NOPASSWD:ALL"));
        let motd_script = crate::setup::build_step_script(SetupStepKind::ConfigureMotd, &cfg);
        assert!(motd_script.contains("rm -f \"/etc/sudoers.d/${NEW_USER}\""));
        Ok(())
    }

    #[test]
    fn build_box_random_password_show_hide_and_regenerate_persist() -> Result<()> {
        let _lock = crate::env_lock();
        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        // Empty/default session generates a 10-char ASCII alphanumeric password
        let form = AccessForm::default();
        assert_eq!(form.sudo_password.len(), SUDO_PASSWORD_LEN);
        assert!(form.sudo_password.chars().all(|c| c.is_ascii_alphanumeric()));

        let from_empty = AccessForm::from_session(&SessionData {
            sudo_password: Some("   ".to_string()),
            ..Default::default()
        });
        assert_eq!(from_empty.sudo_password.len(), SUDO_PASSWORD_LEN);
        assert!(from_empty
            .sudo_password
            .chars()
            .all(|c| c.is_ascii_alphanumeric()));

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        let initial_pw = app.access.sudo_password.clone();
        assert_eq!(initial_pw.len(), SUDO_PASSWORD_LEN);
        assert!(initial_pw.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(!app.show_password);

        app.screen = Screen::BuildBox;
        let masked_render = {
            let backend = TestBackend::new(120, 40);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal.draw(|frame| app.render_frame(frame)).unwrap();
            let buf = terminal.backend().buffer().clone();
            let mut out = String::new();
            for y in 0..buf.area.height {
                for x in 0..buf.area.width {
                    out.push_str(buf.cell((x, y)).unwrap().symbol());
                }
                out.push('\n');
            }
            out
        };
        assert!(masked_render.contains("Sudo Password: ••••••••••"));
        assert!(masked_render.contains("Sudo Pass:     •••••••••• ('w': Show/Hide)"));
        assert!(masked_render.contains("Live Build Activity"));
        assert!(masked_render.contains("w: Show/Hide Password | r: New Password"));
        assert!(!masked_render.contains(&initial_pw));

        // 'w' toggles plain password visibility
        app.handle_key(key(KeyCode::Char('w')));
        assert!(app.show_password);
        assert_eq!(app.status_message, "Sudo password visible");
        let plain_render = render_to_string(&app);
        assert!(plain_render.contains(&initial_pw));

        // 'r' regenerates a new 10-char password and persists to state.conf & credentials.enc
        let mut regenerated = initial_pw.clone();
        for _ in 0..3 {
            app.handle_key(key(KeyCode::Char('r')));
            regenerated = app.access.sudo_password.clone();
            if regenerated != initial_pw {
                break;
            }
        }
        assert_ne!(regenerated, initial_pw);
        assert_eq!(regenerated.len(), SUDO_PASSWORD_LEN);
        assert!(regenerated.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_eq!(
            SessionState::new(&state_path).sudo_password()?.as_deref(),
            Some(regenerated.as_str())
        );
        assert_eq!(
            Settings::new(&settings_path)
                .lookup_instance_password(None, Some(&app.access.hostname), None)?
                .as_deref(),
            Some(regenerated.as_str())
        );

        // 'w' hides password again
        app.handle_key(key(KeyCode::Char('w')));
        assert!(!app.show_password);
        assert_eq!(app.status_message, "Sudo password hidden");

        // Reloading from_paths restores the persisted password
        let reloaded = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        assert_eq!(reloaded.access.sudo_password, regenerated);
        Ok(())
    }

    #[test]
    fn running_instances_shows_masked_sudo_pass_toggles_w_and_cleans_up_tailscale_on_destroy(
    ) -> Result<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        };
        use std::thread;

        struct EnvGuard {
            saved: Vec<(String, Option<String>)>,
        }
        impl EnvGuard {
            fn new(keys: &[&str]) -> Self {
                Self {
                    saved: keys
                        .iter()
                        .map(|k| ((*k).to_string(), std::env::var(k).ok()))
                        .collect(),
                }
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

        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "VULTR_API_BASE_URL",
            "UPCLOUD_API_BASE_URL",
            "LINODE_API_BASE_URL",
            "TAILSCALE_API_BASE",
        ]);

        let vultr_listener = TcpListener::bind("127.0.0.1:0")?;
        let vultr_addr = vultr_listener.local_addr()?;
        let ts_listener = TcpListener::bind("127.0.0.1:0")?;
        let ts_addr = ts_listener.local_addr()?;

        let stop = Arc::new(AtomicBool::new(false));
        let vultr_destroyed = Arc::new(AtomicBool::new(false));
        let ts_deleted_ids: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        let stop_v = Arc::clone(&stop);
        let vultr_destroyed_bg = Arc::clone(&vultr_destroyed);
        let vultr_handle = thread::spawn(move || {
            for stream_res in vultr_listener.incoming() {
                if stop_v.load(Ordering::SeqCst) {
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
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                let mut parts = req_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");
                let (status, body) = if method == "GET" && path.starts_with("/v2/instances") {
                    (
                        "200 OK",
                        r#"{"instances":[{"id":"vultr-pw-1","label":"edge-pw-box","status":"active","power_status":"running","main_ip":"203.0.113.88","region":"ewr","plan":"vc2-1c-1gb"}],"meta":{"links":{"next":""}}}"#,
                    )
                } else if method == "DELETE" && path == "/v2/instances/vultr-pw-1" {
                    vultr_destroyed_bg.store(true, Ordering::SeqCst);
                    ("204 No Content", "")
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

        let stop_t = Arc::clone(&stop);
        let ts_deleted_bg = Arc::clone(&ts_deleted_ids);
        let ts_handle = thread::spawn(move || {
            for stream_res in ts_listener.incoming() {
                if stop_t.load(Ordering::SeqCst) {
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
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                let mut parts = req_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");
                let (status, body) = if method == "GET" && path == "/tailnet/-/devices" {
                    let deleted = ts_deleted_bg.lock().unwrap();
                    if deleted.iter().any(|id| id == "ts-dev-1") {
                        ("200 OK", r#"{"devices":[]}"#)
                    } else {
                        (
                            "200 OK",
                            r#"{"devices":[{"id":"ts-dev-1","hostname":"edge-pw-box","name":"edge-pw-box.tailnet.ts.net","addresses":["100.64.5.5"],"online":true}]}"#,
                        )
                    }
                } else if method == "DELETE" && path == "/device/ts-dev-1" {
                    ts_deleted_bg.lock().unwrap().push("ts-dev-1".to_string());
                    ("200 OK", "{}")
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

        std::env::set_var("VULTR_API_BASE_URL", format!("http://{}/v2", vultr_addr));
        std::env::set_var("TAILSCALE_API_BASE", format!("http://{}", ts_addr));

        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        let state = SessionState::new(&state_path);
        state.save_session(&SessionData {
            vps_provider: Some("vultr".to_string()),
            vps_instance_id: Some("vultr-pw-1".to_string()),
            vps_ip: Some("100.64.5.5".to_string()),
            public_ip: Some("203.0.113.88".to_string()),
            tailscale_ip: Some("100.64.5.5".to_string()),
            tailscale_hostname: Some("edge-pw-box".to_string()),
            username: Some("deploy".to_string()),
            sudo_password: Some("AbCdEf1234".to_string()),
            ..Default::default()
        })?;

        let settings = Settings::new(&settings_path);
        settings.set_vultr_api_key("vultr-test-key")?;
        settings.set_tailscale_api_key("ts-test-key")?;
        settings.record_instance_password(
            Some("vultr-pw-1"),
            Some("edge-pw-box"),
            Some("203.0.113.88"),
            "AbCdEf1234",
        )?;

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.handle_key(key(KeyCode::Char('8')));
        assert_eq!(app.screen, Screen::RunningInstances);
        assert_eq!(app.running_instances.len(), 1);

        let masked = render_to_string(&app);
        assert!(masked.contains("SUDO PASS"));
        assert!(masked.contains("••••••••••"));
        assert!(masked.contains("w: Show/Hide Pass"));
        assert!(!masked.contains("AbCdEf1234"));

        // Press 'w' to show password in table and selected summary
        app.handle_key(key(KeyCode::Char('w')));
        assert!(app.show_password);
        let plain = render_to_string(&app);
        assert!(plain.contains("AbCdEf1234"));

        // Destroy instance -> deletes cloud VM AND removes matching Tailscale device
        app.handle_key(key(KeyCode::Char('d')));
        app.handle_key(key(KeyCode::Char('y')));
        assert!(vultr_destroyed.load(Ordering::SeqCst));
        assert_eq!(ts_deleted_ids.lock().unwrap().as_slice(), &["ts-dev-1"]);
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[TAILSCALE] Removed device(s) from tailnet: edge-pw-box (ts-dev-1)")));
        assert!(app.status_message.contains("removed Tailscale device(s): edge-pw-box (ts-dev-1)"));

        stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(vultr_addr);
        let _ = std::net::TcpStream::connect(ts_addr);
        vultr_handle.join().unwrap();
        ts_handle.join().unwrap();
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn execute_build_with_ui_fires_provision_and_step_callbacks_with_mock_servers() -> Result<()> {
        use std::fs::{self, File};
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };
        use std::thread;

        struct EnvGuard {
            saved: Vec<(String, Option<String>)>,
        }
        impl EnvGuard {
            fn new(keys: &[&str]) -> Self {
                Self {
                    saved: keys
                        .iter()
                        .map(|k| ((*k).to_string(), std::env::var(k).ok()))
                        .collect(),
                }
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

        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "VULTR_API_BASE_URL",
            "TAILSCALE_API_BASE",
            "BAB_SSH_BIN",
            "BAB_SSH_POLL_MS",
        ]);

        let vultr_listener = TcpListener::bind("127.0.0.1:0")?;
        let vultr_addr = vultr_listener.local_addr()?;
        let ts_listener = TcpListener::bind("127.0.0.1:0")?;
        let ts_addr = ts_listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let ts_stale_deleted = Arc::new(AtomicBool::new(false));
        let ts_key_created = Arc::new(AtomicBool::new(false));

        let stop_v = Arc::clone(&stop);
        let vultr_polls = Arc::new(AtomicUsize::new(0));
        let vultr_polls_bg = Arc::clone(&vultr_polls);
        let vultr_handle = thread::spawn(move || {
            for stream_res in vultr_listener.incoming() {
                if stop_v.load(Ordering::SeqCst) {
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
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                let mut parts = req_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");
                let (status, body) = if method == "GET" && path == "/v2/instances" {
                    ("200 OK", r#"{"instances":[],"meta":{"links":{"next":""}}}"#)
                } else if method == "POST" && path == "/v2/instances" {
                    (
                        "202 Accepted",
                        r#"{"instance":{"id":"vultr-new-9","label":"cb-node","status":"pending","power_status":"stopped","main_ip":"0.0.0.0"}}"#,
                    )
                } else if method == "GET" && path == "/v2/instances/vultr-new-9" {
                    let n = vultr_polls_bg.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        (
                            "200 OK",
                            r#"{"instance":{"id":"vultr-new-9","label":"cb-node","status":"pending","power_status":"stopped","main_ip":"0.0.0.0"}}"#,
                        )
                    } else {
                        (
                            "200 OK",
                            r#"{"instance":{"id":"vultr-new-9","label":"cb-node","status":"active","power_status":"running","main_ip":"203.0.113.99"}}"#,
                        )
                    }
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

        let stop_t = Arc::clone(&stop);
        let ts_stale_bg = Arc::clone(&ts_stale_deleted);
        let ts_key_bg = Arc::clone(&ts_key_created);
        let ts_handle = thread::spawn(move || {
            for stream_res in ts_listener.incoming() {
                if stop_t.load(Ordering::SeqCst) {
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
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                let mut parts = req_line.split_whitespace();
                let method = parts.next().unwrap_or("");
                let path = parts.next().unwrap_or("");
                let (status, body) = if method == "GET" && path == "/tailnet/-/devices" {
                    if !ts_key_bg.load(Ordering::SeqCst) {
                        (
                            "200 OK",
                            r#"{"devices":[{"id":"ts-stale-1","hostname":"cb-node","name":"cb-node.tailnet.ts.net","addresses":["100.64.1.2"],"online":false}]}"#,
                        )
                    } else {
                        (
                            "200 OK",
                            r#"{"devices":[{"id":"ts-live-9","hostname":"cb-node","name":"cb-node.tailnet.ts.net","addresses":["100.64.8.9"],"online":true}]}"#,
                        )
                    }
                } else if method == "DELETE" && path == "/device/ts-stale-1" {
                    ts_stale_bg.store(true, Ordering::SeqCst);
                    ("200 OK", "{}")
                } else if method == "POST" && path == "/tailnet/-/keys" {
                    ts_key_bg.store(true, Ordering::SeqCst);
                    ("200 OK", r#"{"id":"key-1","key":"tskey-auth-mock"}"#)
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

        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");
        let mock_ssh = dir.path().join("mock-ssh.sh");
        {
            let mut f = File::create(&mock_ssh)?;
            writeln!(f, "#!/bin/sh\ncat >/dev/null\necho ok\nexit 0")?;
        }
        fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755))?;

        std::env::set_var("VULTR_API_BASE_URL", format!("http://{}/v2", vultr_addr));
        std::env::set_var("TAILSCALE_API_BASE", format!("http://{}", ts_addr));
        std::env::set_var("BAB_SSH_BIN", &mock_ssh);
        std::env::set_var("BAB_SSH_POLL_MS", "5");

        let settings = Settings::new(&settings_path);
        settings.set_vultr_api_key("vultr-test-key")?;
        settings.set_tailscale_api_key("ts-test-key")?;

        let state = SessionState::new(&state_path);
        state.save_session(&SessionData {
            vps_provider: Some("vultr".to_string()),
            tailscale_hostname: Some("cb-node".to_string()),
            transport_mode: Some("tailscale".to_string()),
            username: Some("deploy".to_string()),
            sudo_password: Some("MyPass1234".to_string()),
            ..Default::default()
        })?;

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.build_dry_run = false;

        let mut saw_logs: Vec<String> = Vec::new();
        app.execute_build_with_ui(|snapshot| {
            if let Some(last) = snapshot.logs.last() {
                saw_logs.push(last.clone());
            }
        });

        assert!(ts_stale_deleted.load(Ordering::SeqCst));
        assert!(saw_logs.iter().any(|l| l.contains("[PROVISION]")));
        assert!(saw_logs.iter().any(|l| l.contains("[SSH] Waiting for SSH readiness on 100.64.8.9")));
        assert!(saw_logs.iter().any(|l| l.contains("[STEP 1/6] Running")));
        assert!(saw_logs.iter().any(|l| l.contains("[STEP 6/6] Running")));
        assert!(app.progress_steps.iter().all(|(_, s)| *s == Some(true)));
        assert_eq!(
            settings
                .lookup_instance_password(
                    Some("vultr-new-9"),
                    Some("cb-node"),
                    Some("203.0.113.99")
                )?
                .as_deref(),
            Some("MyPass1234")
        );

        stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(vultr_addr);
        let _ = std::net::TcpStream::connect(ts_addr);
        vultr_handle.join().unwrap();
        ts_handle.join().unwrap();
        Ok(())
    }

    struct TestEnvGuard {
        saved: Vec<(String, Option<String>)>,
    }

    impl TestEnvGuard {
        fn new(keys: &[&str]) -> Self {
            Self {
                saved: keys
                    .iter()
                    .map(|k| ((*k).to_string(), std::env::var(k).ok()))
                    .collect(),
            }
        }
    }

    impl Drop for TestEnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }

    struct MockHttpServer {
        addr: std::net::SocketAddr,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl MockHttpServer {
        fn spawn<F>(mut handler: F) -> Result<Self>
        where
            F: FnMut(&str, &str, &str) -> (&'static str, String) + Send + 'static,
        {
            use std::io::{BufRead, BufReader, Read, Write};
            use std::net::TcpListener;
            use std::sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            };

            let listener = TcpListener::bind("127.0.0.1:0")?;
            let addr = listener.local_addr()?;
            let stop = Arc::new(AtomicBool::new(false));
            let stop_bg = Arc::clone(&stop);
            let handle = std::thread::spawn(move || {
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
                    let mut content_len: usize = 0;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                            break;
                        }
                        if let Some((k, v)) = line.split_once(':') {
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                content_len = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    let mut body_buf = vec![0u8; content_len];
                    if content_len > 0 {
                        let _ = reader.read_exact(&mut body_buf);
                    }
                    let req_body = String::from_utf8_lossy(&body_buf);
                    let mut parts = req_line.split_whitespace();
                    let method = parts.next().unwrap_or("");
                    let raw_path = parts.next().unwrap_or("");
                    let path = raw_path.split('?').next().unwrap_or(raw_path);
                    let (status, resp_body) = handler(method, path, &req_body);
                    let resp = format!(
                        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status,
                        resp_body.len(),
                        resp_body
                    );
                    let _ = stream.write_all(resp.as_bytes());
                    let _ = stream.flush();
                }
            });
            Ok(Self {
                addr,
                stop,
                handle: Some(handle),
            })
        }
    }

    impl Drop for MockHttpServer {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = std::net::TcpStream::connect(self.addr);
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    #[test]
    fn execute_build_with_ui_tailscale_wait_failure_preserves_instance_id_public_ip_and_password(
    ) -> Result<()> {
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        let _lock = crate::env_lock();
        let _guard = TestEnvGuard::new(&["VULTR_API_BASE_URL", "TAILSCALE_API_BASE"]);

        let ts_key_created = Arc::new(AtomicBool::new(false));
        let ts_key_bg = Arc::clone(&ts_key_created);

        let vultr_srv = MockHttpServer::spawn(|method, path, _body| match (method, path) {
            ("GET", "/v2/instances") => (
                "200 OK",
                r#"{"instances":[],"meta":{"links":{"next":""}}}"#.to_string(),
            ),
            ("POST", "/v2/instances") => (
                "202 Accepted",
                r#"{"instance":{"id":"vultr-ts-fail-1","label":"fail-node","status":"pending","power_status":"stopped","main_ip":"0.0.0.0"}}"#
                    .to_string(),
            ),
            ("GET", "/v2/instances/vultr-ts-fail-1") => (
                "200 OK",
                r#"{"instance":{"id":"vultr-ts-fail-1","label":"fail-node","status":"active","power_status":"running","main_ip":"198.51.100.77"}}"#
                    .to_string(),
            ),
            _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
        })?;

        let ts_srv = MockHttpServer::spawn(move |method, path, _body| match (method, path) {
            ("POST", "/tailnet/-/keys") => {
                ts_key_bg.store(true, Ordering::SeqCst);
                (
                    "200 OK",
                    r#"{"id":"key-fail","key":"tskey-auth-fail"}"#.to_string(),
                )
            }
            ("GET", "/tailnet/-/devices") => {
                if !ts_key_bg.load(Ordering::SeqCst) {
                    ("200 OK", r#"{"devices":[]}"#.to_string())
                } else {
                    (
                        "500 Internal Server Error",
                        r#"{"message":"tailscale wait failure"}"#.to_string(),
                    )
                }
            }
            _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
        })?;

        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");

        std::env::set_var(
            "VULTR_API_BASE_URL",
            format!("http://{}/v2", vultr_srv.addr),
        );
        std::env::set_var("TAILSCALE_API_BASE", format!("http://{}", ts_srv.addr));

        let settings = Settings::new(&settings_path);
        settings.set_vultr_api_key("vultr-test-key")?;
        settings.set_tailscale_api_key("ts-test-key")?;

        let state = SessionState::new(&state_path);
        state.save_session(&SessionData {
            vps_provider: Some("vultr".to_string()),
            vps_instance_id: Some("stale-prev-id".to_string()),
            public_ip: Some("203.0.113.1".to_string()),
            vps_ip: Some("100.64.99.99".to_string()),
            tailscale_ip: Some("100.64.99.99".to_string()),
            tailscale_hostname: Some("fail-node".to_string()),
            transport_mode: Some("tailscale".to_string()),
            username: Some("deploy".to_string()),
            sudo_password: Some("FailPass99".to_string()),
            ..Default::default()
        })?;

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.build_dry_run = false;
        app.execute_build_with_ui(|_| {});

        assert!(app.logs.iter().any(|l| l.contains("[ERROR] Provision failed:")));
        assert!(app.status_message.contains("Provision failed:"));

        let saved = state.load_session()?;
        assert_eq!(saved.vps_instance_id.as_deref(), Some("vultr-ts-fail-1"));
        assert_eq!(saved.public_ip.as_deref(), Some("198.51.100.77"));
        assert_eq!(saved.vps_ip, None);
        assert_eq!(saved.tailscale_ip, None);
        assert_eq!(saved.sudo_password.as_deref(), Some("FailPass99"));

        assert_eq!(app.session.vps_instance_id.as_deref(), Some("vultr-ts-fail-1"));
        assert_eq!(app.session.public_ip.as_deref(), Some("198.51.100.77"));
        assert_eq!(app.session.vps_ip, None);
        assert_eq!(app.session.tailscale_ip, None);

        assert_eq!(
            settings
                .lookup_instance_password(
                    Some("vultr-ts-fail-1"),
                    Some("fail-node"),
                    Some("198.51.100.77"),
                )?
                .as_deref(),
            Some("FailPass99")
        );

        let bottom_masked = render_to_string(&app);
        assert!(bottom_masked.contains("Public IP:     198.51.100.77 | Target: (not set)"));
        assert!(bottom_masked.contains("Tailscale IP:  (not set)"));
        assert!(bottom_masked.contains("Sudo Pass:"));
        assert!(!bottom_masked.contains("FailPass99"));

        app.show_password = true;
        let bottom_revealed = render_to_string(&app);
        assert!(bottom_revealed.contains("FailPass99"));

        let running_inst = ProviderInstance {
            provider: ProviderKind::Vultr,
            id: "vultr-ts-fail-1".to_string(),
            name: "fail-node".to_string(),
            status: "active".to_string(),
            public_ip: Some("198.51.100.77".to_string()),
            region: Some("ewr".to_string()),
            plan: Some("vc2-1c-1gb".to_string()),
            created_at: None,
        };
        assert_eq!(
            app.password_for_instance(&running_inst).as_deref(),
            Some("FailPass99")
        );
        app.running_instances = vec![running_inst];
        app.screen = Screen::RunningInstances;
        let running_screen = render_to_string(&app);
        assert!(running_screen.contains("vultr-ts-fail-1"));
        assert!(running_screen.contains("198.51.100.77"));
        assert!(running_screen.contains("FailPass99"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn execute_build_with_ui_destroys_stale_active_vm_absent_from_tailscale_and_creates_fresh_build(
    ) -> Result<()> {
        use std::fs::{self, File};
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        };

        let _lock = crate::env_lock();
        let _guard = TestEnvGuard::new(&[
            "VULTR_API_BASE_URL",
            "TAILSCALE_API_BASE",
            "BAB_SSH_BIN",
            "BAB_SSH_POLL_MS",
        ]);

        let vultr_events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let vultr_events_bg = Arc::clone(&vultr_events);
        let deleted_stale = Arc::new(AtomicBool::new(false));
        let deleted_stale_bg = Arc::clone(&deleted_stale);
        let created_fresh = Arc::new(AtomicBool::new(false));
        let created_fresh_bg = Arc::clone(&created_fresh);
        let ts_key_created = Arc::new(AtomicBool::new(false));
        let ts_key_bg = Arc::clone(&ts_key_created);

        let vultr_srv = MockHttpServer::spawn(move |method, path, body| {
            vultr_events_bg
                .lock()
                .unwrap()
                .push(format!("{} {}", method, path));
            match (method, path) {
                ("GET", "/v2/instances") => (
                    "200 OK",
                    r#"{"instances":[{"id":"vultr-stale-1","label":"stale-node","status":"active","power_status":"running","main_ip":"203.0.113.10","region":"ewr","plan":"vc2-1c-1gb"}],"meta":{"links":{"next":""}}}"#
                        .to_string(),
                ),
                ("DELETE", "/v2/instances/vultr-stale-1") => {
                    deleted_stale_bg.store(true, Ordering::SeqCst);
                    ("204 No Content", String::new())
                }
                ("POST", "/v2/instances") => {
                    assert!(
                        body.contains("user_data"),
                        "expected cloud-init user_data in POST /v2/instances body"
                    );
                    created_fresh_bg.store(true, Ordering::SeqCst);
                    (
                        "202 Accepted",
                        r#"{"instance":{"id":"vultr-fresh-2","label":"stale-node","status":"pending","power_status":"stopped","main_ip":"0.0.0.0"}}"#
                            .to_string(),
                    )
                }
                ("GET", "/v2/instances/vultr-fresh-2") => (
                    "200 OK",
                    r#"{"instance":{"id":"vultr-fresh-2","label":"stale-node","status":"active","power_status":"running","main_ip":"203.0.113.88"}}"#
                        .to_string(),
                ),
                _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
            }
        })?;

        let ts_srv = MockHttpServer::spawn(move |method, path, _body| match (method, path) {
            ("GET", "/tailnet/-/devices") => {
                if !ts_key_bg.load(Ordering::SeqCst) {
                    ("200 OK", r#"{"devices":[]}"#.to_string())
                } else {
                    (
                        "200 OK",
                        r#"{"devices":[{"id":"ts-fresh-2","hostname":"stale-node","name":"stale-node.tailnet.ts.net","addresses":["100.64.22.2"],"online":true}]}"#
                            .to_string(),
                    )
                }
            }
            ("POST", "/tailnet/-/keys") => {
                ts_key_bg.store(true, Ordering::SeqCst);
                (
                    "200 OK",
                    r#"{"id":"key-fresh","key":"tskey-auth-fresh"}"#.to_string(),
                )
            }
            _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
        })?;

        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");
        let mock_ssh = dir.path().join("mock-ssh.sh");
        {
            let mut f = File::create(&mock_ssh)?;
            writeln!(f, "#!/bin/sh\ncat >/dev/null\necho ok\nexit 0")?;
        }
        fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755))?;

        std::env::set_var(
            "VULTR_API_BASE_URL",
            format!("http://{}/v2", vultr_srv.addr),
        );
        std::env::set_var("TAILSCALE_API_BASE", format!("http://{}", ts_srv.addr));
        std::env::set_var("BAB_SSH_BIN", &mock_ssh);
        std::env::set_var("BAB_SSH_POLL_MS", "5");

        let settings = Settings::new(&settings_path);
        settings.set_vultr_api_key("vultr-test-key")?;
        settings.set_tailscale_api_key("ts-test-key")?;

        let state = SessionState::new(&state_path);
        state.save_session(&SessionData {
            vps_provider: Some("vultr".to_string()),
            vps_instance_id: Some("vultr-stale-1".to_string()),
            public_ip: Some("203.0.113.10".to_string()),
            vps_ip: Some("100.64.1.1".to_string()),
            tailscale_ip: Some("100.64.1.1".to_string()),
            tailscale_hostname: Some("stale-node".to_string()),
            transport_mode: Some("tailscale".to_string()),
            username: Some("deploy".to_string()),
            sudo_password: Some("FreshPass1".to_string()),
            ..Default::default()
        })?;

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.build_dry_run = false;
        app.execute_build_with_ui(|_| {});

        assert!(deleted_stale.load(Ordering::SeqCst));
        assert!(created_fresh.load(Ordering::SeqCst));
        let events = vultr_events.lock().unwrap().clone();
        let delete_pos = events
            .iter()
            .position(|e| e == "DELETE /v2/instances/vultr-stale-1")
            .expect("DELETE /v2/instances/vultr-stale-1 recorded");
        let create_pos = events
            .iter()
            .position(|e| e == "POST /v2/instances")
            .expect("POST /v2/instances recorded");
        assert!(delete_pos < create_pos);

        assert!(app.logs.iter().any(|l| {
            l.contains("[PROVISION] Existing Vultr instance 'stale-node' (id=vultr-stale-1) is not on Tailscale; destroying stale instance before creating a fresh one...")
        }));
        assert!(app
            .logs
            .iter()
            .any(|l| l.contains("[PROVISION] Vultr ready: instance=vultr-fresh-2, ip=100.64.22.2")));
        assert!(app.progress_steps.iter().all(|(_, s)| *s == Some(true)));

        assert_eq!(app.session.vps_instance_id.as_deref(), Some("vultr-fresh-2"));
        assert_eq!(app.session.public_ip.as_deref(), Some("203.0.113.88"));
        assert_eq!(app.session.tailscale_ip.as_deref(), Some("100.64.22.2"));
        assert_eq!(app.session.vps_ip.as_deref(), Some("100.64.22.2"));

        let saved = state.load_session()?;
        assert_eq!(saved.vps_instance_id.as_deref(), Some("vultr-fresh-2"));
        assert_eq!(saved.public_ip.as_deref(), Some("203.0.113.88"));
        assert_eq!(saved.tailscale_ip.as_deref(), Some("100.64.22.2"));
        assert_eq!(saved.vps_ip.as_deref(), Some("100.64.22.2"));
        assert_eq!(
            settings
                .lookup_instance_password(
                    Some("vultr-fresh-2"),
                    Some("stale-node"),
                    Some("203.0.113.88"),
                )?
                .as_deref(),
            Some("FreshPass1")
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn execute_build_with_ui_reuses_existing_active_vm_present_on_tailscale() -> Result<()> {
        use std::fs::{self, File};
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };

        let _lock = crate::env_lock();
        let _guard = TestEnvGuard::new(&[
            "VULTR_API_BASE_URL",
            "TAILSCALE_API_BASE",
            "BAB_SSH_BIN",
            "BAB_SSH_POLL_MS",
        ]);

        let destroyed_or_created = Arc::new(AtomicBool::new(false));
        let destroyed_or_created_bg = Arc::clone(&destroyed_or_created);

        let vultr_srv = MockHttpServer::spawn(move |method, path, _body| match (method, path) {
            ("GET", "/v2/instances") => (
                "200 OK",
                r#"{"instances":[{"id":"vultr-live-1","label":"live-node","status":"active","power_status":"running","main_ip":"203.0.113.55","region":"ewr","plan":"vc2-1c-1gb"}],"meta":{"links":{"next":""}}}"#
                    .to_string(),
            ),
            ("DELETE", _) | ("POST", "/v2/instances") => {
                destroyed_or_created_bg.store(true, Ordering::SeqCst);
                ("500 Internal Server Error", r#"{"error":"unexpected"}"#.to_string())
            }
            _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
        })?;

        let ts_srv = MockHttpServer::spawn(|method, path, _body| match (method, path) {
            ("GET", "/tailnet/-/devices") => (
                "200 OK",
                r#"{"devices":[{"id":"ts-live-1","hostname":"live-node","name":"live-node.tailnet.ts.net","addresses":["100.64.33.3"],"online":true}]}"#
                    .to_string(),
            ),
            _ => ("404 Not Found", r#"{"error":"not found"}"#.to_string()),
        })?;

        let dir = tempdir()?;
        let settings_path = dir.path().join("credentials.enc");
        let state_path = dir.path().join("state.conf");
        let mock_ssh = dir.path().join("mock-ssh.sh");
        {
            let mut f = File::create(&mock_ssh)?;
            writeln!(f, "#!/bin/sh\ncat >/dev/null\necho ok\nexit 0")?;
        }
        fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755))?;

        std::env::set_var(
            "VULTR_API_BASE_URL",
            format!("http://{}/v2", vultr_srv.addr),
        );
        std::env::set_var("TAILSCALE_API_BASE", format!("http://{}", ts_srv.addr));
        std::env::set_var("BAB_SSH_BIN", &mock_ssh);
        std::env::set_var("BAB_SSH_POLL_MS", "5");

        let settings = Settings::new(&settings_path);
        settings.set_vultr_api_key("vultr-test-key")?;
        settings.set_tailscale_api_key("ts-test-key")?;

        let state = SessionState::new(&state_path);
        state.save_session(&SessionData {
            vps_provider: Some("vultr".to_string()),
            tailscale_hostname: Some("live-node".to_string()),
            transport_mode: Some("tailscale".to_string()),
            username: Some("deploy".to_string()),
            sudo_password: Some("ReusePass1".to_string()),
            ..Default::default()
        })?;

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.build_dry_run = false;
        app.execute_build_with_ui(|_| {});

        assert!(!destroyed_or_created.load(Ordering::SeqCst));
        assert!(app.logs.iter().any(|l| {
            l.contains("[PROVISION] Reusing existing Vultr instance 'live-node' (id=vultr-live-1, public_ip=203.0.113.55)")
        }));
        assert!(app.progress_steps.iter().all(|(_, s)| *s == Some(true)));
        assert_eq!(app.session.vps_instance_id.as_deref(), Some("vultr-live-1"));
        assert_eq!(app.session.public_ip.as_deref(), Some("203.0.113.55"));
        assert_eq!(app.session.tailscale_ip.as_deref(), Some("100.64.33.3"));
        assert_eq!(app.session.vps_ip.as_deref(), Some("100.64.33.3"));

        let saved = state.load_session()?;
        assert_eq!(saved.vps_instance_id.as_deref(), Some("vultr-live-1"));
        assert_eq!(saved.tailscale_ip.as_deref(), Some("100.64.33.3"));
        assert_eq!(
            settings
                .lookup_instance_password(
                    Some("vultr-live-1"),
                    Some("live-node"),
                    Some("203.0.113.55"),
                )?
                .as_deref(),
            Some("ReusePass1")
        );
        Ok(())
    }
}
