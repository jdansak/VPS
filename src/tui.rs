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
use ratatui::widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{Frame, Terminal};
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use crate::config::{default_config_dir, SessionData, SessionState, Settings};
use crate::dns::{build_cloudflare_dns_stub_plan, CloudflareDnsConfig};
use crate::providers::{
    default_images_for, default_plans_for, default_regions_for, ProviderKind,
};
use crate::roles::ServerRole;
use crate::setup::{normalize_github_repo, SetupStepKind, StepReport};
use crate::transport::default_ssh_key_path;

const HEADER_TITLE: &str = "Build A Box (bab) - Multi-Provider VPS Provisioner";

const ALL_PROVIDERS: [ProviderKind; 5] = [
    ProviderKind::Vultr,
    ProviderKind::UpCloud,
    ProviderKind::Linode,
    ProviderKind::ExistingTailscale,
    ProviderKind::ManualCloudInit,
];

const HOME_MENU_ITEMS: [&str; 7] = [
    "Select Provider, Location & Size",
    "Select Server Role",
    "Access, User & Transport",
    "Cloudflare DNS (Stub)",
    "GitHub Repo Deployment",
    "API Key Settings (Encrypted)",
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

const ACCESS_FIELD_LABELS: [&str; 4] = [
    "Transport Mode",
    "Sudo Username",
    "SSH Key Path",
    "Hostname",
];

const CF_DNS_FIELD_LABELS: [&str; 4] = [
    "Zone",
    "Record Name",
    "Target IP",
    "Proxied",
];

const GITHUB_FIELD_LABELS: [&str; 4] = [
    "Repository",
    "Branch",
    "Deploy Path",
    "Deploy Command",
];

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
}

/// Editable form state for access transport, sudo admin user, SSH key path, and hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessForm {
    pub tailscale_mode: bool,
    pub username: String,
    pub ssh_key_path: String,
    pub hostname: String,
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

        Self {
            tailscale_mode,
            username,
            ssh_key_path,
            hostname,
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

/// Editable form state for Cloudflare DNS stub configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareDnsForm {
    pub zone: String,
    pub record_name: String,
    pub target_mode: String,
    pub proxied: bool,
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

        Self {
            zone,
            record_name,
            target_mode,
            proxied,
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

        Self {
            repo,
            branch,
            deploy_path,
            deploy_cmd,
            active_field: 0,
            editing: false,
        }
    }

    fn active_text_mut(&mut self) -> &mut String {
        match self.active_field {
            0 => &mut self.repo,
            1 => &mut self.branch,
            2 => &mut self.deploy_path,
            _ => &mut self.deploy_cmd,
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

    /// Saves non-empty API keys back to `Settings`.
    pub fn save_to_settings(&self, settings: &Settings) -> Result<()> {
        if !self.tailscale.is_empty() {
            settings.set_tailscale_api_key(&self.tailscale)?;
        }
        if !self.vultr.is_empty() {
            settings.set_vultr_api_key(&self.vultr)?;
        }
        if !self.upcloud.is_empty() {
            settings.set_upcloud_api_token(&self.upcloud)?;
        }
        if !self.linode.is_empty() {
            settings.set_linode_api_token(&self.linode)?;
        }
        if !self.cloudflare.is_empty() {
            settings.set_cloudflare_api_token(&self.cloudflare)?;
        }
        if !self.github.is_empty() {
            settings.set_github_token(&self.github)?;
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
        let state = SessionState::new(&resolved_state_path);

        let session = state.load_session()?;
        let api_keys = ApiKeyForm::from_settings(&settings)?;
        let mut app = Self::new(session, api_keys);
        app.settings_path = Some(resolved_settings_path);
        app.state_path = Some(resolved_state_path);
        Ok(app)
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
        self.logs
            .push(format!("[{}] {}", tag, report.step.title()));
        for line in report.output.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                self.logs.push(format!("  {}", trimmed));
            }
        }
        self.status_message = format!("{}: {}", report.step.title(), tag);
    }

    /// Processes a single terminal key event.
    pub fn handle_key(&mut self, key: KeyEvent) {
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

        if matches!(key.code, KeyCode::Char('q')) {
            self.should_quit = true;
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
            KeyCode::Enter => match self.home_index {
                0 => self.screen = Screen::SelectProvider,
                1 => self.screen = Screen::SelectRole,
                2 => self.screen = Screen::AccessConfig,
                3 => self.screen = Screen::CloudflareDns,
                4 => self.screen = Screen::GithubDeploy,
                5 => self.screen = Screen::ApiKeys,
                6 => self.should_quit = true,
                _ => {}
            },
            KeyCode::Char('1') => {
                self.home_index = 0;
                self.screen = Screen::SelectProvider;
            }
            KeyCode::Char('2') => {
                self.home_index = 1;
                self.screen = Screen::SelectRole;
            }
            KeyCode::Char('3') => {
                self.home_index = 2;
                self.screen = Screen::AccessConfig;
            }
            KeyCode::Char('4') => {
                self.home_index = 3;
                self.screen = Screen::CloudflareDns;
            }
            KeyCode::Char('5') => {
                self.home_index = 4;
                self.screen = Screen::GithubDeploy;
            }
            KeyCode::Char('6') => {
                self.home_index = 5;
                self.screen = Screen::ApiKeys;
            }
            KeyCode::Char('7') => {
                self.home_index = 6;
                self.should_quit = true;
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
            KeyCode::Char(' ') | KeyCode::Left | KeyCode::Right if self.access.active_field == 0 => {
                self.access.toggle_transport();
                self.status_message = format!(
                    "Transport mode set to {} (press 's' to save)",
                    self.access.transport_mode_str()
                );
            }
            KeyCode::Enter => {
                if self.access.active_field == 0 {
                    self.access.toggle_transport();
                    self.status_message = format!(
                        "Transport mode set to {} (press 's' to save)",
                        self.access.transport_mode_str()
                    );
                } else {
                    self.access.editing = true;
                    let label = ACCESS_FIELD_LABELS[self.access.active_field];
                    self.status_message =
                        format!("Editing {} (Enter/Esc to finish)", label);
                }
            }
            KeyCode::Char('e') if self.access.active_field > 0 => {
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
            KeyCode::Enter | KeyCode::Char('e') => {
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
                let label = GITHUB_FIELD_LABELS[self.github_deploy.active_field];
                self.status_message = format!("Updated {} (press 's' to save)", label);
            }
            KeyCode::Backspace => {
                self.github_deploy.active_text_mut().pop();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.github_deploy.active_text_mut().push(c);
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
                    format!("Editing {} (Enter to finish, Esc to stop)", label);
            }
            KeyCode::Char('s') => {
                self.save_api_keys();
            }
            KeyCode::Esc | KeyCode::Char('b') => {
                self.screen = Screen::Home;
            }
            _ => {}
        }
    }

    fn handle_api_key_edit(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Enter | KeyCode::Esc => {
                self.api_keys.editing = false;
                let label = API_KEY_LABELS[self.api_keys.active_field];
                self.status_message = format!("Updated {} (press 's' to save)", label);
            }
            KeyCode::Backspace => {
                self.api_keys.active_value_mut().pop();
            }
            KeyCode::Char(c)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.api_keys.active_value_mut().push(c);
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

        self.session.transport_mode = Some(mode.clone());
        self.session.username = Some(username.clone());
        self.session.ssh_key = Some(ssh_key.clone());
        self.session.tailscale_hostname = Some(hostname.clone());

        if let Some(ref path) = self.state_path {
            let state = SessionState::new(path);
            let res = state
                .set_transport_mode(&mode)
                .and_then(|()| state.set_username(&username))
                .and_then(|()| state.set_ssh_key(&ssh_key))
                .and_then(|()| state.set_tailscale_hostname(&hostname));
            if let Err(err) = res {
                self.status_message = format!("Failed to save access settings: {}", err);
                return;
            }
        }

        self.status_message = format!(
            "Saved access settings (mode: {}, user: {}, host: {})",
            mode, username, hostname
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

        self.session.cf_zone = if zone.is_empty() {
            None
        } else {
            Some(zone.clone())
        };
        self.session.cf_record = Some(record.clone());
        self.session.cf_target = Some(target.clone());
        self.session.cf_proxied = Some(proxied.clone());

        if let Some(ref path) = self.state_path {
            let state = SessionState::new(path);
            if let Err(err) = state.save_session(&self.session) {
                self.status_message = format!("Failed to save Cloudflare DNS config: {}", err);
                return;
            }
        }

        self.status_message = format!(
            "Saved Cloudflare DNS (zone: {}, record: {}, target: {}, proxied: {})",
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

        if let Some(ref path) = self.state_path {
            let state = SessionState::new(path);
            if let Err(err) = state.save_session(&self.session) {
                self.status_message = format!("Failed to save GitHub deploy config: {}", err);
                return;
            }
        }

        self.status_message = format!(
            "Saved GitHub deploy (repo: {}, branch: {})",
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
            Screen::CloudflareDns => "Cloudflare DNS (Stub)",
            Screen::GithubDeploy => "GitHub Repo Deployment",
            Screen::ApiKeys => "API Keys (Encrypted)",
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
            Screen::Home => "Up/Down or j/k: Navigate | 1-7/Enter: Open | q: Quit",
            Screen::SelectProvider => {
                "Up/Down or j/k: Provider | r: Region | p: Plan | i: Image | 1-5/Enter/s: Save | Esc/b: Back | q: Quit"
            }
            Screen::SelectRole => {
                "Up/Down or j/k: Move | 1-4: Quick Select | Enter: Confirm | Esc/b: Back | q: Quit"
            }
            Screen::AccessConfig if self.access.editing => {
                "Type characters | Backspace: Delete | Enter/Esc: Finish Editing"
            }
            Screen::AccessConfig => {
                "Up/Down or j/k: Field | Space/Enter/Left/Right: Toggle/Edit | s: Save | Esc/b: Back | q: Quit"
            }
            Screen::CloudflareDns if self.cf_dns.editing => {
                "Type characters | Backspace: Delete | Enter/Esc: Finish Editing"
            }
            Screen::CloudflareDns => {
                "Up/Down or j/k: Field | Space/Enter/Left/Right: Toggle/Edit | s: Save | Esc/b: Back | q: Quit"
            }
            Screen::GithubDeploy if self.github_deploy.editing => {
                "Type characters | Backspace: Delete | Enter/Esc: Finish Editing"
            }
            Screen::GithubDeploy => {
                "Up/Down or j/k: Field | Enter/e: Edit | s: Save | Esc/b: Back | q: Quit"
            }
            Screen::ApiKeys if self.api_keys.editing => {
                "Type characters | Backspace: Delete | Enter/Esc: Finish Editing"
            }
            Screen::ApiKeys => {
                "Up/Down or j/k: Field | Enter/e: Edit | s: Save | Esc/b: Back | q: Quit"
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
            .map(|(i, label)| ListItem::new(format!("[{}] {}", i + 1, label)))
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
                "Transport Mode: {} | User: {} | Host: {}",
                transport_mode, username, hostname
            )),
            Line::from(format!("SSH Key (SSH_KEY): {}", ssh_key)),
            Line::from(format!(
                "Target IP: {} | Public IP: {} | Tailscale IP: {}",
                vps_ip, public_ip, tailscale_ip
            )),
            Line::from(format!(
                "Cloudflare DNS: {} / {} (target={}, proxied={})",
                cf_zone, cf_record, self.cf_dns.target_mode, self.cf_dns.proxied
            )),
            Line::from(format!(
                "GitHub Repo: {} (branch: {})",
                github_repo, github_branch
            )),
            Line::from(format!("API Keys: {}", key_ready)),
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
            Line::from(format!("TRANSPORT_MODE: {}", self.access.transport_mode_str())),
            Line::from(format!("USERNAME:       {}", self.access.username)),
            Line::from(format!("SSH_KEY:        {}", effective_ssh_key)),
            Line::from(format!("TAILSCALE_HOSTNAME: {}", self.access.hostname)),
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
                Constraint::Min(6),
                Constraint::Length(7),
            ])
            .split(area);

        let help = Paragraph::new(
            "Configure Cloudflare DNS A-record stub settings (CF_ZONE, CF_RECORD, CF_TARGET, CF_PROXIED).",
        )
        .block(
            Block::default()
                .title("Cloudflare DNS (Stub) Help")
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
            Ok(plan) => Line::from(Span::styled(plan, Style::default().fg(Color::Green))),
            Err(err) => Line::from(Span::styled(
                format!("Preview pending: {}", err),
                Style::default().fg(Color::Yellow),
            )),
        };

        let details = Paragraph::new(vec![
            Line::from(format!(
                "CF_ZONE={} | CF_RECORD={} | CF_TARGET={} | CF_PROXIED={}",
                if self.cf_dns.zone.trim().is_empty() {
                    "(not set)"
                } else {
                    self.cf_dns.zone.trim()
                },
                cfg.record_name,
                self.cf_dns.target_mode,
                self.cf_dns.proxied
            )),
            Line::from(format!(
                "CLOUDFLARE_API_TOKEN: {} | Resolved Target IP: {}",
                yes_no(has_token),
                resolved_ip.unwrap_or("(none)")
            )),
            preview_line,
        ])
        .block(
            Block::default()
                .title("Live Stub Plan Preview (Saved on 's')")
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
            Line::from(format!(
                "GITHUB_REPO={} | GITHUB_BRANCH={}",
                if self.github_deploy.repo.trim().is_empty() {
                    "(not set)"
                } else {
                    self.github_deploy.repo.trim()
                },
                effective_branch
            )),
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
                    .title("API Key Settings (Masked, ChaCha20-Poly1305 Encrypted)")
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

    fn render_bottom_pane(&self, frame: &mut Frame, area: Rect) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
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
        let public_ip = self
            .session
            .public_ip
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("(not set)");
        let tailscale_ip = self
            .session
            .tailscale_ip
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("(not set)");
        let target_ip = self
            .session
            .vps_ip
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("(not set)");
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
        let role = self
            .session
            .server_role
            .as_deref()
            .unwrap_or(self.selected_role.label());
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
            Line::from(format!("Public IP:     {}", public_ip)),
            Line::from(format!("Tailscale IP:  {}", tailscale_ip)),
            Line::from(format!("Target IP:     {}", target_ip)),
            Line::from(format!("Region/Plan:   {} / {} ({})", region, plan, provider)),
            Line::from(format!("Role/Mode/Usr: {} / {} / {}", role, transport, username)),
            Line::from(format!("DNS / Repo:    {} / {}", dns_zone, repo)),
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
                app.handle_key(key);
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

    fn render_to_string(app: &TuiApp) -> String {
        let backend = TestBackend::new(100, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| app.render_frame(frame)).unwrap();
        let buf = terminal.backend().buffer();
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
        assert!(text.contains("[4] Cloudflare DNS (Stub)"));
        assert!(text.contains("[5] GitHub Repo Deployment"));
        assert!(text.contains("[6] API Key Settings (Encrypted)"));
        assert!(text.contains("[7] Quit"));
        assert!(text.contains("Setup Progress & Logs"));
        assert!(text.contains("Box & Final Connection Info"));
    }

    #[test]
    fn renders_select_provider_with_all_five_variants_and_catalog() {
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

        // 'q' when not editing sets should_quit
        app.handle_key(key(KeyCode::Char('q')));
        assert!(app.should_quit);
        Ok(())
    }

    #[test]
    fn persistent_bottom_pane_shows_progress_logs_and_connection_info_across_screens() {
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

        // Shortcuts '4', '5', '6' open CloudflareDns, GithubDeploy, ApiKeys
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

        // Navigate to SelectProvider and confirm with Enter
        app.home_index = 0;
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::SelectProvider);
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.selected_provider, ProviderKind::UpCloud);
        assert_eq!(app.screen, Screen::Home);

        // Shortcut '7' quits
        app.handle_key(key(KeyCode::Char('7')));
        assert!(app.should_quit);
    }
}
