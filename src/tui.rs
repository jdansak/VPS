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

use crate::config::{SessionData, SessionState, Settings};
use crate::providers::ProviderKind;
use crate::roles::ServerRole;
use crate::setup::{SetupStepKind, StepReport};
use crate::transport::default_ssh_key_path;

const HEADER_TITLE: &str = "Build A Box (bab) - Multi-Provider VPS Provisioner";

const ALL_PROVIDERS: [ProviderKind; 5] = [
    ProviderKind::Vultr,
    ProviderKind::UpCloud,
    ProviderKind::Linode,
    ProviderKind::ExistingTailscale,
    ProviderKind::ManualCloudInit,
];

const HOME_MENU_ITEMS: [&str; 6] = [
    "Select VPS Provider",
    "Select Server Role",
    "Access, User & Transport",
    "API Key Settings",
    "Setup Progress",
    "Quit",
];

const API_KEY_LABELS: [&str; 4] = [
    "TAILSCALE_API_KEY",
    "VULTR_API_KEY",
    "UPCLOUD_API_TOKEN",
    "LINODE_API_TOKEN",
];

const ACCESS_FIELD_LABELS: [&str; 4] = [
    "Transport Mode",
    "Sudo Username",
    "SSH Key Path",
    "Hostname",
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
    ApiKeys,
    SetupProgress,
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

/// Editable and masked form state for provider and Tailscale API keys.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ApiKeyForm {
    pub tailscale: String,
    pub vultr: String,
    pub upcloud: String,
    pub linode: String,
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
        Ok(())
    }

    fn value_for(&self, idx: usize) -> &str {
        match idx {
            0 => &self.tailscale,
            1 => &self.vultr,
            2 => &self.upcloud,
            _ => &self.linode,
        }
    }

    fn active_value_mut(&mut self) -> &mut String {
        match self.active_field {
            0 => &mut self.tailscale,
            1 => &mut self.vultr,
            2 => &mut self.upcloud,
            _ => &mut self.linode,
        }
    }

    fn configured_count(&self) -> usize {
        [
            &self.tailscale,
            &self.vultr,
            &self.upcloud,
            &self.linode,
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
    pub role_index: usize,
    pub selected_provider: ProviderKind,
    pub selected_role: ServerRole,
    pub session: SessionData,
    pub access: AccessForm,
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
            role_index,
            selected_provider,
            selected_role,
            session,
            access,
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

        if matches!(key.code, KeyCode::Char('q')) {
            self.should_quit = true;
            return;
        }

        match self.screen {
            Screen::Home => self.handle_home_key(key),
            Screen::SelectProvider => self.handle_provider_key(key),
            Screen::SelectRole => self.handle_role_key(key),
            Screen::AccessConfig => self.handle_access_nav_key(key),
            Screen::ApiKeys => self.handle_api_keys_nav_key(key),
            Screen::SetupProgress => self.handle_progress_key(key),
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
                3 => self.screen = Screen::ApiKeys,
                4 => self.screen = Screen::SetupProgress,
                5 => self.should_quit = true,
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
                self.screen = Screen::ApiKeys;
            }
            KeyCode::Char('5') => {
                self.home_index = 4;
                self.screen = Screen::SetupProgress;
            }
            KeyCode::Char('6') => {
                self.home_index = 5;
                self.should_quit = true;
            }
            _ => {}
        }
    }

    fn handle_provider_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.provider_index = prev_index(self.provider_index, ALL_PROVIDERS.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.provider_index = next_index(self.provider_index, ALL_PROVIDERS.len());
            }
            KeyCode::Char(c @ '1'..='5') => {
                let idx = (c as usize) - ('1' as usize);
                self.provider_index = idx;
                self.select_provider_at(idx);
            }
            KeyCode::Enter => {
                self.select_provider_at(self.provider_index);
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

    fn handle_progress_key(&mut self, key: KeyEvent) {
        if matches!(key.code, KeyCode::Esc | KeyCode::Char('b') | KeyCode::Enter) {
            self.screen = Screen::Home;
        }
    }

    fn select_provider_at(&mut self, idx: usize) {
        let provider = ALL_PROVIDERS[idx];
        self.selected_provider = provider;
        self.session.vps_provider = Some(provider.to_string());
        if let Some(ref path) = self.state_path {
            let state = SessionState::new(path);
            if let Err(err) = state.set_vps_provider(&provider.to_string()) {
                self.status_message = format!("Failed to save provider: {}", err);
                return;
            }
        }
        self.status_message = format!("Selected provider: {}", provider_display_label(provider));
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

    fn save_api_keys(&mut self) {
        let settings_res = match self.settings_path {
            Some(ref p) => Ok(Settings::new(p)),
            None => Settings::load_default(),
        };
        match settings_res.and_then(|s| self.api_keys.save_to_settings(&s)) {
            Ok(()) => {
                self.status_message = "API keys saved to settings".to_string();
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
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(frame.area());

        self.render_header(frame, chunks[0]);
        match self.screen {
            Screen::Home => self.render_home(frame, chunks[1]),
            Screen::SelectProvider => self.render_select_provider(frame, chunks[1]),
            Screen::SelectRole => self.render_select_role(frame, chunks[1]),
            Screen::AccessConfig => self.render_access_config(frame, chunks[1]),
            Screen::ApiKeys => self.render_api_keys(frame, chunks[1]),
            Screen::SetupProgress => self.render_setup_progress(frame, chunks[1]),
        }
        self.render_footer(frame, chunks[2]);
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let screen_tag = match self.screen {
            Screen::Home => "Home",
            Screen::SelectProvider => "Select Provider",
            Screen::SelectRole => "Select Server Role",
            Screen::AccessConfig => "Access, User & Transport",
            Screen::ApiKeys => "API Keys",
            Screen::SetupProgress => "Setup Progress",
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
            Screen::Home => "Up/Down or j/k: Navigate | 1-6/Enter: Open | q: Quit",
            Screen::SelectProvider => {
                "Up/Down or j/k: Move | 1-5/Enter: Select | Esc/b: Back | q: Quit"
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
            Screen::ApiKeys if self.api_keys.editing => {
                "Type characters | Backspace: Delete | Enter/Esc: Finish Editing"
            }
            Screen::ApiKeys => {
                "Up/Down or j/k: Field | Enter/e: Edit | s: Save | Esc/b: Back | q: Quit"
            }
            Screen::SetupProgress => "Esc/b/Enter: Back to Home | q: Quit",
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
            .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
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
        let vps_provider = self
            .session
            .vps_provider
            .as_deref()
            .unwrap_or(provider_display_label(self.selected_provider));
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
        let key_ready = format!(
            "{}/4 configured (TS: {}, Vultr: {}, UpCloud: {}, Linode: {})",
            self.api_keys.configured_count(),
            yes_no(!self.api_keys.tailscale.is_empty()),
            yes_no(!self.api_keys.vultr.is_empty()),
            yes_no(!self.api_keys.upcloud.is_empty()),
            yes_no(!self.api_keys.linode.is_empty()),
        );

        let summary_lines = vec![
            Line::from(format!(
                "Provider: {} ({})",
                provider_display_label(self.selected_provider),
                vps_provider
            )),
            Line::from(format!(
                "Role: {} ({})",
                self.selected_role.label(),
                server_role
            )),
            Line::from(format!("Transport Mode: {}", transport_mode)),
            Line::from(format!("Sudo User (USERNAME): {}", username)),
            Line::from(format!("SSH Key (SSH_KEY): {}", ssh_key)),
            Line::from(format!("Hostname (TAILSCALE_HOSTNAME): {}", hostname)),
            Line::from(format!("Target IP (VPS_IP): {}", vps_ip)),
            Line::from(""),
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
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

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
        frame.render_stateful_widget(list, cols[0], &mut state);

        let focused = ALL_PROVIDERS[self.provider_index];
        let api_env = focused.api_key_env_name().unwrap_or("None required");
        let details = Paragraph::new(vec![
            Line::from(format!("Provider: {}", provider_display_label(focused))),
            Line::from(format!("Key ID: {}", focused)),
            Line::from(format!("API Token Var: {}", api_env)),
            Line::from(format!(
                "Currently Selected: {}",
                provider_display_label(self.selected_provider)
            )),
        ])
        .block(
            Block::default()
                .title("Provider Details")
                .borders(Borders::ALL),
        )
        .wrap(Wrap { trim: true });
        frame.render_widget(details, cols[1]);
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

    fn render_api_keys(&self, frame: &mut Frame, area: Rect) {
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
                    .title("API Key Settings (Masked)")
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
        frame.render_stateful_widget(list, area, &mut state);
    }

    fn render_setup_progress(&self, frame: &mut Frame, area: Rect) {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(8),
                Constraint::Min(4),
            ])
            .split(area);

        let total = self.progress_steps.len().max(1);
        let completed = self
            .progress_steps
            .iter()
            .filter(|(_, status)| status.is_some())
            .count();
        let ratio = (completed as f64 / total as f64).clamp(0.0, 1.0);
        let gauge = Gauge::default()
            .block(
                Block::default()
                    .title("Setup Progress")
                    .borders(Borders::ALL),
            )
            .gauge_style(Style::default().fg(Color::Cyan))
            .ratio(ratio)
            .label(format!("{}/{} steps", completed, total));
        frame.render_widget(gauge, rows[0]);

        let step_items: Vec<ListItem> = self
            .progress_steps
            .iter()
            .map(|(step, status)| {
                let marker = match status {
                    None => "[ ]",
                    Some(true) => "[x]",
                    Some(false) => "[!]",
                };
                ListItem::new(format!("{} {}", marker, step.title()))
            })
            .collect();
        let checklist = List::new(step_items).block(
            Block::default()
                .title("Setup Steps")
                .borders(Borders::ALL),
        );
        frame.render_widget(checklist, rows[1]);

        let max_logs = rows[2].height.saturating_sub(2) as usize;
        let skip = self.logs.len().saturating_sub(max_logs);
        let log_lines: Vec<Line> = self.logs[skip..]
            .iter()
            .map(|l| Line::from(l.as_str()))
            .collect();
        let logs = Paragraph::new(log_lines)
            .block(Block::default().title("Logs").borders(Borders::ALL))
            .wrap(Wrap { trim: false });
        frame.render_widget(logs, rows[2]);
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
            ssh_key: Some("tailscale".to_string()),
            username: Some("deploy".to_string()),
            transport_mode: Some("tailscale".to_string()),
            vps_provider: Some("vultr".to_string()),
            vps_instance_id: Some("inst-42".to_string()),
            tailscale_hostname: Some("edge-vps".to_string()),
            server_role: Some("caddy".to_string()),
        };
        let app = TuiApp::new(session, ApiKeyForm::default());
        let text = render_to_string(&app);

        assert!(text.contains("Build A Box (bab) - Multi-Provider VPS Provisioner"));
        assert!(text.contains("100.64.1.10"));
        assert!(text.contains("vultr"));
        assert!(text.contains("edge-vps"));
        assert!(text.contains("caddy"));
        assert!(text.contains("tailscale"));
        assert!(text.contains("deploy"));
        assert!(text.contains("[1] Select VPS Provider"));
        assert!(text.contains("[2] Select Server Role"));
        assert!(text.contains("[3] Access, User & Transport"));
        assert!(text.contains("[4] API Key Settings"));
        assert!(text.contains("[5] Setup Progress"));
        assert!(text.contains("[6] Quit"));
    }

    #[test]
    fn renders_select_provider_with_all_five_variants() {
        let mut app = TuiApp::new(SessionData::default(), ApiKeyForm::default());
        app.screen = Screen::SelectProvider;
        let text = render_to_string(&app);

        assert!(text.contains("Vultr"));
        assert!(text.contains("UpCloud"));
        assert!(text.contains("Linode"));
        assert!(text.contains("Existing Tailscale"));
        assert!(text.contains("Manual Cloud-Init"));
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
        let settings_path = dir.path().join(".bab-settings");
        let state_path = dir.path().join(".bab-local");

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
    fn api_keys_masking_input_and_save() -> Result<()> {
        assert_eq!(ApiKeyForm::mask_key(""), "(not set)");
        assert_eq!(ApiKeyForm::mask_key("short"), "*****");
        assert_eq!(
            ApiKeyForm::mask_key("tskey-auth-12345678"),
            "tske****5678"
        );

        let dir = tempdir()?;
        let settings_path = dir.path().join(".bab-settings");
        let state_path = dir.path().join(".bab-local");

        let mut app = TuiApp::from_paths(Some(&settings_path), Some(&state_path))?;
        app.screen = Screen::ApiKeys;

        // Enter edit mode on TAILSCALE_API_KEY
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

        // Finish editing and save with 's'
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.api_keys.editing);
        app.handle_key(key(KeyCode::Char('s')));

        let settings = Settings::new(&settings_path);
        assert_eq!(
            settings.tailscale_api_key()?,
            Some("tskey-secret-abcd".to_string())
        );

        // 'q' when not editing sets should_quit
        app.handle_key(key(KeyCode::Char('q')));
        assert!(app.should_quit);
        Ok(())
    }

    #[test]
    fn setup_progress_renders_gauge_steps_and_logs() {
        let mut app = TuiApp::new(SessionData::default(), ApiKeyForm::default());
        app.screen = Screen::SetupProgress;
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

        let text = render_to_string(&app);
        assert!(text.contains("2/6 steps"));
        assert!(text.contains("[x] System Update & Base Packages"));
        assert!(text.contains("[!] Create Non-Root User & Sudo"));
        assert!(text.contains("[ ] Harden SSH & Tailscale Access"));
        assert!(text.contains("apt updated successfully"));
        assert!(text.contains("useradd error"));
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

        // Navigate to SelectProvider and confirm with Enter
        app.handle_key(key(KeyCode::Char('k')));
        app.handle_key(key(KeyCode::Char('k')));
        assert_eq!(app.home_index, 0);
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.screen, Screen::SelectProvider);
        app.handle_key(key(KeyCode::Down));
        app.handle_key(key(KeyCode::Enter));
        assert_eq!(app.selected_provider, ProviderKind::UpCloud);
        assert_eq!(app.screen, Screen::Home);

        // Shortcut '6' quits
        app.handle_key(key(KeyCode::Char('6')));
        assert!(app.should_quit);
    }
}
