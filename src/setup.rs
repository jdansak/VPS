use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, USER_AGENT};
use std::env;
use std::time::Duration;

use crate::config::SessionState;
use crate::roles::ServerRole;
use crate::transport::SshTransport;

/// Configuration for cloning/updating and deploying a GitHub repository.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GithubDeployConfig {
    pub repo: String,
    pub branch: String,
    pub deploy_path: Option<String>,
    pub deploy_cmd: Option<String>,
    pub github_token: Option<String>,
    pub username: String,
    pub caddy_labels: bool,
    pub caddy_domain: Option<String>,
    pub caddy_service: Option<String>,
    pub caddy_port: Option<String>,
    pub caddy_extra_labels: Option<String>,
}

/// Configuration for executing the 6-step remote VPS setup pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupConfig {
    pub host: String,
    pub ssh_user: String,
    pub new_username: String,
    pub hostname: String,
    pub role: ServerRole,
    pub provider_name: String,
    pub tailscale_mode: bool,
    pub ssh_pubkey: Option<String>,
    pub dry_run: bool,
    pub github_deploy: Option<GithubDeployConfig>,
    pub sudo_nopasswd: bool,
    pub sudo_password: Option<String>,
}

/// Ordered stages of the remote server setup workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupStepKind {
    SystemUpdate,
    CreateUser,
    HardenSsh,
    ConfigureRole,
    Fail2banAndUpdates,
    ConfigureMotd,
}

impl SetupStepKind {
    /// Human-readable title for progress display.
    pub fn title(&self) -> &'static str {
        match self {
            SetupStepKind::SystemUpdate => "System Update & Base Packages",
            SetupStepKind::CreateUser => "Create Non-Root User & Sudo",
            SetupStepKind::HardenSsh => "Harden SSH & Tailscale Access",
            SetupStepKind::ConfigureRole => "Configure Server Role",
            SetupStepKind::Fail2banAndUpdates => "Fail2ban & Automatic Security Updates",
            SetupStepKind::ConfigureMotd => "Configure MOTD Dashboard",
        }
    }

    /// Returns all setup steps in execution order.
    pub fn all() -> &'static [SetupStepKind] {
        &[
            SetupStepKind::SystemUpdate,
            SetupStepKind::CreateUser,
            SetupStepKind::HardenSsh,
            SetupStepKind::ConfigureRole,
            SetupStepKind::Fail2banAndUpdates,
            SetupStepKind::ConfigureMotd,
        ]
    }
}

/// Result reported for each completed (or dry-run) setup step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepReport {
    pub step: SetupStepKind,
    pub success: bool,
    pub dry_run: bool,
    pub output: String,
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn distro_detect_block() -> &'static str {
    r#"DISTRO_ID="unknown"
DISTRO_FAMILY="unknown"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"
    case "${DISTRO_ID}" in
        ubuntu|debian)
            DISTRO_FAMILY="debian"
            ;;
        almalinux|rocky|centos|rhel|fedora)
            DISTRO_FAMILY="rhel"
            ;;
        *)
            case "${ID_LIKE:-}" in
                *debian*|*ubuntu*)
                    DISTRO_FAMILY="debian"
                    ;;
                *rhel*|*fedora*|*centos*)
                    DISTRO_FAMILY="rhel"
                    ;;
            esac
            ;;
    esac
fi

if [ "${DISTRO_FAMILY}" = "unknown" ]; then
    echo "Unsupported Linux distribution: ${DISTRO_ID}" >&2
    exit 1
fi"#
}

fn wrap_root_script(ssh_user: &str, body: &str) -> String {
    if ssh_user == "root" {
        format!("#!/usr/bin/env bash\nset -euo pipefail\n\n{}\n", body.trim_start())
    } else {
        format!(
            "#!/usr/bin/env bash\nset -euo pipefail\n\nsudo bash -s << 'BAB_STEP_EOF'\nset -euo pipefail\n\n{}\nBAB_STEP_EOF\n",
            body.trim()
        )
    }
}

/// Normalizes a GitHub repository reference (`owner/repo`, `https://...`, or `git@...`)
/// into `(clone_url, repo_name)` while rejecting unsafe characters or traversal sequences.
pub fn normalize_github_repo(input: &str) -> Result<(String, String)> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("GitHub repository cannot be empty"));
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(anyhow!(
            "GitHub repository must not contain whitespace: '{}'",
            trimmed
        ));
    }
    if trimmed.contains("..") {
        return Err(anyhow!(
            "GitHub repository must not contain '..': '{}'",
            trimmed
        ));
    }
    const FORBIDDEN_CHARS: &[char] = &[';', '&', '|', '$', '`', '<', '>', '\'', '"'];
    if trimmed.chars().any(|c| FORBIDDEN_CHARS.contains(&c)) {
        return Err(anyhow!(
            "GitHub repository contains forbidden shell metacharacters: '{}'",
            trimmed
        ));
    }

    if let Some(rest) = trimmed.strip_prefix("https://") {
        let cleaned = rest.trim_end_matches('/');
        let parts: Vec<&str> = cleaned.split('/').filter(|p| !p.is_empty()).collect();
        if parts.len() < 2 {
            return Err(anyhow!("Invalid HTTPS repository URL: '{}'", trimmed));
        }
        let last = parts.last().unwrap();
        let repo_name = last.strip_suffix(".git").unwrap_or(last);
        if repo_name.is_empty() {
            return Err(anyhow!(
                "Could not determine repository name from '{}'",
                trimmed
            ));
        }
        return Ok((
            trimmed.trim_end_matches('/').to_string(),
            repo_name.to_string(),
        ));
    }

    if let Some(after_git) = trimmed.strip_prefix("git@") {
        let (host, path) = after_git
            .split_once(':')
            .ok_or_else(|| anyhow!("Invalid SSH repository URL: '{}'", trimmed))?;
        let cleaned_path = path.trim_matches('/');
        if host.is_empty() || host.contains('/') || cleaned_path.is_empty() {
            return Err(anyhow!("Invalid SSH repository URL: '{}'", trimmed));
        }
        let last = cleaned_path.rsplit('/').next().unwrap_or("");
        let repo_name = last.strip_suffix(".git").unwrap_or(last);
        if repo_name.is_empty() {
            return Err(anyhow!(
                "Could not determine repository name from '{}'",
                trimmed
            ));
        }
        return Ok((trimmed.to_string(), repo_name.to_string()));
    }

    if trimmed.contains("://") || trimmed.contains(':') {
        return Err(anyhow!("Unsupported repository URL format: '{}'", trimmed));
    }

    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(anyhow!(
            "Expected 'owner/repo', 'https://...', or 'git@...' repository format, got '{}'",
            trimmed
        ));
    }
    let owner = parts[0];
    let repo_name = parts[1].strip_suffix(".git").unwrap_or(parts[1]);
    if repo_name.is_empty() {
        return Err(anyhow!(
            "Could not determine repository name from '{}'",
            trimmed
        ));
    }

    Ok((
        format!("https://github.com/{}/{}.git", owner, repo_name),
        repo_name.to_string(),
    ))
}

fn validate_caddy_domain(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!(
            "Caddy domain cannot be empty when Caddy label injection is enabled"
        ));
    }
    if trimmed.len() > 253
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ',' | ' '))
    {
        return Err(anyhow!(
            "Invalid Caddy domain '{}': allowed characters are letters, digits, '.', '-', and ','",
            trimmed
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_caddy_service(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err(anyhow!(
            "Invalid Compose service name '{}': allowed characters are letters, digits, '_', '-', and '.'",
            trimmed
        ));
    }
    Ok(trimmed.to_string())
}

fn validate_caddy_port(raw: &str) -> Result<u16> {
    let trimmed = raw.trim();
    let port: u16 = trimmed
        .parse()
        .map_err(|_| anyhow!("Invalid Caddy upstream port '{}': expected 1..=65535", trimmed))?;
    if port == 0 {
        return Err(anyhow!("Invalid Caddy upstream port '0': expected 1..=65535"));
    }
    Ok(port)
}

fn parse_caddy_extra_labels(raw: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for entry in raw.split([',', ';', '\n']) {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            return Err(anyhow!(
                "Invalid Caddy extra label '{}': expected key=value",
                trimmed
            ));
        };
        let key = k.trim();
        let val = v.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(anyhow!("Invalid Caddy label key '{}'", key));
        }
        if val.is_empty()
            || val
                .chars()
                .any(|c| c.is_control() || matches!(c, '\'' | '\n' | '\r'))
        {
            return Err(anyhow!(
                "Invalid value for Caddy label '{}': control characters and single quotes are not allowed",
                key
            ));
        }
        out.push((key.to_string(), val.to_string()));
    }
    Ok(out)
}

fn build_caddy_compose_deploy_section(cfg: &GithubDeployConfig) -> Result<String> {
    if !cfg.caddy_labels {
        return Ok(r#"if command -v docker >/dev/null 2>&1 && ( [ -f "${DEPLOY_PATH}/docker-compose.yml" ] || [ -f "${DEPLOY_PATH}/docker-compose.yaml" ] || [ -f "${DEPLOY_PATH}/compose.yml" ] || [ -f "${DEPLOY_PATH}/compose.yaml" ] ); then
    run_as_deploy_user 'cd "${DEPLOY_PATH}" && docker compose up -d --build'
fi"#
        .to_string());
    }

    let domain = validate_caddy_domain(cfg.caddy_domain.as_deref().unwrap_or(""))?;
    let service_opt = cfg
        .caddy_service
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(validate_caddy_service)
        .transpose()?;
    let port = match cfg
        .caddy_port
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(p) => validate_caddy_port(p)?,
        None => 8080,
    };
    let extra_labels = match cfg
        .caddy_extra_labels
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => parse_caddy_extra_labels(raw)?,
        None => Vec::new(),
    };

    let service_resolution = if let Some(svc) = service_opt {
        format!("CADDY_SERVICE={}", shell_quote(&svc))
    } else {
        r#"SERVICES_OUT=$(run_as_deploy_user 'cd "${DEPLOY_PATH}" && docker compose -f "${COMPOSE_FILE}" config --services')
    SVC_COUNT=$(printf '%s\n' "${SERVICES_OUT}" | sed '/^[[:space:]]*$/d' | wc -l | tr -d ' ')
    if [ "${SVC_COUNT}" -eq 1 ]; then
        CADDY_SERVICE=$(printf '%s\n' "${SERVICES_OUT}" | sed '/^[[:space:]]*$/d' | head -n 1)
    elif [ "${SVC_COUNT}" -eq 0 ]; then
        echo "No Compose services found in ${COMPOSE_FILE}" >&2
        exit 1
    else
        echo "Multiple Compose services found in ${COMPOSE_FILE}; specify Compose Service (GITHUB_CADDY_SERVICE)" >&2
        exit 1
    fi"#
        .to_string()
    };

    let mut extra_yaml = String::new();
    for (k, v) in extra_labels {
        extra_yaml.push_str(&format!("\n      {}: '{}'", k, v));
    }

    Ok(format!(
        r#"if command -v docker >/dev/null 2>&1; then
    COMPOSE_FILE=""
    for candidate in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
        if [ -f "${{DEPLOY_PATH}}/${{candidate}}" ]; then
            COMPOSE_FILE="${{candidate}}"
            break
        fi
    done
    if [ -n "${{COMPOSE_FILE}}" ]; then
        export COMPOSE_FILE
        docker network inspect caddy >/dev/null 2>&1 || docker network create caddy
        {service_resolution}
        CADDY_OVERRIDE_FILE=$(mktemp /tmp/bab-caddy-override.XXXXXX)
        cat > "${{CADDY_OVERRIDE_FILE}}" << BAB_CADDY_EOF
services:
  ${{CADDY_SERVICE}}:
    networks:
      - caddy
    labels:
      caddy: '{domain}'
      caddy.reverse_proxy: '{{{{upstreams {port}}}}}'{extra_yaml}
networks:
  caddy:
    external: true
BAB_CADDY_EOF
        chmod 0644 "${{CADDY_OVERRIDE_FILE}}"
        export CADDY_OVERRIDE_FILE
        run_as_deploy_user 'cd "${{DEPLOY_PATH}}" && docker compose -f "${{COMPOSE_FILE}}" -f "${{CADDY_OVERRIDE_FILE}}" up -d --build'
        rm -f "${{CADDY_OVERRIDE_FILE}}"
    fi
fi"#
    ))
}

fn build_github_deploy_body(cfg: &GithubDeployConfig) -> Result<String> {
    let (repo_url, repo_name) = normalize_github_repo(&cfg.repo)?;
    let deploy_user = cfg.username.trim();
    if deploy_user.is_empty() {
        return Err(anyhow!("Deploy username cannot be empty"));
    }
    if deploy_user.chars().any(char::is_whitespace) {
        return Err(anyhow!("Deploy username must not contain whitespace"));
    }

    let branch = {
        let trimmed = cfg.branch.trim();
        if trimmed.is_empty() {
            "main"
        } else {
            trimmed
        }
    };

    let deploy_path = match cfg
        .deploy_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(p) => p.to_string(),
        None => format!("/home/{}/apps/{}", deploy_user, repo_name),
    };

    let deploy_cmd = cfg
        .deploy_cmd
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let github_token = cfg
        .github_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let q_repo_url = shell_quote(&repo_url);
    let q_repo_name = shell_quote(&repo_name);
    let q_branch = shell_quote(branch);
    let q_user = shell_quote(deploy_user);
    let q_path = shell_quote(&deploy_path);

    let askpass_setup = if let Some(token) = github_token {
        let q_token = shell_quote(token);
        format!(
            r#"BAB_GITHUB_TOKEN={q_token}
export BAB_GITHUB_TOKEN
GIT_ASKPASS_SCRIPT=$(mktemp /tmp/bab-git-askpass.XXXXXX)
trap 'rm -f "${{GIT_ASKPASS_SCRIPT}}"' EXIT
cat > "${{GIT_ASKPASS_SCRIPT}}" << 'BAB_ASKPASS_EOF'
#!/usr/bin/env bash
case "${{1:-}}" in
    *[Uu]sername*) printf '%s\n' 'x-access-token' ;;
    *) printf '%s\n' "${{BAB_GITHUB_TOKEN}}" ;;
esac
BAB_ASKPASS_EOF
chmod 0700 "${{GIT_ASKPASS_SCRIPT}}"
if id "${{DEPLOY_USER}}" >/dev/null 2>&1; then
    chown "${{DEPLOY_USER}}:${{DEPLOY_USER}}" "${{GIT_ASKPASS_SCRIPT}}"
fi
export GIT_ASKPASS="${{GIT_ASKPASS_SCRIPT}}"
export GIT_TERMINAL_PROMPT=0"#
        )
    } else {
        "export GIT_TERMINAL_PROMPT=0".to_string()
    };

    let deploy_section = if let Some(cmd) = deploy_cmd {
        let q_cmd = shell_quote(cmd);
        format!(
            r#"DEPLOY_CMD={q_cmd}
export DEPLOY_CMD
run_as_deploy_user 'cd "${{DEPLOY_PATH}}" && bash -lc "${{DEPLOY_CMD}}"'"#
        )
    } else {
        build_caddy_compose_deploy_section(cfg)?
    };

    let mut preserve_vars = vec![
        "GIT_TERMINAL_PROMPT",
        "REPO_URL",
        "BRANCH",
        "DEPLOY_PATH",
    ];
    if github_token.is_some() {
        preserve_vars.push("GIT_ASKPASS");
        preserve_vars.push("BAB_GITHUB_TOKEN");
    }
    if deploy_cmd.is_some() {
        preserve_vars.push("DEPLOY_CMD");
    } else if cfg.caddy_labels {
        preserve_vars.push("COMPOSE_FILE");
        preserve_vars.push("CADDY_OVERRIDE_FILE");
    }
    let preserve_env = preserve_vars.join(",");

    let askpass_cleanup = if github_token.is_some() {
        "\nrm -f \"${GIT_ASKPASS_SCRIPT}\"\nunset BAB_GITHUB_TOKEN GIT_ASKPASS"
    } else {
        ""
    };

    Ok(format!(
        r#"REPO_URL={q_repo_url}
REPO_NAME={q_repo_name}
BRANCH={q_branch}
DEPLOY_USER={q_user}
DEPLOY_PATH={q_path}
export REPO_URL BRANCH DEPLOY_PATH

if ! command -v git >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y git
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y git
    else
        echo "Cannot install git: neither apt-get nor dnf found" >&2
        exit 1
    fi
fi

mkdir -p "${{DEPLOY_PATH}}"
if id "${{DEPLOY_USER}}" >/dev/null 2>&1; then
    chown -R "${{DEPLOY_USER}}:${{DEPLOY_USER}}" "${{DEPLOY_PATH}}"
fi

run_as_deploy_user() {{
    local cmd="$1"
    if [ "$(id -un)" = "${{DEPLOY_USER}}" ]; then
        bash -lc "${{cmd}}"
    elif command -v sudo >/dev/null 2>&1; then
        sudo -H -u "${{DEPLOY_USER}}" --preserve-env={preserve_env} bash -lc "${{cmd}}"
    else
        su -p -s /bin/bash "${{DEPLOY_USER}}" -c "bash -lc $(printf '%q' "${{cmd}}")"
    fi
}}

{askpass_setup}

if [ -d "${{DEPLOY_PATH}}/.git" ]; then
    run_as_deploy_user 'git -C "${{DEPLOY_PATH}}" fetch --all --prune && git -C "${{DEPLOY_PATH}}" checkout "${{BRANCH}}" && git -C "${{DEPLOY_PATH}}" pull --ff-only'
else
    run_as_deploy_user 'git clone --branch "${{BRANCH}}" "${{REPO_URL}}" "${{DEPLOY_PATH}}"'
fi{askpass_cleanup}

{deploy_section}"#
    ))
}

/// Builds an idempotent bash script (`set -euo pipefail`) to clone/update and deploy a GitHub repository.
pub fn build_github_deploy_script(cfg: &GithubDeployConfig) -> Result<String> {
    let body = build_github_deploy_body(cfg)?;
    Ok(format!(
        "#!/usr/bin/env bash\nset -euo pipefail\n\n{}\n",
        body.trim()
    ))
}

/// Builds the bash script (`set -euo pipefail`) for a given setup step.
pub fn build_step_script(step: SetupStepKind, cfg: &SetupConfig) -> String {
    match step {
        SetupStepKind::SystemUpdate => {
            let quoted_hostname = shell_quote(&cfg.hostname);
            let distro = distro_detect_block();
            let body = format!(
                r#"{distro}

TARGET_HOSTNAME={quoted_hostname}
if [ -n "${{TARGET_HOSTNAME}}" ] && command -v hostnamectl >/dev/null 2>&1; then
    hostnamectl set-hostname "${{TARGET_HOSTNAME}}" 2>/dev/null || true
fi

case "${{DISTRO_FAMILY}}" in
    debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get upgrade -y
        apt-get install -y git curl wget sudo
        ;;
    rhel)
        dnf update -y
        dnf install -y git curl wget sudo
        ;;
esac"#
            );
            wrap_root_script(&cfg.ssh_user, &body)
        }
        SetupStepKind::CreateUser => {
            let quoted_new_user = shell_quote(&cfg.new_username);
            let quoted_ssh_user = shell_quote(&cfg.ssh_user);
            let quoted_ssh_pubkey = shell_quote(
                cfg.ssh_pubkey
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or(""),
            );
            let quoted_sudo_password = shell_quote(
                cfg.sudo_password
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or(""),
            );
            let sudoers_block = if cfg.sudo_nopasswd {
                r#"if [ ! -f "/etc/sudoers.d/${NEW_USER}" ]; then
    echo "${NEW_USER} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${NEW_USER}"
    chmod 440 "/etc/sudoers.d/${NEW_USER}"
fi"#
            } else {
                r#"if [ "${SSH_USER}" = "root" ]; then
    rm -f "/etc/sudoers.d/${NEW_USER}"
fi"#
            };
            let distro = distro_detect_block();
            let body = format!(
                r#"{distro}

NEW_USER={quoted_new_user}
SSH_USER={quoted_ssh_user}
SSH_PUBKEY={quoted_ssh_pubkey}
SUDO_PASSWORD={quoted_sudo_password}

case "${{DISTRO_FAMILY}}" in
    debian) SUDO_GRP="sudo" ;;
    rhel)   SUDO_GRP="wheel" ;;
esac

if ! id "${{NEW_USER}}" >/dev/null 2>&1; then
    case "${{DISTRO_FAMILY}}" in
        debian)
            adduser --disabled-password --gecos "" "${{NEW_USER}}" 2>/dev/null || adduser --disabled-password --allow-bad-names --gecos "" "${{NEW_USER}}" 2>/dev/null || adduser --disabled-password --force-badname --gecos "" "${{NEW_USER}}" 2>/dev/null || useradd --badname -m -s /bin/bash "${{NEW_USER}}" 2>/dev/null || useradd -m -s /bin/bash "${{NEW_USER}}"
            ;;
        rhel)
            useradd -m -s /bin/bash "${{NEW_USER}}" 2>/dev/null || useradd --badname -m -s /bin/bash "${{NEW_USER}}"
            ;;
    esac
fi

if ! id -nG "${{NEW_USER}}" | grep -qw "${{SUDO_GRP}}"; then
    usermod -aG "${{SUDO_GRP}}" "${{NEW_USER}}"
fi

if [ -n "${{SUDO_PASSWORD}}" ]; then
    if id -u "${{NEW_USER}}" >/dev/null 2>&1; then
        printf '%s:%s\n' "${{NEW_USER}}" "${{SUDO_PASSWORD}}" | chpasswd || true
    fi
fi

{sudoers_block}

SSH_DIR="/home/${{NEW_USER}}/.ssh"
AUTH_KEYS="${{SSH_DIR}}/authorized_keys"
mkdir -p "${{SSH_DIR}}"
if [ -s /root/.ssh/authorized_keys ]; then
    cp /root/.ssh/authorized_keys "${{AUTH_KEYS}}"
elif [ "${{SSH_USER}}" != "root" ] && [ "${{SSH_USER}}" != "${{NEW_USER}}" ] && [ -s "/home/${{SSH_USER}}/.ssh/authorized_keys" ]; then
    cp "/home/${{SSH_USER}}/.ssh/authorized_keys" "${{AUTH_KEYS}}"
else
    touch "${{AUTH_KEYS}}"
fi
if [ -n "${{SSH_PUBKEY}}" ] && ! grep -qxF "${{SSH_PUBKEY}}" "${{AUTH_KEYS}}" 2>/dev/null; then
    if [ -s "${{AUTH_KEYS}}" ] && [ -n "$(tail -c1 "${{AUTH_KEYS}}" 2>/dev/null || true)" ]; then
        printf '\n' >> "${{AUTH_KEYS}}"
    fi
    printf '%s\n' "${{SSH_PUBKEY}}" >> "${{AUTH_KEYS}}"
fi
chown -R "${{NEW_USER}}:${{NEW_USER}}" "${{SSH_DIR}}" 2>/dev/null || chown -R "${{NEW_USER}}" "${{SSH_DIR}}" || true
chmod 700 "${{SSH_DIR}}"
chmod 600 "${{AUTH_KEYS}}"

mkdir -p "/home/${{NEW_USER}}/apps"
chown -R "${{NEW_USER}}:${{NEW_USER}}" "/home/${{NEW_USER}}/apps" 2>/dev/null || chown -R "${{NEW_USER}}" "/home/${{NEW_USER}}/apps" || true"#
            );
            wrap_root_script(&cfg.ssh_user, &body)
        }
        SetupStepKind::HardenSsh => {
            let tailscale_mode = cfg.tailscale_mode;
            let body = format!(
                r#"TAILSCALE_MODE={tailscale_mode}

if [ "${{TAILSCALE_MODE}}" = "true" ]; then
    if ! command -v tailscale >/dev/null 2>&1; then
        curl -fsSL https://tailscale.com/install.sh | sh
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl enable --now tailscaled 2>/dev/null || true
    fi
    tailscale set --ssh 2>/dev/null || true
fi

set_sshd_option() {{
    local key="$1" value="$2"
    if grep -qE "^#?[[:space:]]*${{key}}[[:space:]]" /etc/ssh/sshd_config; then
        sed -i "s/^#\{{0,1\}}[[:space:]]*${{key}}[[:space:]].*/${{key}} ${{value}}/" /etc/ssh/sshd_config
    else
        echo "${{key}} ${{value}}" >> /etc/ssh/sshd_config
    fi
}}

restart_ssh() {{
    systemctl restart sshd 2>/dev/null || systemctl restart ssh
}}

cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
set_sshd_option PermitRootLogin no
set_sshd_option PasswordAuthentication no
set_sshd_option PubkeyAuthentication yes
set_sshd_option KbdInteractiveAuthentication no
set_sshd_option ChallengeResponseAuthentication no
set_sshd_option MaxAuthTries 3
set_sshd_option X11Forwarding no

DROPIN_FILE="/etc/ssh/sshd_config.d/00-bab-hardening.conf"
DROPIN_BAK=""
if [ -f "${{DROPIN_FILE}}" ]; then
    DROPIN_BAK="/tmp/00-bab-hardening.conf.bak"
    cp "${{DROPIN_FILE}}" "${{DROPIN_BAK}}"
fi
if grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config; then
    mkdir -p /etc/ssh/sshd_config.d
    cat > "${{DROPIN_FILE}}" << 'SSHD_HARDEN_EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
MaxAuthTries 3
X11Forwarding no
SSHD_HARDEN_EOF
    chmod 600 "${{DROPIN_FILE}}"
fi

mkdir -p /run/sshd
if sshd -t 2>/dev/null; then
    if [ -n "${{DROPIN_BAK}}" ]; then
        rm -f "${{DROPIN_BAK}}"
    fi
    restart_ssh
    SSHD_EFFECTIVE=$(sshd -T 2>/dev/null || true)
    if ! grep -qx "passwordauthentication no" <<< "${{SSHD_EFFECTIVE}}" || ! grep -qx "permitrootlogin no" <<< "${{SSHD_EFFECTIVE}}"; then
        echo "Warning: effective sshd configuration may be overridden by another drop-in file" >&2
    fi
else
    cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    if [ -n "${{DROPIN_BAK}}" ] && [ -f "${{DROPIN_BAK}}" ]; then
        mv "${{DROPIN_BAK}}" "${{DROPIN_FILE}}"
    else
        rm -f "${{DROPIN_FILE}}"
    fi
    restart_ssh || true
    echo "Invalid sshd_config after hardening; restored backup" >&2
    exit 1
fi"#
            );
            wrap_root_script(&cfg.ssh_user, &body)
        }
        SetupStepKind::ConfigureRole => {
            let mut combined = cfg
                .role
                .role_setup_script(&cfg.new_username, cfg.tailscale_mode);
            if let Some(ref gh) = cfg.github_deploy {
                let gh_body = match build_github_deploy_script(gh) {
                    Ok(full) => full
                        .strip_prefix("#!/usr/bin/env bash\n")
                        .unwrap_or(&full)
                        .strip_prefix("set -euo pipefail\n")
                        .unwrap_or(&full)
                        .trim()
                        .to_string(),
                    Err(err) => format!(
                        "echo {} >&2\nexit 1",
                        shell_quote(&format!("Invalid GitHub deploy config: {}", err))
                    ),
                };
                combined = format!("{}\n\n{}\n", combined.trim_end(), gh_body);
            }
            if cfg.ssh_user == "root" {
                combined
            } else {
                let inner = combined
                    .strip_prefix("#!/usr/bin/env bash\n")
                    .unwrap_or(&combined);
                format!(
                    "#!/usr/bin/env bash\nset -euo pipefail\n\nsudo bash -s << 'BAB_STEP_EOF'\n{}\nBAB_STEP_EOF\n",
                    inner.trim_end()
                )
            }
        }
        SetupStepKind::Fail2banAndUpdates => {
            let distro = distro_detect_block();
            let body = format!(
                r#"{distro}

case "${{DISTRO_FAMILY}}" in
    debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y fail2ban unattended-upgrades
        ;;
    rhel)
        dnf install -y epel-release || true
        dnf install -y fail2ban dnf-automatic
        ;;
esac

mkdir -p /etc/fail2ban
cat > /etc/fail2ban/jail.local << 'F2B_LOCAL_EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
backend = systemd
F2B_LOCAL_EOF

systemctl enable --now fail2ban

case "${{DISTRO_FAMILY}}" in
    debian)
        echo 'Unattended-Upgrade::Automatic-Reboot "false";' > /etc/apt/apt.conf.d/51auto-upgrades
        dpkg-reconfigure -f noninteractive unattended-upgrades
        ;;
    rhel)
        sed -i 's/apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
        systemctl enable --now dnf-automatic.timer
        ;;
esac"#
            );
            wrap_root_script(&cfg.ssh_user, &body)
        }
        SetupStepKind::ConfigureMotd => {
            let distro = distro_detect_block();
            let quoted_role = shell_quote(cfg.role.label());
            let quoted_provider = shell_quote(&cfg.provider_name);
            let transport_label = if cfg.tailscale_mode {
                "Tailscale SSH"
            } else {
                "Standard SSH"
            };
            let quoted_transport = shell_quote(transport_label);
            let quoted_user = shell_quote(&cfg.new_username);
            let sudoers_cleanup = if cfg.sudo_nopasswd {
                String::new()
            } else {
                format!(
                    "\n\nNEW_USER={quoted_user}\nrm -f \"/etc/sudoers.d/${{NEW_USER}}\""
                )
            };
            let body = format!(
                r##"{distro}

MOTD_SCRIPT=$(cat << 'BAB_MOTD_EOF'
#!/usr/bin/env bash
BAB_ROLE={quoted_role}
BAB_PROVIDER={quoted_provider}
BAB_TRANSPORT={quoted_transport}
BAB_USER={quoted_user}
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BOLD="\033[1m"
NC="\033[0m"

HOSTNAME=$(hostname)
OS=$(. /etc/os-release && echo "$PRETTY_NAME")
UPTIME=$(uptime -p 2>/dev/null | sed "s/up //" || echo "N/A")
LOAD=$(awk '{{print $1, $2, $3}}' /proc/loadavg)
CPU_CORES=$(nproc)

RAM_TOTAL=$(free -m | awk '/Mem:/ {{print $2}}')
RAM_USED=$(free -m | awk '/Mem:/ {{print $3}}')
if [ "${{RAM_TOTAL:-0}}" -gt 0 ] 2>/dev/null; then
    RAM_PCT=$((RAM_USED * 100 / RAM_TOTAL))
else
    RAM_PCT=0
fi

DISK_TOTAL=$(df -h / | awk 'NR==2 {{print $2}}')
DISK_USED=$(df -h / | awk 'NR==2 {{print $3}}')
DISK_PCT=$(df / | awk 'NR==2 {{print $5}}' | tr -d "%")
IP=$(hostname -I 2>/dev/null | awk '{{print $1}}' || echo "N/A")

if command -v docker >/dev/null 2>&1; then
    DOCKER_COUNT=$(docker ps -q 2>/dev/null | wc -l | tr -d " ")
    DOCKER_LINE="  Docker     : ${{DOCKER_COUNT}} running"
else
    DOCKER_LINE=""
fi

color_pct() {{
    if [ "$1" -lt 60 ]; then echo -e "${{GREEN}}${{1}}%${{NC}}"
    elif [ "$1" -lt 85 ]; then echo -e "${{YELLOW}}${{1}}%${{NC}}"
    else echo -e "${{RED}}${{1}}%${{NC}}"
    fi
}}

echo ""
echo "========================================="
echo -e "  ${{BOLD}}${{HOSTNAME}}${{NC}} - ${{OS}}"
echo "  Role       : ${{BAB_ROLE}} (${{BAB_PROVIDER}})"
echo "  Transport  : ${{BAB_TRANSPORT}}"
echo "  User       : ${{BAB_USER}}"
echo "========================================="
echo ""
echo "  Uptime     : ${{UPTIME}}"
echo "  Load       : ${{LOAD}}"
echo "  CPU        : ${{CPU_CORES}} cores"
echo -e "  RAM        : ${{RAM_USED}} MB / ${{RAM_TOTAL}} MB ($(color_pct "$RAM_PCT"))"
echo -e "  Disk       : ${{DISK_USED}} / ${{DISK_TOTAL}} ($(color_pct "$DISK_PCT"))"
echo "  IP         : ${{IP}}"
if [ -n "$DOCKER_LINE" ]; then
    echo "$DOCKER_LINE"
fi
echo "========================================="
echo ""
BAB_MOTD_EOF
)

case "${{DISTRO_FAMILY}}" in
    debian)
        chmod -x /etc/update-motd.d/* 2>/dev/null || true
        printf '%s\n' "${{MOTD_SCRIPT}}" > /etc/update-motd.d/99-vps-dashboard
        chmod +x /etc/update-motd.d/99-vps-dashboard
        ;;
    rhel)
        printf '%s\n' "${{MOTD_SCRIPT}}" > /etc/profile.d/vps-dashboard.sh
        chmod +x /etc/profile.d/vps-dashboard.sh
        ;;
esac{sudoers_cleanup}"##
            );
            wrap_root_script(&cfg.ssh_user, &body)
        }
    }
}

fn combine_command_output(stdout: &str, stderr: &str) -> String {
    match (stdout.trim(), stderr.trim()) {
        ("", "") => String::new(),
        (_, "") => stdout.to_string(),
        ("", _) => stderr.to_string(),
        _ => format!("{}\n{}", stdout.trim_end(), stderr.trim_end()),
    }
}

fn root_fallback_user<'a>(
    ssh_user: &str,
    candidate_user: &'a str,
    combined_output: &str,
) -> Option<&'a str> {
    let candidate = candidate_user.trim();
    if ssh_user == "root"
        && !candidate.is_empty()
        && candidate != "root"
        && (combined_output.contains("tailnet policy does not permit")
            || combined_output.contains("Permission denied"))
    {
        Some(candidate)
    } else {
        None
    }
}

/// Executes the 6-step setup pipeline over an `SshTransport`.
pub struct SetupRunner<'a> {
    transport: &'a SshTransport,
    session_state: Option<&'a SessionState>,
}

impl<'a> SetupRunner<'a> {
    /// Creates a new `SetupRunner` with an optional `SessionState` to record `SERVER_ROLE`.
    pub fn new(transport: &'a SshTransport, session_state: Option<&'a SessionState>) -> Self {
        Self {
            transport,
            session_state,
        }
    }

    /// Runs all 6 setup steps in order, invoking `on_progress` after each step.
    /// When `cfg.dry_run` is true, collects generated scripts without invoking SSH.
    pub fn run_all<F>(&self, cfg: &SetupConfig, on_progress: F) -> Result<Vec<StepReport>>
    where
        F: FnMut(&StepReport),
    {
        self.run_all_with_callbacks(cfg, |_, _, _| {}, on_progress)
    }

    /// Runs all 6 setup steps in order, invoking `on_start` before each step and
    /// `on_done` after each step finishes.
    /// When `cfg.dry_run` is true, collects generated scripts without invoking SSH.
    pub fn run_all_with_callbacks<FStart, FDone>(
        &self,
        cfg: &SetupConfig,
        mut on_start: FStart,
        mut on_done: FDone,
    ) -> Result<Vec<StepReport>>
    where
        FStart: FnMut(usize, usize, SetupStepKind),
        FDone: FnMut(&StepReport),
    {
        if let Some(ref gh) = cfg.github_deploy {
            build_github_deploy_script(gh)?;
        }

        let steps = SetupStepKind::all();
        let mut reports = Vec::with_capacity(steps.len());
        let mut active_ssh_user = cfg.ssh_user.clone();

        for (idx, &step) in steps.iter().enumerate() {
            on_start(idx, steps.len(), step);

            if cfg.dry_run {
                let script = build_step_script(step, cfg);
                let report = StepReport {
                    step,
                    success: true,
                    dry_run: true,
                    output: script,
                };
                on_done(&report);
                reports.push(report);
                continue;
            }

            let mut step_cfg = cfg.clone();
            step_cfg.ssh_user = active_ssh_user.clone();
            let script = build_step_script(step, &step_cfg);

            let mut out = self.transport.exec(&active_ssh_user, &cfg.host, &script)?;
            let mut combined_output = combine_command_output(&out.stdout, &out.stderr);
            if !out.success() {
                if let Some(fallback_user) =
                    root_fallback_user(&active_ssh_user, &cfg.new_username, &combined_output)
                {
                    active_ssh_user = fallback_user.to_string();
                    step_cfg.ssh_user = active_ssh_user.clone();
                    let retry_script = build_step_script(step, &step_cfg);
                    out = self
                        .transport
                        .exec(&active_ssh_user, &cfg.host, &retry_script)?;
                    combined_output = combine_command_output(&out.stdout, &out.stderr);
                }
            }

            let success = out.success();
            let status_code = out.status_code;
            let report = StepReport {
                step,
                success,
                dry_run: false,
                output: combined_output.clone(),
            };
            on_done(&report);
            reports.push(report);

            if !success {
                return Err(anyhow!(
                    "setup step '{}' failed (exit {}): {}",
                    step.title(),
                    status_code,
                    combined_output
                ));
            }
        }

        if !cfg.dry_run {
            if let Some(state) = self.session_state {
                state.set_server_role(&cfg.role.to_string())?;
            }
        }

        Ok(reports)
    }

    /// Clones/updates and deploys a GitHub repository on the target host.
    /// When `dry_run` is true, returns the generated script without invoking SSH.
    pub fn deploy_github(
        &self,
        ssh_user: &str,
        host: &str,
        cfg: &GithubDeployConfig,
        dry_run: bool,
    ) -> Result<String> {
        let body = build_github_deploy_body(cfg)?;
        let script = wrap_root_script(ssh_user, &body);
        if dry_run {
            return Ok(script);
        }

        let mut out = self.transport.exec(ssh_user, host, &script)?;
        let mut combined_output = combine_command_output(&out.stdout, &out.stderr);
        if !out.success() {
            if let Some(fallback_user) =
                root_fallback_user(ssh_user, &cfg.username, &combined_output)
            {
                let retry_script = wrap_root_script(fallback_user, &body);
                out = self.transport.exec(fallback_user, host, &retry_script)?;
                combined_output = combine_command_output(&out.stdout, &out.stderr);
            }
        }
        if !out.success() {
            return Err(anyhow!(
                "github deploy failed (exit {}): {}",
                out.status_code,
                combined_output
            ));
        }
        Ok(combined_output)
    }
}

const DEFAULT_GITHUB_API_BASE: &str = "https://api.github.com";

/// Validates a GitHub personal access token against the base URL in `GITHUB_API_BASE`
/// (falling back to `https://api.github.com` when unset or blank).
pub fn validate_github_token(token: &str) -> Result<bool> {
    let base = env::var("GITHUB_API_BASE")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_GITHUB_API_BASE.to_string());
    validate_github_token_with_base(token, &base)
}

/// Validates a GitHub personal access token against an explicit GitHub API base URL.
pub fn validate_github_token_with_base(token: &str, base_url: &str) -> Result<bool> {
    let token = token.trim();
    if token.is_empty() {
        return Ok(false);
    }

    let url = format!("{}/user", base_url.trim().trim_end_matches('/'));
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow!("Failed to build HTTP client: {}", e))?;

    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header(USER_AGENT, "bab/0.1")
        .header(ACCEPT, "application/vnd.github+json")
        .send()?;

    let status = resp.status();
    match status.as_u16() {
        200..=299 => Ok(true),
        401 | 403 => Ok(false),
        _ => {
            let body = resp.text().unwrap_or_default();
            Err(anyhow!(
                "Unexpected status {} when validating GitHub token: {}",
                status,
                body
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::TransportMode;
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;
    use tempfile::tempdir;

    fn sample_config(role: ServerRole, ssh_user: &str, dry_run: bool) -> SetupConfig {
        SetupConfig {
            host: "100.64.0.50".to_string(),
            ssh_user: ssh_user.to_string(),
            new_username: "deploy".to_string(),
            hostname: "prod-vps-1".to_string(),
            role,
            provider_name: "vultr".to_string(),
            tailscale_mode: true,
            ssh_pubkey: None,
            dry_run,
            github_deploy: None,
            sudo_nopasswd: true,
            sudo_password: None,
        }
    }

    fn assert_bash_syntax_ok(script: &str, label: &str) {
        let mut child = Command::new("bash")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn bash -n");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(script.as_bytes())
            .expect("write script");
        let out = child.wait_with_output().expect("wait bash -n");
        assert!(
            out.status.success(),
            "bash -n failed for {}: {}",
            label,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn write_mock_ssh(dir: &Path, log_file: &Path) -> Result<std::path::PathBuf> {
        let mock_ssh = dir.join("mock_ssh");
        {
            let mut f = File::create(&mock_ssh)?;
            writeln!(f, "#!/usr/bin/env bash")?;
            writeln!(f, "set -euo pipefail")?;
            writeln!(f, "printf 'CALL:%s\\n' \"$*\" >> \"{}\"", log_file.display())?;
            writeln!(f, "echo 'MOCK_SSH_OK'")?;
        }
        fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755))?;
        Ok(mock_ssh)
    }

    #[test]
    fn step_scripts_syntax_and_sudo_behavior() {
        for &role in ServerRole::all() {
            let root_cfg = sample_config(role, "root", false);
            let non_root_cfg = sample_config(role, "ubuntu", false);

            for &step in SetupStepKind::all() {
                assert!(!step.title().is_empty());

                let root_script = build_step_script(step, &root_cfg);
                assert_bash_syntax_ok(&root_script, &format!("{}-{:?}-root", role, step));
                assert!(root_script.contains("set -euo pipefail"));
                assert!(!root_script.contains("sudo bash -s"));

                let sudo_script = build_step_script(step, &non_root_cfg);
                assert_bash_syntax_ok(&sudo_script, &format!("{}-{:?}-sudo", role, step));
                assert!(sudo_script.contains("sudo bash -s"));
                assert!(sudo_script.contains("BAB_STEP_EOF"));
                assert!(!sudo_script.contains("VPSKIT_STEP_EOF"));
            }
        }
    }

    #[test]
    fn create_user_installs_ssh_pubkey_idempotently() {
        let mut cfg = sample_config(ServerRole::Vanilla, "root", false);
        cfg.ssh_pubkey = Some("  ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@host  \n".to_string());
        let script = build_step_script(SetupStepKind::CreateUser, &cfg);
        assert_bash_syntax_ok(&script, "create-user-pubkey");
        assert!(script.contains("/etc/sudoers.d/${NEW_USER}"));
        assert!(script.contains("NOPASSWD:ALL"));
        assert!(script.contains("chmod 440 \"/etc/sudoers.d/${NEW_USER}\""));
        assert!(script.contains("cp /root/.ssh/authorized_keys"));
        assert!(script.contains("SSH_PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey user@host'"));
        assert!(script.contains("grep -qxF \"${SSH_PUBKEY}\""));
        assert!(script.contains("chmod 700 \"${SSH_DIR}\""));
        assert!(script.contains("chmod 600 \"${AUTH_KEYS}\""));
        assert!(script.contains("chown -R \"${NEW_USER}:${NEW_USER}\" \"${SSH_DIR}\""));

        let mut cfg_empty = sample_config(ServerRole::Vanilla, "root", false);
        cfg_empty.ssh_pubkey = Some("   ".to_string());
        let script_empty = build_step_script(SetupStepKind::CreateUser, &cfg_empty);
        assert_bash_syntax_ok(&script_empty, "create-user-empty-pubkey");
        assert!(script_empty.contains("SSH_PUBKEY=''"));
    }

    #[test]
    fn harden_ssh_enforces_directives_and_gates_tailscale() {
        for tailscale_mode in [true, false] {
            let mut cfg = sample_config(ServerRole::Vanilla, "root", false);
            cfg.tailscale_mode = tailscale_mode;
            let script = build_step_script(SetupStepKind::HardenSsh, &cfg);
            assert_bash_syntax_ok(&script, &format!("harden-ssh-ts={tailscale_mode}"));
            assert!(script.contains(&format!("TAILSCALE_MODE={tailscale_mode}")));
            assert!(script.contains("if [ \"${TAILSCALE_MODE}\" = \"true\" ]; then"));
            assert!(script.contains("tailscale set --ssh"));
            assert!(script.contains("/etc/ssh/sshd_config.d/00-bab-hardening.conf"));
            assert!(!script.contains("00-vpskit-hardening.conf"));
            for directive in [
                "PermitRootLogin no",
                "PasswordAuthentication no",
                "PubkeyAuthentication yes",
                "KbdInteractiveAuthentication no",
                "ChallengeResponseAuthentication no",
                "MaxAuthTries 3",
                "X11Forwarding no",
            ] {
                assert!(
                    script.contains(directive),
                    "missing hardened directive '{directive}' for tailscale_mode={tailscale_mode}"
                );
            }
            assert!(script.contains("sshd -t"));
            assert!(script.contains("sshd_config.bak"));
        }
    }

    #[test]
    fn fail2ban_and_updates_script_and_motd_rebrand() {
        let mut cfg = sample_config(ServerRole::Vanilla, "ubuntu", false);
        cfg.tailscale_mode = false;

        let f2b_script = build_step_script(SetupStepKind::Fail2banAndUpdates, &cfg);
        assert_bash_syntax_ok(&f2b_script, "fail2ban-and-updates");
        assert!(f2b_script.contains("fail2ban"));
        assert!(f2b_script.contains("unattended-upgrades"));
        assert!(f2b_script.contains("dnf-automatic.timer"));

        let motd_script = build_step_script(SetupStepKind::ConfigureMotd, &cfg);
        assert_bash_syntax_ok(&motd_script, "motd-rebrand");
        assert!(motd_script.contains("BAB_MOTD_EOF"));
        assert!(motd_script.contains("BAB_ROLE="));
        assert!(motd_script.contains("BAB_PROVIDER="));
        assert!(motd_script.contains("BAB_TRANSPORT='Standard SSH'"));
        assert!(motd_script.contains("BAB_USER='deploy'"));
        assert!(!motd_script.contains("VPSKIT_MOTD_EOF"));
        assert!(!motd_script.contains("VPSKIT_ROLE"));
        assert!(!motd_script.contains("VPSKIT_PROVIDER"));
    }

    #[test]
    fn vanilla_role_setup_step_produces_valid_script() {
        let cfg = sample_config(ServerRole::Vanilla, "root", false);
        let script = build_step_script(SetupStepKind::ConfigureRole, &cfg);
        assert_bash_syntax_ok(&script, "configure-role-vanilla");
        assert!(script.contains("ufw default deny incoming"));
        assert!(!script.contains("docker"));
        assert!(!script.contains("caddy"));
    }

    #[test]
    fn dry_run_collects_all_6_steps_without_ssh_for_all_roles() -> Result<()> {
        let dir = tempdir()?;
        let nonexistent_ssh = dir.path().join("does-not-exist-ssh");
        let state_path = dir.path().join(".bab-local");
        let state = SessionState::new(&state_path);
        let transport =
            SshTransport::with_bins(TransportMode::Tailscale, &nonexistent_ssh, &nonexistent_ssh);
        let runner = SetupRunner::new(&transport, Some(&state));

        for &role in ServerRole::all() {
            let cfg = sample_config(role, "ubuntu", true);
            let mut seen_steps = Vec::new();
            let reports = runner.run_all(&cfg, |r| seen_steps.push(r.step))?;

            assert_eq!(reports.len(), 6);
            assert_eq!(seen_steps, SetupStepKind::all());
            for report in &reports {
                assert!(report.success);
                assert!(report.dry_run);
                assert!(report.output.contains("set -euo pipefail"));
                assert_bash_syntax_ok(&report.output, &format!("dry-{}-{:?}", role, report.step));
            }
            assert!(reports[3].output.contains("sudo bash -s"));
            assert_eq!(state.server_role()?, None);
        }

        Ok(())
    }

    #[test]
    fn mock_ssh_executes_all_6_steps_and_records_server_role() -> Result<()> {
        for &role in ServerRole::all() {
            let dir = tempdir()?;
            let log_file = dir.path().join("ssh_calls.log");
            let mock_ssh = write_mock_ssh(dir.path(), &log_file)?;

            let state_path = dir.path().join(".bab-local");
            let state = SessionState::new(&state_path);
            let transport =
                SshTransport::with_bins(TransportMode::Tailscale, &mock_ssh, &mock_ssh);
            let runner = SetupRunner::new(&transport, Some(&state));

            let cfg = sample_config(role, "root", false);
            let mut progressed = Vec::new();
            let reports = runner.run_all(&cfg, |r| progressed.push((r.step, r.success)))?;

            assert_eq!(reports.len(), 6);
            assert_eq!(progressed.len(), 6);
            for (idx, report) in reports.iter().enumerate() {
                assert_eq!(report.step, SetupStepKind::all()[idx]);
                assert!(report.success);
                assert!(!report.dry_run);
                assert!(report.output.contains("MOCK_SSH_OK"));
            }

            let log_content = fs::read_to_string(&log_file)?;
            let call_count = log_content.lines().filter(|l| l.starts_with("CALL:")).count();
            assert_eq!(call_count, 6);
            assert!(log_content.contains("root@100.64.0.50"));

            assert_eq!(state.server_role()?, Some(role.to_string()));
        }

        Ok(())
    }

    #[test]
    fn mock_ssh_stops_on_failure_and_does_not_record_role() -> Result<()> {
        let dir = tempdir()?;
        let mock_ssh = dir.path().join("failing_ssh");
        let counter_file = dir.path().join("count");
        {
            let mut f = File::create(&mock_ssh)?;
            writeln!(f, "#!/usr/bin/env bash")?;
            writeln!(f, "c=0")?;
            writeln!(f, "[ -f \"{0}\" ] && c=$(cat \"{0}\")", counter_file.display())?;
            writeln!(f, "c=$((c + 1))")?;
            writeln!(f, "echo \"$c\" > \"{}\"", counter_file.display())?;
            writeln!(f, "if [ \"$c\" -eq 2 ]; then echo 'user error' >&2; exit 42; fi")?;
            writeln!(f, "echo 'ok'")?;
        }
        fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755))?;

        let state = SessionState::new(dir.path().join(".bab-local"));
        let transport =
            SshTransport::with_bins(TransportMode::Tailscale, &mock_ssh, &mock_ssh);
        let runner = SetupRunner::new(&transport, Some(&state));

        let cfg = sample_config(ServerRole::VpnWireguard, "root", false);
        let mut seen = Vec::new();
        let res = runner.run_all(&cfg, |r| seen.push((r.step, r.success)));
        assert!(res.is_err());
        assert_eq!(
            seen,
            vec![
                (SetupStepKind::SystemUpdate, true),
                (SetupStepKind::CreateUser, false),
            ]
        );
        assert_eq!(state.server_role()?, None);
        Ok(())
    }

    #[test]
    fn normalize_github_repo_accepts_valid_and_rejects_unsafe() -> Result<()> {
        assert_eq!(
            normalize_github_repo("  octocat/hello-world  ")?,
            (
                "https://github.com/octocat/hello-world.git".to_string(),
                "hello-world".to_string()
            )
        );
        assert_eq!(
            normalize_github_repo("octocat/hello-world.git")?,
            (
                "https://github.com/octocat/hello-world.git".to_string(),
                "hello-world".to_string()
            )
        );
        assert_eq!(
            normalize_github_repo("https://github.com/octocat/hello-world.git")?,
            (
                "https://github.com/octocat/hello-world.git".to_string(),
                "hello-world".to_string()
            )
        );
        assert_eq!(
            normalize_github_repo("https://github.com/octocat/hello-world/")?,
            (
                "https://github.com/octocat/hello-world".to_string(),
                "hello-world".to_string()
            )
        );
        assert_eq!(
            normalize_github_repo("git@github.com:octocat/hello-world.git")?,
            (
                "git@github.com:octocat/hello-world.git".to_string(),
                "hello-world".to_string()
            )
        );

        for bad in [
            "",
            "   ",
            "owner/repo with space",
            "owner/../other",
            "owner/repo;rm -rf /",
            "owner/repo&id",
            "owner/repo|cat",
            "owner/repo$HOME",
            "owner/repo`id`",
            "owner/repo<in",
            "owner/repo>out",
            "owner/repo'q",
            "owner/repo\"q",
            "just-repo",
            "http://github.com/owner/repo",
            "https://github.com/",
            "git@github.com",
        ] {
            assert!(
                normalize_github_repo(bad).is_err(),
                "expected error for '{}'",
                bad
            );
        }
        Ok(())
    }

    #[test]
    fn build_github_deploy_script_token_askpass_and_defaults() -> Result<()> {
        let cfg = GithubDeployConfig {
            repo: "acme/web-app".to_string(),
            branch: "".to_string(),
            deploy_path: None,
            deploy_cmd: None,
            github_token: Some("ghp_secretToken123".to_string()),
            username: "deploy".to_string(),
            ..Default::default()
        };

        let script = build_github_deploy_script(&cfg)?;
        assert_bash_syntax_ok(&script, "github-deploy-token-defaults");
        assert!(script.starts_with("#!/usr/bin/env bash\nset -euo pipefail\n"));
        assert!(script.contains("REPO_URL='https://github.com/acme/web-app.git'"));
        assert!(script.contains("BRANCH='main'"));
        assert!(script.contains("DEPLOY_USER='deploy'"));
        assert!(script.contains("DEPLOY_PATH='/home/deploy/apps/web-app'"));
        assert!(script.contains("mktemp /tmp/bab-git-askpass.XXXXXX"));
        assert!(script.contains("trap 'rm -f \"${GIT_ASKPASS_SCRIPT}\"' EXIT"));
        assert!(script.contains("chmod 0700 \"${GIT_ASKPASS_SCRIPT}\""));
        assert!(script.contains("x-access-token"));
        assert!(script.contains("${BAB_GITHUB_TOKEN}"));
        assert!(!script.contains("https://ghp_secretToken123"));
        assert!(!script.contains("x-access-token:ghp_secretToken123@"));
        assert!(script.contains("docker compose up -d --build"));
        assert!(script.contains("docker-compose.yml"));
        assert!(script.contains("compose.yaml"));
        Ok(())
    }

    #[test]
    fn build_github_deploy_script_no_token_and_custom_cmd() -> Result<()> {
        let cfg = GithubDeployConfig {
            repo: "https://github.com/acme/api-service.git".to_string(),
            branch: "production".to_string(),
            deploy_path: Some("/opt/api-service".to_string()),
            deploy_cmd: Some("make build && systemctl restart api".to_string()),
            github_token: None,
            username: "deploy".to_string(),
            ..Default::default()
        };

        let script = build_github_deploy_script(&cfg)?;
        assert_bash_syntax_ok(&script, "github-deploy-no-token-custom-cmd");
        assert!(script.contains("BRANCH='production'"));
        assert!(script.contains("DEPLOY_PATH='/opt/api-service'"));
        assert!(script.contains("DEPLOY_CMD='make build && systemctl restart api'"));
        assert!(script.contains("bash -lc \"${DEPLOY_CMD}\""));
        assert!(!script.contains("GIT_ASKPASS"));
        assert!(!script.contains("BAB_GITHUB_TOKEN"));
        assert!(!script.contains("docker compose up -d --build"));
        Ok(())
    }

    #[test]
    fn configure_role_appends_github_deploy_when_configured() {
        let gh = GithubDeployConfig {
            repo: "acme/stack".to_string(),
            branch: "main".to_string(),
            deploy_path: None,
            deploy_cmd: None,
            github_token: Some("ghp_tok".to_string()),
            username: "deploy".to_string(),
            ..Default::default()
        };

        let mut root_cfg = sample_config(ServerRole::ReverseProxyCaddy, "root", false);
        root_cfg.github_deploy = Some(gh.clone());
        let root_script = build_step_script(SetupStepKind::ConfigureRole, &root_cfg);
        assert_bash_syntax_ok(&root_script, "configure-role-with-github-root");
        assert!(root_script.contains("caddy"));
        assert!(root_script.contains("REPO_URL='https://github.com/acme/stack.git'"));
        assert!(root_script.contains("GIT_ASKPASS_SCRIPT"));

        let mut sudo_cfg = sample_config(ServerRole::Vanilla, "ubuntu", false);
        sudo_cfg.github_deploy = Some(gh);
        let sudo_script = build_step_script(SetupStepKind::ConfigureRole, &sudo_cfg);
        assert_bash_syntax_ok(&sudo_script, "configure-role-with-github-sudo");
        assert!(sudo_script.contains("sudo bash -s << 'BAB_STEP_EOF'"));
        assert!(sudo_script.contains("REPO_URL='https://github.com/acme/stack.git'"));
    }

    #[test]
    fn runner_deploy_github_supports_dry_run_and_exec() -> Result<()> {
        let dir = tempdir()?;
        let log_file = dir.path().join("ssh_calls.log");
        let mock_ssh = write_mock_ssh(dir.path(), &log_file)?;

        let transport = SshTransport::with_bins(TransportMode::Tailscale, &mock_ssh, &mock_ssh);
        let runner = SetupRunner::new(&transport, None);

        let gh = GithubDeployConfig {
            repo: "acme/demo".to_string(),
            branch: "main".to_string(),
            deploy_path: None,
            deploy_cmd: Some("echo deployed".to_string()),
            github_token: None,
            username: "deploy".to_string(),
            ..Default::default()
        };

        let dry_sudo = runner.deploy_github("ubuntu", "100.64.0.50", &gh, true)?;
        assert_bash_syntax_ok(&dry_sudo, "deploy-github-dry-sudo");
        assert!(dry_sudo.contains("sudo bash -s << 'BAB_STEP_EOF'"));
        assert!(!log_file.exists());

        let dry_root = runner.deploy_github("root", "100.64.0.50", &gh, true)?;
        assert_bash_syntax_ok(&dry_root, "deploy-github-dry-root");
        assert!(!dry_root.contains("sudo bash -s"));

        let out = runner.deploy_github("root", "100.64.0.50", &gh, false)?;
        assert!(out.contains("MOCK_SSH_OK"));
        let log_content = fs::read_to_string(&log_file)?;
        assert!(log_content.contains("root@100.64.0.50"));
        Ok(())
    }

    #[test]
    fn create_user_guards_against_self_copy_authorized_keys() {
        let mut cfg = sample_config(ServerRole::Vanilla, "deploy", false);
        cfg.new_username = "deploy".to_string();
        let script = build_step_script(SetupStepKind::CreateUser, &cfg);
        assert_bash_syntax_ok(&script, "create-user-self-copy-guard");
        assert!(script.contains(
            r#"elif [ "${SSH_USER}" != "root" ] && [ "${SSH_USER}" != "${NEW_USER}" ] && [ -s "/home/${SSH_USER}/.ssh/authorized_keys" ]; then"#
        ));
    }

    #[test]
    fn mock_ssh_falls_back_from_root_to_new_username_on_tailscale_policy_denial() -> Result<()> {
        let dir = tempdir()?;
        let log_file = dir.path().join("ssh_calls.log");
        let mock_ssh = dir.path().join("policy_denying_ssh");
        {
            let mut f = File::create(&mock_ssh)?;
            writeln!(f, "#!/usr/bin/env bash")?;
            writeln!(f, "set -euo pipefail")?;
            writeln!(f, "SCRIPT=\"${{!#}}\"")?;
            writeln!(f, "TARGET=\"\"")?;
            writeln!(f, "for arg in \"$@\"; do case \"$arg\" in *@*) TARGET=\"$arg\" ;; esac; done")?;
            writeln!(
                f,
                "HAS_SUDO=no; if printf '%s' \"$SCRIPT\" | grep -q 'sudo bash -s'; then HAS_SUDO=yes; fi"
            )?;
            writeln!(
                f,
                "printf 'CALL:%s|SUDO:%s\\n' \"$TARGET\" \"$HAS_SUDO\" >> \"{}\"",
                log_file.display()
            )?;
            writeln!(
                f,
                "if [ \"$TARGET\" = 'root@100.64.0.50' ]; then"
            )?;
            writeln!(
                f,
                "    echo 'tailnet policy does not permit you to SSH as root' >&2"
            )?;
            writeln!(f, "    exit 255")?;
            writeln!(f, "fi")?;
            writeln!(f, "echo 'FALLBACK_OK'")?;
        }
        fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755))?;

        let state_path = dir.path().join(".bab-local");
        let state = SessionState::new(&state_path);
        let transport = SshTransport::with_bins(TransportMode::Tailscale, &mock_ssh, &mock_ssh);
        let runner = SetupRunner::new(&transport, Some(&state));

        let mut cfg = sample_config(ServerRole::Vanilla, "root", false);
        cfg.new_username = "  deploy  ".to_string();
        let mut progressed = Vec::new();
        let reports = runner.run_all(&cfg, |r| progressed.push((r.step, r.success)))?;

        assert_eq!(reports.len(), 6);
        assert_eq!(progressed.len(), 6);
        for (idx, report) in reports.iter().enumerate() {
            assert_eq!(report.step, SetupStepKind::all()[idx]);
            assert!(report.success);
            assert!(!report.dry_run);
            assert_eq!(report.output.trim(), "FALLBACK_OK");
        }

        let log_content = fs::read_to_string(&log_file)?;
        let lines: Vec<&str> = log_content.lines().collect();
        assert_eq!(lines.len(), 7);
        assert!(lines[0].contains("root@100.64.0.50") && lines[0].ends_with("|SUDO:no"));
        for line in &lines[1..] {
            assert!(line.contains("deploy@100.64.0.50") && line.ends_with("|SUDO:yes"));
        }

        assert_eq!(state.server_role()?, Some(ServerRole::Vanilla.to_string()));
        Ok(())
    }

    #[test]
    fn mock_ssh_deploy_github_falls_back_from_root_to_deploy_user() -> Result<()> {
        for denial_msg in [
            "tailnet policy does not permit you to SSH as root",
            "Permission denied (publickey).",
        ] {
            let dir = tempdir()?;
            let log_file = dir.path().join("ssh_calls.log");
            let mock_ssh = dir.path().join("policy_denying_ssh");
            {
                let mut f = File::create(&mock_ssh)?;
                writeln!(f, "#!/usr/bin/env bash")?;
                writeln!(f, "set -euo pipefail")?;
                writeln!(f, "SCRIPT=\"${{!#}}\"")?;
                writeln!(f, "TARGET=\"\"")?;
                writeln!(f, "for arg in \"$@\"; do case \"$arg\" in *@*) TARGET=\"$arg\" ;; esac; done")?;
                writeln!(
                    f,
                    "HAS_SUDO=no; if printf '%s' \"$SCRIPT\" | grep -q 'sudo bash -s'; then HAS_SUDO=yes; fi"
                )?;
                writeln!(
                    f,
                    "printf 'CALL:%s|SUDO:%s\\n' \"$TARGET\" \"$HAS_SUDO\" >> \"{}\"",
                    log_file.display()
                )?;
                writeln!(
                    f,
                    "if [ \"$TARGET\" = 'root@100.64.0.50' ]; then"
                )?;
                writeln!(f, "    echo '{}' >&2", denial_msg)?;
                writeln!(f, "    exit 255")?;
                writeln!(f, "fi")?;
                writeln!(f, "echo 'DEPLOY_FALLBACK_OK'")?;
            }
            fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755))?;

            let transport =
                SshTransport::with_bins(TransportMode::Tailscale, &mock_ssh, &mock_ssh);
            let runner = SetupRunner::new(&transport, None);

            let gh = GithubDeployConfig {
                repo: "acme/demo".to_string(),
                branch: "main".to_string(),
                deploy_path: None,
                deploy_cmd: Some("echo deployed".to_string()),
                github_token: None,
                username: " deploy ".to_string(),
                ..Default::default()
            };

            let out = runner.deploy_github("root", "100.64.0.50", &gh, false)?;
            assert_eq!(out.trim(), "DEPLOY_FALLBACK_OK");

            let log_content = fs::read_to_string(&log_file)?;
            let lines: Vec<&str> = log_content.lines().collect();
            assert_eq!(lines.len(), 2);
            assert!(lines[0].contains("root@100.64.0.50") && lines[0].ends_with("|SUDO:no"));
            assert!(lines[1].contains("deploy@100.64.0.50") && lines[1].ends_with("|SUDO:yes"));
        }
        Ok(())
    }

    #[test]
    fn create_user_respects_sudo_nopasswd_true_and_false() {
        let mut cfg_true = sample_config(ServerRole::Vanilla, "root", false);
        cfg_true.sudo_nopasswd = true;
        let script_true = build_step_script(SetupStepKind::CreateUser, &cfg_true);
        assert_bash_syntax_ok(&script_true, "create-user-sudo-nopasswd-true");
        assert!(script_true.contains("usermod -aG \"${SUDO_GRP}\" \"${NEW_USER}\""));
        assert!(script_true.contains("echo \"${NEW_USER} ALL=(ALL) NOPASSWD:ALL\" > \"/etc/sudoers.d/${NEW_USER}\""));
        assert!(script_true.contains("chmod 440 \"/etc/sudoers.d/${NEW_USER}\""));

        let mut cfg_false = sample_config(ServerRole::Vanilla, "root", false);
        cfg_false.sudo_nopasswd = false;
        let script_false = build_step_script(SetupStepKind::CreateUser, &cfg_false);
        assert_bash_syntax_ok(&script_false, "create-user-sudo-nopasswd-false");
        assert!(!script_false.contains("NOPASSWD:ALL"));
        assert!(script_false.contains("usermod -aG \"${SUDO_GRP}\" \"${NEW_USER}\""));
        assert!(script_false.contains("if [ \"${SSH_USER}\" = \"root\" ]; then"));
        assert!(script_false.contains("rm -f \"/etc/sudoers.d/${NEW_USER}\""));
    }

    #[test]
    fn configure_motd_cleans_up_sudoers_only_when_sudo_nopasswd_false() {
        for ssh_user in ["root", "ubuntu"] {
            let mut cfg_true = sample_config(ServerRole::Vanilla, ssh_user, false);
            cfg_true.sudo_nopasswd = true;
            let script_true = build_step_script(SetupStepKind::ConfigureMotd, &cfg_true);
            assert_bash_syntax_ok(&script_true, &format!("motd-sudo-nopasswd-true-{ssh_user}"));
            assert!(!script_true.contains("/etc/sudoers.d/"));

            let mut cfg_false = sample_config(ServerRole::Vanilla, ssh_user, false);
            cfg_false.sudo_nopasswd = false;
            let script_false = build_step_script(SetupStepKind::ConfigureMotd, &cfg_false);
            assert_bash_syntax_ok(&script_false, &format!("motd-sudo-nopasswd-false-{ssh_user}"));
            assert!(script_false.contains("NEW_USER='deploy'"));
            assert!(script_false.contains("rm -f \"/etc/sudoers.d/${NEW_USER}\""));
        }
    }

    #[test]
    fn create_user_sets_sudo_password_with_chpasswd_when_configured() {
        let mut cfg_pw = sample_config(ServerRole::Vanilla, "root", false);
        cfg_pw.sudo_password = Some("  s3cr'et$(pw)  ".to_string());
        let script_pw = build_step_script(SetupStepKind::CreateUser, &cfg_pw);
        assert_bash_syntax_ok(&script_pw, "create-user-sudo-password");
        assert!(script_pw.contains("SUDO_PASSWORD='s3cr'\\''et$(pw)'"));
        assert!(script_pw.contains("if [ -n \"${SUDO_PASSWORD}\" ]; then"));
        assert!(script_pw.contains("printf '%s:%s\\n' \"${NEW_USER}\" \"${SUDO_PASSWORD}\" | chpasswd"));

        let cfg_none = sample_config(ServerRole::Vanilla, "root", false);
        let script_none = build_step_script(SetupStepKind::CreateUser, &cfg_none);
        assert_bash_syntax_ok(&script_none, "create-user-sudo-password-none");
        assert!(script_none.contains("SUDO_PASSWORD=''"));

        let mut cfg_blank = sample_config(ServerRole::Vanilla, "root", false);
        cfg_blank.sudo_password = Some("   \t ".to_string());
        let script_blank = build_step_script(SetupStepKind::CreateUser, &cfg_blank);
        assert_bash_syntax_ok(&script_blank, "create-user-sudo-password-blank");
        assert!(script_blank.contains("SUDO_PASSWORD=''"));
    }

    #[test]
    fn run_all_with_callbacks_fires_on_start_before_on_done_for_each_step() -> Result<()> {
        let dir = tempdir()?;
        let log_file = dir.path().join("ssh_calls.log");
        let mock_ssh = write_mock_ssh(dir.path(), &log_file)?;
        let transport = SshTransport::with_bins(TransportMode::Tailscale, &mock_ssh, &mock_ssh);
        let runner = SetupRunner::new(&transport, None);

        for dry_run in [true, false] {
            let cfg = sample_config(ServerRole::Vanilla, "root", dry_run);
            let events = std::cell::RefCell::new(Vec::new());
            let reports = runner.run_all_with_callbacks(
                &cfg,
                |idx, total, step| {
                    events
                        .borrow_mut()
                        .push(format!("start:{}:{}:{:?}", idx, total, step));
                },
                |report| {
                    events
                        .borrow_mut()
                        .push(format!("done:{:?}:{}", report.step, report.success));
                },
            )?;
            assert_eq!(reports.len(), 6);
            let expected: Vec<String> = SetupStepKind::all()
                .iter()
                .enumerate()
                .flat_map(|(idx, step)| {
                    [
                        format!("start:{}:6:{:?}", idx, step),
                        format!("done:{:?}:true", step),
                    ]
                })
                .collect();
            assert_eq!(*events.borrow(), expected);
        }

        Ok(())
    }

    #[test]
    fn create_user_supports_mixed_case_usernames_and_guards_chpasswd_and_chown() {
        for ssh_user in ["root", "ubuntu"] {
            let mut cfg = sample_config(ServerRole::Vanilla, ssh_user, false);
            cfg.new_username = "Goobey".to_string();
            cfg.sudo_password = Some("S3cr'et!".to_string());
            let script = build_step_script(SetupStepKind::CreateUser, &cfg);
            assert_bash_syntax_ok(&script, &format!("create-user-mixed-case-{ssh_user}"));
            assert!(script.contains("NEW_USER='Goobey'"));
            assert!(script.contains(
                "adduser --disabled-password --gecos \"\" \"${NEW_USER}\" 2>/dev/null || adduser --disabled-password --allow-bad-names --gecos \"\" \"${NEW_USER}\" 2>/dev/null || adduser --disabled-password --force-badname --gecos \"\" \"${NEW_USER}\" 2>/dev/null || useradd --badname -m -s /bin/bash \"${NEW_USER}\" 2>/dev/null || useradd -m -s /bin/bash \"${NEW_USER}\""
            ));
            assert!(script.contains(
                "useradd -m -s /bin/bash \"${NEW_USER}\" 2>/dev/null || useradd --badname -m -s /bin/bash \"${NEW_USER}\""
            ));
            assert!(script.contains("if [ -n \"${SUDO_PASSWORD}\" ]; then"));
            assert!(script.contains("if id -u \"${NEW_USER}\" >/dev/null 2>&1; then"));
            assert!(script.contains(
                "printf '%s:%s\\n' \"${NEW_USER}\" \"${SUDO_PASSWORD}\" | chpasswd || true"
            ));
            assert!(script.contains(
                "chown -R \"${NEW_USER}:${NEW_USER}\" \"${SSH_DIR}\" 2>/dev/null || chown -R \"${NEW_USER}\" \"${SSH_DIR}\" || true"
            ));
            assert!(script.contains(
                "chown -R \"${NEW_USER}:${NEW_USER}\" \"/home/${NEW_USER}/apps\" 2>/dev/null || chown -R \"${NEW_USER}\" \"/home/${NEW_USER}/apps\" || true"
            ));
        }
    }

    #[derive(Debug, Clone)]
    struct RecordedGithubRequest {
        method: String,
        path: String,
        authorization: Option<String>,
        user_agent: Option<String>,
        accept: Option<String>,
    }

    struct MockGithubResponse {
        status: u16,
        reason: &'static str,
        body: String,
    }

    impl MockGithubResponse {
        fn json(status: u16, reason: &'static str, body: impl Into<String>) -> Self {
            Self {
                status,
                reason,
                body: body.into(),
            }
        }
    }

    struct GithubEnvGuard {
        key: &'static str,
        original: Option<std::ffi::OsString>,
    }

    impl GithubEnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = env::var_os(key);
            env::set_var(key, value);
            Self { key, original }
        }
    }

    impl Drop for GithubEnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(val) => env::set_var(self.key, val),
                None => env::remove_var(self.key),
            }
        }
    }

    fn spawn_github_mock_server(
        responses: Vec<MockGithubResponse>,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<RecordedGithubRequest>>>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{BufRead, BufReader};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock github server");
        let addr = listener.local_addr().expect("local addr");
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let recorded_clone = Arc::clone(&recorded);

        let handle = thread::spawn(move || {
            for resp in responses {
                let (mut stream, _) = listener.accept().expect("accept connection");
                let mut reader = BufReader::new(&stream);

                let mut request_line = String::new();
                reader.read_line(&mut request_line).expect("read request line");
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();

                let mut authorization = None;
                let mut user_agent = None;
                let mut accept = None;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).expect("read header line");
                    let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((name, val)) = trimmed.split_once(':') {
                        let name_lower = name.trim().to_ascii_lowercase();
                        let val_trimmed = val.trim().to_string();
                        if name_lower == "authorization" {
                            authorization = Some(val_trimmed);
                        } else if name_lower == "user-agent" {
                            user_agent = Some(val_trimmed);
                        } else if name_lower == "accept" {
                            accept = Some(val_trimmed);
                        }
                    }
                }

                recorded_clone.lock().unwrap().push(RecordedGithubRequest {
                    method,
                    path,
                    authorization,
                    user_agent,
                    accept,
                });

                let http_resp = format!(
                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp.status,
                    resp.reason,
                    resp.body.len(),
                    resp.body
                );
                stream
                    .write_all(http_resp.as_bytes())
                    .expect("write response");
                stream.flush().expect("flush response");
            }
        });

        (format!("http://{}", addr), recorded, handle)
    }

    #[test]
    fn validate_github_token_returns_false_for_empty_or_whitespace_token() {
        assert!(!validate_github_token_with_base("", "http://127.0.0.1:1").unwrap());
        assert!(!validate_github_token_with_base("  \t\n ", "http://127.0.0.1:1").unwrap());
    }

    #[test]
    fn validate_github_token_with_base_returns_true_on_200_and_sends_expected_headers() {
        let (base_url, recorded, handle) = spawn_github_mock_server(vec![MockGithubResponse::json(
            200,
            "OK",
            r#"{"login":"octocat"}"#,
        )]);

        assert!(validate_github_token_with_base("  ghp_valid_token \n", &base_url).unwrap());

        handle.join().expect("mock server thread");
        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].path, "/user");
        assert_eq!(
            reqs[0].authorization.as_deref(),
            Some("Bearer ghp_valid_token")
        );
        assert_eq!(reqs[0].user_agent.as_deref(), Some("bab/0.1"));
        assert_eq!(
            reqs[0].accept.as_deref(),
            Some("application/vnd.github+json")
        );
    }

    #[test]
    fn validate_github_token_with_base_returns_false_on_401_and_403() {
        let (base_url, recorded, handle) = spawn_github_mock_server(vec![
            MockGithubResponse::json(401, "Unauthorized", r#"{"message":"Bad credentials"}"#),
            MockGithubResponse::json(403, "Forbidden", r#"{"message":"Forbidden"}"#),
        ]);

        assert!(!validate_github_token_with_base("ghp_bad", &base_url).unwrap());
        assert!(!validate_github_token_with_base("ghp_forbidden", &base_url).unwrap());

        handle.join().expect("mock server thread");
        assert_eq!(recorded.lock().unwrap().len(), 2);
    }

    #[test]
    fn validate_github_token_with_base_errors_on_500() {
        let (base_url, recorded, handle) = spawn_github_mock_server(vec![MockGithubResponse::json(
            500,
            "Internal Server Error",
            r#"{"message":"github outage"}"#,
        )]);

        let err = validate_github_token_with_base("ghp_token", &base_url).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Unexpected status 500"), "unexpected error: {msg}");
        assert!(msg.contains("github outage"), "unexpected error: {msg}");

        handle.join().expect("mock server thread");
        assert_eq!(recorded.lock().unwrap().len(), 1);
    }

    #[test]
    fn validate_github_token_honors_github_api_base_env() {
        let _lock = crate::env_lock();
        let (base_url, recorded, handle) = spawn_github_mock_server(vec![MockGithubResponse::json(
            200,
            "OK",
            r#"{"login":"octocat"}"#,
        )]);
        let _env = GithubEnvGuard::set("GITHUB_API_BASE", &format!("{base_url}/"));

        assert!(validate_github_token("ghp_env_token").unwrap());

        handle.join().expect("mock server thread");
        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].path, "/user");
        assert_eq!(reqs[0].authorization.as_deref(), Some("Bearer ghp_env_token"));
        assert_eq!(reqs[0].user_agent.as_deref(), Some("bab/0.1"));
        assert_eq!(
            reqs[0].accept.as_deref(),
            Some("application/vnd.github+json")
        );
    }

    #[test]
    fn build_github_deploy_script_injects_caddy_labels_override() -> Result<()> {
        let cfg = GithubDeployConfig {
            repo: "acme/web-app".to_string(),
            branch: "main".to_string(),
            deploy_path: None,
            deploy_cmd: None,
            github_token: None,
            username: "deploy".to_string(),
            caddy_labels: true,
            caddy_domain: Some("app.example.com".to_string()),
            caddy_service: Some("web".to_string()),
            caddy_port: Some("3000".to_string()),
            caddy_extra_labels: Some("caddy.encode=gzip; caddy.tls=internal".to_string()),
        };

        let script = build_github_deploy_script(&cfg)?;
        assert_bash_syntax_ok(&script, "github-deploy-caddy-labels");
        assert!(script.contains("docker network create caddy"));
        assert!(script.contains("CADDY_SERVICE='web'"));
        assert!(script.contains("caddy: 'app.example.com'"));
        assert!(script.contains("caddy.reverse_proxy: '{{upstreams 3000}}'"));
        assert!(script.contains("caddy.encode: 'gzip'"));
        assert!(script.contains("caddy.tls: 'internal'"));
        assert!(script.contains("docker compose -f \"${COMPOSE_FILE}\" -f \"${CADDY_OVERRIDE_FILE}\" up -d --build"));

        let auto_svc_cfg = GithubDeployConfig {
            caddy_service: None,
            caddy_port: None,
            caddy_extra_labels: None,
            ..cfg.clone()
        };
        let auto_script = build_github_deploy_script(&auto_svc_cfg)?;
        assert_bash_syntax_ok(&auto_script, "github-deploy-caddy-labels-auto-svc");
        assert!(auto_script.contains("config --services"));
        assert!(auto_script.contains("caddy.reverse_proxy: '{{upstreams 8080}}'"));

        let missing_domain = GithubDeployConfig {
            caddy_domain: None,
            ..cfg.clone()
        };
        assert!(build_github_deploy_script(&missing_domain).is_err());

        let bad_port = GithubDeployConfig {
            caddy_port: Some("99999".to_string()),
            ..cfg
        };
        assert!(build_github_deploy_script(&bad_port).is_err());
        Ok(())
    }
}
