use anyhow::{anyhow, Result};

use crate::config::SessionState;
use crate::roles::ServerRole;
use crate::transport::SshTransport;

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
            let distro = distro_detect_block();
            let body = format!(
                r#"{distro}

NEW_USER={quoted_new_user}
SSH_USER={quoted_ssh_user}
SSH_PUBKEY={quoted_ssh_pubkey}

case "${{DISTRO_FAMILY}}" in
    debian) SUDO_GRP="sudo" ;;
    rhel)   SUDO_GRP="wheel" ;;
esac

if ! id "${{NEW_USER}}" >/dev/null 2>&1; then
    case "${{DISTRO_FAMILY}}" in
        debian)
            adduser --disabled-password --gecos "" "${{NEW_USER}}"
            ;;
        rhel)
            useradd -m -s /bin/bash "${{NEW_USER}}"
            ;;
    esac
fi

if ! id -nG "${{NEW_USER}}" | grep -qw "${{SUDO_GRP}}"; then
    usermod -aG "${{SUDO_GRP}}" "${{NEW_USER}}"
fi

if [ ! -f "/etc/sudoers.d/${{NEW_USER}}" ]; then
    echo "${{NEW_USER}} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${{NEW_USER}}"
    chmod 440 "/etc/sudoers.d/${{NEW_USER}}"
fi

SSH_DIR="/home/${{NEW_USER}}/.ssh"
AUTH_KEYS="${{SSH_DIR}}/authorized_keys"
mkdir -p "${{SSH_DIR}}"
if [ -s /root/.ssh/authorized_keys ]; then
    cp /root/.ssh/authorized_keys "${{AUTH_KEYS}}"
elif [ "${{SSH_USER}}" != "root" ] && [ -s "/home/${{SSH_USER}}/.ssh/authorized_keys" ]; then
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
chown -R "${{NEW_USER}}:${{NEW_USER}}" "${{SSH_DIR}}"
chmod 700 "${{SSH_DIR}}"
chmod 600 "${{AUTH_KEYS}}"

mkdir -p "/home/${{NEW_USER}}/apps"
chown -R "${{NEW_USER}}:${{NEW_USER}}" "/home/${{NEW_USER}}/apps""#
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
            let role_script = cfg.role.role_setup_script(&cfg.new_username, cfg.tailscale_mode);
            if cfg.ssh_user == "root" {
                role_script
            } else {
                let inner = role_script
                    .strip_prefix("#!/usr/bin/env bash\n")
                    .unwrap_or(&role_script);
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
esac"##
            );
            wrap_root_script(&cfg.ssh_user, &body)
        }
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
    pub fn run_all<F>(&self, cfg: &SetupConfig, mut on_progress: F) -> Result<Vec<StepReport>>
    where
        F: FnMut(&StepReport),
    {
        let mut reports = Vec::with_capacity(SetupStepKind::all().len());

        for &step in SetupStepKind::all() {
            let script = build_step_script(step, cfg);
            if cfg.dry_run {
                let report = StepReport {
                    step,
                    success: true,
                    dry_run: true,
                    output: script,
                };
                on_progress(&report);
                reports.push(report);
                continue;
            }

            let out = self.transport.exec(&cfg.ssh_user, &cfg.host, &script)?;
            let success = out.success();
            let status_code = out.status_code;
            let combined_output = match (out.stdout.trim(), out.stderr.trim()) {
                ("", "") => String::new(),
                (_, "") => out.stdout,
                ("", _) => out.stderr,
                _ => format!("{}\n{}", out.stdout.trim_end(), out.stderr.trim_end()),
            };
            let report = StepReport {
                step,
                success,
                dry_run: false,
                output: combined_output.clone(),
            };
            on_progress(&report);
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
}
