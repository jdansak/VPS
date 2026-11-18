use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Supported VPS server role profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerRole {
    Vanilla,
    ReverseProxyCaddy,
    VpnWireguard,
    RemoteBrowserIsolation,
}

impl fmt::Display for ServerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerRole::Vanilla => f.write_str("vanilla"),
            ServerRole::ReverseProxyCaddy => f.write_str("caddy"),
            ServerRole::VpnWireguard => f.write_str("wireguard"),
            ServerRole::RemoteBrowserIsolation => f.write_str("rbi"),
        }
    }
}

impl FromStr for ServerRole {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "vanilla" | "plain" | "base" | "minimal" => Ok(ServerRole::Vanilla),
            "caddy" | "reverseproxy" | "reverse-proxy" | "reverse_proxy" => {
                Ok(ServerRole::ReverseProxyCaddy)
            }
            "wireguard" | "vpn" => Ok(ServerRole::VpnWireguard),
            "rbi" | "remote-browser-isolation" | "remote_browser_isolation" => {
                Ok(ServerRole::RemoteBrowserIsolation)
            }
            _ => Err(anyhow::anyhow!("unknown server role: '{}'", s)),
        }
    }
}

impl ServerRole {
    /// Returns all available server roles in display order.
    pub fn all() -> &'static [ServerRole] {
        &[
            ServerRole::Vanilla,
            ServerRole::ReverseProxyCaddy,
            ServerRole::VpnWireguard,
            ServerRole::RemoteBrowserIsolation,
        ]
    }

    /// Human-readable label for menus and summaries.
    pub fn label(&self) -> &'static str {
        match self {
            ServerRole::Vanilla => "Vanilla (Plain Hardened OS)",
            ServerRole::ReverseProxyCaddy => "ReverseProxy (Caddy)",
            ServerRole::VpnWireguard => "VPN Server (WireGuard)",
            ServerRole::RemoteBrowserIsolation => "Remote Browser Isolation (Build Later)",
        }
    }

    /// Short description of what the role configures.
    pub fn description(&self) -> &'static str {
        match self {
            ServerRole::Vanilla => {
                "Plain hardened base OS with updates, sudo user, firewall, Fail2ban, and unattended security upgrades"
            }
            ServerRole::ReverseProxyCaddy => {
                "Docker Engine with log rotation, caddy-docker-proxy label-driven reverse proxy, and firewall isolation via UFW/docker networking."
            }
            ServerRole::VpnWireguard => {
                "WireGuard VPN server (10.66.66.0/24 on UDP 51820) with IPv4/IPv6 forwarding, NAT masquerading, and client1 profile."
            }
            ServerRole::RemoteBrowserIsolation => {
                "Base hardened host profile reserved for future Remote Browser Isolation implementation"
            }
        }
    }

    /// Ports/protocols opened by this role for the selected transport mode.
    pub fn open_ports_for_mode(&self, tailscale_mode: bool) -> Vec<&'static str> {
        let access_port = if tailscale_mode {
            "41641/udp (Tailscale)"
        } else {
            "22/tcp (SSH rate-limited)"
        };
        match self {
            ServerRole::Vanilla | ServerRole::RemoteBrowserIsolation => vec![access_port],
            ServerRole::ReverseProxyCaddy => {
                vec![access_port, "80/tcp (HTTP)", "443/tcp+udp (HTTPS/HTTP3)"]
            }
            ServerRole::VpnWireguard => vec![access_port, "51820/udp (WireGuard)"],
        }
    }

    /// Ports/protocols opened by this role (defaults to Tailscale mode for compatibility).
    pub fn open_ports(&self) -> Vec<&'static str> {
        self.open_ports_for_mode(true)
    }

    /// Returns `true` if this role is currently a stub profile.
    pub fn is_stub(&self) -> bool {
        matches!(self, ServerRole::RemoteBrowserIsolation)
    }

    /// Generates an idempotent bash setup script (`set -euo pipefail`) for this role.
    pub fn role_setup_script(&self, username: &str, tailscale_mode: bool) -> String {
        match self {
            ServerRole::Vanilla => build_vanilla_script(username, tailscale_mode),
            ServerRole::ReverseProxyCaddy => build_caddy_script(username, tailscale_mode),
            ServerRole::VpnWireguard => build_wireguard_script(username, tailscale_mode),
            ServerRole::RemoteBrowserIsolation => build_rbi_stub_script(username, tailscale_mode),
        }
    }
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

fn ufw_transport_rules(tailscale_mode: bool) -> &'static str {
    if tailscale_mode {
        "        ufw allow in on tailscale0\n        ufw allow 41641/udp\n        ufw delete allow 22/tcp 2>/dev/null || true\n        ufw delete limit 22/tcp 2>/dev/null || true\n        ufw delete allow OpenSSH 2>/dev/null || true"
    } else {
        "        ufw delete allow 41641/udp 2>/dev/null || true\n        ufw delete allow in on tailscale0 2>/dev/null || true\n        ufw delete allow 22/tcp 2>/dev/null || true\n        ufw limit 22/tcp"
    }
}

fn firewalld_transport_rules(tailscale_mode: bool) -> &'static str {
    if tailscale_mode {
        "        firewall-cmd --permanent --zone=trusted --add-interface=tailscale0\n        firewall-cmd --permanent --add-port=41641/udp\n        firewall-cmd --permanent --remove-service=ssh 2>/dev/null || true\n        firewall-cmd --permanent --remove-port=22/tcp 2>/dev/null || true"
    } else {
        "        firewall-cmd --permanent --zone=trusted --remove-interface=tailscale0 2>/dev/null || true\n        firewall-cmd --permanent --remove-port=41641/udp 2>/dev/null || true\n        firewall-cmd --permanent --add-service=ssh"
    }
}

fn build_vanilla_script(username: &str, tailscale_mode: bool) -> String {
    let quoted_user = shell_quote(username);
    let distro = distro_detect_block();
    let ufw_transport = ufw_transport_rules(tailscale_mode);
    let fwd_transport = firewalld_transport_rules(tailscale_mode);

    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

USERNAME={quoted_user}
TAILSCALE_MODE={tailscale_mode}

{distro}

# --- Configure Base Hardened Firewall ---
case "${{DISTRO_FAMILY}}" in
    debian)
        apt-get update
        apt-get install -y ufw
        ufw default deny incoming
        ufw default allow outgoing
{ufw_transport}
        ufw --force enable
        ufw reload >/dev/null 2>&1 || true
        ;;
    rhel)
        dnf install -y firewalld
        systemctl enable --now firewalld
{fwd_transport}
        firewall-cmd --permanent --remove-service=cockpit >/dev/null 2>&1 || true
        firewall-cmd --reload
        ;;
esac
"#
    )
}

fn build_caddy_script(username: &str, tailscale_mode: bool) -> String {
    let quoted_user = shell_quote(username);
    let distro = distro_detect_block();
    let ufw_transport = ufw_transport_rules(tailscale_mode);
    let fwd_transport = firewalld_transport_rules(tailscale_mode);

    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

USERNAME={quoted_user}
TAILSCALE_MODE={tailscale_mode}

{distro}

# --- Install Docker Engine ---
if ! command -v docker >/dev/null 2>&1; then
    case "${{DISTRO_FAMILY}}" in
        debian)
            curl -fsSL https://get.docker.com | sh
            ;;
        rhel)
            repo_os="centos"
            [ "${{DISTRO_ID}}" = "fedora" ] && repo_os="fedora"
            dnf install -y dnf-plugins-core
            dnf config-manager --add-repo "https://download.docker.com/linux/${{repo_os}}/docker-ce.repo"
            dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            systemctl enable --now docker
            ;;
    esac
fi

systemctl enable --now docker >/dev/null 2>&1 || true

if id "${{USERNAME}}" >/dev/null 2>&1; then
    usermod -aG docker "${{USERNAME}}" || true
    mkdir -p "/home/${{USERNAME}}/apps"
    chown -R "${{USERNAME}}:${{USERNAME}}" "/home/${{USERNAME}}/apps"
fi

# --- Docker log rotation and safe localhost binding ---
if [ ! -f /etc/docker/daemon.json ] || ! grep -q "max-size" /etc/docker/daemon.json 2>/dev/null; then
    mkdir -p /etc/docker
    DOCKER_DNS_LINE=""
    if ! grep -qE '^nameserver[[:space:]]+[0-9]+\.' /etc/resolv.conf 2>/dev/null; then
        DOCKER_DNS_LINE='    "dns": ["1.1.1.1", "8.8.8.8"],'
    fi
    cat > /etc/docker/daemon.json << DOCKER_LOG_EOF
{{
${{DOCKER_DNS_LINE}}
    "ip": "127.0.0.1",
    "log-driver": "json-file",
    "log-opts": {{
        "max-size": "10m",
        "max-file": "3"
    }}
}}
DOCKER_LOG_EOF
    sed -i '/^$/d' /etc/docker/daemon.json
    systemctl restart docker 2>/dev/null || true
fi

# --- Ensure shared Docker network for Caddy ---
    docker network inspect caddy >/dev/null 2>&1 || docker network create caddy

    # --- Start caddy-docker-proxy container if not already running ---
    if ! docker ps -a --format '{{.Names}}' | grep -q '^caddy$'; then
        docker run -d --name caddy \
            --restart unless-stopped \
            -p 0.0.0.0:80:80 \
            -p 0.0.0.0:443:443 \
            -p 0.0.0.0:443:443/udp \
            --network caddy \
            -e CADDY_INGRESS_NETWORKS=caddy \
            -v /var/run/docker.sock:/var/run/docker.sock:ro \
            -v caddy_data:/data \
            -v caddy_config:/config \
            lucaslorentz/caddy-docker-proxy:latest
    else
        docker start caddy >/dev/null 2>&1 || true
    fi


# --- Configure Firewall (UFW + ufw-docker or firewalld + docker-forwarding REJECT) ---
case "${{DISTRO_FAMILY}}" in
    debian)
        apt-get update
        apt-get install -y ufw
        ufw default deny incoming
        ufw default allow outgoing
{ufw_transport}
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow 443/udp
        ufw route allow proto tcp from any to any port 80
        ufw route allow proto tcp from any to any port 443
        ufw route allow proto udp from any to any port 443
        if ! grep -q "BEGIN UFW AND DOCKER" /etc/ufw/after.rules 2>/dev/null; then
            cat >> /etc/ufw/after.rules << 'UFW_DOCKER_EOF'

# BEGIN UFW AND DOCKER
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward
-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16
-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 192.168.0.0/16
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -p udp -m udp --dport 0:32767 -d 172.16.0.0/12
-A DOCKER-USER -j RETURN
-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP
COMMIT
# END UFW AND DOCKER
UFW_DOCKER_EOF
        fi
        ufw --force enable
        ufw reload >/dev/null 2>&1 || true
        ;;
    rhel)
        dnf install -y firewalld
        systemctl enable --now firewalld
{fwd_transport}
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --permanent --add-port=443/udp
        firewall-cmd --permanent --remove-service=cockpit >/dev/null 2>&1 || true
        if firewall-cmd --permanent --info-policy docker-forwarding >/dev/null 2>&1; then
            firewall-cmd --permanent --policy docker-forwarding --set-target REJECT >/dev/null
        fi
        firewall-cmd --reload
        ;;
esac
"#
    )
}

fn build_wireguard_script(username: &str, tailscale_mode: bool) -> String {
    let quoted_user = shell_quote(username);
    let distro = distro_detect_block();
    let ufw_transport = ufw_transport_rules(tailscale_mode);
    let fwd_transport = firewalld_transport_rules(tailscale_mode);

    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

USERNAME={quoted_user}
TAILSCALE_MODE={tailscale_mode}

{distro}

# --- Install WireGuard packages ---
case "${{DISTRO_FAMILY}}" in
    debian)
        apt-get update
        apt-get install -y wireguard wireguard-tools iptables qrencode
        ;;
    rhel)
        dnf install -y epel-release || true
        dnf install -y wireguard-tools iptables qrencode
        dnf install -y wireguard 2>/dev/null || true
        ;;
esac

# --- Enable IPv4 & IPv6 forwarding ---
cat > /etc/sysctl.d/99-bab-wireguard.conf << 'SYSCTL_WG_EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
SYSCTL_WG_EOF
sysctl --system

# --- Detect primary egress interface ---
EGRESS_IFACE=$(ip -o -4 route show to default | awk '{{print $5; exit}}')
if [ -z "${{EGRESS_IFACE:-}}" ]; then
    EGRESS_IFACE=$(ip -o route show default | awk '{{print $5; exit}}')
fi
if [ -z "${{EGRESS_IFACE:-}}" ]; then
    echo "Unable to detect primary egress interface" >&2
    exit 1
fi

# --- Idempotently generate server & client1 keys and configs ---
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

if [ ! -f /etc/wireguard/server_private.key ]; then
    (umask 077 && wg genkey > /etc/wireguard/server_private.key)
fi
chmod 600 /etc/wireguard/server_private.key

if [ ! -f /etc/wireguard/server_public.key ]; then
    wg pubkey < /etc/wireguard/server_private.key > /etc/wireguard/server_public.key
fi
chmod 644 /etc/wireguard/server_public.key

if [ ! -f /etc/wireguard/client1_private.key ]; then
    (umask 077 && wg genkey > /etc/wireguard/client1_private.key)
fi
chmod 600 /etc/wireguard/client1_private.key

if [ ! -f /etc/wireguard/client1_public.key ]; then
    wg pubkey < /etc/wireguard/client1_private.key > /etc/wireguard/client1_public.key
fi
chmod 644 /etc/wireguard/client1_public.key

SERVER_PRIV=$(cat /etc/wireguard/server_private.key)
SERVER_PUB=$(cat /etc/wireguard/server_public.key)
CLIENT1_PRIV=$(cat /etc/wireguard/client1_private.key)
CLIENT1_PUB=$(cat /etc/wireguard/client1_public.key)

if [ ! -f /etc/wireguard/wg0.conf ]; then
    cat > /etc/wireguard/wg0.conf << WG0_CONF_EOF
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = ${{SERVER_PRIV}}
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o ${{EGRESS_IFACE}} -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o ${{EGRESS_IFACE}} -j MASQUERADE

[Peer]
PublicKey = ${{CLIENT1_PUB}}
AllowedIPs = 10.66.66.2/32
WG0_CONF_EOF
    chmod 600 /etc/wireguard/wg0.conf
fi

if [ ! -f /etc/wireguard/client1.conf ]; then
    ENDPOINT_IP=$(curl -4 -fsSL https://ifconfig.me 2>/dev/null || hostname -I | awk '{{print $1}}')
    cat > /etc/wireguard/client1.conf << WG_CLIENT1_EOF
[Interface]
PrivateKey = ${{CLIENT1_PRIV}}
Address = 10.66.66.2/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = ${{SERVER_PUB}}
Endpoint = ${{ENDPOINT_IP}}:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
WG_CLIENT1_EOF
    chmod 600 /etc/wireguard/client1.conf
fi

systemctl enable --now wg-quick@wg0

# --- Configure Firewall ---
case "${{DISTRO_FAMILY}}" in
    debian)
        apt-get install -y ufw
        ufw default deny incoming
        ufw default allow outgoing
        ufw default allow routed
{ufw_transport}
        ufw allow 51820/udp
        ufw route allow in on wg0 out on "${{EGRESS_IFACE}}"
        ufw --force enable
        ufw reload >/dev/null 2>&1 || true
        ;;
    rhel)
        dnf install -y firewalld
        systemctl enable --now firewalld
{fwd_transport}
        firewall-cmd --permanent --zone=trusted --add-interface=wg0
        firewall-cmd --permanent --add-port=51820/udp
        firewall-cmd --permanent --add-masquerade
        firewall-cmd --permanent --remove-service=cockpit >/dev/null 2>&1 || true
        firewall-cmd --reload
        ;;
esac
"#
    )
}

fn build_rbi_stub_script(username: &str, tailscale_mode: bool) -> String {
    let quoted_user = shell_quote(username);
    let distro = distro_detect_block();
    let ufw_transport = ufw_transport_rules(tailscale_mode);
    let fwd_transport = firewalld_transport_rules(tailscale_mode);

    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

USERNAME={quoted_user}
TAILSCALE_MODE={tailscale_mode}

{distro}

# --- Configure Base Firewall ---
case "${{DISTRO_FAMILY}}" in
    debian)
        apt-get update
        apt-get install -y ufw
        ufw default deny incoming
        ufw default allow outgoing
{ufw_transport}
        ufw --force enable
        ufw reload >/dev/null 2>&1 || true
        ;;
    rhel)
        dnf install -y firewalld
        systemctl enable --now firewalld
{fwd_transport}
        firewall-cmd --permanent --remove-service=cockpit >/dev/null 2>&1 || true
        firewall-cmd --reload
        ;;
esac

cat > /etc/bab-role-rbi.stub << RBI_STUB_EOF
role=rbi
username=${{USERNAME}}
tailscale_mode=${{TAILSCALE_MODE}}
status=stub
RBI_STUB_EOF
chmod 644 /etc/bab-role-rbi.stub

echo "RBI_STUB_READY: Remote Browser Isolation profile registered (implementation deferred to future phase)"
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::Command;

    fn assert_bash_syntax_ok(script: &str, label: &str) {
        let mut child = Command::new("bash")
            .arg("-n")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("failed to spawn bash -n");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(script.as_bytes())
            .expect("write script");
        let output = child.wait_with_output().expect("wait bash -n");
        assert!(
            output.status.success(),
            "bash -n failed for {}: {}",
            label,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn assert_transport_firewall_rules(script: &str, tailscale_mode: bool, label: &str) {
        if tailscale_mode {
            assert!(
                script.contains("ufw allow in on tailscale0"),
                "{label}: missing tailscale0 ufw allow"
            );
            assert!(
                script.contains("ufw allow 41641/udp"),
                "{label}: missing 41641/udp ufw allow"
            );
            assert!(
                script.contains("ufw delete allow 22/tcp"),
                "{label}: missing delete allow 22/tcp"
            );
            assert!(
                script.contains("ufw delete limit 22/tcp"),
                "{label}: missing delete limit 22/tcp"
            );
            assert!(
                script.contains("ufw delete allow OpenSSH"),
                "{label}: missing delete allow OpenSSH"
            );
            assert!(
                !script.lines().any(|l| l.trim() == "ufw limit 22/tcp"),
                "{label}: unexpected standalone ufw limit 22/tcp in tailscale mode"
            );
            assert!(
                script.contains("--zone=trusted --add-interface=tailscale0"),
                "{label}: missing firewalld tailscale0"
            );
            assert!(
                script.contains("--add-port=41641/udp"),
                "{label}: missing firewalld 41641/udp"
            );
            assert!(
                script.contains("--remove-service=ssh"),
                "{label}: missing firewalld remove ssh"
            );
            assert!(
                script.contains("--remove-port=22/tcp"),
                "{label}: missing firewalld remove 22/tcp"
            );
            assert!(
                !script.contains("--add-service=ssh"),
                "{label}: unexpected --add-service=ssh in tailscale mode"
            );
        } else {
            assert!(
                script.lines().any(|l| l.trim() == "ufw limit 22/tcp"),
                "{label}: missing ufw limit 22/tcp"
            );
            assert!(
                script.contains("ufw delete allow 41641/udp"),
                "{label}: missing delete stale 41641/udp"
            );
            assert!(
                script.contains("ufw delete allow in on tailscale0"),
                "{label}: missing delete stale tailscale0"
            );
            assert!(
                !script.lines().any(|l| l.trim() == "ufw allow in on tailscale0"),
                "{label}: must not open tailscale0 in standard SSH mode"
            );
            assert!(
                !script.lines().any(|l| l.trim() == "ufw allow 41641/udp"),
                "{label}: must not open 41641/udp in standard SSH mode"
            );
            assert!(
                script.contains("--add-service=ssh"),
                "{label}: missing firewalld --add-service=ssh"
            );
            assert!(
                script.contains("--zone=trusted --remove-interface=tailscale0"),
                "{label}: missing firewalld remove tailscale0"
            );
            assert!(
                script.contains("--remove-port=41641/udp"),
                "{label}: missing firewalld remove 41641/udp"
            );
            assert!(
                !script.contains("--add-interface=tailscale0"),
                "{label}: must not add tailscale0 in standard SSH mode"
            );
            assert!(
                !script.contains("--add-port=41641/udp"),
                "{label}: must not add 41641/udp in standard SSH mode"
            );
        }
    }

    #[test]
    fn all_roles_count_and_labels() {
        let all = ServerRole::all();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0], ServerRole::Vanilla);
        assert_eq!(all[0].label(), "Vanilla (Plain Hardened OS)");
        assert_eq!(all[1].label(), "ReverseProxy (Caddy)");
        assert_eq!(all[2].label(), "VPN Server (WireGuard)");
        assert_eq!(all[3].label(), "Remote Browser Isolation (Build Later)");
        assert_eq!(
            ServerRole::Vanilla.description(),
            "Plain hardened base OS with updates, sudo user, firewall, Fail2ban, and unattended security upgrades"
        );
        for role in all {
            assert!(!role.description().is_empty());
        }
    }

    #[test]
    fn from_str_and_display_round_trip() {
        for role in ServerRole::all() {
            let s = role.to_string();
            let parsed = ServerRole::from_str(&s).expect("round-trip parse");
            assert_eq!(*role, parsed);
        }

        assert_eq!(ServerRole::Vanilla.to_string(), "vanilla");
        for alias in ["vanilla", "VANILLA", "plain", "Plain", "base", "minimal"] {
            assert_eq!(
                ServerRole::from_str(alias).unwrap(),
                ServerRole::Vanilla,
                "alias: {alias}"
            );
        }

        assert_eq!(
            ServerRole::from_str("CADDY").unwrap(),
            ServerRole::ReverseProxyCaddy
        );
        assert_eq!(
            ServerRole::from_str("reverse-proxy").unwrap(),
            ServerRole::ReverseProxyCaddy
        );
        assert_eq!(
            ServerRole::from_str("reverse_proxy").unwrap(),
            ServerRole::ReverseProxyCaddy
        );
        assert_eq!(
            ServerRole::from_str("ReverseProxy").unwrap(),
            ServerRole::ReverseProxyCaddy
        );
        assert_eq!(
            ServerRole::from_str("VPN").unwrap(),
            ServerRole::VpnWireguard
        );
        assert_eq!(
            ServerRole::from_str("WireGuard").unwrap(),
            ServerRole::VpnWireguard
        );
        assert_eq!(
            ServerRole::from_str("RBI").unwrap(),
            ServerRole::RemoteBrowserIsolation
        );
        assert_eq!(
            ServerRole::from_str("remote-browser-isolation").unwrap(),
            ServerRole::RemoteBrowserIsolation
        );
        assert_eq!(
            ServerRole::from_str("remote_browser_isolation").unwrap(),
            ServerRole::RemoteBrowserIsolation
        );
        assert!(ServerRole::from_str("unknown-role").is_err());
    }

    #[test]
    fn is_stub_and_open_ports_for_modes() {
        assert!(!ServerRole::Vanilla.is_stub());
        assert!(!ServerRole::ReverseProxyCaddy.is_stub());
        assert!(!ServerRole::VpnWireguard.is_stub());
        assert!(ServerRole::RemoteBrowserIsolation.is_stub());

        assert_eq!(
            ServerRole::Vanilla.open_ports_for_mode(true),
            vec!["41641/udp (Tailscale)"]
        );
        assert_eq!(
            ServerRole::ReverseProxyCaddy.open_ports_for_mode(true),
            vec![
                "41641/udp (Tailscale)",
                "80/tcp (HTTP)",
                "443/tcp+udp (HTTPS/HTTP3)",
            ]
        );
        assert_eq!(
            ServerRole::VpnWireguard.open_ports_for_mode(true),
            vec!["41641/udp (Tailscale)", "51820/udp (WireGuard)"]
        );
        assert_eq!(
            ServerRole::RemoteBrowserIsolation.open_ports_for_mode(true),
            vec!["41641/udp (Tailscale)"]
        );

        assert_eq!(
            ServerRole::Vanilla.open_ports_for_mode(false),
            vec!["22/tcp (SSH rate-limited)"]
        );
        assert_eq!(
            ServerRole::ReverseProxyCaddy.open_ports_for_mode(false),
            vec![
                "22/tcp (SSH rate-limited)",
                "80/tcp (HTTP)",
                "443/tcp+udp (HTTPS/HTTP3)",
            ]
        );
        assert_eq!(
            ServerRole::VpnWireguard.open_ports_for_mode(false),
            vec!["22/tcp (SSH rate-limited)", "51820/udp (WireGuard)"]
        );
        assert_eq!(
            ServerRole::RemoteBrowserIsolation.open_ports_for_mode(false),
            vec!["22/tcp (SSH rate-limited)"]
        );

        for role in ServerRole::all() {
            assert_eq!(role.open_ports(), role.open_ports_for_mode(true));
        }
    }

    #[test]
    fn all_roles_bash_syntax_and_mode_firewall_rules() {
        for role in ServerRole::all() {
            for tailscale_mode in [true, false] {
                let label = format!("{role} tailscale={tailscale_mode}");
                let script = role.role_setup_script("deploy", tailscale_mode);
                assert_bash_syntax_ok(&script, &label);
                assert_transport_firewall_rules(&script, tailscale_mode, &label);
            }
        }
    }

    #[test]
    fn vanilla_script_markers_and_no_extra_services() {
        for tailscale_mode in [true, false] {
            let script = ServerRole::Vanilla.role_setup_script("deploy", tailscale_mode);
            assert_bash_syntax_ok(&script, &format!("vanilla tailscale={tailscale_mode}"));
            assert!(script.contains("ufw default deny incoming"));
            assert!(script.contains("ufw default allow outgoing"));
            assert!(script.contains("firewalld"));
            assert!(!script.contains("docker"));
            assert!(!script.contains("caddy"));
            assert!(!script.contains("wireguard"));
            assert!(!script.contains(".stub"));
        }
    }

    #[test]
    fn caddy_script_syntax_and_markers() {
        let ts_script = ServerRole::ReverseProxyCaddy.role_setup_script("deploy", true);
        assert_bash_syntax_ok(&ts_script, "caddy tailscale=true");
        assert!(ts_script.contains("get.docker.com"));
        assert!(ts_script.contains("docker-ce.repo"));
        assert!(ts_script.contains("/etc/docker/daemon.json"));
        assert!(ts_script.contains("\"max-size\": \"10m\""));
        assert!(ts_script.contains("\"max-file\": \"3\""));
        assert!(ts_script.contains("lucaslorentz/caddy-docker-proxy:latest"));
        assert!(ts_script.contains("ufw route allow proto tcp from any to any port 80"));
        assert!(ts_script.contains("BEGIN UFW AND DOCKER"));
        assert!(ts_script.contains("docker-forwarding --set-target REJECT"));
        assert!(ts_script.contains("80/tcp"));
        assert!(ts_script.contains("443/tcp"));
        assert!(ts_script.contains("443/udp"));
        assert_transport_firewall_rules(&ts_script, true, "caddy tailscale=true");

        let ssh_script = ServerRole::ReverseProxyCaddy.role_setup_script("deploy", false);
        assert_bash_syntax_ok(&ssh_script, "caddy tailscale=false");
        assert_transport_firewall_rules(&ssh_script, false, "caddy tailscale=false");
    }

    #[test]
    fn wireguard_script_syntax_and_markers() {
        let ts_script = ServerRole::VpnWireguard.role_setup_script("deploy", true);
        assert_bash_syntax_ok(&ts_script, "wireguard tailscale=true");
        assert!(ts_script.contains("wireguard-tools"));
        assert!(ts_script.contains("qrencode"));
        assert!(ts_script.contains("/etc/sysctl.d/99-bab-wireguard.conf"));
        assert!(ts_script.contains("sysctl --system"));
        assert!(ts_script.contains("wg genkey"));
        assert!(ts_script.contains("wg pubkey"));
        assert!(ts_script.contains("/etc/wireguard/wg0.conf"));
        assert!(ts_script.contains("10.66.66.1/24"));
        assert!(ts_script.contains("ListenPort = 51820"));
        assert!(ts_script.contains("MASQUERADE"));
        assert!(ts_script.contains("/etc/wireguard/client1.conf"));
        assert!(ts_script.contains("chmod 600 /etc/wireguard/client1.conf"));
        assert!(ts_script.contains("systemctl enable --now wg-quick@wg0"));
        assert!(ts_script.contains("51820/udp"));
        assert!(ts_script.contains("ufw route allow in on wg0"));
        assert_transport_firewall_rules(&ts_script, true, "wireguard tailscale=true");

        let ssh_script = ServerRole::VpnWireguard.role_setup_script("deploy", false);
        assert_bash_syntax_ok(&ssh_script, "wireguard tailscale=false");
        assert_transport_firewall_rules(&ssh_script, false, "wireguard tailscale=false");
    }

    #[test]
    fn rbi_stub_script_syntax_and_markers() {
        let ts_script = ServerRole::RemoteBrowserIsolation.role_setup_script("deploy", true);
        assert_bash_syntax_ok(&ts_script, "rbi tailscale=true");
        assert!(ts_script.contains("/etc/bab-role-rbi.stub"));
        assert!(ts_script.contains(
            "RBI_STUB_READY: Remote Browser Isolation profile registered (implementation deferred to future phase)"
        ));
        assert_transport_firewall_rules(&ts_script, true, "rbi tailscale=true");

        let ssh_script = ServerRole::RemoteBrowserIsolation.role_setup_script("deploy", false);
        assert_bash_syntax_ok(&ssh_script, "rbi tailscale=false");
        assert_transport_firewall_rules(&ssh_script, false, "rbi tailscale=false");
    }
}
