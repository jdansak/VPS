// src/tailscale.rs
// Tailscale client and helper utilities for bab.
// Implements device listing, auth‑key creation, polling, and cloud‑init generation.

use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Representation of a Tailscale device used by bab.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TailscaleDevice {
    pub id: String,
    pub hostname: String,
    pub name: String,
    /// IPv4 address selected according to the rules described in the task.
    pub ipv4: String,
    pub os: String,
    /// Whether the device is considered online.
    pub online: bool,
}

/// Internal structure that mirrors the JSON returned by the Tailscale API.
#[derive(Debug, Deserialize)]
struct ApiDevice {
    id: String,
    hostname: String,
    name: String,
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    os: String,
    #[serde(default)]
    online: Option<bool>,
    #[serde(default)]
    connected_to_control: Option<bool>,
    #[serde(default)]
    last_seen: Option<String>,
}

impl From<ApiDevice> for TailscaleDevice {
    fn from(api: ApiDevice) -> Self {
        // Prefer Tailscale 100.x IPv4, then any IPv4, then first address if any.
        let ipv4 = api
            .addresses
            .iter()
            .filter(|addr| addr.contains('.')) // keep only IPv4-like strings
            .find(|addr| addr.starts_with("100."))
            .cloned()
            .or_else(|| api.addresses.iter().find(|addr| addr.contains('.')).cloned())
            .or_else(|| api.addresses.first().cloned())
            .unwrap_or_default();

        // Determine online status.
        let online = api.online.unwrap_or_else(|| {
            api.connected_to_control.unwrap_or(false) || api.last_seen.is_some()
        });

        TailscaleDevice {
            id: api.id,
            hostname: api.hostname,
            name: api.name,
            ipv4,
            os: api.os,
            online,
        }
    }
}

/// Wrapper around the Tailscale HTTP API.
#[derive(Debug, Clone)]
pub struct TailscaleClient {
    api_key: String,
    base_url: String,
    tailnet: String,
    http: Client,
}

impl TailscaleClient {
    /// Create a client using environment variables.
    pub fn new(api_key: impl Into<String>) -> Result<Self> {
        let api_key = api_key.into();
        let base_url = env::var("TAILSCALE_API_BASE")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "https://api.tailscale.com/api/v2".to_string());
        let tailnet = env::var("TAILSCALE_TAILNET")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "-".to_string());
        Self::with_config(api_key, base_url, tailnet)
    }

    /// Create a client with explicit configuration.
    pub fn with_config(api_key: impl Into<String>, base_url: impl Into<String>, tailnet: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| anyhow!("Failed to build HTTP client: {}", e))?;
        Ok(Self {
            api_key: api_key.into(),
            base_url,
            tailnet: tailnet.into(),
            http,
        })
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.api_key)
    }

    /// Validate that the API key works for the configured tailnet.
    pub fn validate_api_key(&self) -> Result<bool> {
        let url = format!(
            "{}/tailnet/{}/devices",
            self.base_url, self.tailnet
        );
        let resp = self
            .http
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()?;
        match resp.status().as_u16() {
            200..=299 => {
                // Successful – ensure JSON contains a non-null "devices" field.
                let json: serde_json::Value = resp.json()?;
                Ok(json.get("devices").is_some_and(|v| !v.is_null()))
            }
            401 | 403 => Ok(false),
            _ => Err(anyhow!("Unexpected status {} when validating API key", resp.status())),
        }
    }

    /// Retrieve the list of devices for the configured tailnet.
    pub fn list_devices(&self) -> Result<Vec<TailscaleDevice>> {
        let url = format!(
            "{}/tailnet/{}/devices",
            self.base_url, self.tailnet
        );
        let resp = self
            .http
            .get(&url)
            .header("Authorization", self.auth_header())
            .send()?;
        let resp = resp.error_for_status()?;
        #[derive(Debug, Deserialize)]
        struct DevicesResponse {
            devices: Vec<ApiDevice>,
        }
        let parsed: DevicesResponse = resp.json()?;
        Ok(parsed.devices.into_iter().map(TailscaleDevice::from).collect())
    }

    /// Create a new auth key.
    pub fn create_auth_key(
        &self,
        description: &str,
        tags: &[String],
        ephemeral: bool,
        preauthorized: bool,
        expiry_seconds: u64,
    ) -> Result<String> {
        let url = format!("{}/tailnet/{}/keys", self.base_url, self.tailnet);
        // Helper to build the payload, optionally with tags.
        let build_payload = |include_tags: bool| {
            let mut capabilities = json!({
                "devices": {
                    "create": {
                        "reusable": false,
                        "ephemeral": ephemeral,
                        "preauthorized": preauthorized,
                    }
                }
            });
            if include_tags && !tags.is_empty() {
                if let Some(obj) = capabilities.get_mut("devices") {
                    if let Some(create) = obj.get_mut("create") {
                        create
                            .as_object_mut()
                            .unwrap()
                            .insert("tags".to_string(), json!(tags));
                    }
                }
            }
            json!({
                "description": description,
                "capabilities": capabilities,
                "expirySeconds": expiry_seconds,
            })
        };

        // First attempt – with tags if any.
        let first_payload = build_payload(true);
        let first_resp = self
            .http
            .post(&url)
            .header("Authorization", self.auth_header())
            .json(&first_payload)
            .send()?;
        let first_status = first_resp.status();
        let first_body = first_resp.text()?;
        if first_status.is_success() {
            if let Ok(first_json) = serde_json::from_str::<serde_json::Value>(&first_body) {
                if let Some(key) = first_json.get("key").and_then(|k| k.as_str()) {
                    if !key.is_empty() {
                        return Ok(key.to_string());
                    }
                }
            }
        }

        // Only retry without tags if tags were actually included in the first request.
        if tags.is_empty() {
            return Err(anyhow!(
                "Failed to create Tailscale auth key (HTTP {}): {}",
                first_status,
                first_body
            ));
        }

        let retry_payload = build_payload(false);
        let retry_resp = self
            .http
            .post(&url)
            .header("Authorization", self.auth_header())
            .json(&retry_payload)
            .send()?;
        let retry_status = retry_resp.status();
        let retry_body = retry_resp.text()?;
        if retry_status.is_success() {
            if let Ok(retry_json) = serde_json::from_str::<serde_json::Value>(&retry_body) {
                if let Some(key) = retry_json.get("key").and_then(|k| k.as_str()) {
                    if !key.is_empty() {
                        return Ok(key.to_string());
                    }
                }
            }
        }

        Err(anyhow!(
            "Failed to create Tailscale auth key without tags (HTTP {}): {}",
            retry_status,
            retry_body
        ))
    }

    /// Find the IPv4 address of a device matching the query.
    pub fn find_device_ip(&self, query: &str) -> Result<Option<String>> {
        let devices = self.list_devices()?;
        let q = query.to_ascii_lowercase();
        for dev in devices {
            if dev.ipv4.is_empty() {
                continue;
            }
            let name_part = dev.name.split('.').next().unwrap_or("");
            if dev.hostname.eq_ignore_ascii_case(&q)
                || dev.id.eq_ignore_ascii_case(&q)
                || dev.name.eq_ignore_ascii_case(&q)
                || name_part.eq_ignore_ascii_case(&q)
            {
                return Ok(Some(dev.ipv4));
            }
        }
        Ok(None)
    }

    /// Wait until a device with the given hostname appears, or timeout.
    pub fn wait_for_device(
        &self,
        hostname: &str,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<String> {
        let start = Instant::now();
        loop {
            if let Some(ip) = self.find_device_ip(hostname)? {
                return Ok(ip);
            }
            if start.elapsed() >= timeout {
                return Err(anyhow!("Timed out waiting for device {}", hostname));
            }
            sleep(poll_interval);
        }
    }

    /// Delete a device by its ID.
    pub fn delete_device(&self, device_id: &str) -> Result<()> {
        let url = format!("{}/device/{}", self.base_url, device_id);
        self.http
            .delete(&url)
            .header("Authorization", self.auth_header())
            .send()?
            .error_for_status()?;
        Ok(())
    }

    /// Delete every device matching `query` across hostname, id, name, short name, or IPv4.
    pub fn delete_matching_devices(&self, query: &str) -> Result<Vec<String>> {
        self.delete_matching_devices_filtered(query, false)
    }

    /// Delete every offline device matching `query` across hostname, id, name, short name, or IPv4.
    pub fn delete_matching_offline_devices(&self, query: &str) -> Result<Vec<String>> {
        self.delete_matching_devices_filtered(query, true)
    }

    fn delete_matching_devices_filtered(
        &self,
        query: &str,
        offline_only: bool,
    ) -> Result<Vec<String>> {
        let devices = self.list_devices()?;
        let q = query.trim();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let mut deleted = Vec::new();
        for dev in devices {
            if offline_only && dev.online {
                continue;
            }
            if device_matches_query(&dev, q) {
                self.delete_device(&dev.id)?;
                deleted.push(format!("{} ({})", dev.hostname, dev.id));
            }
        }
        Ok(deleted)
    }
}

fn device_matches_query(dev: &TailscaleDevice, query: &str) -> bool {
    let q = query.trim();
    if q.is_empty() {
        return false;
    }
    let name_part = dev.name.split('.').next().unwrap_or("");
    dev.hostname.eq_ignore_ascii_case(q)
        || dev.id.eq_ignore_ascii_case(q)
        || dev.name.eq_ignore_ascii_case(q)
        || name_part.eq_ignore_ascii_case(q)
        || dev.ipv4.eq_ignore_ascii_case(q)
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Generate an idempotent cloud-init script that installs Tailscale and brings the node up.
pub fn generate_cloud_init(auth_key: &str, hostname: &str, username: &str) -> String {
    generate_cloud_init_with_password(auth_key, hostname, username, None)
}

/// Generate an idempotent cloud-init script that installs Tailscale, optionally sets the
/// user's password, and brings the node up.
pub fn generate_cloud_init_with_password(
    auth_key: &str,
    hostname: &str,
    username: &str,
    password: Option<&str>,
) -> String {
    let q_hostname = shell_quote(hostname);
    let q_username = shell_quote(username);
    let q_auth_key = shell_quote(auth_key);
    let q_sudoers = shell_quote(&format!("/etc/sudoers.d/{}", username));
    let password_block = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(pw) => {
            let q_password = shell_quote(pw);
            format!(
                "\nif id -u {q_username} >/dev/null 2>&1; then\n  printf '%s:%s\\n' {q_username} {q_password} | chpasswd || true\nfi\n"
            )
        }
        None => String::new(),
    };
    format!(
        r#"#!/bin/bash
set -euo pipefail

# Set hostname
if command -v hostnamectl >/dev/null 2>&1; then
  hostnamectl set-hostname {q_hostname} 2>/dev/null || true
else
  hostname {q_hostname} 2>/dev/null || true
fi

# Create user if missing
if ! id -u {q_username} >/dev/null 2>&1; then
  if [ -f /etc/debian_version ]; then
    adduser --disabled-password --gecos "" {q_username} 2>/dev/null || adduser --disabled-password --allow-bad-names --gecos "" {q_username} 2>/dev/null || adduser --disabled-password --force-badname --gecos "" {q_username} 2>/dev/null || useradd --badname -m -s /bin/bash {q_username} 2>/dev/null || useradd -m -s /bin/bash {q_username} || true
    if getent group sudo >/dev/null 2>&1; then
      usermod -aG sudo {q_username} || true
    fi
  else
    useradd -m -s /bin/bash {q_username} 2>/dev/null || useradd --badname -m -s /bin/bash {q_username} || true
    if getent group sudo >/dev/null 2>&1; then
      usermod -aG sudo {q_username} || true
    elif getent group wheel >/dev/null 2>&1; then
      usermod -aG wheel {q_username} || true
    fi
  fi
  mkdir -p /etc/sudoers.d
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' {q_username} > {q_sudoers}
  chmod 440 {q_sudoers}
fi
{password_block}
# Install Tailscale if needed
if ! command -v tailscale >/dev/null 2>&1; then
  curl -fsSL https://tailscale.com/install.sh | sh
fi

# Enable and start tailscaled
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now tailscaled 2>/dev/null || true
fi

# Bring up Tailscale
tailscale up --authkey={q_auth_key} --ssh --hostname={q_hostname} || (sleep 3 && tailscale up --authkey={q_auth_key} --ssh --hostname={q_hostname})
"#,
        q_hostname = q_hostname,
        q_username = q_username,
        q_auth_key = q_auth_key,
        q_sudoers = q_sudoers,
        password_block = password_block,
    )
}

/// Generate an idempotent cloud-init script for Standard SSH mode (no Tailscale).
/// Configures hostname, creates a non-root sudo/wheel user with NOPASSWD sudoers,
/// and installs the SSH public key for root and the user.
pub fn generate_ssh_cloud_init(ssh_pubkey: &str, hostname: &str, username: &str) -> String {
    generate_ssh_cloud_init_with_password(ssh_pubkey, hostname, username, None)
}

/// Generate an idempotent cloud-init script for Standard SSH mode (no Tailscale),
/// optionally setting the non-root user's password.
pub fn generate_ssh_cloud_init_with_password(
    ssh_pubkey: &str,
    hostname: &str,
    username: &str,
    password: Option<&str>,
) -> String {
    let q_ssh_pubkey = shell_quote(ssh_pubkey.trim());
    let q_hostname = shell_quote(hostname);
    let q_username = shell_quote(username);
    let password_block = match password.map(str::trim).filter(|s| !s.is_empty()) {
        Some(pw) => {
            let q_password = shell_quote(pw);
            format!(
                "\n  if id -u \"$NEW_USER\" >/dev/null 2>&1; then\n    printf '%s:%s\\n' \"$NEW_USER\" {q_password} | chpasswd || true\n  fi"
            )
        }
        None => String::new(),
    };
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

NEW_HOST={q_hostname}
NEW_USER={q_username}
SSH_PUBKEY={q_ssh_pubkey}

# Set hostname
if command -v hostnamectl >/dev/null 2>&1; then
  hostnamectl set-hostname "$NEW_HOST" 2>/dev/null || printf '%s\n' "$NEW_HOST" > /etc/hostname
else
  printf '%s\n' "$NEW_HOST" > /etc/hostname
  hostname "$NEW_HOST" 2>/dev/null || true
fi

# Detect Debian vs RHEL sudo group
SUDO_GROUP=""
if [ -f /etc/debian_version ] && getent group sudo >/dev/null 2>&1; then
  SUDO_GROUP="sudo"
elif getent group sudo >/dev/null 2>&1; then
  SUDO_GROUP="sudo"
elif getent group wheel >/dev/null 2>&1; then
  SUDO_GROUP="wheel"
fi

# Create non-root user if missing and configure sudoers
if [ "$NEW_USER" != "root" ]; then
  if ! id -u "$NEW_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$NEW_USER" 2>/dev/null || useradd --badname -m -s /bin/bash "$NEW_USER" 2>/dev/null || adduser --disabled-password --allow-bad-names --gecos "" "$NEW_USER" 2>/dev/null || adduser --disabled-password --force-badname --gecos "" "$NEW_USER" 2>/dev/null || adduser --disabled-password --gecos "" "$NEW_USER" 2>/dev/null || true
  fi
  if [ -n "$SUDO_GROUP" ]; then
    usermod -aG "$SUDO_GROUP" "$NEW_USER" || true
  fi
  mkdir -p /etc/sudoers.d
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$NEW_USER" > "/etc/sudoers.d/${{NEW_USER}}"
  chmod 0440 "/etc/sudoers.d/${{NEW_USER}}"{password_block}
fi

# Install SSH key for root
mkdir -p /root/.ssh
chmod 0700 /root/.ssh
touch /root/.ssh/authorized_keys
chmod 0600 /root/.ssh/authorized_keys
if ! grep -Fqx "$SSH_PUBKEY" /root/.ssh/authorized_keys; then
  printf '%s\n' "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
fi

# Install SSH key for non-root user
if [ "$NEW_USER" != "root" ]; then
  USER_SSH_DIR="/home/${{NEW_USER}}/.ssh"
  mkdir -p "$USER_SSH_DIR"
  chmod 0700 "$USER_SSH_DIR"
  touch "${{USER_SSH_DIR}}/authorized_keys"
  chmod 0600 "${{USER_SSH_DIR}}/authorized_keys"
  if ! grep -Fqx "$SSH_PUBKEY" "${{USER_SSH_DIR}}/authorized_keys"; then
    printf '%s\n' "$SSH_PUBKEY" >> "${{USER_SSH_DIR}}/authorized_keys"
  fi
  chown -R "${{NEW_USER}}:${{NEW_USER}}" "$USER_SSH_DIR" 2>/dev/null || chown -R "${{NEW_USER}}" "$USER_SSH_DIR" || true
fi
"#,
        q_hostname = q_hostname,
        q_username = q_username,
        q_ssh_pubkey = q_ssh_pubkey,
        password_block = password_block,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        method: String,
        path: String,
        authorization: Option<String>,
        body: String,
    }

    #[derive(Debug, Clone)]
    struct MockResponse {
        status: u16,
        reason: &'static str,
        body: String,
    }

    impl MockResponse {
        fn json(status: u16, reason: &'static str, body: impl Into<String>) -> Self {
            Self {
                status,
                reason,
                body: body.into(),
            }
        }
    }

    fn spawn_mock_server(
        responses: Vec<MockResponse>,
    ) -> (
        String,
        Arc<Mutex<Vec<RecordedRequest>>>,
        thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
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

                let mut content_length = 0usize;
                let mut authorization = None;
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
                        if name_lower == "content-length" {
                            content_length = val_trimmed.parse().unwrap_or(0);
                        } else if name_lower == "authorization" {
                            authorization = Some(val_trimmed);
                        }
                    }
                }

                let mut body_buf = vec![0u8; content_length];
                if content_length > 0 {
                    reader.read_exact(&mut body_buf).expect("read request body");
                }
                let body = String::from_utf8_lossy(&body_buf).to_string();

                recorded_clone.lock().unwrap().push(RecordedRequest {
                    method,
                    path,
                    authorization,
                    body,
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
    fn validate_api_key_handles_ok_unauthorized_and_error() {
        let (base_url, recorded, handle) = spawn_mock_server(vec![
            MockResponse::json(200, "OK", r#"{"devices":[]}"#),
            MockResponse::json(200, "OK", r#"{"other":true}"#),
            MockResponse::json(401, "Unauthorized", r#"{"message":"invalid"}"#),
            MockResponse::json(403, "Forbidden", r#"{"message":"forbidden"}"#),
            MockResponse::json(500, "Internal Server Error", r#"{"message":"boom"}"#),
        ]);
        let client = TailscaleClient::with_config("ts-secret", &base_url, "example.ts.net").unwrap();

        assert!(client.validate_api_key().unwrap());
        assert!(!client.validate_api_key().unwrap());
        assert!(!client.validate_api_key().unwrap());
        assert!(!client.validate_api_key().unwrap());
        assert!(client.validate_api_key().is_err());

        handle.join().unwrap();
        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 5);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].path, "/tailnet/example.ts.net/devices");
        assert_eq!(reqs[0].authorization.as_deref(), Some("Bearer ts-secret"));
    }

    #[test]
    fn list_devices_prioritizes_100_ipv4_and_derives_online() {
        let body = r#"{
            "devices": [
                {
                    "id": "dev-1",
                    "hostname": "web-01",
                    "name": "web-01.tail123.ts.net",
                    "addresses": ["fd7a:115c:a1e0::1", "10.0.0.5", "100.64.0.10"],
                    "os": "linux",
                    "connected_to_control": true
                },
                {
                    "id": "dev-2",
                    "hostname": "db-01",
                    "name": "db-01.tail123.ts.net",
                    "addresses": ["fd7a:115c:a1e0::2", "192.168.1.20"],
                    "os": "linux"
                },
                {
                    "id": "dev-3",
                    "hostname": "cache-01",
                    "name": "cache-01.tail123.ts.net",
                    "addresses": ["100.100.1.5", "100.100.1.6"],
                    "os": "ubuntu",
                    "online": false,
                    "connected_to_control": true
                }
            ]
        }"#;
        let (base_url, _, handle) = spawn_mock_server(vec![MockResponse::json(200, "OK", body)]);
        let client = TailscaleClient::with_config("key", &base_url, "-").unwrap();

        let devices = client.list_devices().unwrap();
        handle.join().unwrap();

        assert_eq!(devices.len(), 3);
        assert_eq!(devices[0].ipv4, "100.64.0.10");
        assert!(devices[0].online);
        assert_eq!(devices[1].ipv4, "192.168.1.20");
        assert!(!devices[1].online);
        assert_eq!(devices[2].ipv4, "100.100.1.5");
        assert!(!devices[2].online);
    }

    #[test]
    fn create_auth_key_retries_without_tags_on_400() {
        let (base_url, recorded, handle) = spawn_mock_server(vec![
            MockResponse::json(400, "Bad Request", r#"{"message":"requested tags are invalid"}"#),
            MockResponse::json(200, "OK", r#"{"key":"tskey-auth-fallback"}"#),
        ]);
        let client = TailscaleClient::with_config("ts-key", &base_url, "-").unwrap();

        let key = client
            .create_auth_key("bab-bootstrap", &["tag:vps".to_string()], false, true, 3600)
            .unwrap();
        handle.join().unwrap();

        assert_eq!(key, "tskey-auth-fallback");
        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].path, "/tailnet/-/keys");
        let first_json: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
        assert_eq!(first_json["description"], "bab-bootstrap");
        assert_eq!(
            first_json["capabilities"]["devices"]["create"]["tags"],
            json!(["tag:vps"])
        );
        let second_json: serde_json::Value = serde_json::from_str(&reqs[1].body).unwrap();
        assert_eq!(second_json["description"], "bab-bootstrap");
        assert!(second_json["capabilities"]["devices"]["create"]
            .get("tags")
            .is_none());
    }

    #[test]
    fn create_auth_key_does_not_retry_when_tags_empty() {
        let (base_url, recorded, handle) = spawn_mock_server(vec![MockResponse::json(
            400,
            "Bad Request",
            r#"{"message":"bad request"}"#,
        )]);
        let client = TailscaleClient::with_config("ts-key", &base_url, "-").unwrap();

        let err = client
            .create_auth_key("bab-bootstrap", &[], false, true, 3600)
            .unwrap_err();
        handle.join().unwrap();

        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        let body_json: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
        assert_eq!(body_json["description"], "bab-bootstrap");
        let msg = err.to_string();
        assert!(msg.contains("400"), "unexpected error message: {}", msg);
        assert!(
            msg.contains("bad request"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn create_auth_key_checks_retry_http_status() {
        let (base_url, recorded, handle) = spawn_mock_server(vec![
            MockResponse::json(400, "Bad Request", r#"{"message":"invalid tags"}"#),
            MockResponse::json(403, "Forbidden", r#"{"key":"should-not-accept-403"}"#),
        ]);
        let client = TailscaleClient::with_config("ts-key", &base_url, "-").unwrap();

        let err = client
            .create_auth_key("bab-bootstrap", &["tag:vps".to_string()], false, true, 3600)
            .unwrap_err();
        handle.join().unwrap();

        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        let first_json: serde_json::Value = serde_json::from_str(&reqs[0].body).unwrap();
        assert_eq!(first_json["description"], "bab-bootstrap");
        assert!(err.to_string().contains("403"));
    }

    #[test]
    fn find_device_ip_matches_hostname_id_name_and_short_label() {
        let body = r#"{
            "devices": [
                {
                    "id": "node-abc",
                    "hostname": "MyVPS",
                    "name": "myvps.tail99.ts.net",
                    "addresses": ["100.64.9.9"],
                    "os": "linux"
                },
                {
                    "id": "node-empty",
                    "hostname": "noip",
                    "name": "noip.tail99.ts.net",
                    "addresses": [],
                    "os": "linux"
                }
            ]
        }"#;
        let (base_url, _, handle) = spawn_mock_server(vec![
            MockResponse::json(200, "OK", body),
            MockResponse::json(200, "OK", body),
            MockResponse::json(200, "OK", body),
            MockResponse::json(200, "OK", body),
            MockResponse::json(200, "OK", body),
        ]);
        let client = TailscaleClient::with_config("ts-key", &base_url, "-").unwrap();

        assert_eq!(
            client.find_device_ip("myvps").unwrap().as_deref(),
            Some("100.64.9.9")
        );
        assert_eq!(
            client.find_device_ip("NODE-ABC").unwrap().as_deref(),
            Some("100.64.9.9")
        );
        assert_eq!(
            client
                .find_device_ip("myvps.tail99.ts.net")
                .unwrap()
                .as_deref(),
            Some("100.64.9.9")
        );
        assert_eq!(client.find_device_ip("noip").unwrap(), None);
        assert_eq!(client.find_device_ip("missing").unwrap(), None);

        handle.join().unwrap();
    }

    #[test]
    fn delete_device_sends_delete_and_checks_status() {
        let (base_url, recorded, handle) = spawn_mock_server(vec![
            MockResponse::json(200, "OK", "{}"),
            MockResponse::json(404, "Not Found", r#"{"message":"not found"}"#),
        ]);
        let client = TailscaleClient::with_config("ts-key", &base_url, "-").unwrap();

        assert!(client.delete_device("dev-42").is_ok());
        assert!(client.delete_device("dev-missing").is_err());

        handle.join().unwrap();
        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].method, "DELETE");
        assert_eq!(reqs[0].path, "/device/dev-42");
        assert_eq!(reqs[0].authorization.as_deref(), Some("Bearer ts-key"));
    }

    #[test]
    fn generate_cloud_init_is_idempotent_and_valid_bash() {
        let script = generate_cloud_init("tskey-auth-123", "edge-vps", "deploy");
        assert!(script.contains("#!/bin/bash"));
        assert!(script.contains("set -euo pipefail"));
        assert!(script.contains("if ! id -u 'deploy'"));
        assert!(script.contains("getent group sudo"));
        assert!(script.contains("getent group wheel"));
        assert!(script.contains("'/etc/sudoers.d/deploy'"));
        assert!(script.contains("if ! command -v tailscale"));
        assert!(script.contains("systemctl enable --now tailscaled"));
        assert!(script.contains(
            "tailscale up --authkey='tskey-auth-123' --ssh --hostname='edge-vps'"
        ));

        let mut child = Command::new("bash")
            .arg("-n")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn bash -n");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "bash -n failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn assert_valid_bash(script: &str) {
        let mut child = Command::new("bash")
            .arg("-n")
            .stdin(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn bash -n");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "bash -n failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn generate_ssh_cloud_init_is_valid_bash_and_has_no_tailscale() {
        let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey deploy@workstation";
        let script = generate_ssh_cloud_init(pubkey, "ssh-vps", "deploy");

        assert!(script.starts_with("#!/usr/bin/env bash\nset -euo pipefail\n"));
        assert!(script.contains("hostnamectl set-hostname"));
        assert!(script.contains("/etc/hostname"));
        assert!(script.contains("useradd -m -s /bin/bash"));
        assert!(script.contains("getent group sudo"));
        assert!(script.contains("getent group wheel"));
        assert!(script.contains("/etc/sudoers.d/${NEW_USER}"));
        assert!(script.contains("ALL=(ALL) NOPASSWD:ALL"));
        assert!(script.contains("chmod 0440"));
        assert!(script.contains("grep -Fqx \"$SSH_PUBKEY\" /root/.ssh/authorized_keys"));
        assert!(script.contains("/home/${NEW_USER}/.ssh"));
        assert!(script.contains("chown -R \"${NEW_USER}:${NEW_USER}\""));
        assert!(script.contains("chmod 0700"));
        assert!(script.contains("chmod 0600"));

        // Must NOT install Tailscale or call tailscale up
        let lower = script.to_ascii_lowercase();
        assert!(!lower.contains("tailscale"));
        assert!(!lower.contains("tailscaled"));

        assert_valid_bash(&script);
    }

    #[test]
    fn generate_ssh_cloud_init_safely_quotes_special_chars() {
        let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest o'connor $(whoami) `id`";
        let hostname = "my'host$(evil)";
        let username = "user'name";
        let script = generate_ssh_cloud_init(pubkey, hostname, username);

        assert!(script.contains("NEW_HOST='my'\\''host$(evil)'"));
        assert!(script.contains("NEW_USER='user'\\''name'"));
        assert!(script.contains(
            "SSH_PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest o'\\''connor $(whoami) `id`'"
        ));
        assert_valid_bash(&script);
    }

    #[test]
    fn delete_matching_devices_deletes_all_matches_across_fields() {
        let devices_body = r#"{
            "devices": [
                {
                    "id": "dev-1",
                    "hostname": "Edge-VPS",
                    "name": "edge-vps.tail1.ts.net",
                    "addresses": ["100.64.0.1"],
                    "os": "linux",
                    "online": true
                },
                {
                    "id": "dev-2",
                    "hostname": "edge-vps-2",
                    "name": "edge-vps.tail2.ts.net",
                    "addresses": ["100.64.0.2"],
                    "os": "linux",
                    "online": false
                },
                {
                    "id": "dev-3",
                    "hostname": "other-box",
                    "name": "other-box.tail1.ts.net",
                    "addresses": ["100.64.0.3"],
                    "os": "linux",
                    "online": true
                }
            ]
        }"#;
        let (base_url, recorded, handle) = spawn_mock_server(vec![
            MockResponse::json(200, "OK", devices_body),
            MockResponse::json(200, "OK", "{}"),
            MockResponse::json(200, "OK", "{}"),
            MockResponse::json(200, "OK", devices_body),
            MockResponse::json(200, "OK", "{}"),
            MockResponse::json(200, "OK", devices_body),
        ]);
        let client = TailscaleClient::with_config("ts-key", &base_url, "-").unwrap();

        let deleted = client.delete_matching_devices("  EDGE-VPS  ").unwrap();
        assert_eq!(deleted, vec!["Edge-VPS (dev-1)", "edge-vps-2 (dev-2)"]);

        let deleted_by_ip = client.delete_matching_devices("100.64.0.3").unwrap();
        assert_eq!(deleted_by_ip, vec!["other-box (dev-3)"]);

        let deleted_empty = client.delete_matching_devices("   ").unwrap();
        assert!(deleted_empty.is_empty());

        handle.join().unwrap();
        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 6);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].path, "/tailnet/-/devices");
        assert_eq!(reqs[1].method, "DELETE");
        assert_eq!(reqs[1].path, "/device/dev-1");
        assert_eq!(reqs[2].method, "DELETE");
        assert_eq!(reqs[2].path, "/device/dev-2");
        assert_eq!(reqs[3].method, "GET");
        assert_eq!(reqs[3].path, "/tailnet/-/devices");
        assert_eq!(reqs[4].method, "DELETE");
        assert_eq!(reqs[4].path, "/device/dev-3");
        assert_eq!(reqs[5].method, "GET");
        assert_eq!(reqs[5].path, "/tailnet/-/devices");
    }

    #[test]
    fn delete_matching_offline_devices_skips_online_devices() {
        let devices_body = r#"{
            "devices": [
                {
                    "id": "dev-online",
                    "hostname": "web-node",
                    "name": "web-node.tail1.ts.net",
                    "addresses": ["100.64.1.10"],
                    "os": "linux",
                    "online": true
                },
                {
                    "id": "dev-offline",
                    "hostname": "web-node",
                    "name": "web-node-1.tail1.ts.net",
                    "addresses": ["100.64.1.11"],
                    "os": "linux",
                    "online": false
                },
                {
                    "id": "dev-offline-other",
                    "hostname": "db-node",
                    "name": "db-node.tail1.ts.net",
                    "addresses": ["100.64.1.12"],
                    "os": "linux",
                    "online": false
                }
            ]
        }"#;
        let (base_url, recorded, handle) = spawn_mock_server(vec![
            MockResponse::json(200, "OK", devices_body),
            MockResponse::json(200, "OK", "{}"),
        ]);
        let client = TailscaleClient::with_config("ts-key", &base_url, "-").unwrap();

        let deleted = client.delete_matching_offline_devices("WEB-NODE").unwrap();
        assert_eq!(deleted, vec!["web-node (dev-offline)"]);

        handle.join().unwrap();
        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].path, "/tailnet/-/devices");
        assert_eq!(reqs[1].method, "DELETE");
        assert_eq!(reqs[1].path, "/device/dev-offline");
    }

    #[test]
    fn generate_cloud_init_with_password_sets_chpasswd_and_validates_bash() {
        let with_pw = generate_cloud_init_with_password(
            "tskey-auth-123",
            "edge-vps",
            "deploy",
            Some("  p@ss'word$(1)  "),
        );
        assert!(with_pw.contains("printf '%s:%s\\n' 'deploy' 'p@ss'\\''word$(1)' | chpasswd"));
        assert_valid_bash(&with_pw);

        let without_pw = generate_cloud_init_with_password("tskey-auth-123", "edge-vps", "deploy", None);
        assert!(!without_pw.contains("chpasswd"));
        assert_eq!(without_pw, generate_cloud_init("tskey-auth-123", "edge-vps", "deploy"));
        assert_valid_bash(&without_pw);

        let blank_pw =
            generate_cloud_init_with_password("tskey-auth-123", "edge-vps", "deploy", Some("   "));
        assert!(!blank_pw.contains("chpasswd"));
        assert_valid_bash(&blank_pw);
    }

    #[test]
    fn generate_ssh_cloud_init_with_password_sets_chpasswd_for_non_root_and_validates_bash() {
        let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey deploy@workstation";
        let with_pw = generate_ssh_cloud_init_with_password(
            pubkey,
            "ssh-vps",
            "deploy",
            Some("  s3cr'et!  "),
        );
        assert!(with_pw.contains("if [ \"$NEW_USER\" != \"root\" ]; then"));
        assert!(with_pw.contains("printf '%s:%s\\n' \"$NEW_USER\" 's3cr'\\''et!' | chpasswd"));
        assert_valid_bash(&with_pw);

        let without_pw = generate_ssh_cloud_init_with_password(pubkey, "ssh-vps", "deploy", None);
        assert!(!without_pw.contains("chpasswd"));
        assert_eq!(without_pw, generate_ssh_cloud_init(pubkey, "ssh-vps", "deploy"));
        assert_valid_bash(&without_pw);

        let blank_pw =
            generate_ssh_cloud_init_with_password(pubkey, "ssh-vps", "deploy", Some("  \t "));
        assert!(!blank_pw.contains("chpasswd"));
        assert_valid_bash(&blank_pw);
    }

    #[test]
    fn cloud_init_supports_mixed_case_usernames_and_guards_chpasswd_and_tailscale_up() {
        let with_pw = generate_cloud_init_with_password(
            "tskey-auth-123",
            "edge-vps",
            "Goobey",
            Some("MyS3cr'et!"),
        );
        assert!(with_pw.contains("if ! id -u 'Goobey' >/dev/null 2>&1; then"));
        assert!(with_pw.contains(
            "adduser --disabled-password --gecos \"\" 'Goobey' 2>/dev/null || adduser --disabled-password --allow-bad-names --gecos \"\" 'Goobey' 2>/dev/null || adduser --disabled-password --force-badname --gecos \"\" 'Goobey' 2>/dev/null || useradd --badname -m -s /bin/bash 'Goobey' 2>/dev/null || useradd -m -s /bin/bash 'Goobey' || true"
        ));
        assert!(with_pw.contains(
            "useradd -m -s /bin/bash 'Goobey' 2>/dev/null || useradd --badname -m -s /bin/bash 'Goobey' || true"
        ));
        assert!(with_pw.contains("'/etc/sudoers.d/Goobey'"));
        assert!(with_pw.contains("if id -u 'Goobey' >/dev/null 2>&1; then"));
        assert!(with_pw.contains("printf '%s:%s\\n' 'Goobey' 'MyS3cr'\\''et!' | chpasswd || true"));
        assert!(with_pw.contains(
            "tailscale up --authkey='tskey-auth-123' --ssh --hostname='edge-vps' || (sleep 3 && tailscale up --authkey='tskey-auth-123' --ssh --hostname='edge-vps')"
        ));
        assert_valid_bash(&with_pw);

        let without_pw = generate_cloud_init("tskey-auth-123", "edge-vps", "Goobey");
        assert!(!without_pw.contains("chpasswd"));
        assert!(without_pw.contains("--allow-bad-names"));
        assert!(without_pw.contains("--force-badname"));
        assert!(without_pw.contains("useradd --badname -m -s /bin/bash 'Goobey'"));
        assert!(without_pw.contains("(sleep 3 && tailscale up --authkey='tskey-auth-123' --ssh --hostname='edge-vps')"));
        assert_valid_bash(&without_pw);
    }

    #[test]
    fn ssh_cloud_init_supports_mixed_case_usernames_and_guards_chpasswd_and_chown() {
        let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey Goobey@workstation";
        let with_pw = generate_ssh_cloud_init_with_password(
            pubkey,
            "ssh-vps",
            "Goobey",
            Some("Pass'123"),
        );
        assert!(with_pw.contains("NEW_USER='Goobey'"));
        assert!(with_pw.contains(
            "useradd -m -s /bin/bash \"$NEW_USER\" 2>/dev/null || useradd --badname -m -s /bin/bash \"$NEW_USER\" 2>/dev/null || adduser --disabled-password --allow-bad-names --gecos \"\" \"$NEW_USER\" 2>/dev/null || adduser --disabled-password --force-badname --gecos \"\" \"$NEW_USER\" 2>/dev/null || adduser --disabled-password --gecos \"\" \"$NEW_USER\" 2>/dev/null || true"
        ));
        assert!(with_pw.contains("if id -u \"$NEW_USER\" >/dev/null 2>&1; then"));
        assert!(with_pw.contains("printf '%s:%s\\n' \"$NEW_USER\" 'Pass'\\''123' | chpasswd || true"));
        assert!(with_pw.contains(
            "chown -R \"${NEW_USER}:${NEW_USER}\" \"$USER_SSH_DIR\" 2>/dev/null || chown -R \"${NEW_USER}\" \"$USER_SSH_DIR\" || true"
        ));
        assert!(!with_pw.to_ascii_lowercase().contains("tailscale"));
        assert_valid_bash(&with_pw);

        let without_pw = generate_ssh_cloud_init(pubkey, "ssh-vps", "Goobey");
        assert!(!without_pw.contains("chpasswd"));
        assert!(without_pw.contains("--allow-bad-names"));
        assert!(without_pw.contains("--force-badname"));
        assert_valid_bash(&without_pw);
    }
}
