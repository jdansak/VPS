// src/providers/upcloud.rs
// UpCloud provider implementation for bab.

use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, USER_AGENT};
use serde::{Deserialize, Deserializer};
use std::env;
use std::time::Duration;

use super::{
    non_empty_trimmed, validate_instance_id, CreateInstanceRequest, InstanceStatus, ProviderImage,
    ProviderInstance, ProviderKind, ProviderPlan, ProviderRegion, VpsProvider,
};

/// UpCloud API client.
pub struct UpCloudProvider {
    api_token: String,
    base_url: String,
    http: Client,
}

impl UpCloudProvider {
    /// Construct a new provider, reading the base URL from the `UPCLOUD_API_BASE`
    /// environment variable (defaulting to "https://api.upcloud.com/1.3").
    pub fn new(api_token: impl Into<String>) -> Result<Self> {
        let base = env::var("UPCLOUD_API_BASE")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "https://api.upcloud.com/1.3".to_string());
        Self::with_base_url(api_token, base)
    }

    /// Construct a new provider with an explicit base URL.
    pub fn with_base_url(api_token: impl Into<String>, base_url: impl Into<String>) -> Result<Self> {
        let api_token = api_token.into();
        let base_url = base_url.into();
        // Build a client with a generic User-Agent; authentication is added per request.
        let mut headers = HeaderMap::new();
        headers.insert(USER_AGENT, "bab/0.1".parse()?);
        let http = Client::builder().default_headers(headers).build()?;
        Ok(Self { api_token, base_url, http })
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    /// Apply authentication (basic or bearer) to a request builder.
    fn apply_auth(&self, builder: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
        if self.api_token.contains(':') {
            // Basic auth expects "user:pass"
            let (user, pass) = self.api_token.split_once(':').unwrap();
            builder.basic_auth(user, Some(pass))
        } else {
            builder.bearer_auth(&self.api_token)
        }
    }
}

fn deserialize_null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: Deserializer<'de>,
{
    let opt = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

// --- Response structs -----------------------------------------------------

#[derive(Deserialize)]
struct AccountResponse {
    account: serde_json::Value,
}

#[derive(Deserialize)]
struct ZonesResponse {
    zones: Zones,
}

#[derive(Deserialize)]
struct Zones {
    zone: Vec<ZoneItem>,
}

#[derive(Deserialize)]
struct ZoneItem {
    id: String,
    #[serde(default)]
    description: String,
}

#[derive(Deserialize)]
struct PlansResponse {
    plans: Plans,
}

#[derive(Deserialize)]
struct Plans {
    plan: Vec<PlanItem>,
}

#[derive(Deserialize)]
struct PlanItem {
    name: String,
    core_number: u32,
    memory_amount: u32,
    storage_size: u32,
}

#[derive(Deserialize)]
struct StoragesResponse {
    storages: Storages,
}

#[derive(Deserialize)]
struct Storages {
    storage: Vec<StorageItem>,
}

#[derive(Deserialize)]
struct StorageItem {
    uuid: String,
    title: String,
}

#[derive(Deserialize)]
struct CreateServerResponse {
    server: ServerCreated,
}

#[derive(Deserialize)]
struct ServerCreated {
    uuid: String,
}

#[derive(Deserialize)]
struct ServerDetailResponse {
    server: ServerDetail,
}

#[derive(Deserialize)]
struct ServerDetail {
    state: String,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    ip_addresses: IpAddresses,
}

#[derive(Deserialize, Default)]
struct IpAddresses {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    ip_address: Vec<IpAddress>,
}

#[derive(Deserialize)]
struct IpAddress {
    #[serde(default)]
    family: String,
    #[serde(default)]
    access: String,
    address: String,
}

#[derive(Deserialize)]
struct ListServersResponse {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    servers: ServersList,
}

#[derive(Deserialize, Default)]
struct ServersList {
    #[serde(default, deserialize_with = "deserialize_null_default")]
    server: Vec<ServerListItem>,
}

#[derive(Deserialize)]
struct ServerListItem {
    uuid: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    zone: String,
    #[serde(default)]
    plan: String,
    #[serde(default)]
    created: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "deserialize_null_default")]
    ip_addresses: IpAddresses,
}

fn extract_public_ipv4(ip_addresses: &IpAddresses) -> Option<String> {
    let mut public_ipv4: Option<String> = None;
    let mut any_ipv4: Option<String> = None;
    for ip in &ip_addresses.ip_address {
        if ip.family == "IPv4" {
            let Some(addr) = non_empty_trimmed(&ip.address) else {
                continue;
            };
            if any_ipv4.is_none() {
                any_ipv4 = Some(addr.clone());
            }
            if ip.access == "public" && public_ipv4.is_none() {
                public_ipv4 = Some(addr);
            }
        }
    }
    public_ipv4.or(any_ipv4)
}

fn json_value_to_opt_string(val: Option<&serde_json::Value>) -> Option<String> {
    match val? {
        serde_json::Value::String(s) => non_empty_trimmed(s),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

impl VpsProvider for UpCloudProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::UpCloud
    }

    fn validate_key(&self) -> Result<bool> {
        let url = self.url("account");
        let resp = self.apply_auth(self.http.get(&url)).send()?;
        let status = resp.status();
        match status.as_u16() {
            200..=299 => {
                let data: AccountResponse = resp.json()?;
                Ok(!data.account.is_null())
            }
            401 | 403 => Ok(false),
            _ => {
                let body = resp.text().unwrap_or_default();
                Err(anyhow!(
                    "Unexpected status {} when validating UpCloud API token: {}",
                    status,
                    body
                ))
            }
        }
    }

    fn list_regions(&self) -> Result<Vec<ProviderRegion>> {
        let url = self.url("zone");
        let resp = self.apply_auth(self.http.get(&url)).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to list regions ({}): {}", status, body));
        }
        let data: ZonesResponse = resp.json()?;
        let regions = data
            .zones
            .zone
            .into_iter()
            .map(|z| ProviderRegion {
                id: z.id,
                name: z.description,
                country: "".to_string(),
            })
            .collect();
        Ok(regions)
    }

    fn list_plans(&self) -> Result<Vec<ProviderPlan>> {
        let url = self.url("plan");
        let resp = self.apply_auth(self.http.get(&url)).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to list plans ({}): {}", status, body));
        }
        let data: PlansResponse = resp.json()?;
        let plans = data
            .plans
            .plan
            .into_iter()
            .map(|p| ProviderPlan {
                id: p.name,
                summary: format!(
                    "{}vCPU {}MB {}GB",
                    p.core_number, p.memory_amount, p.storage_size
                ),
            })
            .collect();
        Ok(plans)
    }

    fn list_images(&self) -> Result<Vec<ProviderImage>> {
        let url = self.url("storage/template");
        let resp = self.apply_auth(self.http.get(&url)).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to list images ({}): {}", status, body));
        }
        let data: StoragesResponse = resp.json()?;
        let allowed_keywords = [
            "ubuntu",
            "debian",
            "alma",
            "rocky",
            "fedora",
            "centos",
        ];
        let images = data
            .storages
            .storage
            .into_iter()
            .filter(|s| {
                let low = s.title.to_ascii_lowercase();
                allowed_keywords.iter().any(|kw| low.contains(kw))
            })
            .map(|s| ProviderImage {
                id: s.uuid,
                name: s.title,
                vendor: "upcloud".to_string(),
            })
            .collect();
        Ok(images)
    }

    fn create_instance(&self, req: &CreateInstanceRequest) -> Result<String> {
        let payload = serde_json::json!({
            "server": {
                "zone": req.region,
                "title": req.hostname,
                "hostname": req.hostname,
                "plan": req.plan,
                "user_data": req.user_data_raw,
                "login_user": { "create_password": "no" },
                "storage_devices": {
                    "storage_device": [{
                        "action": "clone",
                        "storage": req.image_id,
                        "title": format!("{}-disk", req.hostname),
                        "size": 25,
                        "tier": "maxiops"
                    }]
                }
            }
        });
        let url = self.url("server");
        let resp = self
            .apply_auth(self.http.post(&url))
            .json(&payload)
            .send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to create instance ({}): {}", status, body));
        }
        let data: CreateServerResponse = resp.json()?;
        Ok(data.server.uuid)
    }

    fn get_instance_status(&self, instance_id: &str) -> Result<InstanceStatus> {
        let url = self.url(&format!("server/{}", instance_id));
        let resp = self.apply_auth(self.http.get(&url)).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to get instance status ({}): {}", status, body));
        }
        let data: ServerDetailResponse = resp.json()?;
        let server = data.server;
        let public_ipv4 = extract_public_ipv4(&server.ip_addresses);
        let ready = server.state == "started";
        Ok(InstanceStatus {
            state: server.state,
            public_ipv4,
            ready,
        })
    }

    fn list_instances(&self) -> Result<Vec<ProviderInstance>> {
        let url = self.url("server");
        let resp = self.apply_auth(self.http.get(&url)).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!(
                "Failed to list UpCloud servers ({}): {}",
                status,
                body
            ));
        }
        let data: ListServersResponse = resp.json()?;
        let mut instances = Vec::with_capacity(data.servers.server.len());
        for item in data.servers.server {
            let name = non_empty_trimmed(&item.title)
                .or_else(|| non_empty_trimmed(&item.hostname))
                .unwrap_or_else(|| item.uuid.clone());
            let mut state = item.state;
            let public_ip = if item.ip_addresses.ip_address.is_empty() {
                match self.get_instance_status(&item.uuid) {
                    Ok(detail) => {
                        if state.trim().is_empty() {
                            state = detail.state;
                        }
                        detail.public_ipv4
                    }
                    Err(_) => None,
                }
            } else {
                extract_public_ipv4(&item.ip_addresses)
            };
            let status_str = non_empty_trimmed(&state).unwrap_or_else(|| "unknown".to_string());
            instances.push(ProviderInstance {
                provider: ProviderKind::UpCloud,
                id: item.uuid,
                name,
                status: status_str,
                public_ip,
                region: non_empty_trimmed(&item.zone),
                plan: non_empty_trimmed(&item.plan),
                created_at: json_value_to_opt_string(item.created.as_ref()),
            });
        }
        Ok(instances)
    }

    fn destroy_instance(&self, instance_id: &str) -> Result<()> {
        let id = validate_instance_id(instance_id)?;
        let delete_url = self.url(&format!("server/{}?storages=1", id));
        let resp = self.apply_auth(self.http.delete(&delete_url)).send()?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        if status.as_u16() != 409 {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!(
                "Failed to destroy UpCloud server {} ({}): {}",
                id,
                status,
                body
            ));
        }

        // Running UpCloud servers return 409 Conflict until stopped.
        let stop_url = self.url(&format!("server/{}/stop", id));
        let stop_payload = serde_json::json!({
            "stop_server": {
                "stop_type": "hard",
                "timeout": "60"
            }
        });
        let stop_resp = self
            .apply_auth(self.http.post(&stop_url))
            .json(&stop_payload)
            .send()?;
        let stop_status = stop_resp.status();
        if !stop_status.is_success() && stop_status.as_u16() != 409 {
            let body = stop_resp.text().unwrap_or_default();
            return Err(anyhow!(
                "Failed to stop UpCloud server {} before destroy ({}): {}",
                id,
                stop_status,
                body
            ));
        }

        let retry_delays = [
            Duration::ZERO,
            Duration::from_millis(50),
            Duration::from_millis(100),
            Duration::from_millis(200),
            Duration::from_millis(400),
            Duration::from_millis(800),
            Duration::from_millis(1000),
        ];
        let mut last_status = status;
        let mut last_body = String::new();

        for delay in retry_delays {
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            let retry_resp = self.apply_auth(self.http.delete(&delete_url)).send()?;
            let retry_status = retry_resp.status();
            if retry_status.is_success() {
                return Ok(());
            }
            let retry_body = retry_resp.text().unwrap_or_default();
            if retry_status.as_u16() != 409 {
                return Err(anyhow!(
                    "Failed to destroy UpCloud server {} ({}): {}",
                    id,
                    retry_status,
                    retry_body
                ));
            }
            last_status = retry_status;
            last_body = retry_body;
        }

        Err(anyhow!(
            "Failed to destroy UpCloud server {} after stopping ({}): {}",
            id,
            last_status,
            last_body
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_detail_handles_missing_empty_and_null_ip_addresses() {
        let missing: ServerDetailResponse =
            serde_json::from_str(r#"{"server":{"state":"maintenance"}}"#).unwrap();
        assert_eq!(missing.server.state, "maintenance");
        assert!(missing.server.ip_addresses.ip_address.is_empty());

        let empty: ServerDetailResponse =
            serde_json::from_str(r#"{"server":{"state":"maintenance","ip_addresses":{}}}"#).unwrap();
        assert!(empty.server.ip_addresses.ip_address.is_empty());

        let null_ips: ServerDetailResponse =
            serde_json::from_str(r#"{"server":{"state":"maintenance","ip_addresses":null}}"#).unwrap();
        assert!(null_ips.server.ip_addresses.ip_address.is_empty());
    }

    #[test]
    fn extract_public_ipv4_prefers_public_then_falls_back_to_any_ipv4() {
        let ips = IpAddresses {
            ip_address: vec![
                IpAddress {
                    family: "IPv6".into(),
                    access: "public".into(),
                    address: "2001:db8::1".into(),
                },
                IpAddress {
                    family: "IPv4".into(),
                    access: "private".into(),
                    address: "10.0.0.5".into(),
                },
                IpAddress {
                    family: "IPv4".into(),
                    access: "public".into(),
                    address: "203.0.113.5".into(),
                },
            ],
        };
        assert_eq!(extract_public_ipv4(&ips).as_deref(), Some("203.0.113.5"));

        let private_only = IpAddresses {
            ip_address: vec![IpAddress {
                family: "IPv4".into(),
                access: "private".into(),
                address: "10.0.0.5".into(),
            }],
        };
        assert_eq!(
            extract_public_ipv4(&private_only).as_deref(),
            Some("10.0.0.5")
        );
    }

    #[test]
    fn list_instances_falls_back_to_detail_when_ip_addresses_omitted() -> Result<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let handle = thread::spawn(move || {
            let mut seen_paths = Vec::new();
            for _ in 0..2 {
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
                let path = req_line.split_whitespace().nth(1).unwrap_or("").to_string();
                let body = if path == "/1.3/server" {
                    r#"{
                        "servers": {
                            "server": [
                                {
                                    "uuid": "uc-1",
                                    "title": "",
                                    "hostname": "uc-host-1",
                                    "state": "started",
                                    "zone": "de-fra1",
                                    "plan": "1xCPU-1GB"
                                },
                                {
                                    "uuid": "uc-2",
                                    "title": "My Box 2",
                                    "hostname": "uc-host-2",
                                    "state": "stopped",
                                    "zone": "us-nyc1",
                                    "plan": "2xCPU-4GB",
                                    "ip_addresses": {
                                        "ip_address": [
                                            {"access": "public", "address": "198.51.100.22", "family": "IPv4"}
                                        ]
                                    }
                                }
                            ]
                        }
                    }"#
                } else if path == "/1.3/server/uc-1" {
                    r#"{
                        "server": {
                            "state": "started",
                            "ip_addresses": {
                                "ip_address": [
                                    {"access": "private", "address": "10.0.0.8", "family": "IPv4"},
                                    {"access": "public", "address": "203.0.113.88", "family": "IPv4"}
                                ]
                            }
                        }
                    }"#
                } else {
                    "{}"
                };
                seen_paths.push(path);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
            seen_paths
        });

        let provider = UpCloudProvider::with_base_url("user:pass", format!("http://{}/1.3", addr))?;
        let instances = provider.list_instances()?;
        let seen_paths = handle.join().unwrap();

        assert_eq!(seen_paths, vec!["/1.3/server", "/1.3/server/uc-1"]);
        assert_eq!(instances.len(), 2);
        assert_eq!(instances[0].id, "uc-1");
        assert_eq!(instances[0].name, "uc-host-1");
        assert_eq!(instances[0].public_ip.as_deref(), Some("203.0.113.88"));
        assert_eq!(instances[0].region.as_deref(), Some("de-fra1"));
        assert_eq!(instances[0].plan.as_deref(), Some("1xCPU-1GB"));

        assert_eq!(instances[1].id, "uc-2");
        assert_eq!(instances[1].name, "My Box 2");
        assert_eq!(instances[1].public_ip.as_deref(), Some("198.51.100.22"));
        Ok(())
    }

    #[test]
    fn destroy_instance_stops_and_retries_on_409_conflict() -> Result<()> {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for step in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                reader.read_line(&mut req_line).unwrap();
                let mut content_len = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let trimmed = line.trim_end_matches(['\r', '\n']);
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let mut body_buf = vec![0u8; content_len];
                if content_len > 0 {
                    reader.read_exact(&mut body_buf).unwrap();
                }
                let req_body = String::from_utf8_lossy(&body_buf).to_string();
                requests.push((req_line.trim().to_string(), req_body));

                let (status_line, resp_body) = match step {
                    0 => ("409 Conflict", r#"{"error":{"error_code":"SERVER_STATE_ILLEGAL"}}"#),
                    1 => ("200 OK", r#"{"server":{"state":"stopped"}}"#),
                    _ => ("204 No Content", ""),
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status_line,
                    resp_body.len(),
                    resp_body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
            requests
        });

        let provider = UpCloudProvider::with_base_url("uc-token", format!("http://{}/1.3", addr))?;
        assert!(provider.destroy_instance("bad/id").is_err());
        provider.destroy_instance("uc-uuid-99")?;

        let requests = handle.join().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[0]
            .0
            .starts_with("DELETE /1.3/server/uc-uuid-99?storages=1 "));
        assert!(requests[1]
            .0
            .starts_with("POST /1.3/server/uc-uuid-99/stop "));
        let stop_json: serde_json::Value = serde_json::from_str(&requests[1].1)?;
        assert_eq!(stop_json["stop_server"]["stop_type"], "hard");
        assert_eq!(stop_json["stop_server"]["timeout"], "60");
        assert!(requests[2]
            .0
            .starts_with("DELETE /1.3/server/uc-uuid-99?storages=1 "));
        Ok(())
    }
}
