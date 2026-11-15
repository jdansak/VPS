// src/providers/linode.rs
// Linode provider implementation for bab.

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, AUTHORIZATION, USER_AGENT};
use serde::Deserialize;
use std::env;

use super::{
    non_empty_trimmed, validate_instance_id, CreateInstanceRequest, InstanceStatus, ProviderImage,
    ProviderInstance, ProviderKind, ProviderPlan, ProviderRegion, VpsProvider,
};

/// Linode API client.
pub struct LinodeProvider {
    base_url: String,
    http: Client,
}

impl LinodeProvider {
    /// Construct a new provider, reading the base URL from the `LINODE_API_BASE`
    /// environment variable (defaulting to "https://api.linode.com/v4").
    pub fn new(api_token: impl Into<String>) -> Result<Self> {
        let base = env::var("LINODE_API_BASE")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "https://api.linode.com/v4".to_string());
        Self::with_base_url(api_token, base)
    }

    /// Construct a new provider with an explicit base URL.
    pub fn with_base_url(api_token: impl Into<String>, base_url: impl Into<String>) -> Result<Self> {
        let api_token = api_token.into();
        let base_url = base_url.into();
        let mut headers = HeaderMap::new();
        let bearer = format!("Bearer {}", api_token);
        headers.insert(AUTHORIZATION, bearer.parse()?);
        // optional user‑agent for debugging / consistency with other providers
        headers.insert(USER_AGENT, "bab/0.1".parse()?);
        let http = Client::builder().default_headers(headers).build()?;
        Ok(Self { base_url, http })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), path.trim_start_matches('/'))
    }
}

// ---------- Response structs matching Linode API ----------
#[derive(Deserialize)]
struct ProfileResponse {
    username: String,
}

#[derive(Deserialize)]
struct RegionsResponse {
    data: Vec<RegionItem>,
}

#[derive(Deserialize)]
struct RegionItem {
    id: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    country: String,
}

#[derive(Deserialize)]
struct TypesResponse {
    data: Vec<TypeItem>,
}

#[derive(Deserialize)]
struct TypeItem {
    id: String,
    label: String,
    #[serde(default)]
    vcpus: u32,
    #[serde(default)]
    memory: u32,
    #[serde(default)]
    disk: u32,
    #[serde(default)]
    price: PriceInfo,
}

#[derive(Deserialize, Default)]
struct PriceInfo {
    #[serde(default)]
    monthly: Option<f64>,
}

#[derive(Deserialize)]
struct ImagesResponse {
    data: Vec<ImageItem>,
}

#[derive(Deserialize)]
struct ImageItem {
    id: String,
    label: String,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    is_public: bool,
}

#[derive(Deserialize)]
struct CreateInstanceResponse {
    id: serde_json::Value,
}

#[derive(Deserialize)]
struct InstanceDetailResponse {
    #[serde(default)]
    id: Option<serde_json::Value>,
    status: String,
    #[serde(default)]
    ipv4: Vec<String>,
}

fn default_one() -> u32 {
    1
}

#[derive(Deserialize)]
struct ListInstancesResponse {
    #[serde(default)]
    data: Vec<LinodeInstanceItem>,
    #[serde(default = "default_one")]
    pages: u32,
}

#[derive(Deserialize)]
struct LinodeInstanceItem {
    id: serde_json::Value,
    #[serde(default)]
    label: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    ipv4: Vec<String>,
    #[serde(default)]
    region: String,
    #[serde(default, rename = "type")]
    linode_type: String,
    #[serde(default)]
    created: String,
}

fn id_to_string(val: &serde_json::Value) -> Result<String> {
    if let Some(s) = val.as_str() {
        non_empty_trimmed(s).ok_or_else(|| anyhow!("Unexpected empty instance ID"))
    } else if let Some(i) = val.as_i64() {
        Ok(i.to_string())
    } else if let Some(u) = val.as_u64() {
        Ok(u.to_string())
    } else {
        Err(anyhow!("Unexpected instance ID format"))
    }
}

fn first_public_ipv4(ips: &[String]) -> Option<String> {
    ips.iter()
        .map(|s| s.trim())
        .find(|s| {
            s.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| {
                !ip.is_private()
                    && !ip.is_loopback()
                    && !ip.is_link_local()
                    && !ip.is_unspecified()
            })
        })
        .map(String::from)
}

impl VpsProvider for LinodeProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Linode
    }

    fn validate_key(&self) -> Result<bool> {
        let url = self.url("profile");
        let resp = self.http.get(&url).send()?;
        let status = resp.status();
        match status.as_u16() {
            200..=299 => {
                let profile: ProfileResponse = resp.json()?;
                Ok(!profile.username.is_empty())
            }
            401 | 403 => Ok(false),
            _ => {
                let body = resp.text().unwrap_or_default();
                Err(anyhow!(
                    "Unexpected status {} when validating Linode API token: {}",
                    status,
                    body
                ))
            }
        }
    }

    fn list_regions(&self) -> Result<Vec<ProviderRegion>> {
        let url = self.url("regions");
        let resp = self.http.get(&url).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to list regions ({}): {}", status, body));
        }
        let data: RegionsResponse = resp.json()?;
        let regions = data
            .data
            .into_iter()
            .map(|r| ProviderRegion {
                id: r.id,
                name: r.label,
                country: r.country,
            })
            .collect();
        Ok(regions)
    }

    fn list_plans(&self) -> Result<Vec<ProviderPlan>> {
        let url = self.url("linode/types");
        let resp = self.http.get(&url).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to list plans ({}): {}", status, body));
        }
        let data: TypesResponse = resp.json()?;
        let plans = data
            .data
            .into_iter()
            .map(|p| {
                let price_str = match p.price.monthly {
                    Some(m) => format!("${}/mo", m),
                    None => "N/A".to_string(),
                };
                ProviderPlan {
                    id: p.id,
                    summary: format!(
                        "{} ({}vCPU {}MB {}MB {})",
                        p.label, p.vcpus, p.memory, p.disk, price_str
                    ),
                }
            })
            .collect();
        Ok(plans)
    }

    fn list_images(&self) -> Result<Vec<ProviderImage>> {
        let url = self.url("images");
        let resp = self.http.get(&url).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to list images ({}): {}", status, body));
        }
        let data: ImagesResponse = resp.json()?;
        let allowed = [
            "ubuntu",
            "debian",
            "almalinux",
            "rocky",
            "fedora",
            "centos",
        ];
        let images = data
            .data
            .into_iter()
            .filter(|i| i.is_public && allowed.iter().any(|kw| i.label.to_ascii_lowercase().contains(kw)))
            .map(|i| ProviderImage {
                id: i.id,
                name: i.label,
                vendor: i.vendor.unwrap_or_default(),
            })
            .collect();
        Ok(images)
    }

    fn create_instance(&self, req: &CreateInstanceRequest) -> Result<String> {
        // Encode user data as base64.
        let b64_user_data = BASE64_STANDARD.encode(&req.user_data_raw);

        // Generate a random root password (32 alphanumeric chars + a fixed suffix for complexity).
        let mut rng = thread_rng();
        let pwd: String = (&mut rng)
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        let root_pass = format!("{}!A1a", pwd);

        let payload = serde_json::json!({
            "region": req.region,
            "type": req.plan,
            "image": req.image_id,
            "label": req.hostname,
            "root_pass": root_pass,
            "booted": true,
            "metadata": { "user_data": b64_user_data },
        });

        let url = self.url("linode/instances");
        let resp = self.http.post(&url).json(&payload).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to create instance ({}): {}", status, body));
        }
        let data: CreateInstanceResponse = resp.json()?;
        id_to_string(&data.id)
    }

    fn get_instance_status(&self, instance_id: &str) -> Result<InstanceStatus> {
        let url = self.url(&format!("linode/instances/{}", instance_id));
        let resp = self.http.get(&url).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to get instance status ({}): {}", status, body));
        }
        let data: InstanceDetailResponse = resp.json()?;
        if let Some(ref id_val) = data.id {
            let _ = id_to_string(id_val)?;
        }
        let ready = data.status == "running";
        let public_ipv4 = first_public_ipv4(&data.ipv4).or_else(|| data.ipv4.into_iter().next());
        Ok(InstanceStatus {
            state: data.status,
            public_ipv4,
            ready,
        })
    }

    fn list_instances(&self) -> Result<Vec<ProviderInstance>> {
        const MAX_PAGES: u32 = 20;
        let mut instances = Vec::new();
        let mut page = 1u32;

        loop {
            let url = self.url("linode/instances");
            let page_str = page.to_string();
            let resp = self
                .http
                .get(&url)
                .query(&[("page", page_str.as_str()), ("page_size", "500")])
                .send()?;
            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().unwrap_or_default();
                return Err(anyhow!(
                    "Failed to list Linode instances ({}): {}",
                    status,
                    body
                ));
            }
            let data: ListInstancesResponse = resp.json()?;
            for item in data.data {
                let id = id_to_string(&item.id)?;
                let name = non_empty_trimmed(&item.label).unwrap_or_else(|| id.clone());
                let status_str =
                    non_empty_trimmed(&item.status).unwrap_or_else(|| "unknown".to_string());
                instances.push(ProviderInstance {
                    provider: ProviderKind::Linode,
                    id,
                    name,
                    status: status_str,
                    public_ip: first_public_ipv4(&item.ipv4),
                    region: non_empty_trimmed(&item.region),
                    plan: non_empty_trimmed(&item.linode_type),
                    created_at: non_empty_trimmed(&item.created),
                });
            }
            if page >= data.pages.max(1) || page >= MAX_PAGES {
                break;
            }
            page += 1;
        }

        Ok(instances)
    }

    fn destroy_instance(&self, instance_id: &str) -> Result<()> {
        let id = validate_instance_id(instance_id)?;
        let url = self.url(&format!("linode/instances/{}", id));
        let resp = self.http.delete(&url).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!(
                "Failed to destroy Linode instance {} ({}): {}",
                id,
                status,
                body
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn images_and_types_handle_missing_or_null_fields() {
        let img_raw = r#"{
            "data": [
                {"id": "linode/ubuntu24.04", "label": "Ubuntu 24.04 LTS", "vendor": null, "is_public": true},
                {"id": "linode/debian12", "label": "Debian 12", "is_public": true}
            ]
        }"#;
        let imgs: ImagesResponse = serde_json::from_str(img_raw).unwrap();
        assert_eq!(imgs.data[0].vendor, None);
        assert_eq!(imgs.data[1].vendor, None);

        let types_raw = r#"{
            "data": [
                {"id": "g6-nanode-1", "label": "Nanode 1GB", "vcpus": 1, "memory": 1024, "disk": 25600, "price": {"monthly": null}},
                {"id": "g6-standard-1", "label": "Linode 2GB", "vcpus": 1, "memory": 2048, "disk": 51200, "price": {}}
            ]
        }"#;
        let types: TypesResponse = serde_json::from_str(types_raw).unwrap();
        assert_eq!(types.data[0].price.monthly, None);
        assert_eq!(types.data[1].price.monthly, None);
    }

    #[test]
    fn id_to_string_handles_numeric_and_string_ids() {
        assert_eq!(id_to_string(&serde_json::json!(12345)).unwrap(), "12345");
        assert_eq!(id_to_string(&serde_json::json!(" 987 ")).unwrap(), "987");
        assert!(id_to_string(&serde_json::json!("")).is_err());
        assert!(id_to_string(&serde_json::json!(null)).is_err());
    }

    #[test]
    fn list_instances_paginates_and_selects_first_public_ipv4() -> Result<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let handle = thread::spawn(move || {
            let mut seen_paths = Vec::new();
            for page_idx in 0..2 {
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
                seen_paths.push(path);
                let body = if page_idx == 0 {
                    r#"{
                        "data": [
                            {
                                "id": 1001,
                                "label": "web-1",
                                "status": "running",
                                "ipv4": ["192.168.133.5", "203.0.113.10"],
                                "region": "us-east",
                                "type": "g6-nanode-1",
                                "created": "2025-01-01T12:00:00"
                            }
                        ],
                        "page": 1,
                        "pages": 2
                    }"#
                } else {
                    r#"{
                        "data": [
                            {
                                "id": "1002",
                                "label": "",
                                "status": "offline",
                                "ipv4": ["10.0.0.5"],
                                "region": "eu-central",
                                "type": "g6-standard-1",
                                "created": "2025-01-02T12:00:00"
                            }
                        ],
                        "page": 2,
                        "pages": 2
                    }"#
                };
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

        let provider = LinodeProvider::with_base_url("linode-tok", format!("http://{}/v4", addr))?;
        let instances = provider.list_instances()?;
        let seen_paths = handle.join().unwrap();

        assert_eq!(seen_paths[0], "/v4/linode/instances?page=1&page_size=500");
        assert_eq!(seen_paths[1], "/v4/linode/instances?page=2&page_size=500");
        assert_eq!(instances.len(), 2);

        assert_eq!(instances[0].id, "1001");
        assert_eq!(instances[0].name, "web-1");
        assert_eq!(instances[0].status, "running");
        assert_eq!(instances[0].public_ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(instances[0].region.as_deref(), Some("us-east"));
        assert_eq!(instances[0].plan.as_deref(), Some("g6-nanode-1"));
        assert_eq!(
            instances[0].created_at.as_deref(),
            Some("2025-01-01T12:00:00")
        );

        assert_eq!(instances[1].id, "1002");
        assert_eq!(instances[1].name, "1002");
        assert_eq!(instances[1].public_ip, None);
        Ok(())
    }

    #[test]
    fn destroy_instance_validates_id_and_sends_delete() -> Result<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let handle = thread::spawn(move || {
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
            let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}";
            stream.write_all(resp.as_bytes()).unwrap();
            stream.flush().unwrap();
            req_line
        });

        let provider = LinodeProvider::with_base_url("linode-tok", format!("http://{}/v4", addr))?;
        assert!(provider.destroy_instance("123?foo=bar").is_err());
        provider.destroy_instance(" 12345 ")?;

        let req_line = handle.join().unwrap();
        assert!(req_line.starts_with("DELETE /v4/linode/instances/12345 "));
        Ok(())
    }
}
