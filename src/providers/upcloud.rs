// src/providers/upcloud.rs
// UpCloud provider implementation for bab.

use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, USER_AGENT};
use serde::{Deserialize, Deserializer};
use std::env;

use super::{
    ProviderKind, ProviderRegion, ProviderPlan, ProviderImage, CreateInstanceRequest, InstanceStatus,
    VpsProvider,
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
        // Determine public IPv4, falling back to any IPv4.
        let mut public_ipv4: Option<String> = None;
        let mut any_ipv4: Option<String> = None;
        for ip in server.ip_addresses.ip_address {
            if ip.family == "IPv4" {
                any_ipv4 = Some(ip.address.clone());
                if ip.access == "public" && public_ipv4.is_none() {
                    public_ipv4 = Some(ip.address.clone());
                }
            }
        }
        let ready = server.state == "started";
        Ok(InstanceStatus {
            state: server.state,
            public_ipv4: public_ipv4.or(any_ipv4),
            ready,
        })
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
}
