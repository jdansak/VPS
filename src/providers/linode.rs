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
    ProviderKind, ProviderRegion, ProviderPlan, ProviderImage, CreateInstanceRequest, InstanceStatus,
    VpsProvider,
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
    status: String,
    #[serde(default)]
    ipv4: Vec<String>,
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
        // The `id` field may be numeric or string.
        let id_str = if let Some(s) = data.id.as_str() {
            s.to_string()
        } else if let Some(i) = data.id.as_i64() {
            i.to_string()
        } else if let Some(u) = data.id.as_u64() {
            u.to_string()
        } else {
            return Err(anyhow!("Unexpected instance ID format"));
        };
        Ok(id_str)
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
        let ready = data.status == "running";
        let public_ipv4 = data.ipv4.into_iter().next();
        Ok(InstanceStatus {
            state: data.status,
            public_ipv4,
            ready,
        })
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
}
