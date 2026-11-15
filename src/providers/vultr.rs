// src/providers/vultr.rs
// Vultr provider implementation for bab.

use anyhow::{anyhow, Result};
use base64::Engine;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Deserializer};
use std::env;
use std::str::FromStr;

use super::{
    ProviderKind, ProviderRegion, ProviderPlan, ProviderImage, CreateInstanceRequest, InstanceStatus,
    VpsProvider,
};

/// Vultr API client.
pub struct VultrProvider {
    base_url: String,
    http: Client,
}

impl VultrProvider {
    /// Construct a new provider, reading the base URL from the `VULTR_API_BASE`
    /// environment variable (defaulting to "https://api.vultr.com/v2").
    pub fn new(api_key: impl Into<String>) -> Result<Self> {
        let base = env::var("VULTR_API_BASE")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "https://api.vultr.com/v2".to_string());
        Self::with_base_url(api_key, base)
    }

    /// Construct a new provider with an explicit base URL.
    pub fn with_base_url(api_key: impl Into<String>, base_url: impl Into<String>) -> Result<Self> {
        let api_key = api_key.into();
        let base_url = base_url.into();
        let mut headers = HeaderMap::new();
        let bearer = format!("Bearer {}", api_key);
        headers.insert(AUTHORIZATION, bearer.parse()?);
        headers.insert(USER_AGENT, "bab/0.1".parse()?);
        let http = Client::builder().default_headers(headers).build()?;
        Ok(Self { base_url, http })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base_url.trim_end_matches('/'), path.trim_start_matches('/'))
    }
}

fn deserialize_flexible_f64<'de, D>(deserializer: D) -> std::result::Result<f64, D::Error>
where
    D: Deserializer<'de>,
{
    let val = Option::<serde_json::Value>::deserialize(deserializer)?;
    match val {
        None | Some(serde_json::Value::Null) => Ok(0.0),
        Some(serde_json::Value::Number(n)) => n
            .as_f64()
            .ok_or_else(|| serde::de::Error::custom("invalid numeric value")),
        Some(serde_json::Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(0.0)
            } else {
                trimmed
                    .parse::<f64>()
                    .map_err(|_| serde::de::Error::custom("invalid numeric string"))
            }
        }
        Some(other) => Err(serde::de::Error::custom(format!(
            "expected number or string, got {}",
            other
        ))),
    }
}

fn deserialize_flexible_u32<'de, D>(deserializer: D) -> std::result::Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let val = Option::<serde_json::Value>::deserialize(deserializer)?;
    match val {
        None | Some(serde_json::Value::Null) => Ok(0),
        Some(serde_json::Value::Number(n)) => {
            if let Some(u) = n.as_u64() {
                u32::try_from(u).map_err(|_| serde::de::Error::custom("u32 overflow"))
            } else if let Some(f) = n.as_f64() {
                if f.is_finite() && f >= 0.0 && f <= u32::MAX as f64 {
                    Ok(f as u32)
                } else {
                    Err(serde::de::Error::custom("u32 out of range"))
                }
            } else {
                Err(serde::de::Error::custom("invalid u32 number"))
            }
        }
        Some(serde_json::Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                Ok(0)
            } else {
                trimmed
                    .parse::<u32>()
                    .map_err(|_| serde::de::Error::custom("invalid u32 string"))
            }
        }
        Some(other) => Err(serde::de::Error::custom(format!(
            "expected integer or string, got {}",
            other
        ))),
    }
}

#[derive(Deserialize)]
struct AccountResponse {
    account: serde_json::Value,
}

#[derive(Deserialize)]
struct RegionsResponse {
    regions: Vec<RegionItem>,
}

#[derive(Deserialize)]
struct RegionItem {
    id: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    country: String,
}

#[derive(Deserialize)]
struct PlansResponse {
    plans: Vec<PlanItem>,
}

#[derive(Deserialize)]
struct PlanItem {
    id: String,
    #[serde(default, deserialize_with = "deserialize_flexible_u32")]
    vcpu_count: u32,
    #[serde(default, deserialize_with = "deserialize_flexible_u32")]
    ram: u32,
    #[serde(default, deserialize_with = "deserialize_flexible_u32")]
    disk: u32,
    #[serde(default, deserialize_with = "deserialize_flexible_f64")]
    monthly_cost: f64,
}

#[derive(Deserialize)]
struct OsResponse {
    os: Vec<OsItem>,
}

#[derive(Deserialize)]
struct OsItem {
    id: serde_json::Value,
    name: String,
    #[serde(default)]
    family: String,
}

impl OsItem {
    fn id_string(&self) -> Result<String> {
        if let Some(s) = self.id.as_str() {
            Ok(s.to_string())
        } else if let Some(u) = self.id.as_u64() {
            Ok(u.to_string())
        } else if let Some(i) = self.id.as_i64() {
            Ok(i.to_string())
        } else {
            Err(anyhow!("Unexpected Vultr OS id format: {}", self.id))
        }
    }
}

#[derive(Deserialize)]
struct CreateInstanceResponse {
    instance: InstanceInfo,
}

#[derive(Deserialize)]
struct InstanceInfo {
    id: String,
}

#[derive(Deserialize)]
struct InstanceDetailResponse {
    instance: InstanceDetail,
}

#[derive(Deserialize)]
struct InstanceDetail {
    status: String,
    #[serde(default)]
    power_status: String,
    #[serde(default)]
    main_ip: String,
}

impl VpsProvider for VultrProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Vultr
    }

    fn validate_key(&self) -> Result<bool> {
        let url = self.url("account");
        let resp = self.http.get(&url).send()?;
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
                    "Unexpected status {} when validating Vultr API key: {}",
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
            .regions
            .into_iter()
            .map(|r| ProviderRegion {
                id: r.id,
                name: r.city,
                country: r.country,
            })
            .collect();
        Ok(regions)
    }

    fn list_plans(&self) -> Result<Vec<ProviderPlan>> {
        let url = self.url("plans?type=vc2");
        let resp = self.http.get(&url).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to list plans ({}): {}", status, body));
        }
        let data: PlansResponse = resp.json()?;
        let plans = data
            .plans
            .into_iter()
            .map(|p| ProviderPlan {
                id: p.id,
                summary: format!(
                    "{}vCPU {}MB {}GB ${}/mo",
                    p.vcpu_count,
                    p.ram,
                    p.disk,
                    p.monthly_cost
                ),
            })
            .collect();
        Ok(plans)
    }

    fn list_images(&self) -> Result<Vec<ProviderImage>> {
        let url = self.url("os");
        let resp = self.http.get(&url).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to list images ({}): {}", status, body));
        }
        let data: OsResponse = resp.json()?;
        let allowed = [
            "ubuntu",
            "debian",
            "almalinux",
            "rocky",
            "fedora",
            "centos",
        ];
        let mut images = Vec::new();
        for item in data.os {
            if !allowed
                .iter()
                .any(|kw| item.name.to_ascii_lowercase().contains(kw))
            {
                continue;
            }
            let id = item.id_string()?;
            images.push(ProviderImage {
                id,
                name: item.name,
                vendor: item.family,
            });
        }
        Ok(images)
    }

    fn create_instance(&self, req: &CreateInstanceRequest) -> Result<String> {
        // Encode user data as base64.
        let b64_user_data = base64::engine::general_purpose::STANDARD.encode(&req.user_data_raw);

        // Determine os_id type.
        let os_id_json = if u64::from_str(&req.image_id).is_ok() {
            // numeric id
            let num: u64 = req.image_id.parse()?;
            serde_json::json!(num)
        } else {
            serde_json::json!(req.image_id.clone())
        };

        let payload = serde_json::json!({
            "region": req.region,
            "plan": req.plan,
            "os_id": os_id_json,
            "label": req.hostname,
            "hostname": req.hostname,
            "user_data": b64_user_data,
        });

        let url = self.url("instances");
        let resp = self.http.post(&url).json(&payload).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to create instance ({}): {}", status, body));
        }
        let data: CreateInstanceResponse = resp.json()?;
        Ok(data.instance.id)
    }

    fn get_instance_status(&self, instance_id: &str) -> Result<InstanceStatus> {
        let url = self.url(&format!("instances/{}", instance_id));
        let resp = self.http.get(&url).send()?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().unwrap_or_default();
            return Err(anyhow!("Failed to get instance status ({}): {}", status, body));
        }
        let data: InstanceDetailResponse = resp.json()?;
        let inst = data.instance;
        let ready = inst.status == "active" && inst.power_status == "running";
        let public_ipv4 = if !inst.main_ip.is_empty() && inst.main_ip != "0.0.0.0" {
            Some(inst.main_ip)
        } else {
            None
        };
        Ok(InstanceStatus {
            state: inst.status,
            public_ipv4,
            ready,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_item_handles_integer_and_string_ids() {
        let raw = r#"{
            "os": [
                {"id": 2284, "name": "Ubuntu 24.04 LTS x64", "family": "ubuntu"},
                {"id": "2136", "name": "Debian 12 x64", "family": "debian"}
            ]
        }"#;
        let parsed: OsResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.os[0].id_string().unwrap(), "2284");
        assert_eq!(parsed.os[1].id_string().unwrap(), "2136");
    }

    #[test]
    fn plan_item_deserializes_flexible_numbers() {
        let raw = r#"{
            "plans": [
                {"id": "vc2-1c-1gb", "vcpu_count": 1, "ram": 1024, "disk": 25, "monthly_cost": 5},
                {"id": "vc2-1c-2gb", "vcpu_count": "2", "ram": 2048, "disk": "55", "monthly_cost": "10.5"},
                {"id": "vc2-free", "vcpu_count": 1, "ram": 512, "disk": 10, "monthly_cost": null}
            ]
        }"#;
        let parsed: PlansResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.plans[0].monthly_cost, 5.0);
        assert_eq!(parsed.plans[1].vcpu_count, 2);
        assert_eq!(parsed.plans[1].disk, 55);
        assert_eq!(parsed.plans[1].monthly_cost, 10.5);
        assert_eq!(parsed.plans[2].monthly_cost, 0.0);
    }
}
