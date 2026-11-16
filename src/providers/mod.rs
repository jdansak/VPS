// src/providers/mod.rs
// Provider abstractions for bab.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;
use std::time::Duration;

use crate::config::{SessionData, SessionState, Settings};
use crate::tailscale::{
    generate_cloud_init_with_password, generate_ssh_cloud_init_with_password, TailscaleClient,
};

// Public sub-modules for concrete provider implementations.
pub mod vultr;
pub mod upcloud;
pub mod linode;

use self::linode::LinodeProvider;
use self::upcloud::UpCloudProvider;
use self::vultr::VultrProvider;

/// Enumerates supported providers and special modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderKind {
    Vultr,
    UpCloud,
    Linode,
    ExistingTailscale,
    ManualCloudInit,
}

impl ProviderKind {
    /// Returns the environment variable name for the provider's API key, if any.
    pub fn api_key_env_name(&self) -> Option<&'static str> {
        match self {
            ProviderKind::Vultr => Some("VULTR_API_KEY"),
            ProviderKind::UpCloud => Some("UPCLOUD_API_TOKEN"),
            ProviderKind::Linode => Some("LINODE_API_TOKEN"),
            ProviderKind::ExistingTailscale => None,
            ProviderKind::ManualCloudInit => None,
        }
    }

    /// Human‑readable label for the provider.
    pub fn label(&self) -> &'static str {
        match self {
            ProviderKind::Vultr => "Vultr",
            ProviderKind::UpCloud => "UpCloud",
            ProviderKind::Linode => "Linode",
            ProviderKind::ExistingTailscale => "Existing Tailscale",
            ProviderKind::ManualCloudInit => "Manual Cloud‑Init",
        }
    }
}

impl Display for ProviderKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = match self {
            ProviderKind::Vultr => "vultr",
            ProviderKind::UpCloud => "upcloud",
            ProviderKind::Linode => "linode",
            ProviderKind::ExistingTailscale => "existing_tailscale",
            ProviderKind::ManualCloudInit => "manual_cloud_init",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for ProviderKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "vultr" => Ok(ProviderKind::Vultr),
            "upcloud" => Ok(ProviderKind::UpCloud),
            "linode" | "akamai" => Ok(ProviderKind::Linode),
            "existing" | "existing_tailscale" => Ok(ProviderKind::ExistingTailscale),
            "manual" | "manual_cloud_init" => Ok(ProviderKind::ManualCloudInit),
            _ => Err(anyhow::anyhow!("Unknown provider: {}", s)),
        }
    }
}

/// Simple region description.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderRegion {
    pub id: String,
    pub name: String,
    pub country: String,
}

/// Simple plan description.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderPlan {
    pub id: String,
    pub summary: String,
}

/// Simple image description.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderImage {
    pub id: String,
    pub name: String,
    pub vendor: String,
}

/// Curated default region presets for a given provider.
pub fn default_regions_for(kind: ProviderKind) -> Vec<ProviderRegion> {
    match kind {
        ProviderKind::Vultr => vec![
            ProviderRegion { id: "ewr".into(), name: "Newark, NJ".into(), country: "US".into() },
            ProviderRegion { id: "ord".into(), name: "Chicago, IL".into(), country: "US".into() },
            ProviderRegion { id: "lax".into(), name: "Los Angeles, CA".into(), country: "US".into() },
            ProviderRegion { id: "ams".into(), name: "Amsterdam".into(), country: "NL".into() },
            ProviderRegion { id: "fra".into(), name: "Frankfurt".into(), country: "DE".into() },
            ProviderRegion { id: "lhr".into(), name: "London".into(), country: "GB".into() },
            ProviderRegion { id: "sgp".into(), name: "Singapore".into(), country: "SG".into() },
            ProviderRegion { id: "nrt".into(), name: "Tokyo".into(), country: "JP".into() },
        ],
        ProviderKind::UpCloud => vec![
            ProviderRegion { id: "us-nyc1".into(), name: "New York".into(), country: "US".into() },
            ProviderRegion { id: "us-chi1".into(), name: "Chicago".into(), country: "US".into() },
            ProviderRegion { id: "nl-ams1".into(), name: "Amsterdam".into(), country: "NL".into() },
            ProviderRegion { id: "de-fra1".into(), name: "Frankfurt".into(), country: "DE".into() },
            ProviderRegion { id: "uk-lon1".into(), name: "London".into(), country: "GB".into() },
            ProviderRegion { id: "sg-sin1".into(), name: "Singapore".into(), country: "SG".into() },
        ],
        ProviderKind::Linode => vec![
            ProviderRegion { id: "us-east".into(), name: "Newark, NJ".into(), country: "US".into() },
            ProviderRegion { id: "us-central".into(), name: "Dallas, TX".into(), country: "US".into() },
            ProviderRegion { id: "us-west".into(), name: "Fremont, CA".into(), country: "US".into() },
            ProviderRegion { id: "eu-west".into(), name: "London".into(), country: "GB".into() },
            ProviderRegion { id: "eu-central".into(), name: "Frankfurt".into(), country: "DE".into() },
            ProviderRegion { id: "ap-south".into(), name: "Singapore".into(), country: "SG".into() },
        ],
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => Vec::new(),
    }
}

/// Curated default machine size (plan) presets for a given provider.
pub fn default_plans_for(kind: ProviderKind) -> Vec<ProviderPlan> {
    match kind {
        ProviderKind::Vultr => vec![
            ProviderPlan {
                id: "vc2-1c-1gb".into(),
                summary: "1 vCPU, 1024 MB RAM, 25 GB SSD ($5/mo)".into(),
            },
            ProviderPlan {
                id: "vc2-1c-2gb".into(),
                summary: "1 vCPU, 2048 MB RAM, 55 GB SSD ($10/mo)".into(),
            },
            ProviderPlan {
                id: "vc2-2c-4gb".into(),
                summary: "2 vCPU, 4096 MB RAM, 80 GB SSD ($20/mo)".into(),
            },
            ProviderPlan {
                id: "vc2-4c-8gb".into(),
                summary: "4 vCPU, 8192 MB RAM, 160 GB SSD ($40/mo)".into(),
            },
        ],
        ProviderKind::UpCloud => vec![
            ProviderPlan {
                id: "1xCPU-1GB".into(),
                summary: "1 vCPU, 1024 MB RAM, 25 GB SSD ($5/mo)".into(),
            },
            ProviderPlan {
                id: "1xCPU-2GB".into(),
                summary: "1 vCPU, 2048 MB RAM, 50 GB SSD ($10/mo)".into(),
            },
            ProviderPlan {
                id: "2xCPU-4GB".into(),
                summary: "2 vCPU, 4096 MB RAM, 80 GB SSD ($20/mo)".into(),
            },
            ProviderPlan {
                id: "4xCPU-8GB".into(),
                summary: "4 vCPU, 8192 MB RAM, 160 GB SSD ($40/mo)".into(),
            },
        ],
        ProviderKind::Linode => vec![
            ProviderPlan {
                id: "g6-nanode-1".into(),
                summary: "Nanode 1GB - 1 vCPU, 1024 MB RAM, 25 GB SSD ($5/mo)".into(),
            },
            ProviderPlan {
                id: "g6-standard-1".into(),
                summary: "Linode 2GB - 1 vCPU, 2048 MB RAM, 50 GB SSD ($12/mo)".into(),
            },
            ProviderPlan {
                id: "g6-standard-2".into(),
                summary: "Linode 4GB - 2 vCPU, 4096 MB RAM, 80 GB SSD ($24/mo)".into(),
            },
            ProviderPlan {
                id: "g6-standard-4".into(),
                summary: "Linode 8GB - 4 vCPU, 8192 MB RAM, 160 GB SSD ($48/mo)".into(),
            },
        ],
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => Vec::new(),
    }
}

/// Curated default OS image presets for a given provider.
pub fn default_images_for(kind: ProviderKind) -> Vec<ProviderImage> {
    match kind {
        ProviderKind::Vultr => vec![
            ProviderImage {
                id: "2284".into(),
                name: "Ubuntu 24.04 LTS x64".into(),
                vendor: "ubuntu".into(),
            },
            ProviderImage {
                id: "2136".into(),
                name: "Debian 12 x64 (bookworm)".into(),
                vendor: "debian".into(),
            },
        ],
        ProviderKind::UpCloud => vec![
            ProviderImage {
                id: "01000000-0000-4000-8000-000030240200".into(),
                name: "Ubuntu Server 24.04 LTS".into(),
                vendor: "upcloud".into(),
            },
            ProviderImage {
                id: "01000000-0000-4000-8000-000020060100".into(),
                name: "Debian GNU/Linux 12 (Bookworm)".into(),
                vendor: "upcloud".into(),
            },
        ],
        ProviderKind::Linode => vec![
            ProviderImage {
                id: "linode/ubuntu24.04".into(),
                name: "Ubuntu 24.04 LTS".into(),
                vendor: "Ubuntu".into(),
            },
            ProviderImage {
                id: "linode/debian12".into(),
                name: "Debian 12".into(),
                vendor: "Debian".into(),
            },
        ],
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => Vec::new(),
    }
}

/// Status of a provisioned instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceStatus {
    pub state: String,
    pub public_ipv4: Option<String>,
    pub ready: bool,
}

/// Pricing rates for a cloud VPS plan.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct PlanPricing {
    pub monthly_usd: f64,
    pub hourly_usd: f64,
}

/// Estimated accrued and recurring cost for a running `ProviderInstance`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InstanceCostEstimate {
    pub accrued_usd: Option<f64>,
    pub elapsed_secs: Option<u64>,
    pub monthly_usd: f64,
    pub hourly_usd: f64,
}

fn parse_vcpu_gb_plan(spec: &str, separator: &str) -> Option<PlanPricing> {
    let (vcpu_str, rest) = spec.split_once(separator)?;
    if vcpu_str.is_empty() || !vcpu_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let vcpu: u32 = vcpu_str.parse().ok()?;
    if vcpu == 0 {
        return None;
    }
    let gb_str = rest.strip_suffix("gb")?;
    if gb_str.is_empty() || !gb_str.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return None;
    }
    let gb: f64 = gb_str.parse().ok()?;
    if !gb.is_finite() || gb <= 0.0 {
        return None;
    }
    let monthly_usd = gb * 5.0;
    Some(PlanPricing {
        monthly_usd,
        hourly_usd: monthly_usd / 730.0,
    })
}

/// Look up published monthly and hourly pricing for a provider's plan ID.
pub fn plan_pricing(provider: ProviderKind, plan_id: &str) -> Option<PlanPricing> {
    let trimmed = plan_id.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let rates = match provider {
        ProviderKind::Vultr => match lower.as_str() {
            "vc2-1c-0.5gb-free" => (0.0, 0.0),
            "vc2-1c-0.5gb-v6" => (2.5, 0.003),
            "vc2-1c-0.5gb" => (3.5, 0.005),
            "vc2-1c-1gb" => (5.0, 0.007),
            "vc2-1c-2gb" => (10.0, 0.014),
            "vc2-2c-4gb" => (20.0, 0.027),
            "vc2-4c-8gb" => (40.0, 0.055),
            "vc2-6c-16gb" => (80.0, 0.110),
            "vc2-8c-32gb" => (160.0, 0.219),
            _ => {
                let rest = lower.strip_prefix("vc2-")?;
                return parse_vcpu_gb_plan(rest, "c-");
            }
        },
        ProviderKind::UpCloud => match lower.as_str() {
            "1xcpu-1gb" => (5.0, 0.007),
            "1xcpu-2gb" => (10.0, 0.015),
            "2xcpu-4gb" => (20.0, 0.030),
            "4xcpu-8gb" => (40.0, 0.060),
            "6xcpu-16gb" => (80.0, 0.119),
            _ => return parse_vcpu_gb_plan(&lower, "xcpu-"),
        },
        ProviderKind::Linode => match lower.as_str() {
            "g6-nanode-1" => (5.0, 0.0075),
            "g6-standard-1" => (12.0, 0.018),
            "g6-standard-2" => (24.0, 0.036),
            "g6-standard-4" => (48.0, 0.072),
            "g6-standard-6" => (96.0, 0.144),
            "g6-standard-8" => (192.0, 0.288),
            _ => return None,
        },
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => return None,
    };
    Some(PlanPricing {
        monthly_usd: rates.0,
        hourly_usd: rates.1,
    })
}

/// Format a monthly USD price (`$5/mo` for whole dollars, `$2.50/mo` when fractional).
pub fn format_monthly_usd(monthly_usd: f64) -> String {
    let clamped = if monthly_usd.is_finite() && monthly_usd > 0.0 {
        monthly_usd
    } else {
        0.0
    };
    let rounded = clamped.round();
    if (clamped - rounded).abs() < 0.005 {
        format!("${:.0}/mo", rounded)
    } else {
        format!("${:.2}/mo", clamped)
    }
}

/// Format an hourly USD rate (`$0.007/hr` or `$0.0075/hr` when a 4th decimal digit is significant).
pub fn format_hourly_usd(hourly_usd: f64) -> String {
    let clamped = if hourly_usd.is_finite() && hourly_usd > 0.0 {
        hourly_usd
    } else {
        0.0
    };
    if (clamped * 1000.0 - (clamped * 1000.0).round()).abs() > 0.01 {
        format!("${:.4}/hr", clamped)
    } else {
        format!("${:.3}/hr", clamped)
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => Some(if is_leap_year(year) { 29 } else { 28 }),
        _ => None,
    }
}

/// Converts a proleptic Gregorian date to days since 1970-01-01.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = month as i64;
    let d = day as i64;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parse_ascii_uint(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok()
}

fn parse_tz_offset_secs(rest: &str) -> Option<i64> {
    if rest.is_empty() || rest.eq_ignore_ascii_case("z") {
        return Some(0);
    }
    let (sign, digits) = if let Some(s) = rest.strip_prefix('+') {
        (1i64, s)
    } else {
        (-1i64, rest.strip_prefix('-')?)
    };
    let (hh_str, mm_str) = if digits.len() == 5 && digits.as_bytes()[2] == b':' {
        (&digits[0..2], &digits[3..5])
    } else if digits.len() == 4 {
        (&digits[0..2], &digits[2..4])
    } else {
        return None;
    };
    let hh = parse_ascii_uint(hh_str)?;
    let mm = parse_ascii_uint(mm_str)?;
    if hh > 23 || mm > 59 {
        return None;
    }
    Some(sign * (hh * 3_600 + mm * 60))
}

/// Parse a provider `created_at` timestamp (ISO-8601 / RFC-3339 or positive integer epoch seconds)
/// into UTC Unix epoch seconds.
pub fn parse_created_at_epoch_secs(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return trimmed.parse::<i64>().ok().filter(|&secs| secs > 0);
    }
    if !trimmed.is_ascii() || trimmed.len() < 19 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't' | b' ')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }

    let year = parse_ascii_uint(&trimmed[0..4])?;
    let month = u32::try_from(parse_ascii_uint(&trimmed[5..7])?).ok()?;
    let day = u32::try_from(parse_ascii_uint(&trimmed[8..10])?).ok()?;
    let hour = parse_ascii_uint(&trimmed[11..13])?;
    let minute = parse_ascii_uint(&trimmed[14..16])?;
    let second = parse_ascii_uint(&trimmed[17..19])?;

    let max_day = days_in_month(year, month)?;
    if day == 0 || day > max_day || hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let mut rest = &trimmed[19..];
    if let Some(after_dot) = rest.strip_prefix('.') {
        let frac_digits = after_dot.bytes().take_while(|b| b.is_ascii_digit()).count();
        if frac_digits == 0 {
            return None;
        }
        rest = &after_dot[frac_digits..];
    }

    let offset_secs = parse_tz_offset_secs(rest)?;
    let days = days_from_civil(year, month, day);
    let local_secs = days
        .checked_mul(86_400)?
        .checked_add(hour * 3_600 + minute * 60 + second)?;
    local_secs.checked_sub(offset_secs)
}

/// Format an elapsed uptime duration in seconds as `<1m`, `{m}m`, `{h}h {m}m`, or `{d}d {h}h`.
pub fn format_uptime_duration(elapsed_secs: u64) -> String {
    if elapsed_secs < 60 {
        return "<1m".to_string();
    }
    let total_mins = elapsed_secs / 60;
    if total_mins < 60 {
        return format!("{}m", total_mins);
    }
    let total_hours = total_mins / 60;
    if total_hours < 24 {
        return format!("{}h {}m", total_hours, total_mins % 60);
    }
    format!("{}d {}h", total_hours / 24, total_hours % 24)
}

fn current_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Summary of a cloud VPS instance returned by provider instance listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderInstance {
    pub provider: ProviderKind,
    pub id: String,
    pub name: String,
    pub status: String,
    pub public_ip: Option<String>,
    pub region: Option<String>,
    pub plan: Option<String>,
    pub created_at: Option<String>,
}

impl ProviderInstance {
    /// Estimate the accrued and recurring cost of this instance at the current wall-clock time.
    pub fn cost_estimate(&self) -> Option<InstanceCostEstimate> {
        self.cost_estimate_at(current_epoch_secs())
    }

    /// Estimate the accrued and recurring cost of this instance at `now_epoch_secs`.
    pub fn cost_estimate_at(&self, now_epoch_secs: i64) -> Option<InstanceCostEstimate> {
        let pricing = self
            .plan
            .as_deref()
            .and_then(|plan_id| plan_pricing(self.provider, plan_id))?;

        let (accrued_usd, elapsed_secs) = match self
            .created_at
            .as_deref()
            .and_then(parse_created_at_epoch_secs)
            .filter(|&created| created <= now_epoch_secs)
        {
            Some(created) => {
                let elapsed = now_epoch_secs.abs_diff(created);
                let billable_hours = ((elapsed / 3_600) + 1) as f64;
                let accrued = (billable_hours * pricing.hourly_usd).min(pricing.monthly_usd);
                (Some(accrued), Some(elapsed))
            }
            None => (None, None),
        };

        Some(InstanceCostEstimate {
            accrued_usd,
            elapsed_secs,
            monthly_usd: pricing.monthly_usd,
            hourly_usd: pricing.hourly_usd,
        })
    }

    /// Format a compact running-cost summary at the current wall-clock time (e.g. `"$0.01/$5/mo"`).
    pub fn format_running_cost_compact(&self) -> String {
        self.format_running_cost_compact_at(current_epoch_secs())
    }

    /// Format a compact running-cost summary at `now_epoch_secs`.
    pub fn format_running_cost_compact_at(&self, now_epoch_secs: i64) -> String {
        let Some(est) = self.cost_estimate_at(now_epoch_secs) else {
            return "-".to_string();
        };
        let monthly = format_monthly_usd(est.monthly_usd);
        match est.accrued_usd {
            Some(accrued) => format!("${:.2}/{}", accrued, monthly),
            None => monthly,
        }
    }

    /// Format a detailed running-cost summary at the current wall-clock time.
    pub fn format_running_cost_detailed(&self) -> String {
        self.format_running_cost_detailed_at(current_epoch_secs())
    }

    /// Format a detailed running-cost summary at `now_epoch_secs`.
    pub fn format_running_cost_detailed_at(&self, now_epoch_secs: i64) -> String {
        let Some(est) = self.cost_estimate_at(now_epoch_secs) else {
            return "-".to_string();
        };
        let monthly = format_monthly_usd(est.monthly_usd);
        let hourly = format_hourly_usd(est.hourly_usd);
        match (est.accrued_usd, est.elapsed_secs) {
            (Some(accrued), Some(elapsed)) => format!(
                "${:.2} ({} @ {}, {})",
                accrued,
                format_uptime_duration(elapsed),
                hourly,
                monthly
            ),
            _ => format!("{} ({})", monthly, hourly),
        }
    }
}

/// Per-provider status recorded while querying across cloud providers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderQueryStatus {
    pub provider: ProviderKind,
    pub configured: bool,
    pub instance_count: usize,
    pub error: Option<String>,
}

/// Combined result of querying one or more cloud providers for instances.
#[derive(Debug, Clone, Default)]
pub struct MultiProviderQueryResult {
    pub instances: Vec<ProviderInstance>,
    pub provider_statuses: Vec<ProviderQueryStatus>,
}

/// Validate and trim a cloud instance ID to prevent URL path or query injection.
pub fn validate_instance_id(id: &str) -> Result<&str> {
    let trimmed = id.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Instance ID must not be empty"));
    }
    if trimmed.contains("..") {
        return Err(anyhow!("Instance ID must not contain '..'"));
    }
    if trimmed.chars().any(|c| {
        c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '?' | '#' | '&')
    }) {
        return Err(anyhow!(
            "Instance ID '{}' contains invalid characters",
            trimmed
        ));
    }
    Ok(trimmed)
}

pub(crate) fn non_empty_trimmed(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .as_deref()
        .and_then(non_empty_trimmed)
}

/// Request payload for creating a new instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateInstanceRequest {
    pub region: String,
    pub plan: String,
    pub image_id: String,
    pub hostname: String,
    pub user_data_raw: String,
}

/// Configuration used for the full provisioning flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionConfig {
    pub provider: ProviderKind,
    pub region: String,
    pub plan: String,
    pub image_id: String,
    pub hostname: String,
    pub username: String,
    pub role: String,
    pub tags: Vec<String>,
    pub provider_timeout: Duration,
    pub tailscale_timeout: Duration,
    pub poll_interval: Duration,
    pub tailscale_mode: bool,
    pub ssh_pubkey: Option<String>,
    pub ssh_key_path: Option<String>,
    pub sudo_password: Option<String>,
}

/// Result returned after a successful provisioning run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisionResult {
    pub instance_id: String,
    pub ip: String,
    pub tailscale_ip: String,
    pub public_ip: String,
    pub hostname: String,
    pub provider: String,
    pub username: String,
    pub role: String,
    pub tailscale_mode: bool,
}

/// Trait that concrete providers must implement.
pub trait VpsProvider {
    fn kind(&self) -> ProviderKind;
    fn validate_key(&self) -> Result<bool>;
    fn list_regions(&self) -> Result<Vec<ProviderRegion>>;
    fn list_plans(&self) -> Result<Vec<ProviderPlan>>;
    fn list_images(&self) -> Result<Vec<ProviderImage>>;
    fn create_instance(&self, req: &CreateInstanceRequest) -> Result<String>;
    fn get_instance_status(&self, instance_id: &str) -> Result<InstanceStatus>;
    fn list_instances(&self) -> Result<Vec<ProviderInstance>>;
    fn destroy_instance(&self, instance_id: &str) -> Result<()>;
    fn wait_active(
        &self,
        instance_id: &str,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<InstanceStatus> {
        let start = std::time::Instant::now();
        loop {
            let status = self.get_instance_status(instance_id)?;
            if status.ready {
                return Ok(status);
            }
            if start.elapsed() >= timeout {
                return Err(anyhow::anyhow!("Timed out waiting for instance {} to become ready", instance_id));
            }
            std::thread::sleep(poll_interval);
        }
    }
}

/// Executes the full provisioning flow (Tailscale or Standard SSH mode), waits for the VM to be ready, and records session data.
pub fn provision_full_flow(
    provider: &dyn VpsProvider,
    tailscale: Option<&TailscaleClient>,
    cfg: &ProvisionConfig,
    session: Option<&SessionState>,
) -> Result<ProvisionResult> {
    provision_full_flow_with_progress(provider, tailscale, cfg, session, |_| {})
}

/// Populates provisioning configuration metadata onto `SessionData`, preserving any existing
/// `sudo_password` when `cfg.sudo_password` is `None` or blank.
fn populate_provision_session_data(
    data: &mut SessionData,
    cfg: &ProvisionConfig,
    provider_kind: ProviderKind,
    instance_id: &str,
    transport_mode: &str,
) {
    data.vps_instance_id = Some(instance_id.to_string());
    data.vps_provider = Some(provider_kind.to_string());
    data.tailscale_hostname = Some(cfg.hostname.clone());
    data.username = Some(cfg.username.clone());
    data.transport_mode = Some(transport_mode.to_string());
    data.server_role = Some(cfg.role.clone());
    data.vps_region = Some(cfg.region.clone());
    data.vps_plan = Some(cfg.plan.clone());
    data.vps_image = Some(cfg.image_id.clone());
    if let Some(pw) = cfg.sudo_password.as_deref().and_then(non_empty_trimmed) {
        data.sudo_password = Some(pw);
    }
}

/// Loads `SessionData` (or defaults), applies `update`, and persists it when `session` is `Some`.
fn update_provision_session(
    session: Option<&SessionState>,
    update: impl FnOnce(&mut SessionData),
) -> Result<()> {
    let Some(ss) = session else {
        return Ok(());
    };
    let mut data = ss.load_session().unwrap_or_else(|_| SessionData::default());
    update(&mut data);
    ss.save_session(&data)
}

/// Executes the full provisioning flow while emitting human-readable progress updates via `on_progress`.
pub fn provision_full_flow_with_progress<F>(
    provider: &dyn VpsProvider,
    tailscale: Option<&TailscaleClient>,
    cfg: &ProvisionConfig,
    session: Option<&SessionState>,
    mut on_progress: F,
) -> Result<ProvisionResult>
where
    F: FnMut(&str),
{
    let cloud_init = if cfg.tailscale_mode {
        let ts = tailscale.ok_or_else(|| {
            anyhow!("Tailscale client is required when tailscale_mode is enabled")
        })?;
        on_progress("[PROVISION] Creating Tailscale auth key and cloud-init...");
        let auth_key = ts.create_auth_key("bab-bootstrap", &cfg.tags, false, true, 3600)?;
        generate_cloud_init_with_password(
            &auth_key,
            &cfg.hostname,
            &cfg.username,
            cfg.sudo_password.as_deref(),
        )
    } else {
        let ssh_pubkey = cfg
            .ssh_pubkey
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                anyhow!("SSH public key is required when tailscale_mode is disabled")
            })?;
        generate_ssh_cloud_init_with_password(
            ssh_pubkey,
            &cfg.hostname,
            &cfg.username,
            cfg.sudo_password.as_deref(),
        )
    };

    let req = CreateInstanceRequest {
        region: cfg.region.clone(),
        plan: cfg.plan.clone(),
        image_id: cfg.image_id.clone(),
        hostname: cfg.hostname.clone(),
        user_data_raw: cloud_init,
    };
    on_progress(&format!(
        "[PROVISION] Submitting {} create_instance request for '{}'...",
        provider.kind().label(),
        cfg.hostname
    ));
    let instance_id = provider.create_instance(&req)?;
    let transport_mode = if cfg.tailscale_mode { "tailscale" } else { "ssh" };
    update_provision_session(session, |data| {
        populate_provision_session_data(
            data,
            cfg,
            provider.kind(),
            &instance_id,
            transport_mode,
        );
        data.vps_ip = None;
        data.public_ip = None;
        data.tailscale_ip = None;
    })?;
    on_progress(&format!(
        "[PROVISION] Instance '{}' created; polling {} until active...",
        instance_id,
        provider.kind().label()
    ));

    let start = std::time::Instant::now();
    let status = loop {
        let status = provider.get_instance_status(&instance_id)?;
        if status.ready {
            break status;
        }
        on_progress(&format!(
            "[PROVISION] Polling VM '{}' (state={}, ip={}, elapsed={}s)...",
            instance_id,
            status.state,
            status.public_ipv4.as_deref().unwrap_or("pending"),
            start.elapsed().as_secs()
        ));
        if start.elapsed() >= cfg.provider_timeout {
            return Err(anyhow!(
                "Timed out waiting for instance {} to become ready",
                instance_id
            ));
        }
        std::thread::sleep(cfg.poll_interval);
    };

    let discovered_public_ip = status
        .public_ipv4
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    update_provision_session(session, |data| {
        data.public_ip = discovered_public_ip.clone();
    })?;

    let (ip, tailscale_ip, public_ip, session_tailscale_ip, session_public_ip, ssh_key) =
        if cfg.tailscale_mode {
            let ts = tailscale.expect("validated above");
            let ts_start = std::time::Instant::now();
            let ts_ip = loop {
                on_progress(&format!(
                    "[PROVISION] VM '{}' is active (public IP: {}); waiting for '{}' on Tailscale (elapsed={}s)...",
                    instance_id,
                    discovered_public_ip.as_deref().unwrap_or("none"),
                    cfg.hostname,
                    ts_start.elapsed().as_secs()
                ));
                if let Some(found) = ts.find_device_ip(&cfg.hostname)? {
                    break found;
                }
                if ts_start.elapsed() >= cfg.tailscale_timeout {
                    return Err(anyhow!("Timed out waiting for device {}", cfg.hostname));
                }
                std::thread::sleep(cfg.poll_interval);
            };
            let pub_ip_str = discovered_public_ip.clone().unwrap_or_default();
            (
                ts_ip.clone(),
                ts_ip.clone(),
                pub_ip_str,
                Some(ts_ip),
                discovered_public_ip,
                Some("tailscale".to_string()),
            )
        } else {
            let public_ip = discovered_public_ip.ok_or_else(|| {
                anyhow!(
                    "Instance {} became active without a public IPv4 address",
                    instance_id
                )
            })?;
            let ssh_key = cfg.ssh_key_path.as_deref().and_then(non_empty_trimmed);
            (
                public_ip.clone(),
                String::new(),
                public_ip.clone(),
                None,
                Some(public_ip),
                ssh_key,
            )
        };

    update_provision_session(session, |data| {
        populate_provision_session_data(
            data,
            cfg,
            provider.kind(),
            &instance_id,
            transport_mode,
        );
        data.vps_ip = Some(ip.clone());
        data.public_ip = session_public_ip;
        data.tailscale_ip = session_tailscale_ip;
        data.ssh_key = ssh_key;
    })?;

    Ok(ProvisionResult {
        instance_id,
        ip,
        tailscale_ip,
        public_ip,
        hostname: cfg.hostname.clone(),
        provider: provider.kind().to_string(),
        username: cfg.username.clone(),
        role: cfg.role.clone(),
        tailscale_mode: cfg.tailscale_mode,
    })
}

const CLOUD_PROVIDERS: [ProviderKind; 3] = [
    ProviderKind::Vultr,
    ProviderKind::UpCloud,
    ProviderKind::Linode,
];

/// Build a concrete cloud `VpsProvider` from an API key and optional base URL override.
/// When `base_url` is `None`, checks `VULTR_API_BASE_URL` / `UPCLOUD_API_BASE_URL` /
/// `LINODE_API_BASE_URL` before falling back to each provider's default constructor.
pub fn build_cloud_provider_with_key(
    kind: ProviderKind,
    api_key: &str,
    base_url: Option<&str>,
) -> Result<Box<dyn VpsProvider>> {
    let explicit_base = base_url.and_then(non_empty_trimmed);
    match kind {
        ProviderKind::Vultr => {
            let base = explicit_base.or_else(|| non_empty_env("VULTR_API_BASE_URL"));
            let provider = match base {
                Some(url) => VultrProvider::with_base_url(api_key, url)?,
                None => VultrProvider::new(api_key)?,
            };
            Ok(Box::new(provider))
        }
        ProviderKind::UpCloud => {
            let base = explicit_base.or_else(|| non_empty_env("UPCLOUD_API_BASE_URL"));
            let provider = match base {
                Some(url) => UpCloudProvider::with_base_url(api_key, url)?,
                None => UpCloudProvider::new(api_key)?,
            };
            Ok(Box::new(provider))
        }
        ProviderKind::Linode => {
            let base = explicit_base.or_else(|| non_empty_env("LINODE_API_BASE_URL"));
            let provider = match base {
                Some(url) => LinodeProvider::with_base_url(api_key, url)?,
                None => LinodeProvider::new(api_key)?,
            };
            Ok(Box::new(provider))
        }
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => Err(anyhow!(
            "{} does not use a cloud provider API client",
            kind.label()
        )),
    }
}

fn query_providers_with_resolver<F>(
    filter: Option<ProviderKind>,
    mut resolve_key: F,
) -> MultiProviderQueryResult
where
    F: FnMut(ProviderKind) -> Result<Option<String>>,
{
    let mut result = MultiProviderQueryResult::default();
    for kind in CLOUD_PROVIDERS {
        if let Some(target) = filter {
            if kind != target {
                continue;
            }
        }

        let key = match resolve_key(kind) {
            Ok(opt) => match opt.as_deref().and_then(non_empty_trimmed) {
                Some(k) => k,
                None => {
                    result.provider_statuses.push(ProviderQueryStatus {
                        provider: kind,
                        configured: false,
                        instance_count: 0,
                        error: None,
                    });
                    continue;
                }
            },
            Err(err) => {
                result.provider_statuses.push(ProviderQueryStatus {
                    provider: kind,
                    configured: true,
                    instance_count: 0,
                    error: Some(err.to_string()),
                });
                continue;
            }
        };

        let listed = build_cloud_provider_with_key(kind, &key, None)
            .and_then(|provider| provider.list_instances());

        match listed {
            Ok(mut items) => {
                let count = items.len();
                result.instances.append(&mut items);
                result.provider_statuses.push(ProviderQueryStatus {
                    provider: kind,
                    configured: true,
                    instance_count: count,
                    error: None,
                });
            }
            Err(err) => {
                result.provider_statuses.push(ProviderQueryStatus {
                    provider: kind,
                    configured: true,
                    instance_count: 0,
                    error: Some(err.to_string()),
                });
            }
        }
    }

    result.instances.sort_by(|a, b| {
        a.provider
            .label()
            .cmp(b.provider.label())
            .then_with(|| a.name.cmp(&b.name))
            .then_with(|| a.id.cmp(&b.id))
    });
    result
}

/// Query running/provisioned instances across Vultr, UpCloud, and Linode using explicit API keys.
/// Provider errors are isolated into `provider_statuses` so remaining providers still return results.
pub fn query_providers_with_keys(
    vultr_key: Option<&str>,
    upcloud_key: Option<&str>,
    linode_key: Option<&str>,
    filter: Option<ProviderKind>,
) -> MultiProviderQueryResult {
    query_providers_with_resolver(filter, |kind| {
        let key = match kind {
            ProviderKind::Vultr => vultr_key,
            ProviderKind::UpCloud => upcloud_key,
            ProviderKind::Linode => linode_key,
            ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => None,
        };
        Ok(key.map(String::from))
    })
}

/// Query running/provisioned instances across configured cloud providers in `Settings`.
pub fn query_all_providers(
    settings: &Settings,
    filter: Option<ProviderKind>,
) -> MultiProviderQueryResult {
    query_providers_with_resolver(filter, |kind| match kind {
        ProviderKind::Vultr => settings.vultr_api_key(),
        ProviderKind::UpCloud => settings.upcloud_api_token(),
        ProviderKind::Linode => settings.linode_api_token(),
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => Ok(None),
    })
}

/// Destroy an instance on the given cloud provider using an explicit API key and optional base URL.
pub fn destroy_provider_instance_with_key(
    kind: ProviderKind,
    api_key: &str,
    instance_id: &str,
    base_url: Option<&str>,
) -> Result<()> {
    let key = non_empty_trimmed(api_key)
        .ok_or_else(|| anyhow!("API key for {} is not configured", kind.label()))?;
    let validated_id = validate_instance_id(instance_id)?;
    let provider = build_cloud_provider_with_key(kind, &key, base_url)?;
    provider.destroy_instance(validated_id)
}

/// Destroy an instance on the given cloud provider using credentials from `Settings`.
pub fn destroy_provider_instance(
    settings: &Settings,
    kind: ProviderKind,
    instance_id: &str,
) -> Result<()> {
    let validated_id = validate_instance_id(instance_id)?;
    let key = match kind {
        ProviderKind::Vultr => settings
            .vultr_api_key()?
            .as_deref()
            .and_then(non_empty_trimmed)
            .ok_or_else(|| anyhow!("VULTR_API_KEY is not configured"))?,
        ProviderKind::UpCloud => settings
            .upcloud_api_token()?
            .as_deref()
            .and_then(non_empty_trimmed)
            .ok_or_else(|| anyhow!("UPCLOUD_API_TOKEN is not configured"))?,
        ProviderKind::Linode => settings
            .linode_api_token()?
            .as_deref()
            .and_then(non_empty_trimmed)
            .ok_or_else(|| anyhow!("LINODE_API_TOKEN is not configured"))?,
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => {
            return Err(anyhow!(
                "{} does not support destroying cloud instances",
                kind.label()
            ))
        }
    };
    destroy_provider_instance_with_key(kind, &key, validated_id, None)
}

/// Clear active VPS instance session fields if `SessionData.vps_instance_id` matches `instance_id`.
/// Returns `Ok(true)` when matching session state was cleared and saved, or `Ok(false)` otherwise.
pub fn clear_destroyed_session_if_matches(
    session: &SessionState,
    instance_id: &str,
) -> Result<bool> {
    let Some(target) = non_empty_trimmed(instance_id) else {
        return Ok(false);
    };
    let mut data = session.load_session()?;
    if data.vps_instance_id.as_deref().map(str::trim) != Some(target.as_str()) {
        return Ok(false);
    }
    data.vps_provider = None;
    data.vps_instance_id = None;
    data.vps_ip = None;
    data.public_ip = None;
    data.tailscale_ip = None;
    session.save_session(&data)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_kind_from_str_maps_akamai_to_linode() {
        assert_eq!("vultr".parse::<ProviderKind>().unwrap(), ProviderKind::Vultr);
        assert_eq!("upcloud".parse::<ProviderKind>().unwrap(), ProviderKind::UpCloud);
        assert_eq!("linode".parse::<ProviderKind>().unwrap(), ProviderKind::Linode);
        assert_eq!("akamai".parse::<ProviderKind>().unwrap(), ProviderKind::Linode);
        assert_eq!("Akamai".parse::<ProviderKind>().unwrap(), ProviderKind::Linode);
        assert_eq!(
            "existing_tailscale".parse::<ProviderKind>().unwrap(),
            ProviderKind::ExistingTailscale
        );
        assert_eq!(
            "manual_cloud_init".parse::<ProviderKind>().unwrap(),
            ProviderKind::ManualCloudInit
        );
        assert!("unknown".parse::<ProviderKind>().is_err());
    }

    #[test]
    fn provider_kind_display_roundtrip() {
        for kind in [
            ProviderKind::Vultr,
            ProviderKind::UpCloud,
            ProviderKind::Linode,
            ProviderKind::ExistingTailscale,
            ProviderKind::ManualCloudInit,
        ] {
            let parsed: ProviderKind = kind.to_string().parse().unwrap();
            assert_eq!(parsed, kind);
        }
    }

    struct MockProvider {
        public_ipv4: Option<String>,
        captured_user_data: std::sync::Mutex<Option<String>>,
        instances: std::sync::Mutex<Vec<ProviderInstance>>,
        destroyed_ids: std::sync::Mutex<Vec<String>>,
    }

    impl MockProvider {
        fn new(public_ipv4: Option<&str>) -> Self {
            Self {
                public_ipv4: public_ipv4.map(String::from),
                captured_user_data: std::sync::Mutex::new(None),
                instances: std::sync::Mutex::new(vec![ProviderInstance {
                    provider: ProviderKind::Vultr,
                    id: "inst-123".to_string(),
                    name: "bab-vps".to_string(),
                    status: "active".to_string(),
                    public_ip: public_ipv4.map(String::from),
                    region: Some("ewr".to_string()),
                    plan: Some("vc2-1c-1gb".to_string()),
                    created_at: None,
                }]),
                destroyed_ids: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl VpsProvider for MockProvider {
        fn kind(&self) -> ProviderKind {
            ProviderKind::Vultr
        }
        fn validate_key(&self) -> Result<bool> {
            Ok(true)
        }
        fn list_regions(&self) -> Result<Vec<ProviderRegion>> {
            Ok(vec![])
        }
        fn list_plans(&self) -> Result<Vec<ProviderPlan>> {
            Ok(vec![])
        }
        fn list_images(&self) -> Result<Vec<ProviderImage>> {
            Ok(vec![])
        }
        fn create_instance(&self, req: &CreateInstanceRequest) -> Result<String> {
            *self.captured_user_data.lock().unwrap() = Some(req.user_data_raw.clone());
            Ok("inst-123".to_string())
        }
        fn get_instance_status(&self, _instance_id: &str) -> Result<InstanceStatus> {
            Ok(InstanceStatus {
                state: "active".to_string(),
                public_ipv4: self.public_ipv4.clone(),
                ready: true,
            })
        }
        fn list_instances(&self) -> Result<Vec<ProviderInstance>> {
            Ok(self.instances.lock().unwrap().clone())
        }
        fn destroy_instance(&self, instance_id: &str) -> Result<()> {
            let id = validate_instance_id(instance_id)?.to_string();
            self.instances.lock().unwrap().retain(|i| i.id != id);
            self.destroyed_ids.lock().unwrap().push(id);
            Ok(())
        }
    }

    fn base_cfg(tailscale_mode: bool) -> ProvisionConfig {
        ProvisionConfig {
            provider: ProviderKind::Vultr,
            region: "ewr".to_string(),
            plan: "vc2-1c-1gb".to_string(),
            image_id: "2284".to_string(),
            hostname: "bab-vps".to_string(),
            username: "deploy".to_string(),
            role: "caddy".to_string(),
            tags: vec!["tag:bab".to_string()],
            provider_timeout: Duration::from_secs(5),
            tailscale_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(1),
            tailscale_mode,
            ssh_pubkey: Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host".to_string()),
            ssh_key_path: Some("/tmp/bab_ed25519".to_string()),
            sudo_password: None,
        }
    }

    #[test]
    fn default_catalog_presets_cover_cloud_providers_and_empty_for_special() {
        let vultr_regions = default_regions_for(ProviderKind::Vultr);
        assert!(vultr_regions.iter().any(|r| r.id == "ewr"));
        assert!(vultr_regions.iter().any(|r| r.id == "nrt"));
        let upcloud_regions = default_regions_for(ProviderKind::UpCloud);
        assert!(upcloud_regions.iter().any(|r| r.id == "us-nyc1"));
        assert!(upcloud_regions.iter().any(|r| r.id == "sg-sin1"));
        let linode_regions = default_regions_for(ProviderKind::Linode);
        assert!(linode_regions.iter().any(|r| r.id == "us-east"));
        assert!(linode_regions.iter().any(|r| r.id == "eu-central"));

        let vultr_plans = default_plans_for(ProviderKind::Vultr);
        assert!(vultr_plans.iter().any(|p| p.id == "vc2-1c-1gb" && p.summary.contains("1024 MB")));
        assert!(vultr_plans.iter().any(|p| p.id == "vc2-4c-8gb" && p.summary.contains("8192 MB")));
        let upcloud_plans = default_plans_for(ProviderKind::UpCloud);
        assert!(upcloud_plans.iter().any(|p| p.id == "1xCPU-1GB" && p.summary.contains("1 vCPU")));
        assert!(upcloud_plans.iter().any(|p| p.id == "4xCPU-8GB" && p.summary.contains("8192 MB")));
        let linode_plans = default_plans_for(ProviderKind::Linode);
        assert!(linode_plans.iter().any(|p| p.id == "g6-nanode-1" && p.summary.contains("1024 MB")));
        assert!(linode_plans.iter().any(|p| p.id == "g6-standard-4" && p.summary.contains("8192 MB")));

        let vultr_images = default_images_for(ProviderKind::Vultr);
        assert!(vultr_images.iter().any(|i| i.id == "2284" && i.name.contains("Ubuntu 24.04")));
        assert!(vultr_images.iter().any(|i| i.name.contains("Debian 12")));
        let upcloud_images = default_images_for(ProviderKind::UpCloud);
        assert!(upcloud_images
            .iter()
            .any(|i| i.id == "01000000-0000-4000-8000-000030240200" && i.name.contains("Ubuntu")));
        assert!(upcloud_images.iter().any(|i| i.name.contains("Debian")));
        let linode_images = default_images_for(ProviderKind::Linode);
        assert!(linode_images.iter().any(|i| i.id == "linode/ubuntu24.04"));
        assert!(linode_images.iter().any(|i| i.id == "linode/debian12"));

        for special in [ProviderKind::ExistingTailscale, ProviderKind::ManualCloudInit] {
            assert!(default_regions_for(special).is_empty());
            assert!(default_plans_for(special).is_empty());
            assert!(default_images_for(special).is_empty());
        }
    }

    #[test]
    fn provision_full_flow_standard_ssh_mode_saves_session() -> Result<()> {
        let provider = MockProvider::new(Some("203.0.113.42"));
        let tmp = tempfile::NamedTempFile::new()?;
        let session = SessionState::new(tmp.path());
        // Seed a stale TAILSCALE_IP to ensure SSH mode clears it.
        session.set_tailscale_ip("100.64.9.9")?;
        let cfg = base_cfg(false);

        let res = provision_full_flow(&provider, None, &cfg, Some(&session))?;
        assert_eq!(res.instance_id, "inst-123");
        assert_eq!(res.ip, "203.0.113.42");
        assert_eq!(res.public_ip, "203.0.113.42");
        assert_eq!(res.tailscale_ip, "");
        assert!(!res.tailscale_mode);

        let user_data = provider.captured_user_data.lock().unwrap().clone().unwrap();
        assert!(user_data.contains("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest user@host"));
        assert!(!user_data.to_ascii_lowercase().contains("tailscale"));

        let loaded = session.load_session()?;
        assert_eq!(loaded.vps_ip.as_deref(), Some("203.0.113.42"));
        assert_eq!(loaded.public_ip.as_deref(), Some("203.0.113.42"));
        assert_eq!(loaded.tailscale_ip, None);
        assert_eq!(loaded.ssh_key.as_deref(), Some("/tmp/bab_ed25519"));
        assert_eq!(loaded.transport_mode.as_deref(), Some("ssh"));
        assert_eq!(loaded.username.as_deref(), Some("deploy"));
        assert_eq!(loaded.vps_provider.as_deref(), Some("vultr"));
        assert_eq!(loaded.vps_instance_id.as_deref(), Some("inst-123"));
        assert_eq!(loaded.tailscale_hostname.as_deref(), Some("bab-vps"));
        assert_eq!(loaded.server_role.as_deref(), Some("caddy"));
        assert_eq!(loaded.vps_region.as_deref(), Some("ewr"));
        assert_eq!(loaded.vps_plan.as_deref(), Some("vc2-1c-1gb"));
        assert_eq!(loaded.vps_image.as_deref(), Some("2284"));
        Ok(())
    }

    #[test]
    fn provision_full_flow_validates_ssh_mode_and_tailscale_client() {
        let provider = MockProvider::new(Some("203.0.113.42"));
        let mut cfg_no_key = base_cfg(false);
        cfg_no_key.ssh_pubkey = Some("   ".to_string());
        assert!(provision_full_flow(&provider, None, &cfg_no_key, None).is_err());

        let provider_no_ip = MockProvider::new(Some(""));
        let cfg_ssh = base_cfg(false);
        assert!(provision_full_flow(&provider_no_ip, None, &cfg_ssh, None).is_err());

        let cfg_ts = base_cfg(true);
        assert!(provision_full_flow(&provider, None, &cfg_ts, None).is_err());
    }

    #[test]
    fn provision_full_flow_tailscale_mode_saves_session() -> Result<()> {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || {
            let responses = [
                r#"{"key":"tskey-auth-bab"}"#,
                r#"{"devices":[{"id":"dev-1","hostname":"bab-vps","name":"bab-vps.tail1.ts.net","addresses":["100.64.1.2"],"os":"linux","online":true}]}"#,
            ];
            for body in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&stream);
                let mut req_line = String::new();
                reader.read_line(&mut req_line).unwrap();
                let mut content_len = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if content_len > 0 {
                    let mut buf = vec![0u8; content_len];
                    reader.read_exact(&mut buf).unwrap();
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        let ts = TailscaleClient::with_config("ts-api-key", format!("http://{}", addr), "-")?;
        let provider = MockProvider::new(Some("203.0.113.42"));
        let tmp = tempfile::NamedTempFile::new()?;
        let session = SessionState::new(tmp.path());
        let cfg = base_cfg(true);

        let res = provision_full_flow(&provider, Some(&ts), &cfg, Some(&session))?;
        handle.join().unwrap();

        assert_eq!(res.ip, "100.64.1.2");
        assert_eq!(res.tailscale_ip, "100.64.1.2");
        assert_eq!(res.public_ip, "203.0.113.42");
        assert!(res.tailscale_mode);

        let user_data = provider.captured_user_data.lock().unwrap().clone().unwrap();
        assert!(user_data.contains("tailscale up --authkey='tskey-auth-bab'"));

        let loaded = session.load_session()?;
        assert_eq!(loaded.vps_ip.as_deref(), Some("100.64.1.2"));
        assert_eq!(loaded.public_ip.as_deref(), Some("203.0.113.42"));
        assert_eq!(loaded.tailscale_ip.as_deref(), Some("100.64.1.2"));
        assert_eq!(loaded.ssh_key.as_deref(), Some("tailscale"));
        assert_eq!(loaded.transport_mode.as_deref(), Some("tailscale"));
        assert_eq!(loaded.vps_region.as_deref(), Some("ewr"));
        assert_eq!(loaded.vps_plan.as_deref(), Some("vc2-1c-1gb"));
        assert_eq!(loaded.vps_image.as_deref(), Some("2284"));
        Ok(())
    }

    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn new(keys: &[&str]) -> Self {
            let saved = keys
                .iter()
                .map(|k| ((*k).to_string(), std::env::var(k).ok()))
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }

    #[test]
    fn validate_instance_id_accepts_safe_ids_and_rejects_injection() {
        assert_eq!(validate_instance_id("abc-123_XYZ.1").unwrap(), "abc-123_XYZ.1");
        assert_eq!(validate_instance_id("  12345  ").unwrap(), "12345");
        assert_eq!(
            validate_instance_id("00798b85-efdc-41ca-8021-f6ef457b8531").unwrap(),
            "00798b85-efdc-41ca-8021-f6ef457b8531"
        );

        for bad in [
            "",
            "   ",
            "id with space",
            "id\twith\ttab",
            "id\nnewline",
            "id\x00null",
            "foo/bar",
            "foo\\bar",
            "foo?bar=1",
            "foo#frag",
            "foo&bar=2",
            "../other",
            "a..b",
        ] {
            assert!(
                validate_instance_id(bad).is_err(),
                "expected {:?} to be rejected",
                bad
            );
        }
    }

    #[test]
    fn mock_provider_lists_and_destroys_instances() -> Result<()> {
        let provider = MockProvider::new(Some("203.0.113.10"));
        assert_eq!(provider.list_instances()?.len(), 1);
        assert!(provider.destroy_instance("../bad").is_err());
        provider.destroy_instance("  inst-123 ")?;
        assert!(provider.list_instances()?.is_empty());
        assert_eq!(
            *provider.destroyed_ids.lock().unwrap(),
            vec!["inst-123".to_string()]
        );
        Ok(())
    }

    #[test]
    fn query_providers_with_keys_isolates_failures_and_sorts_deterministically() -> Result<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "VULTR_API_BASE_URL",
            "UPCLOUD_API_BASE_URL",
            "LINODE_API_BASE_URL",
        ]);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            for stream_res in listener.incoming() {
                if stop_bg.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = stream_res else {
                    break;
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                    continue;
                }
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    if line.trim().is_empty() {
                        break;
                    }
                }
                let path = req_line.split_whitespace().nth(1).unwrap_or("");
                let (status, body) = if path.starts_with("/vultr/instances") {
                    (
                        "200 OK",
                        r#"{"instances":[
                            {"id":"v-2","label":"zeta","status":"active","power_status":"running","main_ip":"203.0.113.2","region":"ewr","plan":"vc2-1c-1gb","date_created":"2025-01-02T00:00:00Z"},
                            {"id":"v-1","label":"alpha","status":"active","power_status":"running","main_ip":"203.0.113.1","region":"ord","plan":"vc2-1c-2gb","date_created":"2025-01-01T00:00:00Z"}
                        ],"meta":{"links":{"next":""}}}"#,
                    )
                } else if path.starts_with("/linode/linode/instances") {
                    ("500 Internal Server Error", r#"{"errors":[{"reason":"boom"}]}"#)
                } else {
                    ("404 Not Found", r#"{"error":"not found"}"#)
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });

        std::env::set_var("VULTR_API_BASE_URL", format!("http://{}/vultr", addr));
        std::env::remove_var("UPCLOUD_API_BASE_URL");
        std::env::set_var("LINODE_API_BASE_URL", format!("http://{}/linode", addr));

        let res = query_providers_with_keys(Some("vultr-key"), None, Some("linode-key"), None);

        stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(addr);
        handle.join().unwrap();

        assert_eq!(res.instances.len(), 2);
        assert_eq!(res.instances[0].id, "v-1");
        assert_eq!(res.instances[0].name, "alpha");
        assert_eq!(res.instances[1].id, "v-2");
        assert_eq!(res.instances[1].name, "zeta");

        assert_eq!(res.provider_statuses.len(), 3);
        let vultr_st = res
            .provider_statuses
            .iter()
            .find(|s| s.provider == ProviderKind::Vultr)
            .unwrap();
        assert_eq!(
            *vultr_st,
            ProviderQueryStatus {
                provider: ProviderKind::Vultr,
                configured: true,
                instance_count: 2,
                error: None,
            }
        );
        let upcloud_st = res
            .provider_statuses
            .iter()
            .find(|s| s.provider == ProviderKind::UpCloud)
            .unwrap();
        assert_eq!(
            *upcloud_st,
            ProviderQueryStatus {
                provider: ProviderKind::UpCloud,
                configured: false,
                instance_count: 0,
                error: None,
            }
        );
        let linode_st = res
            .provider_statuses
            .iter()
            .find(|s| s.provider == ProviderKind::Linode)
            .unwrap();
        assert!(linode_st.configured);
        assert_eq!(linode_st.instance_count, 0);
        assert!(linode_st.error.as_deref().unwrap().contains("500"));

        Ok(())
    }

    #[test]
    fn clear_destroyed_session_if_matches_clears_only_matching_instance() -> Result<()> {
        let tmp = tempfile::NamedTempFile::new()?;
        let session = SessionState::new(tmp.path());
        let seed = SessionData {
            vps_provider: Some("vultr".to_string()),
            vps_instance_id: Some("inst-42".to_string()),
            vps_ip: Some("100.64.0.42".to_string()),
            public_ip: Some("203.0.113.42".to_string()),
            tailscale_ip: Some("100.64.0.42".to_string()),
            username: Some("deploy".to_string()),
            server_role: Some("caddy".to_string()),
            ..SessionData::default()
        };
        session.save_session(&seed)?;

        assert!(!clear_destroyed_session_if_matches(&session, "")?);
        assert!(!clear_destroyed_session_if_matches(&session, "inst-other")?);
        let unchanged = session.load_session()?;
        assert_eq!(unchanged.vps_instance_id.as_deref(), Some("inst-42"));

        assert!(clear_destroyed_session_if_matches(&session, " inst-42 ")?);
        let cleared = session.load_session()?;
        assert_eq!(cleared.vps_provider, None);
        assert_eq!(cleared.vps_instance_id, None);
        assert_eq!(cleared.vps_ip, None);
        assert_eq!(cleared.public_ip, None);
        assert_eq!(cleared.tailscale_ip, None);
        // Unrelated fields remain intact.
        assert_eq!(cleared.username.as_deref(), Some("deploy"));
        assert_eq!(cleared.server_role.as_deref(), Some("caddy"));
        Ok(())
    }

    #[test]
    fn query_all_providers_and_destroy_via_settings() -> Result<()> {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;

        let _lock = crate::env_lock();
        let _guard = EnvGuard::new(&[
            "VULTR_API_KEY",
            "UPCLOUD_API_TOKEN",
            "LINODE_API_TOKEN",
            "VULTR_API_BASE_URL",
        ]);
        std::env::remove_var("VULTR_API_KEY");
        std::env::remove_var("UPCLOUD_API_TOKEN");
        std::env::remove_var("LINODE_API_TOKEN");

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let handle = thread::spawn(move || {
            let mut seen = Vec::new();
            for step in 0..2 {
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
                seen.push(req_line.trim().to_string());
                let (status, body) = if step == 0 {
                    (
                        "200 OK",
                        r#"{"instances":[{"id":"v-99","label":"prod-box","status":"active","power_status":"running","main_ip":"203.0.113.99","region":"ewr","plan":"vc2-1c-1gb"}],"meta":{"links":{"next":""}}}"#,
                    )
                } else {
                    ("204 No Content", "")
                };
                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
            seen
        });

        let dir = tempfile::tempdir()?;
        let settings = Settings::new(dir.path().join("credentials.enc"));
        settings.set_vultr_api_key("vultr-secret")?;
        std::env::set_var("VULTR_API_BASE_URL", format!("http://{}/v2", addr));

        let queried = query_all_providers(&settings, Some(ProviderKind::Vultr));
        assert_eq!(queried.provider_statuses.len(), 1);
        assert!(queried.provider_statuses[0].configured);
        assert_eq!(queried.provider_statuses[0].instance_count, 1);
        assert_eq!(queried.instances.len(), 1);
        assert_eq!(queried.instances[0].id, "v-99");

        destroy_provider_instance(&settings, ProviderKind::Vultr, "v-99")?;

        let seen = handle.join().unwrap();
        assert!(seen[0].starts_with("GET /v2/instances?per_page=500 "));
        assert!(seen[1].starts_with("DELETE /v2/instances/v-99 "));

        assert!(build_cloud_provider_with_key(ProviderKind::ExistingTailscale, "k", None).is_err());
        assert!(destroy_provider_instance_with_key(ProviderKind::Vultr, "   ", "v-99", None).is_err());
        assert!(destroy_provider_instance(&settings, ProviderKind::Linode, "123").is_err());
        Ok(())
    }

    #[test]
    fn provision_full_flow_with_progress_emits_updates_and_preserves_or_sets_password() -> Result<()>
    {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        struct PollingMockProvider {
            polls: AtomicUsize,
            captured_user_data: std::sync::Mutex<Option<String>>,
        }

        impl VpsProvider for PollingMockProvider {
            fn kind(&self) -> ProviderKind {
                ProviderKind::Vultr
            }
            fn validate_key(&self) -> Result<bool> {
                Ok(true)
            }
            fn list_regions(&self) -> Result<Vec<ProviderRegion>> {
                Ok(vec![])
            }
            fn list_plans(&self) -> Result<Vec<ProviderPlan>> {
                Ok(vec![])
            }
            fn list_images(&self) -> Result<Vec<ProviderImage>> {
                Ok(vec![])
            }
            fn create_instance(&self, req: &CreateInstanceRequest) -> Result<String> {
                *self.captured_user_data.lock().unwrap() = Some(req.user_data_raw.clone());
                Ok("inst-prog-1".to_string())
            }
            fn get_instance_status(&self, _instance_id: &str) -> Result<InstanceStatus> {
                let count = self.polls.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    Ok(InstanceStatus {
                        state: "pending".to_string(),
                        public_ipv4: None,
                        ready: false,
                    })
                } else {
                    Ok(InstanceStatus {
                        state: "active".to_string(),
                        public_ipv4: Some("203.0.113.77".to_string()),
                        ready: true,
                    })
                }
            }
            fn list_instances(&self) -> Result<Vec<ProviderInstance>> {
                Ok(vec![])
            }
            fn destroy_instance(&self, _instance_id: &str) -> Result<()> {
                Ok(())
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let handle = thread::spawn(move || {
            let responses = [
                r#"{"key":"tskey-auth-prog"}"#,
                r#"{"devices":[]}"#,
                r#"{"devices":[{"id":"dev-1","hostname":"bab-vps","name":"bab-vps.tail1.ts.net","addresses":["100.64.2.5"],"os":"linux","online":true}]}"#,
            ];
            for body in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(&stream);
                let mut req_line = String::new();
                reader.read_line(&mut req_line).unwrap();
                let mut content_len = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if content_len > 0 {
                    let mut buf = vec![0u8; content_len];
                    reader.read_exact(&mut buf).unwrap();
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                stream.write_all(resp.as_bytes()).unwrap();
                stream.flush().unwrap();
            }
        });

        let ts = TailscaleClient::with_config("ts-api-key", format!("http://{}", addr), "-")?;
        let provider = PollingMockProvider {
            polls: AtomicUsize::new(0),
            captured_user_data: std::sync::Mutex::new(None),
        };
        let tmp = tempfile::NamedTempFile::new()?;
        let session = SessionState::new(tmp.path());
        let mut cfg = base_cfg(true);
        cfg.sudo_password = Some("Abc1234567".to_string());

        let mut progress = Vec::new();
        let res =
            provision_full_flow_with_progress(&provider, Some(&ts), &cfg, Some(&session), |msg| {
                progress.push(msg.to_string());
            })?;
        handle.join().unwrap();

        assert_eq!(res.instance_id, "inst-prog-1");
        assert_eq!(res.ip, "100.64.2.5");
        assert_eq!(res.public_ip, "203.0.113.77");

        let ud = provider.captured_user_data.lock().unwrap().clone().unwrap();
        assert!(ud.contains("chpasswd"));
        assert!(ud.contains("Abc1234567"));

        assert!(progress.iter().any(|m| m == "[PROVISION] Creating Tailscale auth key and cloud-init..."));
        assert!(progress.iter().any(|m| m == "[PROVISION] Submitting Vultr create_instance request for 'bab-vps'..."));
        assert!(progress.iter().any(|m| m == "[PROVISION] Instance 'inst-prog-1' created; polling Vultr until active..."));
        assert!(progress.iter().any(|m| m.starts_with("[PROVISION] Polling VM 'inst-prog-1' (state=pending, ip=pending, elapsed=")));
        assert_eq!(
            progress
                .iter()
                .filter(|m| m.starts_with("[PROVISION] VM 'inst-prog-1' is active (public IP: 203.0.113.77); waiting for 'bab-vps' on Tailscale (elapsed="))
                .count(),
            2
        );

        let loaded = session.load_session()?;
        assert_eq!(loaded.sudo_password.as_deref(), Some("Abc1234567"));

        // Verify cfg.sudo_password = None does NOT overwrite existing session.sudo_password.
        let ssh_provider = MockProvider::new(Some("203.0.113.88"));
        let mut ssh_cfg = base_cfg(false);
        ssh_cfg.sudo_password = None;
        provision_full_flow_with_progress(&ssh_provider, None, &ssh_cfg, Some(&session), |_| {})?;
        let after_none = session.load_session()?;
        assert_eq!(after_none.sudo_password.as_deref(), Some("Abc1234567"));

        Ok(())
    }

    #[test]
    fn provision_full_flow_with_progress_preserves_partial_session_on_tailscale_timeout(
    ) -> Result<()> {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            for stream_res in listener.incoming() {
                if stop_bg.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(mut stream) = stream_res else {
                    break;
                };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut req_line = String::new();
                if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut content_len = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if content_len > 0 {
                    let mut buf = vec![0u8; content_len];
                    let _ = reader.read_exact(&mut buf);
                }
                let path = req_line.split_whitespace().nth(1).unwrap_or("");
                let body = if path.ends_with("/keys") {
                    r#"{"key":"tskey-auth-timeout"}"#
                } else {
                    r#"{"devices":[]}"#
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });

        let ts = TailscaleClient::with_config("ts-api-key", format!("http://{}", addr), "-")?;
        let provider = MockProvider::new(Some("203.0.113.55"));
        let tmp = tempfile::NamedTempFile::new()?;
        let session = SessionState::new(tmp.path());
        session.save_session(&SessionData {
            vps_instance_id: Some("old-inst".to_string()),
            vps_provider: Some("linode".to_string()),
            tailscale_hostname: Some("old-host".to_string()),
            vps_ip: Some("100.64.9.9".to_string()),
            public_ip: Some("198.51.100.99".to_string()),
            tailscale_ip: Some("100.64.9.9".to_string()),
            sudo_password: Some("OldPass999".to_string()),
            ..SessionData::default()
        })?;

        let mut cfg = base_cfg(true);
        cfg.tailscale_timeout = Duration::from_millis(20);
        cfg.poll_interval = Duration::from_millis(2);
        cfg.sudo_password = Some("TimeoutPass1".to_string());

        let err = provision_full_flow_with_progress(&provider, Some(&ts), &cfg, Some(&session), |_| {})
            .unwrap_err();
        assert!(err.to_string().contains("Timed out waiting for device bab-vps"));

        let loaded = session.load_session()?;
        assert_eq!(loaded.vps_instance_id.as_deref(), Some("inst-123"));
        assert_eq!(loaded.public_ip.as_deref(), Some("203.0.113.55"));
        assert_eq!(loaded.vps_provider.as_deref(), Some("vultr"));
        assert_eq!(loaded.tailscale_hostname.as_deref(), Some("bab-vps"));
        assert_eq!(loaded.username.as_deref(), Some("deploy"));
        assert_eq!(loaded.transport_mode.as_deref(), Some("tailscale"));
        assert_eq!(loaded.server_role.as_deref(), Some("caddy"));
        assert_eq!(loaded.vps_region.as_deref(), Some("ewr"));
        assert_eq!(loaded.vps_plan.as_deref(), Some("vc2-1c-1gb"));
        assert_eq!(loaded.vps_image.as_deref(), Some("2284"));
        assert_eq!(loaded.sudo_password.as_deref(), Some("TimeoutPass1"));
        assert_eq!(loaded.vps_ip, None);
        assert_eq!(loaded.tailscale_ip, None);

        // Blank sudo_password on a subsequent timed-out run preserves existing sudo_password and clears stale IPs.
        session.set_vps_ip("100.64.8.8")?;
        session.set_tailscale_ip("100.64.8.8")?;
        session.set_public_ip("198.51.100.88")?;
        cfg.sudo_password = Some("   ".to_string());

        let err2 = provision_full_flow_with_progress(&provider, Some(&ts), &cfg, Some(&session), |_| {})
            .unwrap_err();
        assert!(err2.to_string().contains("Timed out waiting for device bab-vps"));

        stop.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(addr);
        handle.join().unwrap();

        let preserved = session.load_session()?;
        assert_eq!(preserved.vps_instance_id.as_deref(), Some("inst-123"));
        assert_eq!(preserved.public_ip.as_deref(), Some("203.0.113.55"));
        assert_eq!(preserved.vps_provider.as_deref(), Some("vultr"));
        assert_eq!(preserved.tailscale_hostname.as_deref(), Some("bab-vps"));
        assert_eq!(preserved.sudo_password.as_deref(), Some("TimeoutPass1"));
        assert_eq!(preserved.vps_ip, None);
        assert_eq!(preserved.tailscale_ip, None);

        Ok(())
    }

    #[test]
    fn default_upcloud_plans_include_pricing_summaries() {
        let plans = default_plans_for(ProviderKind::UpCloud);
        assert_eq!(plans.len(), 4);
        assert_eq!(plans[0].summary, "1 vCPU, 1024 MB RAM, 25 GB SSD ($5/mo)");
        assert_eq!(plans[1].summary, "1 vCPU, 2048 MB RAM, 50 GB SSD ($10/mo)");
        assert_eq!(plans[2].summary, "2 vCPU, 4096 MB RAM, 80 GB SSD ($20/mo)");
        assert_eq!(plans[3].summary, "4 vCPU, 8192 MB RAM, 160 GB SSD ($40/mo)");
    }

    #[test]
    fn plan_pricing_covers_known_fallback_and_unknown_plans() {
        let vultr_cases = [
            ("vc2-1c-0.5gb-free", 0.0, 0.0),
            ("vc2-1c-0.5gb-v6", 2.5, 0.003),
            ("vc2-1c-0.5gb", 3.5, 0.005),
            ("vc2-1c-1gb", 5.0, 0.007),
            ("vc2-1c-2gb", 10.0, 0.014),
            ("vc2-2c-4gb", 20.0, 0.027),
            ("vc2-4c-8gb", 40.0, 0.055),
            ("vc2-6c-16gb", 80.0, 0.110),
            ("vc2-8c-32gb", 160.0, 0.219),
        ];
        for (plan_id, monthly, hourly) in vultr_cases {
            assert_eq!(
                plan_pricing(ProviderKind::Vultr, plan_id),
                Some(PlanPricing {
                    monthly_usd: monthly,
                    hourly_usd: hourly,
                }),
                "vultr plan {plan_id}"
            );
        }

        let vultr_fb = plan_pricing(ProviderKind::Vultr, "vc2-16c-64gb").unwrap();
        assert_eq!(vultr_fb.monthly_usd, 320.0);
        assert!((vultr_fb.hourly_usd - (320.0 / 730.0)).abs() < 1e-12);

        let vultr_frac_fb = plan_pricing(ProviderKind::Vultr, "vc2-1c-1.5gb").unwrap();
        assert_eq!(vultr_frac_fb.monthly_usd, 7.5);

        let upcloud_cases = [
            ("1xCPU-1GB", 5.0, 0.007),
            ("1xCPU-2GB", 10.0, 0.015),
            ("2xCPU-4GB", 20.0, 0.030),
            ("4xCPU-8GB", 40.0, 0.060),
            ("6xCPU-16GB", 80.0, 0.119),
        ];
        for (plan_id, monthly, hourly) in upcloud_cases {
            assert_eq!(
                plan_pricing(ProviderKind::UpCloud, plan_id),
                Some(PlanPricing {
                    monthly_usd: monthly,
                    hourly_usd: hourly,
                }),
                "upcloud plan {plan_id}"
            );
        }

        let uc_fb = plan_pricing(ProviderKind::UpCloud, "8xcpu-32gb").unwrap();
        assert_eq!(uc_fb.monthly_usd, 160.0);
        assert!((uc_fb.hourly_usd - (160.0 / 730.0)).abs() < 1e-12);

        let linode_cases = [
            ("g6-nanode-1", 5.0, 0.0075),
            ("g6-standard-1", 12.0, 0.018),
            ("g6-standard-2", 24.0, 0.036),
            ("g6-standard-4", 48.0, 0.072),
            ("g6-standard-6", 96.0, 0.144),
            ("g6-standard-8", 192.0, 0.288),
        ];
        for (plan_id, monthly, hourly) in linode_cases {
            assert_eq!(
                plan_pricing(ProviderKind::Linode, plan_id),
                Some(PlanPricing {
                    monthly_usd: monthly,
                    hourly_usd: hourly,
                }),
                "linode plan {plan_id}"
            );
        }

        for (provider, bad_id) in [
            (ProviderKind::Vultr, ""),
            (ProviderKind::Vultr, "   "),
            (ProviderKind::Vultr, "vc2-0c-1gb"),
            (ProviderKind::Vultr, "vc2-1c-0gb"),
            (ProviderKind::Vultr, "vc2-free"),
            (ProviderKind::UpCloud, "DEV-1xCPU-1GB"),
            (ProviderKind::UpCloud, "1xCPU-0GB"),
            (ProviderKind::Linode, "g6-dedicated-2"),
            (ProviderKind::ExistingTailscale, "vc2-1c-1gb"),
            (ProviderKind::ManualCloudInit, "1xCPU-1GB"),
        ] {
            assert_eq!(plan_pricing(provider, bad_id), None, "{provider:?} {bad_id}");
        }
    }

    #[test]
    fn format_usd_helpers_format_monthly_and_hourly_rates() {
        assert_eq!(format_monthly_usd(5.0), "$5/mo");
        assert_eq!(format_monthly_usd(0.0), "$0/mo");
        assert_eq!(format_monthly_usd(2.5), "$2.50/mo");
        assert_eq!(format_monthly_usd(3.5), "$3.50/mo");
        assert_eq!(format_hourly_usd(0.0), "$0.000/hr");
        assert_eq!(format_hourly_usd(0.007), "$0.007/hr");
        assert_eq!(format_hourly_usd(0.0075), "$0.0075/hr");
        assert_eq!(format_hourly_usd(0.014), "$0.014/hr");
        assert_eq!(format_hourly_usd(0.030), "$0.030/hr");
    }

    #[test]
    fn parse_created_at_epoch_secs_parses_iso_formats_offsets_and_epoch() {
        // 2025-01-01T00:00:00Z == 1735689600
        assert_eq!(
            parse_created_at_epoch_secs("2025-01-01T00:00:00Z"),
            Some(1_735_689_600)
        );
        assert_eq!(
            parse_created_at_epoch_secs("2025-01-01T02:00:00+02:00"),
            Some(1_735_689_600)
        );
        assert_eq!(
            parse_created_at_epoch_secs("2024-12-31T19:00:00-05:00"),
            Some(1_735_689_600)
        );
        assert_eq!(
            parse_created_at_epoch_secs("2025-01-01T00:00:00"),
            Some(1_735_689_600)
        );
        assert_eq!(
            parse_created_at_epoch_secs("2025-01-01 00:00:00"),
            Some(1_735_689_600)
        );
        assert_eq!(
            parse_created_at_epoch_secs("2025-01-01T00:00:00.123456Z"),
            Some(1_735_689_600)
        );
        assert_eq!(
            parse_created_at_epoch_secs("2025-01-01 05:30:00.999+05:30"),
            Some(1_735_689_600)
        );
        assert_eq!(
            parse_created_at_epoch_secs("2024-02-29T00:00:00Z"),
            Some(1_709_164_800)
        );
        assert_eq!(
            parse_created_at_epoch_secs("2000-02-29T00:00:00Z"),
            Some(951_782_400)
        );
        assert_eq!(
            parse_created_at_epoch_secs(" 1735689600 "),
            Some(1_735_689_600)
        );

        for invalid in [
            "",
            "0",
            "-100",
            "not-a-timestamp",
            "2025-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2025-13-01T00:00:00Z",
            "2025-04-31T00:00:00Z",
            "2025-01-01T24:00:00Z",
            "2025-01-01T00:60:00Z",
            "2025-01-01T00:00:60Z",
            "2025-01-01T00:00:00.",
            "2025-01-01T00:00:00+24:00",
            "2025-01-01T00:00:00Zextra",
        ] {
            assert_eq!(parse_created_at_epoch_secs(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn format_uptime_duration_formats_all_ranges() {
        assert_eq!(format_uptime_duration(0), "<1m");
        assert_eq!(format_uptime_duration(59), "<1m");
        assert_eq!(format_uptime_duration(60), "1m");
        assert_eq!(format_uptime_duration(900), "15m");
        assert_eq!(format_uptime_duration(3599), "59m");
        assert_eq!(format_uptime_duration(3600), "1h 0m");
        assert_eq!(format_uptime_duration(5400), "1h 30m");
        assert_eq!(format_uptime_duration(86399), "23h 59m");
        assert_eq!(format_uptime_duration(86400), "1d 0h");
        assert_eq!(format_uptime_duration(90000), "1d 1h");
        assert_eq!(format_uptime_duration(259200), "3d 0h");
    }

    #[test]
    fn provider_instance_cost_estimate_and_formatters_at() {
        let created_epoch = 1_735_689_600; // 2025-01-01T00:00:00Z
        let mut inst = ProviderInstance {
            provider: ProviderKind::Vultr,
            id: "v-1".to_string(),
            name: "box-1".to_string(),
            status: "active (running)".to_string(),
            public_ip: Some("203.0.113.10".to_string()),
            region: Some("ewr".to_string()),
            plan: Some("vc2-1c-1gb".to_string()),
            created_at: Some("2025-01-01T00:00:00Z".to_string()),
        };

        // 15m elapsed -> 1 billable hour @ $0.007/hr
        let est_15m = inst.cost_estimate_at(created_epoch + 900).unwrap();
        assert_eq!(est_15m.accrued_usd, Some(0.007));
        assert_eq!(est_15m.elapsed_secs, Some(900));
        assert_eq!(est_15m.monthly_usd, 5.0);
        assert_eq!(est_15m.hourly_usd, 0.007);
        assert_eq!(inst.format_running_cost_compact_at(created_epoch + 900), "$0.01/$5/mo");
        assert_eq!(
            inst.format_running_cost_detailed_at(created_epoch + 900),
            "$0.01 (15m @ $0.007/hr, $5/mo)"
        );

        // 2h 30m elapsed -> 3 billable hours @ $0.007/hr = $0.021
        let est_2h30m = inst.cost_estimate_at(created_epoch + 9000).unwrap();
        assert!((est_2h30m.accrued_usd.unwrap() - 0.021).abs() < 1e-12);
        assert_eq!(
            inst.format_running_cost_detailed_at(created_epoch + 9000),
            "$0.02 (2h 30m @ $0.007/hr, $5/mo)"
        );

        // Capped at monthly_usd after many hours (40 days)
        let est_40d = inst.cost_estimate_at(created_epoch + 40 * 86_400).unwrap();
        assert_eq!(est_40d.accrued_usd, Some(5.0));
        assert_eq!(
            inst.format_running_cost_compact_at(created_epoch + 40 * 86_400),
            "$5.00/$5/mo"
        );
        assert_eq!(
            inst.format_running_cost_detailed_at(created_epoch + 40 * 86_400),
            "$5.00 (40d 0h @ $0.007/hr, $5/mo)"
        );

        // Future created_at falls back to pricing-only formatting
        assert_eq!(inst.format_running_cost_compact_at(created_epoch - 60), "$5/mo");
        assert_eq!(
            inst.format_running_cost_detailed_at(created_epoch - 60),
            "$5/mo ($0.007/hr)"
        );

        // Missing created_at with fractional monthly rate
        inst.plan = Some("vc2-1c-0.5gb-v6".to_string());
        inst.created_at = None;
        assert_eq!(inst.format_running_cost_compact_at(created_epoch), "$2.50/mo");
        assert_eq!(
            inst.format_running_cost_detailed_at(created_epoch),
            "$2.50/mo ($0.003/hr)"
        );

        // Linode 4-decimal hourly rate
        inst.provider = ProviderKind::Linode;
        inst.plan = Some("g6-nanode-1".to_string());
        inst.created_at = Some("2025-01-01T00:00:00".to_string());
        assert_eq!(
            inst.format_running_cost_detailed_at(created_epoch + 900),
            "$0.01 (15m @ $0.0075/hr, $5/mo)"
        );

        // Unknown plan -> None / "-"
        inst.plan = Some("unknown-plan".to_string());
        assert_eq!(inst.cost_estimate_at(created_epoch + 900), None);
        assert_eq!(inst.format_running_cost_compact_at(created_epoch + 900), "-");
        assert_eq!(inst.format_running_cost_detailed_at(created_epoch + 900), "-");
    }
}
