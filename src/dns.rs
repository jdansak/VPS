use anyhow::{anyhow, Result};

/// Configuration for a Cloudflare DNS A-record upsert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudflareDnsConfig {
    pub zone: String,
    pub record_name: String,
    pub target_ip: String,
    pub proxied: bool,
}

/// Validates an RFC-1123 domain or DNS record label.
///
/// Allows `@` for the zone apex record and an optional leading `*.` wildcard prefix
/// for record labels. Each dot-separated label must be 1..=63 ASCII alphanumeric
/// or `-` characters with no leading or trailing `-` or whitespace, and total length <= 253.
pub fn validate_dns_domain(s: &str) -> bool {
    if s == "@" {
        return true;
    }
    if s.is_empty() || s.len() > 253 || s.chars().any(char::is_whitespace) {
        return false;
    }

    let rest = s.strip_prefix("*.").unwrap_or(s);
    if rest.is_empty() {
        return false;
    }

    for label in rest.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }

    true
}

/// Validates Cloudflare DNS inputs and builds a stub execution plan description.
pub fn build_cloudflare_dns_stub_plan(
    cfg: &CloudflareDnsConfig,
    has_token: bool,
) -> Result<String> {
    let zone = cfg.zone.trim();
    if zone == "@" || zone.starts_with("*.") || !validate_dns_domain(zone) {
        return Err(anyhow!("Invalid Cloudflare DNS zone: '{}'", cfg.zone));
    }

    let record = cfg.record_name.trim();
    if !(record == "@" || validate_dns_domain(record)) {
        return Err(anyhow!(
            "Invalid Cloudflare DNS record name: '{}'",
            cfg.record_name
        ));
    }

    let ip = cfg.target_ip.trim();
    if ip.is_empty() || !crate::transport::is_valid_target(ip) {
        return Err(anyhow!(
            "Invalid Cloudflare DNS target IP: '{}'",
            cfg.target_ip
        ));
    }

    Ok(format!(
        "[STUB] Cloudflare DNS: would upsert A record '{}' -> '{}' in zone '{}' (proxied={}, token_configured={})",
        record, ip, zone, cfg.proxied, has_token
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_dns_domain_accepts_valid_inputs() {
        assert!(validate_dns_domain("@"));
        assert!(validate_dns_domain("example.com"));
        assert!(validate_dns_domain("sub.example.com"));
        assert!(validate_dns_domain("my-app-01.example.co.uk"));
        assert!(validate_dns_domain("www"));
        assert!(validate_dns_domain("*.example.com"));
        assert!(validate_dns_domain("*.sub"));

        let max_label = "a".repeat(63);
        assert!(validate_dns_domain(&format!("{}.com", max_label)));

        // Total length exactly 253: 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
        let l63 = "a".repeat(63);
        let l61 = "b".repeat(61);
        let max_domain = format!("{}.{}.{}.{}", l63, l63, l63, l61);
        assert_eq!(max_domain.len(), 253);
        assert!(validate_dns_domain(&max_domain));
    }

    #[test]
    fn validate_dns_domain_rejects_invalid_inputs() {
        assert!(!validate_dns_domain(""));
        assert!(!validate_dns_domain("   "));
        assert!(!validate_dns_domain(" example.com"));
        assert!(!validate_dns_domain("example.com "));
        assert!(!validate_dns_domain("bad domain.com"));
        assert!(!validate_dns_domain("-leading.com"));
        assert!(!validate_dns_domain("trailing-.com"));
        assert!(!validate_dns_domain("example.-com"));
        assert!(!validate_dns_domain("example.com-"));
        assert!(!validate_dns_domain(".example.com"));
        assert!(!validate_dns_domain("example.com."));
        assert!(!validate_dns_domain("a..b.com"));
        assert!(!validate_dns_domain("*."));
        assert!(!validate_dns_domain("*"));
        assert!(!validate_dns_domain("a.*.example.com"));
        assert!(!validate_dns_domain("bad_label.example.com"));

        let too_long_label = "a".repeat(64);
        assert!(!validate_dns_domain(&format!("{}.com", too_long_label)));

        let l63 = "a".repeat(63);
        let l62 = "b".repeat(62);
        let too_long_domain = format!("{}.{}.{}.{}", l63, l63, l63, l62);
        assert_eq!(too_long_domain.len(), 254);
        assert!(!validate_dns_domain(&too_long_domain));
    }

    #[test]
    fn build_stub_plan_outputs_expected_format_for_token_true_and_false() {
        let cfg = CloudflareDnsConfig {
            zone: "example.com".to_string(),
            record_name: "@".to_string(),
            target_ip: "203.0.113.10".to_string(),
            proxied: true,
        };
        let with_token = build_cloudflare_dns_stub_plan(&cfg, true).unwrap();
        assert_eq!(
            with_token,
            "[STUB] Cloudflare DNS: would upsert A record '@' -> '203.0.113.10' in zone 'example.com' (proxied=true, token_configured=true)"
        );

        let sub_cfg = CloudflareDnsConfig {
            zone: "example.com".to_string(),
            record_name: "app.example.com".to_string(),
            target_ip: "198.51.100.42".to_string(),
            proxied: false,
        };
        let without_token = build_cloudflare_dns_stub_plan(&sub_cfg, false).unwrap();
        assert_eq!(
            without_token,
            "[STUB] Cloudflare DNS: would upsert A record 'app.example.com' -> '198.51.100.42' in zone 'example.com' (proxied=false, token_configured=false)"
        );
    }

    #[test]
    fn build_stub_plan_rejects_invalid_zone_record_and_ip() {
        let bad_zone_apex = CloudflareDnsConfig {
            zone: "@".to_string(),
            record_name: "www".to_string(),
            target_ip: "203.0.113.10".to_string(),
            proxied: true,
        };
        assert!(build_cloudflare_dns_stub_plan(&bad_zone_apex, true).is_err());

        let bad_zone_wildcard = CloudflareDnsConfig {
            zone: "*.example.com".to_string(),
            record_name: "www".to_string(),
            target_ip: "203.0.113.10".to_string(),
            proxied: true,
        };
        assert!(build_cloudflare_dns_stub_plan(&bad_zone_wildcard, true).is_err());

        let bad_record = CloudflareDnsConfig {
            zone: "example.com".to_string(),
            record_name: "-bad".to_string(),
            target_ip: "203.0.113.10".to_string(),
            proxied: false,
        };
        assert!(build_cloudflare_dns_stub_plan(&bad_record, false).is_err());

        let bad_ip_empty = CloudflareDnsConfig {
            zone: "example.com".to_string(),
            record_name: "www".to_string(),
            target_ip: "   ".to_string(),
            proxied: false,
        };
        assert!(build_cloudflare_dns_stub_plan(&bad_ip_empty, false).is_err());

        let bad_ip_invalid = CloudflareDnsConfig {
            zone: "example.com".to_string(),
            record_name: "www".to_string(),
            target_ip: "999.1.2.3".to_string(),
            proxied: false,
        };
        assert!(build_cloudflare_dns_stub_plan(&bad_ip_invalid, false).is_err());
    }

    #[test]
    fn build_stub_plan_trims_leading_and_trailing_whitespace_before_validating() {
        let apex_cfg = CloudflareDnsConfig {
            zone: "  example.com \t".to_string(),
            record_name: "  @ \n".to_string(),
            target_ip: "\t 203.0.113.10  ".to_string(),
            proxied: true,
        };
        let apex_plan = build_cloudflare_dns_stub_plan(&apex_cfg, true).unwrap();
        assert_eq!(
            apex_plan,
            "[STUB] Cloudflare DNS: would upsert A record '@' -> '203.0.113.10' in zone 'example.com' (proxied=true, token_configured=true)"
        );

        let sub_cfg = CloudflareDnsConfig {
            zone: " example.com ".to_string(),
            record_name: "  app.example.com  ".to_string(),
            target_ip: "  100.64.0.42\n".to_string(),
            proxied: false,
        };
        let sub_plan = build_cloudflare_dns_stub_plan(&sub_cfg, false).unwrap();
        assert_eq!(
            sub_plan,
            "[STUB] Cloudflare DNS: would upsert A record 'app.example.com' -> '100.64.0.42' in zone 'example.com' (proxied=false, token_configured=false)"
        );
    }
}
