use anyhow::{anyhow, Result};
use reqwest::blocking::Client;
use reqwest::header::USER_AGENT;
use serde::Deserialize;
use std::env;
use std::time::Duration;

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

const DEFAULT_CLOUDFLARE_API_BASE: &str = "https://api.cloudflare.com/client/v4";

#[derive(Debug, Deserialize)]
struct CloudflareVerifyResponse {
    success: bool,
}

/// Validates a Cloudflare API token against the base URL in `CLOUDFLARE_API_BASE`
/// (falling back to the default Cloudflare v4 API endpoint when unset or blank).
pub fn validate_cloudflare_token(token: &str) -> Result<bool> {
    let base = env::var("CLOUDFLARE_API_BASE")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_CLOUDFLARE_API_BASE.to_string());
    validate_cloudflare_token_with_base(token, &base)
}

/// Validates a Cloudflare API token against an explicit Cloudflare API base URL.
pub fn validate_cloudflare_token_with_base(token: &str, base_url: &str) -> Result<bool> {
    let token = token.trim();
    if token.is_empty() {
        return Ok(false);
    }

    let url = format!("{}/user/tokens/verify", base_url.trim().trim_end_matches('/'));
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow!("Failed to build HTTP client: {}", e))?;

    let resp = client
        .get(&url)
        .bearer_auth(token)
        .header(USER_AGENT, "bab/0.1")
        .send()?;

    let status = resp.status();
    match status.as_u16() {
        200..=299 => {
            let data: CloudflareVerifyResponse = resp.json()?;
            Ok(data.success)
        }
        401 | 403 => Ok(false),
        _ => {
            let body = resp.text().unwrap_or_default();
            Err(anyhow!(
                "Unexpected status {} when validating Cloudflare API token: {}",
                status,
                body
            ))
        }
    }
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

    #[derive(Debug, Clone)]
    struct RecordedRequest {
        method: String,
        path: String,
        authorization: Option<String>,
        user_agent: Option<String>,
    }

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

    struct EnvGuard {
        key: &'static str,
        original: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let original = env::var_os(key);
            env::set_var(key, value);
            Self { key, original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(val) => env::set_var(self.key, val),
                None => env::remove_var(self.key),
            }
        }
    }

    fn spawn_mock_server(
        responses: Vec<MockResponse>,
    ) -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<RecordedRequest>>>,
        std::thread::JoinHandle<()>,
    ) {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;

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

                let mut authorization = None;
                let mut user_agent = None;
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
                        if name_lower == "authorization" {
                            authorization = Some(val_trimmed);
                        } else if name_lower == "user-agent" {
                            user_agent = Some(val_trimmed);
                        }
                    }
                }

                recorded_clone.lock().unwrap().push(RecordedRequest {
                    method,
                    path,
                    authorization,
                    user_agent,
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
    fn validate_cloudflare_token_returns_false_for_empty_or_whitespace_token() {
        assert!(!validate_cloudflare_token_with_base("", "http://127.0.0.1:1").unwrap());
        assert!(!validate_cloudflare_token_with_base("   \t\n ", "http://127.0.0.1:1").unwrap());
    }

    #[test]
    fn validate_cloudflare_token_with_base_handles_200_success_true_and_false() {
        let (base_url, recorded, handle) = spawn_mock_server(vec![
            MockResponse::json(200, "OK", r#"{"success":true,"errors":[],"messages":[]}"#),
            MockResponse::json(200, "OK", r#"{"success":false,"errors":[],"messages":[]}"#),
        ]);

        assert!(validate_cloudflare_token_with_base("  cf-valid-token \n", &base_url).unwrap());
        assert!(!validate_cloudflare_token_with_base("cf-inactive-token", &base_url).unwrap());

        handle.join().expect("mock server thread");
        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 2);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].path, "/user/tokens/verify");
        assert_eq!(reqs[0].authorization.as_deref(), Some("Bearer cf-valid-token"));
        assert_eq!(reqs[0].user_agent.as_deref(), Some("bab/0.1"));
        assert_eq!(reqs[1].path, "/user/tokens/verify");
        assert_eq!(
            reqs[1].authorization.as_deref(),
            Some("Bearer cf-inactive-token")
        );
    }

    #[test]
    fn validate_cloudflare_token_with_base_returns_false_on_401_and_403() {
        let (base_url, recorded, handle) = spawn_mock_server(vec![
            MockResponse::json(401, "Unauthorized", r#"{"success":false}"#),
            MockResponse::json(403, "Forbidden", r#"{"success":false}"#),
        ]);

        assert!(!validate_cloudflare_token_with_base("bad-token", &base_url).unwrap());
        assert!(!validate_cloudflare_token_with_base("forbidden-token", &base_url).unwrap());

        handle.join().expect("mock server thread");
        assert_eq!(recorded.lock().unwrap().len(), 2);
    }

    #[test]
    fn validate_cloudflare_token_with_base_errors_on_500() {
        let (base_url, recorded, handle) = spawn_mock_server(vec![MockResponse::json(
            500,
            "Internal Server Error",
            r#"{"success":false,"errors":[{"message":"boom"}]}"#,
        )]);

        let err = validate_cloudflare_token_with_base("cf-token", &base_url).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Unexpected status 500"), "unexpected error: {msg}");
        assert!(msg.contains("boom"), "unexpected error: {msg}");

        handle.join().expect("mock server thread");
        assert_eq!(recorded.lock().unwrap().len(), 1);
    }

    #[test]
    fn validate_cloudflare_token_honors_cloudflare_api_base_env() {
        let _lock = crate::env_lock();
        let (base_url, recorded, handle) = spawn_mock_server(vec![MockResponse::json(
            200,
            "OK",
            r#"{"success":true}"#,
        )]);
        let _env = EnvGuard::set("CLOUDFLARE_API_BASE", &format!("{base_url}/"));

        assert!(validate_cloudflare_token("cf-env-token").unwrap());

        handle.join().expect("mock server thread");
        let reqs = recorded.lock().unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].path, "/user/tokens/verify");
        assert_eq!(reqs[0].authorization.as_deref(), Some("Bearer cf-env-token"));
        assert_eq!(reqs[0].user_agent.as_deref(), Some("bab/0.1"));
    }
}
