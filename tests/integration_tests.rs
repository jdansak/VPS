use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tempfile::tempdir;

use bab::config::{SessionData, SessionState};
use bab::providers::linode::LinodeProvider;
use bab::providers::upcloud::UpCloudProvider;
use bab::providers::vultr::VultrProvider;
use bab::providers::{
    clear_destroyed_session_if_matches, destroy_provider_instance_with_key, provision_full_flow,
    query_providers_with_keys, CreateInstanceRequest, ProvisionConfig, ProviderKind, VpsProvider,
};
use bab::roles::ServerRole;
use bab::setup::{GithubDeployConfig, SetupConfig, SetupRunner, SetupStepKind};
use bab::tailscale::TailscaleClient;
use bab::transport::{ensure_ssh_keypair, read_public_key, SshTransport, TransportMode};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct EnvGuard {
    saved: Vec<(String, Option<String>)>,
}

impl EnvGuard {
    fn new(keys: &[&str]) -> Self {
        let saved = keys
            .iter()
            .map(|k| ((*k).to_string(), env::var(k).ok()))
            .collect();
        Self { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, v) in self.saved.drain(..) {
            match v {
                Some(val) => env::set_var(&k, val),
                None => env::remove_var(&k),
            }
        }
    }
}

#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    body: String,
}

struct MockState {
    requests: Vec<RecordedRequest>,
    tailscale_devices: Vec<Value>,
    vultr_instances: HashMap<String, String>,
    vultr_polls: HashMap<String, usize>,
    upcloud_servers: HashMap<String, String>,
    upcloud_polls: HashMap<String, usize>,
    upcloud_stopped: HashSet<String>,
    linode_instances: HashMap<String, String>,
    linode_polls: HashMap<String, usize>,
    force_error_path: Option<String>,
}

impl MockState {
    fn new() -> Self {
        Self {
            requests: Vec::new(),
            tailscale_devices: vec![json!({
                "id": "dev-existing",
                "hostname": "existing-box",
                "name": "existing-box.tail99.ts.net",
                "addresses": ["100.64.0.9"],
                "os": "linux",
                "online": true
            })],
            vultr_instances: HashMap::new(),
            vultr_polls: HashMap::new(),
            upcloud_servers: HashMap::new(),
            upcloud_polls: HashMap::new(),
            upcloud_stopped: HashSet::new(),
            linode_instances: HashMap::new(),
            linode_polls: HashMap::new(),
            force_error_path: None,
        }
    }

    fn register_tailscale_device(&mut self, hostname: &str, ip: &str) {
        if self
            .tailscale_devices
            .iter()
            .any(|d| d.get("hostname").and_then(|v| v.as_str()) == Some(hostname))
        {
            return;
        }
        let id = format!("dev-{}", self.tailscale_devices.len() + 1);
        self.tailscale_devices.push(json!({
            "id": id,
            "hostname": hostname,
            "name": format!("{}.tail99.ts.net", hostname),
            "addresses": [ip, "fd7a:115c:a1e0::50"],
            "os": "linux",
            "connected_to_control": true
        }));
    }
}

struct MockApiServer {
    addr: SocketAddr,
    state: Arc<Mutex<MockState>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MockApiServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock http server");
        let addr = listener.local_addr().expect("mock local_addr");
        let state = Arc::new(Mutex::new(MockState::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let state_bg = Arc::clone(&state);
        let stop_bg = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            for stream_res in listener.incoming() {
                if stop_bg.load(Ordering::SeqCst) {
                    break;
                }
                if let Ok(stream) = stream_res {
                    handle_connection(stream, &state_bg);
                }
            }
        });

        Self {
            addr,
            state,
            stop,
            handle: Some(handle),
        }
    }

    fn base_url(&self, prefix: &str) -> String {
        format!(
            "http://{}/{}",
            self.addr,
            prefix.trim_start_matches('/')
        )
    }

    fn requests(&self) -> Vec<RecordedRequest> {
        self.state.lock().unwrap().requests.clone()
    }
}

impl Drop for MockApiServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn check_auth(auth_header: Option<&str>) -> bool {
    let Some(auth) = auth_header else {
        return false;
    };
    if let Some(token) = auth.strip_prefix("Bearer ") {
        let t = token.trim();
        return !t.is_empty() && !t.starts_with("invalid") && !t.starts_with("bad");
    }
    if let Some(encoded) = auth.strip_prefix("Basic ") {
        let Ok(bytes) = BASE64_STANDARD.decode(encoded.trim()) else {
            return false;
        };
        let Ok(decoded) = String::from_utf8(bytes) else {
            return false;
        };
        return decoded.contains(':')
            && !decoded.starts_with("invalid")
            && !decoded.starts_with("bad");
    }
    false
}

fn send_json(stream: &mut TcpStream, status: u16, reason: &str, body: &Value) {
    let payload = body.to_string();
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        reason,
        payload.len(),
        payload
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn send_no_content(stream: &mut TcpStream) {
    let resp = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn handle_connection(mut stream: TcpStream, state: &Arc<Mutex<MockState>>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

    let mut request_line = String::new();
    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let raw_target = parts.next().unwrap_or("").to_string();
    let path = raw_target
        .split('?')
        .next()
        .unwrap_or(&raw_target)
        .to_string();

    let mut content_length = 0usize;
    let mut authorization: Option<String> = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, val)) = trimmed.split_once(':') {
            let lower = name.trim().to_ascii_lowercase();
            let v = val.trim().to_string();
            if lower == "content-length" {
                content_length = v.parse().unwrap_or(0);
            } else if lower == "authorization" {
                authorization = Some(v);
            }
        }
    }

    let mut body_buf = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body_buf).is_err() {
        return;
    }
    let body = String::from_utf8_lossy(&body_buf).to_string();

    {
        let mut st = state.lock().unwrap();
        st.requests.push(RecordedRequest {
            method: method.clone(),
            path: path.clone(),
            authorization: authorization.clone(),
            body: body.clone(),
        });
    }

    if !check_auth(authorization.as_deref()) {
        send_json(&mut stream, 401, "Unauthorized", &json!({"message": "Unauthorized"}));
        return;
    }

    {
        let st = state.lock().unwrap();
        if st.force_error_path.as_deref() == Some(path.as_str()) {
            send_json(
                &mut stream,
                500,
                "Internal Server Error",
                &json!({"error": "forced server error"}),
            );
            return;
        }
    }

    let parsed_body: Value = if body.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(&body).unwrap_or_else(|_| json!({}))
    };

    match (method.as_str(), path.as_str()) {
        // --- Tailscale API v2 ---
        ("GET", p) if p.starts_with("/api/v2/tailnet/") && p.ends_with("/devices") => {
            let devices = state.lock().unwrap().tailscale_devices.clone();
            send_json(&mut stream, 200, "OK", &json!({ "devices": devices }));
        }
        ("POST", p) if p.starts_with("/api/v2/tailnet/") && p.ends_with("/keys") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({ "key": "tskey-auth-int-123", "id": "key-1" }),
            );
        }
        ("DELETE", p) if p.starts_with("/api/v2/device/") => {
            let dev_id = &p["/api/v2/device/".len()..];
            let mut st = state.lock().unwrap();
            st.tailscale_devices
                .retain(|d| d.get("id").and_then(|v| v.as_str()) != Some(dev_id));
            send_json(&mut stream, 200, "OK", &json!({}));
        }

        // --- Vultr API v2 ---
        ("GET", "/v2/account") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({ "account": { "name": "vultr-mock" } }),
            );
        }
        ("GET", "/v2/regions") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "regions": [
                        { "id": "ewr", "city": "New Jersey", "country": "US" },
                        { "id": "cdg", "city": "Paris", "country": "FR" }
                    ]
                }),
            );
        }
        ("GET", "/v2/plans") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "plans": [
                        { "id": "vc2-1c-1gb", "vcpu_count": 1, "ram": 1024, "disk": 25, "monthly_cost": 5 },
                        { "id": "vc2-1c-2gb", "vcpu_count": 1, "ram": 2048, "disk": 55, "monthly_cost": "10.5" }
                    ]
                }),
            );
        }
        ("GET", "/v2/os") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "os": [
                        { "id": 2284, "name": "Ubuntu 24.04 LTS x64", "family": "ubuntu" },
                        { "id": "2136", "name": "Debian 12 x64", "family": "debian" },
                        { "id": 9999, "name": "Windows Core 2022", "family": "windows" }
                    ]
                }),
            );
        }
        ("POST", "/v2/instances") => {
            let b64 = parsed_body
                .get("user_data")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let hostname = parsed_body
                .get("hostname")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let Ok(decoded_bytes) = BASE64_STANDARD.decode(b64) else {
                send_json(&mut stream, 400, "Bad Request", &json!({"error": "invalid base64"}));
                return;
            };
            let decoded = String::from_utf8_lossy(&decoded_bytes);
            let is_valid_cloud_init = decoded.contains("tailscale up --authkey=")
                || decoded.contains("authorized_keys");
            if !is_valid_cloud_init || hostname.is_empty() {
                send_json(&mut stream, 400, "Bad Request", &json!({"error": "missing cloud-init bootstrap or hostname"}));
                return;
            }
            let inst_id = "vultr-inst-1".to_string();
            let mut st = state.lock().unwrap();
            st.vultr_instances.insert(inst_id.clone(), hostname.to_string());
            st.vultr_polls.insert(inst_id.clone(), 0);
            send_json(&mut stream, 202, "Accepted", &json!({ "instance": { "id": inst_id } }));
        }
        ("GET", "/v2/instances") => {
            let st = state.lock().unwrap();
            let mut entries: Vec<(&String, &String)> = st.vultr_instances.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let instances: Vec<Value> = entries
                .into_iter()
                .map(|(id, hostname)| {
                    json!({
                        "id": id,
                        "label": hostname,
                        "hostname": hostname,
                        "status": "active",
                        "power_status": "running",
                        "main_ip": "203.0.113.10",
                        "region": "ewr",
                        "plan": "vc2-1c-1gb",
                        "date_created": "2026-01-01T00:00:00Z"
                    })
                })
                .collect();
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({ "instances": instances, "meta": { "links": { "next": "" } } }),
            );
        }
        ("GET", p) if p.starts_with("/v2/instances/") => {
            let inst_id = &p["/v2/instances/".len()..];
            let mut st = state.lock().unwrap();
            let Some(hostname) = st.vultr_instances.get(inst_id).cloned() else {
                send_json(&mut stream, 404, "Not Found", &json!({"error": "not found"}));
                return;
            };
            let count = st.vultr_polls.entry(inst_id.to_string()).or_insert(0);
            *count += 1;
            if *count == 1 {
                send_json(
                    &mut stream,
                    200,
                    "OK",
                    &json!({
                        "instance": {
                            "id": inst_id,
                            "status": "pending",
                            "power_status": "stopped",
                            "main_ip": "0.0.0.0"
                        }
                    }),
                );
            } else {
                st.register_tailscale_device(&hostname, "100.64.0.50");
                send_json(
                    &mut stream,
                    200,
                    "OK",
                    &json!({
                        "instance": {
                            "id": inst_id,
                            "status": "active",
                            "power_status": "running",
                            "main_ip": "203.0.113.10"
                        }
                    }),
                );
            }
        }
        ("DELETE", p) if p.starts_with("/v2/instances/") => {
            let inst_id = &p["/v2/instances/".len()..];
            let mut st = state.lock().unwrap();
            if st.vultr_instances.remove(inst_id).is_some() {
                st.vultr_polls.remove(inst_id);
                send_no_content(&mut stream);
            } else {
                send_json(&mut stream, 404, "Not Found", &json!({"error": "not found"}));
            }
        }

        // --- UpCloud API v1.3 ---
        ("GET", "/1.3/account") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({ "account": { "username": "upcloud-mock" } }),
            );
        }
        ("GET", "/1.3/zone") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "zones": {
                        "zone": [
                            { "id": "de-fra1", "description": "Frankfurt #1" },
                            { "id": "us-nyc1", "description": "New York #1" }
                        ]
                    }
                }),
            );
        }
        ("GET", "/1.3/plan") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "plans": {
                        "plan": [
                            { "name": "1xCPU-1GB", "core_number": 1, "memory_amount": 1024, "storage_size": 25 }
                        ]
                    }
                }),
            );
        }
        ("GET", "/1.3/storage/template") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "storages": {
                        "storage": [
                            { "uuid": "01000000-0000-4000-8000-000030240200", "title": "Ubuntu Server 24.04 LTS" },
                            { "uuid": "01000000-0000-4000-8000-000099999999", "title": "Custom Snapshot" }
                        ]
                    }
                }),
            );
        }
        ("POST", "/1.3/server") => {
            let srv = parsed_body.get("server").cloned().unwrap_or(json!({}));
            let user_data = srv.get("user_data").and_then(|v| v.as_str()).unwrap_or("");
            let hostname = srv.get("hostname").and_then(|v| v.as_str()).unwrap_or("");
            let storage_devices = srv
                .get("storage_devices")
                .and_then(|v| v.get("storage_device"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let has_clone = storage_devices.iter().any(|d| {
                d.get("action").and_then(|v| v.as_str()) == Some("clone")
                    && d.get("storage").and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty())
            });

            let is_valid_cloud_init = user_data.contains("tailscale up --authkey=")
                || user_data.contains("authorized_keys");
            if (!user_data.starts_with("#!/bin/bash") && !user_data.starts_with("#!/usr/bin/env bash"))
                || !is_valid_cloud_init
                || !has_clone
                || hostname.is_empty()
            {
                send_json(&mut stream, 400, "Bad Request", &json!({"error": "invalid upcloud payload"}));
                return;
            }
            let uuid = "upcloud-uuid-1".to_string();
            let mut st = state.lock().unwrap();
            st.upcloud_servers.insert(uuid.clone(), hostname.to_string());
            st.upcloud_polls.insert(uuid.clone(), 0);
            st.upcloud_stopped.remove(&uuid);
            send_json(&mut stream, 201, "Created", &json!({ "server": { "uuid": uuid } }));
        }
        ("GET", "/1.3/server") => {
            let st = state.lock().unwrap();
            let mut entries: Vec<(&String, &String)> = st.upcloud_servers.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let servers: Vec<Value> = entries
                .into_iter()
                .map(|(uuid, hostname)| {
                    let srv_state = if st.upcloud_stopped.contains(uuid) {
                        "stopped"
                    } else {
                        "started"
                    };
                    json!({
                        "uuid": uuid,
                        "title": hostname,
                        "hostname": hostname,
                        "state": srv_state,
                        "zone": "de-fra1",
                        "plan": "1xCPU-1GB",
                        "created": "2026-01-01T00:00:00Z",
                        "ip_addresses": {
                            "ip_address": [
                                { "access": "public", "address": "203.0.113.11", "family": "IPv4" }
                            ]
                        }
                    })
                })
                .collect();
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({ "servers": { "server": servers } }),
            );
        }
        ("GET", p) if p.starts_with("/1.3/server/") => {
            let uuid = &p["/1.3/server/".len()..];
            let mut st = state.lock().unwrap();
            let Some(hostname) = st.upcloud_servers.get(uuid).cloned() else {
                send_json(&mut stream, 404, "Not Found", &json!({"error": "not found"}));
                return;
            };
            if st.upcloud_stopped.contains(uuid) {
                send_json(
                    &mut stream,
                    200,
                    "OK",
                    &json!({
                        "server": {
                            "uuid": uuid,
                            "state": "stopped",
                            "ip_addresses": {
                                "ip_address": [
                                    { "access": "public", "address": "203.0.113.11", "family": "IPv4" }
                                ]
                            }
                        }
                    }),
                );
                return;
            }
            let count = st.upcloud_polls.entry(uuid.to_string()).or_insert(0);
            *count += 1;
            if *count == 1 {
                // Deliberately omit ip_addresses during initial maintenance poll
                send_json(
                    &mut stream,
                    200,
                    "OK",
                    &json!({
                        "server": {
                            "uuid": uuid,
                            "state": "maintenance"
                        }
                    }),
                );
            } else {
                st.register_tailscale_device(&hostname, "100.64.0.51");
                send_json(
                    &mut stream,
                    200,
                    "OK",
                    &json!({
                        "server": {
                            "uuid": uuid,
                            "state": "started",
                            "ip_addresses": {
                                "ip_address": [
                                    { "access": "private", "address": "10.0.0.11", "family": "IPv4" },
                                    { "access": "public", "address": "203.0.113.11", "family": "IPv4" }
                                ]
                            }
                        }
                    }),
                );
            }
        }
        ("POST", p) if p.starts_with("/1.3/server/") && p.ends_with("/stop") => {
            let uuid = &p["/1.3/server/".len()..p.len() - "/stop".len()];
            let mut st = state.lock().unwrap();
            if st.upcloud_servers.contains_key(uuid) {
                st.upcloud_stopped.insert(uuid.to_string());
                send_json(
                    &mut stream,
                    200,
                    "OK",
                    &json!({ "server": { "uuid": uuid, "state": "stopped" } }),
                );
            } else {
                send_json(&mut stream, 404, "Not Found", &json!({"error": "not found"}));
            }
        }
        ("DELETE", p) if p.starts_with("/1.3/server/") => {
            let uuid = &p["/1.3/server/".len()..];
            let mut st = state.lock().unwrap();
            if !st.upcloud_servers.contains_key(uuid) {
                send_json(&mut stream, 404, "Not Found", &json!({"error": "not found"}));
            } else if !st.upcloud_stopped.contains(uuid) {
                send_json(
                    &mut stream,
                    409,
                    "Conflict",
                    &json!({
                        "error": {
                            "error_code": "SERVER_STATE_ILLEGAL",
                            "error_message": "Server must be stopped before deletion"
                        }
                    }),
                );
            } else {
                st.upcloud_servers.remove(uuid);
                st.upcloud_polls.remove(uuid);
                st.upcloud_stopped.remove(uuid);
                send_no_content(&mut stream);
            }
        }

        // --- Linode API v4 ---
        ("GET", "/v4/profile") => {
            send_json(&mut stream, 200, "OK", &json!({ "username": "linode-mock" }));
        }
        ("GET", "/v4/regions") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "data": [
                        { "id": "us-east", "label": "Newark, NJ", "country": "us" },
                        { "id": "eu-central", "label": "Frankfurt, DE", "country": "de" }
                    ]
                }),
            );
        }
        ("GET", "/v4/linode/types") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "data": [
                        {
                            "id": "g6-nanode-1",
                            "label": "Nanode 1GB",
                            "vcpus": 1,
                            "memory": 1024,
                            "disk": 25600,
                            "price": { "monthly": 5 }
                        },
                        {
                            "id": "g6-custom",
                            "label": "Custom Plan",
                            "vcpus": 2,
                            "memory": 4096,
                            "disk": 81920,
                            "price": { "monthly": null }
                        }
                    ]
                }),
            );
        }
        ("GET", "/v4/images") => {
            send_json(
                &mut stream,
                200,
                "OK",
                &json!({
                    "data": [
                        { "id": "linode/ubuntu24.04", "label": "Ubuntu 24.04 LTS", "vendor": null, "is_public": true },
                        { "id": "linode/debian12", "label": "Debian 12", "is_public": true },
                        { "id": "private/ubuntu-custom", "label": "Ubuntu Private", "vendor": "Ubuntu", "is_public": false }
                    ]
                }),
            );
        }
        ("POST", "/v4/linode/instances") => {
            let root_pass = parsed_body
                .get("root_pass")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let b64 = parsed_body
                .get("metadata")
                .and_then(|v| v.get("user_data"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let hostname = parsed_body
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let Ok(decoded_bytes) = BASE64_STANDARD.decode(b64) else {
                send_json(&mut stream, 400, "Bad Request", &json!({"errors": [{"reason": "invalid base64"}]}));
                return;
            };
            let decoded = String::from_utf8_lossy(&decoded_bytes);
            let is_valid_cloud_init = decoded.contains("tailscale up --authkey=")
                || decoded.contains("authorized_keys");
            if root_pass.is_empty() || !is_valid_cloud_init || hostname.is_empty() {
                send_json(&mut stream, 400, "Bad Request", &json!({"error": "invalid linode payload"}));
                return;
            }
            let inst_id = 12345u64;
            let mut st = state.lock().unwrap();
            st.linode_instances
                .insert(inst_id.to_string(), hostname.to_string());
            st.linode_polls.insert(inst_id.to_string(), 0);
            send_json(&mut stream, 200, "OK", &json!({ "id": inst_id, "label": hostname }));
        }
        ("GET", "/v4/linode/instances") => {
            let st = state.lock().unwrap();
            let mut entries: Vec<(&String, &String)> = st.linode_instances.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let data: Vec<Value> = entries
                .into_iter()
                .map(|(id, hostname)| {
                    let id_json = id
                        .parse::<u64>()
                        .map(|n| json!(n))
                        .unwrap_or_else(|_| json!(id));
                    json!({
                        "id": id_json,
                        "label": hostname,
                        "status": "running",
                        "ipv4": ["203.0.113.12"],
                        "region": "us-east",
                        "type": "g6-nanode-1",
                        "created": "2026-01-01T00:00:00Z"
                    })
                })
                .collect();
            send_json(&mut stream, 200, "OK", &json!({ "data": data, "pages": 1 }));
        }
        ("GET", p) if p.starts_with("/v4/linode/instances/") => {
            let inst_id = &p["/v4/linode/instances/".len()..];
            let mut st = state.lock().unwrap();
            let Some(hostname) = st.linode_instances.get(inst_id).cloned() else {
                send_json(&mut stream, 404, "Not Found", &json!({"errors": [{"reason": "not found"}]}));
                return;
            };
            let count = st.linode_polls.entry(inst_id.to_string()).or_insert(0);
            *count += 1;
            if *count == 1 {
                send_json(
                    &mut stream,
                    200,
                    "OK",
                    &json!({ "id": 12345, "status": "provisioning", "ipv4": [] }),
                );
            } else {
                st.register_tailscale_device(&hostname, "100.64.0.52");
                send_json(
                    &mut stream,
                    200,
                    "OK",
                    &json!({ "id": 12345, "status": "running", "ipv4": ["203.0.113.12"] }),
                );
            }
        }
        ("DELETE", p) if p.starts_with("/v4/linode/instances/") => {
            let inst_id = &p["/v4/linode/instances/".len()..];
            let mut st = state.lock().unwrap();
            if st.linode_instances.remove(inst_id).is_some() {
                st.linode_polls.remove(inst_id);
                send_json(&mut stream, 200, "OK", &json!({}));
            } else {
                send_json(&mut stream, 404, "Not Found", &json!({"errors": [{"reason": "not found"}]}));
            }
        }

        _ => {
            send_json(
                &mut stream,
                404,
                "Not Found",
                &json!({ "error": format!("Unknown route {} {}", method, path) }),
            );
        }
    }
}

fn write_mock_ssh_script(dir: &Path, args_log: &Path, scripts_dir: &Path) -> Result<PathBuf> {
    fs::create_dir_all(scripts_dir)?;
    let mock_ssh = dir.join("mock_ssh");
    let counter_file = dir.join("call_count");
    let mut f = File::create(&mock_ssh)?;
    writeln!(f, "#!/usr/bin/env bash")?;
    writeln!(f, "set -euo pipefail")?;
    writeln!(f, "c=0")?;
    writeln!(f, "[ -f \"{0}\" ] && c=$(cat \"{0}\")", counter_file.display())?;
    writeln!(f, "c=$((c + 1))")?;
    writeln!(f, "echo \"$c\" > \"{}\"", counter_file.display())?;
    writeln!(f, "printf 'CALL:%s\\n' \"$*\" >> \"{}\"", args_log.display())?;
    writeln!(f, "last_arg=\"${{@: -1}}\"")?;
    writeln!(
        f,
        "printf '%s' \"$last_arg\" > \"{}/step_${{c}}.sh\"",
        scripts_dir.display()
    )?;
    writeln!(f, "echo \"MOCK_STEP_${{c}}_OK\"")?;
    fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755))?;
    Ok(mock_ssh)
}

#[test]
fn vultr_provider_lifecycle_and_full_provision_flow() -> Result<()> {
    let server = MockApiServer::start();
    let ts = TailscaleClient::with_config("ts-valid-key", server.base_url("api/v2"), "-")?;
    assert!(ts.validate_api_key()?);

    let invalid_vultr = VultrProvider::with_base_url("invalid-vultr", server.base_url("v2"))?;
    assert!(!invalid_vultr.validate_key()?);

    let vultr = VultrProvider::with_base_url("vultr-valid-key", server.base_url("v2"))?;
    assert!(vultr.validate_key()?);

    let regions = vultr.list_regions()?;
    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0].id, "ewr");

    let plans = vultr.list_plans()?;
    assert_eq!(plans.len(), 2);
    assert!(plans[0].summary.contains("$5/mo"));
    assert!(plans[1].summary.contains("$10.5/mo"));

    let images = vultr.list_images()?;
    assert_eq!(images.len(), 2);
    assert_eq!(images[0].id, "2284");
    assert_eq!(images[1].id, "2136");

    assert!(vultr.get_instance_status("nonexistent").is_err());

    {
        server.state.lock().unwrap().force_error_path = Some("/v2/regions".to_string());
    }
    assert!(vultr.list_regions().is_err());
    {
        server.state.lock().unwrap().force_error_path = None;
    }

    let dir = tempdir()?;
    let session = SessionState::new(dir.path().join(".bab-local"));
    let cfg = ProvisionConfig {
        provider: ProviderKind::Vultr,
        region: "ewr".to_string(),
        plan: "vc2-1c-1gb".to_string(),
        image_id: "2284".to_string(),
        hostname: "vultr-edge-01".to_string(),
        username: "deploy".to_string(),
        role: "caddy".to_string(),
        tags: vec!["tag:vps".to_string()],
        provider_timeout: Duration::from_secs(5),
        tailscale_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(10),
        tailscale_mode: true,
        ssh_pubkey: None,
        ssh_key_path: None,
        sudo_password: None,
    };

    let res = provision_full_flow(&vultr, Some(&ts), &cfg, Some(&session))?;
    assert_eq!(res.instance_id, "vultr-inst-1");
    assert_eq!(res.ip, "100.64.0.50");
    assert_eq!(res.tailscale_ip, "100.64.0.50");
    assert_eq!(res.public_ip, "203.0.113.10");
    assert_eq!(res.provider, "vultr");
    assert!(res.tailscale_mode);

    let loaded = session.load_session()?;
    assert_eq!(
        loaded,
        SessionData {
            vps_ip: Some("100.64.0.50".to_string()),
            ssh_key: Some("tailscale".to_string()),
            username: Some("deploy".to_string()),
            transport_mode: Some("tailscale".to_string()),
            vps_provider: Some("vultr".to_string()),
            vps_instance_id: Some("vultr-inst-1".to_string()),
            tailscale_hostname: Some("vultr-edge-01".to_string()),
            server_role: Some("caddy".to_string()),
            vps_region: Some("ewr".to_string()),
            vps_plan: Some("vc2-1c-1gb".to_string()),
            vps_image: Some("2284".to_string()),
            public_ip: Some("203.0.113.10".to_string()),
            tailscale_ip: Some("100.64.0.50".to_string()),
            ..Default::default()
        }
    );

    let reqs = server.requests();
    let create_req = reqs
        .iter()
        .find(|r| r.method == "POST" && r.path == "/v2/instances")
        .expect("POST /v2/instances recorded");
    let create_json: Value = serde_json::from_str(&create_req.body)?;
    assert_eq!(create_json["os_id"], json!(2284));
    let b64_ud = create_json["user_data"].as_str().unwrap();
    let decoded_ud = String::from_utf8(BASE64_STANDARD.decode(b64_ud)?)?;
    assert!(decoded_ud.contains("tailscale up --authkey='tskey-auth-int-123'"));

    let poll_count = reqs
        .iter()
        .filter(|r| r.method == "GET" && r.path == "/v2/instances/vultr-inst-1")
        .count();
    assert!(poll_count >= 2, "expected polling until ready, got {}", poll_count);

    Ok(())
}

#[test]
fn upcloud_bearer_and_basic_auth_and_full_provision_flow() -> Result<()> {
    let server = MockApiServer::start();
    let ts = TailscaleClient::with_config("ts-valid-key", server.base_url("api/v2"), "-")?;

    // Invalid credentials -> Ok(false)
    let bad_upcloud = UpCloudProvider::with_base_url("baduser:badpass", server.base_url("1.3"))?;
    assert!(!bad_upcloud.validate_key()?);

    // Bearer token auth
    let bearer_upcloud = UpCloudProvider::with_base_url("upcloud-bearer-tok", server.base_url("1.3"))?;
    assert!(bearer_upcloud.validate_key()?);

    // Basic user:pass auth
    let basic_upcloud = UpCloudProvider::with_base_url("myuser:mypass", server.base_url("1.3"))?;
    assert!(basic_upcloud.validate_key()?);
    assert_eq!(basic_upcloud.list_regions()?.len(), 2);
    assert_eq!(basic_upcloud.list_plans()?.len(), 1);
    let images = basic_upcloud.list_images()?;
    assert_eq!(images.len(), 1);
    assert_eq!(images[0].id, "01000000-0000-4000-8000-000030240200");
    assert!(basic_upcloud.get_instance_status("missing-uuid").is_err());

    let dir = tempdir()?;
    let session = SessionState::new(dir.path().join(".bab-local"));
    let cfg = ProvisionConfig {
        provider: ProviderKind::UpCloud,
        region: "de-fra1".to_string(),
        plan: "1xCPU-1GB".to_string(),
        image_id: images[0].id.clone(),
        hostname: "upcloud-vpn-01".to_string(),
        username: "ops".to_string(),
        role: "wireguard".to_string(),
        tags: vec![],
        provider_timeout: Duration::from_secs(5),
        tailscale_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(10),
        tailscale_mode: true,
        ssh_pubkey: None,
        ssh_key_path: None,
        sudo_password: None,
    };

    let res = provision_full_flow(&basic_upcloud, Some(&ts), &cfg, Some(&session))?;
    assert_eq!(res.instance_id, "upcloud-uuid-1");
    assert_eq!(res.ip, "100.64.0.51");
    assert_eq!(res.tailscale_ip, "100.64.0.51");
    assert_eq!(res.public_ip, "203.0.113.11");
    assert_eq!(res.provider, "upcloud");

    let loaded = session.load_session()?;
    assert_eq!(loaded.vps_ip.as_deref(), Some("100.64.0.51"));
    assert_eq!(loaded.public_ip.as_deref(), Some("203.0.113.11"));
    assert_eq!(loaded.tailscale_ip.as_deref(), Some("100.64.0.51"));
    assert_eq!(loaded.ssh_key.as_deref(), Some("tailscale"));
    assert_eq!(loaded.transport_mode.as_deref(), Some("tailscale"));
    assert_eq!(loaded.vps_provider.as_deref(), Some("upcloud"));
    assert_eq!(loaded.vps_instance_id.as_deref(), Some("upcloud-uuid-1"));
    assert_eq!(loaded.vps_region.as_deref(), Some("de-fra1"));
    assert_eq!(loaded.vps_plan.as_deref(), Some("1xCPU-1GB"));
    assert_eq!(loaded.vps_image.as_deref(), Some(images[0].id.as_str()));
    assert_eq!(loaded.tailscale_hostname.as_deref(), Some("upcloud-vpn-01"));
    assert_eq!(loaded.server_role.as_deref(), Some("wireguard"));

    let reqs = server.requests();
    assert!(reqs.iter().any(|r| {
        r.path == "/1.3/account"
            && r.authorization.as_deref() == Some("Bearer upcloud-bearer-tok")
    }));
    let expected_basic = format!("Basic {}", BASE64_STANDARD.encode("myuser:mypass"));
    let create_req = reqs
        .iter()
        .find(|r| r.method == "POST" && r.path == "/1.3/server")
        .expect("POST /1.3/server recorded");
    assert_eq!(
        create_req.authorization.as_deref(),
        Some(expected_basic.as_str())
    );
    let create_json: Value = serde_json::from_str(&create_req.body)?;
    let raw_ud = create_json["server"]["user_data"].as_str().unwrap();
    assert!(raw_ud.starts_with("#!/bin/bash"));
    assert!(raw_ud.contains("tailscale up --authkey='tskey-auth-int-123'"));
    assert_eq!(
        create_json["server"]["storage_devices"]["storage_device"][0]["action"],
        json!("clone")
    );
    assert_eq!(
        create_json["server"]["storage_devices"]["storage_device"][0]["storage"],
        json!("01000000-0000-4000-8000-000030240200")
    );

    let poll_count = reqs
        .iter()
        .filter(|r| r.method == "GET" && r.path == "/1.3/server/upcloud-uuid-1")
        .count();
    assert!(poll_count >= 2, "expected UpCloud polling until started");

    Ok(())
}

#[test]
fn linode_provider_lifecycle_and_full_provision_flow() -> Result<()> {
    let server = MockApiServer::start();
    let ts = TailscaleClient::with_config("ts-valid-key", server.base_url("api/v2"), "-")?;

    let bad_linode = LinodeProvider::with_base_url("invalid-linode", server.base_url("v4"))?;
    assert!(!bad_linode.validate_key()?);

    let linode = LinodeProvider::with_base_url("linode-valid-tok", server.base_url("v4"))?;
    assert!(linode.validate_key()?);
    assert_eq!(linode.list_regions()?.len(), 2);

    let plans = linode.list_plans()?;
    assert_eq!(plans.len(), 2);
    assert!(plans[0].summary.contains("$5/mo"));
    assert!(plans[1].summary.contains("N/A"));

    let images = linode.list_images()?;
    assert_eq!(images.len(), 2);
    assert_eq!(images[0].id, "linode/ubuntu24.04");
    assert_eq!(images[0].vendor, "");
    assert_eq!(images[1].id, "linode/debian12");
    assert_eq!(images[1].vendor, "");

    assert!(linode.get_instance_status("999999").is_err());

    let dir = tempdir()?;
    let session = SessionState::new(dir.path().join(".bab-local"));
    let cfg = ProvisionConfig {
        provider: ProviderKind::Linode,
        region: "us-east".to_string(),
        plan: "g6-nanode-1".to_string(),
        image_id: "linode/ubuntu24.04".to_string(),
        hostname: "linode-rbi-01".to_string(),
        username: "admin".to_string(),
        role: "rbi".to_string(),
        tags: vec!["tag:prod".to_string()],
        provider_timeout: Duration::from_secs(5),
        tailscale_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(10),
        tailscale_mode: true,
        ssh_pubkey: None,
        ssh_key_path: None,
        sudo_password: None,
    };

    let res = provision_full_flow(&linode, Some(&ts), &cfg, Some(&session))?;
    assert_eq!(res.instance_id, "12345");
    assert_eq!(res.ip, "100.64.0.52");
    assert_eq!(res.tailscale_ip, "100.64.0.52");
    assert_eq!(res.public_ip, "203.0.113.12");
    assert_eq!(res.provider, "linode");

    let loaded = session.load_session()?;
    assert_eq!(loaded.vps_ip.as_deref(), Some("100.64.0.52"));
    assert_eq!(loaded.public_ip.as_deref(), Some("203.0.113.12"));
    assert_eq!(loaded.tailscale_ip.as_deref(), Some("100.64.0.52"));
    assert_eq!(loaded.ssh_key.as_deref(), Some("tailscale"));
    assert_eq!(loaded.transport_mode.as_deref(), Some("tailscale"));
    assert_eq!(loaded.vps_provider.as_deref(), Some("linode"));
    assert_eq!(loaded.vps_instance_id.as_deref(), Some("12345"));
    assert_eq!(loaded.vps_region.as_deref(), Some("us-east"));
    assert_eq!(loaded.vps_plan.as_deref(), Some("g6-nanode-1"));
    assert_eq!(loaded.vps_image.as_deref(), Some("linode/ubuntu24.04"));
    assert_eq!(loaded.tailscale_hostname.as_deref(), Some("linode-rbi-01"));
    assert_eq!(loaded.server_role.as_deref(), Some("rbi"));

    let reqs = server.requests();
    let create_req = reqs
        .iter()
        .find(|r| r.method == "POST" && r.path == "/v4/linode/instances")
        .expect("POST /v4/linode/instances recorded");
    let create_json: Value = serde_json::from_str(&create_req.body)?;
    let b64_ud = create_json["metadata"]["user_data"].as_str().unwrap();
    let decoded_ud = String::from_utf8(BASE64_STANDARD.decode(b64_ud)?)?;
    assert!(decoded_ud.contains("tailscale up --authkey='tskey-auth-int-123'"));

    let _ = CreateInstanceRequest {
        region: "us-east".to_string(),
        plan: "g6-nanode-1".to_string(),
        image_id: "linode/ubuntu24.04".to_string(),
        hostname: "unused".to_string(),
        user_data_raw: String::new(),
    };

    Ok(())
}

#[test]
fn setup_runner_all_roles_over_tailscale_transport_via_with_bins() -> Result<()> {
    let server = MockApiServer::start();
    let ts = TailscaleClient::with_config("ts-valid-key", server.base_url("api/v2"), "-")?;
    let vultr = VultrProvider::with_base_url("vultr-valid-key", server.base_url("v2"))?;

    for &role in ServerRole::all() {
        let dir = tempdir()?;
        let session = SessionState::new(dir.path().join(".bab-local"));
        let hostname = format!("node-{}", role);
        let prov_cfg = ProvisionConfig {
            provider: ProviderKind::Vultr,
            region: "ewr".to_string(),
            plan: "vc2-1c-1gb".to_string(),
            image_id: "2284".to_string(),
            hostname: hostname.clone(),
            username: "deploy".to_string(),
            role: "pending".to_string(),
            tags: vec![],
            provider_timeout: Duration::from_secs(5),
            tailscale_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(10),
            tailscale_mode: true,
            ssh_pubkey: None,
            ssh_key_path: None,
            sudo_password: None,
        };
        let prov_res = provision_full_flow(&vultr, Some(&ts), &prov_cfg, Some(&session))?;

        let args_log = dir.path().join("ssh_args.log");
        let scripts_dir = dir.path().join("scripts");
        let mock_ssh = write_mock_ssh_script(dir.path(), &args_log, &scripts_dir)?;

        let transport = SshTransport::with_bins(TransportMode::Tailscale, &mock_ssh, &mock_ssh);
        // Verify `-i tailscale` stripping and Tailscale StrictHostKeyChecking injection
        let stripped = transport.build_args(&[
            "-i".to_string(),
            "tailscale".to_string(),
            format!("root@{}", prov_res.tailscale_ip),
        ]);
        assert_eq!(
            stripped,
            vec![
                "-o",
                "StrictHostKeyChecking=accept-new",
                &format!("root@{}", prov_res.tailscale_ip),
            ]
        );

        let setup_cfg = SetupConfig {
            host: prov_res.tailscale_ip.clone(),
            ssh_user: "root".to_string(),
            new_username: "deploy".to_string(),
            hostname: hostname.clone(),
            role,
            provider_name: "vultr".to_string(),
            tailscale_mode: true,
            ssh_pubkey: None,
            dry_run: false,
            github_deploy: None,
            sudo_nopasswd: true,
            sudo_password: None,
        };
        let runner = SetupRunner::new(&transport, Some(&session));
        let mut steps_seen = Vec::new();
        let reports = runner.run_all(&setup_cfg, |r| steps_seen.push(r.step))?;

        assert_eq!(reports.len(), 6);
        assert_eq!(steps_seen, SetupStepKind::all());
        for r in &reports {
            assert!(r.success);
            assert!(!r.dry_run);
        }

        let log_text = fs::read_to_string(&args_log)?;
        let call_lines: Vec<&str> = log_text.lines().filter(|l| l.starts_with("CALL:")).collect();
        assert_eq!(call_lines.len(), 6);
        for line in &call_lines {
            assert!(line.contains("-o StrictHostKeyChecking=accept-new"));
            assert!(line.contains("-o BatchMode=yes"));
            assert!(line.contains(&format!("root@{}", prov_res.tailscale_ip)));
            assert!(!line.contains("-i tailscale"));
        }

        let role_script = fs::read_to_string(scripts_dir.join("step_4.sh"))?;
        match role {
            ServerRole::Vanilla => {
                assert!(role_script.contains("ufw default deny incoming"));
                assert!(role_script.contains("ufw allow in on tailscale0"));
                assert!(role_script.contains("41641/udp"));
                assert!(role_script.contains("ufw delete allow 22/tcp"));
            }
            ServerRole::ReverseProxyCaddy => {
                assert!(role_script.contains("get.docker.com"));
                assert!(role_script.contains("/etc/docker/daemon.json"));
                assert!(role_script.contains("systemctl enable --now caddy"));
                assert!(role_script.contains("BEGIN UFW AND DOCKER"));
                assert!(role_script.contains("80/tcp"));
                assert!(role_script.contains("443/tcp"));
                assert!(role_script.contains("ufw delete allow 22/tcp"));
            }
            ServerRole::VpnWireguard => {
                assert!(role_script.contains("wireguard-tools"));
                assert!(role_script.contains("/etc/sysctl.d/99-bab-wireguard.conf"));
                assert!(role_script.contains("/etc/wireguard/wg0.conf"));
                assert!(role_script.contains("10.66.66.1/24"));
                assert!(role_script.contains("ListenPort = 51820"));
                assert!(role_script.contains("/etc/wireguard/client1.conf"));
                assert!(role_script.contains("systemctl enable --now wg-quick@wg0"));
                assert!(role_script.contains("ufw delete allow 22/tcp"));
            }
            ServerRole::RemoteBrowserIsolation => {
                assert!(role_script.contains("/etc/bab-role-rbi.stub"));
                assert!(role_script.contains("RBI_STUB_READY"));
                assert!(role_script.contains("ufw allow in on tailscale0"));
                assert!(role_script.contains("41641/udp"));
                assert!(role_script.contains("ufw delete allow 22/tcp"));
            }
        }

        let loaded = session.load_session()?;
        assert_eq!(loaded.server_role.as_deref(), Some(role.to_string().as_str()));
        assert_eq!(loaded.vps_ip.as_deref(), Some("100.64.0.50"));
        assert_eq!(loaded.ssh_key.as_deref(), Some("tailscale"));
        assert_eq!(loaded.transport_mode.as_deref(), Some("tailscale"));
        assert_eq!(loaded.vps_provider.as_deref(), Some("vultr"));
        assert_eq!(loaded.vps_instance_id.as_deref(), Some("vultr-inst-1"));
        assert_eq!(loaded.tailscale_hostname.as_deref(), Some(hostname.as_str()));
    }

    Ok(())
}

#[test]
fn setup_runner_respects_bab_ssh_bin_env_var_serialized() -> Result<()> {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let _guard = EnvGuard::new(&["BAB_SSH_BIN", "VPSKIT_SSH_BIN"]);
    env::remove_var("VPSKIT_SSH_BIN");

    let dir = tempdir()?;
    let args_log = dir.path().join("ssh_env_args.log");
    let scripts_dir = dir.path().join("env_scripts");
    let mock_ssh = write_mock_ssh_script(dir.path(), &args_log, &scripts_dir)?;

    env::set_var("BAB_SSH_BIN", &mock_ssh);

    let session = SessionState::new(dir.path().join(".bab-local"));
    let transport = SshTransport::from_env(TransportMode::Tailscale);
    let runner = SetupRunner::new(&transport, Some(&session));

    let cfg = SetupConfig {
        host: "100.64.0.88".to_string(),
        ssh_user: "ubuntu".to_string(),
        new_username: "deploy".to_string(),
        hostname: "env-box".to_string(),
        role: ServerRole::ReverseProxyCaddy,
        provider_name: "linode".to_string(),
        tailscale_mode: true,
        ssh_pubkey: None,
        dry_run: false,
        github_deploy: None,
        sudo_nopasswd: true,
        sudo_password: None,
    };

    let reports = runner.run_all(&cfg, |_| {})?;
    assert_eq!(reports.len(), 6);
    assert_eq!(session.server_role()?.as_deref(), Some("caddy"));

    let log_text = fs::read_to_string(&args_log)?;
    assert_eq!(log_text.lines().filter(|l| l.starts_with("CALL:")).count(), 6);
    assert!(log_text.contains("-o StrictHostKeyChecking=accept-new"));
    assert!(log_text.contains("ubuntu@100.64.0.88"));
    let motd_script = fs::read_to_string(scripts_dir.join("step_6.sh"))?;
    assert!(motd_script.contains("sudo bash -s"));
    assert!(motd_script.contains("ReverseProxy (Caddy)"));

    Ok(())
}

#[test]
fn standard_ssh_provisioning_flow_generates_key_and_skips_tailscale() -> Result<()> {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let _guard = EnvGuard::new(&["BAB_SSH_KEYGEN_BIN"]);
    env::remove_var("BAB_SSH_KEYGEN_BIN");

    let server = MockApiServer::start();
    let vultr = VultrProvider::with_base_url("vultr-valid-key", server.base_url("v2"))?;

    let dir = tempdir()?;
    let key_path = dir.path().join("ssh").join("bab_ed25519");
    let pubkey = ensure_ssh_keypair(&key_path, "bab@ssh-box-01")?;
    assert!(pubkey.starts_with("ssh-ed25519 "));
    assert_eq!(read_public_key(&key_path)?, pubkey);

    let session = SessionState::new(dir.path().join(".bab-local"));
    let cfg = ProvisionConfig {
        provider: ProviderKind::Vultr,
        region: "ewr".to_string(),
        plan: "vc2-1c-1gb".to_string(),
        image_id: "2284".to_string(),
        hostname: "ssh-box-01".to_string(),
        username: "ops".to_string(),
        role: "vanilla".to_string(),
        tags: vec![],
        provider_timeout: Duration::from_secs(5),
        tailscale_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(10),
        tailscale_mode: false,
        ssh_pubkey: Some(pubkey.clone()),
        ssh_key_path: Some(key_path.to_string_lossy().into_owned()),
        sudo_password: None,
    };

    let res = provision_full_flow(&vultr, None, &cfg, Some(&session))?;
    assert_eq!(res.instance_id, "vultr-inst-1");
    assert_eq!(res.ip, "203.0.113.10");
    assert_eq!(res.public_ip, "203.0.113.10");
    assert_eq!(res.tailscale_ip, "");
    assert!(!res.tailscale_mode);

    let loaded = session.load_session()?;
    assert_eq!(loaded.vps_ip.as_deref(), Some("203.0.113.10"));
    assert_eq!(loaded.public_ip.as_deref(), Some("203.0.113.10"));
    assert_eq!(loaded.tailscale_ip, None);
    assert_eq!(
        loaded.ssh_key.as_deref(),
        Some(key_path.to_string_lossy().as_ref())
    );
    assert_eq!(loaded.username.as_deref(), Some("ops"));
    assert_eq!(loaded.transport_mode.as_deref(), Some("ssh"));
    assert_eq!(loaded.vps_provider.as_deref(), Some("vultr"));
    assert_eq!(loaded.vps_instance_id.as_deref(), Some("vultr-inst-1"));
    assert_eq!(loaded.vps_region.as_deref(), Some("ewr"));
    assert_eq!(loaded.vps_plan.as_deref(), Some("vc2-1c-1gb"));
    assert_eq!(loaded.vps_image.as_deref(), Some("2284"));
    assert_eq!(loaded.tailscale_hostname.as_deref(), Some("ssh-box-01"));
    assert_eq!(loaded.server_role.as_deref(), Some("vanilla"));

    let reqs = server.requests();
    assert!(
        !reqs.iter().any(|r| r.path.starts_with("/api/v2/")),
        "standard SSH provisioning must make zero Tailscale API calls"
    );
    let create_req = reqs
        .iter()
        .find(|r| r.method == "POST" && r.path == "/v2/instances")
        .expect("POST /v2/instances recorded");
    let create_json: Value = serde_json::from_str(&create_req.body)?;
    let b64_ud = create_json["user_data"].as_str().unwrap();
    let decoded_ud = String::from_utf8(BASE64_STANDARD.decode(b64_ud)?)?;
    assert!(decoded_ud.contains("authorized_keys"));
    assert!(decoded_ud.contains(&pubkey));
    assert!(decoded_ud.contains("NEW_USER='ops'"));
    assert!(!decoded_ud.to_ascii_lowercase().contains("tailscale"));

    Ok(())
}

#[test]
fn setup_runner_vanilla_both_transport_modes_end_to_end() -> Result<()> {
    let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestVanillaKey ops@bab";

    for tailscale_mode in [true, false] {
        let dir = tempdir()?;
        let session = SessionState::new(dir.path().join(".bab-local"));
        let args_log = dir.path().join("ssh_args.log");
        let scripts_dir = dir.path().join("scripts");
        let mock_ssh = write_mock_ssh_script(dir.path(), &args_log, &scripts_dir)?;

        let key_path = dir.path().join("bab_ed25519");
        let mode = if tailscale_mode {
            TransportMode::Tailscale
        } else {
            TransportMode::SshKey(key_path.clone())
        };
        let transport = SshTransport::with_bins(mode, &mock_ssh, &mock_ssh);
        let runner = SetupRunner::new(&transport, Some(&session));

        let host = if tailscale_mode {
            "100.64.0.99"
        } else {
            "203.0.113.99"
        };
        let cfg = SetupConfig {
            host: host.to_string(),
            ssh_user: "root".to_string(),
            new_username: "customops".to_string(),
            hostname: "vanilla-box".to_string(),
            role: ServerRole::Vanilla,
            provider_name: "vultr".to_string(),
            tailscale_mode,
            ssh_pubkey: if tailscale_mode {
                None
            } else {
                Some(pubkey.to_string())
            },
            dry_run: false,
            github_deploy: None,
            sudo_nopasswd: true,
            sudo_password: None,
        };

        let reports = runner.run_all(&cfg, |_| {})?;
        assert_eq!(reports.len(), 6);
        assert!(reports.iter().all(|r| r.success && !r.dry_run));
        assert_eq!(session.server_role()?.as_deref(), Some("vanilla"));

        let log_text = fs::read_to_string(&args_log)?;
        let call_lines: Vec<&str> = log_text.lines().filter(|l| l.starts_with("CALL:")).collect();
        assert_eq!(call_lines.len(), 6);
        for line in &call_lines {
            assert!(line.contains("-o StrictHostKeyChecking=accept-new"));
            assert!(line.contains("-o BatchMode=yes"));
            assert!(line.contains(&format!("root@{}", host)));
            if tailscale_mode {
                assert!(!line.contains("-i "));
            } else {
                assert!(line.contains(&format!("-i {}", key_path.display())));
            }
        }

        let step2 = fs::read_to_string(scripts_dir.join("step_2.sh"))?;
        assert!(step2.contains("NEW_USER='customops'"));
        assert!(step2.contains("/etc/sudoers.d/${NEW_USER}"));
        assert!(step2.contains("NOPASSWD:ALL"));
        assert!(step2.contains("SSH_DIR=\"/home/${NEW_USER}/.ssh\""));
        assert!(step2.contains("AUTH_KEYS=\"${SSH_DIR}/authorized_keys\""));

        let step3 = fs::read_to_string(scripts_dir.join("step_3.sh"))?;
        assert!(step3.contains("PermitRootLogin no"));
        assert!(step3.contains("PasswordAuthentication no"));
        assert!(step3.contains("PubkeyAuthentication yes"));
        assert!(step3.contains("/etc/ssh/sshd_config.d/00-bab-hardening.conf"));

        let step4 = fs::read_to_string(scripts_dir.join("step_4.sh"))?;
        let step5 = fs::read_to_string(scripts_dir.join("step_5.sh"))?;
        assert!(step5.contains("[sshd]"));
        assert!(step5.contains("fail2ban"));

        let step6 = fs::read_to_string(scripts_dir.join("step_6.sh"))?;
        assert!(step6.contains("BAB_USER='customops'"));

        if tailscale_mode {
            assert!(step3.contains("TAILSCALE_MODE=true"));
            assert!(step4.contains("ufw allow in on tailscale0"));
            assert!(step4.contains("ufw allow 41641/udp"));
            assert!(step4.contains("ufw delete allow 22/tcp"));
            assert!(step6.contains("BAB_TRANSPORT='Tailscale SSH'"));
        } else {
            assert!(step2.contains(pubkey));
            assert!(step3.contains("TAILSCALE_MODE=false"));
            assert!(step4.lines().any(|l| l.trim() == "ufw limit 22/tcp"));
            assert!(!step4.lines().any(|l| l.trim() == "ufw allow in on tailscale0"));
            assert!(!step4.lines().any(|l| l.trim() == "ufw allow 41641/udp"));
            assert!(step6.contains("BAB_TRANSPORT='Standard SSH'"));
        }
    }

    Ok(())
}

#[test]
fn provision_records_dual_ips_and_setup_runner_deploy_github_executes_via_mock_ssh() -> Result<()> {
    let server = MockApiServer::start();
    let ts = TailscaleClient::with_config("ts-valid-key", server.base_url("api/v2"), "-")?;
    let vultr = VultrProvider::with_base_url("vultr-valid-key", server.base_url("v2"))?;

    let dir = tempdir()?;
    let session = SessionState::new(dir.path().join("state.conf"));
    let prov_cfg = ProvisionConfig {
        provider: ProviderKind::Vultr,
        region: "ewr".to_string(),
        plan: "vc2-1c-2gb".to_string(),
        image_id: "2284".to_string(),
        hostname: "app-node-01".to_string(),
        username: "deploy".to_string(),
        role: "caddy".to_string(),
        tags: vec![],
        provider_timeout: Duration::from_secs(5),
        tailscale_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(10),
        tailscale_mode: true,
        ssh_pubkey: None,
        ssh_key_path: None,
        sudo_password: None,
    };

    let res = provision_full_flow(&vultr, Some(&ts), &prov_cfg, Some(&session))?;
    assert_eq!(res.public_ip, "203.0.113.10");
    assert_eq!(res.tailscale_ip, "100.64.0.50");
    assert_eq!(res.ip, "100.64.0.50");

    let loaded = session.load_session()?;
    assert_eq!(loaded.public_ip.as_deref(), Some("203.0.113.10"));
    assert_eq!(loaded.tailscale_ip.as_deref(), Some("100.64.0.50"));
    assert_eq!(loaded.vps_region.as_deref(), Some("ewr"));
    assert_eq!(loaded.vps_plan.as_deref(), Some("vc2-1c-2gb"));
    assert_eq!(loaded.vps_image.as_deref(), Some("2284"));

    let args_log = dir.path().join("deploy_args.log");
    let scripts_dir = dir.path().join("deploy_scripts");
    let mock_ssh = write_mock_ssh_script(dir.path(), &args_log, &scripts_dir)?;

    let transport = SshTransport::with_bins(TransportMode::Tailscale, &mock_ssh, &mock_ssh);
    let runner = SetupRunner::new(&transport, Some(&session));

    let gh_cfg = GithubDeployConfig {
        repo: "owner/private-app".to_string(),
        branch: "main".to_string(),
        deploy_path: Some("/home/deploy/apps/private-app".to_string()),
        deploy_cmd: Some("docker compose up -d --build".to_string()),
        github_token: Some("ghp_secret_deploy_token".to_string()),
        username: "deploy".to_string(),
    };

    let out = runner.deploy_github("deploy", &res.tailscale_ip, &gh_cfg, false)?;
    assert!(out.contains("MOCK_STEP_1_OK"));

    let log_text = fs::read_to_string(&args_log)?;
    assert!(log_text.contains("deploy@100.64.0.50"));

    let script = fs::read_to_string(scripts_dir.join("step_1.sh"))?;
    assert!(script.contains("sudo bash -s"));
    assert!(script.contains("https://github.com/owner/private-app.git"));
    assert!(script.contains("git clone --branch"));
    assert!(script.contains("git -C \"${DEPLOY_PATH}\" pull --ff-only"));
    assert!(script.contains("GIT_ASKPASS"));
    assert!(script.contains("chmod 0700 \"${GIT_ASKPASS_SCRIPT}\""));
    assert!(script.contains("trap 'rm -f \"${GIT_ASKPASS_SCRIPT}\"' EXIT"));
    assert!(script.contains("docker compose up -d --build"));

    Ok(())
}

#[test]
fn query_all_providers_and_destroy_instances_lifecycle() -> Result<()> {
    let _lock = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    let _guard = EnvGuard::new(&[
        "VULTR_API_BASE_URL",
        "UPCLOUD_API_BASE_URL",
        "LINODE_API_BASE_URL",
        "VULTR_API_BASE",
        "UPCLOUD_API_BASE",
        "LINODE_API_BASE",
    ]);

    let server = MockApiServer::start();
    env::set_var("VULTR_API_BASE_URL", server.base_url("v2"));
    env::set_var("UPCLOUD_API_BASE_URL", server.base_url("1.3"));
    env::set_var("LINODE_API_BASE_URL", server.base_url("v4"));

    let ts = TailscaleClient::with_config("ts-valid-key", server.base_url("api/v2"), "-")?;
    let vultr = VultrProvider::with_base_url("vultr-valid-key", server.base_url("v2"))?;
    let upcloud = UpCloudProvider::with_base_url("upcloud-valid-tok", server.base_url("1.3"))?;
    let linode = LinodeProvider::with_base_url("linode-valid-tok", server.base_url("v4"))?;

    let dir = tempdir()?;
    let session = SessionState::new(dir.path().join("state.conf"));

    // Provision one instance on each provider; Vultr is recorded last as the active session.
    let up_cfg = ProvisionConfig {
        provider: ProviderKind::UpCloud,
        region: "de-fra1".to_string(),
        plan: "1xCPU-1GB".to_string(),
        image_id: "01000000-0000-4000-8000-000030240200".to_string(),
        hostname: "upcloud-box".to_string(),
        username: "deploy".to_string(),
        role: "vanilla".to_string(),
        tags: vec![],
        provider_timeout: Duration::from_secs(5),
        tailscale_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(10),
        tailscale_mode: true,
        ssh_pubkey: None,
        ssh_key_path: None,
        sudo_password: None,
    };
    let up_res = provision_full_flow(&upcloud, Some(&ts), &up_cfg, None)?;
    assert_eq!(up_res.instance_id, "upcloud-uuid-1");

    let lin_cfg = ProvisionConfig {
        provider: ProviderKind::Linode,
        region: "us-east".to_string(),
        plan: "g6-nanode-1".to_string(),
        image_id: "linode/ubuntu24.04".to_string(),
        hostname: "linode-box".to_string(),
        username: "deploy".to_string(),
        role: "vanilla".to_string(),
        tags: vec![],
        provider_timeout: Duration::from_secs(5),
        tailscale_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(10),
        tailscale_mode: true,
        ssh_pubkey: None,
        ssh_key_path: None,
        sudo_password: None,
    };
    let lin_res = provision_full_flow(&linode, Some(&ts), &lin_cfg, None)?;
    assert_eq!(lin_res.instance_id, "12345");

    let vultr_cfg = ProvisionConfig {
        provider: ProviderKind::Vultr,
        region: "ewr".to_string(),
        plan: "vc2-1c-1gb".to_string(),
        image_id: "2284".to_string(),
        hostname: "vultr-box".to_string(),
        username: "deploy".to_string(),
        role: "caddy".to_string(),
        tags: vec![],
        provider_timeout: Duration::from_secs(5),
        tailscale_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(10),
        tailscale_mode: true,
        ssh_pubkey: None,
        ssh_key_path: None,
        sudo_password: None,
    };
    let vultr_res = provision_full_flow(&vultr, Some(&ts), &vultr_cfg, Some(&session))?;
    assert_eq!(vultr_res.instance_id, "vultr-inst-1");

    // Cross-provider query lists all 3 instances and reports per-provider status.
    let all = query_providers_with_keys(
        Some("vultr-valid-key"),
        Some("upcloud-valid-tok"),
        Some("linode-valid-tok"),
        None,
    );
    assert_eq!(all.instances.len(), 3);
    assert_eq!(all.provider_statuses.len(), 3);
    assert!(all
        .provider_statuses
        .iter()
        .all(|s| s.configured && s.instance_count == 1 && s.error.is_none()));
    assert!(all
        .instances
        .iter()
        .any(|i| i.provider == ProviderKind::Vultr && i.id == "vultr-inst-1" && i.name == "vultr-box"));
    assert!(all
        .instances
        .iter()
        .any(|i| i.provider == ProviderKind::UpCloud && i.id == "upcloud-uuid-1" && i.name == "upcloud-box"));
    assert!(all
        .instances
        .iter()
        .any(|i| i.provider == ProviderKind::Linode && i.id == "12345" && i.name == "linode-box"));

    // Provider filter returns only the selected provider.
    let only_linode = query_providers_with_keys(
        Some("vultr-valid-key"),
        Some("upcloud-valid-tok"),
        Some("linode-valid-tok"),
        Some(ProviderKind::Linode),
    );
    assert_eq!(only_linode.provider_statuses.len(), 1);
    assert_eq!(only_linode.instances.len(), 1);
    assert_eq!(only_linode.instances[0].id, "12345");

    // Partial error isolation: failing UpCloud does not block Vultr or Linode results.
    {
        server.state.lock().unwrap().force_error_path = Some("/1.3/server".to_string());
    }
    let partial = query_providers_with_keys(
        Some("vultr-valid-key"),
        Some("upcloud-valid-tok"),
        Some("linode-valid-tok"),
        None,
    );
    {
        server.state.lock().unwrap().force_error_path = None;
    }
    assert_eq!(partial.instances.len(), 2);
    let up_status = partial
        .provider_statuses
        .iter()
        .find(|s| s.provider == ProviderKind::UpCloud)
        .unwrap();
    assert!(up_status.configured);
    assert_eq!(up_status.instance_count, 0);
    assert!(up_status.error.is_some());

    // Destroy Vultr instance and verify matching active session clearing.
    destroy_provider_instance_with_key(
        ProviderKind::Vultr,
        "vultr-valid-key",
        "vultr-inst-1",
        None,
    )?;
    assert!(!clear_destroyed_session_if_matches(&session, "non-matching-id")?);
    assert_eq!(session.vps_instance_id()?.as_deref(), Some("vultr-inst-1"));
    assert!(clear_destroyed_session_if_matches(&session, "vultr-inst-1")?);
    let cleared = session.load_session()?;
    assert_eq!(cleared.vps_instance_id, None);
    assert_eq!(cleared.vps_provider, None);
    assert_eq!(cleared.vps_ip, None);
    assert_eq!(cleared.public_ip, None);
    assert_eq!(cleared.tailscale_ip, None);
    assert_eq!(cleared.username.as_deref(), Some("deploy"));
    assert_eq!(cleared.server_role.as_deref(), Some("caddy"));

    // Destroy UpCloud (running -> 409 -> POST /stop -> 204 DELETE) and Linode instances.
    destroy_provider_instance_with_key(
        ProviderKind::UpCloud,
        "upcloud-valid-tok",
        "upcloud-uuid-1",
        None,
    )?;
    destroy_provider_instance_with_key(ProviderKind::Linode, "linode-valid-tok", "12345", None)?;

    let reqs = server.requests();
    assert!(reqs
        .iter()
        .any(|r| r.method == "DELETE" && r.path == "/v2/instances/vultr-inst-1"));
    assert!(reqs
        .iter()
        .any(|r| r.method == "POST" && r.path == "/1.3/server/upcloud-uuid-1/stop"));
    assert_eq!(
        reqs.iter()
            .filter(|r| r.method == "DELETE" && r.path == "/1.3/server/upcloud-uuid-1")
            .count(),
        2
    );
    assert!(reqs
        .iter()
        .any(|r| r.method == "DELETE" && r.path == "/v4/linode/instances/12345"));

    let after_destroy = query_providers_with_keys(
        Some("vultr-valid-key"),
        Some("upcloud-valid-tok"),
        Some("linode-valid-tok"),
        None,
    );
    assert!(after_destroy.instances.is_empty());
    assert!(after_destroy
        .provider_statuses
        .iter()
        .all(|s| s.instance_count == 0 && s.error.is_none()));

    Ok(())
}
