use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::thread;
use tempfile::tempdir;

fn strip_bab_env(cmd: &mut Command) {
    for key in [
        "TAILSCALE_API_KEY",
        "TAILSCALE_API_BASE",
        "TAILSCALE_TAILNET",
        "VULTR_API_KEY",
        "VULTR_API_BASE",
        "VULTR_API_BASE_URL",
        "UPCLOUD_API_TOKEN",
        "UPCLOUD_API_BASE",
        "UPCLOUD_API_BASE_URL",
        "LINODE_API_TOKEN",
        "LINODE_API_BASE",
        "LINODE_API_BASE_URL",
        "CLOUDFLARE_API_TOKEN",
        "GITHUB_TOKEN",
        "BAB_CONFIG_DIR",
        "BAB_ENCRYPTION_KEY",
        "BAB_MASTER_KEY_FILE",
        "BAB_SETTINGS_FILE",
        "VPSKIT_SETTINGS_FILE",
        "SETTINGS_FILE",
        "BAB_STATE_FILE",
        "BAB_LOCAL_STATE",
        "VPSKIT_STATE_FILE",
        "VPSKIT_LOCAL_STATE",
        "LOCAL_STATE",
        "BAB_SSH_BIN",
        "BAB_SCP_BIN",
        "BAB_SSH_DIR",
        "BAB_SSH_KEYGEN_BIN",
        "VPSKIT_SSH_BIN",
        "VPSKIT_SCP_BIN",
        "VPSKIT_SSH_DIR",
        "SSH_DIR",
    ] {
        cmd.env_remove(key);
    }
}

fn bab_cmd(settings_path: &Path, state_path: &Path, ssh_dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bab"));
    strip_bab_env(&mut cmd);
    cmd.env("BAB_SETTINGS_FILE", settings_path);
    cmd.env("BAB_STATE_FILE", state_path);
    cmd.env("BAB_SSH_DIR", ssh_dir);
    cmd
}

fn bab_cmd_config_dir(config_dir: &Path, ssh_dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bab"));
    strip_bab_env(&mut cmd);
    cmd.env("BAB_CONFIG_DIR", config_dir);
    cmd.env("BAB_SSH_DIR", ssh_dir);
    cmd
}

#[test]
fn cli_roles_lists_all_four_profiles_and_ssh_mode() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join(".bab-settings");
    let state = dir.path().join(".bab-local");
    let ssh_dir = dir.path().join("ssh");

    let out = bab_cmd(&settings, &state, &ssh_dir)
        .arg("roles")
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("vanilla"));
    assert!(stdout.contains("Vanilla (Plain Hardened OS)"));
    assert!(stdout.contains("caddy"));
    assert!(stdout.contains("ReverseProxy (Caddy)"));
    assert!(stdout.contains("wireguard"));
    assert!(stdout.contains("VPN Server (WireGuard)"));
    assert!(stdout.contains("rbi"));
    assert!(stdout.contains("Remote Browser Isolation (Build Later)"));
    assert!(stdout.contains("41641/udp (Tailscale)"));
    assert!(stdout.contains("80/tcp (HTTP)"));
    assert!(stdout.contains("51820/udp (WireGuard)"));
    assert!(stdout.contains("stub=false"));
    assert!(stdout.contains("stub=true"));

    let out_ssh = bab_cmd(&settings, &state, &ssh_dir)
        .args(["roles", "--transport", "ssh"])
        .output()
        .unwrap();
    assert!(
        out_ssh.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_ssh.stderr)
    );
    let stdout_ssh = String::from_utf8_lossy(&out_ssh.stdout);
    assert!(stdout_ssh.contains("22/tcp (SSH rate-limited)"));
    assert!(!stdout_ssh.contains("41641/udp (Tailscale)"));
}

#[test]
fn cli_setup_dry_run_all_roles() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join(".bab-settings");
    let state = dir.path().join(".bab-local");
    let ssh_dir = dir.path().join("ssh");

    for (role, marker) in [
        ("vanilla", "ufw default deny incoming"),
        ("caddy", "systemctl enable --now caddy"),
        ("wireguard", "systemctl enable --now wg-quick@wg0"),
        ("rbi", "RBI_STUB_READY"),
    ] {
        let out = bab_cmd(&settings, &state, &ssh_dir)
            .args(["setup", "--role", role, "--dry-run"])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "role {} failed: {}",
            role,
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("[DRY-RUN] System Update & Base Packages"));
        assert!(stdout.contains("[DRY-RUN] Configure Server Role"));
        assert!(stdout.contains("[DRY-RUN] Configure MOTD Dashboard"));
        assert!(
            stdout.contains(marker),
            "missing marker '{}' in output for {}",
            marker,
            role
        );
    }
}

#[test]
fn cli_setup_vanilla_ssh_dry_run_rules() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join(".bab-settings");
    let state = dir.path().join(".bab-local");
    let ssh_dir = dir.path().join("ssh");

    let out = bab_cmd(&settings, &state, &ssh_dir)
        .args([
            "setup",
            "--role",
            "vanilla",
            "--transport",
            "ssh",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ufw limit 22/tcp"));
    assert!(stdout.contains("PasswordAuthentication no"));
    assert!(!stdout.contains("ufw allow in on tailscale0"));
    assert!(!stdout.contains("ufw allow 41641/udp"));
    assert!(stdout.contains("BAB_TRANSPORT='Standard SSH'"));
}

#[test]
fn cli_setup_manual_dry_run_without_key_uses_placeholder() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join(".bab-settings");
    let state = dir.path().join(".bab-local");
    let ssh_dir = dir.path().join("ssh");

    let out = bab_cmd(&settings, &state, &ssh_dir)
        .args([
            "setup",
            "--provider",
            "manual",
            "--hostname",
            "manual-box",
            "--user",
            "ops",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("TAILSCALE_API_KEY"));
    assert!(stdout.contains("tskey-auth-DRYRUN"));
    assert!(stdout.contains("--hostname='manual-box'"));
    assert!(stdout.contains("'ops'"));
}

#[test]
fn cli_settings_persists_and_masks_keys() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join("credentials.enc");
    let state = dir.path().join("state.conf");
    let ssh_dir = dir.path().join("ssh");

    let secret = "tskey-api-supersecret1234";
    let out = bab_cmd(&settings, &state, &ssh_dir)
        .args(["settings", "--tailscale-key", secret, "--show"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("TAILSCALE_API_KEY: tske****1234"));
    assert!(stdout.contains("CLOUDFLARE_API_TOKEN:"));
    assert!(stdout.contains("GITHUB_TOKEN:"));
    assert!(stdout.contains("ChaCha20-Poly1305"));
    assert!(!stdout.contains(secret), "raw secret must not appear in output");

    let saved = fs::read_to_string(&settings).unwrap();
    assert!(saved.contains("TAILSCALE_API_KEY=\"enc:v1:"));
    assert!(!saved.contains(secret), "raw secret must not appear on disk");

    // Subsequent --show reads persisted encrypted key and keeps it masked
    let show_out = bab_cmd(&settings, &state, &ssh_dir)
        .args(["settings", "--show"])
        .output()
        .unwrap();
    assert!(show_out.status.success());
    let show_stdout = String::from_utf8_lossy(&show_out.stdout);
    assert!(show_stdout.contains("TAILSCALE_API_KEY: tske****1234"));
    assert!(!show_stdout.contains(secret));
}

#[test]
fn cli_cloud_init_with_explicit_authkey() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join(".bab-settings");
    let state = dir.path().join(".bab-local");
    let ssh_dir = dir.path().join("ssh");

    let out = bab_cmd(&settings, &state, &ssh_dir)
        .args([
            "cloud-init",
            "--hostname",
            "edge-node",
            "--user",
            "deploy",
            "--authkey",
            "tskey-test",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("#!/bin/bash"));
    assert!(stdout.contains("tailscale up --authkey='tskey-test' --ssh --hostname='edge-node'"));
}

#[test]
fn cli_cloud_init_ssh_transport_with_explicit_pubkey() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join(".bab-settings");
    let state = dir.path().join(".bab-local");
    let ssh_dir = dir.path().join("ssh");

    let pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestCliPubKey cli@bab";
    let out = bab_cmd(&settings, &state, &ssh_dir)
        .args([
            "cloud-init",
            "--transport",
            "ssh",
            "--hostname",
            "ssh-box",
            "--user",
            "ops",
            "--ssh-pubkey",
            pubkey,
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("#!/usr/bin/env bash"));
    assert!(stdout.contains("NEW_HOST='ssh-box'"));
    assert!(stdout.contains("NEW_USER='ops'"));
    assert!(stdout.contains(pubkey));
    assert!(!stdout.to_ascii_lowercase().contains("tailscale"));
}

#[test]
fn cli_status_runs_remote_check_via_mock_ssh() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join(".bab-settings");
    let state = dir.path().join(".bab-local");
    let ssh_dir = dir.path().join("ssh");

    fs::write(
        &state,
        "VPS_IP=\"100.64.0.77\"\nUSERNAME=\"deploy\"\n",
    )
    .unwrap();

    let args_log = dir.path().join("ssh_args.log");
    let mock_ssh = dir.path().join("mock_ssh");
    {
        let mut f = File::create(&mock_ssh).unwrap();
        writeln!(f, "#!/usr/bin/env bash").unwrap();
        writeln!(f, "printf '%s\\n' \"$@\" > \"{}\"", args_log.display()).unwrap();
        writeln!(f, "echo 'Linux vps-node 6.8.0'").unwrap();
        writeln!(f, "echo 'active'").unwrap();
        writeln!(f, "echo '/dev/sda1 25G 2G 23G 8% /'").unwrap();
        fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let out = bab_cmd(&settings, &state, &ssh_dir)
        .env("BAB_SSH_BIN", &mock_ssh)
        .arg("status")
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Transport: tailscale"));
    assert!(stdout.contains("User: deploy"));
    assert!(stdout.contains("Linux vps-node 6.8.0"));
    assert!(stdout.contains("active"));

    let recorded = fs::read_to_string(&args_log).unwrap();
    assert!(recorded.contains("deploy@100.64.0.77"));
    assert!(recorded.contains("uname -a && systemctl is-active tailscaled || true && df -h /"));
}

#[test]
fn cli_status_ssh_transport_uses_ssh_key_and_reports_header() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join(".bab-settings");
    let state = dir.path().join(".bab-local");
    let ssh_dir = dir.path().join("ssh");
    let key_path = dir.path().join("bab_ed25519");

    fs::write(
        &state,
        format!(
            "VPS_IP=\"203.0.113.55\"\nUSERNAME=\"ops\"\nTRANSPORT_MODE=\"ssh\"\nSSH_KEY=\"{}\"\n",
            key_path.display()
        ),
    )
    .unwrap();

    let args_log = dir.path().join("ssh_args.log");
    let mock_ssh = dir.path().join("mock_ssh");
    {
        let mut f = File::create(&mock_ssh).unwrap();
        writeln!(f, "#!/usr/bin/env bash").unwrap();
        writeln!(f, "printf '%s\\n' \"$@\" > \"{}\"", args_log.display()).unwrap();
        writeln!(f, "echo 'Linux bab-ssh 6.8.0'").unwrap();
        writeln!(f, "echo 'active'").unwrap();
        writeln!(f, "echo '/dev/sda1 25G 2G 23G 8% /'").unwrap();
        fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let out = bab_cmd(&settings, &state, &ssh_dir)
        .env("BAB_SSH_BIN", &mock_ssh)
        .arg("status")
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Target: 203.0.113.55"));
    assert!(stdout.contains("User: ops"));
    assert!(stdout.contains("Transport: ssh"));
    assert!(stdout.contains("Linux bab-ssh 6.8.0"));

    let recorded = fs::read_to_string(&args_log).unwrap();
    assert!(recorded.contains("-i"));
    assert!(recorded.contains(&key_path.display().to_string()));
    assert!(recorded.contains("ops@203.0.113.55"));
    assert!(!recorded.contains("tailscaled"));
}

#[test]
fn cli_devices_prints_table_from_mock_tailscale_api() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(&stream);
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line.trim().is_empty() {
                break;
            }
        }
        let body = r#"{"devices":[{"id":"dev-1","hostname":"edge","name":"edge.tail.ts.net","addresses":["100.64.0.12"],"os":"linux","online":true}]}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(resp.as_bytes()).unwrap();
        stream.flush().unwrap();
    });

    let dir = tempdir().unwrap();
    let settings = dir.path().join(".bab-settings");
    let state = dir.path().join(".bab-local");
    let ssh_dir = dir.path().join("ssh");

    let out = bab_cmd(&settings, &state, &ssh_dir)
        .env("TAILSCALE_API_KEY", "tskey-test")
        .env("TAILSCALE_API_BASE", format!("http://{}", addr))
        .arg("devices")
        .output()
        .unwrap();
    handle.join().unwrap();

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ID"));
    assert!(stdout.contains("HOSTNAME"));
    assert!(stdout.contains("IPV4"));
    assert!(stdout.contains("dev-1"));
    assert!(stdout.contains("edge.tail.ts.net"));
    assert!(stdout.contains("100.64.0.12"));
    assert!(stdout.contains("true"));
}

#[test]
fn cli_catalog_displays_curated_presets() {
    let dir = tempdir().unwrap();
    let config_dir = dir.path().join("bab-cfg");
    let ssh_dir = dir.path().join("ssh");

    let out = bab_cmd_config_dir(&config_dir, &ssh_dir)
        .args(["catalog", "--provider", "vultr"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Vultr (curated presets)"));
    assert!(stdout.contains("ewr"));
    assert!(stdout.contains("vc2-1c-1gb"));
    assert!(stdout.contains("2284"));
}

#[test]
fn cli_dns_prints_stub_plan_and_persists_state() {
    let dir = tempdir().unwrap();
    let config_dir = dir.path().join("bab-cfg");
    let ssh_dir = dir.path().join("ssh");

    let out = bab_cmd_config_dir(&config_dir, &ssh_dir)
        .args([
            "dns",
            "--zone",
            "example.com",
            "--record",
            "app",
            "--ip",
            "203.0.113.10",
            "--proxied",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[STUB] Cloudflare DNS: would upsert A record 'app' -> '203.0.113.10' in zone 'example.com' (proxied=true, token_configured=false)"));

    let state_raw = fs::read_to_string(config_dir.join("state.conf")).unwrap();
    assert!(state_raw.contains("CF_ZONE=\"example.com\""));
    assert!(state_raw.contains("CF_RECORD=\"app\""));
    assert!(state_raw.contains("CF_TARGET=\"203.0.113.10\""));
    assert!(state_raw.contains("CF_PROXIED=\"true\""));

    // Verify fallback from PUBLIC_IP in state.conf when --ip is omitted
    fs::write(
        config_dir.join("state.conf"),
        "PUBLIC_IP=\"198.51.100.25\"\nVPS_IP=\"100.64.0.99\"\n",
    )
    .unwrap();
    let fallback_out = bab_cmd_config_dir(&config_dir, &ssh_dir)
        .args(["dns", "--zone", "example.com", "--record", "@"])
        .output()
        .unwrap();
    assert!(
        fallback_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&fallback_out.stderr)
    );
    let fallback_stdout = String::from_utf8_lossy(&fallback_out.stdout);
    assert!(fallback_stdout.contains("would upsert A record '@' -> '198.51.100.25'"));
}

#[test]
fn cli_deploy_dry_run_and_mock_ssh_persists_github_state() {
    let dir = tempdir().unwrap();
    let config_dir = dir.path().join("bab-cfg");
    let ssh_dir = dir.path().join("ssh");

    let dry_out = bab_cmd_config_dir(&config_dir, &ssh_dir)
        .args([
            "deploy",
            "--repo",
            "owner/app",
            "--branch",
            "main",
            "--ip",
            "203.0.113.10",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(
        dry_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dry_out.stderr)
    );
    let dry_stdout = String::from_utf8_lossy(&dry_out.stdout);
    assert!(dry_stdout.contains("[DRY-RUN] GitHub Deploy (owner/app)"));
    assert!(dry_stdout.contains("https://github.com/owner/app.git"));
    assert!(dry_stdout.contains("git clone"));

    // Live mock SSH deploy persists GITHUB_* keys in state.conf
    let args_log = dir.path().join("deploy_ssh.log");
    let mock_ssh = dir.path().join("mock_ssh");
    {
        let mut f = File::create(&mock_ssh).unwrap();
        writeln!(f, "#!/usr/bin/env bash").unwrap();
        writeln!(f, "printf '%s\\n' \"$*\" >> \"{}\"", args_log.display()).unwrap();
        writeln!(f, "echo 'DEPLOYED_OK'").unwrap();
        fs::set_permissions(&mock_ssh, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let live_out = bab_cmd_config_dir(&config_dir, &ssh_dir)
        .env("BAB_SSH_BIN", &mock_ssh)
        .args([
            "deploy",
            "--repo",
            "owner/app",
            "--branch",
            "release",
            "--path",
            "/srv/app",
            "--cmd",
            "docker compose up -d",
            "--ip",
            "100.64.0.44",
        ])
        .output()
        .unwrap();
    assert!(
        live_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&live_out.stderr)
    );
    let live_stdout = String::from_utf8_lossy(&live_out.stdout);
    assert!(live_stdout.contains("[OK] GitHub Deploy (owner/app)"));
    assert!(live_stdout.contains("DEPLOYED_OK"));

    let state_raw = fs::read_to_string(config_dir.join("state.conf")).unwrap();
    assert!(state_raw.contains("GITHUB_REPO=\"owner/app\""));
    assert!(state_raw.contains("GITHUB_BRANCH=\"release\""));
    assert!(state_raw.contains("GITHUB_DEPLOY_PATH=\"/srv/app\""));
    assert!(state_raw.contains("GITHUB_DEPLOY_CMD=\"docker compose up -d\""));
}

#[test]
fn cli_settings_cloudflare_and_github_tokens_encrypted_with_permissions() {
    let dir = tempdir().unwrap();
    let config_dir = dir.path().join("bab-cfg");
    let ssh_dir = dir.path().join("ssh");

    let cf_secret = "cf-super-secret-token-9876";
    let gh_secret = "ghp_super_secret_token_5432";

    let out = bab_cmd_config_dir(&config_dir, &ssh_dir)
        .args([
            "settings",
            "--cloudflare-token",
            cf_secret,
            "--github-token",
            gh_secret,
            "--show",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("TAILSCALE_API_KEY:"));
    assert!(stdout.contains("VULTR_API_KEY:"));
    assert!(stdout.contains("UPCLOUD_API_TOKEN:"));
    assert!(stdout.contains("LINODE_API_TOKEN:"));
    assert!(stdout.contains("CLOUDFLARE_API_TOKEN: cf-s****9876"));
    assert!(stdout.contains("GITHUB_TOKEN: ghp_****5432"));
    assert!(stdout.contains("credentials.enc"));
    assert!(stdout.contains("master.key"));
    assert!(stdout.contains("ChaCha20-Poly1305"));
    assert!(!stdout.contains(cf_secret));
    assert!(!stdout.contains(gh_secret));

    let creds_path = config_dir.join("credentials.enc");
    let master_key_path = config_dir.join("master.key");
    let creds_raw = fs::read_to_string(&creds_path).unwrap();
    assert!(creds_raw.contains("CLOUDFLARE_API_TOKEN=\"enc:v1:"));
    assert!(creds_raw.contains("GITHUB_TOKEN=\"enc:v1:"));
    assert!(!creds_raw.contains(cf_secret));
    assert!(!creds_raw.contains(gh_secret));

    assert_eq!(fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(fs::metadata(&creds_path).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(fs::metadata(&master_key_path).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn cli_setup_with_github_cf_and_final_box_info_dry_run() {
    let dir = tempdir().unwrap();
    let config_dir = dir.path().join("bab-cfg");
    let ssh_dir = dir.path().join("ssh");

    let out = bab_cmd_config_dir(&config_dir, &ssh_dir)
        .args([
            "setup",
            "--provider",
            "vultr",
            "--role",
            "caddy",
            "--github-repo",
            "owner/app",
            "--cf-zone",
            "example.com",
            "--cf-record",
            "app",
            "--cf-proxied",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("region=ewr"));
    assert!(stderr.contains("plan=vc2-1c-1gb"));
    assert!(stderr.contains("image=2284"));

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("https://github.com/owner/app.git"));
    assert!(stdout.contains("[STUB] Cloudflare DNS: would upsert A record 'app' -> '100.64.0.1' in zone 'example.com' (proxied=true, token_configured=false)"));
    assert!(stdout.contains("=== Final Box Information ==="));
    assert!(stdout.contains("Public IP:"));
    assert!(stdout.contains("Tailscale IP:          100.64.0.1"));
    assert!(stdout.contains("Active Target IP:      100.64.0.1"));
    assert!(stdout.contains("Vultr (region: ewr, plan: vc2-1c-1gb, image: 2284)"));
    assert!(stdout.contains("Cloudflare DNS:        app -> 100.64.0.1 (zone: example.com, proxied: true)"));
    assert!(stdout.contains("GitHub Repo:           owner/app"));
    assert!(stdout.contains("Encrypted Credentials:"));
    assert!(stdout.contains("Master Key:"));
}

#[test]
fn cli_instances_and_destroy_help_and_dry_run() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join("credentials.enc");
    let state = dir.path().join("state.conf");
    let ssh_dir = dir.path().join("ssh");

    let top_help = bab_cmd(&settings, &state, &ssh_dir)
        .arg("--help")
        .output()
        .unwrap();
    assert!(top_help.status.success());
    let top_help_out = String::from_utf8_lossy(&top_help.stdout);
    assert!(top_help_out.contains("instances"));
    assert!(top_help_out.contains("ps"));
    assert!(top_help_out.contains("list"));
    assert!(top_help_out.contains("destroy"));
    assert!(top_help_out.contains("rm"));
    assert!(top_help_out.contains("delete"));

    let inst_help = bab_cmd(&settings, &state, &ssh_dir)
        .args(["instances", "--help"])
        .output()
        .unwrap();
    assert!(inst_help.status.success());
    let inst_help_out = String::from_utf8_lossy(&inst_help.stdout);
    assert!(inst_help_out.contains("--provider"));
    assert!(inst_help_out.contains("--all"));
    assert!(inst_help_out.contains("--destroy"));
    assert!(inst_help_out.contains("--yes"));

    let destroy_help = bab_cmd(&settings, &state, &ssh_dir)
        .args(["destroy", "--help"])
        .output()
        .unwrap();
    assert!(destroy_help.status.success());
    let destroy_help_out = String::from_utf8_lossy(&destroy_help.stdout);
    assert!(destroy_help_out.contains("--id"));
    assert!(destroy_help_out.contains("--provider"));
    assert!(destroy_help_out.contains("--yes"));
    assert!(destroy_help_out.contains("--dry-run"));

    let dry_ok = bab_cmd(&settings, &state, &ssh_dir)
        .args([
            "destroy",
            "--id",
            "vultr-123",
            "--provider",
            "vultr",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(
        dry_ok.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dry_ok.stderr)
    );
    let dry_stdout = String::from_utf8_lossy(&dry_ok.stdout);
    assert!(dry_stdout.contains("[DRY-RUN] Would destroy Vultr instance 'vultr-123'"));
    assert!(!settings.exists());
    assert!(!state.exists());

    let bad_id = bab_cmd(&settings, &state, &ssh_dir)
        .args([
            "destroy",
            "--id",
            "../bad",
            "--provider",
            "vultr",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(!bad_id.status.success());

    let missing_provider = bab_cmd(&settings, &state, &ssh_dir)
        .args(["destroy", "--id", "unknown-id", "--dry-run"])
        .output()
        .unwrap();
    assert!(!missing_provider.status.success());
    assert!(String::from_utf8_lossy(&missing_provider.stderr).contains("--provider"));
}

#[test]
fn cli_instances_and_destroy_with_mock_provider_server() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    struct MockCliState {
        vultr_alive: bool,
        upcloud_alive: bool,
        upcloud_stopped: bool,
    }

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let state_arc = Arc::new(Mutex::new(MockCliState {
        vultr_alive: true,
        upcloud_alive: true,
        upcloud_stopped: false,
    }));

    let stop_bg = Arc::clone(&stop);
    let state_bg = Arc::clone(&state_arc);
    let handle = thread::spawn(move || {
        for stream_res in listener.incoming() {
            if stop_bg.load(Ordering::SeqCst) {
                break;
            }
            let Ok(mut stream) = stream_res else {
                continue;
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut req_line = String::new();
            if reader.read_line(&mut req_line).unwrap_or(0) == 0 {
                continue;
            }
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                let trimmed = line.trim_end_matches(['\r', '\n']);
                if trimmed.is_empty() {
                    break;
                }
                if let Some((k, v)) = trimmed.split_once(':') {
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
            }
            if content_length > 0 {
                let mut sink = vec![0u8; content_length];
                let _ = std::io::Read::read_exact(&mut reader, &mut sink);
            }

            let mut parts = req_line.split_whitespace();
            let method = parts.next().unwrap_or("");
            let target = parts.next().unwrap_or("");
            let path = target.split('?').next().unwrap_or(target);

            let mut st = state_bg.lock().unwrap();
            let (status, reason, body) = match (method, path) {
                ("GET", "/v2/instances") => {
                    let body = if st.vultr_alive {
                        r#"{"instances":[{"id":"vultr-cli-1","label":"web-edge","status":"active","power_status":"running","main_ip":"203.0.113.50","region":"ewr","plan":"vc2-1c-1gb"}],"meta":{"links":{"next":""}}}"#
                    } else {
                        r#"{"instances":[],"meta":{"links":{"next":""}}}"#
                    };
                    (200, "OK", body.to_string())
                }
                ("DELETE", "/v2/instances/vultr-cli-1") => {
                    if st.vultr_alive {
                        st.vultr_alive = false;
                        (204, "No Content", String::new())
                    } else {
                        (404, "Not Found", r#"{"error":"not found"}"#.to_string())
                    }
                }
                ("GET", "/1.3/server") => {
                    let body = if st.upcloud_alive {
                        let srv_state = if st.upcloud_stopped { "stopped" } else { "started" };
                        format!(
                            r#"{{"servers":{{"server":[{{"uuid":"upcloud-cli-1","title":"vpn-core","state":"{}","zone":"de-fra1","plan":"1xCPU-1GB","ip_addresses":{{"ip_address":[{{"access":"public","address":"203.0.113.60","family":"IPv4"}}]}}}}]}}}}"#,
                            srv_state
                        )
                    } else {
                        r#"{"servers":{"server":[]}}"#.to_string()
                    };
                    (200, "OK", body)
                }
                ("POST", "/1.3/server/upcloud-cli-1/stop") => {
                    if st.upcloud_alive {
                        st.upcloud_stopped = true;
                        (
                            200,
                            "OK",
                            r#"{"server":{"uuid":"upcloud-cli-1","state":"stopped"}}"#.to_string(),
                        )
                    } else {
                        (404, "Not Found", r#"{"error":"not found"}"#.to_string())
                    }
                }
                ("DELETE", "/1.3/server/upcloud-cli-1") => {
                    if !st.upcloud_alive {
                        (404, "Not Found", r#"{"error":"not found"}"#.to_string())
                    } else if !st.upcloud_stopped {
                        (
                            409,
                            "Conflict",
                            r#"{"error":{"error_code":"SERVER_STATE_ILLEGAL"}}"#.to_string(),
                        )
                    } else {
                        st.upcloud_alive = false;
                        (204, "No Content", String::new())
                    }
                }
                _ => (404, "Not Found", r#"{"error":"unknown"}"#.to_string()),
            };

            let resp = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                reason,
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });

    let dir = tempdir().unwrap();
    let settings = dir.path().join("credentials.enc");
    let state_path = dir.path().join("state.conf");
    let ssh_dir = dir.path().join("ssh");
    fs::write(
        &state_path,
        "VPS_PROVIDER=\"vultr\"\nVPS_INSTANCE_ID=\"vultr-cli-1\"\nVPS_IP=\"203.0.113.50\"\nUSERNAME=\"deploy\"\n",
    )
    .unwrap();

    let vultr_base = format!("http://{}/v2", addr);
    let upcloud_base = format!("http://{}/1.3", addr);

    let list_out = bab_cmd(&settings, &state_path, &ssh_dir)
        .env("VULTR_API_KEY", "vultr-cli-key")
        .env("UPCLOUD_API_TOKEN", "upcloud-cli-tok")
        .env("VULTR_API_BASE_URL", &vultr_base)
        .env("UPCLOUD_API_BASE_URL", &upcloud_base)
        .args(["instances", "--all"])
        .output()
        .unwrap();
    assert!(
        list_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_stdout.contains("Vultr    1 instance(s)"));
    assert!(list_stdout.contains("UpCloud  1 instance(s)"));
    assert!(list_stdout.contains("Linode   not configured"));
    assert!(list_stdout.contains("vultr-cli-1"));
    assert!(list_stdout.contains("web-edge"));
    assert!(list_stdout.contains("upcloud-cli-1"));
    assert!(list_stdout.contains("vpn-core"));

    // Destroy Vultr instance via `rm` alias without --provider (auto-resolved) and verify session clearing.
    let rm_out = bab_cmd(&settings, &state_path, &ssh_dir)
        .env("VULTR_API_BASE_URL", &vultr_base)
        .env("UPCLOUD_API_BASE_URL", &upcloud_base)
        .args(["rm", "--id", "vultr-cli-1", "--yes"])
        .output()
        .unwrap();
    assert!(
        rm_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rm_out.stderr)
    );
    let rm_stdout = String::from_utf8_lossy(&rm_out.stdout);
    assert!(rm_stdout.contains("Destroyed Vultr instance 'vultr-cli-1'"));
    assert!(rm_stdout.contains("Cleared matching active session state"));

    let state_after = fs::read_to_string(&state_path).unwrap();
    assert!(!state_after.contains("VPS_INSTANCE_ID="));
    assert!(!state_after.contains("VPS_IP="));
    assert!(state_after.contains("USERNAME=\"deploy\""));

    // Destroy UpCloud instance via `ps --destroy -y` (triggers stop + retry delete).
    let ps_destroy_out = bab_cmd(&settings, &state_path, &ssh_dir)
        .env("VULTR_API_BASE_URL", &vultr_base)
        .env("UPCLOUD_API_BASE_URL", &upcloud_base)
        .args(["ps", "--destroy", "upcloud-cli-1", "-y"])
        .output()
        .unwrap();
    assert!(
        ps_destroy_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&ps_destroy_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&ps_destroy_out.stdout)
            .contains("Destroyed UpCloud instance 'upcloud-cli-1'")
    );

    // Verify `list` alias reports no remaining instances.
    let final_list = bab_cmd(&settings, &state_path, &ssh_dir)
        .env("VULTR_API_BASE_URL", &vultr_base)
        .env("UPCLOUD_API_BASE_URL", &upcloud_base)
        .arg("list")
        .output()
        .unwrap();
    assert!(final_list.status.success());
    assert!(String::from_utf8_lossy(&final_list.stdout).contains("No instances found."));

    stop.store(true, Ordering::SeqCst);
    let _ = std::net::TcpStream::connect(addr);
    handle.join().unwrap();
}

#[test]
fn cli_settings_auto_saves_env_api_keys_encrypted() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join("credentials.enc");
    let state = dir.path().join("state.conf");
    let ssh_dir = dir.path().join("ssh");
    let master_key = dir.path().join("master.key");

    let env_secret = "vultr-env-secret-9876";
    let first = bab_cmd(&settings, &state, &ssh_dir)
        .env("VULTR_API_KEY", env_secret)
        .args(["settings", "--show"])
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_stdout = String::from_utf8_lossy(&first.stdout);
    assert!(first_stdout.contains("VULTR_API_KEY: vult****9876"));
    assert!(!first_stdout.contains(env_secret));

    let creds_raw = fs::read_to_string(&settings).unwrap();
    assert!(creds_raw.contains("VULTR_API_KEY=\"enc:v1:"));
    assert!(!creds_raw.contains(env_secret));
    assert_eq!(
        fs::metadata(&settings).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&master_key).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Run again with VULTR_API_KEY removed from env and verify persisted encrypted key remains.
    let second = bab_cmd(&settings, &state, &ssh_dir)
        .args(["settings", "--show"])
        .output()
        .unwrap();
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_stdout = String::from_utf8_lossy(&second.stdout);
    assert!(second_stdout.contains("VULTR_API_KEY: vult****9876"));
    assert!(!second_stdout.contains(env_secret));
}

#[test]
fn cli_setup_cf_dns_and_no_cf_dns_dry_run() {
    let dir = tempdir().unwrap();
    let settings = dir.path().join("credentials.enc");
    let state = dir.path().join("state.conf");
    let ssh_dir = dir.path().join("ssh");

    fs::write(
        &state,
        "CF_ENABLED=\"true\"\nCF_ZONE=\"example.com\"\nCF_RECORD=\"app\"\nCF_TARGET=\"public\"\nCF_PROXIED=\"true\"\n",
    )
    .unwrap();

    // Saved CF_ENABLED="true" triggers Cloudflare DNS stub plan automatically.
    let with_saved = bab_cmd(&settings, &state, &ssh_dir)
        .args(["setup", "--provider", "vultr", "--dry-run"])
        .output()
        .unwrap();
    assert!(
        with_saved.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&with_saved.stderr)
    );
    let saved_stdout = String::from_utf8_lossy(&with_saved.stdout);
    assert!(saved_stdout.contains("[STUB] Cloudflare DNS: would upsert A record 'app'"));
    assert!(saved_stdout.contains("Cloudflare DNS:        app ->"));

    // --no-cf-dns skips Cloudflare DNS stub plan even when CF_ENABLED="true" in state.
    let skipped = bab_cmd(&settings, &state, &ssh_dir)
        .args(["setup", "--provider", "vultr", "--no-cf-dns", "--dry-run"])
        .output()
        .unwrap();
    assert!(
        skipped.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&skipped.stderr)
    );
    let skipped_stdout = String::from_utf8_lossy(&skipped.stdout);
    assert!(!skipped_stdout.contains("[STUB] Cloudflare DNS:"));
    assert!(!skipped_stdout.contains("Cloudflare DNS:"));

    // --cf-dns forces Cloudflare DNS using saved CF_* values even when CF_ENABLED="false".
    fs::write(
        &state,
        "CF_ENABLED=\"false\"\nCF_ZONE=\"example.com\"\nCF_RECORD=\"web\"\nCF_TARGET=\"203.0.113.77\"\nCF_PROXIED=\"false\"\n",
    )
    .unwrap();
    let forced = bab_cmd(&settings, &state, &ssh_dir)
        .args(["setup", "--provider", "vultr", "--cf-dns", "--dry-run"])
        .output()
        .unwrap();
    assert!(
        forced.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let forced_stdout = String::from_utf8_lossy(&forced.stdout);
    assert!(forced_stdout.contains(
        "[STUB] Cloudflare DNS: would upsert A record 'web' -> '203.0.113.77' in zone 'example.com' (proxied=false"
    ));
}
