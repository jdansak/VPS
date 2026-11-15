use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::thread;
use tempfile::tempdir;

fn bab_cmd(settings_path: &Path, state_path: &Path, ssh_dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_bab"));
    for key in [
        "TAILSCALE_API_KEY",
        "TAILSCALE_API_BASE",
        "TAILSCALE_TAILNET",
        "VULTR_API_KEY",
        "UPCLOUD_API_TOKEN",
        "LINODE_API_TOKEN",
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
    cmd.env("BAB_SETTINGS_FILE", settings_path);
    cmd.env("BAB_STATE_FILE", state_path);
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
    let settings = dir.path().join(".bab-settings");
    let state = dir.path().join(".bab-local");
    let ssh_dir = dir.path().join("ssh");

    let secret = "tskey-api-supersecret1234";
    let out = bab_cmd(&settings, &state, &ssh_dir)
        .args(["settings", "--tailscale-key", secret, "--show"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("TAILSCALE_API_KEY: tske****1234"));
    assert!(!stdout.contains(secret), "raw secret must not appear in output");

    let saved = fs::read_to_string(&settings).unwrap();
    assert!(saved.contains(&format!("TAILSCALE_API_KEY=\"{}\"", secret)));

    // Subsequent --show reads persisted key and keeps it masked
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
