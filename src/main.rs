use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use bab::config::{SessionState, Settings};
use bab::providers::linode::LinodeProvider;
use bab::providers::upcloud::UpCloudProvider;
use bab::providers::vultr::VultrProvider;
use bab::providers::{provision_full_flow, ProvisionConfig, ProviderKind, VpsProvider};
use bab::roles::ServerRole;
use bab::setup::{SetupConfig, SetupRunner};
use bab::tailscale::{
    generate_cloud_init, generate_ssh_cloud_init, TailscaleClient, TailscaleDevice,
};
use bab::transport::{
    default_ssh_key_path, ensure_ssh_keypair, is_valid_target, read_public_key, SshTransport,
    TransportMode,
};
use bab::tui::{run_tui, ApiKeyForm};

fn parse_provider(s: &str) -> std::result::Result<ProviderKind, String> {
    ProviderKind::from_str(s).map_err(|e| e.to_string())
}

fn parse_role(s: &str) -> std::result::Result<ServerRole, String> {
    ServerRole::from_str(s).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TransportArg {
    Tailscale,
    Ssh,
}

#[derive(Debug, Parser)]
#[command(
    name = "bab",
    version,
    about = "Build A Box (bab) - VPS provisioner and hardener"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Launch the interactive terminal UI
    Tui(TuiArgs),
    /// List available server role profiles
    Roles(RolesArgs),
    /// Provision and configure a VPS node
    Setup(SetupArgs),
    /// List Tailscale devices in the tailnet
    Devices,
    /// Generate a cloud-init bootstrap script
    CloudInit(CloudInitArgs),
    /// View or update saved API key settings
    Settings(SettingsArgs),
    /// Check remote status of the configured VPS node
    Status,
}

#[derive(Debug, Args)]
struct TuiArgs {
    /// Path to settings file
    #[arg(long, value_name = "PATH")]
    settings: Option<PathBuf>,
    /// Path to session state file
    #[arg(long, value_name = "PATH")]
    state: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct RolesArgs {
    /// Transport mode for port summary (tailscale or ssh)
    #[arg(long, value_enum, default_value_t = TransportArg::Tailscale)]
    transport: TransportArg,
}

#[derive(Debug, Args)]
struct SetupArgs {
    /// VPS provider or bootstrap mode (vultr, upcloud, linode, existing, manual)
    #[arg(long, default_value = "existing", value_parser = parse_provider)]
    provider: ProviderKind,
    /// Server role profile (vanilla, caddy, wireguard, rbi)
    #[arg(long, default_value = "vanilla", value_parser = parse_role)]
    role: ServerRole,
    /// Transport mode (tailscale or ssh)
    #[arg(long, value_enum, default_value_t = TransportArg::Tailscale)]
    transport: TransportArg,
    /// Path to SSH private key for Standard SSH mode (defaults to ~/.ssh/bab_ed25519)
    #[arg(long, value_name = "PATH")]
    ssh_key: Option<PathBuf>,
    /// Explicit SSH public key string for Standard SSH mode
    #[arg(long, value_name = "KEY")]
    ssh_pubkey: Option<String>,
    /// Generate an Ed25519 SSH keypair if missing
    #[arg(long)]
    generate_ssh_key: bool,
    /// Hostname for the VPS / Tailscale node
    #[arg(long, default_value = "bab-node")]
    hostname: String,
    /// Non-root deploy user to create
    #[arg(long, default_value = "deploy")]
    user: String,
    /// Initial SSH login user for remote setup
    #[arg(long, default_value = "root")]
    ssh_user: String,
    /// Target IP address or MagicDNS hostname
    #[arg(long, value_name = "TARGET")]
    ip: Option<String>,
    /// Cloud provider region ID
    #[arg(long, value_name = "R")]
    region: Option<String>,
    /// Cloud provider plan ID
    #[arg(long, value_name = "P")]
    plan: Option<String>,
    /// Cloud provider OS image ID
    #[arg(long, value_name = "I")]
    image: Option<String>,
    /// Comma-separated Tailscale ACL tags
    #[arg(long, value_name = "CSV")]
    tags: Option<String>,
    /// Preview setup scripts without executing remote commands
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct CloudInitArgs {
    /// Transport mode (tailscale or ssh)
    #[arg(long, value_enum, default_value_t = TransportArg::Tailscale)]
    transport: TransportArg,
    /// Path to SSH private key for Standard SSH mode (defaults to ~/.ssh/bab_ed25519)
    #[arg(long, value_name = "PATH")]
    ssh_key: Option<PathBuf>,
    /// Explicit SSH public key string for Standard SSH mode
    #[arg(long, value_name = "KEY")]
    ssh_pubkey: Option<String>,
    /// Generate an Ed25519 SSH keypair if missing
    #[arg(long)]
    generate_ssh_key: bool,
    /// Hostname for the node
    #[arg(long, default_value = "bab-node")]
    hostname: String,
    /// Non-root sudo user to create
    #[arg(long, default_value = "deploy")]
    user: String,
    /// Existing Tailscale auth key (if omitted, creates one via TAILSCALE_API_KEY)
    #[arg(long)]
    authkey: Option<String>,
}

#[derive(Debug, Args)]
struct SettingsArgs {
    /// Display masked API key status
    #[arg(long)]
    show: bool,
    /// Set TAILSCALE_API_KEY
    #[arg(long)]
    tailscale_key: Option<String>,
    /// Set VULTR_API_KEY
    #[arg(long)]
    vultr_key: Option<String>,
    /// Set UPCLOUD_API_TOKEN
    #[arg(long)]
    upcloud_token: Option<String>,
    /// Set LINODE_API_TOKEN
    #[arg(long)]
    linode_token: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    dispatch(cli)
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        None => run_tui(None, None),
        Some(Commands::Tui(args)) => run_tui(args.settings.as_deref(), args.state.as_deref()),
        Some(Commands::Roles(args)) => {
            cmd_roles(args);
            Ok(())
        }
        Some(Commands::Setup(args)) => cmd_setup(args),
        Some(Commands::Devices) => cmd_devices(),
        Some(Commands::CloudInit(args)) => cmd_cloud_init(args),
        Some(Commands::Settings(args)) => cmd_settings(args),
        Some(Commands::Status) => cmd_status(),
    }
}

fn cmd_roles(args: RolesArgs) {
    let tailscale_mode = args.transport == TransportArg::Tailscale;
    for role in ServerRole::all() {
        println!(
            "{} | {} | stub={}",
            role,
            role.label(),
            role.is_stub()
        );
        println!("  Description: {}", role.description());
        println!(
            "  Open ports:  {}",
            role.open_ports_for_mode(tailscale_mode).join(", ")
        );
    }
}

fn parse_tags(csv: Option<&str>) -> Vec<String> {
    csv.unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn require_tailscale_key(settings: &Settings) -> Result<String> {
    settings
        .tailscale_api_key()?
        .filter(|k| !k.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "TAILSCALE_API_KEY is not configured. Set it via `bab settings --tailscale-key <KEY>` or the TAILSCALE_API_KEY environment variable."
            )
        })
}

struct ResolvedSsh {
    key_path: Option<PathBuf>,
    pubkey: String,
}

fn resolve_ssh_credentials(
    ssh_key: Option<&PathBuf>,
    ssh_pubkey: Option<&str>,
    generate_ssh_key: bool,
    hostname: &str,
    dry_run: bool,
) -> Result<ResolvedSsh> {
    let comment = format!("bab@{}", hostname);
    let explicit_pubkey = ssh_pubkey
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);

    let resolved_path = match ssh_key {
        Some(p) => Some(p.clone()),
        None => default_ssh_key_path().ok(),
    };

    if generate_ssh_key {
        let key_path = match resolved_path {
            Some(p) => p,
            None => default_ssh_key_path()?,
        };
        let generated_pub = ensure_ssh_keypair(&key_path, &comment)?;
        let pubkey = explicit_pubkey.unwrap_or(generated_pub);
        return Ok(ResolvedSsh {
            key_path: Some(key_path),
            pubkey,
        });
    }

    if let Some(pubkey) = explicit_pubkey {
        let effective_key_path = ssh_key
            .cloned()
            .or_else(|| default_ssh_key_path().ok().filter(|p| p.exists()));
        return Ok(ResolvedSsh {
            key_path: effective_key_path,
            pubkey,
        });
    }

    let key_path = match resolved_path {
        Some(p) => p,
        None => default_ssh_key_path()?,
    };

    match read_public_key(&key_path) {
        Ok(pubkey) => Ok(ResolvedSsh {
            key_path: Some(key_path),
            pubkey,
        }),
        Err(_) if dry_run => {
            eprintln!(
                "Note: --dry-run in ssh mode without an existing SSH key at {}; using placeholder public key.",
                key_path.display()
            );
            Ok(ResolvedSsh {
                key_path: Some(key_path),
                pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDryRunPlaceholderKey bab@dry-run"
                    .to_string(),
            })
        }
        Err(_) => {
            let pubkey = ensure_ssh_keypair(&key_path, &comment)?;
            Ok(ResolvedSsh {
                key_path: Some(key_path),
                pubkey,
            })
        }
    }
}

fn build_cloud_provider(kind: ProviderKind, settings: &Settings) -> Result<Box<dyn VpsProvider>> {
    match kind {
        ProviderKind::Vultr => {
            let key = settings
                .vultr_api_key()?
                .filter(|k| !k.is_empty())
                .ok_or_else(|| anyhow!("VULTR_API_KEY is not configured"))?;
            Ok(Box::new(VultrProvider::new(key)?))
        }
        ProviderKind::UpCloud => {
            let token = settings
                .upcloud_api_token()?
                .filter(|k| !k.is_empty())
                .ok_or_else(|| anyhow!("UPCLOUD_API_TOKEN is not configured"))?;
            Ok(Box::new(UpCloudProvider::new(token)?))
        }
        ProviderKind::Linode => {
            let token = settings
                .linode_api_token()?
                .filter(|k| !k.is_empty())
                .ok_or_else(|| anyhow!("LINODE_API_TOKEN is not configured"))?;
            Ok(Box::new(LinodeProvider::new(token)?))
        }
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit => {
            Err(anyhow!("{} does not use a cloud provider API client", kind.label()))
        }
    }
}

fn resolve_or_first<F>(
    explicit: Option<String>,
    list_ids: F,
    flag: &str,
    provider: ProviderKind,
) -> Result<String>
where
    F: FnOnce() -> Result<Vec<String>>,
{
    if let Some(val) = explicit.filter(|s| !s.is_empty()) {
        return Ok(val);
    }
    let ids = list_ids().with_context(|| {
        format!(
            "{} was not provided and querying {} options failed",
            flag,
            provider.label()
        )
    })?;
    ids.into_iter().next().ok_or_else(|| {
        anyhow!(
            "{} is required for {} (no default options returned by provider)",
            flag,
            provider.label()
        )
    })
}

fn wait_for_ssh_ready(
    transport: &SshTransport,
    ssh_user: &str,
    host: &str,
    timeout: Duration,
    interval: Duration,
) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    let probe_cmd =
        "if [ -d /var/lib/cloud ]; then test -f /var/lib/cloud/instance/boot-finished; fi";
    let mut last_status;

    loop {
        match transport.exec(ssh_user, host, probe_cmd) {
            Ok(out) if out.success() => return Ok(()),
            Ok(out) => {
                last_status = format!("exit code {}", out.status_code);
            }
            Err(err) => {
                last_status = err.to_string();
            }
        }

        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(anyhow!(
                "Timed out after {:?} waiting for SSH and cloud-init readiness on {}@{} (last status: {})",
                timeout,
                ssh_user,
                host,
                last_status
            ));
        }

        let sleep_for = interval.min(deadline.saturating_duration_since(now));
        if !sleep_for.is_zero() {
            std::thread::sleep(sleep_for);
        }
    }
}

fn persist_setup_session(
    session: &SessionState,
    target: &str,
    username: &str,
    hostname: &str,
    tailscale_mode: bool,
    key_path_opt: Option<&Path>,
) -> Result<()> {
    session.set_vps_ip(target)?;
    session.set_username(username)?;
    session.set_tailscale_hostname(hostname)?;
    if tailscale_mode {
        session.set_transport_mode("tailscale")?;
        session.set_ssh_key("tailscale")?;
    } else {
        session.set_transport_mode("ssh")?;
        match key_path_opt.filter(|p| !p.as_os_str().is_empty()) {
            Some(path) => {
                session.set_ssh_key(&path.to_string_lossy())?;
            }
            None => {
                if session
                    .ssh_key()?
                    .as_deref()
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("tailscale"))
                {
                    session.set_ssh_key("")?;
                }
            }
        }
    }
    Ok(())
}

fn cmd_setup(args: SetupArgs) -> Result<()> {
    let settings = Settings::load_default()?;
    let session = SessionState::load_default()?;
    let tags = parse_tags(args.tags.as_deref());
    let tailscale_mode = args.transport == TransportArg::Tailscale;

    let resolved_ssh = if !tailscale_mode {
        Some(resolve_ssh_credentials(
            args.ssh_key.as_ref(),
            args.ssh_pubkey.as_deref(),
            args.generate_ssh_key,
            &args.hostname,
            args.dry_run,
        )?)
    } else {
        None
    };

    if args.provider == ProviderKind::ManualCloudInit {
        let script = if tailscale_mode {
            let maybe_ts_key = settings.tailscale_api_key()?.filter(|k| !k.is_empty());
            let auth_key = match maybe_ts_key {
                None if args.dry_run => {
                    eprintln!(
                        "Note: --dry-run without TAILSCALE_API_KEY configured; generating sample cloud-init with placeholder auth key."
                    );
                    "tskey-auth-DRYRUN".to_string()
                }
                None => return Err(anyhow!(
                    "TAILSCALE_API_KEY is not configured. Set it via `bab settings --tailscale-key <KEY>` or the TAILSCALE_API_KEY environment variable."
                )),
                Some(ts_key) => {
                    let ts_client = TailscaleClient::new(ts_key)?;
                    ts_client.create_auth_key("bab-bootstrap", &tags, false, true, 3600)?
                }
            };
            generate_cloud_init(&auth_key, &args.hostname, &args.user)
        } else {
            let ssh = resolved_ssh
                .as_ref()
                .ok_or_else(|| anyhow!("Failed to resolve SSH credentials"))?;
            generate_ssh_cloud_init(&ssh.pubkey, &args.hostname, &args.user)
        };
        print!("{}", script);
        return Ok(());
    }

    let mut needs_ssh_wait = false;
    let target = match args.provider {
        ProviderKind::Vultr | ProviderKind::UpCloud | ProviderKind::Linode => {
            if let Some(ip) = args.ip.clone().filter(|s| !s.is_empty()) {
                ip
            } else if args.dry_run {
                let default_ip = if tailscale_mode {
                    "100.64.0.1"
                } else {
                    "203.0.113.10"
                };
                eprintln!(
                    "Note: --dry-run without --ip for {} provider; defaulting target to {}.",
                    args.provider.label(),
                    default_ip
                );
                default_ip.to_string()
            } else {
                let ts_client = if tailscale_mode {
                    let ts_key = require_tailscale_key(&settings)?;
                    Some(TailscaleClient::new(ts_key)?)
                } else {
                    None
                };
                let provider = build_cloud_provider(args.provider, &settings)?;

                let region = resolve_or_first(
                    args.region.clone(),
                    || {
                        Ok(provider
                            .list_regions()?
                            .into_iter()
                            .map(|r| r.id)
                            .collect())
                    },
                    "--region",
                    args.provider,
                )?;
                let plan = resolve_or_first(
                    args.plan.clone(),
                    || {
                        Ok(provider
                            .list_plans()?
                            .into_iter()
                            .map(|p| p.id)
                            .collect())
                    },
                    "--plan",
                    args.provider,
                )?;
                let image_id = resolve_or_first(
                    args.image.clone(),
                    || {
                        Ok(provider
                            .list_images()?
                            .into_iter()
                            .map(|i| i.id)
                            .collect())
                    },
                    "--image",
                    args.provider,
                )?;

                let prov_cfg = ProvisionConfig {
                    provider: args.provider,
                    region,
                    plan,
                    image_id,
                    hostname: args.hostname.clone(),
                    username: args.user.clone(),
                    role: args.role.to_string(),
                    tags,
                    provider_timeout: Duration::from_secs(300),
                    tailscale_timeout: Duration::from_secs(300),
                    poll_interval: Duration::from_secs(5),
                    tailscale_mode,
                    ssh_pubkey: resolved_ssh.as_ref().map(|s| s.pubkey.clone()),
                    ssh_key_path: resolved_ssh
                        .as_ref()
                        .and_then(|s| s.key_path.as_ref())
                        .map(|p| p.to_string_lossy().into_owned()),
                };

                let result = provision_full_flow(
                    provider.as_ref(),
                    ts_client.as_ref(),
                    &prov_cfg,
                    Some(&session),
                )?;
                if result.tailscale_mode {
                    println!(
                        "Provisioned {} instance {} at Tailscale IP {}",
                        result.provider, result.instance_id, result.ip
                    );
                } else {
                    println!(
                        "Provisioned {} instance {} at Public IP {}",
                        result.provider, result.instance_id, result.ip
                    );
                    needs_ssh_wait = true;
                }
                result.ip
            }
        }
        ProviderKind::ExistingTailscale => {
            if let Some(ip) = args.ip.clone().filter(|s| !s.is_empty()) {
                ip
            } else if let Some(saved_ip) = session.vps_ip()?.filter(|s| !s.is_empty()) {
                saved_ip
            } else if args.dry_run {
                let default_ip = if tailscale_mode {
                    "100.64.0.1"
                } else {
                    "203.0.113.10"
                };
                eprintln!(
                    "Note: --dry-run with no --ip or saved VPS_IP; defaulting target to {}.",
                    default_ip
                );
                default_ip.to_string()
            } else {
                return Err(anyhow!(
                    "No target IP specified. Pass --ip <TARGET> or save VPS_IP in session state."
                ));
            }
        }
        ProviderKind::ManualCloudInit => unreachable!(),
    };

    if !is_valid_target(&target) {
        return Err(anyhow!("Invalid target IP or hostname: '{}'", target));
    }

    let ssh_pubkey_for_setup = resolved_ssh.as_ref().map(|s| s.pubkey.clone());
    let ssh_key_for_transport = resolved_ssh
        .as_ref()
        .and_then(|s| s.key_path.clone())
        .unwrap_or_default();

    let cfg = SetupConfig {
        host: target.clone(),
        ssh_user: args.ssh_user,
        new_username: args.user.clone(),
        hostname: args.hostname.clone(),
        role: args.role,
        provider_name: args.provider.to_string(),
        tailscale_mode,
        ssh_pubkey: ssh_pubkey_for_setup,
        dry_run: args.dry_run,
    };

    let mode = if tailscale_mode {
        TransportMode::Tailscale
    } else {
        TransportMode::SshKey(ssh_key_for_transport.clone())
    };
    let transport = SshTransport::from_env(mode);
    if needs_ssh_wait {
        println!(
            "Waiting for SSH and cloud-init readiness on {}@{}...",
            cfg.ssh_user, cfg.host
        );
        wait_for_ssh_ready(
            &transport,
            &cfg.ssh_user,
            &cfg.host,
            Duration::from_secs(180),
            Duration::from_secs(5),
        )?;
    }

    let runner = SetupRunner::new(&transport, Some(&session));
    runner.run_all(&cfg, |report| {
        let tag = if report.dry_run {
            "DRY-RUN"
        } else if report.success {
            "OK"
        } else {
            "FAIL"
        };
        println!("[{}] {}", tag, report.step.title());
        if !report.output.trim().is_empty() {
            println!("{}", report.output.trim_end());
        }
    })?;

    if !args.dry_run {
        let key_path_opt = resolved_ssh.as_ref().and_then(|s| s.key_path.as_deref());
        persist_setup_session(
            &session,
            &target,
            &args.user,
            &args.hostname,
            tailscale_mode,
            key_path_opt,
        )?;
    }

    Ok(())
}

fn cmd_devices() -> Result<()> {
    let settings = Settings::load_default()?;
    let ts_key = require_tailscale_key(&settings)?;
    let client = TailscaleClient::new(ts_key)?;
    let devices = client.list_devices()?;
    print_devices_table(&devices);
    Ok(())
}

fn print_devices_table(devices: &[TailscaleDevice]) {
    let mut w_id = "ID".len();
    let mut w_host = "HOSTNAME".len();
    let mut w_name = "NAME".len();
    let mut w_ipv4 = "IPV4".len();
    let mut w_os = "OS".len();
    let w_online = "ONLINE".len();

    for d in devices {
        w_id = w_id.max(d.id.len());
        w_host = w_host.max(d.hostname.len());
        w_name = w_name.max(d.name.len());
        w_ipv4 = w_ipv4.max(d.ipv4.len());
        w_os = w_os.max(d.os.len());
    }

    println!(
        "{:<w_id$}  {:<w_host$}  {:<w_name$}  {:<w_ipv4$}  {:<w_os$}  {:<w_online$}",
        "ID", "HOSTNAME", "NAME", "IPV4", "OS", "ONLINE"
    );
    for d in devices {
        println!(
            "{:<w_id$}  {:<w_host$}  {:<w_name$}  {:<w_ipv4$}  {:<w_os$}  {:<w_online$}",
            d.id, d.hostname, d.name, d.ipv4, d.os, d.online
        );
    }
}

fn cmd_cloud_init(args: CloudInitArgs) -> Result<()> {
    let script = match args.transport {
        TransportArg::Tailscale => {
            let auth_key = match args.authkey.filter(|k| !k.is_empty()) {
                Some(key) => key,
                None => {
                    let settings = Settings::load_default()?;
                    let ts_key = require_tailscale_key(&settings)?;
                    let client = TailscaleClient::new(ts_key)?;
                    client.create_auth_key("bab-bootstrap", &[], false, true, 3600)?
                }
            };
            generate_cloud_init(&auth_key, &args.hostname, &args.user)
        }
        TransportArg::Ssh => {
            let ssh = resolve_ssh_credentials(
                args.ssh_key.as_ref(),
                args.ssh_pubkey.as_deref(),
                args.generate_ssh_key,
                &args.hostname,
                false,
            )?;
            generate_ssh_cloud_init(&ssh.pubkey, &args.hostname, &args.user)
        }
    };
    print!("{}", script);
    Ok(())
}

fn cmd_settings(args: SettingsArgs) -> Result<()> {
    let settings = Settings::load_default()?;
    let mut updated = false;

    if let Some(ref key) = args.tailscale_key {
        settings.set_tailscale_api_key(key)?;
        updated = true;
    }
    if let Some(ref key) = args.vultr_key {
        settings.set_vultr_api_key(key)?;
        updated = true;
    }
    if let Some(ref token) = args.upcloud_token {
        settings.set_upcloud_api_token(token)?;
        updated = true;
    }
    if let Some(ref token) = args.linode_token {
        settings.set_linode_api_token(token)?;
        updated = true;
    }

    if args.show || updated || (!args.show && !updated) {
        let ts = settings.tailscale_api_key()?.unwrap_or_default();
        let vultr = settings.vultr_api_key()?.unwrap_or_default();
        let upcloud = settings.upcloud_api_token()?.unwrap_or_default();
        let linode = settings.linode_api_token()?.unwrap_or_default();

        println!("TAILSCALE_API_KEY: {}", ApiKeyForm::mask_key(&ts));
        println!("VULTR_API_KEY:     {}", ApiKeyForm::mask_key(&vultr));
        println!("UPCLOUD_API_TOKEN: {}", ApiKeyForm::mask_key(&upcloud));
        println!("LINODE_API_TOKEN:  {}", ApiKeyForm::mask_key(&linode));
    }

    Ok(())
}

fn cmd_status() -> Result<()> {
    let session = SessionState::load_default()?;
    let target = session
        .vps_ip()?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("No VPS_IP found in session state. Run `bab setup` first."))?;

    if !is_valid_target(&target) {
        return Err(anyhow!("Invalid target in session state: '{}'", target));
    }

    let username = session
        .username()?
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "deploy".to_string());

    let transport_mode_val = session.transport_mode()?.unwrap_or_default();
    let ssh_key_val = session.ssh_key()?.unwrap_or_default();
    let use_ssh_key = transport_mode_val.eq_ignore_ascii_case("ssh")
        || (!ssh_key_val.is_empty() && ssh_key_val != "tailscale");

    let (mode, transport_label, remote_cmd) = if use_ssh_key {
        let key_path = if !ssh_key_val.is_empty() && ssh_key_val != "tailscale" {
            PathBuf::from(&ssh_key_val)
        } else {
            default_ssh_key_path()
                .ok()
                .filter(|p| p.exists())
                .unwrap_or_default()
        };
        (
            TransportMode::SshKey(key_path),
            "ssh",
            "uname -a && (systemctl is-active sshd || systemctl is-active ssh || true) && df -h /",
        )
    } else {
        (
            TransportMode::Tailscale,
            "tailscale",
            "uname -a && systemctl is-active tailscaled || true && df -h /",
        )
    };

    println!(
        "Target: {} | User: {} | Transport: {}",
        target, username, transport_label
    );

    let transport = SshTransport::from_env(mode);
    let out = transport.exec(&username, &target, remote_cmd)?;

    if !out.stdout.is_empty() {
        print!("{}", out.stdout);
        if !out.stdout.ends_with('\n') {
            println!();
        }
    }
    if !out.stderr.is_empty() {
        eprint!("{}", out.stderr);
    }
    if !out.success() {
        return Err(anyhow!(
            "Status command failed with exit code {}",
            out.status_code
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_no_subcommand_defaults_to_none() {
        let cli = Cli::try_parse_from(["bab"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn parse_tui_subcommand_with_paths() {
        let cli = Cli::try_parse_from(["bab", "tui"]).unwrap();
        match cli.command {
            Some(Commands::Tui(args)) => {
                assert_eq!(args.settings, None);
                assert_eq!(args.state, None);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        let cli_paths = Cli::try_parse_from([
            "bab",
            "tui",
            "--settings",
            "/tmp/s.conf",
            "--state",
            "/tmp/l.conf",
        ])
        .unwrap();
        match cli_paths.command {
            Some(Commands::Tui(args)) => {
                assert_eq!(args.settings, Some(PathBuf::from("/tmp/s.conf")));
                assert_eq!(args.state, Some(PathBuf::from("/tmp/l.conf")));
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn parse_roles_devices_status_subcommands() {
        match Cli::try_parse_from(["bab", "roles"]).unwrap().command {
            Some(Commands::Roles(args)) => assert_eq!(args.transport, TransportArg::Tailscale),
            other => panic!("unexpected command: {:?}", other),
        }
        match Cli::try_parse_from(["bab", "roles", "--transport", "ssh"])
            .unwrap()
            .command
        {
            Some(Commands::Roles(args)) => assert_eq!(args.transport, TransportArg::Ssh),
            other => panic!("unexpected command: {:?}", other),
        }
        assert!(matches!(
            Cli::try_parse_from(["bab", "devices"]).unwrap().command,
            Some(Commands::Devices)
        ));
        assert!(matches!(
            Cli::try_parse_from(["bab", "status"]).unwrap().command,
            Some(Commands::Status)
        ));
    }

    #[test]
    fn parse_setup_defaults_and_all_roles_and_providers() {
        let def = Cli::try_parse_from(["bab", "setup"]).unwrap();
        match def.command {
            Some(Commands::Setup(args)) => {
                assert_eq!(args.provider, ProviderKind::ExistingTailscale);
                assert_eq!(args.role, ServerRole::Vanilla);
                assert_eq!(args.transport, TransportArg::Tailscale);
                assert_eq!(args.ssh_key, None);
                assert_eq!(args.ssh_pubkey, None);
                assert!(!args.generate_ssh_key);
                assert_eq!(args.hostname, "bab-node");
                assert_eq!(args.user, "deploy");
                assert_eq!(args.ssh_user, "root");
                assert_eq!(args.ip, None);
                assert!(!args.dry_run);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        for (role_str, expected_role) in [
            ("vanilla", ServerRole::Vanilla),
            ("caddy", ServerRole::ReverseProxyCaddy),
            ("wireguard", ServerRole::VpnWireguard),
            ("rbi", ServerRole::RemoteBrowserIsolation),
        ] {
            let cli = Cli::try_parse_from([
                "bab",
                "setup",
                "--provider",
                "vultr",
                "--role",
                role_str,
                "--transport",
                "ssh",
                "--ssh-key",
                "/tmp/bab_key",
                "--ssh-pubkey",
                "ssh-ed25519 AAAA test",
                "--generate-ssh-key",
                "--hostname",
                "my-box",
                "--user",
                "ops",
                "--ssh-user",
                "ubuntu",
                "--ip",
                "203.0.113.42",
                "--region",
                "ewr",
                "--plan",
                "vc2-1c-1gb",
                "--image",
                "2284",
                "--tags",
                "tag:prod,tag:web",
                "--dry-run",
            ])
            .unwrap();
            match cli.command {
                Some(Commands::Setup(args)) => {
                    assert_eq!(args.provider, ProviderKind::Vultr);
                    assert_eq!(args.role, expected_role);
                    assert_eq!(args.transport, TransportArg::Ssh);
                    assert_eq!(args.ssh_key, Some(PathBuf::from("/tmp/bab_key")));
                    assert_eq!(args.ssh_pubkey.as_deref(), Some("ssh-ed25519 AAAA test"));
                    assert!(args.generate_ssh_key);
                    assert_eq!(args.hostname, "my-box");
                    assert_eq!(args.user, "ops");
                    assert_eq!(args.ssh_user, "ubuntu");
                    assert_eq!(args.ip.as_deref(), Some("203.0.113.42"));
                    assert_eq!(args.region.as_deref(), Some("ewr"));
                    assert_eq!(args.plan.as_deref(), Some("vc2-1c-1gb"));
                    assert_eq!(args.image.as_deref(), Some("2284"));
                    assert_eq!(args.tags.as_deref(), Some("tag:prod,tag:web"));
                    assert!(args.dry_run);
                }
                other => panic!("unexpected command: {:?}", other),
            }
        }

        for (prov_str, expected_prov) in [
            ("vultr", ProviderKind::Vultr),
            ("upcloud", ProviderKind::UpCloud),
            ("linode", ProviderKind::Linode),
            ("existing", ProviderKind::ExistingTailscale),
            ("manual", ProviderKind::ManualCloudInit),
        ] {
            let cli = Cli::try_parse_from(["bab", "setup", "--provider", prov_str]).unwrap();
            match cli.command {
                Some(Commands::Setup(args)) => assert_eq!(args.provider, expected_prov),
                other => panic!("unexpected command: {:?}", other),
            }
        }

        assert!(Cli::try_parse_from(["bab", "setup", "--role", "invalid"]).is_err());
        assert!(Cli::try_parse_from(["bab", "setup", "--provider", "invalid"]).is_err());
        assert!(Cli::try_parse_from(["bab", "setup", "--transport", "invalid"]).is_err());
    }

    #[test]
    fn parse_cloud_init_subcommand() {
        let def = Cli::try_parse_from(["bab", "cloud-init"]).unwrap();
        match def.command {
            Some(Commands::CloudInit(args)) => {
                assert_eq!(args.transport, TransportArg::Tailscale);
                assert_eq!(args.ssh_key, None);
                assert_eq!(args.ssh_pubkey, None);
                assert!(!args.generate_ssh_key);
                assert_eq!(args.hostname, "bab-node");
                assert_eq!(args.user, "deploy");
                assert_eq!(args.authkey, None);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        let custom = Cli::try_parse_from([
            "bab",
            "cloud-init",
            "--transport",
            "ssh",
            "--ssh-key",
            "/tmp/id_ed25519",
            "--ssh-pubkey",
            "ssh-ed25519 AAAA custom",
            "--generate-ssh-key",
            "--hostname",
            "edge-1",
            "--user",
            "admin",
            "--authkey",
            "tskey-test",
        ])
        .unwrap();
        match custom.command {
            Some(Commands::CloudInit(args)) => {
                assert_eq!(args.transport, TransportArg::Ssh);
                assert_eq!(args.ssh_key, Some(PathBuf::from("/tmp/id_ed25519")));
                assert_eq!(args.ssh_pubkey.as_deref(), Some("ssh-ed25519 AAAA custom"));
                assert!(args.generate_ssh_key);
                assert_eq!(args.hostname, "edge-1");
                assert_eq!(args.user, "admin");
                assert_eq!(args.authkey.as_deref(), Some("tskey-test"));
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn parse_settings_subcommand() {
        let cli = Cli::try_parse_from([
            "bab",
            "settings",
            "--show",
            "--tailscale-key",
            "ts-123",
            "--vultr-key",
            "vultr-456",
            "--upcloud-token",
            "up-789",
            "--linode-token",
            "lin-012",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Settings(args)) => {
                assert!(args.show);
                assert_eq!(args.tailscale_key.as_deref(), Some("ts-123"));
                assert_eq!(args.vultr_key.as_deref(), Some("vultr-456"));
                assert_eq!(args.upcloud_token.as_deref(), Some("up-789"));
                assert_eq!(args.linode_token.as_deref(), Some("lin-012"));
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, val: &std::ffi::OsStr) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, val);
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn write_mock_ssh_script(path: &Path, body: &str) -> Result<()> {
        std::fs::write(path, body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }

    #[test]
    fn wait_for_ssh_ready_retries_until_probe_succeeds() -> Result<()> {
        let _lock = ENV_LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap();
        let dir = tempfile::tempdir()?;
        let count_file = dir.path().join("count.txt");
        let cmd_file = dir.path().join("last_cmd.txt");
        let mock_ssh = dir.path().join("mock_ssh.sh");

        write_mock_ssh_script(
            &mock_ssh,
            &format!(
                "#!/bin/sh\ncount=$(cat '{count}' 2>/dev/null || echo 0)\ncount=$((count + 1))\necho \"$count\" > '{count}'\neval \"last=\\$$#\"\nprintf '%s' \"$last\" > '{cmd}'\nif [ \"$count\" -lt 3 ]; then\n  exit 255\nfi\nexit 0\n",
                count = count_file.display(),
                cmd = cmd_file.display(),
            ),
        )?;

        let _guard = EnvVarGuard::set("BAB_SSH_BIN", mock_ssh.as_os_str());
        let transport = SshTransport::from_env(TransportMode::SshKey(dir.path().join("id_ed25519")));

        wait_for_ssh_ready(
            &transport,
            "root",
            "203.0.113.10",
            Duration::from_secs(2),
            Duration::from_millis(10),
        )?;

        let attempts = std::fs::read_to_string(&count_file)?;
        assert_eq!(attempts.trim(), "3");
        let probed_cmd = std::fs::read_to_string(&cmd_file)?;
        assert_eq!(
            probed_cmd,
            "if [ -d /var/lib/cloud ]; then test -f /var/lib/cloud/instance/boot-finished; fi"
        );
        Ok(())
    }

    #[test]
    fn wait_for_ssh_ready_times_out_with_clear_error() -> Result<()> {
        let _lock = ENV_LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap();
        let dir = tempfile::tempdir()?;
        let mock_ssh = dir.path().join("mock_ssh_fail.sh");
        write_mock_ssh_script(&mock_ssh, "#!/bin/sh\nexit 1\n")?;

        let _guard = EnvVarGuard::set("BAB_SSH_BIN", mock_ssh.as_os_str());
        let transport = SshTransport::from_env(TransportMode::SshKey(dir.path().join("id_ed25519")));

        let err = wait_for_ssh_ready(
            &transport,
            "root",
            "203.0.113.10",
            Duration::from_millis(60),
            Duration::from_millis(15),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Timed out"), "unexpected error: {}", msg);
        assert!(
            msg.contains("waiting for SSH and cloud-init readiness"),
            "unexpected error: {}",
            msg
        );
        assert!(msg.contains("exit code 1"), "unexpected error: {}", msg);
        Ok(())
    }

    #[test]
    fn persist_setup_session_clears_stale_tailscale_key_in_ssh_mode() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let state_path = dir.path().join(".bab-local");
        let state = SessionState::new(&state_path);

        // Seed stale tailscale state first.
        persist_setup_session(&state, "100.64.0.10", "deploy", "ts-box", true, None)?;
        assert_eq!(state.transport_mode()?.as_deref(), Some("tailscale"));
        assert_eq!(state.ssh_key()?.as_deref(), Some("tailscale"));

        // Switch to SSH mode with --ssh-pubkey (key_path_opt == None): clears stale "tailscale".
        persist_setup_session(&state, "203.0.113.20", "ops", "ssh-box", false, None)?;
        assert_eq!(state.transport_mode()?.as_deref(), Some("ssh"));
        assert_eq!(state.ssh_key()?.as_deref(), Some(""));
        assert_eq!(state.vps_ip()?.as_deref(), Some("203.0.113.20"));

        // Explicit key path sets SSH_KEY.
        let key_path = PathBuf::from("/tmp/custom_ed25519");
        persist_setup_session(
            &state,
            "203.0.113.20",
            "ops",
            "ssh-box",
            false,
            Some(&key_path),
        )?;
        assert_eq!(state.ssh_key()?.as_deref(), Some("/tmp/custom_ed25519"));

        // Subsequent SSH run with key_path_opt == None keeps non-"tailscale" SSH_KEY.
        persist_setup_session(&state, "203.0.113.20", "ops", "ssh-box", false, None)?;
        assert_eq!(state.ssh_key()?.as_deref(), Some("/tmp/custom_ed25519"));
        Ok(())
    }
}
