use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use bab::config::{
    default_config_dir, generate_random_password, LogStore, SessionData, SessionState, Settings,
    MAX_LOG_FILE_BYTES, SUDO_PASSWORD_LEN,
};
use bab::dns::{build_cloudflare_dns_stub_plan, CloudflareDnsConfig};
use bab::providers::linode::LinodeProvider;
use bab::providers::upcloud::UpCloudProvider;
use bab::providers::vultr::VultrProvider;
use bab::providers::{
    clear_destroyed_session_if_matches, default_images_for, default_plans_for,
    default_regions_for, destroy_provider_instance, provision_full_flow, query_all_providers,
    validate_instance_id, ProvisionConfig, ProviderInstance, ProviderKind, ProviderQueryStatus,
    VpsProvider,
};
use bab::roles::ServerRole;
use bab::setup::{GithubDeployConfig, SetupConfig, SetupRunner};
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
    /// List curated or live regions, plans, and OS images for a cloud provider
    Catalog(CatalogArgs),
    /// Provision and configure a VPS node
    Setup(SetupArgs),
    /// Preview/record a Cloudflare DNS A-record stub plan
    Dns(DnsArgs),
    /// Deploy or update a GitHub repository on the VPS node
    Deploy(DeployArgs),
    /// List Tailscale devices in the tailnet
    Devices,
    /// Generate a cloud-init bootstrap script
    CloudInit(CloudInitArgs),
    /// View or update saved encrypted API key settings
    Settings(SettingsArgs),
    /// Check remote status of the configured VPS node
    Status,
    /// List running instances across configured cloud providers
    #[command(visible_aliases = ["ps", "list"])]
    Instances(InstancesArgs),
    /// Destroy a cloud VPS instance by ID
    #[command(visible_aliases = ["rm", "delete"])]
    Destroy(DestroyArgs),
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
struct CatalogArgs {
    /// Cloud provider (vultr, upcloud, linode)
    #[arg(long, value_parser = parse_provider)]
    provider: ProviderKind,
    /// Query live options from the provider API instead of curated presets
    #[arg(long)]
    live: bool,
}

#[derive(Debug, Args)]
struct DnsArgs {
    /// Cloudflare DNS zone (e.g. example.com)
    #[arg(long, value_name = "ZONE")]
    zone: String,
    /// DNS record name (e.g. @, app, or app.example.com)
    #[arg(long, value_name = "NAME")]
    record: String,
    /// Target IP address or hostname (defaults to saved PUBLIC_IP / TAILSCALE_IP / VPS_IP)
    #[arg(long, value_name = "IP")]
    ip: Option<String>,
    /// Enable Cloudflare proxy (orange cloud)
    #[arg(long)]
    proxied: bool,
}

#[derive(Debug, Args)]
struct DeployArgs {
    /// GitHub repository (owner/repo, https://..., or git@...)
    #[arg(long, value_name = "REPO")]
    repo: String,
    /// Git branch to deploy
    #[arg(long, default_value = "main", value_name = "BRANCH")]
    branch: String,
    /// Remote deploy path (defaults to /home/<user>/apps/<repo>)
    #[arg(long, value_name = "PATH")]
    path: Option<String>,
    /// Post-clone deploy command (defaults to docker compose up -d --build when compose file exists)
    #[arg(long, value_name = "CMD")]
    cmd: Option<String>,
    /// Target IP address or MagicDNS hostname (defaults to saved VPS_IP)
    #[arg(long, value_name = "TARGET")]
    ip: Option<String>,
    /// Transport mode (tailscale or ssh; defaults to saved session mode or tailscale)
    #[arg(long, value_enum)]
    transport: Option<TransportArg>,
    /// Path to SSH private key for Standard SSH mode
    #[arg(long, value_name = "PATH")]
    ssh_key: Option<PathBuf>,
    /// Initial SSH login user (defaults to saved USERNAME or deploy)
    #[arg(long, value_name = "USER")]
    ssh_user: Option<String>,
    /// Target deploy user on the remote host (defaults to saved USERNAME or deploy)
    #[arg(long, value_name = "USER")]
    user: Option<String>,
    /// Preview generated deploy script without executing remote commands
    #[arg(long)]
    dry_run: bool,
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
    /// Grant passwordless sudo (NOPASSWD:ALL) to the created user (overrides saved state)
    #[arg(long)]
    sudo_nopasswd: bool,
    /// Require a password for sudo instead of NOPASSWD:ALL (overrides saved state)
    #[arg(long, conflicts_with = "sudo_nopasswd")]
    no_sudo_nopasswd: bool,
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
    /// Cloudflare DNS zone for A-record stub (e.g. example.com)
    #[arg(long, value_name = "ZONE")]
    cf_zone: Option<String>,
    /// Cloudflare DNS record name (e.g. @ or app)
    #[arg(long, value_name = "NAME")]
    cf_record: Option<String>,
    /// Enable Cloudflare proxy (orange cloud) for the DNS record
    #[arg(long)]
    cf_proxied: bool,
    /// Enable Cloudflare DNS stub plan using saved session settings
    #[arg(long, conflicts_with = "no_cf_dns")]
    cf_dns: bool,
    /// Skip Cloudflare DNS stub plan even if enabled in saved session state
    #[arg(long)]
    no_cf_dns: bool,
    /// Enable GitHub repository deployment using saved session settings
    #[arg(long, conflicts_with = "no_github_deploy")]
    github_deploy: bool,
    /// Skip GitHub repository deployment even if enabled in saved session state
    #[arg(long)]
    no_github_deploy: bool,
    /// GitHub repository to deploy (owner/repo, https://..., or git@...)
    #[arg(long, value_name = "REPO")]
    github_repo: Option<String>,
    /// GitHub branch to deploy (defaults to main)
    #[arg(long, value_name = "BRANCH")]
    github_branch: Option<String>,
    /// Remote directory for GitHub deployment
    #[arg(long, value_name = "PATH")]
    github_path: Option<String>,
    /// Custom post-clone deploy command for GitHub deployment
    #[arg(long, value_name = "CMD")]
    github_cmd: Option<String>,
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
    /// Set CLOUDFLARE_API_TOKEN
    #[arg(long)]
    cloudflare_token: Option<String>,
    /// Set GITHUB_TOKEN
    #[arg(long)]
    github_token: Option<String>,
}

#[derive(Debug, Args)]
struct InstancesArgs {
    /// Cloud provider filter (vultr, upcloud, linode)
    #[arg(long, value_parser = parse_provider)]
    provider: Option<ProviderKind>,
    /// Include status details for all providers (including unconfigured)
    #[arg(long)]
    all: bool,
    /// Destroy the specified instance ID directly
    #[arg(long, value_name = "ID")]
    destroy: Option<String>,
    /// Skip interactive confirmation when --destroy is used
    #[arg(short = 'y', long)]
    yes: bool,
}

#[derive(Debug, Args)]
struct DestroyArgs {
    /// Cloud instance ID to destroy
    #[arg(long, value_name = "ID")]
    id: String,
    /// Cloud provider (vultr, upcloud, linode); optional if ID uniquely matches across configured providers
    #[arg(long, value_parser = parse_provider)]
    provider: Option<ProviderKind>,
    /// Skip interactive confirmation
    #[arg(short = 'y', long)]
    yes: bool,
    /// Validate ID and print destroy plan without API calls or state modification
    #[arg(long)]
    dry_run: bool,
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
        Some(Commands::Catalog(args)) => cmd_catalog(args),
        Some(Commands::Setup(args)) => cmd_setup(args),
        Some(Commands::Dns(args)) => cmd_dns(args),
        Some(Commands::Deploy(args)) => cmd_deploy(args),
        Some(Commands::Devices) => cmd_devices(),
        Some(Commands::CloudInit(args)) => cmd_cloud_init(args),
        Some(Commands::Settings(args)) => cmd_settings(args),
        Some(Commands::Status) => cmd_status(),
        Some(Commands::Instances(args)) => cmd_instances(args),
        Some(Commands::Destroy(args)) => cmd_destroy(args),
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

fn cmd_catalog(args: CatalogArgs) -> Result<()> {
    if matches!(
        args.provider,
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit
    ) {
        return Err(anyhow!(
            "{} does not have a region, plan, or image catalog",
            args.provider.label()
        ));
    }

    let (regions, plans, images, source) = if args.live {
        let settings = Settings::load_default()?;
        let provider = build_cloud_provider(args.provider, &settings)?;
        (
            provider.list_regions()?,
            provider.list_plans()?,
            provider.list_images()?,
            "live API",
        )
    } else {
        (
            default_regions_for(args.provider),
            default_plans_for(args.provider),
            default_images_for(args.provider),
            "curated presets",
        )
    };

    println!("Provider: {} ({})", args.provider.label(), source);
    println!("Regions:");
    for r in &regions {
        println!("  {:<16} {} ({})", r.id, r.name, r.country);
    }
    println!("Plans:");
    for p in &plans {
        println!("  {:<16} {}", p.id, p.summary);
    }
    println!("Images:");
    for i in &images {
        if i.vendor.is_empty() {
            println!("  {:<38} {}", i.id, i.name);
        } else {
            println!("  {:<38} {} ({})", i.id, i.name, i.vendor);
        }
    }
    Ok(())
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

fn resolve_option<F>(
    explicit: Option<String>,
    saved: Option<String>,
    list_ids: F,
    catalog_fallback: Option<String>,
    flag: &str,
    provider: ProviderKind,
) -> Result<String>
where
    F: FnOnce() -> Result<Vec<String>>,
{
    if let Some(val) = explicit
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return Ok(val);
    }
    if let Some(val) = saved
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return Ok(val);
    }
    match list_ids() {
        Ok(ids) => {
            if let Some(first) = ids.into_iter().find(|s| !s.trim().is_empty()) {
                return Ok(first);
            }
            if let Some(val) = catalog_fallback.filter(|s| !s.trim().is_empty()) {
                return Ok(val);
            }
            Err(anyhow!(
                "{} is required for {} (no default options returned by provider)",
                flag,
                provider.label()
            ))
        }
        Err(err) => {
            if let Some(val) = catalog_fallback.filter(|s| !s.trim().is_empty()) {
                eprintln!(
                    "Note: querying {} options for {} failed ({}); falling back to curated default '{}'.",
                    provider.label(),
                    flag,
                    err,
                    val
                );
                return Ok(val);
            }
            Err(err).with_context(|| {
                format!(
                    "{} was not provided and querying {} options failed",
                    flag,
                    provider.label()
                )
            })
        }
    }
}

fn resolve_dry_run_option(
    explicit: Option<&str>,
    saved: Option<&str>,
    catalog_default: Option<String>,
) -> Option<String> {
    explicit
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| {
            saved
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
        .or_else(|| catalog_default.filter(|s| !s.trim().is_empty()))
}

#[cfg(test)]
fn wait_for_ssh_ready(
    transport: &SshTransport,
    ssh_user: &str,
    host: &str,
    timeout: Duration,
    interval: Duration,
) -> Result<()> {
    wait_for_ssh_ready_with_fallback(transport, ssh_user, None, host, timeout, interval).map(|_| ())
}

fn wait_for_ssh_ready_with_fallback(
    transport: &SshTransport,
    ssh_user: &str,
    fallback_user: Option<&str>,
    host: &str,
    timeout: Duration,
    interval: Duration,
) -> Result<String> {
    let deadline = std::time::Instant::now() + timeout;
    let primary_probe_cmd =
        "if [ -d /var/lib/cloud ]; then test -f /var/lib/cloud/instance/boot-finished; fi";
    let fallback_probe_cmd =
        "sudo -n true && (test ! -d /var/lib/cloud || test -f /var/lib/cloud/instance/boot-finished)";
    let fallback = fallback_user
        .map(str::trim)
        .filter(|u| !u.is_empty() && *u != ssh_user);
    let mut last_status;

    loop {
        let primary_status = match transport.exec(ssh_user, host, primary_probe_cmd) {
            Ok(out) if out.success() => return Ok(ssh_user.to_string()),
            Ok(out) => format!("exit code {}", out.status_code),
            Err(err) => err.to_string(),
        };
        last_status = primary_status.clone();

        if let Some(fb_user) = fallback {
            match transport.exec(fb_user, host, fallback_probe_cmd) {
                Ok(out) if out.success() => return Ok(fb_user.to_string()),
                Ok(out) => {
                    last_status = format!(
                        "{}: {}; {}: exit code {}",
                        ssh_user, primary_status, fb_user, out.status_code
                    );
                }
                Err(err) => {
                    last_status = format!("{}: {}; {}: {}", ssh_user, primary_status, fb_user, err);
                }
            }
        }

        let now = std::time::Instant::now();
        if now >= deadline {
            let target_desc = match fallback {
                Some(fb_user) => format!("{}@{} (or {}@{})", ssh_user, host, fb_user, host),
                None => format!("{}@{}", ssh_user, host),
            };
            return Err(anyhow!(
                "Timed out after {:?} waiting for SSH and cloud-init readiness on {} (last status: {})",
                timeout,
                target_desc,
                last_status
            ));
        }

        let sleep_for = interval.min(deadline.saturating_duration_since(now));
        if !sleep_for.is_zero() {
            std::thread::sleep(sleep_for);
        }
    }
}

fn saved_catalog_for_provider(
    session: &SessionState,
    provider: ProviderKind,
) -> Result<(Option<String>, Option<String>, Option<String>)> {
    let same_provider = session
        .vps_provider()?
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<ProviderKind>().ok())
        == Some(provider);
    if !same_provider {
        return Ok((None, None, None));
    }
    Ok((
        session.vps_region()?.filter(|s| !s.trim().is_empty()),
        session.vps_plan()?.filter(|s| !s.trim().is_empty()),
        session.vps_image()?.filter(|s| !s.trim().is_empty()),
    ))
}

fn is_tailscale_host(target: &str) -> bool {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return false;
    }
    match trimmed.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let octets = v4.octets();
            octets[0] == 100 && (octets[1] & 0b1100_0000) == 64
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let segs = v6.segments();
            segs[0] == 0xfd7a && segs[1] == 0x115c && segs[2] == 0xa1e0
        }
        Err(_) => true,
    }
}

fn resolve_non_provisioned_ips(
    session: &SessionState,
    target: &str,
    tailscale_mode: bool,
) -> Result<(Option<String>, Option<String>)> {
    if !tailscale_mode {
        return Ok((Some(target.to_string()), None));
    }
    if is_tailscale_host(target) {
        let same_target = session.vps_ip()?.as_deref() == Some(target);
        let pub_ip = if same_target {
            session
                .public_ip()?
                .filter(|s| !s.trim().is_empty() && !is_tailscale_host(s))
        } else {
            None
        };
        Ok((pub_ip, Some(target.to_string())))
    } else {
        Ok((Some(target.to_string()), None))
    }
}

struct SetupSessionUpdate<'a> {
    provider: ProviderKind,
    target: &'a str,
    username: &'a str,
    hostname: &'a str,
    tailscale_mode: bool,
    sudo_nopasswd: bool,
    sudo_password: Option<&'a str>,
    key_path: Option<&'a Path>,
    catalog: (Option<&'a str>, Option<&'a str>, Option<&'a str>),
    provisioned_ips: Option<(Option<&'a str>, Option<&'a str>)>,
}

fn persist_setup_session(session: &SessionState, update: &SetupSessionUpdate<'_>) -> Result<()> {
    let mut data = session.load_session().unwrap_or_else(|_| SessionData::default());
    let prev_vps_ip = data.vps_ip.clone();

    data.vps_provider = Some(update.provider.to_string());
    data.vps_ip = Some(update.target.to_string());
    data.username = Some(update.username.to_string());
    data.tailscale_hostname = Some(update.hostname.to_string());
    data.sudo_nopasswd = Some(if update.sudo_nopasswd { "true" } else { "false" }.to_string());
    if let Some(pw) = update
        .sudo_password
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        data.sudo_password = Some(pw.to_string());
    }
    data.vps_region = update.catalog.0.map(str::to_string);
    data.vps_plan = update.catalog.1.map(str::to_string);
    data.vps_image = update.catalog.2.map(str::to_string);

    if let Some((pub_ip, ts_ip)) = update.provisioned_ips {
        data.public_ip = pub_ip.map(str::to_string);
        data.tailscale_ip = ts_ip.map(str::to_string);
    } else if update.tailscale_mode {
        if is_tailscale_host(update.target) {
            data.tailscale_ip = Some(update.target.to_string());
            let same_target = prev_vps_ip.as_deref() == Some(update.target);
            let existing_pub_valid = data
                .public_ip
                .as_deref()
                .map(str::trim)
                .is_some_and(|ip| !ip.is_empty() && !is_tailscale_host(ip));
            if !(same_target && existing_pub_valid) {
                data.public_ip = None;
            }
        } else {
            data.public_ip = Some(update.target.to_string());
            data.tailscale_ip = None;
        }
    } else {
        data.public_ip = Some(update.target.to_string());
        data.tailscale_ip = None;
    }

    if update.tailscale_mode {
        data.transport_mode = Some("tailscale".to_string());
        data.ssh_key = Some("tailscale".to_string());
    } else {
        data.transport_mode = Some("ssh".to_string());
        match update.key_path.filter(|p| !p.as_os_str().is_empty()) {
            Some(path) => {
                data.ssh_key = Some(path.to_string_lossy().into_owned());
            }
            None => {
                if data
                    .ssh_key
                    .as_deref()
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("tailscale"))
                {
                    data.ssh_key = Some(String::new());
                }
            }
        }
    }

    session.save_session(&data)
}

fn persist_github_session(session: &SessionState, gh: &GithubDeployConfig) -> Result<()> {
    session.set_github_repo(&gh.repo)?;
    session.set_github_branch(&gh.branch)?;
    session.set_github_deploy_path(gh.deploy_path.as_deref().unwrap_or(""))?;
    session.set_github_deploy_cmd(gh.deploy_cmd.as_deref().unwrap_or(""))?;
    session.set_github_enabled("true")?;
    Ok(())
}

fn resolve_github_deploy_config(
    args: &SetupArgs,
    settings: &Settings,
    session: &SessionState,
) -> Result<Option<GithubDeployConfig>> {
    if args.no_github_deploy {
        return Ok(None);
    }

    let explicit_repo = args
        .github_repo
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let explicit_branch = args
        .github_branch
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let explicit_path = args
        .github_path
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let explicit_cmd = args
        .github_cmd
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);

    let resolve_branch = |explicit: Option<String>| -> Result<String> {
        if let Some(b) = explicit {
            return Ok(b);
        }
        Ok(session
            .github_branch()?
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("main")
            .to_string())
    };

    if let Some(repo) = explicit_repo {
        let branch = resolve_branch(explicit_branch)?;
        let github_token = settings
            .github_token()?
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        return Ok(Some(GithubDeployConfig {
            repo,
            branch,
            deploy_path: explicit_path,
            deploy_cmd: explicit_cmd,
            github_token,
            username: args.user.clone(),
        }));
    }

    if args.github_deploy || parse_truthy(session.github_enabled()?.as_deref()) {
        let saved_repo = session
            .github_repo()?
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);
        match saved_repo {
            Some(repo) => {
                let branch = resolve_branch(explicit_branch)?;
                let deploy_path = match explicit_path {
                    Some(p) => Some(p),
                    None => session
                        .github_deploy_path()?
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                };
                let deploy_cmd = match explicit_cmd {
                    Some(c) => Some(c),
                    None => session
                        .github_deploy_cmd()?
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                };
                let github_token = settings
                    .github_token()?
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                Ok(Some(GithubDeployConfig {
                    repo,
                    branch,
                    deploy_path,
                    deploy_cmd,
                    github_token,
                    username: args.user.clone(),
                }))
            }
            None if args.github_deploy => Err(anyhow!(
                "--github-deploy requires GITHUB_REPO in session state (pass --github-repo <REPO> or configure GitHub Repo Deployment first)"
            )),
            None => {
                eprintln!(
                    "Note: GITHUB_ENABLED is enabled in session state, but GITHUB_REPO is empty; skipping GitHub repository deployment."
                );
                Ok(None)
            }
        }
    } else {
        Ok(None)
    }
}

fn parse_truthy(val: Option<&str>) -> bool {
    val.is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        )
    })
}

fn parse_sudo_nopasswd(val: Option<&str>) -> bool {
    !matches!(
        val.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("false" | "0" | "no" | "off")
    )
}

fn resolve_sudo_nopasswd(
    sudo_nopasswd: bool,
    no_sudo_nopasswd: bool,
    session: &SessionData,
) -> bool {
    if no_sudo_nopasswd {
        false
    } else if sudo_nopasswd {
        true
    } else {
        parse_sudo_nopasswd(session.sudo_nopasswd.as_deref())
    }
}

struct PlannedCloudflareDns {
    zone: String,
    record_name: String,
    target_pref: Option<String>,
    proxied: bool,
}

fn persist_cf_session(session: &SessionState, dns: &CloudflareDnsConfig) -> Result<()> {
    session.set_cf_zone(&dns.zone)?;
    session.set_cf_record(&dns.record_name)?;
    session.set_cf_target(&dns.target_ip)?;
    session.set_cf_proxied(if dns.proxied { "true" } else { "false" })?;
    session.set_cf_enabled("true")?;
    Ok(())
}

fn resolve_cli_log_store(settings: &Settings) -> LogStore {
    if let Ok(val) = std::env::var("BAB_LOG_FILE") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return LogStore::new(PathBuf::from(trimmed));
        }
    }
    if let Some(parent) = settings
        .path()
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        return LogStore::new(parent.join("bab.log"));
    }
    LogStore::load_default().unwrap_or_else(|_| LogStore::new("bab.log"))
}

fn append_cli_log(log: &LogStore, lines: &[String]) {
    let _ = log.append_timestamped_lines(lines);
}

fn cmd_setup(args: SetupArgs) -> Result<()> {
    let settings = Settings::load_default()?;
    let session = SessionState::load_default()?;
    let session_data = session.load_session().unwrap_or_else(|_| SessionData::default());
    let sudo_nopasswd =
        resolve_sudo_nopasswd(args.sudo_nopasswd, args.no_sudo_nopasswd, &session_data);
    let sudo_password = session_data
        .sudo_password
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| generate_random_password(SUDO_PASSWORD_LEN));
    let log = resolve_cli_log_store(&settings);
    let tags = parse_tags(args.tags.as_deref());
    let tailscale_mode = args.transport == TransportArg::Tailscale;

    let cf_zone_clean = args
        .cf_zone
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let cf_record_clean = args
        .cf_record
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    if cf_zone_clean.is_some() != cf_record_clean.is_some() {
        return Err(anyhow!(
            "Both --cf-zone and --cf-record must be provided together"
        ));
    }

    let planned_cf_dns = if args.no_cf_dns {
        None
    } else if let (Some(zone), Some(record_name)) = (cf_zone_clean, cf_record_clean) {
        Some(PlannedCloudflareDns {
            zone,
            record_name,
            target_pref: None,
            proxied: args.cf_proxied,
        })
    } else if args.cf_dns || parse_truthy(session.cf_enabled()?.as_deref()) {
        let saved_zone = session
            .cf_zone()?
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from);
        match saved_zone {
            Some(zone) => {
                let record_name = session
                    .cf_record()?
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("@")
                    .to_string();
                let target_pref = session
                    .cf_target()?
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from);
                let proxied = args.cf_proxied || parse_truthy(session.cf_proxied()?.as_deref());
                Some(PlannedCloudflareDns {
                    zone,
                    record_name,
                    target_pref,
                    proxied,
                })
            }
            None if args.cf_dns => {
                return Err(anyhow!(
                    "--cf-dns requires CF_ZONE in session state (pass --cf-zone and --cf-record or run `bab dns` first)"
                ));
            }
            None => {
                eprintln!(
                    "Note: CF_ENABLED is enabled in session state, but CF_ZONE is empty; skipping Cloudflare DNS stub plan."
                );
                None
            }
        }
    } else {
        None
    };

    if let Some(ref planned) = planned_cf_dns {
        build_cloudflare_dns_stub_plan(
            &CloudflareDnsConfig {
                zone: planned.zone.clone(),
                record_name: planned.record_name.clone(),
                target_ip: "203.0.113.10".to_string(),
                proxied: planned.proxied,
            },
            false,
        )?;
    }

    let github_deploy = resolve_github_deploy_config(&args, &settings, &session)?;

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
    let mut was_provisioned = false;
    let resolved_region: Option<String>;
    let resolved_plan: Option<String>;
    let resolved_image: Option<String>;
    let mut resolved_public_ip: Option<String> = None;
    let mut resolved_tailscale_ip: Option<String> = None;
    let mut resolved_instance_id: Option<String> = session_data
        .vps_instance_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);

    let target = match args.provider {
        ProviderKind::Vultr | ProviderKind::UpCloud | ProviderKind::Linode => {
            let (saved_region, saved_plan, saved_image) =
                saved_catalog_for_provider(&session, args.provider)?;
            let cat_region = default_regions_for(args.provider).into_iter().next().map(|r| r.id);
            let cat_plan = default_plans_for(args.provider).into_iter().next().map(|p| p.id);
            let cat_image = default_images_for(args.provider).into_iter().next().map(|i| i.id);

            if args.dry_run {
                let dry_region = resolve_dry_run_option(
                    args.region.as_deref(),
                    saved_region.as_deref(),
                    cat_region,
                );
                let dry_plan = resolve_dry_run_option(
                    args.plan.as_deref(),
                    saved_plan.as_deref(),
                    cat_plan,
                );
                let dry_image = resolve_dry_run_option(
                    args.image.as_deref(),
                    saved_image.as_deref(),
                    cat_image,
                );
                resolved_region = dry_region.clone();
                resolved_plan = dry_plan.clone();
                resolved_image = dry_image.clone();

                let target_ip = if let Some(ip) = args.ip.clone().filter(|s| !s.is_empty()) {
                    ip
                } else if tailscale_mode {
                    "100.64.0.1".to_string()
                } else {
                    "203.0.113.10".to_string()
                };
                (resolved_public_ip, resolved_tailscale_ip) =
                    resolve_non_provisioned_ips(&session, &target_ip, tailscale_mode)?;

                eprintln!(
                    "Note: --dry-run for {} provider (region={}, plan={}, image={}); using target {}.",
                    args.provider.label(),
                    dry_region.as_deref().unwrap_or("N/A"),
                    dry_plan.as_deref().unwrap_or("N/A"),
                    dry_image.as_deref().unwrap_or("N/A"),
                    target_ip
                );
                target_ip
            } else if let Some(ip) = args.ip.clone().filter(|s| !s.is_empty()) {
                resolved_region = resolve_dry_run_option(
                    args.region.as_deref(),
                    saved_region.as_deref(),
                    cat_region,
                );
                resolved_plan = resolve_dry_run_option(
                    args.plan.as_deref(),
                    saved_plan.as_deref(),
                    cat_plan,
                );
                resolved_image = resolve_dry_run_option(
                    args.image.as_deref(),
                    saved_image.as_deref(),
                    cat_image,
                );
                (resolved_public_ip, resolved_tailscale_ip) =
                    resolve_non_provisioned_ips(&session, &ip, tailscale_mode)?;
                ip
            } else {
                let ts_client = if tailscale_mode {
                    let ts_key = require_tailscale_key(&settings)?;
                    Some(TailscaleClient::new(ts_key)?)
                } else {
                    None
                };
                let provider = build_cloud_provider(args.provider, &settings)?;

                let region = resolve_option(
                    args.region.clone(),
                    saved_region,
                    || {
                        Ok(provider
                            .list_regions()?
                            .into_iter()
                            .map(|r| r.id)
                            .collect())
                    },
                    cat_region,
                    "--region",
                    args.provider,
                )?;
                let plan = resolve_option(
                    args.plan.clone(),
                    saved_plan,
                    || {
                        Ok(provider
                            .list_plans()?
                            .into_iter()
                            .map(|p| p.id)
                            .collect())
                    },
                    cat_plan,
                    "--plan",
                    args.provider,
                )?;
                let image_id = resolve_option(
                    args.image.clone(),
                    saved_image,
                    || {
                        Ok(provider
                            .list_images()?
                            .into_iter()
                            .map(|i| i.id)
                            .collect())
                    },
                    cat_image,
                    "--image",
                    args.provider,
                )?;

                resolved_region = Some(region.clone());
                resolved_plan = Some(plan.clone());
                resolved_image = Some(image_id.clone());

                if let Some(ref ts) = ts_client {
                    if let Ok(removed) = ts.delete_matching_offline_devices(&args.hostname) {
                        if !removed.is_empty() {
                            let msg = format!(
                                "[TAILSCALE] Pruned stale offline device(s) matching '{}': {}",
                                args.hostname,
                                removed.join(", ")
                            );
                            println!("{}", msg);
                            append_cli_log(&log, &[msg]);
                        }
                    }
                }

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
                    sudo_password: Some(sudo_password.clone()),
                };

                let result = provision_full_flow(
                    provider.as_ref(),
                    ts_client.as_ref(),
                    &prov_cfg,
                    Some(&session),
                )?;
                was_provisioned = true;
                if !result.instance_id.trim().is_empty() {
                    resolved_instance_id = Some(result.instance_id.clone());
                }
                if !result.public_ip.is_empty() {
                    resolved_public_ip = Some(result.public_ip.clone());
                }
                if !result.tailscale_ip.is_empty() {
                    resolved_tailscale_ip = Some(result.tailscale_ip.clone());
                }
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
            let (saved_region, saved_plan, saved_image) =
                saved_catalog_for_provider(&session, args.provider)?;
            resolved_region = args
                .region
                .clone()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or(saved_region);
            resolved_plan = args
                .plan
                .clone()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or(saved_plan);
            resolved_image = args
                .image
                .clone()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .or(saved_image);

            let ip = if let Some(ip) = args.ip.clone().filter(|s| !s.is_empty()) {
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
            };

            (resolved_public_ip, resolved_tailscale_ip) =
                resolve_non_provisioned_ips(&session, &ip, tailscale_mode)?;
            ip
        }
        ProviderKind::ManualCloudInit => unreachable!(),
    };

    if !is_valid_target(&target) {
        return Err(anyhow!("Invalid target IP or hostname: '{}'", target));
    }

    append_cli_log(
        &log,
        &[format!(
            "[BUILD] CLI setup start (provider={}, target={}, dry_run={})",
            args.provider, target, args.dry_run
        )],
    );
    if let Some(ref gh) = github_deploy {
        append_cli_log(
            &log,
            &[format!(
                "[GITHUB] Configured GitHub deploy: {} (branch: {})",
                gh.repo, gh.branch
            )],
        );
    }

    let ssh_pubkey_for_setup = resolved_ssh.as_ref().map(|s| s.pubkey.clone());
    let ssh_key_for_transport = resolved_ssh
        .as_ref()
        .and_then(|s| s.key_path.clone())
        .unwrap_or_default();

    let mut cfg = SetupConfig {
        host: target.clone(),
        ssh_user: args.ssh_user,
        new_username: args.user.clone(),
        hostname: args.hostname.clone(),
        role: args.role,
        provider_name: args.provider.to_string(),
        tailscale_mode,
        sudo_nopasswd,
        sudo_password: Some(sudo_password.clone()),
        ssh_pubkey: ssh_pubkey_for_setup,
        dry_run: args.dry_run,
        github_deploy: github_deploy.clone(),
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
        cfg.ssh_user = wait_for_ssh_ready_with_fallback(
            &transport,
            &cfg.ssh_user,
            Some(&cfg.new_username),
            &cfg.host,
            Duration::from_secs(180),
            Duration::from_secs(5),
        )?;
        println!("Connected as {}@{}.", cfg.ssh_user, cfg.host);
    } else if was_provisioned && tailscale_mode {
        println!(
            "Waiting for Tailscale SSH readiness on {}@{} (fallback: {})...",
            cfg.ssh_user, cfg.host, cfg.new_username
        );
        cfg.ssh_user = wait_for_ssh_ready_with_fallback(
            &transport,
            &cfg.ssh_user,
            Some(&cfg.new_username),
            &cfg.host,
            Duration::from_secs(60),
            Duration::from_secs(3),
        )?;
        println!("Connected as {}@{}.", cfg.ssh_user, cfg.host);
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
        let header = format!("[{}] {}", tag, report.step.title());
        println!("{}", header);
        let mut log_lines = vec![header];
        if !report.output.trim().is_empty() {
            let trimmed_out = report.output.trim_end();
            println!("{}", trimmed_out);
            for line in trimmed_out.lines() {
                if !line.trim().is_empty() {
                    log_lines.push(line.to_string());
                }
            }
        }
        append_cli_log(&log, &log_lines);
    })?;

    let cf_dns_cfg = if let Some(planned) = planned_cf_dns {
        let fallback_target = || {
            resolved_public_ip
                .clone()
                .or_else(|| resolved_tailscale_ip.clone())
                .unwrap_or_else(|| target.clone())
        };
        let dns_target = match planned.target_pref {
            Some(ref pref) if pref.eq_ignore_ascii_case("tailscale") => resolved_tailscale_ip
                .clone()
                .or_else(|| resolved_public_ip.clone())
                .unwrap_or_else(|| target.clone()),
            Some(ref pref) if pref.eq_ignore_ascii_case("public") => fallback_target(),
            Some(explicit_saved) => explicit_saved,
            None => fallback_target(),
        };
        let has_cf_token = settings
            .cloudflare_api_token()?
            .is_some_and(|t| !t.trim().is_empty());
        let dns_cfg = CloudflareDnsConfig {
            zone: planned.zone,
            record_name: planned.record_name,
            target_ip: dns_target,
            proxied: planned.proxied,
        };
        let stub_plan = build_cloudflare_dns_stub_plan(&dns_cfg, has_cf_token)?;
        println!("{}", stub_plan);
        let dns_lines: Vec<String> = stub_plan
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| format!("[DNS] {}", l))
            .collect();
        append_cli_log(&log, &dns_lines);
        Some(dns_cfg)
    } else {
        None
    };

    if !args.dry_run {
        let key_path_opt = resolved_ssh.as_ref().and_then(|s| s.key_path.as_deref());
        let provisioned_ips = if was_provisioned {
            Some((
                resolved_public_ip.as_deref(),
                resolved_tailscale_ip.as_deref(),
            ))
        } else {
            None
        };
        persist_setup_session(
            &session,
            &SetupSessionUpdate {
                provider: args.provider,
                target: &target,
                username: &args.user,
                hostname: &args.hostname,
                tailscale_mode,
                sudo_nopasswd,
                sudo_password: Some(&sudo_password),
                key_path: key_path_opt,
                catalog: (
                    resolved_region.as_deref(),
                    resolved_plan.as_deref(),
                    resolved_image.as_deref(),
                ),
                provisioned_ips,
            },
        )?;
        let _ = settings.record_instance_password(
            resolved_instance_id.as_deref(),
            Some(&args.hostname),
            resolved_public_ip.as_deref(),
            &sudo_password,
        );
        if let Some(ref gh) = github_deploy {
            persist_github_session(&session, gh)?;
        }
        if let Some(ref dns) = cf_dns_cfg {
            persist_cf_session(&session, dns)?;
        }
    }

    let max_log_mb = MAX_LOG_FILE_BYTES / (1024 * 1024);
    let mut summary_lines = vec![
        "=== Final Box Information ===".to_string(),
        format!(
            "Public IP:             {}",
            resolved_public_ip.as_deref().unwrap_or("(none)")
        ),
        format!(
            "Tailscale IP:          {}",
            resolved_tailscale_ip.as_deref().unwrap_or("(none)")
        ),
        format!("Active Target IP:      {}", target),
        format!(
            "Provider:              {} (region: {}, plan: {}, image: {})",
            args.provider.label(),
            resolved_region.as_deref().unwrap_or("N/A"),
            resolved_plan.as_deref().unwrap_or("N/A"),
            resolved_image.as_deref().unwrap_or("N/A")
        ),
        format!("Role:                  {} ({})", args.role.label(), args.role),
        format!(
            "Transport Mode:        {}",
            if tailscale_mode {
                "Tailscale SSH"
            } else {
                "Standard SSH"
            }
        ),
        format!(
            "Sudo User:             {} (passwordless: {})",
            args.user,
            if sudo_nopasswd {
                "ON (NOPASSWD:ALL)"
            } else {
                "OFF (password required)"
            }
        ),
        format!("Sudo Password:         {}", sudo_password),
    ];
    if let Some(ref dns) = cf_dns_cfg {
        summary_lines.push(format!(
            "Cloudflare DNS:        {} -> {} (zone: {}, proxied: {})",
            dns.record_name, dns.target_ip, dns.zone, dns.proxied
        ));
    }
    if let Some(ref gh) = github_deploy {
        summary_lines.push(format!(
            "GitHub Repo:           {} (branch: {}, path: {})",
            gh.repo,
            gh.branch,
            gh.deploy_path
                .as_deref()
                .unwrap_or("(default /home/<user>/apps/<repo>)")
        ));
    }
    summary_lines.push(format!(
        "Encrypted Credentials: {} (0600, ChaCha20-Poly1305)",
        settings.path().display()
    ));
    summary_lines.push(format!(
        "Master Key:            {} (0600)",
        settings.key_file_path().display()
    ));
    summary_lines.push(format!(
        "Log File:              {} (0600, max {} MB)",
        log.path().display(),
        max_log_mb
    ));

    println!();
    for line in &summary_lines {
        println!("{}", line);
    }
    append_cli_log(&log, &summary_lines);

    Ok(())
}

fn cmd_dns(args: DnsArgs) -> Result<()> {
    let settings = Settings::load_default()?;
    let session = SessionState::load_default()?;

    let target_ip = if let Some(ip) = args
        .ip
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        ip
    } else if let Some(ip) = session
        .public_ip()?
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        ip
    } else if let Some(ip) = session
        .tailscale_ip()?
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        ip
    } else if let Some(ip) = session
        .vps_ip()?
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        ip
    } else {
        return Err(anyhow!(
            "No target IP specified. Pass --ip <IP> or run `bab setup` first."
        ));
    };

    let has_token = settings
        .cloudflare_api_token()?
        .is_some_and(|t| !t.trim().is_empty());

    let cfg = CloudflareDnsConfig {
        zone: args.zone.trim().to_string(),
        record_name: args.record.trim().to_string(),
        target_ip,
        proxied: args.proxied,
    };

    let plan = build_cloudflare_dns_stub_plan(&cfg, has_token)?;
    persist_cf_session(&session, &cfg)?;
    println!("{}", plan);
    Ok(())
}

fn cmd_deploy(args: DeployArgs) -> Result<()> {
    let settings = Settings::load_default()?;
    let session = SessionState::load_default()?;
    let log = resolve_cli_log_store(&settings);

    let tailscale_mode = match args.transport {
        Some(TransportArg::Tailscale) => true,
        Some(TransportArg::Ssh) => false,
        None => {
            let saved_mode = session.transport_mode()?.unwrap_or_default();
            !saved_mode.eq_ignore_ascii_case("ssh")
        }
    };

    let target = if let Some(ip) = args
        .ip
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        ip
    } else if let Some(saved) = session
        .vps_ip()?
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        saved
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
    };

    if !is_valid_target(&target) {
        return Err(anyhow!("Invalid target IP or hostname: '{}'", target));
    }

    let saved_user = session
        .username()?
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let deploy_user = args
        .user
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| saved_user.clone())
        .unwrap_or_else(|| "deploy".to_string());
    let ssh_user = args
        .ssh_user
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or(saved_user)
        .unwrap_or_else(|| deploy_user.clone());

    let mode = if tailscale_mode {
        TransportMode::Tailscale
    } else {
        let key_path = if let Some(p) = args.ssh_key {
            p
        } else {
            let saved_key = session.ssh_key()?.unwrap_or_default();
            if !saved_key.is_empty() && !saved_key.eq_ignore_ascii_case("tailscale") {
                PathBuf::from(saved_key)
            } else {
                default_ssh_key_path()
                    .ok()
                    .filter(|p| p.exists())
                    .unwrap_or_default()
            }
        };
        TransportMode::SshKey(key_path)
    };

    let github_token = settings
        .github_token()?
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let gh_cfg = GithubDeployConfig {
        repo: args.repo.trim().to_string(),
        branch: args.branch.trim().to_string(),
        deploy_path: args
            .path
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        deploy_cmd: args
            .cmd
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        github_token,
        username: deploy_user,
    };

    let transport = SshTransport::from_env(mode);
    let runner = SetupRunner::new(&transport, Some(&session));
    let output = match runner.deploy_github(&ssh_user, &target, &gh_cfg, args.dry_run) {
        Ok(out) => out,
        Err(err) => {
            append_cli_log(
                &log,
                &[format!(
                    "[FAIL] GitHub Deploy ({}) failed: {}",
                    gh_cfg.repo, err
                )],
            );
            return Err(err);
        }
    };

    let tag = if args.dry_run { "DRY-RUN" } else { "OK" };
    let header = format!("[{}] GitHub Deploy ({})", tag, gh_cfg.repo);
    println!("{}", header);
    let mut log_lines = vec![header];
    if !output.trim().is_empty() {
        let trimmed_out = output.trim_end();
        println!("{}", trimmed_out);
        for line in trimmed_out.lines() {
            if !line.trim().is_empty() {
                log_lines.push(line.to_string());
            }
        }
    }
    append_cli_log(&log, &log_lines);

    if !args.dry_run {
        persist_github_session(&session, &gh_cfg)?;
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
    if let Some(ref token) = args.cloudflare_token {
        settings.set_cloudflare_api_token(token)?;
        updated = true;
    }
    if let Some(ref token) = args.github_token {
        settings.set_github_token(token)?;
        updated = true;
    }

    if args.show || updated || (!args.show && !updated) {
        let ts = settings.tailscale_api_key()?.unwrap_or_default();
        let vultr = settings.vultr_api_key()?.unwrap_or_default();
        let upcloud = settings.upcloud_api_token()?.unwrap_or_default();
        let linode = settings.linode_api_token()?.unwrap_or_default();
        let cloudflare = settings.cloudflare_api_token()?.unwrap_or_default();
        let github = settings.github_token()?.unwrap_or_default();

        let config_dir = settings
            .path()
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                default_config_dir().unwrap_or_else(|_| PathBuf::from("~/.config/bab"))
            });

        let log = resolve_cli_log_store(&settings);
        let max_log_mb = MAX_LOG_FILE_BYTES / (1024 * 1024);

        println!("TAILSCALE_API_KEY: {}", ApiKeyForm::mask_key(&ts));
        println!("VULTR_API_KEY: {}", ApiKeyForm::mask_key(&vultr));
        println!("UPCLOUD_API_TOKEN: {}", ApiKeyForm::mask_key(&upcloud));
        println!("LINODE_API_TOKEN: {}", ApiKeyForm::mask_key(&linode));
        println!("CLOUDFLARE_API_TOKEN: {}", ApiKeyForm::mask_key(&cloudflare));
        println!("GITHUB_TOKEN: {}", ApiKeyForm::mask_key(&github));
        println!("Config Directory: {} (0700)", config_dir.display());
        println!(
            "Encrypted Credentials: {} (0600, ChaCha20-Poly1305)",
            settings.path().display()
        );
        println!("Master Key: {} (0600)", settings.key_file_path().display());
        println!(
            "Log File: {} (0600, max {} MB)",
            log.path().display(),
            max_log_mb
        );
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

    let sudo_nopasswd_label = if parse_sudo_nopasswd(session.sudo_nopasswd()?.as_deref()) {
        "ON"
    } else {
        "OFF"
    };
    println!(
        "Target: {} | User: {} | Transport: {} | Passwordless Sudo: {}",
        target, username, transport_label, sudo_nopasswd_label
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

fn ensure_cloud_provider(kind: ProviderKind, action: &str) -> Result<()> {
    if matches!(
        kind,
        ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit
    ) {
        return Err(anyhow!("{} does not support {}", kind.label(), action));
    }
    Ok(())
}

fn print_instances_table(instances: &[ProviderInstance]) {
    if instances.is_empty() {
        println!("No instances found.");
        return;
    }

    let mut w_prov = "PROVIDER".len();
    let mut w_id = "ID".len();
    let mut w_name = "NAME".len();
    let mut w_status = "STATUS".len();
    let mut w_ip = "PUBLIC IP".len();
    let mut w_region = "REGION".len();
    let mut w_plan = "PLAN".len();

    for inst in instances {
        w_prov = w_prov.max(inst.provider.label().len());
        w_id = w_id.max(inst.id.len());
        w_name = w_name.max(inst.name.len());
        w_status = w_status.max(inst.status.len());
        w_ip = w_ip.max(inst.public_ip.as_deref().unwrap_or("-").len());
        w_region = w_region.max(inst.region.as_deref().unwrap_or("-").len());
        w_plan = w_plan.max(inst.plan.as_deref().unwrap_or("-").len());
    }

    println!(
        "{:<w_prov$}  {:<w_id$}  {:<w_name$}  {:<w_status$}  {:<w_ip$}  {:<w_region$}  {:<w_plan$}",
        "PROVIDER", "ID", "NAME", "STATUS", "PUBLIC IP", "REGION", "PLAN"
    );
    for inst in instances {
        println!(
            "{:<w_prov$}  {:<w_id$}  {:<w_name$}  {:<w_status$}  {:<w_ip$}  {:<w_region$}  {:<w_plan$}",
            inst.provider.label(),
            inst.id,
            inst.name,
            inst.status,
            inst.public_ip.as_deref().unwrap_or("-"),
            inst.region.as_deref().unwrap_or("-"),
            inst.plan.as_deref().unwrap_or("-"),
        );
    }
}

fn resolve_provider_for_instance(
    instances: &[ProviderInstance],
    statuses: &[ProviderQueryStatus],
    explicit: Option<ProviderKind>,
    id: &str,
) -> Result<(ProviderKind, Option<String>)> {
    if let Some(kind) = explicit {
        ensure_cloud_provider(kind, "destroying cloud instances")?;
        let name = instances
            .iter()
            .find(|inst| inst.provider == kind && inst.id == id)
            .map(|inst| inst.name.clone());
        return Ok((kind, name));
    }

    let matches: Vec<&ProviderInstance> = instances.iter().filter(|inst| inst.id == id).collect();
    match matches.len() {
        1 => Ok((matches[0].provider, Some(matches[0].name.clone()))),
        0 => {
            let errors: Vec<String> = statuses
                .iter()
                .filter_map(|st| {
                    st.error
                        .as_ref()
                        .map(|e| format!("{}: {}", st.provider.label(), e))
                })
                .collect();
            if errors.is_empty() {
                Err(anyhow!(
                    "Instance '{}' was not found across configured providers; pass --provider <vultr|upcloud|linode>.",
                    id
                ))
            } else {
                Err(anyhow!(
                    "Instance '{}' was not found across configured providers (query errors: {}); pass --provider <vultr|upcloud|linode>.",
                    id,
                    errors.join("; ")
                ))
            }
        }
        _ => {
            let labels: Vec<&str> = matches.iter().map(|m| m.provider.label()).collect();
            Err(anyhow!(
                "Instance '{}' matches multiple providers ({}); specify --provider.",
                id,
                labels.join(", ")
            ))
        }
    }
}

fn confirm_destroy(provider: ProviderKind, id: &str, name: Option<&str>) -> Result<bool> {
    use std::io::{self, BufRead, Write};
    let target_desc = match name.filter(|n| !n.is_empty() && *n != id) {
        Some(n) => format!("{} instance '{}' ({})", provider.label(), id, n),
        None => format!("{} instance '{}'", provider.label(), id),
    };
    print!("Destroy {}? [y/N]: ", target_desc);
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    let trimmed = answer.trim().to_ascii_lowercase();
    Ok(matches!(trimmed.as_str(), "y" | "yes"))
}

fn execute_destroy(
    settings: &Settings,
    kind: ProviderKind,
    id: &str,
    name: Option<&str>,
    skip_confirm: bool,
) -> Result<()> {
    let log = resolve_cli_log_store(settings);
    if !skip_confirm && !confirm_destroy(kind, id, name)? {
        println!("Aborted.");
        append_cli_log(
            &log,
            &[format!(
                "[DESTROY] Aborted destroying {} instance '{}'.",
                kind.label(),
                id
            )],
        );
        return Ok(());
    }

    let session_state = SessionState::load_default().ok();
    let pre_destroy_session = session_state
        .as_ref()
        .and_then(|s| s.load_session().ok())
        .unwrap_or_default();
    let session_matches =
        pre_destroy_session.vps_instance_id.as_deref().map(str::trim) == Some(id.trim());

    if let Err(err) = destroy_provider_instance(settings, kind, id) {
        append_cli_log(
            &log,
            &[format!(
                "[DESTROY] Failed to destroy {} instance '{}': {}",
                kind.label(),
                id,
                err
            )],
        );
        return Err(err);
    }

    let cleared = match session_state {
        Some(ref s) => clear_destroyed_session_if_matches(s, id)?,
        None => clear_destroyed_session_if_matches(&SessionState::load_default()?, id)?,
    };
    let msg = format!("Destroyed {} instance '{}'.", kind.label(), id);
    println!("{}", msg);
    let mut log_lines = vec![format!("[DESTROY] {}", msg)];
    if cleared {
        let cleared_msg = "Cleared matching active session state.";
        println!("{}", cleared_msg);
        log_lines.push(format!("[DESTROY] {}", cleared_msg));
    }

    if let Ok(Some(ts_key)) = settings.tailscale_api_key() {
        let ts_key = ts_key.trim().to_string();
        if !ts_key.is_empty() {
            let mut queries: Vec<String> = Vec::new();
            let mut push_unique = |cand: Option<&str>| {
                if let Some(c) = cand.map(str::trim).filter(|s| !s.is_empty()) {
                    if !queries.iter().any(|existing| existing.eq_ignore_ascii_case(c)) {
                        queries.push(c.to_string());
                    }
                }
            };
            push_unique(name);
            if session_matches {
                push_unique(pre_destroy_session.tailscale_hostname.as_deref());
                push_unique(pre_destroy_session.tailscale_ip.as_deref());
            }
            push_unique(Some(id));

            match TailscaleClient::new(ts_key) {
                Ok(ts) => {
                    let mut removed_all: Vec<String> = Vec::new();
                    for q in &queries {
                        match ts.delete_matching_devices(q) {
                            Ok(removed) => {
                                for item in removed {
                                    if !removed_all.contains(&item) {
                                        removed_all.push(item);
                                    }
                                }
                            }
                            Err(err) => {
                                let warn_msg = format!(
                                    "[WARN] Failed to check/remove Tailscale device matching '{}': {}",
                                    q, err
                                );
                                eprintln!("{}", warn_msg);
                                log_lines.push(warn_msg);
                            }
                        }
                    }
                    if !removed_all.is_empty() {
                        let ts_msg = format!(
                            "[TAILSCALE] Removed device(s) from tailnet: {}",
                            removed_all.join(", ")
                        );
                        println!("{}", ts_msg);
                        log_lines.push(ts_msg);
                    }
                }
                Err(err) => {
                    let warn_msg = format!(
                        "[WARN] Could not initialize Tailscale client for device cleanup: {}",
                        err
                    );
                    eprintln!("{}", warn_msg);
                    log_lines.push(warn_msg);
                }
            }
        }
    }

    append_cli_log(&log, &log_lines);
    Ok(())
}

fn cmd_instances(args: InstancesArgs) -> Result<()> {
    let settings = Settings::load_default()?;
    if let Some(p) = args.provider {
        ensure_cloud_provider(p, "querying cloud instances")?;
    }
    let destroy_id = args
        .destroy
        .as_deref()
        .map(validate_instance_id)
        .transpose()?
        .map(String::from);

    let result = query_all_providers(&settings, args.provider);

    println!("Providers:");
    let mut printed_status = false;
    for st in &result.provider_statuses {
        if args.all || st.configured || st.error.is_some() {
            printed_status = true;
            if let Some(ref err) = st.error {
                println!("  {:<8} ERROR: {}", st.provider.label(), err);
            } else if !st.configured {
                println!("  {:<8} not configured", st.provider.label());
            } else {
                println!(
                    "  {:<8} {} instance(s)",
                    st.provider.label(),
                    st.instance_count
                );
            }
        }
    }
    if !printed_status {
        println!(
            "  No cloud providers configured (set VULTR_API_KEY, UPCLOUD_API_TOKEN, or LINODE_API_TOKEN)."
        );
    }

    print_instances_table(&result.instances);

    if let Some(id) = destroy_id {
        let (kind, name) = resolve_provider_for_instance(
            &result.instances,
            &result.provider_statuses,
            args.provider,
            &id,
        )?;
        execute_destroy(&settings, kind, &id, name.as_deref(), args.yes)?;
    }

    Ok(())
}

fn cmd_destroy(args: DestroyArgs) -> Result<()> {
    let settings = Settings::load_default()?;
    let id = validate_instance_id(&args.id)?.to_string();
    if let Some(p) = args.provider {
        ensure_cloud_provider(p, "destroying cloud instances")?;
    }

    if args.dry_run {
        let session_data = SessionState::load_default()?.load_session()?;
        let session_matches =
            session_data.vps_instance_id.as_deref().map(str::trim) == Some(id.as_str());
        let kind = match args.provider {
            Some(p) => p,
            None => {
                let session_provider = if session_matches {
                    session_data
                        .vps_provider
                        .as_deref()
                        .and_then(|s| s.parse::<ProviderKind>().ok())
                        .filter(|p| {
                            !matches!(
                                p,
                                ProviderKind::ExistingTailscale | ProviderKind::ManualCloudInit
                            )
                        })
                } else {
                    None
                };
                session_provider.ok_or_else(|| {
                    anyhow!(
                        "--provider is required in --dry-run mode when instance '{}' does not match the active session",
                        id
                    )
                })?
            }
        };
        let log = resolve_cli_log_store(&settings);
        let dry_msg = format!(
            "[DRY-RUN] Would destroy {} instance '{}'.",
            kind.label(),
            id
        );
        println!("{}", dry_msg);
        let mut log_lines = vec![dry_msg];
        if session_matches {
            let clear_msg = format!(
                "[DRY-RUN] Would clear matching active session state for '{}'.",
                id
            );
            println!("{}", clear_msg);
            log_lines.push(clear_msg);
        }
        let ts_dry_msg =
            "[DRY-RUN] Would remove matching device from Tailscale network if present.".to_string();
        println!("{}", ts_dry_msg);
        log_lines.push(ts_dry_msg);
        append_cli_log(&log, &log_lines);
        return Ok(());
    }

    let (kind, name) = if let Some(p) = args.provider {
        (p, None)
    } else {
        let result = query_all_providers(&settings, None);
        resolve_provider_for_instance(&result.instances, &result.provider_statuses, None, &id)?
    };

    execute_destroy(&settings, kind, &id, name.as_deref(), args.yes)
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
                assert_eq!(args.cf_zone, None);
                assert_eq!(args.cf_record, None);
                assert!(!args.cf_proxied);
                assert_eq!(args.github_repo, None);
                assert_eq!(args.github_branch, None);
                assert_eq!(args.github_path, None);
                assert_eq!(args.github_cmd, None);
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
                "--cf-zone",
                "example.com",
                "--cf-record",
                "app",
                "--cf-proxied",
                "--github-repo",
                "owner/app",
                "--github-branch",
                "develop",
                "--github-path",
                "/srv/app",
                "--github-cmd",
                "docker compose up -d",
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
                    assert_eq!(args.cf_zone.as_deref(), Some("example.com"));
                    assert_eq!(args.cf_record.as_deref(), Some("app"));
                    assert!(args.cf_proxied);
                    assert_eq!(args.github_repo.as_deref(), Some("owner/app"));
                    assert_eq!(args.github_branch.as_deref(), Some("develop"));
                    assert_eq!(args.github_path.as_deref(), Some("/srv/app"));
                    assert_eq!(args.github_cmd.as_deref(), Some("docker compose up -d"));
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
            "--cloudflare-token",
            "cf-345",
            "--github-token",
            "ghp-678",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Settings(args)) => {
                assert!(args.show);
                assert_eq!(args.tailscale_key.as_deref(), Some("ts-123"));
                assert_eq!(args.vultr_key.as_deref(), Some("vultr-456"));
                assert_eq!(args.upcloud_token.as_deref(), Some("up-789"));
                assert_eq!(args.linode_token.as_deref(), Some("lin-012"));
                assert_eq!(args.cloudflare_token.as_deref(), Some("cf-345"));
                assert_eq!(args.github_token.as_deref(), Some("ghp-678"));
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn parse_catalog_dns_deploy_subcommands() {
        let cat = Cli::try_parse_from(["bab", "catalog", "--provider", "linode", "--live"]).unwrap();
        match cat.command {
            Some(Commands::Catalog(args)) => {
                assert_eq!(args.provider, ProviderKind::Linode);
                assert!(args.live);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        let dns = Cli::try_parse_from([
            "bab",
            "dns",
            "--zone",
            "example.com",
            "--record",
            "app",
            "--ip",
            "203.0.113.10",
            "--proxied",
        ])
        .unwrap();
        match dns.command {
            Some(Commands::Dns(args)) => {
                assert_eq!(args.zone, "example.com");
                assert_eq!(args.record, "app");
                assert_eq!(args.ip.as_deref(), Some("203.0.113.10"));
                assert!(args.proxied);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        let deploy = Cli::try_parse_from([
            "bab",
            "deploy",
            "--repo",
            "owner/app",
            "--branch",
            "release",
            "--path",
            "/srv/app",
            "--cmd",
            "make deploy",
            "--ip",
            "203.0.113.10",
            "--transport",
            "ssh",
            "--ssh-key",
            "/tmp/id_ed25519",
            "--ssh-user",
            "ops",
            "--user",
            "deploy",
            "--dry-run",
        ])
        .unwrap();
        match deploy.command {
            Some(Commands::Deploy(args)) => {
                assert_eq!(args.repo, "owner/app");
                assert_eq!(args.branch, "release");
                assert_eq!(args.path.as_deref(), Some("/srv/app"));
                assert_eq!(args.cmd.as_deref(), Some("make deploy"));
                assert_eq!(args.ip.as_deref(), Some("203.0.113.10"));
                assert_eq!(args.transport, Some(TransportArg::Ssh));
                assert_eq!(args.ssh_key, Some(PathBuf::from("/tmp/id_ed25519")));
                assert_eq!(args.ssh_user.as_deref(), Some("ops"));
                assert_eq!(args.user.as_deref(), Some("deploy"));
                assert!(args.dry_run);
            }
            other => panic!("unexpected command: {:?}", other),
        }
    }

    #[test]
    fn resolve_option_prefers_explicit_then_saved_then_provider_then_catalog() -> Result<()> {
        let mut queried = false;
        let explicit = resolve_option(
            Some("ord".to_string()),
            Some("ams".to_string()),
            || {
                queried = true;
                Ok(vec!["ewr".to_string()])
            },
            Some("fra".to_string()),
            "--region",
            ProviderKind::Vultr,
        )?;
        assert_eq!(explicit, "ord");
        assert!(!queried);

        let saved = resolve_option(
            None,
            Some("ams".to_string()),
            || {
                queried = true;
                Ok(vec!["ewr".to_string()])
            },
            Some("fra".to_string()),
            "--region",
            ProviderKind::Vultr,
        )?;
        assert_eq!(saved, "ams");
        assert!(!queried);

        let live = resolve_option(
            None,
            None,
            || Ok(vec!["lhr".to_string()]),
            Some("ewr".to_string()),
            "--region",
            ProviderKind::Vultr,
        )?;
        assert_eq!(live, "lhr");

        let cat = resolve_option(
            None,
            None,
            || Ok(vec![]),
            Some("ewr".to_string()),
            "--region",
            ProviderKind::Vultr,
        )?;
        assert_eq!(cat, "ewr");
        Ok(())
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

        fn remove(key: &'static str) -> Self {
            let prev = std::env::var_os(key);
            std::env::remove_var(key);
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
        persist_setup_session(
            &state,
            &SetupSessionUpdate {
                provider: ProviderKind::ExistingTailscale,
                target: "100.64.0.10",
                username: "deploy",
                hostname: "ts-box",
                tailscale_mode: true,
                sudo_nopasswd: true,
                sudo_password: Some("Abc123XyZ9"),
                key_path: None,
                catalog: (None, None, None),
                provisioned_ips: None,
            },
        )?;
        assert_eq!(state.transport_mode()?.as_deref(), Some("tailscale"));
        assert_eq!(state.ssh_key()?.as_deref(), Some("tailscale"));
        assert_eq!(state.sudo_nopasswd()?.as_deref(), Some("true"));
        assert_eq!(state.sudo_password()?.as_deref(), Some("Abc123XyZ9"));

        // Switch to SSH mode with --ssh-pubkey (key_path_opt == None): clears stale "tailscale".
        persist_setup_session(
            &state,
            &SetupSessionUpdate {
                provider: ProviderKind::Vultr,
                target: "203.0.113.20",
                username: "ops",
                hostname: "ssh-box",
                tailscale_mode: false,
                sudo_nopasswd: false,
                sudo_password: None,
                key_path: None,
                catalog: (Some("ewr"), Some("vc2-1c-1gb"), Some("2284")),
                provisioned_ips: None,
            },
        )?;
        assert_eq!(state.transport_mode()?.as_deref(), Some("ssh"));
        assert_eq!(state.ssh_key()?.as_deref(), Some(""));
        assert_eq!(state.vps_ip()?.as_deref(), Some("203.0.113.20"));
        assert_eq!(state.sudo_nopasswd()?.as_deref(), Some("false"));

        // Explicit key path sets SSH_KEY.
        let key_path = PathBuf::from("/tmp/custom_ed25519");
        persist_setup_session(
            &state,
            &SetupSessionUpdate {
                provider: ProviderKind::Vultr,
                target: "203.0.113.20",
                username: "ops",
                hostname: "ssh-box",
                tailscale_mode: false,
                sudo_nopasswd: true,
                sudo_password: None,
                key_path: Some(&key_path),
                catalog: (Some("ewr"), Some("vc2-1c-1gb"), Some("2284")),
                provisioned_ips: None,
            },
        )?;
        assert_eq!(state.ssh_key()?.as_deref(), Some("/tmp/custom_ed25519"));

        // Subsequent SSH run with key_path_opt == None keeps non-"tailscale" SSH_KEY.
        persist_setup_session(
            &state,
            &SetupSessionUpdate {
                provider: ProviderKind::Vultr,
                target: "203.0.113.20",
                username: "ops",
                hostname: "ssh-box",
                tailscale_mode: false,
                sudo_nopasswd: true,
                sudo_password: None,
                key_path: None,
                catalog: (Some("ewr"), Some("vc2-1c-1gb"), Some("2284")),
                provisioned_ips: None,
            },
        )?;
        assert_eq!(state.ssh_key()?.as_deref(), Some("/tmp/custom_ed25519"));
        Ok(())
    }

    #[test]
    fn saved_catalog_for_provider_ignores_cross_provider_stale_values() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let state_path = dir.path().join(".bab-local");
        let state = SessionState::new(&state_path);

        state.set_vps_provider("vultr")?;
        state.set_vps_region("ewr")?;
        state.set_vps_plan("vc2-1c-1gb")?;
        state.set_vps_image("2284")?;

        // Matching provider reuses saved catalog IDs.
        let (r_vultr, p_vultr, i_vultr) = saved_catalog_for_provider(&state, ProviderKind::Vultr)?;
        assert_eq!(r_vultr.as_deref(), Some("ewr"));
        assert_eq!(p_vultr.as_deref(), Some("vc2-1c-1gb"));
        assert_eq!(i_vultr.as_deref(), Some("2284"));

        // Different provider ignores stale Vultr IDs so live query or Linode catalog defaults apply.
        let (r_linode, p_linode, i_linode) =
            saved_catalog_for_provider(&state, ProviderKind::Linode)?;
        assert_eq!(r_linode, None);
        assert_eq!(p_linode, None);
        assert_eq!(i_linode, None);

        let cat_region = default_regions_for(ProviderKind::Linode)
            .into_iter()
            .next()
            .map(|r| r.id);
        let cat_plan = default_plans_for(ProviderKind::Linode)
            .into_iter()
            .next()
            .map(|p| p.id);
        let cat_image = default_images_for(ProviderKind::Linode)
            .into_iter()
            .next()
            .map(|i| i.id);

        assert_eq!(
            resolve_dry_run_option(None, r_linode.as_deref(), cat_region.clone()).as_deref(),
            Some("us-east")
        );
        assert_eq!(
            resolve_dry_run_option(None, p_linode.as_deref(), cat_plan.clone()).as_deref(),
            Some("g6-nanode-1")
        );
        assert_eq!(
            resolve_dry_run_option(None, i_linode.as_deref(), cat_image.clone()).as_deref(),
            Some("linode/ubuntu24.04")
        );

        let resolved_live_region = resolve_option(
            None,
            r_linode,
            || Ok(vec!["eu-central".to_string()]),
            cat_region,
            "--region",
            ProviderKind::Linode,
        )?;
        assert_eq!(resolved_live_region, "eu-central");

        // ExistingTailscale ignores stale Vultr catalog IDs and resolves to None.
        let (r_existing, p_existing, i_existing) =
            saved_catalog_for_provider(&state, ProviderKind::ExistingTailscale)?;
        assert_eq!(r_existing, None);
        assert_eq!(p_existing, None);
        assert_eq!(i_existing, None);
        assert_eq!(resolve_dry_run_option(None, r_existing.as_deref(), None), None);

        // Provider alias ("akamai" -> Linode) matches ProviderKind::Linode.
        state.set_vps_provider("akamai")?;
        state.set_vps_region("eu-central")?;
        let (r_alias, _, _) = saved_catalog_for_provider(&state, ProviderKind::Linode)?;
        assert_eq!(r_alias.as_deref(), Some("eu-central"));
        Ok(())
    }

    #[test]
    fn persist_setup_session_updates_public_and_tailscale_ips_cleanly() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let state_path = dir.path().join(".bab-local");
        let state = SessionState::new(&state_path);

        // Seed stale TAILSCALE_IP before an SSH non-provisioned run.
        state.set_tailscale_ip("100.64.99.99")?;

        // SSH mode sets PUBLIC_IP = host, clears stale TAILSCALE_IP, and saves VPS_PROVIDER.
        persist_setup_session(
            &state,
            &SetupSessionUpdate {
                provider: ProviderKind::Vultr,
                target: "203.0.113.20",
                username: "ops",
                hostname: "ssh-box",
                tailscale_mode: false,
                sudo_nopasswd: true,
                sudo_password: None,
                key_path: None,
                catalog: (Some("ewr"), Some("vc2-1c-1gb"), Some("2284")),
                provisioned_ips: None,
            },
        )?;
        assert_eq!(state.vps_provider()?.as_deref(), Some("vultr"));
        assert_eq!(state.vps_ip()?.as_deref(), Some("203.0.113.20"));
        assert_eq!(state.public_ip()?.as_deref(), Some("203.0.113.20"));
        assert_eq!(state.tailscale_ip()?, None);
        assert_eq!(state.vps_region()?.as_deref(), Some("ewr"));

        // Switching to Tailscale mode with a Tailscale IP sets TAILSCALE_IP and clears stale PUBLIC_IP.
        persist_setup_session(
            &state,
            &SetupSessionUpdate {
                provider: ProviderKind::ExistingTailscale,
                target: "100.64.0.10",
                username: "deploy",
                hostname: "ts-box",
                tailscale_mode: true,
                sudo_nopasswd: true,
                sudo_password: None,
                key_path: None,
                catalog: (None, None, None),
                provisioned_ips: None,
            },
        )?;
        assert_eq!(
            state.vps_provider()?.as_deref(),
            Some("existing_tailscale")
        );
        assert_eq!(state.vps_ip()?.as_deref(), Some("100.64.0.10"));
        assert_eq!(state.tailscale_ip()?.as_deref(), Some("100.64.0.10"));
        assert_eq!(state.public_ip()?, None);
        assert_eq!(state.vps_region()?, None);
        assert_eq!(state.vps_plan()?, None);
        assert_eq!(state.vps_image()?, None);

        // MagicDNS hostname in Tailscale mode also sets TAILSCALE_IP.
        state.set_public_ip("198.51.100.5")?;
        persist_setup_session(
            &state,
            &SetupSessionUpdate {
                provider: ProviderKind::ExistingTailscale,
                target: "ts-box.tail123.ts.net",
                username: "deploy",
                hostname: "ts-box",
                tailscale_mode: true,
                sudo_nopasswd: true,
                sudo_password: None,
                key_path: None,
                catalog: (None, None, None),
                provisioned_ips: None,
            },
        )?;
        assert_eq!(
            state.tailscale_ip()?.as_deref(),
            Some("ts-box.tail123.ts.net")
        );
        assert_eq!(state.public_ip()?, None);

        // Non-Tailscale IP in Tailscale mode does not pollute TAILSCALE_IP.
        persist_setup_session(
            &state,
            &SetupSessionUpdate {
                provider: ProviderKind::ExistingTailscale,
                target: "198.51.100.99",
                username: "deploy",
                hostname: "ts-box",
                tailscale_mode: true,
                sudo_nopasswd: true,
                sudo_password: None,
                key_path: None,
                catalog: (None, None, None),
                provisioned_ips: None,
            },
        )?;
        assert_eq!(state.public_ip()?.as_deref(), Some("198.51.100.99"));
        assert_eq!(state.tailscale_ip()?, None);

        // Provisioned path preserves both discovered PUBLIC_IP and TAILSCALE_IP.
        persist_setup_session(
            &state,
            &SetupSessionUpdate {
                provider: ProviderKind::Linode,
                target: "100.64.1.2",
                username: "deploy",
                hostname: "linode-box",
                tailscale_mode: true,
                sudo_nopasswd: true,
                sudo_password: None,
                key_path: None,
                catalog: (Some("us-east"), Some("g6-standard-1"), Some("linode/ubuntu24.04")),
                provisioned_ips: Some((Some("203.0.113.42"), Some("100.64.1.2"))),
            },
        )?;
        assert_eq!(state.vps_provider()?.as_deref(), Some("linode"));
        assert_eq!(state.public_ip()?.as_deref(), Some("203.0.113.42"));
        assert_eq!(state.tailscale_ip()?.as_deref(), Some("100.64.1.2"));
        Ok(())
    }

    #[test]
    fn parse_instances_and_aliases() {
        for sub in ["instances", "ps", "list"] {
            let def = Cli::try_parse_from(["bab", sub]).unwrap();
            match def.command {
                Some(Commands::Instances(args)) => {
                    assert_eq!(args.provider, None);
                    assert!(!args.all);
                    assert_eq!(args.destroy, None);
                    assert!(!args.yes);
                }
                other => panic!("unexpected command for {}: {:?}", sub, other),
            }

            let full = Cli::try_parse_from([
                "bab",
                sub,
                "--provider",
                "upcloud",
                "--all",
                "--destroy",
                "upcloud-uuid-1",
                "-y",
            ])
            .unwrap();
            match full.command {
                Some(Commands::Instances(args)) => {
                    assert_eq!(args.provider, Some(ProviderKind::UpCloud));
                    assert!(args.all);
                    assert_eq!(args.destroy.as_deref(), Some("upcloud-uuid-1"));
                    assert!(args.yes);
                }
                other => panic!("unexpected command for {}: {:?}", sub, other),
            }
        }
    }

    #[test]
    fn parse_destroy_and_aliases() {
        for sub in ["destroy", "rm", "delete"] {
            let min = Cli::try_parse_from(["bab", sub, "--id", "vultr-123"]).unwrap();
            match min.command {
                Some(Commands::Destroy(args)) => {
                    assert_eq!(args.id, "vultr-123");
                    assert_eq!(args.provider, None);
                    assert!(!args.yes);
                    assert!(!args.dry_run);
                }
                other => panic!("unexpected command for {}: {:?}", sub, other),
            }

            let full = Cli::try_parse_from([
                "bab",
                sub,
                "--id",
                "12345",
                "--provider",
                "linode",
                "--yes",
                "--dry-run",
            ])
            .unwrap();
            match full.command {
                Some(Commands::Destroy(args)) => {
                    assert_eq!(args.id, "12345");
                    assert_eq!(args.provider, Some(ProviderKind::Linode));
                    assert!(args.yes);
                    assert!(args.dry_run);
                }
                other => panic!("unexpected command for {}: {:?}", sub, other),
            }
        }

        assert!(Cli::try_parse_from(["bab", "destroy"]).is_err());
    }

    #[test]
    fn parse_setup_cf_dns_flags() {
        let cf_on = Cli::try_parse_from(["bab", "setup", "--cf-dns"]).unwrap();
        match cf_on.command {
            Some(Commands::Setup(args)) => {
                assert!(args.cf_dns);
                assert!(!args.no_cf_dns);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        let cf_off = Cli::try_parse_from(["bab", "setup", "--no-cf-dns"]).unwrap();
        match cf_off.command {
            Some(Commands::Setup(args)) => {
                assert!(!args.cf_dns);
                assert!(args.no_cf_dns);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        assert!(Cli::try_parse_from(["bab", "setup", "--cf-dns", "--no-cf-dns"]).is_err());
    }

    #[test]
    fn parse_setup_github_deploy_flags() {
        let def = Cli::try_parse_from(["bab", "setup"]).unwrap();
        match def.command {
            Some(Commands::Setup(args)) => {
                assert!(!args.github_deploy);
                assert!(!args.no_github_deploy);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        let gh_on = Cli::try_parse_from(["bab", "setup", "--github-deploy"]).unwrap();
        match gh_on.command {
            Some(Commands::Setup(args)) => {
                assert!(args.github_deploy);
                assert!(!args.no_github_deploy);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        let gh_off = Cli::try_parse_from(["bab", "setup", "--no-github-deploy"]).unwrap();
        match gh_off.command {
            Some(Commands::Setup(args)) => {
                assert!(!args.github_deploy);
                assert!(args.no_github_deploy);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        assert!(
            Cli::try_parse_from(["bab", "setup", "--github-deploy", "--no-github-deploy"]).is_err()
        );
    }

    #[test]
    fn resolve_github_deploy_config_respects_flags_and_session() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let state = SessionState::new(dir.path().join("state.conf"));
        let settings = Settings::new(dir.path().join("settings.conf"));

        let parse_setup = |argv: &[&str]| -> SetupArgs {
            match Cli::try_parse_from(argv).unwrap().command {
                Some(Commands::Setup(args)) => args,
                other => panic!("unexpected command: {:?}", other),
            }
        };

        // Empty session, no flags -> None.
        let args_default = parse_setup(&["bab", "setup"]);
        assert!(resolve_github_deploy_config(&args_default, &settings, &state)?.is_none());

        // --github-deploy with empty GITHUB_REPO -> clear error.
        let args_on = parse_setup(&["bab", "setup", "--github-deploy"]);
        let err = resolve_github_deploy_config(&args_on, &settings, &state).unwrap_err();
        assert!(
            err.to_string()
                .contains("--github-deploy requires GITHUB_REPO in session state"),
            "unexpected error: {}",
            err
        );

        // GITHUB_ENABLED=true with empty GITHUB_REPO -> Ok(None) (Note printed to stderr).
        state.set_github_enabled("true")?;
        assert!(resolve_github_deploy_config(&args_default, &settings, &state)?.is_none());

        // Explicit --github-repo with no saved GITHUB_BRANCH defaults branch to "main".
        let args_fresh = parse_setup(&["bab", "setup", "--github-repo", "owner/fresh"]);
        let cfg_fresh = resolve_github_deploy_config(&args_fresh, &settings, &state)?.unwrap();
        assert_eq!(cfg_fresh.repo, "owner/fresh");
        assert_eq!(cfg_fresh.branch, "main");

        // Seed saved GitHub session with GITHUB_ENABLED=false.
        state.set_github_repo("owner/saved")?;
        state.set_github_branch("release")?;
        state.set_github_deploy_path("/srv/saved")?;
        state.set_github_deploy_cmd("make run")?;
        state.set_github_enabled("false")?;

        // Disabled in session without --github-deploy -> None.
        assert!(resolve_github_deploy_config(&args_default, &settings, &state)?.is_none());

        // --github-deploy uses saved session values (and CLI overrides like --github-branch).
        let args_on_branch =
            parse_setup(&["bab", "setup", "--github-deploy", "--github-branch", "hotfix"]);
        let cfg_on = resolve_github_deploy_config(&args_on_branch, &settings, &state)?.unwrap();
        assert_eq!(cfg_on.repo, "owner/saved");
        assert_eq!(cfg_on.branch, "hotfix");
        assert_eq!(cfg_on.deploy_path.as_deref(), Some("/srv/saved"));
        assert_eq!(cfg_on.deploy_cmd.as_deref(), Some("make run"));

        // Explicit --github-repo takes precedence even when GITHUB_ENABLED=false,
        // defaulting branch to saved GITHUB_BRANCH.
        let args_explicit = parse_setup(&["bab", "setup", "--github-repo", "owner/explicit"]);
        let cfg_explicit = resolve_github_deploy_config(&args_explicit, &settings, &state)?.unwrap();
        assert_eq!(cfg_explicit.repo, "owner/explicit");
        assert_eq!(cfg_explicit.branch, "release");
        assert_eq!(cfg_explicit.deploy_path, None);
        assert_eq!(cfg_explicit.deploy_cmd, None);

        // persist_github_session sets GITHUB_ENABLED=true.
        persist_github_session(&state, &cfg_explicit)?;
        assert_eq!(state.github_enabled()?.as_deref(), Some("true"));

        // Enabled in session with no flags -> uses saved session.
        let cfg_saved = resolve_github_deploy_config(&args_default, &settings, &state)?.unwrap();
        assert_eq!(cfg_saved.repo, "owner/explicit");
        assert_eq!(cfg_saved.branch, "release");

        // --no-github-deploy skips even when GITHUB_ENABLED=true or --github-repo is given.
        let args_off = parse_setup(&["bab", "setup", "--no-github-deploy"]);
        assert!(resolve_github_deploy_config(&args_off, &settings, &state)?.is_none());
        let args_off_with_repo = parse_setup(&[
            "bab",
            "setup",
            "--no-github-deploy",
            "--github-repo",
            "owner/ignored",
        ]);
        assert!(resolve_github_deploy_config(&args_off_with_repo, &settings, &state)?.is_none());
        Ok(())
    }

    #[test]
    fn wait_for_ssh_ready_with_fallback_switches_to_fallback_user() -> Result<()> {
        let _lock = ENV_LOCK.get_or_init(|| std::sync::Mutex::new(())).lock().unwrap();
        let dir = tempfile::tempdir()?;
        let attempts_file = dir.path().join("attempts.log");
        let count_file = dir.path().join("deploy_count.txt");
        let mock_ssh = dir.path().join("mock_ssh_fallback.sh");

        write_mock_ssh_script(
            &mock_ssh,
            &format!(
                "#!/bin/sh\nuser=\"\"\nfor arg in \"$@\"; do\n  case \"$arg\" in\n    *@*) user=\"${{arg%%@*}}\" ;;\n  esac\ndone\neval \"last=\\$$#\"\necho \"$user|$last\" >> '{attempts}'\nif [ \"$user\" = \"root\" ]; then\n  echo 'tailnet policy does not permit you to SSH as \"root\"' >&2\n  exit 255\nfi\nif [ \"$user\" = \"deploy\" ]; then\n  c=$(cat '{count}' 2>/dev/null || echo 0)\n  c=$((c + 1))\n  echo \"$c\" > '{count}'\n  if [ \"$c\" -lt 2 ]; then\n    exit 1\n  fi\n  exit 0\nfi\nexit 1\n",
                attempts = attempts_file.display(),
                count = count_file.display(),
            ),
        )?;

        let _guard = EnvVarGuard::set("BAB_SSH_BIN", mock_ssh.as_os_str());
        let transport = SshTransport::from_env(TransportMode::Tailscale);

        let connected = wait_for_ssh_ready_with_fallback(
            &transport,
            "root",
            Some("deploy"),
            "100.64.0.10",
            Duration::from_secs(2),
            Duration::from_millis(10),
        )?;
        assert_eq!(connected, "deploy");

        let log = std::fs::read_to_string(&attempts_file)?;
        assert!(
            log.contains("root|if [ -d /var/lib/cloud ]; then test -f /var/lib/cloud/instance/boot-finished; fi"),
            "missing root probe in log:\n{}",
            log
        );
        assert!(
            log.contains("deploy|sudo -n true && (test ! -d /var/lib/cloud || test -f /var/lib/cloud/instance/boot-finished)"),
            "missing deploy fallback probe in log:\n{}",
            log
        );

        // When primary succeeds immediately, fallback is not needed and primary user is returned.
        let mock_ssh_ok = dir.path().join("mock_ssh_primary_ok.sh");
        write_mock_ssh_script(&mock_ssh_ok, "#!/bin/sh\nexit 0\n")?;
        let _guard_ok = EnvVarGuard::set("BAB_SSH_BIN", mock_ssh_ok.as_os_str());
        let transport_ok = SshTransport::from_env(TransportMode::Tailscale);
        let connected_primary = wait_for_ssh_ready_with_fallback(
            &transport_ok,
            "root",
            Some("deploy"),
            "100.64.0.10",
            Duration::from_secs(1),
            Duration::from_millis(10),
        )?;
        assert_eq!(connected_primary, "root");

        // Timeout reports both users clearly.
        let mock_ssh_fail = dir.path().join("mock_ssh_both_fail.sh");
        write_mock_ssh_script(&mock_ssh_fail, "#!/bin/sh\nexit 1\n")?;
        let _guard_fail = EnvVarGuard::set("BAB_SSH_BIN", mock_ssh_fail.as_os_str());
        let transport_fail = SshTransport::from_env(TransportMode::Tailscale);
        let err = wait_for_ssh_ready_with_fallback(
            &transport_fail,
            "root",
            Some("deploy"),
            "203.0.113.10",
            Duration::from_millis(50),
            Duration::from_millis(10),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("Timed out"), "unexpected error: {}", msg);
        assert!(
            msg.contains("root@203.0.113.10 (or deploy@203.0.113.10)"),
            "unexpected error: {}",
            msg
        );
        Ok(())
    }

    #[test]
    fn resolve_cli_log_store_respects_bab_log_file_and_config_dir() -> Result<()> {
        let _lock = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir()?;
        let cfg_dir = dir.path().join("cfg");
        let explicit_log = dir.path().join("custom.log");

        let _g_cfg = EnvVarGuard::set("BAB_CONFIG_DIR", cfg_dir.as_os_str());
        let _g_settings = EnvVarGuard::remove("BAB_SETTINGS_FILE");
        let _g_log_clear = EnvVarGuard::remove("BAB_LOG_FILE");

        let settings = Settings::load_default()?;
        assert_eq!(resolve_cli_log_store(&settings).path(), cfg_dir.join("bab.log"));

        // Whitespace-only BAB_LOG_FILE falls back to settings parent directory.
        let _g_log_blank = EnvVarGuard::set("BAB_LOG_FILE", std::ffi::OsStr::new("   "));
        assert_eq!(resolve_cli_log_store(&settings).path(), cfg_dir.join("bab.log"));

        // Explicit BAB_LOG_FILE overrides settings parent directory.
        let _g_log_set = EnvVarGuard::set("BAB_LOG_FILE", explicit_log.as_os_str());
        assert_eq!(resolve_cli_log_store(&settings).path(), explicit_log);
        Ok(())
    }

    #[test]
    fn cli_log_persistence_writes_0600_for_setup_deploy_destroy_and_settings() -> Result<()> {
        let _lock = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir()?;
        let cfg_dir = dir.path().join("bab-cfg");

        let _g_cfg = EnvVarGuard::set("BAB_CONFIG_DIR", cfg_dir.as_os_str());
        let _g_settings = EnvVarGuard::remove("BAB_SETTINGS_FILE");
        let _g_state = EnvVarGuard::remove("BAB_STATE_FILE");
        let _g_log = EnvVarGuard::remove("BAB_LOG_FILE");

        let settings = Settings::load_default()?;
        let log = resolve_cli_log_store(&settings);
        append_cli_log(&log, &["[TEST] direct helper entry".to_string()]);

        // Best-effort logging never panics or errors when log path cannot be created.
        let bad_parent = dir.path().join("not-a-dir");
        std::fs::write(&bad_parent, "file")?;
        let unwritable_log = LogStore::new(bad_parent.join("bab.log"));
        append_cli_log(&unwritable_log, &["[TEST] ignored failure".to_string()]);

        // cmd_settings succeeds with resolved log file path.
        let settings_args = match Cli::try_parse_from(["bab", "settings", "--show"])?.command {
            Some(Commands::Settings(a)) => a,
            other => panic!("unexpected command: {:?}", other),
        };
        cmd_settings(settings_args)?;

        // cmd_setup (--dry-run) logs start, steps, GitHub/DNS outcomes, and Final Box Information.
        let setup_args = match Cli::try_parse_from([
            "bab",
            "setup",
            "--provider",
            "existing",
            "--role",
            "caddy",
            "--github-repo",
            "owner/app",
            "--cf-zone",
            "example.com",
            "--cf-record",
            "app",
            "--dry-run",
        ])?
        .command
        {
            Some(Commands::Setup(a)) => a,
            other => panic!("unexpected command: {:?}", other),
        };
        cmd_setup(setup_args)?;

        // cmd_deploy (--dry-run) logs GitHub Deploy lines.
        let deploy_args = match Cli::try_parse_from([
            "bab",
            "deploy",
            "--repo",
            "owner/app",
            "--branch",
            "main",
            "--ip",
            "100.64.0.1",
            "--dry-run",
        ])?
        .command
        {
            Some(Commands::Deploy(a)) => a,
            other => panic!("unexpected command: {:?}", other),
        };
        cmd_deploy(deploy_args)?;

        // cmd_destroy (--dry-run) logs dry-run destroy outcome.
        let destroy_args = match Cli::try_parse_from([
            "bab",
            "destroy",
            "--id",
            "vultr-123",
            "--provider",
            "vultr",
            "--dry-run",
        ])?
        .command
        {
            Some(Commands::Destroy(a)) => a,
            other => panic!("unexpected command: {:?}", other),
        };
        cmd_destroy(destroy_args)?;

        let log_path = cfg_dir.join("bab.log");
        assert!(log_path.exists(), "expected {} to exist", log_path.display());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&log_path)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let lines = log.read_lines()?;
        assert!(lines.iter().any(|l| l.contains("[TEST] direct helper entry")));
        assert!(lines
            .iter()
            .any(|l| l.contains("[BUILD] CLI setup start (provider=existing_tailscale, target=100.64.0.1, dry_run=true)")));
        assert!(lines
            .iter()
            .any(|l| l.contains("[DRY-RUN] Configure Server Role")));
        assert!(lines
            .iter()
            .any(|l| l.contains("[GITHUB] Configured GitHub deploy: owner/app (branch: main)")));
        assert!(lines
            .iter()
            .any(|l| l.contains("[DNS] [STUB] Cloudflare DNS: would upsert A record 'app'")));
        assert!(lines
            .iter()
            .any(|l| l.contains("=== Final Box Information ===")));
        assert!(lines
            .iter()
            .any(|l| l.contains("Sudo User:") && l.contains("(passwordless: ON (NOPASSWD:ALL))")));
        assert!(lines.iter().any(|l| l.contains("Sudo Password:")));
        assert!(lines.iter().any(|l| l.contains("Log File:") && l.contains("bab.log")));
        assert!(lines
            .iter()
            .any(|l| l.contains("[DRY-RUN] GitHub Deploy (owner/app)")));
        assert!(lines
            .iter()
            .any(|l| l.contains("[DRY-RUN] Would destroy Vultr instance 'vultr-123'.")));
        assert!(lines
            .iter()
            .any(|l| l.contains("[DRY-RUN] Would remove matching device from Tailscale network if present.")));
        Ok(())
    }

    #[test]
    fn parse_setup_sudo_nopasswd_flags() {
        let def = Cli::try_parse_from(["bab", "setup"]).unwrap();
        match def.command {
            Some(Commands::Setup(args)) => {
                assert!(!args.sudo_nopasswd);
                assert!(!args.no_sudo_nopasswd);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        let on = Cli::try_parse_from(["bab", "setup", "--sudo-nopasswd"]).unwrap();
        match on.command {
            Some(Commands::Setup(args)) => {
                assert!(args.sudo_nopasswd);
                assert!(!args.no_sudo_nopasswd);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        let off = Cli::try_parse_from(["bab", "setup", "--no-sudo-nopasswd"]).unwrap();
        match off.command {
            Some(Commands::Setup(args)) => {
                assert!(!args.sudo_nopasswd);
                assert!(args.no_sudo_nopasswd);
            }
            other => panic!("unexpected command: {:?}", other),
        }

        assert!(
            Cli::try_parse_from(["bab", "setup", "--sudo-nopasswd", "--no-sudo-nopasswd"])
                .is_err()
        );
    }

    #[test]
    fn resolve_sudo_nopasswd_precedence_and_defaults() {
        let default_session = SessionData::default();
        assert!(resolve_sudo_nopasswd(false, false, &default_session));
        assert!(resolve_sudo_nopasswd(true, false, &default_session));
        assert!(!resolve_sudo_nopasswd(false, true, &default_session));

        for falsey in ["false", "FALSE", " 0 ", "no", "Off"] {
            let s = SessionData {
                sudo_nopasswd: Some(falsey.to_string()),
                ..SessionData::default()
            };
            assert!(
                !resolve_sudo_nopasswd(false, false, &s),
                "expected '{}' to resolve false",
                falsey
            );
            assert!(
                resolve_sudo_nopasswd(true, false, &s),
                "expected --sudo-nopasswd to override '{}'",
                falsey
            );
        }

        for truthy in ["true", "1", "yes", "ON", "unexpected"] {
            let s = SessionData {
                sudo_nopasswd: Some(truthy.to_string()),
                ..SessionData::default()
            };
            assert!(
                resolve_sudo_nopasswd(false, false, &s),
                "expected '{}' to resolve true",
                truthy
            );
            assert!(
                !resolve_sudo_nopasswd(false, true, &s),
                "expected --no-sudo-nopasswd to override '{}'",
                truthy
            );
        }
    }

    struct MockDestroyServer {
        addr: std::net::SocketAddr,
        requests: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        handle: std::thread::JoinHandle<()>,
    }

    impl MockDestroyServer {
        fn shutdown(self) -> Vec<(String, String)> {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = std::net::TcpStream::connect(self.addr);
            self.handle.join().unwrap();
            self.requests.lock().unwrap().clone()
        }
    }

    fn spawn_destroy_mock_server(fail_tailscale: bool) -> MockDestroyServer {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let addr = listener.local_addr().expect("mock local_addr");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let reqs_clone = Arc::clone(&requests);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let handle = std::thread::spawn(move || {
            let mut ts_device_present = true;
            while !stop_clone.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                if stop_clone.load(Ordering::SeqCst) {
                    break;
                }

                let mut reader = BufReader::new(&stream);
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                    continue;
                }
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let path = parts.next().unwrap_or("").to_string();

                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((name, val)) = trimmed.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("content-length") {
                            content_length = val.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if content_length > 0 {
                    let mut buf = vec![0u8; content_length];
                    let _ = reader.read_exact(&mut buf);
                }

                reqs_clone
                    .lock()
                    .unwrap()
                    .push((method.clone(), path.clone()));

                let (status, reason, body): (u16, &str, String) =
                    match (method.as_str(), path.as_str()) {
                        ("DELETE", p) if p.starts_with("/v2/instances/") => {
                            (204, "No Content", String::new())
                        }
                        ("GET", "/api/v2/tailnet/-/devices") => {
                            if fail_tailscale {
                                (
                                    500,
                                    "Internal Server Error",
                                    r#"{"message":"tailscale api error"}"#.to_string(),
                                )
                            } else if ts_device_present {
                                (
                                    200,
                                    "OK",
                                    r#"{"devices":[{"id":"ts-dev-42","hostname":"ts-edge-box","name":"ts-edge-box.tail123.ts.net","addresses":["100.64.5.6"],"os":"linux","online":true}]}"#.to_string(),
                                )
                            } else {
                                (200, "OK", r#"{"devices":[]}"#.to_string())
                            }
                        }
                        ("DELETE", "/api/v2/device/ts-dev-42") => {
                            ts_device_present = false;
                            (200, "OK", "{}".to_string())
                        }
                        _ => (404, "Not Found", r#"{"error":"not found"}"#.to_string()),
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

        MockDestroyServer {
            addr,
            requests,
            stop,
            handle,
        }
    }

    #[test]
    fn cmd_destroy_removes_matching_tailscale_device_via_mock_servers() -> Result<()> {
        let _lock = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir()?;
        let cfg_dir = dir.path().join("cfg");
        let server = spawn_destroy_mock_server(false);
        let vultr_base = format!("http://{}/v2", server.addr);
        let ts_base = format!("http://{}/api/v2", server.addr);

        let _g_cfg = EnvVarGuard::set("BAB_CONFIG_DIR", cfg_dir.as_os_str());
        let _g_settings = EnvVarGuard::remove("BAB_SETTINGS_FILE");
        let _g_state = EnvVarGuard::remove("BAB_STATE_FILE");
        let _g_log = EnvVarGuard::remove("BAB_LOG_FILE");
        let _g_vultr_key = EnvVarGuard::set("VULTR_API_KEY", std::ffi::OsStr::new("vultr-test-key"));
        let _g_ts_key = EnvVarGuard::set("TAILSCALE_API_KEY", std::ffi::OsStr::new("ts-test-key"));
        let _g_vultr_base =
            EnvVarGuard::set("VULTR_API_BASE", std::ffi::OsStr::new(&vultr_base));
        let _g_vultr_base_url =
            EnvVarGuard::set("VULTR_API_BASE_URL", std::ffi::OsStr::new(&vultr_base));
        let _g_ts_base = EnvVarGuard::set("TAILSCALE_API_BASE", std::ffi::OsStr::new(&ts_base));

        let session = SessionState::load_default()?;
        session.save_session(&SessionData {
            vps_provider: Some("vultr".to_string()),
            vps_instance_id: Some("vultr-ts-1".to_string()),
            vps_ip: Some("100.64.5.6".to_string()),
            tailscale_ip: Some("100.64.5.6".to_string()),
            tailscale_hostname: Some("ts-edge-box".to_string()),
            ..SessionData::default()
        })?;

        let destroy_args = match Cli::try_parse_from([
            "bab",
            "destroy",
            "--id",
            "vultr-ts-1",
            "--provider",
            "vultr",
            "--yes",
        ])?
        .command
        {
            Some(Commands::Destroy(a)) => a,
            other => panic!("unexpected command: {:?}", other),
        };
        let res = cmd_destroy(destroy_args);
        let recorded = server.shutdown();
        res?;

        assert!(recorded
            .iter()
            .any(|(m, p)| m == "DELETE" && p == "/v2/instances/vultr-ts-1"));
        assert!(recorded
            .iter()
            .any(|(m, p)| m == "GET" && p == "/api/v2/tailnet/-/devices"));
        assert!(recorded
            .iter()
            .any(|(m, p)| m == "DELETE" && p == "/api/v2/device/ts-dev-42"));

        assert_eq!(session.vps_instance_id()?, None);

        let log_lines = LogStore::new(cfg_dir.join("bab.log")).read_lines()?;
        assert!(log_lines
            .iter()
            .any(|l| l.contains("[DESTROY] Destroyed Vultr instance 'vultr-ts-1'.")));
        assert!(log_lines.iter().any(|l| {
            l.contains("[TAILSCALE] Removed device(s) from tailnet: ts-edge-box (ts-dev-42)")
        }));
        Ok(())
    }

    #[test]
    fn cmd_destroy_warns_without_failing_when_tailscale_api_fails() -> Result<()> {
        let _lock = ENV_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir()?;
        let cfg_dir = dir.path().join("cfg");
        let server = spawn_destroy_mock_server(true);
        let vultr_base = format!("http://{}/v2", server.addr);
        let ts_base = format!("http://{}/api/v2", server.addr);

        let _g_cfg = EnvVarGuard::set("BAB_CONFIG_DIR", cfg_dir.as_os_str());
        let _g_settings = EnvVarGuard::remove("BAB_SETTINGS_FILE");
        let _g_state = EnvVarGuard::remove("BAB_STATE_FILE");
        let _g_log = EnvVarGuard::remove("BAB_LOG_FILE");
        let _g_vultr_key = EnvVarGuard::set("VULTR_API_KEY", std::ffi::OsStr::new("vultr-test-key"));
        let _g_ts_key = EnvVarGuard::set("TAILSCALE_API_KEY", std::ffi::OsStr::new("ts-test-key"));
        let _g_vultr_base =
            EnvVarGuard::set("VULTR_API_BASE", std::ffi::OsStr::new(&vultr_base));
        let _g_vultr_base_url =
            EnvVarGuard::set("VULTR_API_BASE_URL", std::ffi::OsStr::new(&vultr_base));
        let _g_ts_base = EnvVarGuard::set("TAILSCALE_API_BASE", std::ffi::OsStr::new(&ts_base));

        let destroy_args = match Cli::try_parse_from([
            "bab",
            "destroy",
            "--id",
            "vultr-warn-1",
            "--provider",
            "vultr",
            "--yes",
        ])?
        .command
        {
            Some(Commands::Destroy(a)) => a,
            other => panic!("unexpected command: {:?}", other),
        };
        let res = cmd_destroy(destroy_args);
        let _recorded = server.shutdown();
        res?;

        let log_lines = LogStore::new(cfg_dir.join("bab.log")).read_lines()?;
        assert!(log_lines
            .iter()
            .any(|l| l.contains("[DESTROY] Destroyed Vultr instance 'vultr-warn-1'.")));
        assert!(log_lines
            .iter()
            .any(|l| l.contains("[WARN] Failed to check/remove Tailscale device")));
        Ok(())
    }
}
