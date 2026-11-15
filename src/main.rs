use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use bab::config::{default_config_dir, SessionData, SessionState, Settings};
use bab::dns::{build_cloudflare_dns_stub_plan, CloudflareDnsConfig};
use bab::providers::linode::LinodeProvider;
use bab::providers::upcloud::UpCloudProvider;
use bab::providers::vultr::VultrProvider;
use bab::providers::{
    default_images_for, default_plans_for, default_regions_for, provision_full_flow,
    ProvisionConfig, ProviderKind, VpsProvider,
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
    Ok(())
}

fn persist_cf_session(session: &SessionState, dns: &CloudflareDnsConfig) -> Result<()> {
    session.set_cf_zone(&dns.zone)?;
    session.set_cf_record(&dns.record_name)?;
    session.set_cf_target(&dns.target_ip)?;
    session.set_cf_proxied(if dns.proxied { "true" } else { "false" })?;
    Ok(())
}

fn cmd_setup(args: SetupArgs) -> Result<()> {
    let settings = Settings::load_default()?;
    let session = SessionState::load_default()?;
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
    if let (Some(ref zone), Some(ref record)) = (&cf_zone_clean, &cf_record_clean) {
        build_cloudflare_dns_stub_plan(
            &CloudflareDnsConfig {
                zone: zone.clone(),
                record_name: record.clone(),
                target_ip: "203.0.113.10".to_string(),
                proxied: args.cf_proxied,
            },
            false,
        )?;
    }

    let github_deploy = args
        .github_repo
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|repo| -> Result<GithubDeployConfig> {
            let github_token = settings
                .github_token()?
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            Ok(GithubDeployConfig {
                repo: repo.to_string(),
                branch: args
                    .github_branch
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("main")
                    .to_string(),
                deploy_path: args
                    .github_path
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from),
                deploy_cmd: args
                    .github_cmd
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from),
                github_token,
                username: args.user.clone(),
            })
        })
        .transpose()?;

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
                was_provisioned = true;
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

    let cf_dns_cfg = if let (Some(zone), Some(record_name)) = (cf_zone_clean, cf_record_clean) {
        let dns_target = resolved_public_ip
            .clone()
            .or_else(|| resolved_tailscale_ip.clone())
            .unwrap_or_else(|| target.clone());
        let has_cf_token = settings
            .cloudflare_api_token()?
            .is_some_and(|t| !t.trim().is_empty());
        let dns_cfg = CloudflareDnsConfig {
            zone,
            record_name,
            target_ip: dns_target,
            proxied: args.cf_proxied,
        };
        let stub_plan = build_cloudflare_dns_stub_plan(&dns_cfg, has_cf_token)?;
        println!("{}", stub_plan);
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
                key_path: key_path_opt,
                catalog: (
                    resolved_region.as_deref(),
                    resolved_plan.as_deref(),
                    resolved_image.as_deref(),
                ),
                provisioned_ips,
            },
        )?;
        if let Some(ref gh) = github_deploy {
            persist_github_session(&session, gh)?;
        }
        if let Some(ref dns) = cf_dns_cfg {
            persist_cf_session(&session, dns)?;
        }
    }

    println!("\n=== Final Box Information ===");
    println!(
        "Public IP:             {}",
        resolved_public_ip.as_deref().unwrap_or("(none)")
    );
    println!(
        "Tailscale IP:          {}",
        resolved_tailscale_ip.as_deref().unwrap_or("(none)")
    );
    println!("Active Target IP:      {}", target);
    println!(
        "Provider:              {} (region: {}, plan: {}, image: {})",
        args.provider.label(),
        resolved_region.as_deref().unwrap_or("N/A"),
        resolved_plan.as_deref().unwrap_or("N/A"),
        resolved_image.as_deref().unwrap_or("N/A")
    );
    println!("Role:                  {} ({})", args.role.label(), args.role);
    println!(
        "Transport Mode:        {}",
        if tailscale_mode {
            "Tailscale SSH"
        } else {
            "Standard SSH"
        }
    );
    println!("Sudo User:             {}", args.user);
    if let Some(ref dns) = cf_dns_cfg {
        println!(
            "Cloudflare DNS:        {} -> {} (zone: {}, proxied: {})",
            dns.record_name, dns.target_ip, dns.zone, dns.proxied
        );
    }
    if let Some(ref gh) = github_deploy {
        println!(
            "GitHub Repo:           {} (branch: {}, path: {})",
            gh.repo,
            gh.branch,
            gh.deploy_path
                .as_deref()
                .unwrap_or("(default /home/<user>/apps/<repo>)")
        );
    }
    println!(
        "Encrypted Credentials: {} (0600, ChaCha20-Poly1305)",
        settings.path().display()
    );
    println!(
        "Master Key:            {} (0600)",
        settings.key_file_path().display()
    );

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
    let output = runner.deploy_github(&ssh_user, &target, &gh_cfg, args.dry_run)?;

    let tag = if args.dry_run { "DRY-RUN" } else { "OK" };
    println!("[{}] GitHub Deploy ({})", tag, gh_cfg.repo);
    if !output.trim().is_empty() {
        println!("{}", output.trim_end());
    }

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
                key_path: None,
                catalog: (None, None, None),
                provisioned_ips: None,
            },
        )?;
        assert_eq!(state.transport_mode()?.as_deref(), Some("tailscale"));
        assert_eq!(state.ssh_key()?.as_deref(), Some("tailscale"));

        // Switch to SSH mode with --ssh-pubkey (key_path_opt == None): clears stale "tailscale".
        persist_setup_session(
            &state,
            &SetupSessionUpdate {
                provider: ProviderKind::Vultr,
                target: "203.0.113.20",
                username: "ops",
                hostname: "ssh-box",
                tailscale_mode: false,
                key_path: None,
                catalog: (Some("ewr"), Some("vc2-1c-1gb"), Some("2284")),
                provisioned_ips: None,
            },
        )?;
        assert_eq!(state.transport_mode()?.as_deref(), Some("ssh"));
        assert_eq!(state.ssh_key()?.as_deref(), Some(""));
        assert_eq!(state.vps_ip()?.as_deref(), Some("203.0.113.20"));

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
}
