# Build A Box (`bab`)

**Build A Box (`bab`)** is a pure-Rust terminal UI (TUI) and CLI tool for provisioning, hardening, and configuring Linux VPS instances across multiple cloud providers with either **Tailscale SSH** or **Standard SSH** transport.

## Highlights

- **Pure Rust TUI & CLI (`bab`)**: Interactive `ratatui` terminal UI (`bab` / `bab tui`) plus scriptable CLI subcommands (`setup`, `instances` / `ps` / `list`, `destroy` / `rm` / `delete`, `catalog`, `dns`, `deploy`, `roles`, `cloud-init`, `devices`, `settings`, `status`).
- **Interactive TUI (10-Item Home Menu)**:
  1. **Select Provider, Location & Size**
  2. **Select Server Role**
  3. **Access, User & Transport** (includes synced `SUDO_NOPASSWD` Passwordless Sudo ON/OFF toggle)
  4. **Cloudflare DNS** (includes synced `CF_ENABLED` ON/OFF toggle)
  5. **GitHub Repo Deployment** (includes synced `GITHUB_ENABLED` ON/OFF toggle)
  6. **API Key Settings** (`Screen::ApiKeys`): supports bracketed paste directly into any selected or edited key field (including `CLOUDFLARE_API_TOKEN` and `GITHUB_TOKEN`), Show/Hide (`w`), Clear (`c` / `Delete` / `Backspace`, or `Ctrl+U` while editing), live key testing (`t` to test selected key, `a` to test all configured keys; or `bab settings --test` in CLI), and automatic encrypted persistence as you edit.
  7. **Build Box with Current Options** (`Screen::BuildBox`): review current configuration, toggle Cloudflare DNS ON/OFF (`d` / `Space`), GitHub Repo Deployment ON/OFF (`g`), and Passwordless Sudo ON/OFF (`p`), show/hide (`w`) or regenerate (`r`) the 10-character sudo password, toggle Dry-Run (`n`), and run provisioning + setup (`Enter` / `x`). Bright green (`ON`) and bright red (`OFF`) toggle indicators stay synced across **Access, User & Transport**, **Cloudflare DNS**, **GitHub Repo Deployment**, and **Build Box with Current Options**.
  8. **Running Systems & Destroy** (`Screen::RunningInstances`): query live instances across configured Vultr, UpCloud, and Linode accounts (`r` to refresh), inspect status/IPs/region/plan, running cost tracking (per-instance `COST` column, `Total Cost:` across priced instances, and detailed `accrued`, uptime, hourly, and monthly rates in the selected-instance bar), and recorded per-box sudo passwords (`w` to Show/Hide Password), and destroy selected instances (`d` / `x` / `Delete` with strict `'y'` confirmation — never `Enter` — automatically removing any matching device from your Tailscale tailnet).
  9. **`[9]` View Log** (`Screen::ViewLog`): inspect persistent timestamped logs stored in `~/.config/bab/bab.log` (`j`/`k` or `Up`/`Down` to scroll, `PgUp`/`PgDn` to page, `g`/`G` to jump to top/bottom, `r` to reload from disk, `c` to clear).
  10. **`[0]` Quit** (`0` or `q` on the Home screen).
  - **Consistent Back Navigation**: Pressing `q`, `Esc`, or `b` from any submenu returns to the **Home** screen instead of exiting the application (when not editing a field or confirming an action).
- **Four Server Roles**:
  1. **Vanilla (`vanilla`)**: Plain hardened base OS with system updates, non-root `sudo` user, SSH/Tailscale hardening, firewall (`ufw`/`firewalld`), Fail2ban, and unattended security upgrades — without Docker, Caddy, or WireGuard.
  2. **ReverseProxy (`caddy`)**: Docker Engine + hardened daemon defaults + official Caddy reverse proxy (`80/tcp`, `443/tcp+udp`) + `ufw-docker` / `firewalld` hardening.
  3. **VPN Server (`wireguard`)**: WireGuard server (`51820/udp`), IPv4/IPv6 forwarding, auto-generated server and `client1` keys/configs, and `NAT` routing rules.
  4. **Remote Browser Isolation (`rbi`)**: Stub role profile reserved for a future phase.
- **Dual Transport Modes (Tailscale vs. Standard SSH)**:
  - **Tailscale Mode (`--transport tailscale`, default)**: Creates an ephemeral/reusable Tailscale auth key via the Tailscale API, joins the tailnet in cloud-init, enables Tailscale SSH, opens `tailscale0` + `41641/udp`, and closes public TCP port `22`.
  - **Standard SSH Mode (`--transport ssh`)**: Generates or loads an Ed25519 keypair (`~/.ssh/bab_ed25519` by default), injects the public key into `/root/.ssh/authorized_keys` and `/home/<user>/.ssh/authorized_keys`, provisions via provider public IPv4 (no Tailscale API key required), hardens `/etc/ssh/sshd_config` & `/etc/ssh/sshd_config.d/00-bab-hardening.conf` (`PermitRootLogin no`, `PasswordAuthentication no`, `PubkeyAuthentication yes`, `KbdInteractiveAuthentication no`, `MaxAuthTries 3`, `X11Forwarding no`), rate-limits port `22/tcp` (`ufw limit 22/tcp` / `firewalld` SSH service), and enables Fail2ban `[sshd]`.
- **Supported Cloud Providers & Catalog Selection**:
  - **Vultr**, **UpCloud**, **Akamai Connected Cloud / Linode**, plus **Existing Host** and **Manual Cloud-Init** generation.
  - The Vultr client binds an **IPv4-first** local address by default (falling back automatically to dual-stack if needed) so IP-whitelisted Vultr API keys authenticate reliably on dual-stack hosts without hitting IPv6 `401 Unauthorized IP address` errors.
  - Inspect curated or live provider regions, machine sizes (plans), and OS images via `bab catalog --provider <vultr|upcloud|linode> [--live]`, pass `--region`, `--plan`, `--image` to `bab setup`, or choose interactively in the TUI under **Select Provider, Location & Size**.
- **Persistent TUI Bottom Pane**:
  - Displays a clean **Setup Progress** step-status pane (step gauge plus the 6 setup steps with `[x]` / `[>]` / `[!]` / `[ ]` status indicators instead of duplicate bottom logs; full logs remain on **Build Box with Current Options** and **`[9]` View Log**) alongside the **Final Connection Info** summary (`Public IP`, `Tailscale IP`, `Active Target`, `Provider/Region/Plan/Image`, `Role`, `Transport`, `Cloudflare DNS`, and `GitHub Repo`) across screens.
- **Cloudflare DNS (Stub) & Toggle**:
  - Plan and record an A-record upsert with `bab dns --zone <ZONE> --record <NAME> [--ip <IP>] [--proxied]` or via `--cf-zone` / `--cf-record` / `--cf-proxied` on `bab setup`, or in the TUI under **Cloudflare DNS**.
  - Enable or skip the Cloudflare DNS step during `bab setup` with `--cf-dns` (uses saved `CF_ZONE` / `CF_RECORD` / `CF_TARGET` / `CF_PROXIED`) or `--no-cf-dns`, or toggle `CF_ENABLED` ON/OFF directly on the TUI **Cloudflare DNS** (`t`) and **Build Box with Current Options** (`d` / `Space`) screens.
- **Cross-Provider Instance Listing & Destruction**:
  - Query running instances across Vultr, UpCloud, and Akamai/Linode in the TUI (**Running Systems & Destroy**) or via `bab instances` (aliases `ps`, `list`; supports `--provider`, `--all`, `--destroy <ID>`, `-y/--yes`) and `bab destroy` (aliases `rm`, `delete`; supports `--id <ID>`, `--provider`, `-y/--yes`, `--dry-run`). UpCloud servers that are still running are automatically stopped (`POST /1.3/server/<id>/stop`) before deletion, matching Tailscale network devices are automatically removed from your tailnet when `TAILSCALE_API_KEY` is configured (in both TUI and CLI `bab destroy` / `bab instances --destroy`), and matching active session state in `state.conf` is cleared automatically.
  - **Running Cost Tracking**: Both `bab instances` (via the `COST` column) and the TUI **Running Systems & Destroy** screen estimate `accrued` running spend from instance creation time alongside hourly and monthly plan rates (falling back to monthly/hourly rates when creation timestamps are unavailable), while **Running Systems & Destroy** also shows a `Total Cost:` summary across priced instances.
- **GitHub Repository Deployment & Toggle**:
  - Clone/update and deploy public or private GitHub repositories idempotently with `bab deploy --repo <REPO> [--branch <BRANCH>] [--path <PATH>] [--cmd <CMD>]`, via `--github-repo` flags on `bab setup`, or in the TUI under **GitHub Repo Deployment**. Private repositories authenticate using the stored `GITHUB_TOKEN` via an ephemeral `0700` `GIT_ASKPASS` helper script cleaned up on exit.
  - Enable or skip GitHub deployment during `bab setup` with `--github-deploy` (uses saved `GITHUB_REPO` / `GITHUB_BRANCH` / `GITHUB_DEPLOY_PATH` / `GITHUB_DEPLOY_CMD`) or `--no-github-deploy`, or toggle `GITHUB_ENABLED` ON/OFF directly on the TUI **GitHub Repo Deployment** (`t`) and **Build Box with Current Options** (`g`) screens (with synced bright green `ON` / bright red `OFF` styling matching **Cloudflare DNS**).
- **Automatic Encrypted API Key Persistence**:
  - API keys and tokens (`TAILSCALE_API_KEY`, `VULTR_API_KEY`, `UPCLOUD_API_TOKEN`, `LINODE_API_TOKEN`, `CLOUDFLARE_API_TOKEN`, `GITHUB_TOKEN`) are encrypted at rest with **ChaCha20-Poly1305** (`enc:v1:`) in `~/.config/bab/credentials.enc` (`0600`) using an auto-generated `~/.config/bab/master.key` (`0600`) inside `~/.config/bab` (`0700`), or deterministically derived from `BAB_ENCRYPTION_KEY`.
  - Any API keys supplied via environment variables are automatically encrypted and persisted to `credentials.enc` whenever `Settings::load_default()` runs (on CLI invocations and TUI startup), and edits in the TUI **API Key Settings** screen are automatically encrypted and saved (or removed from `credentials.enc` when cleared) as you finish editing without needing to press `s`.

## Non-Root `sudo` User Configuration

`bab` always creates a non-root administrative user on the target VPS, adds it to the `sudo` (Debian/Ubuntu) or `wheel` (RHEL/AlmaLinux/Rocky/Fedora) group, assigns a randomly generated 10-character sudo password (`SUDO_PASSWORD`, stored encrypted per box in `credentials.enc` and in `state.conf`), configures passwordless sudo (`NOPASSWD:ALL`) via `/etc/sudoers.d/<username>` (`0440`) when **Passwordless Sudo (`SUDO_NOPASSWD`)** is `ON` (or removes `/etc/sudoers.d/<username>` after setup completes when `OFF` so `sudo` prompts for that password), and installs your SSH authorized keys for that user.

Where the username, sudo password, and passwordless sudo setting are configured:

- **Default**: username `deploy`, randomly generated 10-character `SUDO_PASSWORD`, passwordless sudo `ON` (`SUDO_NOPASSWD=true`)
- **TUI**: Select **Access, User & Transport** (`[3]`) from the Home menu to edit **Sudo Username** (`'s'` to save) or toggle **Passwordless Sudo** ON/OFF (`Space`/`Enter`/`Left`/`Right` on that field or `'p'`). On **Build Box with Current Options** (`[7]`), press `'p'` to toggle Passwordless Sudo, `'w'` to Show/Hide Password, and `'r'` to Regenerate a new 10-character password. On **Running Systems & Destroy** (`[8]`), press `'w'` to Show/Hide per-box sudo passwords.
- **CLI**: Pass `--user <USERNAME>` on `bab setup`, `bab deploy`, or `bab cloud-init`, and pass `--sudo-nopasswd` or `--no-sudo-nopasswd` on `bab setup` (overrides saved `SUDO_NOPASSWD`). `bab setup` prints the active `Sudo Password` under `=== Final Box Information ===` and records it per box in `credentials.enc` and `state.conf`.
- **State & Credentials Files**: Saved as `USERNAME`, `SUDO_NOPASSWD`, and `SUDO_PASSWORD` in `~/.config/bab/state.conf`, plus encrypted per-box entries (`SUDO_PASSWORD`, `BOX_PASS_ID_*`, `BOX_PASS_HOST_*`, `BOX_PASS_IP_*`) in `~/.config/bab/credentials.enc` (override paths with `BAB_STATE_FILE` / `BAB_SETTINGS_FILE` / `BAB_CONFIG_DIR`).

## Quick Start

### Build & Run

```bash
cargo build --release
./target/release/bab
```

### Common CLI Examples

```bash
# Launch interactive TUI
bab

# Store API keys (encrypted with ChaCha20-Poly1305 in ~/.config/bab/credentials.enc)
bab settings --tailscale-key tskey-api-... --vultr-key ... --linode-token ... --upcloud-token ... --cloudflare-token ... --github-token ...
bab settings --show
# Validate all configured API keys against their live APIs
bab settings --test

# Inspect curated or live provider regions, plans, and images
bab catalog --provider vultr
bab catalog --provider linode --live

# List available roles and open firewall ports by transport mode
bab roles
bab roles --transport ssh

# Provision & harden a plain Vanilla VPS over Standard SSH (auto-generating ~/.ssh/bab_ed25519)
bab setup \
  --provider vultr \
  --region ewr \
  --plan vc2-1c-1gb \
  --image 2284 \
  --role vanilla \
  --transport ssh \
  --generate-ssh-key \
  --user myadmin \
  --hostname my-vanilla-box

# Provision a Caddy ReverseProxy VPS over Tailscale with GitHub deploy and Cloudflare DNS stub
bab setup \
  --provider linode \
  --region us-east \
  --plan g6-nanode-1 \
  --role caddy \
  --transport tailscale \
  --user deploy \
  --hostname edge-proxy \
  --github-repo owner/app \
  --github-branch main \
  --cf-zone example.com \
  --cf-record app \
  --cf-proxied

# Deploy or update a GitHub repository on the configured VPS
bab deploy --repo owner/app --branch main --path /home/deploy/apps/app --cmd "docker compose up -d --build"

# Preview or update the Cloudflare DNS stub plan for the active VPS
bab dns --zone example.com --record app --proxied

# Run setup using saved Cloudflare DNS settings (--cf-dns) or skip DNS (--no-cf-dns)
bab setup --provider existing --cf-dns --dry-run
bab setup --provider existing --no-cf-dns --dry-run

# Run setup using saved GitHub deployment settings (--github-deploy) or skip GitHub deploy (--no-github-deploy)
bab setup --provider existing --github-deploy --dry-run
bab setup --provider existing --no-github-deploy --dry-run

# Require a password for sudo (--no-sudo-nopasswd) or grant passwordless NOPASSWD:ALL (--sudo-nopasswd)
bab setup --provider existing --no-sudo-nopasswd --dry-run
bab setup --provider existing --sudo-nopasswd --dry-run

# List running instances across configured cloud providers (aliases: ps, list)
bab instances
bab ps --provider vultr --all

# Preview or destroy a cloud instance by ID (aliases: rm, delete)
bab destroy --id vultr-inst-1 --provider vultr --dry-run
bab destroy --id vultr-inst-1 --yes
bab instances --destroy upcloud-uuid-1 -y

# Generate standalone cloud-init script (Tailscale or Standard SSH)
bab cloud-init --hostname my-box --user myadmin
bab cloud-init --transport ssh --generate-ssh-key --hostname my-box --user myadmin

# Inspect saved box health over its configured transport
bab status
```

## Configuration & State Files

- **`~/.config/bab/`** (`0700`): Default configuration directory (override with `BAB_CONFIG_DIR` or legacy `BAB_SSH_DIR` / `VPSKIT_SSH_DIR` / `SSH_DIR`).
- **`~/.config/bab/credentials.enc`** (`0600`): `ChaCha20-Poly1305` (`enc:v1:`) encrypted API keys, tokens (`TAILSCALE_API_KEY`, `VULTR_API_KEY`, `UPCLOUD_API_TOKEN`, `LINODE_API_TOKEN`, `CLOUDFLARE_API_TOKEN`, `GITHUB_TOKEN`), and per-box sudo passwords (`SUDO_PASSWORD`, `BOX_PASS_ID_*`, `BOX_PASS_HOST_*`, `BOX_PASS_IP_*`; override path with `BAB_SETTINGS_FILE`).
- **`~/.config/bab/master.key`** (`0600`): Auto-generated 256-bit base64 master key used for `credentials.enc` (override path with `BAB_MASTER_KEY_FILE`, or set `BAB_ENCRYPTION_KEY` to derive the key from a passphrase instead of using `master.key`).
- **`~/.config/bab/state.conf`** (`0600`): Saved session state including `VPS_IP`, `PUBLIC_IP`, `TAILSCALE_IP`, `SSH_KEY`, `USERNAME`, `SUDO_NOPASSWD`, `SUDO_PASSWORD`, `TRANSPORT_MODE`, `VPS_PROVIDER`, `VPS_INSTANCE_ID`, `VPS_REGION`, `VPS_PLAN`, `VPS_IMAGE`, `TAILSCALE_HOSTNAME`, `SERVER_ROLE`, `CF_ZONE`, `CF_RECORD`, `CF_TARGET`, `CF_PROXIED`, `CF_ENABLED`, `GITHUB_REPO`, `GITHUB_BRANCH`, `GITHUB_DEPLOY_PATH`, `GITHUB_DEPLOY_CMD`, `GITHUB_ENABLED` (override path with `BAB_STATE_FILE`).
- **`~/.config/bab/bab.log`** (`0600`): Persistent timestamped activity log shared by TUI builds/destroys and CLI `setup`, `deploy`, and `destroy` runs, with an auto-trimmed 10 MB cap (override path with `BAB_LOG_FILE`).
- **`BAB_SSH_BIN` / `BAB_SCP_BIN` / `BAB_SSH_KEYGEN_BIN`**: Optional binary overrides for SSH/SCP/`ssh-keygen` execution and testing.

## Testing

```bash
cargo clippy --all-targets -- -D warnings
RUSTFLAGS="-D warnings" cargo test
```
