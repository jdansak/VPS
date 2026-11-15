# Build A Box (`bab`)

**Build A Box (`bab`)** is a pure-Rust terminal UI (TUI) and CLI tool for provisioning, hardening, and configuring Linux VPS instances across multiple cloud providers with either **Tailscale SSH** or **Standard SSH** transport.

## Highlights

- **Pure Rust TUI & CLI (`bab`)**: Interactive `ratatui` terminal UI (`bab` / `bab tui`) plus scriptable CLI subcommands (`setup`, `catalog`, `dns`, `deploy`, `roles`, `cloud-init`, `devices`, `settings`, `status`).
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
  - Inspect curated or live provider regions, machine sizes (plans), and OS images via `bab catalog --provider <vultr|upcloud|linode> [--live]`, pass `--region`, `--plan`, `--image` to `bab setup`, or choose interactively in the TUI under **Select Provider, Location & Size**.
- **Persistent TUI Bottom Pane**:
  - Displays live provisioning/setup progress alongside the **Final Connection Info** summary (`Public IP`, `Tailscale IP`, `Active Target`, `Provider/Region/Plan/Image`, `Role`, `Transport`, `Cloudflare DNS`, and `GitHub Repo`) across screens.
- **Cloudflare DNS (Stub)**:
  - Plan and record an A-record upsert with `bab dns --zone <ZONE> --record <NAME> [--ip <IP>] [--proxied]` or via `--cf-zone` / `--cf-record` / `--cf-proxied` on `bab setup`, or in the TUI under **Cloudflare DNS (Stub)**.
- **GitHub Repository Deployment**:
  - Clone/update and deploy public or private GitHub repositories idempotently with `bab deploy --repo <REPO> [--branch <BRANCH>] [--path <PATH>] [--cmd <CMD>]`, via `--github-repo` flags on `bab setup`, or in the TUI under **GitHub Repo Deployment**. Private repositories authenticate using the stored `GITHUB_TOKEN` via an ephemeral `0700` `GIT_ASKPASS` helper script cleaned up on exit.
- **Encrypted API Key Storage**:
  - API keys and tokens (`TAILSCALE_API_KEY`, `VULTR_API_KEY`, `UPCLOUD_API_TOKEN`, `LINODE_API_TOKEN`, `CLOUDFLARE_API_TOKEN`, `GITHUB_TOKEN`) are encrypted at rest with **ChaCha20-Poly1305** (`enc:v1:`) in `~/.config/bab/credentials.enc` (`0600`) using an auto-generated `~/.config/bab/master.key` (`0600`) inside `~/.config/bab` (`0700`), or deterministically derived from `BAB_ENCRYPTION_KEY`.

## Non-Root `sudo` User Configuration

`bab` always creates a non-root administrative user on the target VPS, adds it to the `sudo` (Debian/Ubuntu) or `wheel` (RHEL/AlmaLinux/Rocky/Fedora) group, configures passwordless sudo via `/etc/sudoers.d/<username>` (`0440`), and installs your SSH authorized keys for that user.

Where the username is set:

- **Default**: `deploy`
- **TUI**: Select **Access, User & Transport** from the Home menu and edit **Sudo Username** (`'s'` to save).
- **CLI**: Pass `--user <USERNAME>` on `bab setup`, `bab deploy`, or `bab cloud-init`.
- **State File**: Saved as `USERNAME` in `~/.config/bab/state.conf` (override path with `BAB_STATE_FILE` / `BAB_CONFIG_DIR`).

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

# Generate standalone cloud-init script (Tailscale or Standard SSH)
bab cloud-init --hostname my-box --user myadmin
bab cloud-init --transport ssh --generate-ssh-key --hostname my-box --user myadmin

# Inspect saved box health over its configured transport
bab status
```

## Configuration & State Files

- **`~/.config/bab/`** (`0700`): Default configuration directory (override with `BAB_CONFIG_DIR` or legacy `BAB_SSH_DIR` / `VPSKIT_SSH_DIR` / `SSH_DIR`).
- **`~/.config/bab/credentials.enc`** (`0600`): `ChaCha20-Poly1305` (`enc:v1:`) encrypted API keys and tokens (`TAILSCALE_API_KEY`, `VULTR_API_KEY`, `UPCLOUD_API_TOKEN`, `LINODE_API_TOKEN`, `CLOUDFLARE_API_TOKEN`, `GITHUB_TOKEN`; override path with `BAB_SETTINGS_FILE`).
- **`~/.config/bab/master.key`** (`0600`): Auto-generated 256-bit base64 master key used for `credentials.enc` (override path with `BAB_MASTER_KEY_FILE`, or set `BAB_ENCRYPTION_KEY` to derive the key from a passphrase instead of using `master.key`).
- **`~/.config/bab/state.conf`** (`0600`): Saved session state including `VPS_IP`, `PUBLIC_IP`, `TAILSCALE_IP`, `SSH_KEY`, `USERNAME`, `TRANSPORT_MODE`, `VPS_PROVIDER`, `VPS_INSTANCE_ID`, `VPS_REGION`, `VPS_PLAN`, `VPS_IMAGE`, `TAILSCALE_HOSTNAME`, `SERVER_ROLE`, `CF_ZONE`, `CF_RECORD`, `CF_TARGET`, `CF_PROXIED`, `GITHUB_REPO`, `GITHUB_BRANCH`, `GITHUB_DEPLOY_PATH`, `GITHUB_DEPLOY_CMD` (override path with `BAB_STATE_FILE`).
- **`BAB_SSH_BIN` / `BAB_SCP_BIN` / `BAB_SSH_KEYGEN_BIN`**: Optional binary overrides for SSH/SCP/`ssh-keygen` execution and testing.

## Testing

```bash
cargo clippy --all-targets -- -D warnings
RUSTFLAGS="-D warnings" cargo test
```
