# Build A Box (`bab`)

**Build A Box (`bab`)** is a pure-Rust terminal UI (TUI) and CLI tool for provisioning, hardening, and configuring Linux VPS instances across multiple cloud providers with either **Tailscale SSH** or **Standard SSH** transport.

## Highlights

- **Pure Rust TUI & CLI (`bab`)**: Interactive `ratatui` terminal UI (`bab` / `bab tui`) plus scriptable CLI subcommands (`setup`, `roles`, `cloud-init`, `devices`, `settings`, `status`).
- **Four Server Roles**:
  1. **Vanilla (`vanilla`)**: Plain hardened base OS with system updates, non-root `sudo` user, SSH/Tailscale hardening, firewall (`ufw`/`firewalld`), Fail2ban, and unattended security upgrades — without Docker, Caddy, or WireGuard.
  2. **ReverseProxy (`caddy`)**: Docker Engine + hardened daemon defaults + official Caddy reverse proxy (`80/tcp`, `443/tcp+udp`) + `ufw-docker` / `firewalld` hardening.
  3. **VPN Server (`wireguard`)**: WireGuard server (`51820/udp`), IPv4/IPv6 forwarding, auto-generated server and `client1` keys/configs, and `NAT` routing rules.
  4. **Remote Browser Isolation (`rbi`)**: Stub role profile reserved for a future phase.
- **Dual Transport Modes (Tailscale vs. Standard SSH)**:
  - **Tailscale Mode (`--transport tailscale`, default)**: Creates an ephemeral/reusable Tailscale auth key via the Tailscale API, joins the tailnet in cloud-init, enables Tailscale SSH, opens `tailscale0` + `41641/udp`, and closes public TCP port `22`.
  - **Standard SSH Mode (`--transport ssh`)**: Generates or loads an Ed25519 keypair (`~/.ssh/bab_ed25519` by default), injects the public key into `/root/.ssh/authorized_keys` and `/home/<user>/.ssh/authorized_keys`, provisions via provider public IPv4 (no Tailscale API key required), hardens `/etc/ssh/sshd_config` & `/etc/ssh/sshd_config.d/00-bab-hardening.conf` (`PermitRootLogin no`, `PasswordAuthentication no`, `PubkeyAuthentication yes`, `KbdInteractiveAuthentication no`, `MaxAuthTries 3`, `X11Forwarding no`), rate-limits port `22/tcp` (`ufw limit 22/tcp` / `firewalld` SSH service), and enables Fail2ban `[sshd]`.
- **Supported Cloud Providers & Workflows**:
  - **Vultr**, **UpCloud**, **Akamai Connected Cloud / Linode**, plus **Existing Host** and **Manual Cloud-Init** generation.

## Non-Root `sudo` User Configuration

`bab` always creates a non-root administrative user on the target VPS, adds it to the `sudo` (Debian/Ubuntu) or `wheel` (RHEL/AlmaLinux/Rocky/Fedora) group, configures passwordless sudo via `/etc/sudoers.d/<username>` (`0440`), and installs your SSH authorized keys for that user.

Where the username is set:

- **Default**: `deploy`
- **TUI**: Select **Access, User & Transport** from the Home menu and edit **Sudo Username** (`'s'` to save).
- **CLI**: Pass `--user <USERNAME>` on `bab setup` or `bab cloud-init`.
- **State File**: Saved as `USERNAME` in `~/.ssh/.bab-local` (override path with `BAB_STATE_FILE` / `BAB_SSH_DIR`).

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

# Store API keys (written with 0600 permissions to ~/.ssh/.bab-settings)
bab settings --tailscale-key tskey-api-... --vultr-key ... --linode-token ... --upcloud-token ...
bab settings --show

# List available roles and open firewall ports by transport mode
bab roles
bab roles --transport ssh

# Provision & harden a plain Vanilla VPS over Standard SSH (auto-generating ~/.ssh/bab_ed25519)
bab setup \
  --provider vultr \
  --role vanilla \
  --transport ssh \
  --generate-ssh-key \
  --user myadmin \
  --hostname my-vanilla-box

# Provision a Caddy ReverseProxy VPS over Tailscale (public port 22 closed)
bab setup \
  --provider linode \
  --role caddy \
  --transport tailscale \
  --user deploy \
  --hostname edge-proxy

# Generate standalone cloud-init script (Tailscale or Standard SSH)
bab cloud-init --hostname my-box --user myadmin
bab cloud-init --transport ssh --generate-ssh-key --hostname my-box --user myadmin

# Inspect saved box health over its configured transport
bab status
```

## Configuration & State Files

- **`~/.ssh/.bab-settings`** (`0600`): `TAILSCALE_API_KEY`, `VULTR_API_KEY`, `UPCLOUD_API_TOKEN`, `LINODE_API_TOKEN` (override with `BAB_SETTINGS_FILE` or `BAB_SSH_DIR`).
- **`~/.ssh/.bab-local`** (`0600`): `VPS_IP`, `SSH_KEY`, `USERNAME`, `TRANSPORT_MODE`, `VPS_PROVIDER`, `VPS_INSTANCE_ID`, `TAILSCALE_HOSTNAME`, `SERVER_ROLE` (override with `BAB_STATE_FILE` or `BAB_SSH_DIR`).
- **`BAB_SSH_BIN` / `BAB_SCP_BIN` / `BAB_SSH_KEYGEN_BIN`**: Optional binary overrides for SSH/SCP/`ssh-keygen` execution and testing.

## Testing

```bash
cargo clippy --all-targets -- -D warnings
RUSTFLAGS="-D warnings" cargo test
```
