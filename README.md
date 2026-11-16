# bab (Build A Box)

`bab` is a Rust TUI and CLI for spinning up, hardening, and tearing down Linux VPS instances on Vultr, UpCloud, and Akamai/Linode.

Instead of manually clicking through cloud dashboards or maintaining ad-hoc setup scripts, `bab` handles instance creation, cloud-init bootstrapping, user and sudo configuration, SSH/Tailscale lockdown, firewall rules, optional repo deploys, cost estimates, and cleanup from one place.

## Quick start

```bash
cargo build --release
./target/release/bab
```

Run `bab` with no arguments for the interactive terminal UI, or use subcommands (`bab --help`) for scripted runs.

## How it works

### Providers & access modes

`bab` supports **Vultr**, **UpCloud**, and **Linode**, plus configuring an already-running host (`--provider existing`) or printing standalone `cloud-init` output.

Two transport modes are supported:

- **Tailscale SSH** *(default)* — mints an auth key via the Tailscale API, joins your tailnet on first boot, enables Tailscale SSH, and keeps public TCP port `22` closed.
- **Standard SSH** — creates or reuses an Ed25519 key (`~/.ssh/bab_ed25519`), locks down `sshd` (no root login or password auth), rate-limits port `22`, and configures Fail2ban.

The Vultr client prefers IPv4 by default and falls back to dual-stack if needed, so IP-allowlisted API keys don't randomly fail with `401` on dual-stack connections.

### Server roles

- `vanilla` — OS security updates, non-root `sudo` user, SSH/Tailscale hardening, `ufw`/`firewalld`, Fail2ban, and unattended upgrades.
- `caddy` — Docker Engine plus Caddy (`80/tcp`, `443/tcp+udp`) with container-aware firewall rules.
- `wireguard` — WireGuard VPN (`51820/udp`) with IP forwarding, NAT rules, and generated server/`client1` configs.
- `rbi` — reserved placeholder for Remote Browser Isolation (stub only).

### Building multiple boxes & user credentials

Every build creates a fresh instance rather than overwriting an existing box. If your configured hostname is already running on a cloud provider or online in Tailscale, `bab` appends `-2`, `-3`, and so on and generates a new password.

Each VM gets a non-root admin user (default `deploy`) with a random 10-character sudo password. Passwordless sudo (`NOPASSWD:ALL`) is on by default and can be toggled off per box or in settings. Passwords stay masked in the UI (`w` reveals or hides them, and `r` rolls a new one before launch).

### Tracking spend & tearing boxes down

From **Running Systems & Destroy** (or `bab instances`), you can list active VMs across providers alongside hourly/monthly rates and estimated accrued cost. Destroying a box requires pressing `y` explicitly, stops active UpCloud servers first before deleting them, and removes matching nodes from your Tailscale tailnet when `TAILSCALE_API_KEY` is configured.

### TUI navigation

The main menu maps `1`–`9` to provider/role/transport settings, Cloudflare DNS (currently a dry-run/plan stub), GitHub repo deploy, API keys, building a box, managing running instances, and viewing logs (`~/.config/bab/bab.log`). Inside submenus, `q`, `Esc`, or `b` takes you back home; `q` on the home screen exits.

A few handy TUI shortcuts:

- **API Key Settings (`6`)** — paste directly into any field (saved automatically as you edit), `w` to show/hide, `c` to clear, `t` to test the selected key live, or `a` to test all keys. For `cfat_*` Cloudflare Account API tokens, fill in `CLOUDFLARE_ACCOUNT_ID` right below the token field so verification hits `/accounts/<id>/tokens/verify`.
- **Build Box (`7`)** — `d` toggles Cloudflare DNS, `g` toggles GitHub deploy, `p` toggles passwordless sudo, `n` toggles dry-run, `w` toggles password visibility, `r` regenerates the sudo password, and `Enter` starts the build. Bottom panes track the 6 setup steps and show final connection details.
- **Running Systems (`8`)** — `r` refreshes, `w` shows/hides recorded per-box sudo passwords, and `d` followed by `y` destroys the selected instance.

## CLI examples

```bash
# Save API keys (encrypted locally) and test them against live APIs
bab settings \
  --tailscale-key tskey-api-... \
  --vultr-key ... \
  --linode-token ... \
  --upcloud-token ... \
  --cloudflare-token ... \
  --cloudflare-account-id ... \
  --github-token ...

bab settings --show
bab settings --test

# Check cached presets or fetch live regions, plans, and images
bab catalog --provider vultr
bab catalog --provider linode --live

# View server roles and firewall ports by transport mode
bab roles
bab roles --transport ssh

# Spin up a hardened Vanilla box over Standard SSH
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

# Spin up a Caddy proxy over Tailscale with GitHub deploy and Cloudflare DNS stub
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

# Override saved DNS, GitHub deploy, or passwordless sudo settings for one run
bab setup --provider existing --no-cf-dns --no-github-deploy --no-sudo-nopasswd --dry-run

# Deploy/update a repo or plan a Cloudflare A-record on the active box
bab deploy --repo owner/app --branch main --path /home/deploy/apps/app --cmd "docker compose up -d --build"
bab dns --zone example.com --record app --proxied

# List running boxes (aliases: ps, list) or destroy one (aliases: rm, delete)
bab instances
bab ps --provider vultr --all
bab destroy --id vultr-inst-1 --provider vultr --dry-run
bab destroy --id vultr-inst-1 --yes
bab instances --destroy upcloud-uuid-1 -y

# Emit standalone cloud-init scripts or run a status check on the active box
bab cloud-init --hostname my-box --user myadmin
bab cloud-init --transport ssh --generate-ssh-key --hostname my-box --user myadmin
bab status
```

## Config, encryption & logs

State and credentials live in `~/.config/bab/` (`0700`, override with `BAB_CONFIG_DIR`):

- `credentials.enc` (`0600`) — `ChaCha20-Poly1305` encrypted API keys and per-box sudo passwords (override with `BAB_SETTINGS_FILE`). Any provider/service env vars in your shell are automatically encrypted into this file on startup.
- `master.key` (`0600`) — auto-generated 256-bit key for `credentials.enc` (override with `BAB_MASTER_KEY_FILE`, or set `BAB_ENCRYPTION_KEY` to derive a key from a passphrase instead).
- `state.conf` (`0600`) — current box metadata, IPs, transport, role, and toggle flags (override with `BAB_STATE_FILE`).
- `bab.log` (`0600`) — persistent timestamped log shared by the TUI and CLI, capped at 10 MB (override with `BAB_LOG_FILE`).

`BAB_SSH_BIN`, `BAB_SCP_BIN`, and `BAB_SSH_KEYGEN_BIN` can override the system SSH tooling if needed.

## Tests

```bash
cargo clippy --all-targets -- -D warnings
RUSTFLAGS="-D warnings" cargo test
```
