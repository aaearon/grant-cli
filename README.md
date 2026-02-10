# sca-cli

A CLI tool for elevating Azure permissions via CyberArk Secure Cloud Access (SCA) — without leaving the terminal.

## Overview

`sca-cli` enables terminal-based Azure permission elevation through CyberArk SCA. It wraps the `idsec-sdk-golang` SDK for authentication and builds a custom SCA Access API client for JIT role elevation.

## Installation

### Go Install

```bash
go install github.com/aaearon/sca-cli@latest
```

### From Source

```bash
git clone https://github.com/aaearon/sca-cli.git
cd sca-cli
make build
```

## Quick Start

```bash
# First-time setup
sca-cli configure

# Authenticate
sca-cli login

# Elevate permissions (interactive)
sca-cli elevate

# Check active sessions
sca-cli status
```

## Commands

| Command | Description |
|---------|-------------|
| `configure` | First-time setup — configure tenant URL, username, MFA method |
| `login` | Authenticate to CyberArk Identity (interactive, with MFA) |
| `logout` | Clear cached tokens from keyring |
| `elevate` | Elevate cloud permissions (core command) |
| `status` | Show authentication state and active SCA sessions |
| `favorites` | Manage saved role favorites (add/list/remove) |
| `version` | Print version information |

### Elevate

```bash
# Interactive mode — select target from list
sca-cli elevate

# Direct mode — specify target and role
sca-cli elevate --target "Prod-EastUS" --role "Contributor"

# Using a saved favorite
sca-cli elevate --favorite prod-contrib
```

**Flags:**
- `--provider, -p` — Cloud provider (default: `azure`)
- `--target, -t` — Target name (subscription, resource group, etc.)
- `--role, -r` — Role name
- `--favorite, -f` — Use a saved favorite alias
- `--duration, -d` — Requested session duration (policy-controlled)

### Favorites

```bash
# Save a favorite
sca-cli favorites add prod-contrib --target "Prod-EastUS" --role "Contributor"

# List favorites
sca-cli favorites list

# Remove a favorite
sca-cli favorites remove prod-contrib
```

## Configuration

### App Config (`~/.sca-cli/config.yaml`)

```yaml
profile: sca-cli
default_provider: azure

favorites:
  prod-contrib:
    provider: azure
    target: "Prod-EastUS"
    role: "Contributor"
```

### SDK Profile (`~/.idsec_profiles/sca-cli.json`)

Managed by `sca-cli configure` — stores tenant URL, username, and MFA preferences.

## How It Works

For Azure, SCA elevation activates a JIT (just-in-time) role assignment. No Azure credentials are returned — your existing `az` CLI session automatically picks up the elevated permissions.

## License

MIT
