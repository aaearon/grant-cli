# grant

A CLI tool for elevating cloud permissions (Azure, AWS) via CyberArk Secure Cloud Access (SCA) — without leaving the terminal.

![grant demo](demo/demo.gif)

## Overview

`grant` enables terminal-based cloud permission elevation (Azure, AWS) through CyberArk SCA. It wraps the `idsec-sdk-golang` SDK for authentication and builds a custom SCA Access API client for JIT role elevation.

- **Azure:** SCA creates a JIT RBAC role assignment — your existing `az` CLI session picks up the elevated permissions automatically.
- **AWS:** SCA returns temporary credentials. Use `grant env` to export them: `eval $(grant env --provider aws)`

## Usage

```bash
# Authenticate (one-time setup)
grant login

# Elevate permissions interactively (shows all providers)
grant

# Elevate for a specific provider
grant --provider azure
grant --provider aws

# Direct elevation with target and role
grant --provider azure --target "Prod-EastUS" --role "Contributor"

# Export AWS credentials to your shell
eval $(grant env --provider aws)

# Use a saved favorite
grant --favorite prod-contrib

# Elevate Entra ID group membership
grant --groups
grant --group "Cloud Admins"

# List eligible targets (no elevation)
grant list
grant list --provider azure
grant list --output json

# Check active sessions
grant status

# Revoke sessions
grant revoke                        # interactive multi-select
grant revoke <session-id>           # direct by ID
grant revoke --all                  # revoke all
```

![grant env demo](demo/demo-env-status.gif)

## Installation

### Binary Releases (Recommended)

Download pre-built binaries from the [Releases](https://github.com/aaearon/grant-cli/releases) page.

```bash
# macOS / Linux (adjust OS and ARCH as needed)
VERSION=$(gh release view --repo aaearon/grant-cli --json tagName -q '.tagName' | tr -d v)
OS=linux ARCH=amd64  # darwin/amd64, darwin/arm64, linux/amd64, linux/arm64
curl -LO "https://github.com/aaearon/grant-cli/releases/download/v${VERSION}/grant-cli_${VERSION}_${OS}_${ARCH}.tar.gz"
tar xzf "grant-cli_${VERSION}_${OS}_${ARCH}.tar.gz"
sudo mv grant /usr/local/bin/

# Self-update
grant update
```

**Windows:** Download `grant-cli_<version>_windows_<arch>.zip` from [releases](https://github.com/aaearon/grant-cli/releases) and extract to a directory in your PATH.

### Go Install

```bash
go install github.com/aaearon/grant-cli@latest
```

### From Source

```bash
git clone https://github.com/aaearon/grant-cli.git
cd grant-cli
make build
```

## Commands

Running `grant` with no subcommand elevates cloud permissions (the core behavior).

| Command | Description |
|---------|-------------|
| `grant` | Elevate cloud permissions (interactive, direct with `--target`/`--role`, or `--favorite`) |
| `configure` | Configure Identity URL and username (optional — `login` auto-configures) |
| `env` | Elevate and output AWS credential export statements for `eval $(grant env)` |
| `list` | List eligible targets and groups without elevation (`--provider`, `--groups`, `--output json`) |
| `login` | Authenticate to CyberArk Identity (MFA handled interactively) |
| `logout` | Clear cached tokens from keyring |
| `status` | Show auth state and active sessions |
| `favorites` | Manage saved role favorites (`add`/`list`/`remove`) |
| `revoke` | Revoke sessions (interactive, by ID, or `--all`) |
| `update` | Self-update to the latest release from GitHub |
| `version` | Print version information |

### Flags

**Global:** `--verbose, -v` (detailed output) | `--output, -o` (`text` or `json`)

**Elevation** (`grant`, `env`, `favorites add`):
`--provider, -p` | `--target, -t` | `--role, -r` | `--favorite, -f` | `--group, -g` | `--groups` | `--refresh`

Target matching is case-insensitive and supports partial match; interactive mode provides fuzzy search.

## Configuration

### App Config (`~/.grant/config.yaml`)

Override path with `GRANT_CONFIG` environment variable.

```yaml
profile: grant              # SDK profile name
default_provider: azure     # Default cloud provider
cache_ttl: 4h               # Eligibility cache TTL (Go duration syntax)

favorites:
  prod-contrib:
    provider: azure
    target: "Prod-EastUS"
    role: "Contributor"
  aws-admin:
    provider: aws
    target: "Production"
    role: "AdministratorAccess"
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GRANT_CONFIG` | Custom path to app config YAML | `~/.grant/config.yaml` |
| `IDSEC_LOG_LEVEL` | SDK log level (`DEBUG`, `INFO`, `CRITICAL`) — overrides `--verbose` | Not set |

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Azure CLI doesn't see new role after elevation | Refresh token: `az account get-access-token --output none` (or `az account clear && az login`) |
| "No eligible targets found" | Verify SCA policies with your CyberArk admin; try without `--provider` to see all targets |
| "Failed to elevate" | Check `grant status` for active sessions; verify target/role names |
| `grant env` errors for Azure | `env` is AWS-only — Azure doesn't return credentials, use `grant` directly |
| Permission denied accessing keyring (Linux) | Install and start `gnome-keyring` or `kwalletmanager` |

## Development

```bash
make build              # Build binary
make test               # Unit tests
make test-integration   # Integration tests (builds binary)
make test-all           # All tests
make lint               # Lint (golangci-lint)
```

## Contributing

Contributions welcome! Please follow existing patterns, write tests (TDD preferred), update docs, and use conventional commits.

## License

MIT
