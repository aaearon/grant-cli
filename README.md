# grant

A CLI tool for elevating cloud permissions (Azure, AWS) via Idira (formerly CyberArk) Secure Cloud Access (SCA) — without leaving the terminal.

![grant demo](demo/demo.gif)

## Overview

`grant` enables terminal-based cloud permission elevation (Azure, AWS) through Idira SCA. It wraps the `idsec-sdk-golang` SDK for authentication and builds a custom SCA Access API client for JIT role elevation.

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

# Access request workflow
grant request submit                # interactive: pick workspace, role, fill details
grant request submit --provider azure --target "Prod" --role "Contributor" --reason "Incident"
grant request list                  # list your requests
grant request list --state PENDING --role APPROVER
grant request get                   # fuzzy-pick a request (TTY) or pass <id>
grant request get <request-id>
grant request cancel <request-id>   # cancel an open request
grant request approve <request-id>  # approve a pending request (approvers only)
grant request reject <request-id>   # reject a pending request (approvers only)
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

`grant update` checks GitHub Releases for a newer version, verifies the downloaded archive's SHA-256 against the release's `checksums.txt`, and replaces the running binary in place. It refuses to run on dev builds — install a release build or download from the releases page. Because `checksums.txt` is published alongside the archive, verification protects against corrupted or tampered downloads, not against a compromised release pipeline.

The replacement stages the new binary next to the old one, flushes it to disk, then swaps it in. Each step is atomic on its own, so you never end up running a half-written binary, and a failed swap rolls back automatically. In the rare case that grant is killed mid-swap, the binary path is left empty with `.grant.old` beside it; grant prints the exact `mv` command to restore it (`mv /path/to/.grant.old /path/to/grant`).

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
| `login` | Authenticate to Idira Identity (MFA handled interactively) |
| `logout` | Clear cached tokens from keyring |
| `status` | Show auth state and active sessions |
| `favorites` | Manage saved role favorites (`add`/`list`/`remove`) |
| `revoke` | Revoke sessions (interactive, by ID, or `--all`) |
| `request` | Manage access requests through an approval workflow (see subcommands below) |
| `update` | Self-update to the latest release from GitHub |
| `version` | Print version information |

### `grant request` subcommands

| Subcommand | Description |
|------------|-------------|
| `submit` | Submit an on-demand access request (interactive workspace + role picker, or direct with flags) |
| `list` | List access requests (`--state`, `--result`, `--priority`, `--role CREATOR\|APPROVER`, `--search`, `--sort`, `--desc`) |
| `get [id]` | Show full request details; omit `<id>` in a TTY to open a fuzzy picker |
| `cancel [id]` | Cancel an open request; omit `<id>` in a TTY to pick from your open requests |
| `approve [id]` | Approve a pending request (approvers only); omit `<id>` in a TTY to pick from pending requests |
| `reject [id]` | Reject a pending request (approvers only); omit `<id>` in a TTY to pick from pending requests |

### Flags

**Global:** `--verbose, -v` (detailed output) | `--output, -o` (`text` or `json`)

**Elevation** (`grant`, `env`, `favorites add`):
`--provider, -p` | `--target, -t` | `--role, -r` | `--favorite, -f` | `--group, -g` | `--groups` | `--refresh`

**`grant request submit`:**
`--provider, -p` | `--target, -t` | `--role` | `--role-id` | `--reason` | `--priority` | `--date` | `--timezone` | `--from` | `--to` | `--yes` | `--refresh`

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
| "No eligible targets found" | Verify SCA policies with your Idira admin; try without `--provider` to see all targets |
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
