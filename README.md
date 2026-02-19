# grant

A CLI tool for elevating cloud permissions (Azure, AWS) via CyberArk Secure Cloud Access (SCA) — without leaving the terminal.

![grant demo](demo/demo.gif)

## Overview

`grant` enables terminal-based cloud permission elevation (Azure, AWS) through CyberArk SCA. It wraps the `idsec-sdk-golang` SDK for authentication and builds a custom SCA Access API client for JIT role elevation.

**Key Features:**
- Multi-CSP support (Azure, AWS) with concurrent eligibility queries
- Interactive permission elevation with fuzzy search
- Direct elevation with target and role flags
- AWS credential export via `grant env` for shell integration
- Favorites management for frequently used roles
- Entra ID group membership elevation via `grant --group` or `grant --groups`
- Session revocation via `grant revoke`
- Session status monitoring
- Local eligibility cache with configurable TTL
- Secure token storage in system keyring

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

# Check active sessions
grant status

# Revoke sessions
grant revoke              # interactive multi-select
grant revoke <session-id> # direct by ID
grant revoke --all        # revoke all
```

## Installation

### Binary Releases (Recommended)

Download pre-built binaries from the [Releases](https://github.com/aaearon/grant-cli/releases) page.

**macOS / Linux:**
```bash
VERSION=$(gh release view --repo aaearon/grant-cli --json tagName -q '.tagName' | tr -d v)
# macOS Intel: OS=darwin ARCH=amd64
# macOS Apple Silicon: OS=darwin ARCH=arm64
# Linux x86_64: OS=linux ARCH=amd64
# Linux ARM64: OS=linux ARCH=arm64
OS=linux ARCH=amd64
curl -LO "https://github.com/aaearon/grant-cli/releases/download/v${VERSION}/grant-cli_${VERSION}_${OS}_${ARCH}.tar.gz"
tar xzf "grant-cli_${VERSION}_${OS}_${ARCH}.tar.gz"
sudo mv grant /usr/local/bin/
```

**Windows:**
Download the appropriate `grant-cli_<version>_windows_<arch>.zip` from [releases](https://github.com/aaearon/grant-cli/releases) and extract to a directory in your PATH.

**Updating:**
```bash
grant update
```

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

Running `grant` with no subcommand elevates cloud permissions (the core behavior). Subcommands are listed below.

| Command | Description |
|---------|-------------|
| `configure` | Configure or reconfigure Identity URL and username (optional — `login` auto-configures on first run) |
| `env` | Perform elevation and output AWS credential export statements (for `eval $(grant env)`) |
| `login` | Authenticate to CyberArk Identity (auto-configures on first run, MFA handled interactively) |
| `logout` | Clear cached tokens from keyring |
| `status` | Show authentication state and active SCA sessions |
| `favorites` | Manage saved role favorites (add/list/remove) |
| `revoke` | Revoke active elevation sessions (interactive, by ID, or `--all`) |
| `update` | Self-update to the latest release from GitHub |
| `version` | Print version information |

### Global Flags

- `--verbose, -v` — Enable verbose output, including request/response details and timing

### configure

Reconfigure your CyberArk tenant connection (Identity URL and username). Optional — `grant login` auto-configures on first run.

```bash
grant configure
```

### env

Perform elevation and output AWS credential export statements for shell evaluation.

![grant env demo](demo/demo-env-status.gif)

```bash
eval $(grant env --provider aws)
eval $(grant env --provider aws --target "MyAccount" --role "AdminAccess")
eval $(grant env --favorite my-aws-admin)
```

This command:
- Performs the full elevation flow (interactive, direct, or favorite mode)
- Outputs only shell `export` statements (no human-readable messages)
- Designed for AWS elevations — returns an error for Azure (which doesn't return credentials)

Supports the same flags as the root command: `--provider`, `--target`, `--role`, `--favorite`.

### login

Authenticate to CyberArk Identity with MFA.

```bash
grant login
```

On first run, prompts for Identity URL and username (auto-configures). Authenticates with password and MFA (method selected interactively), then stores tokens in the system keyring. Tokens are automatically refreshed during operations.

### logout

Clear all cached tokens from the system keyring.

```bash
grant logout
```

This removes stored authentication tokens but preserves your configuration files.

### Default Behavior (Elevate)

Running `grant` with no subcommand requests JIT (just-in-time) permission elevation for cloud resources. Supports interactive, direct (`--target`/`--role`), and favorite (`--favorite`) modes as shown in the [Usage](#usage) section.

**Flags:**
- `--provider, -p` — Cloud provider: `azure`, `aws` (omit to show all providers)
- `--target, -t` — Target name (subscription, resource group, account, etc.)
- `--role, -r` — Role name (e.g., "Contributor", "Reader", "AdministratorAccess")
- `--favorite, -f` — Use a saved favorite alias (combines provider, target, and role)
- `--groups` — Show only Entra ID groups in the interactive selector
- `--group, -g` — Group name for direct group membership elevation

**Target matching:**
- Matches by workspace name (case-insensitive, partial match)
- Interactive mode provides fuzzy search
- Shows workspace type (subscription, resource group, etc.) and available roles

**How it works:**
- **Azure:** SCA creates a JIT Azure RBAC role assignment. Your existing `az` CLI session automatically picks up the elevated permissions — no credentials are returned.
- **AWS:** SCA returns temporary AWS credentials (access key, secret key, session token). Use `grant env` to export them: `eval $(grant env --provider aws)`

### status

Display authentication state and active elevation sessions.

```bash
grant status
grant status --provider azure  # filter by Azure
grant status --provider aws    # filter by AWS
```

### favorites

Manage saved role combinations for quick elevation.

**Add a favorite (interactive):**
```bash
grant favorites add <name>
```
Fetches your eligible targets from SCA and presents an interactive selector with fuzzy search — the same experience as `grant` elevation. Select a target/role combination and it's saved as a favorite.

**Add a favorite (non-interactive):**
```bash
grant favorites add <name> --target "Prod-EastUS" --role "Contributor"
grant favorites add <name> -t "MyResourceGroup" -r "Owner" -p azure
```
When `--target` and `--role` are both provided, the interactive selector is skipped and no authentication is required.
Provider defaults to the config value (azure) if omitted.

**List favorites:**
```bash
grant favorites list
```
Shows all saved favorites with their provider, target, and role.

**Remove a favorite:**
```bash
grant favorites remove <name>
```

## Configuration

### App Config (`~/.grant/config.yaml`)

Application settings including default provider and favorites.

**Default location:** `~/.grant/config.yaml`

**Override:** Set `GRANT_CONFIG` environment variable to use a custom path.

```yaml
profile: grant              # SDK profile name
default_provider: azure     # Default cloud provider

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

**Fields:**
- `profile` — Name of the SDK profile in `~/.idsec_profiles/` (default: `grant`)
- `default_provider` — Default cloud provider for elevation (used when `--provider` is omitted)
- `favorites` — Map of favorite names to provider/target/role combinations

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GRANT_CONFIG` | Custom path to app config YAML | `~/.grant/config.yaml` |
| `IDSEC_LOG_LEVEL` | SDK log level (`DEBUG`, `INFO`, `CRITICAL`) — overrides `--verbose` | Not set |
| `HOME` | User home directory (used for config paths) | System default |

## Troubleshooting

### Elevation succeeds but Azure CLI doesn't see new role

**Cause:** Azure CLI token cache may be stale.

**Solution:**
```bash
# Refresh Azure CLI token
az account get-access-token --output none

# Or clear Azure CLI cache and re-login
az account clear
az login
```

### "No eligible targets found"

**Cause:** Either you have no SCA policies granting access, or your policies don't grant access for the specified provider.

**Solution:**
1. Contact your CyberArk administrator to verify SCA policies
2. Ensure policies grant you access to the cloud provider (Azure, AWS)
3. Try without `--provider` to see all available targets: `grant`
4. Or specify a provider explicitly: `grant --provider azure` or `grant --provider aws`

### "Failed to elevate" or partial success

**Cause:** Policy may not allow the specific role or target, or session limit reached.

**Solution:**
1. Check active sessions: `grant status`
2. Verify the target name and role name are correct
3. Contact your CyberArk administrator if role should be available or if you've reached session limits

### Provider-related errors

Supported providers: `azure`, `aws`. `grant env` only works with AWS (Azure doesn't return credentials). For Azure, use `grant` directly.

### Permission denied accessing keyring (Linux)

Install and start a keyring service (`gnome-keyring` or `kwalletmanager`).

## Development

### Running Tests

```bash
# Unit tests
make test

# Integration tests (requires binary build)
make test-integration

# All tests
make test-all
```

### Building

```bash
# Build binary
make build

# Build with version info
VERSION=1.0.0 make build
```

### Linting

```bash
make lint
```

## Contributing

Contributions welcome! Please:
1. Follow existing code patterns and conventions
2. Write tests for new functionality (TDD preferred)
3. Update documentation for user-facing changes
4. Use conventional commits for commit messages

## License

MIT
