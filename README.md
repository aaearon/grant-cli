# sca-cli

A CLI tool for elevating Azure permissions via CyberArk Secure Cloud Access (SCA) — without leaving the terminal.

## Overview

`sca-cli` enables terminal-based Azure permission elevation through CyberArk SCA. It wraps the `idsec-sdk-golang` SDK for authentication and builds a custom SCA Access API client for JIT role elevation.

**Key Features:**
- Interactive permission elevation with fuzzy search
- Direct elevation with target and role flags
- Favorites management for frequently used roles
- Session status monitoring
- Secure token storage in system keyring

## Installation

### Binary Releases (Recommended)

Download pre-built binaries from the [Releases](https://github.com/aaearon/sca-cli/releases) page.

**macOS:**
```bash
# Intel
curl -LO https://github.com/aaearon/sca-cli/releases/latest/download/sca-cli_Darwin_x86_64.tar.gz
tar xzf sca-cli_Darwin_x86_64.tar.gz
sudo mv sca-cli /usr/local/bin/

# Apple Silicon
curl -LO https://github.com/aaearon/sca-cli/releases/latest/download/sca-cli_Darwin_arm64.tar.gz
tar xzf sca-cli_Darwin_arm64.tar.gz
sudo mv sca-cli /usr/local/bin/
```

**Linux:**
```bash
curl -LO https://github.com/aaearon/sca-cli/releases/latest/download/sca-cli_Linux_x86_64.tar.gz
tar xzf sca-cli_Linux_x86_64.tar.gz
sudo mv sca-cli /usr/local/bin/
```

**Windows:**
Download `sca-cli_Windows_x86_64.zip` from releases and extract to a directory in your PATH.

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

### Initial Setup

1. **Configure your CyberArk tenant:**
   ```bash
   sca-cli configure
   ```
   You'll be prompted for:
   - Tenant URL (e.g., `https://yourcompany.cyberark.cloud`)
   - Username
   - MFA method (optional: `otp`, `oath`, `sms`, `email`, `pf`)

2. **Authenticate:**
   ```bash
   sca-cli login
   ```
   Follow the interactive prompts to complete MFA authentication.

3. **Elevate permissions:**
   ```bash
   sca-cli elevate
   ```
   Select your target and role from the interactive list.

4. **Verify active sessions:**
   ```bash
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

### configure

Initial setup for connecting to your CyberArk tenant.

```bash
sca-cli configure
```

This command:
- Creates `~/.sca-cli/config.yaml` for application settings
- Creates `~/.idsec_profiles/sca-cli.json` for SDK authentication
- Prompts for tenant URL (must be HTTPS)
- Prompts for username
- Optionally prompts for preferred MFA method

**Valid MFA methods:** `otp`, `oath`, `sms`, `email`, `pf`

### login

Authenticate to CyberArk Identity with MFA.

```bash
sca-cli login
```

This command:
- Uses credentials from `~/.idsec_profiles/sca-cli.json`
- Prompts for password and MFA challenge
- Stores tokens securely in system keyring
- Shows token expiration time on success

**Note:** Tokens are automatically refreshed during operations if still valid.

### logout

Clear all cached tokens from the system keyring.

```bash
sca-cli logout
```

This removes stored authentication tokens but preserves your configuration files.

### elevate

Request JIT (just-in-time) permission elevation for cloud resources.

**Interactive mode** — select from eligible targets:
```bash
sca-cli elevate
sca-cli elevate --provider azure  # explicit provider
```

**Direct mode** — specify target and role:
```bash
sca-cli elevate --target "Prod-EastUS" --role "Contributor"
sca-cli elevate -t "MyResourceGroup" -r "Owner"
```

**Favorite mode** — use a saved favorite:
```bash
sca-cli elevate --favorite prod-contrib
sca-cli elevate -f dev-reader
```

**Flags:**
- `--provider, -p` — Cloud provider (default: `azure`, v1 supports Azure only)
- `--target, -t` — Target name (subscription, resource group, management group, directory, or resource)
- `--role, -r` — Role name (e.g., "Contributor", "Reader", "Owner")
- `--favorite, -f` — Use a saved favorite alias (combines provider, target, and role)
- `--duration, -d` — Requested session duration in hours (subject to policy limits)

**Target matching:**
- Matches by workspace name (case-insensitive, partial match)
- Interactive mode provides fuzzy search
- Shows workspace type (subscription, resource group, etc.) and available roles

**How it works:**
For Azure, SCA creates a JIT Azure RBAC role assignment. Your existing `az` CLI session automatically picks up the elevated permissions — no credentials are returned.

### status

Display authentication state and active elevation sessions.

```bash
sca-cli status
sca-cli status --provider azure  # filter by provider
```

**Output includes:**
- Authentication status (username and token validity)
- Active sessions grouped by cloud provider
- Session details: target name, role, expiration time
- Human-readable time remaining (e.g., "2h 15m")

### favorites

Manage saved role combinations for quick elevation.

**Add a favorite:**
```bash
sca-cli favorites add <name>
```
This interactively prompts for:
- Provider (default: azure)
- Target name
- Role name

**List favorites:**
```bash
sca-cli favorites list
```
Shows all saved favorites with their provider, target, and role.

**Remove a favorite:**
```bash
sca-cli favorites remove <name>
```

**Example workflow:**
```bash
# Add a favorite
$ sca-cli favorites add prod-contrib
Provider: azure
Target: Prod-EastUS
Role: Contributor
Favorite 'prod-contrib' added successfully.

# Use the favorite
$ sca-cli elevate --favorite prod-contrib

# List favorites
$ sca-cli favorites list
prod-contrib:
  Provider: azure
  Target: Prod-EastUS
  Role: Contributor
```

### version

Display version information including commit hash and build date.

```bash
sca-cli version
```

## Configuration

### App Config (`~/.sca-cli/config.yaml`)

Application settings including default provider and favorites.

**Default location:** `~/.sca-cli/config.yaml`

**Override:** Set `SCA_CLI_CONFIG` environment variable to use a custom path.

```yaml
profile: sca-cli              # SDK profile name
default_provider: azure       # Default cloud provider

favorites:
  prod-contrib:
    provider: azure
    target: "Prod-EastUS"
    role: "Contributor"
  dev-reader:
    provider: azure
    target: "Dev-Subscription"
    role: "Reader"
```

**Fields:**
- `profile` — Name of the SDK profile in `~/.idsec_profiles/` (default: `sca-cli`)
- `default_provider` — Default cloud provider for elevate command (default: `azure`)
- `favorites` — Map of favorite names to provider/target/role combinations

### SDK Profile (`~/.idsec_profiles/sca-cli.json`)

CyberArk Identity SDK profile containing tenant URL and authentication preferences.

**Managed by:** `sca-cli configure` command

**Contains:**
- Tenant URL
- Username
- MFA method preference
- SDK version metadata

**Note:** Tokens are NOT stored in this file — they're stored securely in the system keyring.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SCA_CLI_CONFIG` | Custom path to app config YAML | `~/.sca-cli/config.yaml` |
| `HOME` | User home directory (used for config paths) | System default |

## How It Works

### Azure Elevation Flow

1. **List Eligibility:** Queries SCA API for roles you're eligible to activate
2. **Request Elevation:** Submits elevation request with target and role
3. **JIT Activation:** SCA creates a time-limited Azure RBAC role assignment
4. **Automatic Access:** Your existing `az` CLI picks up the new role assignment
5. **Session Expiry:** Role assignment automatically expires (default: 8 hours, policy-controlled)

**Important:** No Azure credentials are returned to you. SCA manages the Azure role assignment behind the scenes. Your Azure CLI session uses its existing authentication but gains the new role assignment.

### Authentication Flow

1. **Initial Authentication:** `sca-cli login` authenticates to CyberArk Identity with MFA
2. **Token Storage:** Tokens stored securely in system keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service)
3. **Token Reuse:** Subsequent commands reuse cached tokens if still valid
4. **Auto-Refresh:** SDK automatically refreshes tokens before expiry
5. **Manual Logout:** `sca-cli logout` clears tokens from keyring

## Troubleshooting

### "Error: failed to load config" or "profile not found"

**Cause:** Configuration files not created or corrupted.

**Solution:**
```bash
sca-cli configure  # Re-run configuration
```

### "Error: not authenticated" or "authentication required"

**Cause:** No valid authentication token in keyring.

**Solution:**
```bash
sca-cli login
```

If login fails, verify:
1. Tenant URL is correct (check `~/.idsec_profiles/sca-cli.json`)
2. Username is correct
3. Password is correct
4. MFA method matches your account settings

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

**Cause:** Either you have no SCA policies granting access, or your policies don't grant Azure access.

**Solution:**
1. Contact your CyberArk administrator to verify SCA policies
2. Ensure policies grant you access to Azure targets
3. Verify you're using the correct provider: `sca-cli elevate --provider azure`

### "Failed to elevate" or partial success

**Cause:** Policy may not allow the specific role or target, or session limit reached.

**Solution:**
1. Check active sessions: `sca-cli status`
2. Verify the target name and role name are correct
3. Try with different duration: `sca-cli elevate --duration 4`
4. Contact your CyberArk administrator if role should be available

### Interactive selection doesn't appear

**Cause:** Terminal doesn't support interactive input (e.g., non-TTY, CI environment).

**Solution:**
Use direct mode with explicit flags:
```bash
sca-cli elevate --target "MyTarget" --role "Contributor"
```

### "Error: invalid provider" (v1)

**Cause:** Version 1.x only supports Azure.

**Solution:**
Use `--provider azure` (or omit the flag, as Azure is the default):
```bash
sca-cli elevate --provider azure
```

### Token expired or invalid during operation

**Cause:** Token expired between operations or keyring access denied.

**Solution:**
```bash
sca-cli logout
sca-cli login
```

### Permission denied accessing keyring (Linux)

**Cause:** No keyring service available or `gnome-keyring` / `kde-wallet` not running.

**Solution:**
1. Install and start a keyring service:
   ```bash
   # For GNOME
   sudo apt install gnome-keyring

   # For KDE
   sudo apt install kwalletmanager
   ```
2. Or use environment-based auth (not recommended for production)

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
