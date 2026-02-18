# grant

A CLI tool for elevating cloud permissions (Azure, AWS) via CyberArk Secure Cloud Access (SCA) — without leaving the terminal.

## Overview

`grant` enables terminal-based cloud permission elevation (Azure, AWS) through CyberArk SCA. It wraps the `idsec-sdk-golang` SDK for authentication and builds a custom SCA Access API client for JIT role elevation.

**Key Features:**
- Multi-CSP support (Azure, AWS) with concurrent eligibility queries
- Interactive permission elevation with fuzzy search
- Direct elevation with target and role flags
- AWS credential export via `grant env` for shell integration
- Favorites management for frequently used roles
- Session status monitoring
- Secure token storage in system keyring

## Installation

### Binary Releases (Recommended)

Download pre-built binaries from the [Releases](https://github.com/aaearon/grant-cli/releases) page.

**macOS:**
```bash
# Intel
curl -LO https://github.com/aaearon/grant-cli/releases/latest/download/grant_Darwin_x86_64.tar.gz
tar xzf grant_Darwin_x86_64.tar.gz
sudo mv grant /usr/local/bin/

# Apple Silicon
curl -LO https://github.com/aaearon/grant-cli/releases/latest/download/grant_Darwin_arm64.tar.gz
tar xzf grant_Darwin_arm64.tar.gz
sudo mv grant /usr/local/bin/
```

**Linux:**
```bash
curl -LO https://github.com/aaearon/grant-cli/releases/latest/download/grant_Linux_x86_64.tar.gz
tar xzf grant_Linux_x86_64.tar.gz
sudo mv grant /usr/local/bin/
```

**Windows:**
Download `grant_Windows_x86_64.zip` from releases and extract to a directory in your PATH.

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

## Quick Start

### Initial Setup

1. **Authenticate (auto-configures on first run):**
   ```bash
   grant login
   ```
   On first run, you'll be prompted for:
   - Identity URL (e.g., `https://abc1234.id.cyberark.cloud`)
   - Username

   Then follow the interactive prompts to complete MFA authentication. The MFA method will be selected interactively during login.

2. **Elevate permissions:**
   ```bash
   grant
   ```
   Select your target and role from the interactive list.

3. **Verify active sessions:**
   ```bash
   grant status
   ```

**Optional:** Run `grant configure` to reconfigure your Identity URL or username.

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
| `version` | Print version information |

### Global Flags

- `--verbose, -v` — Enable verbose output, including request/response details and timing

### configure

Configure or reconfigure your CyberArk tenant connection.

```bash
grant configure
```

This command:
- Creates `~/.grant/config.yaml` for application settings
- Creates `~/.idsec_profiles/grant.json` for SDK authentication
- Prompts for Identity URL (must be HTTPS, format: `https://{subdomain}.id.cyberark.cloud`)
- Prompts for username

**Note:** This command is optional. Running `grant login` for the first time automatically runs configuration. Use `configure` to change your Identity URL or username.

### env

Perform elevation and output AWS credential export statements for shell evaluation.

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

This command:
- **First time:** Prompts for Identity URL and username, then authenticates
- **Subsequent runs:** Uses credentials from `~/.idsec_profiles/grant.json`
- Prompts for password and MFA challenge (MFA method selected interactively)
- Stores tokens securely in system keyring
- Shows token expiration time on success

**Note:** Tokens are automatically refreshed during operations if still valid.

### logout

Clear all cached tokens from the system keyring.

```bash
grant logout
```

This removes stored authentication tokens but preserves your configuration files.

### Default Behavior (Elevate)

Running `grant` with no subcommand requests JIT (just-in-time) permission elevation for cloud resources.

**Interactive mode** — select from eligible targets:
```bash
grant                    # show all providers
grant --provider azure   # Azure only
grant --provider aws     # AWS only
```

**Direct mode** — specify target and role:
```bash
grant --target "Prod-EastUS" --role "Contributor"
grant -t "MyResourceGroup" -r "Owner"
```

**Favorite mode** — use a saved favorite:
```bash
grant --favorite prod-contrib
grant -f dev-reader
```

**Flags:**
- `--provider, -p` — Cloud provider: `azure`, `aws` (omit to show all providers)
- `--target, -t` — Target name (subscription, resource group, account, etc.)
- `--role, -r` — Role name (e.g., "Contributor", "Reader", "AdministratorAccess")
- `--favorite, -f` — Use a saved favorite alias (combines provider, target, and role)

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

**Output includes:**
- Authentication status (username and token validity)
- Active sessions grouped by cloud provider
- Session details: target name, role, expiration time
- Human-readable time remaining (e.g., "2h 15m")

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

**Example workflow:**
```bash
# Add a favorite interactively (select from eligible targets)
$ grant favorites add prod-contrib
? Select target: Subscription: Prod-EastUS / Role: Contributor
Added favorite "prod-contrib": azure/Prod-EastUS/Contributor

# Add a favorite non-interactively (no auth required)
$ grant favorites add dev-reader --target "Dev-WestEU" --role "Reader"
Added favorite "dev-reader": azure/Dev-WestEU/Reader

# Use the favorite
$ grant --favorite prod-contrib

# List favorites
$ grant favorites list
prod-contrib: azure/Prod-EastUS/Contributor
dev-reader: azure/Dev-WestEU/Reader
```

### version

Display version information including commit hash and build date.

```bash
grant version
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

### SDK Profile (`~/.idsec_profiles/grant.json`)

CyberArk Identity SDK profile containing Identity URL and authentication preferences.

**Managed by:** `grant configure` command (or auto-created by `grant login`)

**Contains:**
- Identity URL (format: `https://{subdomain}.id.cyberark.cloud`)
- Username
- SDK version metadata

**Note:** Tokens are NOT stored in this file — they're stored securely in the system keyring. MFA method selection is handled interactively during login.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GRANT_CONFIG` | Custom path to app config YAML | `~/.grant/config.yaml` |
| `IDSEC_LOG_LEVEL` | SDK log level (`DEBUG`, `INFO`, `CRITICAL`) — overrides `--verbose` | Not set |
| `HOME` | User home directory (used for config paths) | System default |

## How It Works

### Azure Elevation Flow

1. **List Eligibility:** Queries SCA API for Azure roles you're eligible to activate
2. **Request Elevation:** Submits elevation request with target and role
3. **JIT Activation:** SCA creates a time-limited Azure RBAC role assignment
4. **Automatic Access:** Your existing `az` CLI picks up the new role assignment
5. **Session Expiry:** Role assignment automatically expires (policy-controlled)

**Important:** No Azure credentials are returned to you. SCA manages the Azure role assignment behind the scenes. Your Azure CLI session uses its existing authentication but gains the new role assignment.

### AWS Elevation Flow

1. **List Eligibility:** Queries SCA API for AWS roles you're eligible to activate
2. **Request Elevation:** Submits elevation request with account and role
3. **Credential Issuance:** SCA returns temporary AWS credentials (access key, secret key, session token)
4. **Export Credentials:** Use `eval $(grant env --provider aws)` to export credentials to your shell
5. **Session Expiry:** Credentials automatically expire (policy-controlled)

**Important:** AWS credentials are returned directly. Export them using `grant env` or manually set the environment variables shown in the elevation output.

### Authentication Flow

1. **Initial Authentication:** `grant login` authenticates to CyberArk Identity with MFA
2. **Token Storage:** Tokens stored securely in system keyring (macOS Keychain, Windows Credential Manager, Linux Secret Service)
3. **Token Reuse:** Subsequent commands reuse cached tokens if still valid
4. **Auto-Refresh:** SDK automatically refreshes tokens before expiry
5. **Manual Logout:** `grant logout` clears tokens from keyring

## Troubleshooting

### "Error: failed to load config" or "profile not found"

**Cause:** Configuration files not created or corrupted.

**Solution:**
```bash
grant login      # Auto-configures on first run
# or
grant configure  # Explicit reconfiguration
```

### "Error: not authenticated" or "authentication required"

**Cause:** No valid authentication token in keyring.

**Solution:**
```bash
grant login
```

If login fails, verify:
1. Identity URL is correct (check `~/.idsec_profiles/grant.json` - should be `https://{subdomain}.id.cyberark.cloud`)
2. Username is correct
3. Password is correct
4. MFA device/method is available and working

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

### Interactive selection doesn't appear

**Cause:** Terminal doesn't support interactive input (e.g., non-TTY, CI environment).

**Solution:**
Use direct mode with explicit flags:
```bash
grant --target "MyTarget" --role "Contributor"
```

### "Error: provider not supported"

**Cause:** The specified provider is not supported. Currently supported: `azure`, `aws`.

**Solution:**
Use a supported provider:
```bash
grant --provider azure
grant --provider aws
grant  # omit to see all providers
```

### "grant env is only supported for AWS elevations"

**Cause:** `grant env` was used for an Azure elevation. Azure doesn't return credentials.

**Solution:**
For Azure, use `grant` directly. For AWS, specify the provider:
```bash
eval $(grant env --provider aws)
```

### Token expired or invalid during operation

**Cause:** Token expired between operations or keyring access denied.

**Solution:**
```bash
grant logout
grant login
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
