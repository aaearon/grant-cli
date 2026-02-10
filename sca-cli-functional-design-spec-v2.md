# sca-cli — Functional Design Specification

**Version:** 2.2 (Draft)
**Author:** Tim Schindler
**Date:** 2026-02-10
**License:** MIT

---

## 1. Problem Statement

Users who need to elevate their Azure permissions via CyberArk Secure Cloud Access (SCA) are forced to leave their terminal, open a web browser, navigate the SCA web console, select the target role, and then return to the Azure CLI. This context-switching is disruptive for CLI-first workflows.

`sca-cli` eliminates this by enabling users to discover eligible Azure roles, elevate permissions, and inject temporary credentials into their shell — all without leaving the terminal.

## 2. Target Audience

- DevOps engineers and cloud operators using Azure with CyberArk SCA
- End-user customers operating Azure environments secured by CyberArk SCA

The tool will be released as open-source.

## 3. Scope

### 3.1 In Scope (v1)

- Authentication to CyberArk Identity — interactive human users only (delegated to idsec-sdk-golang)
- MFA support — push/OTP, OATH, SMS, email, phone call, browser-based IdP redirect (delegated to idsec-sdk-golang)
- List eligible Azure targets from the SCA Access API
- Elevate access to a selected Azure role
- Inject Azure credentials as environment variables (`AZURE_*`, `ARM_*`) into the current shell
- Interactive role selection with fuzzy search/filter (when no flag is provided)
- Direct role selection via CLI flag (`--role`, `--target`)
- Role favorites/aliases stored in a local config file
- Azure cloud provider only

### 3.2 Out of Scope (v1)

- Service user / non-human authentication (not applicable to the end-user elevation use case)
- AWS and GCP cloud providers (future versions)
- Session listing and revocation (use SCA web console)
- Session timer / TTL countdown
- Auto-refresh of tokens before expiry
- Policy management (admin-only — use the `idsec` CLI's `policy cloudaccess` commands or the SCA web console)
- Workspace onboarding / discovery (admin-only — available via `idsec` CLI's `cce` and `sca` commands)

## 4. Architecture: Leveraging idsec-sdk-golang

### 4.1 Key Decision

`sca-cli` is a thin, purpose-built CLI wrapper around CyberArk's official `idsec-sdk-golang` SDK. We import it as a Go module dependency and reuse its authentication, HTTP client, keyring, and ISP service client layers. We do **not** fork the `idsec` CLI or reimplement any functionality the SDK already provides.

**Source:** https://github.com/cyberark/idsec-sdk-golang (Apache 2.0, updated Feb 2026)

#### Why idsec-sdk-golang over ark-sdk-golang

| Criteria | ark-sdk-golang | idsec-sdk-golang |
|----------|---------------|------------------|
| Maintenance | Stable but older | Actively updated (Feb 2026) |
| SCA packages | `uap/sca` (policy management only) | `sca` (discovery), `cce/azure` (workspace mgmt), `policy/cloudaccess` (policy CRUD) |
| Auth model | `ArkISPAuth` | `IdsecISPAuth` — same capabilities, newer codebase |
| Identity auth | Uses `github.com/AlecAkey/survey` (archived) | Uses `github.com/Iilun/survey/v2` (maintained fork) |
| SIA packages | Full SIA support | Full SIA support + settings, certificates |
| Package naming | `Ark*` prefix | `Idsec*` prefix — aligns with CyberArk's current "Identity Security" branding |

`idsec-sdk-golang` is the newer SDK that CyberArk is actively developing. While neither SDK wraps the SCA Access APIs we need (eligibility, elevate), `idsec-sdk-golang` gives us a better foundation.

### 4.2 What idsec-sdk-golang Provides (We Reuse)

| Capability | SDK Package | What It Does |
|-----------|-------------|--------------|
| **Authentication** | `pkg/auth` → `IdsecISPAuth` | CyberArk Identity auth with interactive MFA (push/OTP, OATH, SMS, email, phone call), browser-based IdP redirect, token refresh, profile-based multi-tenant support |
| **Identity auth engine** | `pkg/auth/identity` → `IdsecIdentity` | Start/Advance authentication flows against CyberArk Identity, mechanism selection, IdP detection, interactive prompts via `survey/v2` |
| **Token caching & keyring** | `pkg/common/keyring` → `IdsecKeyring` | Cross-platform credential storage (OS keyring + AES-encrypted file fallback for Docker/WSL) |
| **HTTP client** | `pkg/common` → `IdsecClient` | Auth headers, cookie management (persistent jar), TLS config, token refresh callbacks, request/response logging, fake user-agent |
| **ISP service resolution** | `pkg/common/isp` → `IdsecISPServiceClient` | Resolves tenant service URLs from JWT claims, manages cookies, provides `Get`/`Post` methods with automatic auth header injection |
| **Profile management** | `pkg/models` → `IdsecProfile` | Profile storage at `~/.idsec_profiles`, multi-tenant config |
| **Logging** | `pkg/common` → `IdsecLogger` | Structured logging with verbosity levels |

### 4.3 What We Build (SCA Access Client Layer)

Neither `idsec-sdk-golang` nor `ark-sdk-golang` wraps the end-user SCA Access APIs. The existing SDK packages cover only admin operations:

| SDK Package | Purpose | End-user? |
|-------------|---------|-----------|
| `pkg/services/sca` | Workspace discovery (`/api/cloud/discovery`) | ❌ Admin |
| `pkg/services/cce/azure` | Azure workspace onboarding (Entra, subscriptions, mgmt groups) | ❌ Admin / Terraform |
| `pkg/services/policy/cloudaccess` | Cloud access policy CRUD | ❌ Admin |

**We build a custom `SCAAccessService`** that wraps the three end-user SCA Access API endpoints on top of `IdsecISPServiceClient`. This follows the same service pattern used by all `idsec-sdk-golang` services (implements `IdsecService`, uses `IdsecBaseService`, takes `IdsecAuth` authenticators).

### 4.4 Authentication Flow

`sca-cli` uses **only** the `auth.Identity` method (interactive human user). The `auth.IdentityServiceUser` method is explicitly not supported — it is intended for non-human automation and is not applicable to the end-user elevation use case.

The `IdsecISPAuth` authenticator handles the full interactive flow:

```
User runs `sca-cli login`
        │
        ▼
IdsecISPAuth.Authenticate()
        │
        ├─► Username + Password prompt (via survey/v2)
        │
        ▼
CyberArk Identity StartAuthentication
        │
        ├─► If IdP redirect detected → opens browser via webbrowser package
        │
        ├─► If MFA required → interactive mechanism selection:
        │     📲 Push / Code (otp)
        │     🔐 OATH Code (oath)
        │     📟 SMS (sms)
        │     📧 Email (email)
        │     📞 Phone call (pf)
        │
        ▼
JWT session token returned
        │
        ├─► Cached in OS keyring via IdsecKeyring
        ├─► Cookie jar persisted for session continuity
        └─► Token refresh handled automatically via refresh token
```

**Key behaviors inherited from the SDK:**

- Tokens are cached in the OS keyring and reused until expiry
- If a cached token exists and is valid, authentication is a no-op (no re-prompt)
- If a cached token exists but is expired, the SDK attempts a silent refresh via refresh token
- MFA method can be pre-configured (via `IdentityMFAMethod`) or selected interactively
- External IdP users (non-`@cyberark.cloud.*`) are detected automatically and redirected to browser-based SSO

**Important: Tenant subdomain resolution.** The identity URL subdomain (e.g., `abz4452` in `abz4452.id.cyberark.cloud`) is **not** the tenant subdomain used for SCA API calls. The correct subdomain is extracted from the JWT `subdomain` claim (e.g., `cyberiam-poc`). The SDK's `IdsecISPServiceClient.resolveServiceURL()` handles this automatically by parsing the JWT claims `subdomain` and `platform_domain` to construct service URLs like `https://{subdomain}.sca.{platform_domain}/api`.

### 4.5 Dependency Benefits

Importing `idsec-sdk-golang` eliminates ~70% of the implementation effort:

| Without SDK | With SDK |
|-------------|----------|
| Implement CyberArk Identity OAuth2/OIDC from scratch | `IdsecISPAuth.Authenticate()` — done |
| Build MFA challenge/response handling for 6 mechanisms | Built-in with interactive prompts |
| Implement browser-based IdP redirect with local callback server | Built-in via `webbrowser` package + polling |
| Build token caching with OS keyring abstraction | `IdsecKeyring` — done |
| Handle cookie persistence for session continuity | `IdsecClient` — done |
| Resolve ISP service URLs from tenant configuration | `IdsecISPServiceClient.FromISPAuth()` — done |
| Implement token refresh logic | Built-in refresh callback |

## 5. SCA Access API Endpoints

Reference: https://api-docs.cyberark.com/sca-api/docs/secure-cloud-access-apis

**Base URL:** `https://{subdomain}.sca.cyberark.cloud/api` where `{subdomain}` is the JWT `subdomain` claim (e.g., `cyberiam-poc`).

**Required headers:** `Authorization: Bearer {jwt}`, `X-API-Version: 2.0`, `Origin` and `Referer` matching the service host, `Content-Type: application/json`.

These are the **end-user** SCA APIs that `sca-cli` wraps. They are distinct from the admin APIs already covered by the SDK.

| Operation | Method | Endpoint | Purpose |
|-----------|--------|----------|---------|
| List eligible targets | `GET` | `/api/access/{csp}/eligibility` | Retrieve targets the user can elevate to (CSP as path param: `AWS`, `AZURE`, `GCP`) |
| Elevate access | `POST` | `/api/access/elevate` | Request JIT elevation for one or more targets |
| List sessions | `GET` | `/api/access/sessions` | List active elevated sessions |
| Revoke sessions | `POST` | `/api/access/sessions/revoke` | Revoke active elevated sessions |

Note: The OpenAPI spec also defines `POST /oauth2/token/{app_id}` on the **identity** host (`{tenant}.id.cyberark.cloud`) for service-to-service authentication using Basic Auth with client credentials. This is **not relevant** for `sca-cli` — we use the ISP JWT from interactive Identity auth directly.

### 5.1 Resolved Questions (Validated Against Live Tenant)

The following questions from v2.1 have been answered via the PoC (see `poc/` directory):

1. **What does `/access/elevate` return for Azure?** The response schema is `{response: {csp, organizationId, results: [{workspaceId, roleId, sessionId, accessCredentials, errorInfo}]}}`. The `accessCredentials` field contains the credentials needed to access the workspace once elevation succeeds. The `errorInfo` field (with `code`, `message`, `description`) is present only if elevation failed.

2. **Does `/oauth2/token/{app_id}` require a pre-registered application?** Yes — this endpoint is on the identity host, uses Basic Auth (`UserPassBasicAuth`), and requires `grant_type: client_credentials`. It is for service-to-service authentication and is **not needed** for the interactive CLI flow. The ISP JWT is used directly.

3. **Is the ISP JWT sufficient for SCA Access APIs?** **Yes.** The Identity JWT from `IdsecISPAuth` works directly as a `Bearer` token on `{subdomain}.sca.cyberark.cloud/api/*` endpoints. No token exchange is required. The `X-API-Version: 2.0` header is required (set by the SDK's `IdsecSCAService`).

4. **What is the exact response schema for `/access/{csp}/eligibility`?** See Section 5.2.

### 5.2 Eligibility Response Schema

`GET /api/access/{CSP}/eligibility` where `{CSP}` is `AWS`, `AZURE`, or `GCP` (path parameter).

Optional query parameters: `limit` (1-50), `nextToken` (pagination).

**Response (Azure example):**

```json
{
  "response": [
    {
      "organizationId": "29cb7961-e16d-42c7-8ade-1794bbb76782",
      "workspaceId": "providers/Microsoft.Management/managementGroups/29cb7961-...",
      "workspaceName": "Tenant Root Group",
      "workspaceType": "management_group",
      "roleInfo": {
        "id": "/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-...",
        "name": "User Access Administrator"
      }
    },
    {
      "organizationId": "29cb7961-e16d-42c7-8ade-1794bbb76782",
      "workspaceId": "29cb7961-e16d-42c7-8ade-1794bbb76782",
      "workspaceName": "CyberIAM Tech Labs",
      "workspaceType": "directory",
      "roleInfo": {
        "id": "62e90394-69f5-4237-9190-012177145e10",
        "name": "Global Administrator"
      }
    }
  ],
  "nextToken": null,
  "total": 2
}
```

**Note:** The live API returns `roleInfo` (with `id` and `name` fields). The OpenAPI spec defines this as `role` in `CommonEligibleTarget` — the field name discrepancy should be handled in the client.

Azure `workspaceType` values: `RESOURCE`, `RESOURCE_GROUP`, `SUBSCRIPTION`, `MANAGEMENT_GROUP`, `DIRECTORY`.

### 5.3 Elevate Request/Response Schema

`POST /api/access/elevate`

**Request body:**

```json
{
  "csp": "AZURE",
  "organizationId": "29cb7961-e16d-42c7-8ade-1794bbb76782",
  "targets": [
    {
      "workspaceId": "29cb7961-e16d-42c7-8ade-1794bbb76782",
      "roleId": "62e90394-69f5-4237-9190-012177145e10"
    }
  ]
}
```

Required fields: `csp` (enum: `AWS`, `AZURE`, `GCP`), `targets` (array, 1-5 items). Each target requires `workspaceId` and either `roleId` or `roleName`. The `organizationId` is required for Azure and GCP but not for standalone AWS accounts.

**Response body:**

```json
{
  "response": {
    "csp": "AZURE",
    "organizationId": "...",
    "results": [
      {
        "workspaceId": "...",
        "roleId": "...",
        "sessionId": "...",
        "accessCredentials": "...",
        "errorInfo": null
      }
    ]
  }
}
```

The `accessCredentials` field contains cloud-provider-specific credentials. The `errorInfo` object (with `code`, `message`, `description`) is present only on per-target failure.

## 6. User Flows

### 6.1 First-Time Setup

```
$ sca-cli configure
? CyberArk tenant URL: https://acme.cyberark.cloud
? Username: tim@iosharp.com
? MFA method (leave blank for interactive selection): [otp/oath/sms/email/pf]
Profile saved to ~/.idsec_profiles/sca-cli.json
Config saved to ~/.sca-cli/config.yaml
```

Note: `sca-cli configure` creates both an idsec SDK profile (for authentication) and a sca-cli config file (for favorites, defaults, etc.).

### 6.2 Authentication

```
$ sca-cli login
? Password: ********
? Select MFA method:
  ▸ 📲 Push / Code
    🔐 OATH Code
    📟 SMS
    📧 Email
✓ Authenticated as tim@iosharp.com (token cached, expires in 1h)
```

Or for external IdP users:

```
$ sca-cli login
Opening browser for SSO authentication...
✓ Authenticated as tim@customer.com (token cached, expires in 1h)
```

### 6.3 Interactive Role Selection (no flags)

```
$ sca-cli elevate
Fetching eligible Azure targets...

? Select a target (type to filter):
  ▸ Subscription: Prod-EastUS / Role: Contributor (2h max)
    Subscription: Dev-WestEU / Role: Owner (1h max)
    Subscription: Staging-NorthEU / Role: Reader (4h max)
    Resource Group: rg-databases / Role: SQL Admin (1h max)

✓ Elevated to Contributor on Prod-EastUS
  Session expires at 16:32 UTC

  Run the following to activate in your current shell:
  eval $(sca-cli env)
```

### 6.4 Direct Role Selection (with flags)

```
$ sca-cli elevate --target "Prod-EastUS" --role "Contributor"
✓ Elevated to Contributor on Prod-EastUS
  Session expires at 16:32 UTC

  eval $(sca-cli env)
```

### 6.5 Using Favorites

```
$ sca-cli elevate --favorite prod-contrib
✓ Elevated to Contributor on Prod-EastUS
```

### 6.6 Credential Injection

```
$ eval $(sca-cli env)
# This outputs:
# export AZURE_SUBSCRIPTION_ID=...
# export AZURE_TENANT_ID=...
# export ARM_ACCESS_TOKEN=...
# export ARM_SUBSCRIPTION_ID=...
# export SCA_SESSION_EXPIRY=...
```

After `eval`, the user can run `az` commands directly:

```
$ az vm list --output table
```

## 7. CLI Command Structure

```
sca-cli
├── configure          # First-time setup / edit config
├── login              # Authenticate to CyberArk Identity (interactive only)
├── logout             # Clear cached tokens from keyring
├── elevate            # Elevate Azure permissions (core command)
│   ├── --target, -t   # Target name (subscription, resource group)
│   ├── --role, -r     # Role name
│   ├── --favorite, -f # Use a saved favorite alias
│   └── --duration, -d # Requested session duration (if policy allows)
├── env                # Output export statements for shell injection
│   └── --format       # shell (default), powershell, json, fish
├── favorites          # Manage role favorites
│   ├── add            # Save a target+role as a named favorite
│   ├── list           # List saved favorites
│   └── remove         # Delete a favorite
├── status             # Show current auth and session state
└── version            # Print version info
```

## 8. Configuration

### 8.1 SDK Profile

Location: `~/.idsec_profiles/sca-cli.json` (managed by idsec-sdk-golang)

Stores authentication state: username, auth method, tenant URL, MFA preferences, cached tokens (via keyring reference).

### 8.2 sca-cli Config File

Location: `~/.sca-cli/config.yaml`

```yaml
# Reference to the idsec SDK profile name
profile: sca-cli

# Default cloud provider (v1: azure only)
provider: azure

# Output format for `sca-cli env`
env_format: shell  # shell | powershell | fish | json

favorites:
  prod-contrib:
    target: "Prod-EastUS"
    role: "Contributor"
  dev-owner:
    target: "Dev-WestEU"
    role: "Owner"
```

Note: Authentication configuration (tenant URL, username, MFA method) lives in the SDK profile, not in the sca-cli config. This avoids duplication and lets the SDK manage auth state consistently.

## 9. Technology Stack

`sca-cli` introduces **zero new Go module dependencies**. Every library used is already in `idsec-sdk-golang`'s dependency tree, either as a direct or transitive dependency. This minimises supply chain risk, binary size, and maintenance burden.

| Component | Library | Source |
|-----------|---------|--------|
| Language | Go | — |
| SDK dependency | `github.com/cyberark/idsec-sdk-golang` | Direct import |
| CLI framework | `spf13/cobra` + `spf13/viper` | Already in SDK |
| Interactive prompts & role selection | `Iilun/survey/v2` | Already in SDK — `Select` with `WithFilter` provides type-to-filter role picker |
| Terminal colours | `fatih/color` | Already in SDK |
| Config format | YAML (`~/.sca-cli/config.yaml`) | `gopkg.in/yaml.v3` already transitive via viper |
| Keyring / credential storage | `99designs/keyring` | Already in SDK via `IdsecKeyring` |
| JWT parsing | `golang-jwt/jwt/v5` | Already in SDK |
| Cookie persistence | `juju/persistent-cookiejar` | Already in SDK |
| Browser opening (IdP SSO) | `toqueteos/webbrowser` | Already in SDK |
| UUID generation | `google/uuid` | Already in SDK |
| Distribution | GitHub Releases (goreleaser), Homebrew tap | Build tooling (not a Go dep) |

**Future (post-v1):** `rhysd/go-github-selfupdate` (already in SDK) can power a `sca-cli update` command at zero additional dependency cost.

## 10. Elevation Flow (Internal Logic)

```
┌─────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  sca-cli    │────▶│ IdsecISPAuth         │────▶│ Check cached    │
│  elevate    │     │ .LoadAuthentication() │     │ token validity  │
└─────────────┘     └──────────────────────┘     └────────┬────────┘
                                                           │
                                              Valid token exists? ──No──▶ "Run sca-cli login"
                                                           │
                                                          Yes
                                                           │
                                                           ▼
                                             ┌──────────────────────┐
                                             │ SCAAccessService     │
                                             │ .ListEligibility()   │
                                             │ GET /api/access/     │
                                             │ {CSP}/eligibility    │
                                             └──────────┬───────────┘
                                                        │
                                                        ▼
                                             ┌──────────────────────┐
                                             │ Display eligible     │
                                             │ targets (interactive │
                                             │ or flag-based)       │
                                             └──────────┬───────────┘
                                                        │
                                               User selects target
                                                        │
                                                        ▼
                                             ┌──────────────────────┐
                                             │ SCAAccessService     │
                                             │ .Elevate()           │
                                             │ POST /api/access/    │
                                             │ elevate              │
                                             └──────────┬───────────┘
                                                        │
                                               API returns session
                                               credentials + expiry
                                                        │
                                                        ▼
                                             ┌──────────────────────┐
                                             │ Cache credentials    │
                                             │ for `sca-cli env`    │
                                             └──────────────────────┘
```

## 11. Environment Variable Output

`sca-cli env` outputs shell-appropriate export statements. The `--format` flag controls syntax:

| Format | Example output |
|--------|---------------|
| `shell` (default) | `export AZURE_SUBSCRIPTION_ID="..."` |
| `powershell` | `$env:AZURE_SUBSCRIPTION_ID="..."` |
| `fish` | `set -gx AZURE_SUBSCRIPTION_ID "..."` |
| `json` | `{"AZURE_SUBSCRIPTION_ID": "..."}` |

### Variables Exported

| Variable | Description |
|----------|-------------|
| `AZURE_SUBSCRIPTION_ID` | Target subscription ID |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `ARM_ACCESS_TOKEN` | Temporary access token for Azure Resource Manager |
| `ARM_SUBSCRIPTION_ID` | Same as `AZURE_SUBSCRIPTION_ID` (Terraform compatibility) |
| `SCA_SESSION_ID` | SCA session identifier |
| `SCA_SESSION_EXPIRY` | ISO 8601 timestamp of session expiration |
| `SCA_ROLE` | Name of the elevated role |
| `SCA_TARGET` | Name of the target (subscription/resource group) |

Note: The exact variables exported depend on what `/api/access/elevate` returns in `accessCredentials` — see Section 5.3 for the response schema. The `accessCredentials` field is cloud-provider-specific and its format for Azure needs to be captured from a successful elevation call.

## 12. Error Handling

| Scenario | Behavior |
|----------|----------|
| No cached token / expired token | Prompt: "Not authenticated. Run `sca-cli login` first." |
| Token expired but refresh token available | SDK silently refreshes — transparent to user |
| No eligible targets returned | "No eligible Azure targets found. Check your SCA policies." |
| Elevation denied (policy) | Display the API error message (e.g., approval required, time window) |
| Network failure | Retry once, then display error with `--verbose` hint |
| Target/role not found (direct mode) | "Target 'X' or role 'Y' not found. Run `sca-cli elevate` to see available options." |
| Favorite not found | "Favorite 'X' not found. Run `sca-cli favorites list`." |
| MFA timeout | "MFA verification timed out (360s). Run `sca-cli login` to retry." |
| External IdP browser not available | "Browser could not be opened for SSO. Ensure a browser is available or use a CyberArk cloud directory user." |

## 13. Security Considerations

- **No credentials in config files.** Tokens are stored in the OS keyring via `IdsecKeyring` (macOS Keychain, Windows Credential Manager, Linux Secret Service) with automatic fallback to AES-encrypted file for Docker/WSL environments.
- **No plaintext logging of tokens.** `--verbose` mode logs request/response metadata but redacts token values.
- **Short-lived sessions.** The tool respects SCA policy-defined session durations and does not attempt to extend them.
- **No credential persistence beyond session.** `sca-cli env` outputs ephemeral variables; they are lost when the shell session ends.
- **Interactive auth only.** No service account credentials are stored or accepted — the tool is designed for human users with MFA enforcement.

## 14. Cross-Platform Support

Inherited from `IdsecKeyring` and `IdsecIdentity`:

| Platform | Shell support | Keyring backend |
|----------|--------------|-----------------|
| macOS | bash, zsh, fish | macOS Keychain |
| Linux | bash, zsh, fish | Secret Service (GNOME Keyring / KWallet) |
| Windows | PowerShell, cmd | Windows Credential Manager |
| WSL | bash, zsh | AES-encrypted file fallback |
| Docker | bash | AES-encrypted file fallback (auto-detected) |

## 15. Project Structure

```
sca-cli/
├── cmd/                    # Cobra command definitions
│   ├── root.go
│   ├── configure.go
│   ├── login.go
│   ├── logout.go
│   ├── elevate.go
│   ├── env.go
│   ├── favorites.go
│   ├── status.go
│   └── version.go
├── internal/
│   ├── sca/                # SCA Access API client (what we build)
│   │   ├── service.go      # SCAAccessService — implements IdsecService pattern
│   │   ├── service_config.go
│   │   └── models/
│   │       ├── eligibility.go   # Request/response types for /access/csp/eligibility
│   │       └── elevate.go       # Request/response types for /access/elevate
│   ├── config/             # sca-cli specific configuration
│   │   ├── config.go       # YAML config management
│   │   └── favorites.go    # Favorite management
│   ├── shell/              # Environment variable output formatting
│   │   └── env.go          # shell/powershell/fish/json formatters
│   └── ui/                 # Interactive TUI components
│       └── selector.go     # Role picker using survey/v2 Select with filter
├── go.mod                  # Depends on github.com/cyberark/idsec-sdk-golang
├── go.sum
├── main.go
├── Makefile
├── goreleaser.yml          # Cross-platform release config
├── README.md
├── LICENSE
└── .github/
    └── workflows/
        └── release.yml     # CI/CD for goreleaser
```

### Key difference from v1 spec

The `internal/auth/` and `internal/credentials/` directories are **gone** — all authentication and credential storage is delegated to `idsec-sdk-golang`. The only custom code we write is the `internal/sca/` package (SCA Access API client) and the CLI/UI glue.

## 16. SCA Access Service Implementation Pattern

The custom `SCAAccessService` follows the same pattern as all services in `idsec-sdk-golang`:

```go
package sca

import (
    "github.com/cyberark/idsec-sdk-golang/pkg/auth"
    "github.com/cyberark/idsec-sdk-golang/pkg/common"
    "github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
    "github.com/cyberark/idsec-sdk-golang/pkg/services"
)

type SCAAccessService struct {
    services.IdsecService
    *services.IdsecBaseService
    ispAuth *auth.IdsecISPAuth
    client  *isp.IdsecISPServiceClient
}

func NewSCAAccessService(authenticators ...auth.IdsecAuth) (*SCAAccessService, error) {
    svc := &SCAAccessService{}
    var svcIface services.IdsecService = svc
    base, err := services.NewIdsecBaseService(svcIface, authenticators...)
    // ... resolve ISP auth, create ISP service client for "sca" service
    // Pattern: isp.FromISPAuth(ispAuth, "sca", ".", "", refreshCallback)
    // Sets X-API-Version: 2.0 header (required by the SCA API gateway)
}

func (s *SCAAccessService) ListEligibility(csp string) (*EligibilityResponse, error) {
    // GET /api/access/{csp}/eligibility via s.client.Get(...)
    // csp: "AWS", "AZURE", or "GCP" (path parameter)
}

func (s *SCAAccessService) Elevate(req *ElevateRequest) (*ElevateResponse, error) {
    // POST /api/access/elevate via s.client.Post(...)
    // Body: {csp, organizationId, targets: [{workspaceId, roleId|roleName}]}
}
```

This ensures our service works identically to the SDK's built-in services: same auth flow, same token refresh, same cookie management, same error handling.

## 17. Distribution

| Method | Details |
|--------|---------|
| GitHub Releases | Pre-built binaries for macOS (amd64, arm64), Linux (amd64, arm64), Windows (amd64) via goreleaser |
| Homebrew | `brew install aaearon/tap/sca-cli` |
| Manual | `go install github.com/aaearon/sca-cli@latest` |

## 18. Future Considerations (Post-v1)

- AWS and GCP cloud provider support
- Active session listing and revocation (`sca-cli sessions`)
- Session TTL countdown and auto-refresh
- Shell prompt integration (show active role in PS1)
- On-demand access request workflow (approval-gated elevation)
- MCP server mode for AI agent integration (similar to CyberArk's AWS SCA MCP server)
- Bash/Zsh/Fish completion scripts
- `sca-cli wrap -- az vm list` (one-shot elevation + command execution)
- `sca-cli update` — self-update via `go-github-selfupdate` (already in SDK dep tree)

## Appendix A: SDK Comparison — What Exists vs. What We Build

| Component | ark-sdk-golang | idsec-sdk-golang | sca-cli (custom) |
|-----------|---------------|------------------|------------------|
| CyberArk Identity auth (interactive) | `ArkISPAuth` | `IdsecISPAuth` ✅ | — (reuse SDK) |
| CyberArk Identity auth (service user) | `ArkISPAuth` | `IdsecISPAuth` | ❌ Not supported |
| MFA handling (6 mechanisms) | Built-in | Built-in ✅ | — (reuse SDK) |
| Token caching / keyring | `ArkKeyring` | `IdsecKeyring` ✅ | — (reuse SDK) |
| HTTP client with auth | `ArkClient` | `IdsecClient` ✅ | — (reuse SDK) |
| ISP service URL resolution | `ArkISPServiceClient` | `IdsecISPServiceClient` ✅ | — (reuse SDK) |
| SCA workspace discovery | — | `IdsecSCAService` (admin) | — (not needed) |
| Azure workspace management | — | `IdsecCCEAzureService` (admin) | — (not needed) |
| Cloud access policy CRUD | `ArkUAPSCAService` (admin) | `IdsecPolicyCloudAccessService` (admin) | — (not needed) |
| **SCA Access: List eligibility** | ❌ Not in SDK | ❌ Not in SDK | ✅ `SCAAccessService.ListEligibility()` |
| **SCA Access: Elevate** | ❌ Not in SDK | ❌ Not in SDK | ✅ `SCAAccessService.Elevate()` |
| Interactive role selection UI | — | — | ✅ Custom (via `survey/v2` Select) |
| Shell env var injection | — | — | ✅ Custom formatter |
| Favorites management | — | — | ✅ Custom config |

## Appendix B: Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-02-10 | Initial spec with standalone implementation |
| 2.0 | 2026-02-10 | Major rewrite: switched from ark-sdk-golang to idsec-sdk-golang; scoped auth to interactive human users only (auth.Identity); removed service user support; corrected SIA vs SCA product confusion; added SCA Access Service implementation pattern; restructured project to eliminate custom auth/credential code |
| 2.1 | 2026-02-10 | Dependency alignment: removed bubbletea (use survey/v2 Select with filter instead); removed go-keyring (use 99designs/keyring via SDK); confirmed zero new Go module dependencies — all libraries reused from idsec-sdk-golang dep tree; added fatih/color for terminal output; noted go-github-selfupdate available for future self-update command |
| 2.2 | 2026-02-10 | PoC validation against live tenant. Corrected API paths: base URL is `https://{subdomain}.sca.cyberark.cloud/api`, eligibility is `GET /api/access/{CSP}/eligibility` (CSP as path param), elevate is `POST /api/access/elevate`. Resolved all 4 open questions from Section 5.1: ISP JWT works directly (no token exchange), `/oauth2/token/{app_id}` is identity-host-only Basic Auth (not needed for CLI), documented full eligibility and elevate request/response schemas. Added note that JWT `subdomain` claim differs from identity URL subdomain. Added `X-API-Version: 2.0` header requirement. Added `roleInfo` vs `role` field name discrepancy note. |
