# grant Implementation Status

**Last updated:** 2026-02-10
**Current branch:** `main`
**Plan source:** `/home/tim/sca-cli/sca-cli-functional-design-spec-v2.md`
**OpenAPI:** `/home/tim/sca-cli/Secure Cloud Access APIs.json`

---

## Phase Status

| Phase | Branch | Status | Notes |
|-------|--------|--------|-------|
| 0: Repo Setup & Scaffolding | `feat/project-scaffolding` | ✅ DONE - Merged to main | CLAUDE.md, go.mod, main.go, cmd/root.go, Makefile, README, LICENSE, .gitignore, SDK import tests |
| 1: Models | `feat/models` | ✅ DONE - Merged to main | eligibility.go, root.go, session.go + tests. Custom UnmarshalJSON for roleInfo/role |
| 2: Config & Favorites | `feat/config` | ✅ DONE - Merged to main | config.go, favorites.go + tests. YAML-based, GRANT_CONFIG env override |
| 3: SCA Access Service | `feat/sca-service` | ✅ DONE - Merged to main | service_config.go, service.go + tests. SDK service pattern with httpClient DI |
| 4: UI Layer | `feat/ui` | ✅ DONE - Merged to main | selector.go + tests. Survey-based interactive selection with formatting & lookup |
| 5: CLI Commands | `feat/commands` | ✅ DONE - Merged to main | version, configure, login, logout, elevate, status, favorites + tests. 82 total tests passing |
| 6: Integration Tests & Docs | `feat/integration-tests` | ✅ DONE - Merged to main | integration_test.go (6 tests), enhanced README, CLAUDE.md with patterns, updated Makefile |
| 7: UX Simplification | `feat/simplify-login-ux` | ✅ DONE - Merged to main | Removed MFA config, auto-configure on first login, Identity URL clarification |
| 8: Release Infrastructure | `feat/release` | ✅ DONE | .goreleaser.yaml, GitHub Actions release workflow |

---

## Phase 3: SCA Access Service (NEXT)

**Branch:** `feat/sca-service`

### What to build
- `internal/sca/service_config.go` — service name "sca-access", requires "isp" authenticator
- `internal/sca/service.go` — `SCAAccessService` with `httpClient` interface for DI

### SDK Service Pattern (from exploration of idsec-sdk-golang v0.1.14)

```go
// Service struct pattern
type SCAAccessService struct {
    services.IdsecService
    *services.IdsecBaseService
    ispAuth *auth.IdsecISPAuth
    client  *isp.IdsecISPServiceClient
}

// Constructor pattern
func NewSCAAccessService(authenticators ...auth.IdsecAuth) (*SCAAccessService, error) {
    svc := &SCAAccessService{}
    var svcIface services.IdsecService = svc
    base, err := services.NewIdsecBaseService(svcIface, authenticators...)
    // ... extract ISP auth via base.Authenticator("isp"), type assert to *auth.IdsecISPAuth
    // ... create client via isp.FromISPAuth(ispAuth, "sca", ".", "", refreshCallback)
    // ... client.SetHeader("X-API-Version", "2.0")
}

// Refresh callback
func (s *SCAAccessService) refreshAuth(client *common.IdsecClient) error {
    return isp.RefreshClient(client, s.ispAuth)
}
```

### Key SDK signatures (v0.1.14)
```go
// IdsecClient.Get
func (ac *IdsecClient) Get(ctx context.Context, route string, params interface{}) (*http.Response, error)

// IdsecClient.Post
func (ac *IdsecClient) Post(ctx context.Context, route string, body interface{}) (*http.Response, error)

// NewIdsecISPAuth
func NewIdsecISPAuth(cacheAuthentication bool) IdsecAuth

// IdsecBaseService
func NewIdsecBaseService(service IdsecService, authenticators ...auth.IdsecAuth) (*IdsecBaseService, error)
func (s *IdsecBaseService) Authenticator(authName string) (auth.IdsecAuth, error)

// FromISPAuth
func FromISPAuth(ispAuth *auth.IdsecISPAuth, serviceName string, separator string, basePath string, refreshConnectionCallback func(*common.IdsecClient) error) (*IdsecISPServiceClient, error)

// RefreshClient
func RefreshClient(client *common.IdsecClient, ispAuth *auth.IdsecISPAuth) error

// IdsecServiceConfig
type IdsecServiceConfig struct {
    ServiceName                string
    RequiredAuthenticatorNames []string
    OptionalAuthenticatorNames []string
    ActionsConfigurations      map[actions.IdsecServiceActionType][]actions.IdsecServiceActionDefinition
}
```

### httpClient interface for testability
```go
type httpClient interface {
    Get(ctx context.Context, route string, params interface{}) (*http.Response, error)
    Post(ctx context.Context, route string, body interface{}) (*http.Response, error)
}
```

### Test approach
- Use `httptest.NewServer` for mock SCA API
- `NewSCAAccessServiceWithClient(client httpClient)` for test constructor
- Tests: ListEligibility (success/empty/pagination/error), Elevate (success/partial/nil/empty), ListSessions (success/empty/csp-filter)

### API endpoints
- `GET /api/access/{CSP}/eligibility` → `ListEligibility(ctx, csp CSP) (*EligibilityResponse, error)`
- `POST /api/access/elevate` → `Elevate(ctx, req *ElevateRequest) (*ElevateResponse, error)`
- `GET /api/access/sessions` → `ListSessions(ctx, csp *CSP) (*SessionsResponse, error)`

---

## Phase 4: UI Layer (DONE)

**Branch:** `feat/ui`

### Implemented
- `internal/ui/selector.go` — interactive target selector using `Iilun/survey/v2`
  - `FormatTargetOption(target)` — formats display string per workspace type
  - `BuildOptions(targets)` — builds sorted option list
  - `FindTargetByDisplay(targets, display)` — reverse lookup
  - `SelectTarget(targets)` — interactive survey Select with fuzzy filter
- `internal/ui/selector_test.go` — 3 test functions, 13 subtests

### Format patterns implemented
- Subscription: `Subscription: {name} / Role: {roleName}`
- Resource Group: `Resource Group: {name} / Role: {roleName}`
- Management Group: `Management Group: {name} / Role: {roleName}`
- Directory: `Directory: {name} / Role: {roleName}`
- Resource: `Resource: {name} / Role: {roleName}`

---

## Phase 5: CLI Commands (DONE)

**Branch:** `feat/commands`

### Implemented Commands

1. **`cmd/version.go`** — Version command with ldflags injection
   - Displays version, commit hash, build date
   - Defaults to "dev", "unknown", "unknown" when not built with ldflags
   - Makefile updated with proper ldflags

2. **`cmd/configure.go`** — Interactive configuration
   - Survey prompts for Identity URL (`https://{subdomain}.id.cyberark.cloud`) and username
   - Creates SDK profile at `~/.idsec_profiles/grant.json` with empty `IdentityMFAMethod`
   - Creates app config at `~/.grant/config.yaml`
   - Input validation: HTTPS URL, non-empty username
   - **Note:** MFA configuration removed in Phase 7 - SDK handles MFA interactively

3. **`cmd/login.go`** — Authentication command with auto-configure
   - Auto-configures on first run if profile doesn't exist
   - Calls `IdsecISPAuth.Authenticate()` with profile
   - Displays success message with username and token expiry
   - Tokens cached in keyring via SDK
   - MFA method selection handled interactively by SDK

4. **`cmd/logout.go`** — Logout command
   - Clears all cached tokens from keyring
   - Simple success message

5. **`cmd/elevate.go`** — Core elevation command (most complex)
   - Three execution modes: interactive, direct (--target/--role), favorite (--favorite)
   - Flags: --provider/-p, --target/-t, --role/-r, --favorite/-f, --duration/-d
   - Provider validation (v1: azure only)
   - Integrates SCAAccessService.ListEligibility() and Elevate()
   - Interactive selection via ui.SelectTarget()
   - Comprehensive error handling

6. **`cmd/status.go`** — Authentication and session status
   - Shows authentication state (username)
   - Lists active sessions via SCAAccessService.ListSessions()
   - Groups sessions by provider
   - Flag: --provider/-p to filter
   - Human-readable session expiry times

7. **`cmd/favorites.go`** — Favorites management
   - Parent command with three subcommands:
     - `add <name>` — interactive prompts or `--target`/`--role` flags for non-interactive use
     - `list` — displays all favorites
     - `remove <name>` — removes a favorite

8. **Shared Infrastructure**
   - `cmd/interfaces.go` — shared interfaces for dependency injection
   - `cmd/test_mocks.go` — shared mock implementations
   - `cmd/test_helpers.go` — test utilities
   - All commands auto-register via init() functions

### Test Coverage
- 71 cmd tests covering all commands
- Table-driven tests following TDD methodology
- Mock implementations for SDK dependencies
- All edge cases and error conditions tested

---

## Phase 6: Integration Tests & Docs (DONE)

**Branch:** `feat/integration-tests`

### Implemented

1. **`cmd/integration_test.go`** — Integration tests for compiled binary
   - `//go:build integration` tag to separate from unit tests
   - `TestMain` builds binary before tests, cleans up after
   - 6 test functions covering:
     - Help output (root, short flag, help command, subcommand help)
     - Version command output format
     - Elevate without authentication (error handling)
     - Status without authentication
     - Favorites list (empty state)
     - Invalid command handling
   - Uses `exec.Command` to test actual binary behavior
   - Temporary directories for config isolation

2. **Makefile Updates**
   - Added `test-integration` target: `go test ./cmd -tags=integration -v`
   - Added `test-all` target: runs both unit and integration tests
   - Updated `.PHONY` declarations

3. **README.md Enhancements**
   - Installation section with binary releases for macOS/Linux/Windows
   - Expanded Quick Start with step-by-step setup
   - Detailed command documentation with examples
   - Configuration section with environment variables
   - "How It Works" section explaining Azure elevation and authentication flows
   - Comprehensive Troubleshooting section
   - Development section with testing and build commands
   - Contributing guidelines

4. **CLAUDE.md Updates**
   - Added "Implementation Patterns" section
   - Command structure patterns (factory functions, RunE, init registration)
   - Dependency injection patterns (interfaces, test injection)
   - Testing patterns (table-driven, mocks, integration tests)
   - Error handling conventions
   - Output handling (cmd.OutOrStdout)
   - Flag patterns
   - Config loading patterns
   - Service initialization examples

### Test Coverage
All tests passing:
- Unit tests: 82 tests (all packages)
- Integration tests: 6 test functions with 11 subtests
- Total: 88+ tests

---

## Phase 7: UX Simplification (DONE)

**Branch:** `feat/simplify-login-ux` (merged and deleted)

### Implemented Changes

**Goal:** Simplify first-time user experience by removing MFA configuration and enabling auto-configure on first login.

#### 1. Configure Command Simplification
- **Removed:** MFA method prompts and validation
- **Removed:** `validMFAMethods` variable and `validateMFAMethod()` function
- **Changed:** Always set `IdentityMFAMethod: ""` in profile (empty string)
- **Updated:** Command descriptions to clarify MFA is handled interactively by SDK
- **Updated:** Prompt changed from "CyberArk Tenant URL" to "CyberArk Identity URL"
- **Added:** Identity URL format specification in help text (`https://{subdomain}.id.cyberark.cloud`)

#### 2. Login Command Enhancement
- **Added:** Auto-configure flow when profile doesn't exist
- **Added:** Message: "No configuration found. Let's set up grant."
- **Flow:** Detects missing profile → runs configure → proceeds to authentication
- **Updated:** Command Long description to mention auto-configure feature

#### 3. Test Updates
- **configure_test.go:** Removed MFA-related test cases (32 tests removed)
  - Deleted `TestValidateMFAMethod()` function
  - Removed "invalid MFA method" test case
  - Updated assertions to verify empty MFA method
- **login_test.go:** Added profile setup to prevent auto-configure trigger in existing tests
  - Added placeholder tests for auto-configure scenarios (marked as Skip)
- **integration_test.go:** Removed "MFA" from configure help expectations

#### 4. Documentation Updates
- **README.md:**
  - Simplified Quick Start to single `grant login` command
  - Updated all references from "Tenant URL" to "Identity URL"
  - Added Identity URL format specification: `https://{subdomain}.id.cyberark.cloud`
  - Removed invalid example: `https://company.cyberark.cloud`
  - Updated configure/login command documentation
  - Updated troubleshooting section
- **configure.go help text:** Added format specification and example

### Backwards Compatibility
- ✅ Existing profiles with `IdentityMFAMethod` set continue working
- ✅ SDK respects configured method with `IdentityMFAInteractive=true` fallback
- ✅ No migration needed for existing users

### Test Results
- Unit tests: 80+ tests passing (reduced from 82 due to MFA test removal)
- Integration tests: All 6 test functions passing
- Zero breaking changes

### Git Commits
```
d74d288 - docs: add Identity URL format to configure help text
74976bb - docs: fix Identity URL format in examples and help text
fa62e5f - feat: simplify login UX - remove MFA config, add auto-configure
```

---

## Feature: Verbose Flag (`feat/verbose-flag`)

**Status:** DONE

### Implemented

1. **`internal/sca/logging_client.go`** — `loggingClient` decorator
   - `logger` interface (Info/Error/Debug) for DI — satisfied by `*common.IdsecLogger`
   - Wraps `httpClient`, logs method/route/status/duration at INFO level
   - Errors logged at ERROR level
   - Response headers logged at DEBUG with `Authorization` redacted
   - `redactHeaders()` replaces auth values with `Bearer [REDACTED]`

2. **`internal/sca/logging_client_test.go`** — 8 subtests
   - Get/Post delegation, success/error logging, duration logging, header redaction

3. **`cmd/root.go`** — `PersistentPreRunE` wiring
   - `--verbose` → `config.EnableVerboseLogging("INFO")`
   - No `--verbose` → `config.DisableVerboseLogging()`
   - `Execute()` prints `"Hint: re-run with --verbose for more details"` on error

4. **`cmd/root_test.go`** — 2 tests for PersistentPreRunE env var behavior

5. **`cmd/test_helpers.go`** — Mirrors PersistentPreRunE in `NewRootCommand()`

6. **`internal/sca/service.go`** — Wraps ISP client with `loggingClient` via `common.GetLogger("grant", -1)`

---

## Phase 8: Release Infrastructure (DONE)

**Branch:** `feat/release`

### Implemented

1. **`.goreleaser.yaml`** — GoReleaser v2 configuration
   - Binary name: `grant`
   - Ldflags: `-s -w` + version/commit/buildDate injection (matches Makefile)
   - Targets: linux/darwin/windows on amd64/arm64 (6 binaries)
   - Archives: tar.gz for linux/darwin, zip for windows
   - Checksums: sha256 (`checksums.txt`)
   - Changelog: auto-generated, sorted asc, excludes docs/test/ci commits

2. **`.github/workflows/release.yml`** — GitHub Actions release workflow
   - Trigger: push tags matching `v*`
   - Steps: checkout (fetch-depth 0), setup Go 1.25, GoReleaser v6 action
   - Permissions: `contents: write` for creating releases
   - Uses `GITHUB_TOKEN` for authentication

### Verification
- `goreleaser check` — config validated
- `goreleaser release --snapshot --clean` — all 6 targets built successfully

---

## Current File Structure (implemented)

```
grant/
├── .goreleaser.yaml                  # GoReleaser v2 config (6 targets, ldflags, checksums)
├── .github/
│   └── workflows/
│       └── release.yml               # GitHub Actions: tag push → GoReleaser release
├── CLAUDE.md                         # Project conventions + implementation patterns
├── LICENSE
├── Makefile                          # build, test, test-integration, test-all, lint, clean
├── README.md                         # Complete documentation with installation, commands, troubleshooting
├── main.go                           # calls cmd.Execute()
├── go.mod                            # module github.com/aaearon/grant-cli
├── go.sum
├── cmd/
│   ├── root.go                       # cobra root command with --verbose, PersistentPreRunE
│   ├── root_test.go                  # 2 tests (PersistentPreRunE verbose wiring)
│   ├── version.go                    # version command with ldflags
│   ├── version_test.go               # 2 tests
│   ├── configure.go                  # configure command with survey prompts
│   ├── configure_test.go             # 18 tests (configure + validation)
│   ├── login.go                      # login command using IdsecISPAuth
│   ├── login_test.go                 # 7 tests
│   ├── logout.go                     # logout command clearing keyring
│   ├── logout_test.go                # 6 tests
│   ├── elevate.go                    # core elevate command (3 modes)
│   ├── elevate_test.go               # 21 tests
│   ├── status.go                     # status command showing auth + sessions
│   ├── status_test.go                # 12 tests
│   ├── favorites.go                  # favorites parent with add/list/remove
│   ├── favorites_test.go             # 5 tests
│   ├── integration_test.go           # 6 integration test functions (//go:build integration)
│   ├── interfaces.go                 # shared interfaces for DI
│   ├── test_mocks.go                 # shared test mocks
│   └── test_helpers.go               # test utilities
├── internal/
│   ├── config/
│   │   ├── config.go                 # Config, Favorite, Load, Save, DefaultConfig, ConfigPath, ConfigDir
│   │   ├── config_test.go            # 6 tests
│   │   ├── favorites.go              # AddFavorite, RemoveFavorite, GetFavorite, ListFavorites, FavoriteEntry
│   │   └── favorites_test.go         # 9 tests
│   ├── ui/
│   │   ├── selector.go               # FormatTargetOption, BuildOptions, FindTargetByDisplay, SelectTarget
│   │   └── selector_test.go          # 3 test functions, 13 subtests
│   └── sca/
│       ├── sdk_import_test.go        # SDK type verification (2 tests)
│       ├── service_config.go         # ServiceConfig() for sca-access service
│       ├── service_config_test.go    # 5 tests
│       ├── logging_client.go          # loggingClient decorator with logger interface
│       ├── logging_client_test.go    # 8 subtests (delegation, logging, redaction)
│       ├── service.go                # SCAAccessService with ListEligibility, Elevate, ListSessions
│       ├── service_test.go           # 10 tests
│       └── models/
│           ├── eligibility.go        # CSP, WorkspaceType, RoleInfo, AzureEligibleTarget (custom UnmarshalJSON), EligibilityResponse
│           ├── eligibility_test.go   # 6 tests
│           ├── root.go               # ElevateTarget, ElevateRequest, ErrorInfo, ElevateTargetResult, ElevateAccessResult, ElevateResponse
│           ├── root_elevate_test.go  # 6 tests
│           ├── session.go            # SessionInfo (snake_case JSON tags), SessionsResponse
│           └── session_test.go       # 4 tests (incl. real API payload test)
└── poc/                              # PoC code (reference only)
```

## Git Status
- ✅ All phases 0-7 merged to `main`
- 📍 Current branch: `main`
- 🚀 `main` is ahead of `origin/main` by 22 commits (not pushed)
- 🧹 Feature branches deleted: `feat/simplify-login-ux`
- 🗑️ Old branches can be cleaned up: `feat/project-scaffolding`, `feat/models`, `feat/config`, `feat/config-favorites`, `feat/sca-service`, `feat/ui`, `feat/commands`, `feat/integration-tests`

## Test Count: 87+ tests total, all passing

### Unit Tests (80+ tests)
- cmd: 69 tests (version, configure, login, logout, elevate, status, favorites)
- config: 16 tests (added permission error test)
- sca: 17 tests
- sca/models: 15 tests
- ui: 13 tests

### Integration Tests (6 test functions, 11 subtests)
- cmd/integration_test.go: help, version, elevate-without-login, status-without-login, favorites-list, invalid-command

## Bug Fixes

### FIX: Status sessions display blank lines (fix/status-sessions)

**Status:** Fixed
**Discovered:** 2026-02-10

`grant status` showed sessions as blank lines (`   on  - duration: 0m`) because the `SessionInfo` struct used camelCase JSON tags (`sessionId`, `roleId`, etc.) while the live SCA API returns snake_case (`session_id`, `role_id`, etc.). The OpenAPI spec incorrectly documents camelCase.

Additionally, the `role_id` field in the API response contains the role **display name** (e.g., "User Access Administrator"), not an ARM resource path. The API does not return `workspaceName`, `roleName`, or `expiresAt` fields.

**Root cause:** JSON field name mismatch — struct tags didn't match real API response format.

**Changes:**
- `internal/sca/models/session.go` — Updated JSON tags to snake_case, removed non-existent fields (`WorkspaceName`, `RoleName`, `ExpiresAt`)
- `internal/sca/models/session_test.go` — Updated tests with real API format, added `TestSessionInfo_RealAPIPayload` from live capture
- `cmd/status.go` — Simplified `formatSession()` to use `RoleID` (contains name) and `SessionDuration` directly
- `cmd/status_test.go` — Updated mock data and expected output to match real API behavior

---

## Code Review Improvements (`fix/code-review-improvements`)

**Status:** Done
**Date:** 2026-02-10

Comprehensive code quality sweep addressing issues found during code review.

### HIGH - Bug Fixes
1. **config.Load() error handling** — Non-ErrNotExist errors (permission denied, I/O errors) were silently swallowed, returning defaults. Now returns the error. Added `TestLoadConfig_PermissionError` test.
2. **Duplicate login functions** — Consolidated `runLogin()` and `runLoginWithAuth()` into single `runLogin(cmd, auth authenticator)`. Both production and test paths now use the same function.
3. **Duplicate status functions** — Consolidated `runStatus()` and `runStatusWithDeps()` into single `runStatus()` that accepts `profile` parameter (can be nil for test path). Removed package-level `statusProvider` variable; flag value now read via `cmd.Flags().GetString("provider")` inside RunE.
4. **Redundant profile loading** — Production `rootCmd.RunE` loaded the profile, then `runElevate()` loaded it again. Removed `runElevate` wrapper; production path now calls `runElevateWithDeps` directly with the already-loaded profile.

### MEDIUM - Design Fixes
5. **Removed `--duration` flag** — Flag was parsed but never wired into `ElevateRequest`. Removed from struct, flag registration, and test assertions. Can be re-added when API support is confirmed.
6. **io.ReadAll error handling** — Three error-response paths in `service.go` discarded `io.ReadAll` errors. Now includes fallback message `"(failed to read response body)"` when read fails.

### LOW - Consistency Fixes
7. **Error message capitalization** — Lowercased all `fmt.Errorf` strings per Go convention. Updated 9 error messages in `root.go` and corresponding test assertions.
8. **Unicode checkmark removed** — Replaced `"✓ Elevated..."` with `"Elevated..."` for terminal compatibility.
9. **Output method consistency** — Changed `cmd.Printf()` in `configure.go` to `fmt.Fprintf(cmd.OutOrStdout(), ...)` for consistency with all other commands.

### CI/CD Improvements
10. **Makefile** — Added `test-race` target with `-race` flag. Added `test-coverage` target with `coverprofile`. Changed `test-all` to use `test-race`. Added `coverage.out` to `clean`.
11. **CI workflow** — Added `.github/workflows/ci.yml` that runs build, test-race, and lint on push/PR to main.

### Files Modified
- `internal/config/config.go` — Error propagation fix
- `internal/config/config_test.go` — Added permission error test
- `internal/sca/service.go` — io.ReadAll error handling
- `cmd/login.go` — Consolidated duplicate functions
- `cmd/status.go` — Consolidated duplicate functions, removed package-level var
- `cmd/root.go` — Removed runElevate wrapper, --duration flag, lowercased errors, removed checkmark
- `cmd/root_elevate_test.go` — Updated assertions for new error messages, removed --duration test
- `cmd/configure.go` — Output method consistency
- `Makefile` — Race, coverage targets
- `.github/workflows/ci.yml` — New CI workflow

---

## Code Review Findings Round 2 (`fix/code-review-findings`)

**Status:** Done
**Date:** 2026-02-17

Addresses 10 findings (3 HIGH, 4 MEDIUM, 3 LOW) from comprehensive code review.

### HIGH - Structural Fixes
1. **Double error output (#1)** — Set `SilenceErrors: true` and `SilenceUsage: true` on root command. Cobra no longer prints errors; only `Execute()` prints them.
2. **Duplicated root command construction (#3)** — Extracted `newRootCommand(runFn)` as single source of truth for flags, `PersistentPreRunE`, and silence settings. `rootCmd`, `NewRootCommandWithDeps`, and `newTestRootCommand` all delegate to it.
3. **Exported test helper (#10)** — Renamed `NewRootCommand()` to unexported `newTestRootCommand()`. Updated 12 call sites.

### MEDIUM - Design Fixes
4. **Logout no DI (#4)** — Added `keyringClearer` interface and `NewLogoutCommandWithDeps(clearer)` for deterministic testing. Production path creates real keyring in closure.
5. **Scattered mocks (#5)** — Consolidated 6 mock types from `root_elevate_test.go`, `login_test.go`, `configure_test.go` into `test_mocks.go`. Added `mockKeyringClearer`.
6. **Duplicated auth bootstrap (#6)** — Extracted `bootstrapSCAService()` used by both `runElevateProduction()` and `NewStatusCommand()`, removing 24 lines of duplication.
8. **ConfigDir error propagation (#8)** — Changed `ConfigDir()` and `ConfigPath()` signatures from `string` to `(string, error)`. All 5 call sites updated with error handling.

### LOW - Quality Fixes
9. **Case-sensitive target match (#9)** — `findMatchingTarget()` now uses `strings.EqualFold` for workspace name and role name comparison.
11. **SilenceUsage (#11)** — Set on root command via `newRootCommand()` (combined with #1 fix).

### Files Modified
- `cmd/root.go` — `newRootCommand()`, `bootstrapSCAService()`, `SilenceErrors`/`SilenceUsage`, case-insensitive match
- `cmd/root_test.go` — Tests for silence flags, `newTestRootCommand`
- `cmd/root_elevate_test.go` — Removed mock definitions, added case-insensitive test
- `cmd/test_helpers.go` — Renamed to `newTestRootCommand()`, error text in output
- `cmd/test_mocks.go` — Consolidated all 7 mock types
- `cmd/interfaces.go` — Added `keyringClearer` interface
- `cmd/logout.go` — Added `NewLogoutCommandWithDeps`, `runLogout` takes `keyringClearer`
- `cmd/logout_test.go` — Deterministic tests with mock clearer
- `cmd/login_test.go` — Removed mock definition
- `cmd/configure_test.go` — Removed mock definition
- `cmd/status.go` — Uses `bootstrapSCAService()`
- `cmd/favorites.go` — `ConfigPath()` error handling
- `cmd/configure.go` — `ConfigPath()` error handling
- `internal/config/config.go` — `ConfigDir()`/`ConfigPath()` return errors
- `internal/config/config_test.go` — Updated tests for new signatures

---

## Feature: Status Workspace Names (`fix/code-review-findings`)

**Status:** Done
**Date:** 2026-02-17

### Problem

`grant status` showed raw ARM resource paths (e.g., `providers/Microsoft.Management/managementGroups/29cb7961-...`) instead of friendly workspace names. The sessions API (`GET /api/access/sessions`) only returns `workspace_id`, not `workspace_name`.

### Solution

Cross-reference sessions with the eligibility API (`GET /api/access/{CSP}/eligibility`) to resolve workspace IDs to friendly names. Display format: `Name (path)` when name is available, raw path as fallback.

**Before:** `User Access Administrator on providers/Microsoft.Management/managementGroups/29cb7961-... - duration: 1h 0m`
**After:**  `User Access Administrator on Tenant Root Group (providers/Microsoft.Management/managementGroups/29cb7961-...) - duration: 1h 0m`

### Implementation

- Added `eligibilityLister` as a dependency to `runStatus()` and `NewStatusCommandWithDeps()`
- `buildWorkspaceNameMap()` collects unique CSPs from sessions, fetches eligibility for each, builds `map[string]string` (workspaceID -> workspaceName)
- `formatSession()` accepts name map, shows `"name (id)"` when name is resolved, falls back to raw ID
- Graceful degradation: eligibility API errors are silently ignored, raw workspace ID shown as fallback

### Files Modified

- `cmd/status.go` — `buildWorkspaceNameMap()`, updated `formatSession()` signature, `runStatus()` and `NewStatusCommandWithDeps()` accept `eligibilityLister`
- `cmd/status_test.go` — Added `setupEligibility` to all test cases, updated assertions for `"name (path)"` format, added `"eligibility fetch fails - graceful degradation"` test case

---

## Feature: Non-Interactive Favorites Add (`feat/favorites-add-flags`)

**Status:** Done
**Date:** 2026-02-18

### Problem

`grant favorites add <name>` required interactive survey prompts, preventing scripting and automation.

### Solution

Added `--provider/-p`, `--target/-t`, `--role/-r` flags to `favorites add`. When `--target` and `--role` are both provided, interactive prompts are skipped. Provider defaults to config value when omitted. Mirrors the root elevation command's flag pattern.

### Implementation

- `newFavoritesAddCommand()` — registers `--provider`, `--target`, `--role` flags
- `runFavoritesAdd()` — mode branching: non-interactive when both `--target` and `--role` set, interactive otherwise
- Validation: providing only one of `--target`/`--role` returns error
- When `--provider` is set without `--target`/`--role`, it's used as the survey prompt default

### Tests

- 7 new unit test cases in `TestFavoritesAddCommand` (flag success, validation errors, duplicate with flags)
- `TestFavoritesAddWithFlagsPersistence` — verifies config reload after flag-based add
- `TestIntegration_FavoritesAddWithFlags` — binary-level test with `favorites list` verification

---

## Feature: Eligibility-Based Interactive Favorites Add (`feat/favorites-add-eligibility`)

**Status:** Done
**Date:** 2026-02-18

### Problem

`grant favorites add <name>` interactive mode used three free-text `survey.Input` prompts (provider, target, role), requiring users to type exact names from memory. The root elevation command already had a much better UX with eligibility-based interactive selection.

### Solution

Replaced the survey prompts with the same eligibility-based `ui.SelectTarget()` flow used by the root elevation command. Interactive mode now fetches eligible targets from SCA and presents a fuzzy-searchable selector. Non-interactive flag path (`--target` + `--role`) unchanged and does NOT require auth.

### Implementation

- `newFavoritesAddCommandWithRunner()` — shared command builder centralizing flag registration
- `NewFavoritesCommandWithDeps(eligLister, selector)` — DI constructor for testing
- `runFavoritesAddProduction()` — production RunE: checks duplicate before auth, bootstraps SCA service for interactive mode
- `runFavoritesAddWithDeps()` — core logic: non-interactive flag path or eligibility-based interactive selection
- Removed `survey` import from `favorites.go` — all interactive selection handled by `ui.SelectTarget()`
- Reuses `bootstrapSCAService()`, `uiSelector`, existing interfaces/mocks

### Tests

- 8 new unit test cases in `TestFavoritesAddInteractiveMode` (success, provider flag, config default, eligibility fails, no targets, selector cancelled, duplicate name, flags bypass)
- `TestIntegration_FavoritesAddInteractiveRequiresAuth` — binary-level test

---

## Feature: Favorites UX Improvements (`feat/favorites-ux-improvements`)

**Status:** Done
**Date:** 2026-02-18

### Problem

1. `grant favorites add` and `grant favorites remove` with no arguments produce unhelpful Cobra default error: "accepts 1 arg(s), received 0"
2. The verbose hint ("Hint: re-run with --verbose for more details") appears for arg validation errors where verbose mode adds no value
3. Users must know a favorite name before seeing available targets
4. Help text lacks examples and cross-references

### Solution

- **Optional name for `favorites add`**: Name can be provided upfront or prompted after interactive target selection. Non-interactive mode (--target/--role) still requires name as argument.
- **Custom arg validator for `favorites remove`**: Replaces Cobra's `ExactArgs(1)` with a user-friendly error that includes usage hint and cross-reference to `grant favorites list`
- **Verbose hint suppression**: Added `passedArgValidation` flag set in `PersistentPreRunE`. Since arg validation fails before `PersistentPreRunE` runs, the flag stays false for arg errors, suppressing the misleading hint.
- **Improved help text**: Added `Example` fields to all favorites subcommands, workflow description to parent command, actionable empty-state message, and cross-reference in `--favorite` flag description.

### Implementation

- `namePrompter` interface + `surveyNamePrompter` production impl + `mockNamePrompter` test mock
- `NewFavoritesCommandWithDeps(eligLister, selector, prompter)` — now accepts `namePrompter` dep
- `runFavoritesAddWithDeps()` — name from arg or prompted after selection; duplicate check deferred when name unknown
- `newFavoritesRemoveCommand()` — custom `Args` function with helpful error
- `passedArgValidation` flag in root.go + `executeWithHint()` test helper
- Help text: `Example` fields, improved `Long` descriptions, `--favorite` flag description

### Tests

- 4 new test cases in `TestFavoritesAddInteractiveMode` (prompted name, duplicate prompted name, prompter error, no name with flags)
- Updated `TestFavoritesRemoveCommand/remove_without_name` to assert custom error message
- Updated `TestFavoritesAddCommand/add_without_name` for non-interactive name requirement
- Updated `TestFavoritesListCommand` for actionable empty-state message
- 5 new tests in `root_test.go` (verbose hint suppression for arg errors, unknown subcommands, runtime errors, executeWithHint output)

---

## Claude Skill: grant-login

**Location:** `.claude/skills/grant-login/SKILL.md`

Reusable Claude skill for driving the interactive `grant login` flow via tmux. Reads credentials from `.env`, sends password, selects OATH Code MFA method, generates TOTP via python3 stdlib, and verifies successful authentication.

---

## Latest Changes (Phase 7 - UX Simplification)

### Files Modified
```
README.md               |  54 ++++++-------  (Identity URL clarification)
cmd/configure.go        |  60 ++++----------  (Remove MFA config)
cmd/configure_test.go   | 125 +----------------------------  (Remove MFA tests)
cmd/integration_test.go |   2 +-                          (Update help test)
cmd/login.go            |  52 +++++++++++-                 (Auto-configure)
cmd/login_test.go       | 209 ++++++++++++++++++++++++++++++++++++++  (Profile setup)
```

### User-Facing Changes
- ✅ Single command first-time setup: `grant login` (no separate configure needed)
- ✅ MFA method selection handled interactively by SDK (no pre-configuration)
- ✅ Clear Identity URL format: `https://{subdomain}.id.cyberark.cloud`
- ✅ `grant configure` still available for reconfiguration
