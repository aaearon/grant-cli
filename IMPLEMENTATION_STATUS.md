# sca-cli Implementation Status

**Last updated:** 2026-02-10
**Current branch:** `feat/integration-tests`
**Plan source:** `/home/tim/sca-cli/sca-cli-functional-design-spec-v2.md`
**OpenAPI:** `/home/tim/sca-cli/Secure Cloud Access APIs.json`

---

## Phase Status

| Phase | Branch | Status | Notes |
|-------|--------|--------|-------|
| 0: Repo Setup & Scaffolding | `feat/project-scaffolding` | DONE - Merged to main | CLAUDE.md, go.mod, main.go, cmd/root.go, Makefile, README, LICENSE, .gitignore, SDK import tests |
| 1: Models | `feat/models` | DONE - Merged to main | eligibility.go, elevate.go, session.go + tests. Custom UnmarshalJSON for roleInfo/role |
| 2: Config & Favorites | `feat/config` | DONE - Merged to main | config.go, favorites.go + tests. YAML-based, SCA_CLI_CONFIG env override |
| 3: SCA Access Service | `feat/sca-service` | DONE - Merged to main | service_config.go, service.go + tests. SDK service pattern with httpClient DI |
| 4: UI Layer | `feat/ui` | DONE - Merged to main | selector.go + tests. Survey-based interactive selection with formatting & lookup |
| 5: CLI Commands | `feat/commands` | DONE - Merged to main | version, configure, login, logout, elevate, status, favorites + tests. 82 total tests passing |
| 6: Integration Tests & Docs | `feat/integration-tests` | DONE - Ready to merge | integration_test.go (6 tests), enhanced README, CLAUDE.md with patterns, updated Makefile |
| 7: Release Infrastructure | `feat/release` | TODO | Parallelizable with Phase 6 |

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
   - Survey prompts for tenant URL, username, optional MFA method
   - Creates SDK profile at `~/.idsec_profiles/sca-cli.json`
   - Creates app config at `~/.sca-cli/config.yaml`
   - Input validation: HTTPS URL, non-empty username, valid MFA methods

3. **`cmd/login.go`** — Authentication command
   - Calls `IdsecISPAuth.Authenticate()` with profile
   - Displays success message with username and token expiry
   - Tokens cached in keyring via SDK

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
     - `add <name>` — interactive prompts for provider/target/role
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

## Phase 7: Release Infrastructure

**Branch:** `feat/release`

- `.goreleaser.yml` — darwin/amd64+arm64, linux/amd64+arm64, windows/amd64
- `.github/workflows/ci.yml` — on push/PR: test + lint
- `.github/workflows/release.yml` — on tag v*: test + goreleaser

---

## Current File Structure (implemented)

```
sca-cli/
├── CLAUDE.md                         # Project conventions + implementation patterns
├── LICENSE
├── Makefile                          # build, test, test-integration, test-all, lint, clean
├── README.md                         # Complete documentation with installation, commands, troubleshooting
├── main.go                           # calls cmd.Execute()
├── go.mod                            # module github.com/aaearon/sca-cli
├── go.sum
├── cmd/
│   ├── root.go                       # cobra root command with --verbose
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
│       ├── service.go                # SCAAccessService with ListEligibility, Elevate, ListSessions
│       ├── service_test.go           # 10 tests
│       └── models/
│           ├── eligibility.go        # CSP, WorkspaceType, RoleInfo, AzureEligibleTarget (custom UnmarshalJSON), EligibilityResponse
│           ├── eligibility_test.go   # 6 tests
│           ├── elevate.go            # ElevateTarget, ElevateRequest, ErrorInfo, ElevateTargetResult, ElevateAccessResult, ElevateResponse
│           ├── elevate_test.go       # 6 tests
│           ├── session.go            # SessionInfo, SessionsResponse
│           └── session_test.go       # 3 tests
└── poc/                              # PoC code (reference only)
```

## Git Status
- All phases 0-5 merged to `main`
- Phase 6 on `feat/integration-tests` branch, ready to merge
- `main` is ahead of `origin/main` by 18 commits (not pushed)
- Old branches can be cleaned up: `feat/project-scaffolding`, `feat/models`, `feat/config`, `feat/config-favorites`, `feat/sca-service`, `feat/ui`, `feat/commands`

## Test Count: 88+ tests total, all passing

### Unit Tests (82 tests)
- cmd: 71 tests (version, configure, login, logout, elevate, status, favorites)
- config: 15 tests
- sca: 17 tests
- sca/models: 15 tests
- ui: 13 tests

### Integration Tests (6 test functions, 11 subtests)
- cmd/integration_test.go: help, version, elevate-without-login, status-without-login, favorites-list, invalid-command
