# sca-cli Implementation Status

**Last updated:** 2026-02-10
**Current branch:** `main`
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
| 4: UI Layer | `feat/ui` | TODO | Depends on Phase 1 (done) |
| 5: CLI Commands | `feat/commands` | TODO | Depends on Phases 2, 3, 4 |
| 6: Integration Tests & Docs | `feat/integration-tests` | TODO | Depends on Phase 5 |
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

## Phase 4: UI Layer (NEXT, parallelizable with Phase 3)

**Branch:** `feat/ui`

### What to build
- `internal/ui/selector.go` — interactive target selector using `survey/v2`
- `FormatTargetOption(target)` — formats display string per workspace type
- `BuildOptions(targets)` — builds sorted option list
- `FindTargetByDisplay(targets, display)` — reverse lookup
- `SelectTarget(targets)` — interactive survey Select with filter

### Format patterns
- Subscription: `Subscription: {name} / Role: {roleName}`
- Resource Group: `Resource Group: {name} / Role: {roleName}`
- Management Group: `Management Group: {name} / Role: {roleName}`
- Directory: `Directory: {name} / Role: {roleName}`

---

## Phase 5: CLI Commands (after Phases 2-4)

**Branch:** `feat/commands`

### Commands to implement
1. `cmd/version.go` — ldflags-injected version/commit/date
2. `cmd/configure.go` — survey prompts for tenant URL, username, MFA; creates SDK profile + app config
3. `cmd/login.go` — calls IdsecISPAuth.Authenticate()
4. `cmd/logout.go` — clears keyring
5. `cmd/elevate.go` — core command with --provider/-p, --target/-t, --role/-r, --favorite/-f, --duration/-d
6. `cmd/status.go` — shows auth state + active sessions
7. `cmd/favorites.go` — parent with add/list/remove subcommands
8. Wire all into `cmd/root.go`

---

## Phase 6: Integration Tests & Docs

**Branch:** `feat/integration-tests`

- `cmd/integration_test.go` with `//go:build integration` tag
- Test compiled binary: help, version, elevate-without-login error
- Finalize README with install, quickstart, all commands, config reference, troubleshooting
- Update CLAUDE.md with implementation patterns

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
├── CLAUDE.md
├── LICENSE
├── Makefile
├── README.md
├── main.go                           # calls cmd.Execute()
├── go.mod                            # module github.com/aaearon/sca-cli
├── go.sum
├── cmd/
│   └── root.go                       # cobra root command with --verbose
├── internal/
│   ├── config/
│   │   ├── config.go                 # Config, Favorite, Load, Save, DefaultConfig, ConfigPath, ConfigDir
│   │   ├── config_test.go            # 6 tests
│   │   ├── favorites.go              # AddFavorite, RemoveFavorite, GetFavorite, ListFavorites, FavoriteEntry
│   │   └── favorites_test.go         # 9 tests
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
- All phases 0-3 merged to `main`
- `main` is ahead of `origin/main` by 11 commits (not pushed)
- Old branches can be cleaned up: `feat/project-scaffolding`, `feat/models`, `feat/config`, `feat/config-favorites`, `feat/sca-service`

## Test Count: 52 tests total, all passing
