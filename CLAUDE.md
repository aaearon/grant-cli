# grant

## Project
- **Language:** Go 1.24+
- **Module:** `github.com/aaearon/grant-cli`
- **Sole dependency:** `github.com/cyberark/idsec-sdk-golang` — zero new Go module deps (all libs reused from SDK dep tree)

## SDK Import Conventions
```go
import (
    "github.com/cyberark/idsec-sdk-golang/pkg/auth"
    "github.com/cyberark/idsec-sdk-golang/pkg/common"
    "github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
    "github.com/cyberark/idsec-sdk-golang/pkg/models"
    "github.com/cyberark/idsec-sdk-golang/pkg/services"
)
```

## SDK Types Cheat-Sheet
| Type | Package | Purpose |
|------|---------|---------|
| `auth.IdsecAuth` | `pkg/auth` | Auth interface |
| `auth.IdsecISPAuth` | `pkg/auth` | ISP authenticator — `NewIdsecISPAuth(isServiceUser bool)` |
| `isp.IdsecISPServiceClient` | `pkg/common/isp` | HTTP client with auth headers |
| `services.IdsecService` | `pkg/services` | Service interface |
| `services.IdsecBaseService` | `pkg/services` | Base service with auth resolution |
| `models.IdsecProfile` | `pkg/models` | Profile storage |

## Service Pattern
Custom `SCAAccessService` follows SDK conventions:
- Embed `services.IdsecService` + `*services.IdsecBaseService`
- Create client via `isp.FromISPAuth(ispAuth, "sca", ".", "", refreshCallback)`
- Set `X-API-Version: 2.0` header on all requests
- `httpClient` interface for DI/testing

## SCA Access API
- **Base URL:** `https://{subdomain}.sca.{platform_domain}/api`
- **Endpoints:**
  - `GET /api/access/{CSP}/eligibility` — list eligible targets
  - `POST /api/access/elevate` — request JIT elevation
  - `GET /api/access/sessions` — list active sessions
- **Headers:** `Authorization: Bearer {jwt}`, `X-API-Version: 2.0`, `Content-Type: application/json`

## Testing
- TDD: write `_test.go` before `.go` for every package
- Table-driven tests
- `httptest.NewServer` for service mocks
- `httpClient` interface for DI
- Test files co-located as `_test.go`

## CLI
- `spf13/cobra` + `spf13/viper` for CLI framework
- `Iilun/survey/v2` for interactive prompts
- `fatih/color` for terminal output

## Verbose / Logging
- `--verbose` / `-v` global flag wired via `PersistentPreRunE` in `cmd/root.go`
- Calls `config.EnableVerboseLogging("INFO")` (sets `IDSEC_LOG_LEVEL=INFO`) or `config.DisableVerboseLogging()` (sets `IDSEC_LOG_LEVEL=CRITICAL`)
- `loggingClient` in `internal/sca/logging_client.go` decorates `httpClient`, logging method/route/status/duration at INFO, response headers at DEBUG with Authorization redaction
- `NewSCAAccessService()` wraps ISP client with `loggingClient` using `common.GetLogger("grant", -1)` (dynamic level from env)
- `NewSCAAccessServiceWithClient()` (test constructor) does not wrap — tests don't need logging
- `Execute()` prints `"Hint: re-run with --verbose for more details"` on error when verbose is off
- Users can set `IDSEC_LOG_LEVEL=DEBUG` env var for deeper SDK output

## Config
- App config: `~/.grant/config.yaml`
- SDK profile: `~/.idsec_profiles/grant.json`

## Build
```bash
make build              # Build binary with ldflags
make test               # Run unit tests
make test-integration   # Run integration tests (builds binary)
make test-all           # Run all tests
make lint               # Run linter
make clean              # Clean build artifacts
```

## Git
- Feature branches, conventional commits
- Branch naming: `feat/`, `fix/`, `docs/`

---

## Implementation Patterns

### Command Structure

Commands follow Cobra best practices:

```go
// Factory function for testability
func NewCommandName() *cobra.Command {
    return &cobra.Command{
        Use:   "command-name",
        Short: "Brief description",
        Long:  "Detailed description...",
        RunE: func(cmd *cobra.Command, args []string) error {
            return runCommandName(cmd, args)
        },
    }
}

// Separate run function for testability
func runCommandName(cmd *cobra.Command, args []string) error {
    // Implementation
}

// Auto-register in init()
func init() {
    rootCmd.AddCommand(NewCommandName())
}
```

### Dependency Injection

Commands use interfaces for testability:

```go
// interfaces.go
type authProvider interface {
    Authenticate(profile *models.IdsecProfile) (*models.IdsecToken, error)
}

type scaService interface {
    ListEligibility(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error)
    Elevate(ctx context.Context, req *models.ElevateRequest) (*models.ElevateResponse, error)
}

// Command runtime resolution
var (
    getAuth = func() (authProvider, error) { /* ... */ }
    getSCAService = func() (scaService, error) { /* ... */ }
)

// Test injection via package vars
func TestMyCommand(t *testing.T) {
    originalGetAuth := getAuth
    defer func() { getAuth = originalGetAuth }()

    getAuth = func() (authProvider, error) {
        return &mockAuth{}, nil
    }
}
```

### Testing Patterns

#### Table-Driven Tests
```go
func TestCommand(t *testing.T) {
    tests := []struct {
        name    string
        args    []string
        flags   map[string]string
        wantErr bool
        wantOutput string
    }{
        {name: "success case", args: []string{}, wantErr: false},
        {name: "error case", args: []string{}, wantErr: true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

#### Mock Implementations
```go
// test_mocks.go - shared mocks across tests
type mockAuthProvider struct {
    authenticateFn func(*models.IdsecProfile) (*models.IdsecToken, error)
}

func (m *mockAuthProvider) Authenticate(p *models.IdsecProfile) (*models.IdsecToken, error) {
    if m.authenticateFn != nil {
        return m.authenticateFn(p)
    }
    return &models.IdsecToken{}, nil
}
```

#### Integration Tests
```go
//go:build integration

// integration_test.go - tests compiled binary
func TestMain(m *testing.M) {
    // Build binary before tests
    cmd := exec.Command("go", "build", "-o", "../grant-test", "../.")
    cmd.Run()
    code := m.Run()
    os.Remove("../grant-test")
    os.Exit(code)
}
```

### Error Handling

Commands use consistent error patterns:

```go
// Return errors, don't print
func runCommand(cmd *cobra.Command, args []string) error {
    if err := validate(args); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }

    result, err := doWork()
    if err != nil {
        return fmt.Errorf("operation failed: %w", err)
    }

    cmd.Println("Success:", result)
    return nil
}

// Cobra automatically prints errors from RunE
```

### Output Handling

Use `cmd.OutOrStdout()` for testability:

```go
func runCommand(cmd *cobra.Command, args []string) error {
    // Use cmd methods for output
    fmt.Fprintln(cmd.OutOrStdout(), "Output message")
    fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)

    // NOT: fmt.Println("message")
}
```

### Flag Patterns

```go
cmd.Flags().StringP("flag", "f", "default", "description")
cmd.Flags().StringVarP(&variable, "flag", "f", "default", "description")

// Mark flags as required
cmd.MarkFlagRequired("required-flag")

// Mutually exclusive flags (handled in RunE)
if cmd.Flags().Changed("flag1") && cmd.Flags().Changed("flag2") {
    return errors.New("--flag1 and --flag2 are mutually exclusive")
}
```

### Config Loading

```go
// Load config with GRANT_CONFIG override
cfg, err := config.Load()
if err != nil {
    // Default config if not found
    cfg = config.DefaultConfig()
}
```

### Service Initialization

```go
// Create ISP auth
ispAuth := auth.NewIdsecISPAuth(true) // cacheAuthentication=true

// Load profile and authenticate
profile, err := models.LoadProfile(cfg.Profile)
token, err := ispAuth.Authenticate(profile)

// Create SCA service
svc, err := sca.NewSCAAccessService(ispAuth)
```
