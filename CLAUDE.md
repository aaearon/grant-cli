# sca-cli

## Project
- **Language:** Go 1.24+
- **Module:** `github.com/aaearon/sca-cli`
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

## Config
- App config: `~/.sca-cli/config.yaml`
- SDK profile: `~/.idsec_profiles/sca-cli.json`

## Build
```bash
make build    # Build binary
make test     # Run tests
make lint     # Run linter
```

## Git
- Feature branches, conventional commits
- Branch naming: `feat/`, `fix/`, `docs/`
