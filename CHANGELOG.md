# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- AWS elevation support (`--provider aws`)
- `grant env` command for AWS credential export: `eval $(grant env --provider aws)`
- Multi-CSP: omitting `--provider` fetches eligibility from all providers and shows combined results
- Provider label `(azure)` / `(aws)` in interactive selector when showing all providers
- `WorkspaceTypeAccount` workspace type for AWS accounts
- `AWSCredentials` model for parsing `accessCredentials` response

### Fixed

- Validate AWS credential fields are non-empty in `ParseAWSCredentials()` — prevents silent empty exports
- Provider validation in `fetchEligibility()` now uses `supportedCSPs` instead of hardcoded switch
- Log per-CSP eligibility errors in verbose mode when `--provider` is omitted

### Removed

- Unused `CSPGCP` constant (re-add when GCP is implemented)
- GCP references from `grant status` provider flag help and `parseProvider()`

### Performance

- Parallelize multi-CSP eligibility queries — all providers fetched concurrently when `--provider` is omitted

### Documentation

- Condense README: remove duplicate Quick Start and How It Works sections, slim command docs, trim obvious troubleshooting entries (~40% reduction)

### Changed

- Renamed `AzureEligibleTarget` to `EligibleTarget` (CSP-agnostic)
- Provider validation accepts `azure` and `aws` (was azure-only)
- Elevation output shows AWS export statements when credentials are present
- UI selector normalizes workspace type display (case-insensitive)
- `--provider` flag no longer defaults to Azure; omit to see all providers

### Refactored

- Accept `*IdsecProfile` directly in `NewRootCommandWithDeps` to eliminate filesystem access during tests
- Wrap original error in authentication check (`runElevateWithDeps`) instead of discarding it
- Extract `checkResponse` helper in SCA service to deduplicate HTTP error handling across 3 endpoints
- Add safety comments about package-level state and `t.Parallel()` restriction in `cmd/` tests

### Fixed

- CLAUDE.md documenting Go 1.24+ when `go.mod` requires Go 1.25+
- `favorites add` with partial flags (`--target` without `--role`) hitting auth before flag validation in CI

### Previously Refactored

- Remove dead `mfaMethod` parameter from configure command signatures
- Remove inconsistent nil check for `eligibilityLister` in root command
- Rename snake_case import aliases to Go-idiomatic single-word style (`sdkconfig`, `sdkmodels`, `authmodels`, `scamodels`, `commonmodels`)
- Add `io.LimitReader` (4 KB cap) to error response body reads in SCA service
- Pass `io.Writer` to `buildWorkspaceNameMap` for testable verbose warnings (replaces `os.Stderr`)
- Add context cancellation check in `buildWorkspaceNameMap` CSP loop
- Remove duplicate `(c *Config) GetFavorite()` method; use `config.GetFavorite(cfg, ...)` consistently
- Add defer cleanup for `passedArgValidation` global state in root tests
- Add `t.Parallel()` to pure tests in eligibility, session, selector, and favorites packages
- Consolidate `authenticator` and `profileSaver` interfaces into `cmd/interfaces.go`
- Add `config.LoadDefaultWithPath()` helper to reduce boilerplate config loading
- Extract `parseElevateFlags()` helper to eliminate duplicate flag reading in root command
- Remove duplicate `--target`/`--role` validation in favorites add (handled by `runFavoritesAddWithDeps`)
- Pass pre-loaded config into `runFavoritesAddWithDeps` to avoid double config load
- Move `executeWithHint` test helper from `root.go` to `test_helpers.go`
- Consolidate scattered `init()` functions into single `cmd/commands.go`
- Use `MarkFlagsMutuallyExclusive` for `--favorite` vs `--target`/`--role` flags
- Use `rootCmd.ErrOrStderr()` instead of `os.Stderr` in `Execute()` for testability
- Change `version` command from `Run` to `RunE` for consistency

### Added

- 30-second API request timeouts via `context.WithTimeout` on all SCA API calls
- Verbose warning when workspace name lookup fails in `grant status`
- Documentation comments for package-level state variables

### Removed

- `poc/` directory from version control (added to `.gitignore`)
