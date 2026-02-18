# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Refactored

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
