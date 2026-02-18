# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- Demo GIFs in README showing interactive elevation and `grant env` workflow

## [0.2.0] - 2026-02-18

### Added

- AWS elevation support (`--provider aws`)
- `grant env` command for AWS credential export: `eval $(grant env --provider aws)`
- Multi-CSP support: omitting `--provider` fetches eligibility from all providers and shows combined results
- Provider label `(azure)` / `(aws)` in interactive selector when showing all providers
- Non-interactive `favorites add` with `--target` and `--role` flags for scripting
- Optional name argument for `favorites add` — name can be prompted after interactive target selection
- 30-second API request timeouts on all SCA API calls
- Workspace name resolution in `grant status` via eligibility API cross-reference
- Simplified bug report issue template

### Changed

- `--provider` flag no longer defaults to Azure; omit to see all providers
- Identity URL is now optional in `grant configure` — the SDK auto-discovers it from the username
- `favorites remove` with no arguments now shows a helpful error with usage hint
- Verbose hint suppressed for argument validation errors where it adds no value
- Improved help text with examples and cross-references for all favorites subcommands

### Fixed

- `config.Load()` now propagates non-ErrNotExist errors (e.g., permission denied) instead of silently returning defaults
- `favorites add` with partial flags (`--target` without `--role`) no longer requires authentication before reporting the validation error
- Case-insensitive target matching for `--target` and `--role` flags
- Double error output from Cobra eliminated (`SilenceErrors`, `SilenceUsage`)
- `io.ReadAll` errors in SCA service error-response paths now produce fallback messages instead of empty strings
- Error messages lowercased per Go conventions

### Performance

- Multi-CSP eligibility queries run concurrently when `--provider` is omitted

### Removed

- Unused `--duration` flag (was parsed but never sent to API)
- `CSPGCP` constant (re-add when GCP is implemented)
