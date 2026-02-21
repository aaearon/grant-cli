# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- TTY detection with fail-fast: all interactive prompts now return a descriptive error instead of hanging when stdin is not a terminal (pipes, CI, LLM agents)
- `--output json` / `-o json` global flag for machine-readable output on all commands (`grant`, `env`, `status`, `revoke`, `favorites list`)
- `grant list` command to discover eligible cloud targets and Entra ID groups without triggering elevation; supports `--provider`, `--groups`, `--refresh`, and `--output json`

## [0.5.1] - 2026-02-21

### Fixed

- Elevation requests no longer fail with `context deadline exceeded` when the interactive target selector takes longer than 30 seconds

### Added

- golangci-lint configuration (`.golangci.yml`) with 19 linters enabled and Go best practices applied

## [0.5.0] - 2026-02-19

### Added

- Verbose logging (`--verbose`/`-v`) now produces output for all commands, not just those using `SCAAccessService`
- Commands `update`, `version`, `login`, `logout`, `configure`, and `favorites` now emit SDK-format verbose logs (`grant | timestamp | INFO | message`)

### Changed

- Migrated 4 ad-hoc `[verbose]`/`Warning:` messages in `fetchStatusData`, `buildDirectoryNameMap`, `buildWorkspaceNameMap`, and `fetchEligibility` to use the SDK logger for consistent format
- Removed `errWriter io.Writer` parameter from `fetchStatusData`, `buildDirectoryNameMap`, `buildWorkspaceNameMap`, and `fetchGroupsEligibility` (verbose output now goes through SDK logger, not injected writer)

## [0.4.0] - 2026-02-19

### Added

- `grant update` command for self-updating the binary via GitHub Releases using `rhysd/go-github-selfupdate`

## [0.3.0] - 2026-02-19

### Added

- Local file-based eligibility cache (`~/.grant/cache/`) with 4-hour default TTL — skips API roundtrip on subsequent runs
- `--refresh` flag on `grant` and `grant env` to bypass the eligibility cache and fetch fresh data
- `cache_ttl` config option in `~/.grant/config.yaml` to customize cache TTL (e.g., `cache_ttl: 2h`)
- `--groups` flag on root command to show only Entra ID groups in the interactive selector
- `--group` / `-g` flag on root command for direct group membership elevation (`grant --group "Cloud Admins"`)
- `grant --favorite <name>` now handles both cloud and group favorites directly
- `grant revoke` command for session revocation with three modes: direct (by session ID), `--all`, and interactive (multi-select); works with both cloud and group sessions
- `--yes`/`-y` flag on `grant revoke` to skip confirmation for scripting
- `--provider`/`-p` flag on `grant revoke --all` and interactive mode to filter by cloud provider
- Session ID displayed in `grant status` output for easy reference with `grant revoke`

### Changed

- `grant favorites add` interactive selector now shows both cloud roles and Entra ID groups in a unified list (previously cloud-only)
- Group membership elevation merged into root command — `grant` interactive selector shows both cloud roles and Entra ID groups in a unified list
- Eligibility caching now covers all commands (`grant status`, `grant revoke`, `grant favorites add`) — previously only `grant` and `grant env` used the cache
- `grant status` now fetches sessions and eligibility data concurrently, reducing wall-clock time by ~2s
- `grant revoke` interactive mode now fetches workspace names concurrently across CSPs

### Fixed

- `grant revoke` now rejects `--provider` in direct mode (session IDs are already explicit)
- `grant status` session formatting reuses shared `ui.FormatSessionOption` instead of duplicated logic
- `buildWorkspaceNameMap` moved to shared `cmd/helpers.go` to eliminate cross-command dependency
- Group favorites now verify DirectoryID, preventing wrong-group elevation when multiple directories have identically-named groups
- `grant status` now resolves directory names for group sessions via `buildDirectoryNameMap`
- `buildDirectoryNameMap` now handles nil eligibility response gracefully
- `grant favorites add` now resolves directory names for groups, matching root command display (`Directory: X / Group: Y`)

### Removed

- `grant groups` subcommand — functionality absorbed into the root command with `--groups` and `--group` flags

## [0.2.1] - 2026-02-18

### Fixed

- Interactive selector UI (arrows, highlighting) was written to stdout, breaking `eval $(grant env ...)` — now redirected to stderr

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
