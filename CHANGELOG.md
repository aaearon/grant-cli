# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- `grant groups` command for Entra ID group membership elevation with interactive, direct (`--group`), and favorite (`--favorite`) modes
- `grant --favorite <name>` now detects group-type favorites and redirects users to `grant groups --favorite <name>`
- `grant revoke` command for session revocation with three modes: direct (by session ID), `--all`, and interactive (multi-select); works with both cloud and group sessions
- `--yes`/`-y` flag on `grant revoke` to skip confirmation for scripting
- `--provider`/`-p` flag on `grant revoke --all` and interactive mode to filter by cloud provider
- Session ID displayed in `grant status` output for easy reference with `grant revoke`

### Changed

- `grant status` now fetches sessions and eligibility data concurrently, reducing wall-clock time by ~2s
- `grant revoke` interactive mode now fetches workspace names concurrently across CSPs

### Fixed

- `grant revoke` now rejects `--provider` in direct mode (session IDs are already explicit)
- `grant status` session formatting reuses shared `ui.FormatSessionOption` instead of duplicated logic
- `buildWorkspaceNameMap` moved to shared `cmd/helpers.go` to eliminate cross-command dependency
- `grant groups --favorite` now verifies DirectoryID from the favorite, preventing wrong-group elevation when multiple directories have identically-named groups
- `grant groups` interactive selector sorts a local copy of groups, fixing wrong-group selection when display strings collide
- `grant status` now resolves directory names for group sessions via `buildDirectoryNameMap`
- `grant groups` subcommand no longer sets `SilenceErrors`/`SilenceUsage`, matching other subcommand patterns
- Removed dead code in `TestGroupsCommandFavoriteMode` and consolidated `NewGroupsCommandWithDeps`/`NewGroupsCommandWithDepsAndConfig` into a single test constructor
- `buildDirectoryNameMap` now handles nil eligibility response gracefully

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
