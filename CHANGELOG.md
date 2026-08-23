# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixed

- `grant request list --state`, `--result` and `--priority` now work; every filtered invocation previously failed with HTTP 400

## [0.10.0] - 2026-08-17

### Changed

- An invalid `cache_ttl` (unparseable, zero or negative) now fails the command instead of silently defaulting; the error names the config file, the expected duration syntax and `--refresh`

### Fixed

- `grant configure` no longer discards your saved favorites, `default_provider` and `cache_ttl` when re-run
- `grant favorites add` now fails immediately without a terminal instead of authenticating first
- `grant favorites add`'s non-interactive error now mentions the required favorite name, not only the flags
- Interactive selectors now elevate the row you picked, not another target or Entra ID group that happens to render the same way

### Security

- `grant update` now refuses to install a zero-length binary from a release archive
- `grant update` now rejects non-regular zip entries, matching the existing tar behaviour

## [0.9.0] - 2026-08-14

### Added

- End-to-end self-update tests that replace a real, running binary, covering both the success and rollback paths (build tag `selfupdate_e2e`)
- CI runs the self-update end-to-end tests on both `ubuntu-latest` and `windows-latest`
- `grant revoke --output json` gains a per-session `outcome` field

### Fixed

- `grant login` no longer hangs on WSL2; grant now detects WSL and forces the file-based keyring. A token stored in the OS keyring becomes invisible — re-run `grant login` if prompted
- `grant revoke` now exits 1 when any requested session was not accepted for revocation, instead of reporting success — check scripts relying on exit 0

## [0.8.0] - 2026-08-14

### Added

- GCP support for `grant`, `grant list`, `grant status` and `grant revoke`: `--provider gcp`, GCP included in the multi-provider fan-out, and the `PROJECT`/`FOLDER`/`GCP_ORGANIZATION` workspace types rendered in the interactive selector. `grant env` stays AWS-only (the SCA API spec defines no GCP credential shape) and `grant request submit` explicitly rejects GCP. Not yet verified against a live GCP tenant

### Changed

- Rebranded user-facing references from CyberArk to Idira (formerly CyberArk) in the README and CLI help/prompt text, following the Palo Alto Networks rebrand. No functional or API changes; SDK import paths (`github.com/cyberark/idsec-sdk-golang`), `*.cyberark.cloud` URLs, and environment variables are unchanged.
- Enabled the `gofmt` linter in `.golangci.yml` and reformatted the existing tree to match
- CI now runs the build and race-enabled test suite on both `ubuntu-latest` and `windows-latest` (`fail-fast: false`). The Windows leg invokes `go build` / `go test` directly because GitHub's Windows runners have no GNU make; lint still runs on Linux only.
- Upgraded dependencies:
  - `github.com/cyberark/idsec-sdk-golang` v0.2.3 → v0.8.1
  - `github.com/spf13/cobra` v1.9.1 → v1.10.2
  - `github.com/spf13/pflag` v1.0.6 → v1.0.10 (indirect)
  - `github.com/mattn/go-isatty` v0.0.20 → v0.0.24
  - `golang.org/x/crypto` v0.45.0 → v0.55.0 (indirect)
  - `golang.org/x/net` v0.47.0 → v0.58.0 (indirect)
  - `github.com/dvsekhvalnov/jose2go` v1.5.0 → v1.7.0 (indirect)
  - `github.com/golang-jwt/jwt/v5` v5.2.2 → v5.3.1 (indirect)
  - `golang.org/x/sys` v0.38.0 → v0.47.0 (indirect)
  - `golang.org/x/term` v0.37.0 → v0.45.0 (indirect)
  - `golang.org/x/text` v0.31.0 → v0.41.0 (indirect)
- SDK v0.8.1 enables automatic retries on HTTP 429 and transient transport errors by default. `grant` disables these on its SCA and UAR service clients (see the retry-policy change) because `Elevate` and `SubmitRequest` are non-idempotent POSTs with no idempotency header.
- SDK v0.8.1 changes 401 / re-authentication handling: the rejected response is drained, a token refresh is forced, a concurrently-refreshed token is adopted rather than duplicated, and cookie-decode errors that were previously silently ignored are now propagated.
- Disabled the SDK v0.8.1 automatic transient-retry on both the SCA and Access Requests (UAR) HTTP clients (`internal/sdkclient.DisableTransientRetry`). The SDK retries HTTP 429 with no method filter and bare `EOF` transport errors for any method including POST, which could replay non-idempotent requests (duplicate elevation or a duplicate access request in an approver's queue). Read paths lose automatic rate-limit retry; a 429 now surfaces as an error
- `grant update` no longer depends on the abandoned `github.com/rhysd/go-github-selfupdate` (last commit Jan 2021). Release discovery, version comparison, asset selection, checksum verification and archive extraction are now implemented in-house in `internal/selfupdate/`; the binary swap (staged sibling file, the two-rename dance including the Windows path, and rollback) is delegated to `github.com/minio/selfupdate` v0.6.0, with grant adding an `fsync` of the staged file before the swap
- **Replacement guarantees, stated precisely.** Each rename is individually atomic, so the installed binary is never a partially written file. The *pair* of renames is not atomic: if the process is killed between them, or if the second rename and the rollback both fail, the binary path is left absent with `.grant.old` and `.grant.new` beside it. grant now detects that state and prints the exact `mv` command that restores the previous binary
- Dependency graph, after the selfupdate replacement and the SDK upgrade together. Build graph (`go list -deps`, the modules actually compiled in): 39 → 33. `go.mod` require directives: 47 → 39 (indirect 40 → 33). Full module graph (`go list -m all`): 110 → 109 — the selfupdate replacement removed 15 and SDK v0.8.1 adds 14 back, but none of the SDK's additions are in the linked graph. The only genuinely new module paths in the build graph are `github.com/minio/selfupdate` and `aead.dev/minisign`. Removed `blang/semver`, `rhysd/go-github-selfupdate`, `google/go-github/v30`, `google/go-querystring`, `golang.org/x/oauth2` (a Nov 2018 pseudo-version), `golang/protobuf`, `google.golang.org/appengine`, `tcnksm/go-gitconfig`, `inconshreveable/go-update` and `ulikunitz/xz`

### Fixed

- `grant env` no longer performs an elevation before validating the provider. Previously `grant env --provider azure` created a real SCA session and recorded a session timestamp before failing with "no credentials returned", leaving an unwanted active session behind. The provider is now validated before the elevation request is issued
- `grant configure` no longer reports a stale SDK profile location. The help text and the "Profile saved to" success message printed `~/.idsec_profiles/grant`, which has been wrong since the SDK upgrade in v0.7.0. The path is now resolved with the SDK's own `profiles.GetProfilesFolder()`, so it always matches the directory the profile loader reads (`~/.idsec/profiles/grant` by default, or `IDSEC_PROFILES_FOLDER` when set).
- Made the test suite pass on Windows: skipped Unix-only assertions in `internal/config` (POSIX permission bits, `HOME`) and `internal/cache` (`0600` cache-file mode, which Go reports as `0666` on Windows), and reworked `cmd`'s `config save error` case to block the write with a path under an existing regular file instead of a hardcoded `/dev/null` path.
- Made `internal/selfupdate` pass on Windows: the `unwritable target directory` case is skipped (a `0500` chmod does not deny directory writes there), and the recovery-hint assertion now compares against the `%q`-quoted path, which escapes the backslashes in a Windows path.
- Fixed a data race in the `internal/ui` parallel tests, which mutated shared package state while running under `t.Parallel()`.

### Security

- `grant update` now verifies the downloaded archive's SHA-256 against the release's `checksums.txt` before replacing the binary. Previously no validation was performed at all (`selfupdate.DefaultUpdater()` ships a nil `Validator`). Note the trust model: `checksums.txt` is fetched from the same origin as the archive, so this protects against corrupted or tampered downloads in transit, not against a compromised GitHub account or release pipeline
- Archive extraction now rejects oversized entries instead of silently truncating them at the 128 MiB cap, rejects drive-absolute (`C:\...`) and UNC archive paths alongside `..` traversal, and only accepts the binary at the archive root (never a nested entry, never two candidates)
- Clears two dependency advisories. Replacing `rhysd/go-github-selfupdate` with `minio/selfupdate` removes `golang.org/x/crypto/openpgp` from the build graph, clearing GO-2026-5932 (unmaintained package, no fix available); dropping `ulikunitz/xz` with the same dependency tail clears GO-2025-3922. No third-party module in the build graph has a called vulnerability
- The `govulncheck` findings that remained at release time were Go standard library issues, not dependency issues, and the count is a property of the scanning toolchain rather than of this tree. Scanned with go1.25.0 the release tree reports called stdlib vulnerabilities (34 at the time this section was first written, 29 on a re-scan on 2026-08-14 as the advisory database grew); scanned with go1.25.13 it reports **0 called vulnerabilities**. CI and the release pipeline pin a floating `go-version: "1.25"`, so published binaries are built against the current patched standard library. The only residuals under go1.25.13 are not called: GO-2026-5942 (`net` SVCB/HTTPS RR parsing panic, fixed in `net@go1.26.6`, with no Go 1.25 patch available) and GO-2026-5932, which lingers as a module-graph entry outside the build graph

## [0.7.0] - 2026-04-21

### Changed

- **Profile location moved.** As a side effect of the SDK upgrade, the SDK profile directory changed from `~/.idsec_profiles/` to `~/.idsec/profiles/` (override with `IDSEC_PROFILES_FOLDER`). Users upgrading from v0.6.x or earlier must either re-run `grant configure` (recommended) or move the old file into place. If a profile already exists at the new location it is the current one and must win, so use the no-clobber form (`-n` is supported by both GNU and BSD/macOS `mv`): `mkdir -p ~/.idsec/profiles && mv -n ~/.idsec_profiles/grant ~/.idsec/profiles/grant`.
- Upgraded `github.com/cyberark/idsec-sdk-golang` from v0.1.14 to v0.2.3. `isp.FromISPAuth` now takes a retry-strategy argument; we pass `nil` to preserve v0.1.14 behavior (which itself defaulted to nil internally). No new direct Go module dependencies; indirect dep set is smaller
- `--output json` is now a pure serialisation flag; it no longer forces non-interactive mode. Interactive pickers and prompts (e.g. `grant request get -o json` with no ID, `grant request submit -o json` without `--target`/`--role`) work in a TTY, writing prompts to stderr and JSON to stdout.

### Fixed

- `grant request submit` no longer performs 2–3 back-to-back ISP authentication cycles. Profile load + `Authenticate` is now memoized per-invocation and shared by `bootstrapSCAService` / `bootstrapWorkflowsService`. `Authenticate` is also called with `refreshAuth=false` so cached, unexpired keyring tokens short-circuit the network round-trip. Keyring ops drop from ~18× to ~6× per invocation.

### Added

- `grant request` command group for managing access requests through the approval workflow
  - `grant request submit` — submit a new access request with target selection from eligibility, reason, priority, date/time scheduling
  - `grant request list` — list access requests with filtering (state, result, priority, role), sorting, and free-text search
  - `grant request get <id>` — view full details of a specific access request
  - `grant request cancel <id>` — cancel an open request with optional reason
  - `grant request approve <id>` — approve a pending request with optional reason
  - `grant request reject <id>` — reject a pending request with optional reason
- All `grant request` subcommands support `--output json` for machine-readable output
- New `internal/workflows/` package implementing the CyberArk Access Requests API client (`/api/workflows/requests`)
- Interactive role selector for `grant request submit`: after workspace selection, fuzzy-filterable list of requestable roles is fetched from the SCA on-demand role discovery endpoints (`/api/cloud/resources/ondemand`, `/api/cloud/cloud-roles/ondemand`)
  - Supported workspace types: `DIRECTORY` (azure_ad), `ACCOUNT` (aws), `MANAGEMENT_GROUP` (azure_resource)
  - Interactive role selection now also supports `SUBSCRIPTION`, `RESOURCE_GROUP`, and `RESOURCE` workspaces (uses naive 2-level ancestors; custom roles scoped to intermediate management groups may not appear — use `--role-id` for those)
  - Roles cached in `~/.grant/cache/ondemand_roles_<platform>_<sha256(workspaceID)>.json` (4h TTL)
- `grant request submit --refresh` bypasses the on-demand role and eligibility caches (mirrors `grant --refresh`)
- Interactive request picker for `grant request cancel`, `approve`, `reject`, and `get` — omit the `<requestId>` positional argument in a terminal to pick from a scoped, fuzzy-filterable list (cancel: open requests you created; approve/reject: pending requests assigned to you; get: any request). Non-TTY invocation still requires the positional argument.

## [0.6.1] - 2026-04-08

### Fixed

- AWS elevation no longer shows the Azure CLI session message — post-elevation guidance is now CSP-aware (#37, thanks @svnlto)
- SCA list endpoints (`eligibility`, `sessions`, `groups eligibility`) now paginate correctly via `nextToken`, preventing truncated results on large tenants (#38, thanks @svnlto)

## [0.6.0] - 2026-02-21

### Added

- TTY detection with fail-fast: all interactive prompts now return a descriptive error instead of hanging when stdin is not a terminal (pipes, CI, LLM agents)
- `--output json` / `-o json` global flag for machine-readable output on all commands (`grant`, `env`, `status`, `revoke`, `favorites list`)
- `grant list` command to discover eligible cloud targets and Entra ID groups without triggering elevation; supports `--provider`, `--groups`, `--refresh`, and `--output json`
- `grant status` now shows remaining session time instead of total duration for sessions elevated via `grant` or `grant env`; sessions elevated outside the CLI continue to show total duration
- `grant status` now resolves group names from the groups eligibility API — group sessions display `Group: CloudAdmins in Contoso` instead of `Group: d554b344-uuid in 29cb7961-uuid`
- JSON output for `grant status` includes new additive fields: `remainingSeconds` (omitted when unknown) and `groupName` (omitted when unresolved)
- Session elevation timestamps tracked locally in `~/.grant/cache/session_timestamps.json` with automatic cleanup of stale entries

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
