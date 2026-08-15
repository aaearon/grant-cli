# grant

## Project
- **Language:** Go 1.25+
- **Module:** `github.com/aaearon/grant-cli`
- **Dependencies:** `github.com/cyberark/idsec-sdk-golang` is the primary dependency; zero-new-Go-module-deps is a goal, not an absolute rule. Documented exception: `github.com/minio/selfupdate` (+ its one transitive `aead.dev/minisign`) for `grant update`, adopted to remove the abandoned `rhysd/go-github-selfupdate` and advisory GO-2026-5932. It was a net *reduction* in every dependency measure — the exception cost nothing. Measure with `go list -deps` / `go list -m all` if a current figure is needed; do not record one here

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
- The service slug (`"sca"` / `"uar"`) is what `isp.FromISPAuth` resolves into the live host, and the retry/header tests overwrite `client.BaseURL` before issuing a request — so it is pinned separately, by asserting the constructed `BaseURL` against the fake-JWT tenant (`TestNewSCAAccessService_UsesSCAServiceSlug`, `TestNewAccessRequestService_UsesUARServiceSlug`) **before** any swap. Assert it before mutating `BaseURL`, never after
- Wire contracts are asserted on what is *sent*: the `mockHTTPClient` in both packages records `gotRoute`/`gotBody`/`gotParams` before dispatching. Assert the exact route and the full body contents — "non-nil body" lets a nil payload through, and a canned response tells you nothing about the request

## SCA Access API
- **Base URL:** `https://{subdomain}.sca.{platform_domain}/api`
- **Endpoints:**
  - `GET /api/access/{CSP}/eligibility` — list eligible targets (`AZURE`, `AWS`, `GCP`)
  - `POST /api/access/elevate` — request JIT elevation (AWS responses include `accessCredentials` JSON string)
  - `GET /api/access/sessions` — list active sessions
  - `POST /api/access/sessions/revoke` — revoke sessions by ID (request: `sessionIds[]`, response: `SessionRevocationInfo[]`)
    - `sessionIds` is capped at `maxItems: 100` per request, so `cmd/revoke_batch.go` chunks the requested set into sequential ≤100-ID calls and aggregates; a mid-sequence batch error keeps the outcomes already collected
    - `revocationStatus`: the spec enum is only `SUCCESSFULLY_REVOKED` and `REVOCATION_IN_PROGRESS`. The live API also returns the **undocumented** `REVOCATION_NOT_APPLICABLE` (in neither the spec nor the SDK), so the status set is open and `ClassifyRevocationStatus` (`internal/sca/models/revoke.go`) **fails closed** — anything unrecognized, including `""`, is `OutcomeUnknown` and counts as a failure. Match is exact; case variants are unknown
    - Outcomes are reconciled against the **requested** session IDs, never the returned rows (`cmd/revoke_reconcile.go`): a requested session with no row is `unknown`, duplicate rows resolve worst-outcome-wins, and rows for unrequested or empty IDs satisfy nothing
    - **Exit policy (deliberate, not blanket "fail closed"):** exit 0 when every requested session was accepted, which *includes* `in_progress` — a documented async success state, so failing on it would make legitimate revocations look broken. Exit 1 on `not_applicable`, unrecognized statuses and missing rows. So exit 0 does not prove access is gone; only that nothing was refused or unaccounted for. State it that precisely in docs — `ClassifyRevocationStatus` fails closed, the *command* does not fail on in-progress
    - `outcome` (`revoked`/`in_progress`/`not_applicable`/`unknown`) is the single classification field in the JSON. Do not add derived booleans (`accepted`, `complete`, `revoked`) beside it: two representations of one concept drift apart and disagree. Callers switch on `outcome`
    - Never attribute a cause for `REVOCATION_NOT_APPLICABLE` (e.g. an AWS/STS story). Observing the status does not prove the reason, and grant supports Azure/AWS/GCP plus group sessions. Render provider-neutral text and keep the raw token
  - `GET /api/access/{CSP}/eligibility/groups` — list eligible Entra ID groups (response: `groupId`/`groupName`/`directoryId`)
  - `POST /api/access/elevate/groups` — request group membership elevation (response wrapped in `response` key, same as cloud elevation)
- **Headers:** `Authorization: Bearer {jwt}`, `X-API-Version: 2.0`, `Content-Type: application/json`

## Access Requests API (Workflows)
- **Base URL:** `https://{subdomain}.uar.{platform_domain}/api`
- **Package:** `internal/workflows/` — `AccessRequestService` (mirrors SCA service pattern with ISP client for "uar" service)
- **Models:** `internal/workflows/models/` — `AccessRequest`, `RequestState`, `RequestResult`, `SubmitAccessRequest`, `CancelAccessRequest`, `FinalizeAccessRequest`, `RequestFormResponse`
- **Endpoints:**
  - `GET /api/workflows/request-forms` — get form structure for target category + request type
  - `GET /api/workflows/requests` — list access requests (offset/limit pagination, filter/sort/freeText)
  - `GET /api/workflows/requests/{requestId}` — get single request details
  - `POST /api/workflows/requests` — submit new access request
  - `POST /api/workflows/requests/{requestId}/cancel` — cancel an open request
  - `POST /api/workflows/requests/{requestId}/finalize` — approve or reject a request
- **Pagination:** offset/limit (not nextToken); `ListRequests` fetches all pages automatically
- **DI interfaces:** `accessRequestService` in `cmd/interfaces.go`
- **Target category:** `CLOUD_CONSOLE` (hardcoded for v1)
- **Headers:** `Authorization: Bearer {jwt}`, `Content-Type: application/json`

## SDK Retry Behavior
- idsec-sdk-golang v0.8.1 added automatic transient retry, enabled by default: 3 retries **on top of** the initial attempt (up to 4 requests), 500ms base wait, 10s cap (`pkg/common/idsec_client.go:53-60`, `:375-377`). Backoff jitter can exceed the cap by up to ~50% (`:1331-1349`)
- Two retry paths, neither safe for non-idempotent POSTs:
  - **429** (`:865-885`) — no HTTP method filter at all; honors `Retry-After` (clamped to max wait), else exponential backoff
  - **Transport errors** (`:835-849` via `isRetryableTransportError` `:1244-1283`) — bare `io.EOF`/`io.ErrUnexpectedEOF`/`"eof"`/`"server closed idle connection"` are retried for **any** method including POST (`:1252-1266`); only connection-reset/broken-pipe/GOAWAY are gated behind `isIdempotentMethod` (`:1269-1281`). An EOF can surface after the server already processed the request, so this path can replay a mutation
- **grant disables transient retry on BOTH the SCA and UAR/workflows clients** via `internal/sdkclient.DisableTransientRetry` (calls `SetTransientRetry(0, 0, 0)`, `:1187-1197`), invoked right after `isp.FromISPAuth` in `internal/sca/service.go` and `internal/workflows/service.go`
- Why client-wide rather than per-mutation: the SDK has no per-request opt-out, and toggling client state around individual calls is race-prone (grant fans out concurrently across CSPs). SCA `elevate` / `elevate/groups` are as non-idempotent as UAR `submit`
- `isp.IdsecISPServiceClient` embeds `*common.IdsecClient`, so the helper takes `client.IdsecClient`
- POSTs protected, by actual replay risk:
  - **Mutating** — `internal/sca/service.go` elevate, group elevate (a duplicate creates a second session); `internal/workflows/service.go` submit (a duplicate is visible in an approver's queue), cancel, finalize
  - **Effectively idempotent / read-shaped, covered incidentally** — `internal/sca/service.go` sessions/revoke (re-revoking is a no-op) and on-demand roles (`POST` used only for role discovery)
- Tests: `internal/sdkclient/retry_test.go` covers the helper; `internal/sca/retry_policy_test.go` and `internal/workflows/retry_policy_test.go` drive the **real constructors** with a fake-JWT ISP token, then repoint `client.BaseURL` at an `httptest` 429 server and assert exactly one inbound request. Removing a `DisableTransientRetry` call makes them fail with 4

## Testing
- TDD: write `_test.go` before `.go` for every package
- Table-driven tests
- `httptest.NewServer` for service mocks
- `httpClient` interface for DI
- Test files co-located as `_test.go`
- **Mock capture convention** (`cmd/test_mocks.go`, precedent `mockSessionRevoker`): record the arguments in the method body *before* dispatching to any `xxxFunc` callback, keep a history slice plus a `lastX()` accessor (a history is what answers "called exactly once?"), defensively copy slices/maps and pointer-to-struct args, and guard against a nil request. An optional `*string` argument is flattened to `reason string` + `reasonSet bool` so a test can tell `nil` from `""`. There is exactly one mock per interface — an arg-blind sibling silently opts every future test out of capture
- No mutex on those histories: only the eligibility listers fan out across goroutines (`cmd/helpers.go:44,59,71`, `cmd/root.go:316,326,734,739`); `Elevate`, `ElevateGroups` and all five `accessRequestService` methods are called from strictly sequential paths. `make test-race` is what keeps that honest
- Shared test helpers live in `cmd/test_helpers_test.go` (`executeCommand`, `executeCommandStreams`, `executeWithHint`, `withInteractiveTTY`). It is a `_test.go` file on purpose. It used to be a production file; that never linked `testing` into the binary (the old file imported only `bytes` and `cobra`), so the move was **preventive, not remedial** — adding `withInteractiveTTY` would have been the first helper to pull `testing` in
- Any test whose behavior depends on interactivity MUST set it explicitly with `withInteractiveTTY`: `go test` happens to run with a non-TTY stdin, but that is an accident of the harness, not an assertion
- Tests that swap a package-level var (e.g. `ui.IsTerminalFunc`, `recordSessionTimestamp`, `bootstrapImpl`) MUST NOT call `t.Parallel()` — `-race` flags concurrent access to the global. Mark them with a `// Not parallel: mutates the package-global X.` comment. This is why the `cmd` package tests are all serial.

## CLI
- `spf13/cobra` for CLI framework
- `Iilun/survey/v2` for interactive prompts
- `grant env` — **AWS only**; performs elevation, outputs only `export` statements (no human text); usage: `eval $(grant env --provider aws)`; supports `--refresh`. Non-AWS targets are rejected by `requireAWSTarget` (passed as the `preElevate` hook to `resolveAndElevate`) *before* any elevation is issued, so no session is created. It fails closed — an unresolved CSP is rejected too; the `AccessCredentials == nil` check remains as a fallback
- `grant list` — list eligible targets and groups without triggering elevation; supports `--provider`, `--groups`, `--refresh`, `--output json`; used by LLMs to discover available targets programmatically
- `grant revoke` — revoke sessions: direct (`grant revoke <id>`), `--all`, or interactive multi-select; `--yes` skips confirmation
- `grant request` — manage access requests through approval workflow; subcommands: `submit`, `list`, `get`, `cancel`, `approve`, `reject`
- `grant request submit` — submit on-demand access request; workspace selector uses SCA eligibility (deduplicated to unique workspaces); after workspace selection, interactive role selector fetches roles via SCA on-demand endpoints (GET `/api/cloud/resources/ondemand` for `azure_ad`/`aws`, POST `/api/cloud/cloud-roles/ondemand` for `azure_resource`); shows summary + confirmation before submitting; flags: `--target`, `--role-id`, `--role`, `--provider`, `--reason`, `--priority`, `--date`, `--timezone`, `--from`, `--to`, `--yes`, `--refresh`
  - Interactive role selection supports `DIRECTORY`, `ACCOUNT` (AWS), `MANAGEMENT_GROUP`, `SUBSCRIPTION`, `RESOURCE_GROUP`, and `RESOURCE` workspaces (azure_resource scopes use naive 2-level ancestors; custom roles scoped to intermediate management groups may be missing — fall back to `--role-id`)
  - On-demand role cache: `~/.grant/cache/ondemand_roles_<platform>_<sha256(workspaceID)>.json` (4h TTL); `--refresh` on `grant request submit` bypasses the cache
- `grant request list` — list access requests; flags: `--state`, `--result`, `--priority`, `--role` (CREATOR/APPROVER), `--search`, `--sort`, `--desc`
- `grant request get [id]` — get full request details; omitting `<id>` in a TTY opens a fuzzy-filterable picker of all your requests
- `grant request cancel [id]` — cancel an open request; optional `--reason`. Omitting `<id>` in a TTY opens a picker scoped to STARTING/RUNNING/PENDING requests you created (role=CREATOR)
- `grant request approve [id]` / `grant request reject [id]` — finalize a request; optional `--reason`. Omitting `<id>` in a TTY opens a picker scoped to PENDING requests assigned to you (role=APPROVER)
- Request picker: `internal/ui/request_selector.go` mirrors the role-selector Format/Build/Select quartet; `resolveRequestIDFn` in `cmd/request_picker.go` is injectable for tests. Non-TTY invocation without `<id>` returns `ErrNotInteractive` with a hint to run `grant request list`
- `grant update` — self-update binary via GitHub Releases; guards against dev builds. Implemented in `internal/selfupdate/`:
  - Discovery: `GET https://api.github.com/repos/aaearon/grant-cli/releases/latest` (`apiBaseURL` field injectable for tests)
  - Version compare: in-house SemVer 2.0.0 parser (`ParseVersion`/`CompareVersions`). Handles pre-release and build metadata (GoReleaser can emit both) with SemVer precedence: build metadata ignored for ordering, pre-release sorts before its release. A leading `v`/`V` is tolerated; leading zeroes are rejected
  - Asset selection: `grant-cli_<version>_<goos>_<goarch>.tar.gz` (`.zip` on windows) — must stay in sync with `.goreleaser.yaml`
  - Integrity: SHA-256 of the archive checked against the release's `checksums.txt` (GNU `*filename` binary marker tolerated). **Trust model:** `checksums.txt` comes from the same origin as the archive, so it defends against corrupted/tampered downloads in transit, **not** against a compromised GitHub account or release pipeline. Signature verification would be needed for that. Note the checksum covers the *archive*, not the extracted binary — hence the independent size checks below
  - Extraction: `archive/tar`+`compress/gzip` / `archive/zip`. Rejects absolute, drive-absolute (`C:\`), UNC and `..` paths (gosec G305); accepts only a single `grant`/`grant.exe` at the archive root (nested entries and duplicate candidates are errors). Size cap is 128 MiB (`maxDownloadBytes`), enforced by `readCapped`, which probes one byte past the cap — a bare `io.LimitReader` reports a *successful* short read and would silently install a truncated binary (gosec G110). `maxDownloadBytes` is a var only so tests can shrink it — mutate it exclusively through the `withMaxDownloadBytes(t, n)` helper (restores via `t.Cleanup`), and never call `t.Parallel()` in a test that does
  - **Zero-length binaries are refused twice**, in `extractBinary` and again at `applyBinaryTo`: the checksum covers the *archive*, not the extracted bytes, so an empty payload verifies against itself and would replace a working binary with nothing. Backstops, not the fix — they do not catch a non-regular entry carrying non-empty bytes (`tar.TypeCont` and vendor types `'A'..'Z'` are not header-only), which is why the type guards below must never be removed in favour of them
  - **Path-guard order in `checkArchivePath` is load-bearing**: the UNC (`//`) arm must precede `path.IsAbs`, because `path.Clean` collapses `//host/share/x` to `/host/share/x` and the absolute arm would otherwise make the UNC arm dead code
  - **Non-regular entries are rejected symmetrically and deliberately so**: tar filters on `hdr.Typeflag != tar.TypeReg`, zip on `f.Mode()&fs.ModeType != 0`. `IsDir()` alone accepted a `fs.ModeSymlink` entry named `grant.exe`, extracting the link-target string as the binary. The two formats must reject the same shapes
  - The tar/zip declared-size asymmetry is **intentional**: tar checks every entry because reaching the next header inflates the current one, while `zip.NewReader` reads only the central directory and never opens a skipped entry. Neither cap is an *aggregate* one — nothing bounds total inflated bytes or entry count, so a tar bomb can burn CPU inside `extractBinary` — but `verifyChecksum` runs first, so reaching it requires control of `checksums.txt`, which the trust model above already excludes
  - `internal/selfupdate/fuzz_test.go` carries fuzz targets for `checkArchivePath` and both extractors; run them by hand (never in CI) and commit any `testdata/fuzz/` entry a real failure produces, as a permanent regression seed
  - Apply: `github.com/minio/selfupdate` v0.6.0 owns the staged-file write, the two-rename swap including the Windows path, and rollback — do not hand-roll this. grant adds the `fsync` of the staged file (minio does not sync) plus a best-effort directory sync. Seams: `applyWithOptions`, `prepareFn`, `commitFn`, `syncStagedFileFn` in `internal/selfupdate/apply.go`; `syncStagedFileFn` is a test seam only, and the real `fsync` failure is exercised on Unix alone via a FIFO staged path (`//go:build !windows` — no portable Windows equivalent exists)
  - **Atomicity, precisely:** each rename is atomic, so the installed binary is never partially written. The *pair* is not: a kill between the two renames, or a failed second rename whose rollback also fails, leaves the binary path absent with `.grant.old`/`.grant.new` beside it. `InterruptedUpdate()` detects that state and `recoveryHint()` prints the `mv` command that fixes it. Do not describe this as fully atomic
  - `selfUpdater` in `cmd/interfaces.go` is defined over grant-owned types: `UpdateSelf(ctx, current string) (newVersion string, updated bool, err error)`
  - **End-to-end apply test:** `internal/selfupdate/e2e_test.go`, build tag `selfupdate_e2e`, run with `go test -tags=selfupdate_e2e ./internal/selfupdate/`. Everything else in `apply_test.go` swaps inert byte blobs; this compiles two real fixture binaries (a dependency-free module built with `-ldflags -X main.version=...`, so no network), executes one, and replaces it through `applyBinaryTo`/`applyWithOptions` **while a process is still running from that image**. That running child is what makes the Windows path real — a running `.exe` cannot be deleted, only renamed. `heldProcess.alive()` asserts the child survived the swap so the held cases cannot silently degrade into the idle cases. Covers success, rollback after a failed second rename (the restored file must still *execute*), and debris
  - **Windows leaves `.grant.old` behind, by design:** `minio.CommitBinary` cannot `os.Remove` the backup while a process still runs from that image, so it calls `SetFileAttributesW(FILE_ATTRIBUTE_HIDDEN)` and leaves it. It does not accumulate — the next `CommitBinary` removes the old path before renaming. The e2e test asserts exactly that rather than demanding a debris-free directory on Windows. The staged `.grant.new` must never survive on either platform
- `--groups` flag on root command shows only Entra ID groups in the interactive selector
- `--group` / `-g` flag on root command for direct group membership elevation (`grant --group "Cloud Admins"`)
- Root command unified selector shows both cloud roles and Entra ID groups; groups use `/eligibility/groups` and `/elevate/groups` API endpoints
- Multi-CSP: omitting `--provider` fetches eligibility from all supported CSPs (`supportedCSPs` in `cmd/root.go` — Azure, AWS, GCP) and merges results; a CSP that errors is skipped
- GCP: `list`/elevate/`status`/`revoke` only. Workspace types `PROJECT`/`FOLDER`/`GCP_ORGANIZATION`; no `accessCredentials` in the API spec, so `grant env` stays AWS-only and `grant request submit` rejects GCP (`rejectGCPWorkspace`, applied after target resolution so `--role-id` cannot skip it). **Untested against a live GCP tenant**
- `--refresh` bypasses eligibility cache on `grant` and `grant env`
- `fetchEligibility()` and `resolveTargetCSP()` in `cmd/root.go` — shared by root, env, and favorites

## TTY Detection
- `internal/ui/tty.go` — `IsTerminalFunc` (overridable), `IsInteractive()`, `ErrNotInteractive`
- All interactive prompts (`SelectTarget`, `SelectSessions`, `ConfirmRevocation`, `SelectGroup`, `uiUnifiedSelector.SelectItem`, `surveyNamePrompter.PromptName`) fail fast with `ErrNotInteractive` when stdin is not a TTY
- Error messages suggest the appropriate non-interactive flag (e.g., `--target/--role`, `--all`, `--yes`, `--group`, `--favorite`)
- `go-isatty` is a direct dependency (promoted from indirect via survey); see `go.mod` for the pinned version

## JSON Output
- `--output` / `-o` persistent flag on root command: `text` (default) or `json`
- Validated in `PersistentPreRunE`. `--output json` is a pure serialisation flag; it does not affect interactivity — interactive prompts still run in a TTY and write to stderr while JSON goes to stdout
- `cmd/output.go` — `outputFormat` var, `isJSONOutput()`, `writeJSON(w, data)`
- `cmd/output_types.go` — JSON structs: `cloudElevationOutput`, `groupElevationJSON`, `sessionOutput`, `statusOutput`, `revocationOutput`, `favoriteOutput`, `awsCredentialOutput`, `accessRequestOutput`, `accessRequestListOutput`
- All commands support JSON: root elevation, `env`, `status`, `revoke`, `favorites list`, `request list`, `request get`, `request submit`, `request cancel`, `request approve`, `request reject`
- `config.Favorite` has both `yaml:"..."` and `json:"..."` struct tags

## Cache
- Eligibility responses cached in `~/.grant/cache/` as JSON files (e.g., `eligibility_azure.json`, `groups_eligibility_azure.json`)
- Default TTL: 4 hours, configurable via `cache_ttl` in `~/.grant/config.yaml` (Go duration syntax: `2h`, `30m`)
- `config.ParseCacheTTL` returns `(time.Duration, error)`. **Absent** means "use the default"; **any explicitly supplied** value that cannot serve as a TTL — unparseable, zero or negative — is an error. Treating those two the same way is the point: silently defaulting `garbage` while rejecting `0s` would validate one field by two opposite rules. `config.Load` validates it so a bad value surfaces at load, not when some command happens to build a cache. `buildCachedLister` (`cmd/root.go`) therefore returns an error too — its bad-TTL arm is reachable only for a `Config` assembled in memory. Both rejection messages must name a remedy: the unparseable arm names the expected syntax (`must be a positive Go duration such as 4h or 30m`) and still wraps the `time.ParseDuration` error with `%w`; the non-positive arm names `--refresh` as the way to bypass the cache for one command, since `0s` used to work as an accidental kill-switch. Neither may point at `grant configure` (see Config)
- `--refresh` flag on `grant` and `grant env` bypasses cache reads but still writes fresh data
- `internal/cache/cache.go` — generic `Store` with `Get[T]`/`Set[T]`, injectable clock for testing
- `internal/cache/cached_eligibility.go` — `CachedEligibilityLister` decorator implementing `eligibilityLister` + `groupsEligibilityLister`
- `internal/cache/session_tracker.go` — `RecordSession`, `SessionTimestamps`, `CleanupSessions` for tracking elevation timestamps in `session_timestamps.json`
  - `sessionTimestampRetention` (24h) is **local retention for the remaining-time display only** — not a session lifetime, not a session limit, not an access-control boundary. Dropping a timestamp only costs grant the ability to show how long a session has left. `SessionTimestamps` filters on it; `CleanupSessions` does **not** read it at all — that filters purely on `activeIDs` membership
- `buildCachedLister()` in `cmd/root.go` — shared factory used by all commands (root, env, status, revoke, favorites add)
- Commands without `--refresh` (status, revoke, favorites add) always pass `refresh: false` — they use eligibility for display only
- Cache failures (read/write) silently fall through to the live API
- `cmd/session_tracking.go` — `recordSessionTimestamp` var (injectable for tests), called after elevation in root and env commands

## Verbose / Logging
- `--verbose` / `-v` global flag wired via `PersistentPreRunE` in `cmd/root.go`
- Calls `config.EnableVerboseLogging("INFO")` (sets `IDSEC_LOG_LEVEL=INFO`) or `config.DisableVerboseLogging()` (sets `IDSEC_LOG_LEVEL=CRITICAL`)
- `cmdLogger` interface in `cmd/verbose.go` — `Info(msg string, v ...interface{})`, satisfied by `*common.IdsecLogger`
- `log` package-level var in `cmd/verbose.go` — all commands use `log.Info(...)` for verbose output; tests swap with `spyLogger`
- `loggingClient` in `internal/sca/logging_client.go` decorates `httpClient`, logging method/route/status/duration at INFO, response headers at DEBUG with Authorization redaction
- `NewSCAAccessService()` wraps ISP client with `loggingClient` using `common.GetLogger("grant", -1)` (dynamic level from env)
- `NewSCAAccessServiceWithClient()` (test constructor) does not wrap — tests don't need logging
- `Execute()` prints `"Hint: re-run with --verbose for more details"` on error when verbose is off
- Users can set `IDSEC_LOG_LEVEL=DEBUG` env var for deeper SDK output

## Config
- App config: `~/.grant/config.yaml`
- SDK profile: `~/.idsec/profiles/grant` (default; override via `IDSEC_PROFILES_FOLDER`)
- **`runConfigure` rebuilds the config from scratch** (`cmd/configure.go`): it never reads the existing file, it constructs a fresh `&config.Config{}` with a hardcoded `default_provider` and an empty `Favorites` map and `Save`s that, so every favorite and the user's `default_provider` are silently destroyed. That is also what keeps `grant configure` reachable when the on-disk config is unloadable (the no-lockout property, pinned by `TestConfigure_OverwritesInvalidCacheTTLAndClobbersFavorites`), so it is not purely a bug — but it means **`grant configure` must never be advertised as the remedy for a bad config value**. The user-facing remedy is to edit the file, whose path every load error names. Known sharp edge, follow-up, deliberately not fixed here
- Always resolve the profile directory with `profiles.GetProfilesFolder()` (SDK) — never hand-roll it. The SDK reads `os.Getenv("HOME")`, not `os.UserHomeDir()`; on Windows `HOME` is frequently unset, so it resolves to a **relative** `.idsec/profiles` under the process CWD. Any code that prints or computes the profile path must agree with the loader, so reproduce the SDK's behavior rather than "correcting" it

## Keyring
- The SDK stores the auth token via `pkg/common/keyring`. `GetKeyring(enforceBasic bool)` (`idsec_keyring.go:117-131`) picks: basic (file) keyring if Docker **or** its own `isWSL()` **or** `IDSEC_BASIC_KEYRING != ""` **or** `enforceBasic`; else the OS keyring on windows/darwin, and on linux the OS-provided (D-Bus/libsecret) keyring whenever `DBUS_SESSION_BUS_ADDRESS` is non-empty; else basic
- **SDK bug (v0.8.1):** `isWSL()` (`:90-95`) matches `"Microsoft"` **case-sensitively** against `/proc/version`. Modern WSL2 reports `-microsoft-standard-WSL2`, so it returns false. Under WSLg `DBUS_SESSION_BUS_ADDRESS` is set, the D-Bus keyring is chosen, and the call can block forever against an unresponsive `gnome-keyring-daemon`
- **The SDK's fallbacks cannot save you.** Both the OS-keyring wrapper and `SaveToken` (`:154-171`) fall back to the basic keyring only when the underlying call returns an **error**. A hang is not an error, so the fallback is unreachable. The hang is also not write-only — `LoadToken`/`GetPassword` can wedge before anything is ever written
- **`IDSEC_BASIC_KEYRING` semantics:** the SDK tests `os.Getenv(...) != ""`, so **any** non-empty value forces the file keyring, `0` and `false` included. Empty/unset does not itself force it — the other `GetKeyring` conditions (Docker, SDK-detected WSL, `enforceBasic`) still apply
- **grant's override:** `internal/keyringenv` detects WSL and sets `IDSEC_BASIC_KEYRING=1`. A non-empty existing value is preserved; an explicitly **empty** value is overwritten on WSL, because empty is precisely the dangerous setting. No-op off linux (the `GOOS` guard short-circuits before any filesystem access)
- Signals, OR'd, in the order the diagnostic reports them: `/run/WSL` exists → `/proc/sys/fs/binfmt_misc/WSLInterop` exists → `/proc/sys/kernel/osrelease` contains `microsoft`/`wsl` → `/proc/version` contains `microsoft` → non-empty `WSL_DISTRO_NAME`/`WSL_INTEROP`. All string matching is case-insensitive
- **Why the token sets differ:** `osrelease` is short and structured, so `wsl` is safe there — systemd matches `Microsoft`/`WSL` on it in `src/basic/virt.c`. (npm `is-wsl` is *not* a precedent for the `wsl` token: it matches only `microsoft`, on `os.release()` then `/proc/version`, before falling back to `WSLInterop`/`/run/WSL`, with everything gated behind `!isInsideContainer()`. It is a precedent for the markers.) `/proc/version` is free-form and carries the kernel build user, build host and compiler banner, so a bare `wsl` there would match a plain Linux box built on a host named `wsl-builder` — `microsoft` only
- **`/run/WSL` is the strongest single signal**, not the string matching: it survives custom kernels, `sudo`, systemd units and cron. `WSL_DISTRO_NAME` is lost under `sudo -i` (microsoft/WSL#5914) and absent in systemd units (#9719), and custom WSL2 kernels may carry neither token (#6911). snapd abandoned string matching for this marker after Launchpad #1991823. WSL's init creates it in `InteropServer::Create()` (`src/linux/init/util.cpp`) from an unguarded call in `ConfigInitializeInstance()` (`src/linux/init/config.cpp`), so it appears even when interop is disabled
- **`WSLInterop` is a supplement only** — but not for the reason previously recorded here. The old claim was "that binfmt entry exists only when interop is enabled". That is true on **WSL1**, where the per-distro registration is gated on `Config.InteropEnabled` (`src/linux/init/config.cpp:543-551`); on WSL2 the entry is registered at VM level and is kernel-global, so it is instead vulnerable to being wiped or shadowed VM-wide
- **All five signals are deliberately redundant, and the redundancy is about *visibility*, not reliability.** This is the point that stops someone simplifying this again — an attempt in `db73645` was reverted in `23ac108` for exactly this reason. The five sources fail **independently** because they are reached by different mechanisms:
  - filesystem markers (`/run/WSL`, `WSLInterop`) are **namespace-local** — a chroot or mount namespace with a clean `/run`, or without `binfmt_misc` mounted, sees neither, no matter what init did
  - proc paths (`osrelease`, `/proc/version`) are **independently maskable** — they are separate mount-visible paths, so one can be masked, omitted or replaced while the other is readable
  - env vars (`WSL_DISTRO_NAME`, `WSL_INTEROP`) are the only ones **inherited across** chroot and mount-namespace boundaries, which is precisely where every marker above disappears
- **Content equivalence is not signal redundancy.** `/proc/version` and `osrelease` provably cannot *disagree*: `fs/proc/version.c` does `seq_printf(m, linux_proc_banner, utsname()->sysname, utsname()->release, utsname()->version)`, and `/proc/sys/kernel/osrelease` **is** `utsname()->release` (`kernel/utsname_sysctl.c`, `uts_kern_table` entry `osrelease` → `init_uts_ns.name.release`, resolved per-namespace by `get_uts()`); a UTS namespace change moves both together. Useful for reasoning about the *values*, but **not grounds for removing either** — identical content is no help when one path is not visible. Same shape of argument for the env vars: init sets `WSL_DISTRO_NAME` and creates `/run/WSL` in the same unguarded function, which proves init made the marker, **not** that a descendant process can still see it
- **Error asymmetry drives the tuning:** a false negative attempts the OS keyring under WSLg and hangs indefinitely with no error and no timeout (unrecoverable); a false positive is a file keyring on a plain Linux desktop (bounded security downgrade). Bias toward over-detection. A redundant check is the cheap side of that trade — do not trade it away for tidiness
- Rejected: container gating (`/run/WSL` is container-safe since a container gets its own `/run` tmpfs). Note the *old* justification — "inside a container `DBUS_SESSION_BUS_ADDRESS` is rarely set, so the SDK already picks basic" — is **refuted**: WSL init injects `DBUS_SESSION_BUS_ADDRESS` explicitly for systemd-backed launches (`src/linux/init/init.cpp`), and ordinary `chroot` preserves it, so the SDK cannot be assumed to fall back on its own. Also rejected: `WSLENV` (user-configurable, often absent), shelling out to `systemd-detect-virt`, and third-party libs (`gookit/goutil` has the same case-sensitive `"Microsoft"` bug)
- Applied in `executeWithKeyringOverride` (`cmd/root.go`), called from `Execute()` before `rootCmd.Execute()` — the single deterministic entry point for the binary, ahead of every keyring access (`cmd/login.go`, `cmd/root.go`, `cmd/logout.go`). It **fails closed**: a `Setenv` error aborts before any command runs
- The applied notice is stashed in `keyringEnvNotice` and emitted from `PersistentPreRunE` inside the `if verbose` branch, so it is verbose-only and unit-testable with `spyLogger` (gating on `IDSEC_LOG_LEVEL` alone would be invisible to the spy)
- Backend switch caveat: a token written to the OS keyring is invisible to the file keyring. Worst case the user re-runs `grant login`

## Authentication
- Use the `/grant-login` skill when you need to authenticate to the grant CLI (e.g., before manual testing)
- Skill definition: `.claude/skills/grant-login/SKILL.md`
- Requires `.env` at project root with `GRANT_PASSWORD` and `TOTP_SECRET`

## Lint
- Config: `.golangci.yml` (golangci-lint v1 format)
- Linters enabled (`disable-all: true`, so this list is exhaustive): defaults (errcheck, gosimple, govet, ineffassign, staticcheck, unused) + bodyclose, errorlint, noctx, gosec (G101 excluded), errname, gocritic, misspell, revive, gocognit (threshold 40), perfsprint, unconvert, usetesting, gofmt (`simplify: true`)
- Test files excluded from gosec, gocognit, bodyclose — `gofmt` has no exclusion, formatting is universal
- Run `gofmt -s -w .` before committing; `gofumpt` was rejected because the codebase is not gofumpt-clean
- `revive/unused-parameter` and `revive/exported` disabled (Cobra signatures, established API names)
- Use `errors.New` for static error strings (perfsprint enforced); `fmt.Errorf` only with `%` verbs
- Use `t.Context()` instead of `context.Background()` in tests (usetesting enforced)

## Build
```bash
make build              # Build binary with -trimpath and ldflags
make test               # Run unit tests
make test-integration   # Run integration tests (builds binary)
make test-all           # Run all tests
make lint               # Run linter (golangci-lint)
make clean              # Clean build artifacts
```
- `-trimpath` used in both `Makefile` and `.goreleaser.yaml` for reproducible builds
- `VERSION ?= dev` (`Makefile:2`) is injected as `-X ...cmd.version=$(VERSION)` (`Makefile:5-8`), so a plain `make build` stamps `version=dev`. `runUpdate` refuses `""`/`"dev"` (`cmd/update.go:38-39`, "cannot update a dev build"), so `grant update` can never succeed on a default local build
- To exercise `grant update` locally: `make build VERSION=0.7.0`, then `./grant update`. Use a version *older* than the latest release so an update is actually found
- `.goreleaser.yaml` uses `CommitDate` (not build date) and `mod_timestamp` for reproducibility

## CI
- `.github/workflows/ci.yml` — `test` job runs as a matrix over `ubuntu-latest` and `windows-latest` with `fail-fast: false`
- Windows runners have no GNU make, so that leg runs the equivalent Go commands directly (`go build -trimpath -o grant.exe .`, `go test -race ./... -v`); Linux keeps `make build` / `make test-race`. Keep the two legs in sync when Makefile targets change
- `go test -race` works on windows/amd64 because the runner image ships gcc (the race detector needs cgo)
- The `Self-update end-to-end` step runs the `selfupdate_e2e`-tagged tests on **both** legs (no `if:` guard) — it is the only test that replaces a real running executable, and comparing the two platforms is the whole point. It builds its fixtures locally, so it needs no network. Keep it unguarded; guarding it to Linux would defeat its purpose
- `Integration tests` (`go test -tags=integration ./cmd -shuffle=on`) and `Test with shuffled order` (`go test -shuffle=on -count=1 ./...`) run **unguarded on both legs**. Integration needs no network and takes ~2s; shuffling is what catches order dependence in a suite that mutates package globals. The integration step is shuffled too because the untagged `cmd/*_test.go` files compile into that binary as well — without it their order dependence is only ever shuffled in the untagged build
- `.golangci.yml` sets `run.build-tags: [integration, selfupdate_e2e]` so both tagged files are linted. Side effect: with `integration` set, `cmd/main_test.go` (`//go:build !integration`) is excluded from linting
- Lint (`golangci-lint-action`) runs on Linux only — a second pass on Windows adds minutes and finds nothing new
- Tests must be OS-portable. Never assert POSIX permission bits without a `runtime.GOOS == "windows"` skip: Go synthesizes `0666`/`0777` for Windows files and `os.Chmod` there only toggles the read-only attribute. Current skips: `internal/config/config_test.go` (`TestLoadConfig_PermissionError`, `TestConfigDir_Error` — chmod 0000 and `HOME`) and `internal/cache/cache_test.go` (`TestSet_FilePermissions`)
- Prefer a portable construction over a skip where one exists. To force a write failure, point at a path whose parent component is an existing regular file rather than a hardcoded `/dev/null/...` path, which is an ordinary writable location on Windows. `MkdirAll` fails with `ENOTDIR` on **both** platforms — no Windows error code is involved: `os.MkdirAll` (`os/path.go`) stats the parent itself and synthesizes `&PathError{Op: "mkdir", Err: syscall.ENOTDIR}` in platform-independent Go, which is also why asserting `Op == "mkdir"` is portable

## CHANGELOG Style
Entries are short and concise. This applies to `[Unreleased]` and everything added from now on; already-released sections are published history and are not rewritten.
- One line per entry — a single sentence, ideally under ~120 characters.
- Say WHAT changed and, where it isn't obvious, the user-visible effect. Not the mechanism, not the root cause, not measurements, not `file:line` references.
- Rationale, evidence, benchmarks, dependency counts and advisory analysis go in the PR description. Durable architecture and policy go in CLAUDE.md.
- Keep the Keep-a-Changelog section headings: `Added` / `Changed` / `Fixed` / `Security`.
- A breaking or behaviour-changing entry may add a short second clause naming the impact. Brevity must never hide a behavioural break from someone skimming before an upgrade.

## Release Process
1. Move `[Unreleased]` entries in `CHANGELOG.md` to a new `[X.Y.Z] - YYYY-MM-DD` section (leave `[Unreleased]` header empty)
2. Commit: `docs: prepare CHANGELOG for vX.Y.Z release`
3. Tag: `git tag vX.Y.Z`
4. Push commit and tag: `git push origin main && git push origin vX.Y.Z`
5. The `release.yml` GitHub Actions workflow triggers on `v*` tags and runs GoReleaser to build binaries and create the GitHub Release

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

Commands declare their collaborators as interfaces in `cmd/interfaces.go` (`authLoader`, `eligibilityLister`, `groupsEligibilityLister`, `elevateService`, `accessRequestService`, `selfUpdater`, …). There are two ways to substitute them.

**Preferred — `New*WithDeps` constructors.** Every command has one: `NewRootCommandWithDeps`, `NewEnvCommandWithDeps`, `NewStatusCommandWithDeps`, `NewRevokeCommandWithDeps`, `NewListCommandWithDeps`, `NewRequestCommandWithDeps`, `NewLogoutCommandWithDeps`, `NewUpdateCommandWithDeps`, plus `runFavoritesAddWithDeps`. The production factory is a thin wrapper that bootstraps the real services and calls the same function. Tests build the command with mocks and never touch a global.

**Package-var seams**, for the few things a constructor cannot reach:

| Var | File | Purpose |
|---|---|---|
| `bootstrapImpl` | `cmd/root.go` | Profile load + authenticate. Memoized by `bootstrapISPAuth` via `sync.Once`; clear it with `resetBootstrapCache()` |
| `recordSessionTimestamp` | `cmd/session_tracking.go` | Elevation timestamp writer |
| `resolveRequestIDFn` | `cmd/request_picker.go` | Interactive request picker |
| `submitPromptFn`, `confirmSubmitFn`, `resolveSubmitTargetFn`, `submitWorkspaceSelectorFn`, `resolveRoleFn` | `cmd/request_submit.go` | `request submit` prompt and resolution steps |
| `log` | `cmd/verbose.go` | Verbose logger; tests swap in `spyLogger` |
| `ui.IsTerminalFunc` | `internal/ui/tty.go` | TTY detection |

There is no `getAuth`/`getSCAService`; those never existed. Every test that swaps one of these globals restores it via `t.Cleanup`, and no such test may call `t.Parallel()`.

### Test Isolation

`internal/testenv` is a normal package imported only from `_test.go` files, so it never links into the binary. `testenv.Run(m.Run)` redirects eight variables under one temp root before `m.Run`, then restores them: `HOME`, `USERPROFILE`, `XDG_CONFIG_HOME`, `IDSEC_PROFILES_FOLDER`, `GRANT_CONFIG`, `IDSEC_KEYRING_FOLDER`, `IDSEC_FILE_LOG_PATH` and `IDSEC_BASIC_KEYRING`.

- `USERPROFILE` is not optional: Go's Windows `os.UserHomeDir` reads `USERPROFILE`, then `HOMEDRIVE`+`HOMEPATH`, and never `HOME`. `HOME` alone leaves the Windows CI leg pointed at the real profile. The SDK profile loader, conversely, reads `HOME` on every platform.
- `GRANT_CONFIG` does **not** cover the cache: `cache.CacheDir()` → `config.ConfigDir()` → `os.UserHomeDir()`. Before this existed the suite wrote the developer's real `~/.grant/cache/session_timestamps.json` on every run.
- `IDSEC_KEYRING_FOLDER` and `IDSEC_FILE_LOG_PATH` are **absolute-path overrides that bypass the `HOME` fallback entirely** (`pkg/common/keyring/idsec_basic_keyring.go`, `pkg/common/idsec_logger.go`, which `MkdirAll`s the log's parent). A value already exported in the developer's or CI environment sends those writes outside the sandbox no matter what `HOME` says.
- `IDSEC_BASIC_KEYRING=1` is set because the OS keyring is a **daemon, not a path**, so no redirect can sandbox it: on a non-WSL Linux box with `DBUS_SESSION_BUS_ADDRESS` set, `GetKeyring` picks the real libsecret store. Forcing the file backend puts keyring state into the sandboxed folder instead. If a future SDK stops honoring the variable, this containment is gone and nothing here detects it.
- `XDG_CONFIG_HOME` is **speculative/defensive** — nothing in grant or the pinned SDK reads it (`rg XDG_` finds only testenv's own comment and tests). It is redirected because it is the conventional escape hatch and costs nothing.
- `IDSEC_PROFILE` and `DEPLOY_ENV` are **unset**, not redirected (`unsetVars`) — they select behavior, not a location, so the only safe state is absent. `IDSEC_PROFILE` picks the SDK's default profile *name*; `DEPLOY_ENV` feeds tenant-env resolution inside `isp.FromISPAuth`, which the sca/workflows retry-policy tests drive for real. `Run` captures set-vs-unset per variable and restores that exact state.
- `testenv` must not import `testing`; `AssertSandboxed` therefore takes a `TB` interface (`Helper`/`Errorf`) that `*testing.T` satisfies.
- `AssertSandboxed` checks the *configured destinations* — `config.ConfigDir`, `config.ConfigPath`, `cache.CacheDir`, `profiles.GetProfilesFolder`, the SDK keyring folder and the SDK file-log path — plus that `IDSEC_BASIC_KEYRING` is non-empty. The last two resolvers are **reimplemented** in testenv rather than called, because the SDK constructor creates the directory as a side effect and an assertion must not write. It does not prove nothing was written outside the sandbox, and cannot see reads. A snapshot-diff gate was considered and rejected: a concurrently running real `grant` false-positives with certainty, and size+mtime misses same-size rewrites.
- Each `AssertSandboxed` block must be individually killable, which means asserting the failure **count and which resolver failed**, not `len(errs) > 0`: any other assertion satisfies a bare "at least one", so the block under test could be deleted outright. `GRANT_CONFIG` pointed outside the sandbox isolates `config.ConfigPath` (1 failure); `HOME`+`USERPROFILE` pointed outside isolates `config.ConfigDir` **and** `cache.CacheDir` (2 failures, because `CacheDir` delegates to `ConfigDir` → `os.UserHomeDir`). `recordingTB` therefore stores the *formatted* message — the resolver name is an argument, not part of the format string.
- The redirect list is validated against an **explicit literal** in `testenv_test.go`, and every entry additionally gets a hostile pre-existing value before `Run` in `TestRun_OverridesPreExistingHostileValues`. Ranging over `redirectedVars` itself is the trap this replaced: dropping an entry merely checked one fewer thing, and four of the original five survived a drop-one mutation because with `HOME` redirected their *fallbacks* already landed in-sandbox. A var's whole value is defending against a pre-existing value, so that is what the test must supply.
- `Run` restores the environment and removes the sandbox from a **`defer`**, so a panic inside `m.Run` (a `-race` detection, a stray panic) cannot leak the directory or leave the process redirected. `sandboxRoot` is saved and restored rather than cleared, so a nested `Run` hands the outer root back.
- `TestMain` lives in `cmd/main_test.go` (`//go:build !integration`, because `cmd/integration_test.go` declares its own), `internal/config/main_test.go`, `internal/cache/main_test.go`, `internal/sca/main_test.go`, `internal/workflows/main_test.go` and `internal/sdkclient/main_test.go`. The `config`/`cache` ones are in the **external** test package (`config_test`/`cache_test`) because `testenv` imports those packages — an in-package test file importing it would be an import cycle. `sca`/`workflows`/`sdkclient` can be in-package: `testenv` imports `internal/sca/models`, not `internal/sca`. Those three earn a `TestMain` because their retry-policy tests drive the **real** service constructors.
- `os.Setenv` in `TestMain` runs before `m.Run`, so it does not collide with the `t.Parallel()` sites in `internal/` — unlike `t.Setenv`, which the stdlib forbids in parallel tests.
- `cmd/bootstrap_stub_test.go` (untagged, so both build configurations get it) points `bootstrapImpl` at `errTestBootstrapDisabled`. Assert it with `errors.Is`, never a bare `wantErr: true` — otherwise a stray bootstrap attempt silently satisfies an unrelated case. `recordSessionTimestamp` is deliberately left live: it is what proves the redirect works.
- `executeCommand`/`executeCommandStreams`/`executeWithHint` call `restoreCommandGlobals` to put back **both** globals Cobra binds to persistent flags: `outputFormat` (`--output`) and `verbose` (`--verbose`). Without that a command built outside the root (e.g. `NewEnvCommandWithDeps`) inherits the previous test's values — an order dependence `go test -shuffle=on` exposes. `outputFormat` is the load-bearing half (a no-op restore fails 5 of 8 fixed shuffle seeds); `verbose` is latent only because pflag rewrites it at registration.

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

`cmd/integration_test.go` (`//go:build integration`) drives the compiled binary as a child process. Its `TestMain` runs inside `testenv.Run` and builds into a unique temp directory — never the shared `../grant-test`, which two concurrent runs would fight over. `GOCACHE`/`GOMODCACHE`/`GOPATH`/`GOENV` are resolved **before** the `HOME` redirect and passed to the build, otherwise it starts from an empty module cache and needs the network. `GOENV` is in the list because the child `go build` finds its env file via `os.UserConfigDir` — `$XDG_CONFIG_HOME/go/env` on Linux (redirected to an empty sandbox) but `%AppData%\go\env` on Windows (not redirected at all), so without it the two CI legs read different files and any `go env -w GOPROXY=…`/`GOFLAGS`/`GOPRIVATE` is silently dropped on Linux.

Assertions are exact exit codes plus exact error text. Keyword soup (`error|Error|failed|not found`) is banned here: a panic satisfies it. `runGrant` fails the test outright if the child output contains a panic, and closes stdin so no prompt can block.

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
