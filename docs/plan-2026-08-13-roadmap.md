# grant-cli Roadmap Plan — 2026-08-13

Status: planning only. Every `file:line` below was verified against the working tree at commit `f191f82` (branch `chore/dependency-upgrades`) and against `~/go/pkg/mod/github.com/cyberark/idsec-sdk-golang@v0.8.1`.

## Execution order (dependency + risk)

**Execution order: 3 → 1 → 2 → 4 → 5.**

| Order | # | Item | Why here | Blocking |
|---|---|------|----------|----------|
| 1st | 3 | Stale profile paths + retroactive CHANGELOG | Already-shipped, user-visible wrong-path bug. Small, independent, zero runtime risk — ship it first | None |
| 2nd | 1 | 429 / transient-retry safety on non-idempotent POSTs | Gates PR #47; cheap to resolve | Blocks #47 merge |
| 3rd | 2 | Replace `rhysd/go-github-selfupdate` | Advisory GO-2026-5932 is real but **not currently exploitable in grant**: grant never configures PGP validation — `cmd/update.go:17` uses `selfupdate.DefaultUpdater()`, whose `Config.Validator` is nil, so the `openpgp` code path is never entered. That drops it below item 1, but it stays ahead of feature work: the dependency is abandoned (Jan 2021) and unfixable in place | None |
| 4th | 4 | GCP support | Small, additive, mostly config-driven | Wants #47 merged |
| 5th | 5 | `grant k8s` / `grant kubeconfig` | Largest by far. Now implementation-ready: D-4 is decided (5B — import the SDK's k8s package), which supplies the exec-credential flow that a hand-rolled control plane could not | Wants #47 merged |

Items 3, 1 and 2 are independent and can proceed concurrently on separate branches if capacity allows; the ordering above is the priority sequence for a single worker. Items 4 and 5 both touch `cmd/root.go` `supportedCSPs`/provider help text — sequence 4 before 5.

---

## Item 1 — Verify 429 / transient auto-retry safety on non-idempotent POSTs

### Goal
Determine whether SDK v0.8.1's new automatic retry can replay grant's non-idempotent POSTs, and either document it as safe (unblocking PR #47) or opt out for the affected clients.

### What the SDK actually does (verified)

`~/go/pkg/mod/github.com/cyberark/idsec-sdk-golang@v0.8.1/pkg/common/idsec_client.go`:

- **Request construction, `doRequest` :766-826** — the body is marshaled from the caller's `body interface{}` *inside* `doRequest`. Every retry is a fresh recursive call to `doRequest` with the same `body` value, so the retried request carries a byte-identical, correctly-formed body. There is no exhausted-`io.Reader` bug.
- **429 branch, :865-885** — `if resp.StatusCode == http.StatusTooManyRequests && transientRetryLocal > 0`. **No method filter.** Honors `Retry-After` via `parseRetryAfter` (:1295), else exponential backoff `transientRetryBackoff` (:1331); a server-supplied `Retry-After` is clamped to `transientRetryMaxWait` (:870-875). Drains and closes the body, sleeps via `sleepWithContext` (aborts on ctx cancel), recurses with `transientRetryLocal-1`.
- **Transport-error branch, :835-849** — `isRetryableTransportError(err, method)` (:1244-1283). This *does* filter by method, but only partially: `io.EOF` / `io.ErrUnexpectedEOF` / the substrings `"eof"` and `"server closed idle connection"` are retried **for any method including POST** (:1252-1266); only the genuinely ambiguous set (`connection reset`, `broken pipe`, `http2: server sent goaway`) is gated behind `isIdempotentMethod` (:1269-1281).
- **Defaults, :53-60 and :375-377** — `transientRetryCount = 3`, base wait `500ms`, max wait `10s`.
- **Opt-out, :1187-1197** — `func (ac *IdsecClient) SetTransientRetry(count int, baseWait, maxWait time.Duration)`; `SetTransientRetry(0, 0, 0)` disables. `isp.IdsecISPServiceClient` embeds `*common.IdsecClient` (`pkg/common/isp/idsec_isp_service_client.go:29-32`), so the client returned by `isp.FromISPAuth` exposes this method directly.
- Bounded by grant's own context: `apiTimeout = 30 * time.Second` (`cmd/root.go:30`). Note the `≤10s per sleep` reading is **not quite right**: `transientRetryBackoff` (:1331-1349) caps the *base* delay at `maxWait` and then **adds** `randomJitter(delay)` — up to 50% more — so a single sleep can reach ~15s with the default 10s cap. `sleepWithContext` still returns the ctx error rather than over-running the 30s budget, so the practical bound is grant's context, not the SDK's cap.

### Assessment (to be confirmed by the assignee)

- **429 replay is low-risk.** A 429 is a *rejection*: the request was rate-limited, not processed. Retrying it is standard, server-directed behavior, the delay honors `Retry-After`, and the retried body is identical. The realistic failure mode (a gateway that 429s *after* the backend committed) is not something grant can detect or defend against anyway.
- **The real replay hazard is the transport-error branch**, specifically bare `EOF` on POST. An `EOF` can, rarely, surface after the server accepted and processed the request but the response was truncated. That is the path that could double-elevate or double-submit.

Blast radius per non-idempotent POST:

| Call site | Duplicate effect | Severity |
|---|---|---|
| `internal/sca/service.go:199` `POST /api/access/elevate` | second SCA session on same target; visible in `grant status`, revocable | Low |
| `internal/sca/service.go:381` `POST /api/access/elevate/groups` | second group elevation session | Low |
| `internal/sca/service.go:227` `POST /api/access/sessions/revoke` | re-revoking already-revoked IDs | Effectively idempotent |
| `internal/sca/service.go:354` `POST /api/cloud/cloud-roles/ondemand` | read-shaped POST (role discovery) | None |
| `internal/workflows/service.go:208` `POST /api/workflows/requests` | **duplicate access request visible to approvers** | Moderate |
| `internal/workflows/service.go:232` `.../cancel` | second cancel on a cancelled request → 409 | Low |
| `internal/workflows/service.go:259` `.../finalize` | second approve/reject → 409 | Low |

### Recommended outcome: **disable transient retry on BOTH clients (D-1c)**

The earlier "UAR only" recommendation does not survive scrutiny:

- **There is no per-request retry opt-out.** `SetTransientRetry` is client-wide state on `*common.IdsecClient` (`idsec_client.go:1187-1197`). There is no per-call override, so "retry on reads, not on writes" cannot be expressed at call granularity.
- **Toggling it mid-flight is race-prone.** Setting the count to 0 around a POST and restoring it afterwards mutates shared client state. grant already fans out eligibility across CSPs concurrently (`cmd/root.go:271-312`), so a concurrent read could observe the temporarily-zeroed policy — or worse, a concurrent write could observe the restored one. Same hazard class as the SDK's own `SetHeader`/`RemoveHeader` dance around `Content-Type` (see item 5).
- **SCA's POSTs are not meaningfully more idempotent than UAR's.** `POST /api/access/elevate` and `POST /api/access/elevate/groups` create real sessions. "Cheap and self-healing" is a judgement about blast radius, not about idempotency — and the same bare-`EOF`-on-POST replay path applies to both.

Therefore: call `SetTransientRetry(0, 0, 0)` on **both** the SCA and UAR ISP clients.

**Acceptable alternative if 429 resilience on reads is judged necessary:** a *read/mutation client split* — build two ISP clients per service, one with retry enabled used only by the GET/pagination paths, one with retry disabled used by every POST. This is more code and two auth-sharing clients per service, so only take it if the fan-out actually gets rate-limited in practice. Do **not** implement the mid-flight-toggle variant.

### Files to modify
- `internal/sca/service_test.go` — new cases first (TDD).
- `internal/sca/service.go:59` — after `isp.FromISPAuth(...)`, call `client.SetTransientRetry(0, 0, 0)` with a comment citing `idsec_client.go:865-885` and `:1252-1266`.
- `internal/workflows/service_test.go` — new cases first.
- `internal/workflows/service.go:55-60` — same call, same comment.
- Prefer a single shared helper (e.g. `internal/ispclient.configureRetry(*common.IdsecClient)`) over two copies, so the policy has one definition and one test.
- `CLAUDE.md` — new "SDK Retry Behavior" section under `## SCA Access API` / `## Access Requests API`.
- `CHANGELOG.md` `[Unreleased]` — add a bullet under the existing dependency-upgrade entry.

### TDD test plan
`internal/workflows/service_test.go` (new tests, written before the change):
- `TestSubmitRequestDoesNotRetryOn429` — `httptest.NewServer` counting handler that always returns `429` with `Retry-After: 1`. Assert exactly **1** inbound request and that `SubmitRequest` returns an error. Requires exercising the real ISP client path, which needs auth; therefore:
- Preferred seam: a small unit test on the shared `configureRetry(c *common.IdsecClient)` helper so the policy is testable without ISP auth. Table cases: `{name: "disables transient retry", want: 0}`.
- `internal/sca/service_test.go` — mirror image: assert the SCA constructor also runs `configureRetry`, i.e. `TestNewSCAAccessServiceDisablesTransientRetry`. Both services must be covered, since the policy is now symmetric.
- **Concurrency:** add a `-race` test that drives the SCA service's read path from N goroutines while a POST path runs, pinning that no code mutates client-wide retry/header state mid-flight. This is the regression guard against the rejected toggle approach and against grant's existing multi-CSP fan-out.

Do **not** unit-test the SDK's retry loop itself — that is upstream-tested (`idsec_client_test.go` in the module cache) and mocking it in grant only tests the mock.

### Acceptance criteria
- `make test`, `make test-race`, `make lint`, `make build` pass.
- A `grant request submit` against a rate-limited/interrupted UAR endpoint issues exactly one POST; likewise `grant` (elevate) against SCA.
- `CLAUDE.md` documents the retry semantics and the opt-out on both clients, with the SDK line references, including the note that `SetTransientRetry` is client-wide state and must not be toggled per-request.
- PR #47 description updated with the finding; #47 merges.

### Manual testing (needs a real tenant — use `/grant-login`)
- `grant --verbose` (elevate) and `grant request submit --verbose` end-to-end to confirm no behavior regression from the upgraded client.
- No practical way to force a 429 from a tenant; do not gate the merge on that.

### Branch / rollback
- Branch: `chore/sdk-retry-policy` (merge into `chore/dependency-upgrades` so #47 ships as one unit, or land after #47).
- Rollback: delete the shared `configureRetry` helper and its two call sites.

### Verify sequence
```bash
make test && make lint && make build
govulncheck ./...
```

### Correction to prior analysis (verified, propagate this)
The earlier claim that "the SDK logs full URLs including query params, which would leak UAR `freeText`" is **not accurate for v0.8.1**. `idsec_client.go:828` and `:832` log `method` + `fullURL`, and `fullURL` is built at :735-765 *before* query parameters are applied — the params go onto `req.URL.RawQuery` at :825, after `fullURL` is finalized. The SDK therefore does not log query strings on these paths. The decision to keep `internal/sca/logging_client.go` and `internal/workflows/logging_client.go` still stands on its other grounds: those clients log response **status codes**, **durations**, and DEBUG-level **redacted headers** (`internal/sca/logging_client.go:38-56`), none of which the SDK emits.

---

## Item 2 — Replace `rhysd/go-github-selfupdate`

### Goal
Remove the abandoned (Jan 2021) self-update dependency, eliminate the `golang.org/x/crypto/openpgp` exposure (GO-2026-5932, no fix available), and drop its dependency tail: `blang/semver v3.5.1+incompatible`, `google/go-github/v30`, `golang.org/x/oauth2 v0.0.0-20181106182150` (Nov 2018), `golang/protobuf v1.3.2`, `google.golang.org/appengine v1.3.0`, `tcnksm/go-gitconfig`, `google/go-querystring v1.0.0`, `inconshreveable/go-update`, `ulikunitz/xz`.

### CRITICAL finding — the preferred replacement does not solve the problem

`creativeprojects/go-selfupdate` **v1.6.0 still imports `golang.org/x/crypto/openpgp`**, in `validate.go` (verified via GitHub API: `validate.go` imports `"golang.org/x/crypto/openpgp"` at line 17, alongside `crypto/ecdsa`). `validate.go` is in the root `selfupdate` package, so importing the package puts `openpgp` in grant's build graph — exactly the situation GO-2026-5932 flags (the advisory lists *no symbols*, only import paths, so it is reported at package granularity).

Its `go.mod` (v1.6.0) also **adds**, not removes, weight: `code.gitea.io/sdk/gitea v0.23.2`, `gitlab.com/gitlab-org/api/client-go v1.46.0`, `github.com/google/go-github/v86`, `Masterminds/semver/v3`, `hashicorp/go-retryablehttp`, `hashicorp/go-cleanhttp`, `hashicorp/go-version`, `42wim/httpsig`, `go-fed/httpsig`, `davidmz/go-pageant`, `golang.org/x/oauth2 v0.36.0`, `golang.org/x/time`. `gitea_source.go` and `gitlab_source.go` live in the same package as `github_source.go`, so all three provider SDKs are pulled in unconditionally.

**Recommendation: do not adopt `creativeprojects/go-selfupdate`.** Two viable options remained; **D-2 is now DECIDED in favour of Option B** — `minio/selfupdate` for apply/rollback with in-house discovery. Option A is retained below as a documented alternative and as the source of the discovery/checksum design that Option B still uses.

> **Framing note.** "Zero new Go module deps" is a **goal**, not a hard rule. New modules are acceptable when the reason is stated and the cost is measured. That is exactly the trade being made here: +1 tiny module in exchange for not owning the most dangerous code path in the CLI on three operating systems.

#### DECIDED — Option B: `minio/selfupdate` for apply/rollback, in-house discovery
`minio/selfupdate` v0.6.0 gives a hardened, well-exercised `Apply()`: atomic replace, fsync, the Windows rename dance plus `hide_windows.go`, rollback, and an optional patcher. **Discovery, asset selection, version comparison and checksum verification stay hand-written and stay in grant** — exactly as specified under Option A below; only the "Replace" and "Rollback" bullets are delegated.

Dependency accounting (verified against the module proxy — the earlier "requires only two deps" wording was wrong):
- `minio/selfupdate` v0.6.0 `go.mod` requires `aead.dev/minisign v0.2.0` and `golang.org/x/crypto`;
- `aead.dev/minisign` in turn requires `golang.org/x/crypto`, **`golang.org/x/sys`**, and `golang.org/x/term`;
- grant's `go.mod` already carries `golang.org/x/crypto` (`:44`), `golang.org/x/sys` (`:50`) and `golang.org/x/term` (`:51`) as indirects, so none of those three is new to the graph.

**Net: +1 new module (`aead.dev/minisign`), −10 modules, and GO-2026-5932 removed.** No `openpgp`. Last release Jan 2023, but the package is small (`apply.go`, `patcher.go`, `minisign.go`, two `hide_*` files) and the surface is stable. grant uses only `Apply()`; the minisign verification path is unused unless a future decision grows the updater to signature verification.

Why this over full in-house ownership: the hardening list under Option A (symlinks, fsync, concurrent updates, Windows locks/AV, rollback-of-rollback) is real work on a path whose failure mode is *"the user's binary is destroyed"*, with no upstream and no other users exercising it. `aead.dev/minisign` is a single tiny pure-Go module adding no new transitive modules, so it costs essentially nothing against either the vulnerability-surface or binary-size goals.

#### Option A (alternative, not chosen) — fully in-house updater, zero new modules
Retained because Option B still uses everything in this list except the last two bullets.

grant's release surface is fully known and stable (verified against the live `v0.7.0` release):
```
checksums.txt
grant-cli_0.7.0_{linux,darwin}_{amd64,arm64}.tar.gz
grant-cli_0.7.0_windows_{amd64,arm64}.zip
```
produced by `.goreleaser.yaml` (`archives.formats: tar.gz`, `format_overrides` → `zip` for windows; `checksum.name_template: "checksums.txt"`). Everything needed is stdlib:
- Discovery: `GET https://api.github.com/repos/aaearon/grant-cli/releases/latest` (`net/http` + `encoding/json`).
- Version compare: internal semver compare over `MAJOR.MINOR.PATCH` (grant only ever emits GoReleaser-style tags) — removes `blang/semver` entirely instead of lifting it to v4.
- Asset selection: `runtime.GOOS`/`GOARCH` → `grant-cli_<ver>_<os>_<arch>.<ext>`.
- Integrity: download `checksums.txt`, `crypto/sha256` the archive, compare. **This is a security *improvement*: the current `rhysd` path performs no checksum validation at all** (no `Validator` is configured in `cmd/update.go`).
- Extract: `archive/tar` + `compress/gzip`, `archive/zip`.
- Replace *(delegated to `minio/selfupdate.Apply()` under the chosen Option B)*: write to `<exe>.new` in the same directory, `chmod 0755`, then `os.Rename` over the target. Windows: `os.Rename(exe, exe+".old")` → `os.Rename(new, exe)` → best-effort `os.Remove(exe+".old")` (a running Windows binary cannot be deleted but *can* be renamed).
- Rollback *(also delegated under Option B)*: on any failure after the first rename, restore from `<exe>.old`/`<exe>.bak`.

Benefit: keeps the zero-new-modules goal intact absolutely, removes 10 modules, removes `openpgp` from the graph entirely, and adds checksum verification we don't have today.

Cost — **the reason this option was not chosen.** The "~250 lines" figure covers the happy path only. A production-safe in-house `Apply()` also has to handle:
- **symlinks** — `os.Executable()` may resolve to a symlink (Homebrew, `/usr/local/bin` shims); replacing the link vs. its target are different operations with different failure modes;
- **fsync** — the new binary must be `Sync()`ed before the rename, or a crash/power loss between write and rename leaves a truncated executable;
- **concurrent updates** — two `grant update` runs racing on the same path;
- **Windows file locks and AV interference** — the rename dance can fail because an antivirus scanner or another process holds the image open; retries and clear diagnostics are needed, not just the two-rename sequence;
- **rollback that itself fails** — the `.old` restore can fail, and the user must be told exactly which file to move back by hand;
- **archive-bomb / traversal handling** — `io.LimitReader` caps, per-entry size caps, and path-traversal rejection for both `tar.gz` and `zip`.

Realistically that is several hundred lines of genuinely fiddly, platform-specific code that grant then owns forever, on a code path whose failure mode is "the user's binary is destroyed".

#### Option C — `creativeprojects/go-selfupdate`: rejected
Retains `openpgp`; adds Gitea + GitLab + go-github/v86 + hashicorp + httpsig transitives. Does not meet the stated goal.

### Trust model — what `checksums.txt` actually buys (be honest about this)

Adding checksum verification is a real improvement over today's *nothing*, but it must not be documented as more than it is.

`checksums.txt` is fetched from **the same origin as the binary** — the same GitHub release, over the same TLS connection, with no independent key. Therefore:

| Threat | Protected by SHA-256 vs `checksums.txt`? |
|---|---|
| Truncated / corrupted download, flaky network, partial CDN response | **Yes.** This is the primary value. |
| Wrong asset selected (arch/OS mismatch, `name_template` drift) | **Yes** — the filename lookup fails or the digest mismatches. |
| Corrupt or misbehaving intermediate cache/proxy that mangles bytes | **Yes.** |
| Active MITM who can serve arbitrary content for `github.com` / `objects.githubusercontent.com` | **No.** They serve a matching `checksums.txt` too. TLS is the only defence here, and TLS is already the defence with or without checksums. |
| Compromise of the GitHub repo, the release, or the CI token that publishes it | **No.** The attacker publishes a consistent release. |

What *would* raise the bar is a signature over the checksum file verified against a key **shipped in the grant binary itself** (GoReleaser `signs:` with cosign or minisign, verified at update time). That is out of scope for this item, but note that Option B already puts `aead.dev/minisign` in the graph, so minisign-signed releases would be a small incremental step later rather than a new dependency decision.

**Documentation requirement:** `README.md` and `CLAUDE.md` must describe `grant update` as "integrity-checked" (detects corruption), **not** "signed" or "verified authentic".

### Recovery from an interrupted self-update

An update can be interrupted at any point — Ctrl-C, crash, power loss, AV quarantine mid-rename. Define and test the behavior:

- **Before the rename:** only `<exe>.new` exists. Harmless, but stale temp files accumulate. Remove `<exe>.new`/`*.tmp` siblings on the *next* `grant update` run, and always write temp artifacts into the executable's own directory so the cleanup scope is unambiguous.
- **After the first rename, before the second (Windows path):** the running binary is now at `<exe>.old` and `<exe>` may not exist. This is the dangerous window. `minio/selfupdate.Apply()` handles the rollback, but grant must surface an explicit, copy-pasteable recovery instruction naming both absolute paths if rollback itself fails — never a bare "update failed".
- **After a successful update, with `<exe>.old` still present:** expected on Windows (a running image cannot be deleted). Best-effort remove it on the *next* run, at startup, not only inside `grant update`.
- **Never** leave the user with no executable at `<exe>` and no printed instruction.

Test: `TestApplyUpdateInterrupted` — inject a `renameFn` that fails on the Nth call, and assert for each N that either the original binary is intact or the error message contains both the `.old` and target paths.

### Files to create / modify
- **Create** `internal/selfupdate/` — GitHub release discovery, asset naming, version comparison, checksum verification, archive extraction, and a thin wrapper over `minio/selfupdate.Apply()` (testable without the cobra layer).
- **Add** `github.com/minio/selfupdate v0.6.0` to `go.mod` (pulls `aead.dev/minisign v0.2.0`; `x/crypto`, `x/sys`, `x/term` already present). Record the justification in the `go.mod` vicinity and in `CLAUDE.md`.
- **Create** `internal/selfupdate/selfupdate_test.go`, `internal/selfupdate/version_test.go`.
- **Modify** `cmd/update.go` (currently `1-64`) — remove `github.com/blang/semver` (`:8`) and `github.com/rhysd/go-github-selfupdate/selfupdate` (`:9`) imports. Keep the dev-build guard at `:33-36` verbatim (`version == "" || version == "dev"`; `version` declared in `cmd/version.go:11`, set by `-ldflags` in `Makefile:5-8` and `.goreleaser.yaml`). Keep `updateSlug = "aaearon/grant-cli"` (`:13`). Replace `semver.Parse` (`:40`) and `updater.UpdateSelf(current, updateSlug)` (`:47`).
- **Modify** `cmd/interfaces.go:90-93` — the `selfUpdater` interface leaks external types: `UpdateSelf(current semver.Version, slug string) (*selfupdate.Release, error)`. Redefine over grant-owned types, e.g. `UpdateSelf(ctx context.Context, current string) (newVersion string, updated bool, err error)`. Drop the `blang/semver` (`:9`) and `rhysd/...` (`:12`) imports.
- **Modify** `cmd/update_test.go:1-100+` — constructs `selfupdate.Release{Version: semver.MustParse(...)}` at `:42-44` and `:56-58`; rewrite against the new interface.
- **Modify** `cmd/test_mocks.go` — `mockSelfUpdater` (referenced at `cmd/update_test.go:16`).
- **Modify** `go.mod` / `go.sum` — remove `blang/semver`, `rhysd/go-github-selfupdate`; indirect tail drops via `go mod tidy`.
- **Modify** `README.md:81-85` (`# Self-update`) and `CLAUDE.md` (the `grant update` bullet naming `rhysd/go-github-selfupdate` → `minio/selfupdate`, plus the "integrity-checked, not signed" wording from the trust-model section).
- **Modify** `.github/workflows/` — add a `windows-latest` job (see "Windows CI" below).
- **Modify** `CHANGELOG.md` `[Unreleased]` — Changed/Security entries.

### TDD test plan
Tests before implementation, in `internal/selfupdate/*_test.go`:

1. **`TestParseVersion` / `TestCompareVersions`** — table: `{"1.0.0","1.0.1",-1}`, `{"v1.2.3","1.2.3",0}`, `{"1.10.0","1.9.0",1}`, `{"1.0.0","1.0.0",0}`, invalid → error.
2. **`TestAssetNameFor`** — table over `{goos, goarch, version}` → `grant-cli_0.7.0_linux_amd64.tar.gz`, `..._darwin_arm64.tar.gz`, `..._windows_amd64.zip`. Guards against `.goreleaser.yaml` `name_template` drift.
3. **`TestFetchLatestRelease`** — `httptest.NewServer` serving a captured GitHub `releases/latest` JSON fixture (trimmed to `tag_name` + `assets[].{name,browser_download_url}`). Cases: happy path; 404; 403 rate-limit body; malformed JSON; release with no matching asset. Base URL injected via an unexported `apiBaseURL` field, mirroring the `httpClient` DI pattern in `internal/sca/service.go:21-24`.
4. **`TestVerifyChecksum`** — in-memory `checksums.txt` (`<sha256>  <filename>` lines, GoReleaser format). Cases: match; mismatch → error; filename absent → error; malformed line → error.
5. **`TestExtractBinary`** — construct a `tar.gz` and a `zip` in memory containing `grant`, plus a decoy `README.md` and a `../evil` path-traversal entry that must be rejected (gosec G305 requires this anyway). Assert extracted bytes and traversal rejection.
6. **`TestApplyUpdate`** — `t.TempDir()` with a fake current binary, driving grant's wrapper around `minio/selfupdate.Apply()`. Cases: successful replace (contents swapped, mode `0755`); mid-way failure leaves the original intact; rollback restores; `TestApplyUpdateInterrupted` per the recovery section. Inject the apply function behind an interface so the failure cases are reachable without corrupting the test binary.
7. **`TestCleanupStaleArtifacts`** — `.new`/`.old` siblings left by an interrupted run are removed on the next invocation, and nothing outside the executable's directory is touched.
8. **`cmd/update_test.go`** — keep the existing four behavioral cases (dev build rejected ×2, already-up-to-date, error propagated, nil-release) retargeted at the new mock. **No network access in any test.**

Linter notes (`.golangci.yml`): `noctx` — use `http.NewRequestWithContext`; `bodyclose` — close every response body; `gosec` — G305 (zip slip), G110 (decompression bomb: wrap in `io.LimitReader`, cap ~128 MiB).

### Windows CI (new requirement)

An injected `renameFn` stub is **not** sufficient coverage for the Windows path. The stub exercises grant's call sequence, not the behavior that actually breaks on Windows: a running image cannot be replaced in place, `os.Remove` on the live executable fails, and AV/Defender can hold a handle open long enough to fail the rename. None of that reproduces on Linux under a stub.

**Recommendation: add `windows-latest` to the GitHub Actions test matrix** and run the full `go test ./...` there, plus a dedicated integration test that builds a small throwaway binary in `t.TempDir()`, invokes the real apply path against it, and asserts the swap succeeded with no dangling `.old`. Cost is one extra CI job; the alternative is discovering the failure in a user's `grant update`, which is the one failure mode that cannot be rolled back remotely.

If a Windows runner is declined, the manual Windows step in the matrix below becomes **blocking for every release that touches `internal/selfupdate`**, not just this one — say so explicitly in `CLAUDE.md`.

### Acceptance criteria
- `go.mod` no longer lists `rhysd/go-github-selfupdate` or `blang/semver`; `golang.org/x/oauth2`, `golang/protobuf`, `google.golang.org/appengine`, `google/go-github/v30`, `google/go-querystring`, `tcnksm/go-gitconfig`, `inconshreveable/go-update` gone from the indirect block.
- `go.mod` lists exactly one new direct module, `github.com/minio/selfupdate`, plus `aead.dev/minisign` indirect — and nothing else new. Verify with the `go list -deps` diff in the verify sequence.
- `govulncheck ./...` no longer reports GO-2026-5932; findings drop from 26 to ≤25 (remainder being stdlib issues fixed by go1.25.x).
- `make test`, `make lint`, `make build`, `make test-race` pass.
- `grant update` on a real release build performs a checksum-verified update.

### Manual testing (required — cannot be covered by unit tests)
1. `make build VERSION=0.6.1`, run `./grant update`, confirm it discovers `v0.7.0`, verifies the checksum, replaces the binary; `./grant version` reports `0.7.0`.
2. Repeat at latest version → "already up to date".
3. Windows: build `windows/amd64`, repeat on a Windows host or under Wine; confirm the rename dance and no dangling `.old`.
4. `./grant update` on a `make build` (VERSION defaults to `dev`) → dev-build guard fires.
5. Corrupt download simulation via local fixture server with a bad checksum → update aborts, original binary intact.

### Branch / rollback
- Branch: `fix/replace-selfupdate`.
- Rollback: revert the commit. Because the failure mode is "user's binary gets clobbered", ship only after the full manual matrix.

### Verify sequence
```bash
go mod tidy && git diff --stat go.mod go.sum
make test && make test-race && make lint && make build
govulncheck ./...
go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./... | sort -u   # confirm module set shrank
```

---

## Item 3 — Fix stale profile paths + retroactive CHANGELOG note

### Goal
Stop telling users their SDK profile lives at `~/.idsec_profiles/grant`. Since SDK v0.2.3 (shipped in grant **v0.7.0**, CHANGELOG line 23) the real default is `$HOME/.idsec/profiles`, overridable by `IDSEC_PROFILES_FOLDER`.

Verified upstream: `pkg/profiles/idsec_profile_loader.go:126-131`
```go
func GetProfilesFolder() string {
	if folder := os.Getenv("IDSEC_PROFILES_FOLDER"); folder != "" { return folder }
	return filepath.Join(os.Getenv("HOME"), ".idsec", "profiles")
}
```

### Exact stale locations (verified)
| File:line | Current text | Fix |
|---|---|---|
| `cmd/configure.go:27` | `- SDK profile at ~/.idsec_profiles/grant` | `- SDK profile at ~/.idsec/profiles/grant (override with IDSEC_PROFILES_FOLDER)` |
| `cmd/configure.go:114-118` | hand-rolled `os.Getenv("IDSEC_PROFILES_FOLDER")` + `filepath.Join(home, ".idsec_profiles")` fallback | `profileDir := profiles.GetProfilesFolder()` — `profiles` already imported at `cmd/configure.go:14` |
| `cmd/configure.go:119` | `profilePath := filepath.Join(profileDir, "grant")` | unchanged (correct once `profileDir` is right) |
| `cmd/configure.go:139` | `fmt.Fprintf(..., "Profile saved to %s\n", profilePath)` | unchanged; now prints the truth |
| `CLAUDE.md:132` | `- SDK profile: ~/.idsec_profiles/grant` | `- SDK profile: ~/.idsec/profiles/grant (default; override via IDSEC_PROFILES_FOLDER)` |

After the change, `os` may become unused in `cmd/configure.go` (used only at `:114-117`); `filepath` survives via `:119`. Expect to drop the `"os"` import (`:7`). `make lint` will catch it.

`grep -rn 'idsec_profiles'` over `README.md` and `internal/` returns nothing.

### Windows caveat to surface (not to paper over)
`GetProfilesFolder()` uses `os.Getenv("HOME")`, not `os.UserHomeDir()`. On Windows `HOME` is frequently unset, so the SDK resolves to a **relative** `.idsec/profiles` under the process CWD. Because `runConfigure` must print the same path the loader will later read, the fix must call `profiles.GetProfilesFolder()` exactly rather than "improving" it — otherwise `configure` and `login` disagree. Document the caveat in `CLAUDE.md`; file upstream if it bites. Do **not** silently substitute `os.UserHomeDir()`.

### Retroactive CHANGELOG note
Add to the **existing** `## [0.7.0] - 2026-04-21` section (`CHANGELOG.md:21`), under its `### Changed` block (starts `:23`):

> - **Profile location moved.** As a side effect of the SDK upgrade, the SDK profile directory changed from `~/.idsec_profiles/` to `~/.idsec/profiles/` (override with `IDSEC_PROFILES_FOLDER`). Users upgrading from v0.6.x or earlier must either re-run `grant configure` or move the file: `mkdir -p ~/.idsec/profiles && mv ~/.idsec_profiles/grant ~/.idsec/profiles/grant`.

Also add an `[Unreleased] / ### Fixed` bullet for the `grant configure` help-text and success-message correction. Editing a released section is a deliberate exception to Keep-a-Changelog immutability — call it out in the commit body.

### TDD test plan
`cmd/configure_test.go` (exists; extend):
- `TestRunConfigurePrintsProfilePath` — table-driven with `t.Setenv`:
  - `{name: "honors IDSEC_PROFILES_FOLDER", env: "/tmp/custom", wantContains: "/tmp/custom/grant"}`
  - `{name: "default under HOME", env: "", home: t.TempDir(), wantContains: filepath.Join(home, ".idsec", "profiles", "grant")}`
  - `{name: "never mentions legacy path", wantNotContains: ".idsec_profiles"}`
  Use `NewConfigureCommandWithDeps` (`cmd/configure.go:46`) with a stub `profileSaver` (`cmd/interfaces.go:70-73`) and a `bytes.Buffer` via `cmd.SetOut`. `t.Setenv("HOME", ...)` is required because the SDK reads `HOME` directly.
- `TestConfigureLongHelpHasNoLegacyPath` — assert `NewConfigureCommand().Long` does not contain `.idsec_profiles`.

Both tests written first; they should fail against current `main`.

### Acceptance criteria
- `grep -rn 'idsec_profiles' --include='*.go' --include='*.md' .` returns zero hits outside `CHANGELOG.md`.
- `grant configure` prints a path that `grant login` actually reads.
- `make test`, `make lint`, `make build` pass.

### Branch / rollback
- Branch: `fix/stale-profile-paths`. Trivial single-commit revert; zero runtime risk.

### Verify sequence
```bash
make test && make lint && make build
grep -rn 'idsec_profiles' --include='*.go' --include='*.md' .
```

---

## Item 4 — GCP support

### Goal
Extend eligibility listing, elevation, status and revoke to GCP; scope `grant env` correctly.

### What the API says (verified against `Secure Cloud Access APIs.json` in the repo root)
- `GET /access/{csp}/eligibility` — `csp` enum includes `GCP`.
- `GET /access/sessions` — `csp` enum includes `GCP`.
- `POST /access/elevate` request `csp` enum: `["AWS","AZURE","GCP"]`.
- `ElevateAccessResult.csp` and `SessionInfo.csp` enums include `GCP`.
- `components.schemas.GCPEligibleTarget` — "A project that is part of a GCP organization"; requires `organizationId` and `workspaceType`, enum **`PROJECT` | `FOLDER` | `GCP_ORGANIZATION`**; otherwise `allOf` → `CommonEligibleTarget` (same `workspaceId`/`workspaceName`/role shape grant already parses).
- Elevate targets: "A maximum of 5 targets can be provided when requesting access to GCP folders or projects that are part of the same GCP organization" — grant only ever sends one target (`cmd/root.go:739-745`), so no change needed.
- **`accessCredentials`**: *"The credentials used to access the workspace once the elevation is successful… **Relevant only for specific cloud providers**."* The spec does not say GCP returns credentials, and there is no GCP credential schema anywhere in the spec.

SDK corroboration: `pkg/services/sca/models/idsec_sca_eligibility.go:13` `CSPGCP = "GCP"`, `:18` `ValidCloudAccessCSPs = []string{CSPAWS, CSPAzure, CSPGCP}`. The SDK's own comment at `:17`: *"GCP is supported here but not in k8s list-targets"*.

### Scope decision
**Ship list + elevate + status + revoke for GCP. Leave `grant env` AWS-only** until a real tenant proves otherwise. `cmd/env.go:98-100` already returns a clean error when `AccessCredentials == nil` — reword it to name AWS explicitly and mention GCP/Azure use their native CLI session. **Confirm against a live GCP-enabled tenant before merge**; if GCP *does* return `accessCredentials`, capture its shape and add `ParseGCPCredentials` alongside `ParseAWSCredentials` (`internal/sca/models/credentials.go:16-29`).

### Files to modify
| File:line | Change |
|---|---|
| `internal/sca/models/eligibility.go:9-12` | add `CSPGCP CSP = "GCP"` |
| `internal/sca/models/eligibility.go:17-24` | add `WorkspaceTypeProject = "PROJECT"`, `WorkspaceTypeFolder = "FOLDER"`, `WorkspaceTypeGCPOrganization = "GCP_ORGANIZATION"` |
| `cmd/root.go:266` | `supportedCSPs = []models.CSP{models.CSPAzure, models.CSPAWS, models.CSPGCP}` — propagates GCP to the fan-out (`:271-312`), provider validation (`:315-322`), `grant list`, and `grant status` via `cmd/helpers.go:50` |
| `cmd/root.go:111` | flag help `"Cloud provider: azure, aws, gcp (omit to show all)"` |
| `cmd/root.go:86-89` | update `--provider` examples in `Long` |
| `cmd/root.go:846-863` | add `case models.CSPGCP:` to the post-elevation guidance switch (wording pending tenant verification) |
| `cmd/env.go:32` | flag help |
| `cmd/env.go:17-26` | `Short`/`Long` — state `env` is AWS-only |
| `cmd/env.go:98-100` | reword the error; point Azure/GCP users at the native CLI |
| `cmd/list.go:69` | flag help |
| `cmd/status.go:244-253` | `parseProvider` — add `case "GCP"`; error string → `must be one of: azure, aws, gcp` |
| `internal/ui/selector.go:16-41` | verify GCP `workspaceType` values render sensibly |
| `cmd/request_submit.go:538-585` | `buildOnDemandRequest` — on-demand role discovery branches on Azure/AWS workspace types only (`DIRECTORY`→`azure_ad`, `ACCOUNT`→`aws`, `MANAGEMENT_GROUP`/`SUBSCRIPTION`/`RESOURCE_GROUP`/`RESOURCE`→`azure_resource`); **explicitly leave GCP out of scope** and return a clear "not supported for GCP" error rather than falling through silently. *(Corrects an earlier citation of `:467-470`, which is `buildRequestDetails`' `locationType` formatting, not the on-demand branching.)* |

Not changing: `internal/config/config.go:44` and `cmd/configure.go:124` keep `DefaultProvider: "azure"`.

### Bug 4a — `grant env` elevates *before* it validates the provider (fix this first)

Independent of GCP, and shipping today. In `runEnvWithDeps` (`cmd/env.go:81-99`):

```go
res, err := resolveAndElevate(...)   // :90  — performs a REAL elevation
...
recordSessionTimestamp(res.result.SessionID)
if res.result.AccessCredentials == nil {
    return errors.New("no credentials returned; grant env is only supported for AWS elevations")   // :99
}
```

The AWS-only guard is only reached **after** `resolveAndElevate` has already created a live session. So `grant env --provider azure` burns a real elevation, records a session timestamp, and *then* errors out — leaving the user with an active session they neither wanted nor were told about, which they must find via `grant status` and revoke by hand. GCP will make this worse (item 4 adds a third provider that returns no credentials), but the bug exists now with Azure.

**Fix:** validate the resolved provider **before** calling `resolveAndElevate`. Resolve the target CSP first (`resolveTargetCSP`, `cmd/root.go`), and if it is not AWS, return the error immediately with no API call. Keep the post-elevation `AccessCredentials == nil` check as a defence-in-depth fallback for the case where AWS itself returns nothing — but it must no longer be the primary gate.

Wording for the pre-flight error: name AWS explicitly and point Azure/GCP users at their native CLI session, per the `cmd/env.go:98-100` reword already listed above.

**Test (write first, must fail on current `main`):**
- `cmd/env_test.go` — `TestEnvDoesNotElevateForNonAWSProvider`: inject a mock `elevateService` whose `Elevate` increments a counter and fails the test if called. Run `grant env --provider azure` (and `gcp`). Assert: **elevation call count is exactly 0**, the returned error names AWS, and `recordSessionTimestamp` was not invoked (stub the injectable `recordSessionTimestamp` var per `cmd/session_tracking.go`).
- Keep a companion case asserting `--provider aws` still elevates exactly once.

This can land ahead of the rest of item 4 as its own small `fix/` commit; it is not GCP-dependent.

### TDD test plan
- `internal/sca/models/eligibility_test.go` — unmarshal a `GCPEligibleTarget` fixture; assert all fields including the `role`-vs-`roleInfo` fallback at `:44-63`.
- `internal/sca/service_test.go` — extend `httptest.NewServer` eligibility tests with `GET /api/access/GCP/eligibility`; assert route construction and `nextToken` pagination (`internal/sca/service.go:111-160`).
- `cmd/root_test.go` / `cmd/root_elevate_test.go`:
  - `fetchEligibility` with `provider: "gcp"` → queries `GCP` only;
  - `provider: ""` → fans out to three CSPs and merges; assert `CSP` field set per `:304-307`;
  - `provider: "oracle"` → error lists `azure, aws, gcp`;
  - one CSP erroring → other two still return (existing behavior `:299-308`).
- `cmd/status_test.go` — `parseProvider` gains `{"gcp", CSPGCP, false}`, `{"GCP", CSPGCP, false}`.
- `cmd/env_test.go` — `--provider gcp` errors **without elevating** (bug 4a); and, as defence-in-depth, an AWS elevation returning `accessCredentials: null` produces the reworded error, not a panic.
- `cmd/root_elevate_test.go` — GCP elevation success prints the GCP guidance line.

### Acceptance criteria
- `grant list --provider gcp`, `grant list` (merged), `grant --provider gcp`, `grant status`, `grant revoke` work against a GCP-enabled tenant.
- `grant env --provider gcp` (and `--provider azure`) fails with a clear, actionable message **and performs no elevation** — verify with `--verbose` that no `POST /api/access/elevate` is issued.
- `make test`, `make test-race`, `make lint`, `make build` pass.

### Manual testing (blocking — needs a GCP-enabled tenant)
1. `grant list --provider gcp --output json --verbose` — capture the raw `GCPEligibleTarget` shape; confirm `workspaceType` values match the spec enum.
2. `grant --provider gcp --verbose` — capture the full elevate response, **specifically whether `accessCredentials` is non-null and its JSON shape**. This decides whether Item 4 stays list/elevate-only or grows `grant env --provider gcp`.
3. `grant status` — confirm GCP sessions appear and workspace-name resolution (`cmd/helpers.go:136-160`) works.
4. `grant revoke` on a GCP session.
5. Record findings in `docs/` (mirroring `docs/entra-groups-api-findings.md`).

If no GCP tenant is available, **do not merge speculative GCP code** — park the branch and record the blocker.

### Docs
`CLAUDE.md` (endpoint notes, Multi-CSP bullet, `grant env` AWS-only), `README.md:101-142` and `:30-32`, `CHANGELOG.md` `[Unreleased] / ### Added`.

### Branch / rollback
- Branch: `feat/gcp-support`. Revert is clean; only shared-state change is one element in `supportedCSPs`. Risk of a broken GCP call degrading the merged path is mitigated by existing per-CSP failure skipping (`cmd/root.go:299-303`) — add a test pinning that for GCP.

### Verify sequence
```bash
make test && make test-race && make lint && make build
./grant list --provider gcp --output json --verbose
```

---

## Item 5 — `grant k8s` (Kubernetes / kubeconfig support)

### Goal
Let users generate a kubeconfig and obtain kubectl credentials for SCA-eligible clusters, matching grant's existing UX (interactive selector, TTY detection with `ErrNotInteractive`, `--output json`, cache, `--refresh`).

### CRITICAL — dependency impact (measured, not estimated)

Importing `github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s` adds **16 modules** to grant's build graph, measured by diffing `go list -deps` of the SDK's `k8s` package against grant's current module set:

```
github.com/Azure/azure-sdk-for-go/sdk/azcore
github.com/Azure/azure-sdk-for-go/sdk/azidentity
github.com/Azure/azure-sdk-for-go/sdk/internal
github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2
github.com/AzureAD/microsoft-authentication-library-for-go
github.com/aws/aws-sdk-go-v2
github.com/aws/aws-sdk-go-v2/credentials
github.com/aws/aws-sdk-go-v2/internal/configsources
github.com/aws/aws-sdk-go-v2/internal/endpoints/v2
github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding
github.com/aws/aws-sdk-go-v2/service/internal/presigned-url
github.com/aws/aws-sdk-go-v2/service/sts
github.com/aws/smithy-go
github.com/go-jose/go-jose/v4
github.com/kylelemons/godebug
github.com/pkg/browser
```

These are in the *SDK's* `go.mod` but not currently in grant's build graph, and they will materially grow the binary. `pkg/services/sca/k8s/models` and `.../k8s/actions` are clean — only the root `k8s` package is contaminated, and it is a single Go package, so the import is all-or-nothing.

This is in tension with the CLAUDE.md *goal* of "zero new Go module deps" — a goal, not a hard rule. **D-4 is DECIDED: accept the +16 modules (option 5B).** The reasoning and the accepted costs are in "D-4 — DECIDED: 5B" below.

### The partial escape hatch (verified) — and why it is not enough

It is worth recording precisely what a zero-new-modules implementation *could* have covered, because it defines the boundary between the SDK-backed layer and the layer grant still owns.

The heavy dependencies exist only for the **credential/token providers**. The **control-plane** endpoints are plain HTTP against ISP clients grant already builds:

| Capability | Route | Client | Notes (SDK source) |
|---|---|---|---|
| List eligible clusters | `GET access/<CSP>/eligibility/clusters` | `sca` | `idsec_sca_k8s_service.go:23`, impl `:202-241`. Paginates via `nextToken` — grant's generic `paginate[T]` (`internal/sca/service.go:111-160`) already handles this correctly across all pages |
| Evaluate connection method | `POST access/<CSP>/eligibility/clusters/evaluate` | `sca` | `:26`, `:256-320` |
| Elevate for a cluster | `POST access/elevate/clusters` | `sca` | `:29`, `:326-393` |
| **Generate kubeconfig** | `GET k8s/kube-config[/<AWS\|azure_resource>]` | **`dpa`** | `:33`, `:634-691`. Segment mapping at `:693-701`: azure → `azure_resource`, aws → `AWS` (uppercase) |

Mechanics, corrected against the SDK source (three claims in the earlier draft were wrong or overstated):

1. **`X-CLI-Signature` header** — required on evaluate, elevate and generate-kubeconfig. Specified in `pkg/services/sca/k8s/idsec_sca_k8s_cli_signature.go:18-49`:
   `Base64(HMAC-SHA256(key = ISP access token, msg = floor(unixUTC/5) + "|" + "/" + apiRelativePath))`, set per-request and removed afterwards (`:51-62`). `crypto/hmac` + `crypto/sha256` + `encoding/base64` — no dependency. Token available via `client.GetToken()`.
   **Correction:** **list-clusters does NOT send it.** `listTargetsForCSP` (`idsec_sca_k8s_service.go:202-241`) calls `s.ISPClient().Get(...)` directly — the signature helpers are used only at `:285` (evaluate), `:363` (elevate) and `:670` (generate-kubeconfig). Any test asserting `X-CLI-Signature` on the list-clusters request is asserting behavior that does not exist; **remove that assertion** from the test plan.
2. **`Content-Type` removal on GETs — not needed.** The SDK does `RemoveHeader("Content-Type")` / `SetHeader` around its GETs (`:216-218`, `:668-670`), but that is redundant belt-and-braces: `common.IdsecClient.doRequest` already skips the header when there is no body — `if strings.EqualFold(key, "Content-Type") && bodyReader == nil { continue }` (`idsec_client.go:~799`). grant must **not** replicate the remove/restore dance; it is exactly the client-wide-mutable-state hazard flagged in Item 1, for no benefit.
3. **Caller context — partially propagated, not universally discarded.** The earlier "every SDK k8s method discards the caller's context" is overbroad. `GenerateKubeconfigParallel(ctx context.Context, csps []string, kubeconfigLocation string)` (`idsec_sca_k8s_service.go:528`) **does** accept a `ctx`. What is true is that the *underlying* per-request calls still use `context.Background()` internally (e.g. `:218`), so the accepted context does not reach the HTTP layer. Net effect on grant: where the SDK accepts a context, pass grant's `apiTimeout` context through; where it does not, wrap the call in grant's own timeout/cancellation at the command layer and note the limitation. Worth filing upstream.

The **DPA** ISP client is `isp.FromISPAuth(ispAuth, "dpa", ".", "api", refreshCb, nil)` — the same call grant already makes for `"sca"` (`internal/sca/service.go:59`) and `"uar"` (`internal/workflows/service.go:55`). Under 5B the SDK builds this itself; the note is retained because grant's own DPA-adjacent code may still need it.

#### Why the escape hatch cannot ship the product

The zero-new-modules approach covers **only the control plane** — list, evaluate, elevate, generate-kubeconfig. It does **not** deliver the exec-credential flow, which is the thing that makes `kubectl` actually work:

- **Direct connection method, AWS** — needs an STS presigned identity token. `idsec_sca_k8s_aws_token.go` imports `github.com/aws/aws-sdk-go-v2/aws`, `.../credentials`, `.../service/sts`.
- **Direct connection method, Azure** — needs an AAD token via Azure CLI credential. `idsec_sca_k8s_azure_token.go` and `idsec_sca_k8s_azure_role_propagation.go` import `github.com/Azure/azure-sdk-for-go/sdk/azidentity`.
- **Proxy connection method** — needs **JWE** decryption of the DPA-issued credential. `idsec_sca_k8s_proxy_creds_helper.go` imports `github.com/go-jose/go-jose/v4`.

So option 5A as originally written **could not ship `grant k8s exec-credential` at all**, for either connection method. It would have delivered `list`, `elevate` and a kubeconfig that `kubectl` cannot authenticate with — a non-product. That is why 5A was rejected outright rather than deferred.

### D-4 — DECIDED: 5B (import the SDK `pkg/services/sca/k8s`)

**Chosen: 5B.** grant imports the SDK's k8s package and accepts the +16 modules. This makes item 5 implementation-ready: the exec-credential flow, AWS IdC device auth, the Azure AKS path and `WaitForAzureRolePropagation` all come from the SDK rather than being reimplemented.

Rejected alternatives, kept as a record:
- **5A — own `internal/k8s`, zero new modules.** Rejected: cannot deliver exec-credential for either connection method (see above), so it ships a kubeconfig `kubectl` cannot use.
- **5C — hybrid (5A now, SDK later).** Rejected for the same reason: the "later" is not an optional enhancement, it is the feature. Building the control plane by hand first would mean writing a transport + signature layer that 5B then deletes.

**Accepted costs — carry these into the docs and the release notes, do not soften them:**
- **~2-3× binary size increase.** Measure it before and after and record the actual numbers in `CHANGELOG.md`.
- **Materially enlarged CVE surface.** The Azure and AWS SDKs are frequent advisory subjects. This is in direct tension with Item 2, which exists to *shrink* the vulnerability surface — the two items pull in opposite directions and that is a deliberate, eyes-open trade. **Mitigation: track Azure/AWS SDK advisories explicitly** — keep `govulncheck ./...` in the verify sequence for every item, and record a baseline finding count at merge so regressions are visible. Consider a scheduled `govulncheck` CI job, since these modules will now generate advisory traffic that grant did not previously see.
- **Azure still requires the Azure CLI installed and logged in.** The SDK uses `azidentity.NewAzureCLICredential` (`idsec_sca_k8s_azure_token.go:142`, `idsec_sca_k8s_azure_role_propagation.go:141`). **Do not market this as "no Azure CLI needed"** — document `az login` as a prerequisite for the Azure path in `README.md`, and produce a clear error (not an opaque azidentity failure) when it is missing.
- **CLAUDE.md must be updated** to record that the zero-new-deps *goal* was consciously traded here, with the reason — not silently violated.

What grant still owns under 5B: the entire UI/UX layer — selector, TTY detection, cache decorator, `--output json`, `--refresh`, command wiring, kubeconfig write/merge semantics, and context propagation wherever the SDK accepts a `ctx`.

### D-5 — DECIDED: `grant k8s <sub>`

**Chosen: `grant k8s <sub>`** over a top-level `grant kubeconfig`:
- grant already establishes a noun-first subcommand group with `grant request <sub>` (`cmd/request.go`, registered at `cmd/commands.go:15`).
- The feature is inherently multi-verb (`list`, `kubeconfig`, `elevate`, and protocol-mandated `exec-credential`).
- `grant kubeconfig` can be a hidden alias if discoverability testing suggests it.

```
grant k8s list                       # eligible clusters; --provider, --refresh, --output json
grant k8s kubeconfig                 # generate + merge/write kubeconfig; --provider, --all, --output <path>, --stdout
grant k8s elevate [cluster]          # elevate for a cluster; interactive selector when omitted in a TTY
grant k8s exec-credential            # hidden; kubectl exec-credential plugin protocol (stdout JSON only)
```

`exec-credential` **must** be `Hidden: true` and write *nothing* to stdout except the `ExecCredential` JSON — same discipline as `grant env` (`cmd/env.go:18-21`).

### Reference implementations to study (do NOT import — separate Go module)
`github.com/cyberark/idsec-cli-golang`, `pkg/services/sca/k8s/actions/`:
- `idsec_kubectl_login_action.go` — the exec-credential contract end to end.
- `idsec_kubectl_login_creds_cache.go` — credential caching and the expiry buffer.
- `idsec_generate_kubeconfig_action.go` — how the CLI writes/merges the kubeconfig, and what `exec.command` the generated kubeconfig embeds.

SDK exec-credential shape: `pkg/services/sca/k8s/models/idsec_sca_k8s_exec_credential.go:14-29` — `{apiVersion, kind: "ExecCredential", status: {token | clientCertificateData + clientKeyData, expirationTimestamp}}`. Expiry buffering is applied once, where the raw DPA expiry is known (`idsec_sca_k8s_service.go:~503`, `expiresAt.Add(-proxyExecCredRefreshBuffer)`) — mirror that "bake it in once, never re-apply downstream" rule.

**Open risk R-5a:** the DPA-generated kubeconfig almost certainly embeds `users[].user.exec.command` pointing at the *official* CLI binary (`idsec`/`ark`), not `grant`. grant will need to rewrite those exec stanzas to `grant k8s exec-credential` after fetching. Confirm against a real tenant before finalizing design — it changes whether `grant k8s kubeconfig` is a thin passthrough or a rewriting transform.

### Kubeconfig security and write semantics (must be decided before implementation)

Writing a kubeconfig is a security-relevant filesystem operation, not a convenience. Pin all of the following:

- **File permissions.** The kubeconfig may embed bearer tokens or client key material (`clientKeyData` in the ExecCredential shape). Write with mode **`0600`**, and create any parent directory `0700`. When the target file already exists, do **not** widen its mode; if it is already world- or group-readable, warn loudly rather than silently writing secrets into it.
- **Merge vs. overwrite — default to merge, never clobber.** The default target is `$KUBECONFIG` (first entry if it is a list) or `~/.kube/config`, which typically already contains the user's other clusters. Destroying that file is unacceptable. Default behavior: **merge** — add/replace only the `clusters`, `users` and `contexts` entries whose names grant owns, leaving every other entry byte-identical.
- **What happens to existing contexts.** Entries grant does not own are preserved untouched. Entries with a colliding name are **replaced**, and the replacement is reported on stderr. `current-context` is **not** changed unless the user passes an explicit opt-in flag — silently repointing `kubectl` at a different cluster is a foot-gun with production consequences.
- **Naming.** Prefix grant-owned entry names deterministically (e.g. `grant-<csp>-<cluster>`) so ownership is decidable on the next merge without extra state.
- **Atomic write.** Write to a temp file **in the same directory**, `fsync`, then `os.Rename` over the target. Never truncate-in-place: an interrupted write must not leave the user with a corrupt `~/.kube/config`.
- **Escape hatches.** `--stdout` writes the generated YAML to stdout and touches no file. `--output <path>` targets an explicit file. An `--overwrite` flag may exist but must never be the default.
- **Backup.** On the first merge into a pre-existing file, write a `<target>.grant.bak` once, and say so.

### Files to create (under the decided option 5B)
```
internal/k8s/service.go            # thin wrapper over the SDK's sca/k8s service: DI seam, context
                                   #   propagation where the SDK accepts a ctx, grant-shaped errors
internal/k8s/service_test.go
internal/k8s/kubeconfig.go         # merge + atomic 0600 write + exec-stanza rewrite (R-5a)
internal/k8s/kubeconfig_test.go
internal/k8s/execcred_cache.go     # credential cache: 0600 file, buffered expiry, injectable clock
internal/k8s/execcred_cache_test.go
internal/ui/cluster_selector.go    # Format/Build/Find/Select quartet, mirrors internal/ui/selector.go:16-80
internal/ui/cluster_selector_test.go
internal/cache/cached_clusters.go  # decorator, mirrors internal/cache/cached_eligibility.go
internal/cache/cached_clusters_test.go
cmd/k8s.go                         # parent command
cmd/k8s_list.go / cmd/k8s_kubeconfig.go / cmd/k8s_elevate.go / cmd/k8s_exec_credential.go
cmd/k8s_*_test.go
```

**Deleted from the 5A plan** (now supplied by the SDK, do not build): `internal/k8s/signature.go` + tests (the `X-CLI-Signature` implementation), `internal/k8s/service_config.go`, `internal/k8s/logging_client.go`, and the whole `internal/k8s/models/` tree — use `pkg/services/sca/k8s/models` types, re-exported behind grant-owned aliases only where a command signature would otherwise leak SDK types (the same discipline applied to `selfUpdater` in Item 2).

Modify: `cmd/commands.go` (register `NewK8sCommand()`), `cmd/interfaces.go` (new `clusterLister`, `kubeconfigGenerator`, `clusterElevator`, `clusterSelector` — defined over grant-owned or SDK model types, with mocks in `cmd/test_mocks.go`), `cmd/output_types.go` (`clusterOutput`, `kubeconfigOutput`), `cmd/root.go` (`bootstrapK8sService()` alongside `bootstrapSCAService()` at `:177-189`), `go.mod` (+16 modules — record the measured binary-size delta).

### TDD test plan

The transport-layer and signature tests from the 5A draft are **gone** — that code is now the SDK's and testing it in grant only tests a mock. Note in particular: do **not** write an assertion that list-clusters carries `X-CLI-Signature` (it does not — see the corrections above), and do not test for `Content-Type` removal on GETs (the common client already omits it when the body is nil).

- `internal/k8s/service_test.go` — the wrapper only: SDK errors are wrapped with grant-shaped messages; a cancelled context aborts where the SDK accepts a `ctx` (`GenerateKubeconfigParallel`), and the documented limitation is asserted where it does not.
- **`internal/k8s/kubeconfig_test.go`** — merge and atomic-write semantics, written first:
  - merging into an existing kubeconfig preserves every non-grant `clusters`/`users`/`contexts` entry **byte-identically**;
  - a colliding grant-owned entry is replaced, not duplicated;
  - `current-context` is unchanged by default, and changed only with the explicit opt-in flag;
  - target file mode is `0600` on create; an existing narrower mode is not widened; an existing world-readable target produces a warning;
  - the temp file is created in the **same directory** as the target (same-filesystem rename);
  - an injected failure between write and rename leaves the original file untouched and complete (no truncation);
  - empty/absent target file, and a `$KUBECONFIG` list where only the first entry is written;
  - `--stdout` writes nothing to disk;
  - exec-stanza rewrite (R-5a): `users[].user.exec.command` is rewritten to grant's own absolute path with `k8s exec-credential` args.
- `internal/ui/cluster_selector_test.go` — `FormatClusterOption` table; `ErrNotInteractive` when `ui.IsTerminalFunc` is stubbed false (`internal/ui/tty.go:12-23`).
- `cmd/k8s_*_test.go` — table-driven over injected mocks: `--output json` shape; `--provider` validation; non-TTY without a cluster arg → `ErrNotInteractive` with a hint to run `grant k8s list`; `--refresh` bypasses cache.
- **`cmd/k8s_exec_credential_test.go`** — the kubectl plugin contract is unforgiving; cover all of:
  - stdout is **exactly** the ExecCredential JSON and nothing else (no log lines, no trailing text, verbose output goes to stderr);
  - **apiVersion / version negotiation** — kubectl passes the requested apiVersion via the `KUBERNETES_EXEC_INFO` env var, and the response `apiVersion` **must echo the request**. Table over `client.authentication.k8s.io/v1beta1` and `/v1`; an unrecognised or absent apiVersion produces a clear error rather than a silently-wrong response. Assert grant never hardcodes one version into the output;
  - **`interactiveMode`** — the `ExecConfig.interactiveMode` / `KUBERNETES_EXEC_INFO.spec.interactive` signal decides whether an interactive device-code or browser flow is permissible. When kubectl says stdin is not available, grant must **not** attempt an interactive flow and must fail with an actionable message. Cases: interactive-allowed + cache miss → flow attempted; interactive-forbidden + cache miss → clean error; interactive-forbidden + cache hit → success;
  - **clock skew** — expiry decisions use a single injected clock. Cases: a credential whose expiry is in the past by less than the refresh buffer is treated as expired; a credential with an expiry *ahead* of local time (server/client skew) is not cached indefinitely; a malformed or absent `expirationTimestamp` is treated as non-cacheable rather than eternal. Assert the buffer is applied **once**, at the point the raw DPA expiry is known (`idsec_sca_k8s_service.go:~503`), and never re-applied downstream;
  - **cache file permissions** — the credential cache holds live bearer tokens. Assert the cache file is created `0600` and its directory `0700`; that a pre-existing cache file with looser permissions is either refused or re-secured (decide which, and test it); and that cached credentials are reused until buffered expiry and re-fetched after (injectable clock, per `internal/cache/cache.go`).
- Integration (`//go:build integration`): `grant k8s --help`, `grant k8s list --output json` against a stub — no network.

### Acceptance criteria
- `grant k8s list` matches `grant list`'s look and JSON conventions.
- `grant k8s kubeconfig` writes a kubeconfig `kubectl get ns` can actually use, **merged** into a pre-existing config without disturbing the user's other contexts, at mode `0600`.
- `grant k8s exec-credential` satisfies kubectl's plugin protocol (validated by kubectl actually invoking it), for both `direct` and `proxy` connection methods.
- Under 5B: `go list -deps` grows by exactly the 16 modules enumerated above and no others. **Record the measured binary-size delta** in the PR description and `CHANGELOG.md`.
- `make test`, `make test-race`, `make lint`, `make build` pass. `govulncheck ./...` findings **will** increase — record the new baseline explicitly and justify each new finding, rather than treating "no increase" as the criterion.

### Manual testing (blocking — real tenant with SCA K8s entitlements)
1. `grant k8s list --verbose` — confirm eligible clusters exist.
2. Capture a real `generate-kubeconfig` response and **inspect the embedded `exec.command`** (risk R-5a).
3. Run `EvaluateEligibility` and record the `direct`/`proxy` split — no longer a go/no-go for 5A vs 5B (5B is decided), but it determines which exec-credential path gets the most testing.
4. Full `kubectl` round-trip with the generated kubeconfig, against a **pre-existing** `~/.kube/config` containing unrelated contexts — confirm they survive and `current-context` is unchanged.
5. Azure path: confirm `az login` behavior in practice, and that a missing/logged-out Azure CLI produces grant's clear error rather than a raw azidentity failure.
6. Interrupt `grant k8s kubeconfig` mid-write (Ctrl-C) and confirm `~/.kube/config` is intact.

### Docs
`CLAUDE.md` (new `## SCA K8s API` section with routes, the D-4 outcome **and its accepted costs**, the `az login` prerequisite, and the kubeconfig write/merge/permissions semantics), `README.md` (new command section + Flags table + Azure CLI prerequisite), `CHANGELOG.md` (including the binary-size delta and the new dependency set).

### Branch / rollback
- Branch: `feat/k8s-kubeconfig`. Entirely additive; revert is clean. Shared-file edits limited to `cmd/commands.go`, `cmd/interfaces.go`, `cmd/output_types.go`.
- Largest item by far. **Split into two PRs** — (a) SDK wiring + `grant k8s list` + `grant k8s elevate` (this is where the +16 modules and the binary-size hit land, so they get reviewed on their own), (b) `kubeconfig` merge/write + `exec-credential` — so the service layer is exercised before the kubectl-protocol and filesystem surfaces.

### Verify sequence
```bash
make test && make test-race && make lint && make build
go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./... | sort -u   # expect exactly the 16 listed modules added
ls -l ./grant                                                              # record binary size before/after
govulncheck ./...                                                          # expect an increase; record the new baseline
```

### PAUSED — updated 2026-08-14 (PR #55, branch `feat/k8s-clusters`, head `633a5ba`)

**PR #55 is still a draft and must not ship**: nothing has been validated against a real Kubernetes tenant. But both blockers recorded on 2026-08-13 are now addressed, and the branch is rebased onto post-v0.9.0 `main` (`f14e2b9`), so CI runs on it — both the `ubuntu-latest` and `windows-latest` legs are green at `633a5ba`.

Blocker status:

1. **stdout contamination in `exec-credential` — reduced, not eliminated.** `cmd/stdout_guard.go` takes the boundary rather than the writers: it dups the descriptor behind stdout, re-points it at stderr, sets `os.Stdout = os.Stderr`, and writes the `ExecCredential` JSON to the saved descriptor. The guard is installed **before Cobra's pre-run** — installing it inside `RunE` was too late, because `PersistentPreRunE` emits the `--verbose` WSL keyring notice through an SDK logger built on `os.Stdout`. **Residual gap:** writers that captured `os.Stdout` at init (`pkg/browser`'s `Stdout` var, grant's own `log` var) are uncontained on Windows, where a handle cannot be re-pointed and `SetStdHandle` does not affect an already-built `*os.File`. This is not platform parity.
2. **Windows symlink checks — fixed and CI-verified.** `openNoFollowRead` is `O_NOFOLLOW` on POSIX and `CreateFile` with `FILE_FLAG_OPEN_REPARSE_POINT` plus a reparse-attribute check on Windows, so links, junctions and mount points are refused with no TOCTOU window. It uses `golang.org/x/sys/windows`, already in the Windows build graph, so no module was added. The symlink tests no longer skip on Windows — `TestOpenNoFollowRead{RefusesSymlink,OpensRegularFile,ReportsMissingFile}` all **run and pass** on the `windows-latest` leg.

The three lower-severity items (first-use false security warning, partial-backup integrity in `BackupOnce`, error swallowing in `readEntry`) and the stale `--fqdn` hint are all fixed. Two POSIX-mode tests that were *failing* rather than skipping on Windows are now platform-qualified and confirmed correct on the Windows leg.

**Known gap, deliberately open:** `checkPrivateToCurrentUser` is a no-op on Windows, so the credential cache's ownership checks do not run there; confidentiality rests on the default `%USERPROFILE%` ACLs.

To resume, re-verify in this order:

1. Confirm the stdout boundary end to end — a real WSL `grant --verbose k8s exec-credential`, plus init-time `os.Stdout` capturers on Windows where layer 2 does not apply.
2. Run the complete Windows CI suite against the head being resumed from, rather than assuming from the Linux run.
3. Exercise the DPA-generated kubeconfig shape and the `exec.command` rewrite against a real tenant.
4. Run an actual `kubectl` round-trip for both the direct and proxy paths, including AWS IdC and the Azure CLI identity binding.
5. Validate Windows cache ACL ownership and privacy before treating cached credentials there as equivalently protected to POSIX.

The SDK token providers (AWS STS presign, Azure CLI, DPA JWE) sit behind an injected seam and have never executed. Full handoff, with file:line references for every finding, is the pinned comment on PR #55.

---

## Decisions

> **Standing framing correction:** *"zero new Go module deps" in CLAUDE.md is a **goal**, not a hard rule.* New modules are acceptable when the reason is stated and the cost is measured. Wording elsewhere in this plan and in CLAUDE.md that treats it as an absolute constraint should be corrected to match. D-2 and D-4 are both deliberate, justified departures from the goal.

### Resolved

| ID | Decision | Outcome | Rejected options (kept as record) |
|---|---|---|---|
| **D-1** | Item 1 outcome | **DECIDED — (c) disable transient retry everywhere**, on both the SCA and UAR ISP clients. Implementation launched on this basis. | (a) document as safe, no code change — leaves the bare-`EOF`-on-POST replay path live. (b) UAR only — rejected: `SetTransientRetry` is client-wide state with no per-request override, mid-flight toggling races against grant's concurrent multi-CSP fan-out, and SCA's elevate/group-elevate are equally non-idempotent. |
| **D-2** | Item 2 replacement strategy | **DECIDED — (b) `minio/selfupdate` for apply/rollback, +1 module (`aead.dev/minisign`).** In-house GitHub release discovery, asset selection, version comparison and checksum verification; `minio/selfupdate` owns atomic replace, rollback and the Windows path. Net ≈ −10 modules and GO-2026-5932 removed. Also pulls `golang.org/x/sys` (and `x/term`) through minisign — all already in grant's graph, so still +1 net. | (a) fully in-house, zero new modules — demoted to a documented alternative: production-safe apply/rollback (symlinks, fsync, concurrent updates, Windows locks/AV, rollback-of-rollback, archive bombs) is far more than the "~250 lines" first estimated, on the one code path whose failure mode is a destroyed user binary. (c) `creativeprojects/go-selfupdate` — **rejected: still imports `x/crypto/openpgp`, so it does not fix GO-2026-5932, and adds Gitea + GitLab + go-github/v86 + hashicorp transitives.** |
| **D-4** | **Item 5 dependency policy.** Importing the SDK k8s package adds **16 modules** | **DECIDED — (b) 5B: import `pkg/services/sca/k8s`, accept the +16 modules.** This resolves the credential-architecture question: exec-credential, AWS IdC device auth and the Azure AKS path all come from the SDK, making item 5 implementation-ready. Accepted costs: ~2-3× binary size, enlarged CVE surface (track Azure/AWS SDK advisories; direct tension with Item 2), and **Azure still requires Azure CLI installed and logged in**. | (a) 5A own `internal/k8s`, zero new deps — **rejected: covers only the control plane.** Direct AWS needs `aws-sdk-go-v2/sts`, direct Azure needs `azidentity`, proxy needs JWE via `go-jose` — so 5A cannot ship `grant k8s exec-credential` at all and would produce a kubeconfig `kubectl` cannot authenticate with. (c) 5C hybrid — rejected: the deferred half is the feature, and the hand-built transport/signature layer would immediately be deleted. |
| **D-5** | Item 5 command shape | **DECIDED — (a) `grant k8s <sub>`**: `list`, `kubeconfig`, `elevate`, `exec-credential` (hidden, stdout JSON only). Matches `grant request <sub>`. | (b) top-level `grant kubeconfig` — single-verb shape does not fit a four-verb feature. (c) both, with a hidden alias — may still be added later if discoverability testing suggests it; not needed now. |

### Still open

| ID | Decision | Options | Default if no answer |
|---|---|---|---|
| **D-3** | Retroactive CHANGELOG edit to the released `[0.7.0]` section | (a) **yes, add migration note** (recommended); (b) `[Unreleased]` only | (a) |
| **D-6** | Item 4 scope if no GCP tenant is available | (a) **park the branch** (recommended); (b) merge behind an undocumented flag | (a) |
| **D-7** | Item 2 — should `grant update` gain checksum verification (behavior change vs today's unverified download)? | (a) **yes** (recommended; comes free under the decided D-2b); (b) preserve current behavior. Note the trust-model section: checksums detect corruption and wrong-asset errors, **not** a compromised release — document accordingly | (a) |
| **D-8** | **New:** add `windows-latest` to the GitHub Actions test matrix for the self-update path | (a) **yes** (recommended — an injected `renameFn` stub does not exercise live-image replacement, `os.Remove` on a running binary, or AV interference); (b) no, and make the manual Windows step blocking for every release touching `internal/selfupdate` | (a) |

## Items needing authenticated manual testing against a real tenant

Use the `/grant-login` skill (`.claude/skills/grant-login/SKILL.md`, credentials in `.env`).

Listed in execution order (3 → 1 → 2 → 4 → 5).

1. **Item 3** — `configure` → `login` round-trip (light).
2. **Item 1** — smoke-test elevate and `request submit` on SDK v0.8.1 (non-blocking).
3. **Item 2** — full `grant update` matrix on Linux/macOS/Windows real binaries (**blocking**, unless D-8a adds a Windows CI runner, which downgrades the Windows leg to a spot check).
4. **Item 4** — GCP eligibility shape and **whether GCP elevation returns `accessCredentials`** (**blocking**). Bug 4a (`grant env` elevating before validating the provider) needs no tenant beyond confirming no session is created.
5. **Item 5** — cluster eligibility, the generated kubeconfig's embedded `exec.command`, the direct/proxy split, a real `kubectl` round-trip against a **pre-existing** `~/.kube/config`, and the Azure `az login` prerequisite (**blocking**).

## Documentation obligations (per CLAUDE.md, every item)

- **CLAUDE.md** — SDK retry semantics + the both-clients opt-out, plus the "`SetTransientRetry` is client-wide state, never toggle per-request" rule (1); self-update implementation (`minio/selfupdate`), the trust model ("integrity-checked, not signed"), interrupted-update recovery, and the dependency justification (2); profile path + Windows `HOME` caveat (3); GCP in Multi-CSP and endpoint notes, `grant env` AWS-only **and validated before elevating** (4); new `## SCA K8s API` section with the D-4 outcome, its accepted costs, the `az login` prerequisite, and kubeconfig write/merge/permission semantics (5).
- **Also correct in CLAUDE.md:** reword the "zero new Go module deps" line as a **goal** rather than an absolute constraint, and record the two justified departures (D-2, D-4).
- **CHANGELOG.md** — `[Unreleased]` for all five, plus the retroactive `[0.7.0]` migration note (item 3). Item 5's entry must include the measured binary-size delta and the new dependency set.
- **README.md** — self-update section, with honest integrity-vs-authenticity wording (2); provider values and `grant env` scoping (4); new `grant k8s` command section + Flags table + Azure CLI prerequisite (5).
- Commits: conventional, branch prefixes `chore/` (1), `fix/` (2, 3, bug 4a), `feat/` (4, 5).
