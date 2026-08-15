# Mutation ledger

This is the definition of done for the test-remediation effort. Every row is one
mutation that a five-part adversarial mutation audit applied to production code
and that the test suite failed to notice — plus the rows the verifiers **refuted**,
which are recorded here precisely so nobody re-opens a settled question.

**How a row is closed.**

1. Apply the mutation in the **Mutation** cell verbatim at the **File:line** shown.
2. Run the test named in **Planned test** and watch it **fail**.
3. Revert the mutation.
4. Run the same test and watch it **pass**.
5. Always `-count=1`. A cached success is not evidence.

Then flip **Status** to `done`. **A PR is not complete until every one of its rows
is `done`.** `wont-fix` and `refuted` rows are closed by review, not by a test;
mark them `done` when the PR that owns them has landed the comment / rationale.

**Line numbers are relative to this branch's tree**, not to `main`. They were first
re-verified against `main` post-`f14e2b9`; the nine `cmd/favorites.go` rows were then
shifted by +13 for the non-interactive guard this branch inserts at
`cmd/favorites.go:148`. Several also drifted from the source reports; those corrections
are noted in the Mutation cell with `(was ...)`. **File:line is always the production
site, never the test site.**

**Verdicts** are the verifiers' conclusions, not the original reports':
`CONFIRMED` (survivor reproduced), `OVERSTATED` (survivor real, stated consequence
weaker than claimed), `REFUTED` (the claim is false — the mutant dies, or the
premise does not hold).

---

## Ledger

| ID | Area | File:line | Mutation (exact, applyable) | Verdict | Disposition | Planned test | PR | Status |
|---|---|---|---|---|---|---|---|---|
| REQ-01 | cmd/request finalize | `cmd/request_finalize.go:100` | `svc.FinalizeRequest(ctx, requestID, decision, reason)` → `svc.FinalizeRequest(ctx, requestID, "APPROVED", reason)` | CONFIRMED | test | `TestRequestReject_SendsRejectedDecision` | PR4 | todo |
| REQ-02 | cmd/request cancel | `cmd/request_cancel.go:60` | `svc.CancelRequest(ctx, requestID, reason)` → `svc.CancelRequest(ctx, "WRONG-ID", reason)` | CONFIRMED | test | `TestRequestCancel_PassesRequestID` | PR4 | todo |
| REQ-03 | cmd/request get | `cmd/request_get.go:53` | `svc.GetRequest(ctx, requestID)` → `svc.GetRequest(ctx, "WRONG-ID")` | CONFIRMED | test | `TestRequestGet_PassesRequestID` | PR4 | todo |
| REQ-04 | cmd/request list | `cmd/request_list.go:93-98` | Swap the asc/desc branches: `order := "asc"` → `order := "desc"` and `order = "desc"` → `order = "asc"` | CONFIRMED | test | `TestRequestList_SortDirection` | PR4 | todo |
| REQ-05 | cmd/request list | `cmd/request_list.go:82` | `if role != "CREATOR" && role != "APPROVER" {` → `if false {` | CONFIRMED | test | `TestRequestList_RejectsInvalidRole` | PR4 | todo |
| REQ-06 | cmd/request list | `cmd/request_list.go:78` | `params.FreeText = v` → `params.FreeText = ""` | CONFIRMED | test | `TestRequestList_PassesFreeText` | PR4 | todo |
| REQ-07 | cmd/request list | `cmd/request_list.go:58` | Delete `filters = append(filters, fmt.Sprintf("(requestState eq %s)", upper))` | CONFIRMED | test | `TestRequestList_PassesStateFilter` | PR4 | todo |
| REQ-08 | cmd/request submit | `cmd/request_submit.go:306` | `TargetCategory: "CLOUD_CONSOLE"` → `TargetCategory: "WRONG"` | CONFIRMED | test | `TestRunRequestSubmit_SubmitPayload` | PR4 | todo |
| REQ-09 | cmd/request submit | `cmd/request_submit.go:507` | `"workspaceId": ws.WorkspaceID,` → `"workspaceId": "",` | CONFIRMED | test | `TestRunRequestSubmit_SubmitPayload` | PR4 | todo |
| REQ-10 | cmd/request submit | `cmd/request_submit.go:511-512` | Swap the two values: `"timeFrom": f.timeTo,` / `"timeTo": f.timeFrom,` | CONFIRMED | test | `TestRunRequestSubmit_SubmitPayload` | PR4 | todo |
| REQ-11 | cmd/request submit | `cmd/request_submit.go:274` | Delete the `if err := validateSubmitFields(fields); err != nil { return err }` call site | CONFIRMED | test | `TestRunRequestSubmit_InvokesValidation` | PR4 | todo |
| REQ-12 | cmd/request submit | `cmd/request_submit.go:631` | `return errors.New("--date is required")` → `return errors.New("WRONG ERROR MESSAGE")` | CONFIRMED | test | `TestValidateSubmitFields_ErrorMessages` | PR4 | todo |
| REQ-13 | cmd/request get | `cmd/request_picker.go:15` (reached from `cmd/request_get.go`) | In the `get` path, disable the guard: `if requestID == "" && !ui.IsInteractive() {` → `if false {`, keeping `_ = requestID` so it compiles | CONFIRMED | test | `TestRequestGet_NonInteractiveRequiresID` | PR4 | todo |
| REQ-14 | cmd/request approve | `cmd/request_finalize.go:16` | Disable the early non-interactive guard for `approve` (`if false {`), preserving `_ = requestID` — a literal deletion does not compile (`declared and not used: requestID`) | CONFIRMED | test | `TestRequestApprove_NonInteractiveRequiresID` | PR4 | todo |
| REQ-15 | cmd/request reject | `cmd/request_finalize.go:16` | Same as REQ-14 for the `reject` path, with `_ = requestID` | CONFIRMED | test | `TestRequestReject_NonInteractiveRequiresID` | PR4 | todo |
| REQ-16 | cmd/request submit | `cmd/request_submit.go:377` | `if ws.CSP == models.CSPGCP {` → `if false {` inside `rejectGCPWorkspace`. The fixture sets both `WorkspaceType: WorkspaceTypeProject` and `CSP: CSPGCP`, so the workspace-type switch masks loss of the CSP arm | CONFIRMED | test | `TestRejectGCPWorkspace_CSPTagOnly` | PR4 | todo |
| REQ-17 | cmd/request output (text) | `cmd/request.go:79-80` | Swap the table values: `r.DetailString("workspaceName")` / `r.DetailString("roleName")` | CONFIRMED | test | `TestRequestList_TextFieldMapping` | PR5 | todo |
| REQ-18 | cmd/request output (text) | `cmd/request.go:125` | `fmt.Fprintf(w, "Created By:    %s\n", r.CreatedBy)` → source from `r.UpdatedBy` | CONFIRMED | test | `TestRequestGet_TextFieldMapping` | PR5 | todo |
| REQ-19 | cmd/request output (JSON) | `cmd/request.go:190-191` | Swap `TimeFrom: r.DetailString("timeFrom")` and `TimeTo: r.DetailString("timeTo")` | CONFIRMED | test | `TestRequestGetJSON_FieldMapping` (`assertJSONEqual`) | PR5 | todo |
| REQ-20 | cmd/login | `cmd/login.go:52` | `if profile == nil {` → `if false {` (auto-configure branch). Feature *is* implemented; `login_test.go` skips it with the factually wrong reason "Auto-configure not yet implemented" — delete the skip | CONFIRMED | test | `TestRunLogin_AutoConfiguresMissingProfile` | PR4 | todo |
| REQ-21 | cmd/login | `cmd/login.go:74` | `auth.Authenticate(profile, nil, &authmodels.IdsecSecret{Secret: ""}, false, true)` → `..., true, false)` (swap `force`/`refreshAuth`) | CONFIRMED | test | `TestRunLogin_AuthenticateFlags` | PR4 | todo |
| REQ-22 | cmd/request submit | `cmd/request_submit.go:251` | `if !ui.IsInteractive() {` → `if false {` inside the `roleID == ""` branch | CONFIRMED | test | `TestRunRequestSubmit_NonInteractiveRequiresRoleID` | PR4 | todo |
| REQ-23 | cmd integration suite | `cmd/integration_test.go` (harness, not a production site) | No mutation. Claim was "integration tests are absent from CI **and** every assertion accepts a panic". First half confirmed (`.github/workflows/ci.yml` runs `make test-race` / `go test -race`, never `-tags=integration`); second half is too broad — only line 153 accepts any panic; lines 71/125/235 require specific output | OVERSTATED | test | `TestMain` isolation + exact exit-code/error-text assertions; add `-tags=integration` to both CI legs | PR1 | done |
| OUT-01 | cmd/list flags | `cmd/list.go:73` | Delete `cmd.MarkFlagsMutuallyExclusive("groups", "provider")`. `TestListCommand_MutualExclusivity` passes today on the *unrelated* runtime error `no eligible targets or groups found` | CONFIRMED | test | `TestListCommand_MutualExclusivity` (assert Cobra's `[groups provider] were all set`) | PR5 | todo |
| OUT-02 | cmd/favorites (interactive) | `cmd/favorites.go:258` | `fav.DirectoryID = selected.group.DirectoryID` → delete the line, in `selectFavoriteInteractive` | CONFIRMED | test | `TestFavoritesAddInteractive_PersistsDirectoryID` + `findMatchingGroup` round-trip | PR5 | todo |
| OUT-03 | cmd/favorites (group add) | `cmd/favorites.go:388` | `fav.DirectoryID = selected.group.DirectoryID` → delete the line, in `addGroupFavorite` | CONFIRMED | test | `TestAddGroupFavorite_PersistsDirectoryID` + `findMatchingGroup` round-trip | PR5 | todo |
| OUT-04 | cmd/list | `cmd/list.go:135` | `if provider == "" {` → `if true {` (groups fetched and emitted even when `--provider` is set) | CONFIRMED | test | `TestListCommand_ProviderSuppressesGroups` | PR5 | todo |
| OUT-05 | cmd/status JSON | `cmd/status.go:212` | `Provider: strings.ToLower(string(s.CSP))` → `strings.ToUpper(string(s.CSP))` | CONFIRMED | test | `TestStatusJSON_Contract` (`assertJSONEqual`) | PR5 | todo |
| OUT-06 | cmd/status JSON | `cmd/status.go:213` | `WorkspaceID: s.WorkspaceID` → `WorkspaceID: ""` | CONFIRMED | test | `TestStatusJSON_Contract` | PR5 | todo |
| OUT-07 | cmd/status JSON | `cmd/status.go:214` | `Duration: s.SessionDuration` → `Duration: 0` | CONFIRMED | test | `TestStatusJSON_Contract` | PR5 | todo |
| OUT-08 | cmd/status JSON | `cmd/status.go:215` | `RoleID: s.RoleID` → `RoleID: ""` | CONFIRMED | test | `TestStatusJSON_Contract` | PR5 | todo |
| OUT-09 | cmd/status JSON | `cmd/status.go:217-219` | Delete the `if name, ok := data.nameMap[s.WorkspaceID]; ok { so.WorkspaceName = name }` block | CONFIRMED | test | `TestStatusJSON_ResolvesWorkspaceName` | PR5 | todo |
| OUT-10 | cmd/status JSON | `cmd/status.go:221` | `so.Type = "group"` → `so.Type = "cloud"` | CONFIRMED | test | `TestStatusJSON_GroupSessionType` | PR5 | todo |
| OUT-11 | cmd/list JSON | `cmd/list.go:164` | `WorkspaceID: t.WorkspaceID` → `WorkspaceID: t.OrganizationID` | CONFIRMED | test | `TestListJSON_Contract` (`assertJSONEqual`) | PR5 | todo |
| OUT-12 | cmd/list JSON | `cmd/list.go:165` | `WorkspaceType: strings.ToLower(string(t.WorkspaceType))` → `WorkspaceType: ""` | CONFIRMED | test | `TestListJSON_Contract` | PR5 | todo |
| OUT-13 | cmd/list JSON | `cmd/list.go:167` | `RoleID: t.RoleInfo.ID` → `RoleID: ""`. `roleId` is the field an LLM/automation feeds straight back into `grant request submit --role-id`. Note the verifier's correction: `--target` resolves on the emitted **name**, not `workspaceId` | CONFIRMED | test | `TestListJSON_RoundTripsToRequestSubmit` | PR5 | todo |
| OUT-14 | cmd/list JSON | `cmd/list.go:175` | `GroupID: g.GroupID` → `GroupID: ""` | CONFIRMED | test | `TestListJSON_Contract` | PR5 | todo |
| OUT-15 | cmd/list JSON | `cmd/list.go:176` | `DirectoryID: g.DirectoryID` → `DirectoryID: ""` | CONFIRMED | test | `TestListJSON_Contract` | PR5 | todo |
| OUT-16 | cmd/favorites JSON | `cmd/favorites.go:462` | `Provider: entry.Provider` → `Provider: ""` | CONFIRMED | test | `TestFavoritesListJSON_Contract` (`assertJSONEqual`) | PR5 | todo |
| OUT-17 | cmd/favorites JSON | `cmd/favorites.go:464` | `Role: entry.Role` → `Role: ""` | CONFIRMED | test | `TestFavoritesListJSON_Contract` | PR5 | todo |
| OUT-18 | cmd/favorites JSON | `cmd/favorites.go:466` | `DirectoryID: entry.DirectoryID` → `DirectoryID: ""` | CONFIRMED | test | `TestFavoritesListJSON_Contract` | PR5 | todo |
| OUT-19 | cmd/favorites | `cmd/favorites.go:333` | `fav.Provider = cfg.DefaultProvider` → `fav.Provider = "azure"`. Every command test uses the azure default, so a non-default `DefaultProvider` (aws/gcp) is unpinned. Secondary, same defect class: `internal/config/favorites.go:21-22` independently defaults empty → `"azure"` | CONFIRMED | test | `TestFavoritesAdd_HonorsNonDefaultProvider` | PR5 | todo |
| OUT-20 | cmd/favorites | `cmd/favorites.go:199-205` | Delete the `--type groups` / `--target`+`--role` pairing validation from `parseFavoritesAddFlags`. Dead-covered: `runFavoritesAddProduction` re-validates, so this is redundancy loss for DI callers, not a current user-facing hole | CONFIRMED | test | `TestParseFavoritesAddFlags_Validation` | PR5 | todo |
| OUT-21 | cmd/status | `cmd/status.go:110-114` | Make the directory-name merge unconditional: drop the `if _, exists := data.nameMap[k]; !exists` guard. Precedence is genuinely unasserted, but in production both lookups read the same cached Azure eligibility response, so a divergence needs colliding IDs or malformed data | OVERSTATED | test | `TestStatus_DirectoryNameMergePrecedence` | PR5 | todo |
| OUT-22 | cmd/status | `cmd/status.go:129` | Delete `_ = cache.CleanupSessions(tracker, activeIDs)` | CONFIRMED | test | `TestStatus_CleansUpStaleSessionTimestamps` | PR5 | todo |
| OUT-23 | cmd/status (test quality) | `cmd/status.go:185-192` (`computeRemainingTime`) | No production defect. `TestStatusCommand_RemainingTime/text_output_shows_remaining_time` asserts `remaining: 4` as a substring, which `remaining: 4h 30m` satisfies — only the JSON sibling killed a sixfold arithmetic error. Signal-poor assertion, not an uncovered defect | CONFIRMED | test | Tighten the text subtest to an exact `remaining: 45m` | PR5 | todo |
| OUT-24 | cmd/favorites | `cmd/favorites.go:432-433` | Delete the `if len(args) > 1 { return fmt.Errorf("expected 1 favorite name, got %d", len(args)) }` arity check. Without it `favorites remove first second` silently removes `first` | CONFIRMED | test | `TestFavoritesRemove_RejectsExtraArgs` | PR5 | todo |
| OUT-25 | cmd/list flags | `cmd/list.go:71` | Delete `cmd.Flags().Bool("refresh", ...)` registration. **Verifier correction:** `grant list --refresh` is **not** already a no-op — `list.go:91-92` reads it and passes it into `buildCachedLister`, and CLAUDE.md is correct. The real finding is missing flag-registration/wiring coverage | OVERSTATED | test | `TestListCommand_RefreshBypassesCache` | PR5 | todo |
| OUT-26 | cmd test isolation | `cmd/favorites_test.go` → production `bootstrapImpl` (`cmd/root.go:158`) | No production mutation. A passing unit test (`TestFavoritesAddCommand/add_duplicate_favorite_name`) reaches the **real** `~/.idsec` profile and keyring; it accepts any error, so keyring access or an SDK auth attempt counts as success. The exact `Identity Security Platform Secret` prompt was **not** reproduced, even under a PTY; `ui.IsTerminalFunc` does not guard this because it runs after `bootstrapSCAService()` | OVERSTATED | prod-fix | `TestMain` env redirect + `AssertSandboxed`; `favorites add` early non-interactive guard with a favorites-specific message | PR1 | done |
| OUT-27 | cmd/favorites | `cmd/favorites.go:248-250` | `if provider != "" { fav.Provider = provider }` → ignore the interactive `--provider`. **Mutant dies**: `TestFavoritesAddInteractiveMode/eligibility_fetch_fails` fails with `output missing "failed to fetch eligible targets"`. A genuine assertion kill — not a compile error, panic, or environment failure | REFUTED | refuted | n/a — already killed | — | todo |
| OUT-28 | cmd/status docs | n/a | Claim: `computeRemainingTimeAt` is referenced but missing, and CLAUDE.md is stale. **False on both counts.** `rg computeRemainingTimeAt .` → no hits; the clock seam was deliberately removed in `2f34795`; current CLAUDE.md never claims it exists | REFUTED | refuted | n/a — no such symbol | — | todo |
| OUT-29 | cmd test mocks | `cmd/test_mocks.go:26,41,54,198` | Claim: argument-ignoring mocks are the *general* root cause. Every mock already supports argument-aware callbacks (`loadFunc`, `listFunc`), and OUT-27 is killed by an argument-sensitive error-path test. The default return path is arg-blind, which explains individual weak fixtures — but not as a blanket root cause | REFUTED | refuted | n/a — superseded by PR4's capture convention | — | todo |
| SCA-01 | internal/sca models | `internal/sca/models/elevate.go:30` | `AccessCredentials *string \`json:"accessCredentials"\`` → `json:"accessCredentialsXX"`. Passes the **entire repo suite**. Only fixtures use `"accessCredentials": null`; service tests marshal Go structs whose field is nil. This is the one field `grant env` exists to deliver | CONFIRMED | test | `TestElevateResponse_DecodesPopulatedAccessCredentials` — decode a *populated* value off the wire through `ParseAWSCredentials` and assert all three values | PR8 | todo |
| SCA-02 | internal/sca | `internal/sca/service.go:208` | `s.httpClient.Post(ctx, "/api/access/elevate", req)` → `..., nil)` | CONFIRMED | test | `TestElevate_SendsExactBody` (add `gotBody` to `mockHTTPClient`) | PR8 | todo |
| SCA-03 | internal/sca | `internal/sca/service.go:236` | `s.httpClient.Post(ctx, "/api/access/sessions/revoke", req)` → `..., nil)` | CONFIRMED | test | `TestRevokeSessions_SendsExactBody` | PR8 | todo |
| SCA-04 | internal/sca | `internal/sca/service.go:390` | `s.httpClient.Post(ctx, "/api/access/elevate/groups", req)` → `..., nil)` | CONFIRMED | test | `TestElevateGroups_SendsExactBody` | PR8 | todo |
| SCA-05 | internal/sca | `internal/sca/service.go:208` | Route `"/api/access/elevate"` → `"/WRONG"` | CONFIRMED | test | `TestElevate_Route` (add `gotRoute`) | PR8 | todo |
| SCA-06 | internal/sca | `internal/sca/service.go:258` | Route `"/api/access/sessions"` → `"/WRONG"` | CONFIRMED | test | `TestListSessions_Route` | PR8 | todo |
| SCA-07 | internal/sca | `internal/sca/service.go:236` | Route `"/api/access/sessions/revoke"` → `"/WRONG"` | CONFIRMED | test | `TestRevokeSessions_Route` | PR8 | todo |
| SCA-08 | internal/sca | `internal/sca/service.go:285` | `route := fmt.Sprintf("/api/access/%s/eligibility/groups", csp)` → `fmt.Sprintf("/WRONG/%s", csp)` | CONFIRMED | test | `TestListGroupsEligibility_Route` | PR8 | todo |
| SCA-09 | internal/sca | `internal/sca/service.go:390` | Route `"/api/access/elevate/groups"` → `"/WRONG"` | CONFIRMED | test | `TestElevateGroups_Route` | PR8 | todo |
| SCA-10 | internal/sca | `internal/sca/service.go:323` and `:356` | `"pageSize": -1` → `"pageSize": 10` at **both** on-demand call sites. The wire contract is genuinely untested; the *consequence* ("-1 means all, so 10 truncates the role picker") is **unevidenced** — neither the repo, the pinned SDK, nor official docs document this endpoint's `-1` semantics. Assert the sent value; do not assert a truncation story | OVERSTATED | test | `TestListOnDemandResources_ExactQueryParams` | PR8 | todo |
| SCA-11 | internal/sca | `internal/sca/service.go:326` and `:360` | `"target_category": "cloud_console"` → `"WRONG"` at **both** on-demand call sites | CONFIRMED | test | `TestListOnDemandResources_ExactQueryParams` | PR8 | todo |
| SCA-12 | internal/sca | `internal/sca/service.go:258-262` | `ListSessions`'s `buildParams` closure returns `nil` instead of `map[string]string{"csp": string(*csp)}`. `TestListSessions_WithCSPFilter` is tautological — its canned response is already Azure and it never inspects params. `grant status --provider azure` does no local filtering, so all providers' sessions would display | CONFIRMED | test | Replace `TestListSessions_WithCSPFilter` with `TestListSessions_SendsCSPQueryParam` (add `gotParams`) | PR8 | todo |
| SCA-13 | internal/sca | `internal/sca/service.go:144` | `s.httpClient.Get(ctx, route, p)` → `s.httpClient.Get(context.Background(), route, p)` in `paginate` | CONFIRMED | test | `TestPaginate_PropagatesContextCancellation` | PR8 | todo |
| SCA-14 | internal/sca | `internal/sca/service.go:184` (and the sibling decoders at `:267`, `:291`) | In the `ListEligibility` decode closure, swallow the error: `if err := json.NewDecoder(r).Decode(&page); err != nil { return nil, nil, 0, nil }` | CONFIRMED | test | `TestListEligibility_PropagatesDecodeError` | PR8 | todo |
| SCA-15 | internal/sca | `internal/sca/service.go:74` | `client.SetHeader("X-API-Version", "2.0")` → delete the call, and separately → `"1.0"`. The **only** guard lives inside `TestNewSCAAccessServiceDisablesTransientRetry`, so a retry-motivated rename silently deletes the header assertion. Verifier could not execute it (loopback prohibited in that sandbox); coverage topology confirmed by grep | OVERSTATED | test | Extract `TestNewSCAAccessService_SetsAPIVersionHeader` as its own named test | PR8 | todo |
| SCA-16 | internal/sca models | `internal/sca/models/elevate.go:28` | `RoleID string \`json:"roleId"\`` → `json:"roleIdXX"` on the **request** model | CONFIRMED | test | `TestElevateRequest_JSONTags` | PR8 | todo |
| SCA-17 | internal/sca models | `internal/sca/models/credentials.go:17` (`ParseAWSCredentials`) | Swap `SecretAccessKey` and `SessionToken` in the parser output. **Mutant dies repo-wide**: `env_test.go:77` and `root_elevate_test.go:426`. Nuance: swapping the *struct JSON tags* instead is also caught, by `TestAWSCredentials_JSONUnmarshal`. Recorded so this is not re-filed as a survivor | REFUTED | refuted | n/a — already killed | — | todo |
| SCA-18 | internal/sca | `internal/sca/service.go:75-ish` (`sdkclient.DisableTransientRetry` call) | Claim: deleting the call yields `inbound requests = 4, want 1`. **Not reproducible** in the verifier's sandbox (loopback prohibited); a literal deletion is a compile kill first (`"internal/sdkclient" imported and not used`). Same for the workflows twin. The guard tests exist and are correctly aimed; only their runtime assertion was unverifiable | OVERSTATED | refuted | n/a — `internal/sca/retry_policy_test.go` / `internal/workflows/retry_policy_test.go` already guard this | — | todo |
| WF-01 | internal/workflows | `internal/workflows/service.go:102` | Delete `if err := checkResponse(resp, "request forms"); err != nil { return nil, err }` | CONFIRMED | test | `TestWorkflows_Non200` (table over all six call sites) | PR8 | todo |
| WF-02 | internal/workflows | `internal/workflows/service.go:161` | Delete the `checkResponse(resp, "list requests")` guard | CONFIRMED | test | `TestWorkflows_Non200` | PR8 | todo |
| WF-03 | internal/workflows | `internal/workflows/service.go:196` | Delete the `checkResponse(resp, "get request")` guard | CONFIRMED | test | `TestWorkflows_Non200` | PR8 | todo |
| WF-04 | internal/workflows | `internal/workflows/service.go:221` | Delete the `checkResponse(resp, "submit request")` guard. Verified consequence: a 500 carrying `{}` decodes to an empty request, so `grant request submit` prints a blank `Request ID:` / `State:` and exits 0 | CONFIRMED | test | `TestWorkflows_Non200` | PR8 | todo |
| WF-05 | internal/workflows | `internal/workflows/service.go:245` | Delete the `checkResponse(resp, "cancel request")` guard | CONFIRMED | test | `TestWorkflows_Non200` | PR8 | todo |
| WF-06 | internal/workflows | `internal/workflows/service.go:272` | Delete the `checkResponse(resp, "finalize request")` guard | CONFIRMED | test | `TestWorkflows_Non200` | PR8 | todo |
| WF-07 | internal/workflows | `internal/workflows/logging_client.go:58` | Delete the `if redacted.Get("Authorization") != ""` redaction block. Real token-in-logs risk; the SCA twin is covered by `TestLoggingClient_DebugLogsHeaders` | CONFIRMED | test | new `internal/workflows/logging_client_test.go`, mirroring the sca one **including Authorization redaction** | PR8 | todo |
| WF-08 | internal/workflows | `internal/workflows/logging_client.go:24-26` | Route `Get` through `c.inner.Post(ctx, route, params)` | CONFIRMED | test | `TestLoggingClient_GetUsesGet` (workflows) | PR8 | todo |
| WF-09 | internal/workflows | `internal/workflows/logging_client.go:24-33` | Swallow the inner error and return a synthetic 200 response with `err = nil` | CONFIRMED | test | `TestLoggingClient_PropagatesInnerError` (workflows) | PR8 | todo |
| WF-10 | internal/workflows models | `internal/workflows/models/submit.go:6` | `RequestDetails map[string]interface{} \`json:"requestDetails"\`` → `json:"requestDetailsXX"` | CONFIRMED | test | `TestSubmitAccessRequest_JSONTags` | PR8 | todo |
| WF-11 | internal/workflows models | `internal/workflows/models/finalize.go:5` | `Result string \`json:"result"\`` → `json:"resultXX"` | CONFIRMED | test | `TestFinalizeAccessRequest_JSONTags` | PR8 | todo |
| WF-12 | internal/workflows models | `internal/workflows/models/cancel.go:5` | `CancelReason *string \`json:"cancelReason"\`` → `json:"cancelReasonXX"` | CONFIRMED | test | `TestCancelAccessRequest_JSONTags` | PR8 | todo |
| WF-13 | internal/workflows | `internal/workflows/service.go:263` | Delete `FinalizationReason: reason,` from the `FinalizeAccessRequest` literal | CONFIRMED | test | `TestFinalizeRequest_SendsFinalizationReason` | PR8 | todo |
| WF-14 | internal/workflows | `internal/workflows/service.go:260` | `route := fmt.Sprintf("/api/workflows/requests/%s/finalize", requestID)` → `"/api/workflows/requests/finalize"`. The cancel twin *is* covered (`service_test.go:274`), which is the contrast that proves the gap | CONFIRMED | test | `TestFinalizeRequest_ExactRoute` | PR8 | todo |
| WF-15 | internal/workflows | `internal/workflows/service.go:141` | Delete `qp["limit"] = strconv.Itoa(limit)` | CONFIRMED | test | `TestListRequests_SendsLimit` | PR8 | todo |
| WF-16 | internal/workflows | `internal/workflows/service.go:124` | `const defaultPageSize = 50` → `= 1` | CONFIRMED | test | `TestListRequests_DefaultPageSize` | PR8 | todo |
| WF-17 | internal/workflows | `internal/workflows/service.go:156` | `s.httpClient.Get(ctx, "/api/workflows/requests", qp)` → `Get(context.Background(), ...)` in the pagination loop | CONFIRMED | test | `TestListRequests_PropagatesContextCancellation` | PR8 | todo |
| WF-18 | internal/workflows | `internal/workflows/service.go:201` | In `GetRequest`, swallow the decode error: `if err := json.NewDecoder(resp.Body).Decode(&result); err != nil { return &result, nil }` | CONFIRMED | test | `TestGetRequest_PropagatesDecodeError` | PR8 | todo |
| WF-19 | internal/workflows | `internal/workflows/service_config.go:9` | `ServiceName: "access-requests"` → `"WRONG"`. There is no workflows `service_config_test.go` at all | CONFIRMED | test | new `internal/workflows/service_config_test.go` | PR8 | todo |
| WF-20 | internal/workflows | `internal/workflows/service.go:45` | `base.Authenticator("isp")` → `base.Authenticator("WRONG")` | CONFIRMED | test | new `internal/workflows/service_config_test.go` | PR8 | todo |
| ELV-01 | cmd/selection | `cmd/selection.go:78` | `return &items[i], nil` → `return &items[0], nil`. `TestFindItemByDisplay` only checks non-nil/error, so selecting one display value silently elevates the first sorted target and prints a success line naming the wrong one | CONFIRMED | test | `TestFindItemByDisplay_ReturnsMatchingItem` | PR4 | todo |
| ELV-02 | cmd/root (unified elevate builder) | `cmd/root.go:786-793` | In `elevateCloud`, swap `WorkspaceID: selectedTarget.WorkspaceID` and `RoleID: selectedTarget.RoleInfo.ID` | CONFIRMED | test | `TestElevateCloud_RequestPayload` (`mockElevateService` history) | PR4 | todo |
| ELV-03 | cmd/root (unified elevate builder) | `cmd/root.go:786-788` | In `elevateCloud`, blank both `CSP:` and `OrganizationID:` | CONFIRMED | test | `TestElevateCloud_RequestPayload` | PR4 | todo |
| ELV-04 | cmd/root (env/direct elevate builder) | `cmd/root.go:497-506` | In `resolveAndElevate`, swap `WorkspaceID` and `RoleID` in the `ElevateRequest` literal. (Plan calls these "both builders": `:497` and `:786`) | CONFIRMED | test | `TestResolveAndElevate_RequestPayload` | PR4 | todo |
| ELV-05 | cmd/env favorite path | `cmd/root.go:429` | `if flags.favorite != "" {` → `if false {` in `resolveAndElevate`. No env test exercises `--favorite`, yet the flag is registered (`cmd/env.go:39`) and advertised in help (`cmd/env.go:29`) | CONFIRMED | test | `TestEnv_FavoriteMode` | PR4 | todo |
| ELV-06 | cmd/env favorite path | `cmd/root.go:438-440` | Delete the group-favorite rejection (`if fav.ResolvedType() == config.FavoriteTypeGroups { return ... }`) | CONFIRMED | test | `TestEnv_RejectsGroupFavorite` | PR4 | todo |
| ELV-07 | cmd/env favorite path | `cmd/root.go:443-445` | Delete the provider-mismatch check `if flags.provider != "" && !strings.EqualFold(flags.provider, fav.Provider)` | CONFIRMED | test | `TestEnv_FavoriteProviderMismatch` | PR4 | todo |
| ELV-08 | cmd/env direct path | `cmd/root.go:456-458` | Delete the paired `--target`/`--role` validation in `resolveAndElevate` | CONFIRMED | test | `TestEnv_RequiresBothTargetAndRole` | PR4 | todo |
| ELV-09 | cmd/root favorite path | `cmd/root.go:577` | `if fav.ResolvedType() == config.FavoriteTypeGroups {` → `if false {` in `resolveFavoriteFlags`. This is the row that refutes "all root equivalents are covered" — root group-favorite **detection** is also unpinned | CONFIRMED | test | `TestResolveFavoriteFlags_DetectsGroupFavorite` | PR4 | todo |
| ELV-10 | cmd/root group elevate | `cmd/root.go:837-841` | `if result.ErrorInfo != nil {` → `if false {` in `elevateGroup`. Execution then builds a result and returns nil: a policy denial prints as success and exits 0 | CONFIRMED | test | `TestElevateGroup_SurfacesErrorInfo` | PR4 | todo |
| ELV-11 | cmd/env elevate | `cmd/root.go:525-530` | `if result.ErrorInfo != nil {` → `if false {` in `resolveAndElevate` (the env path). Same false-success consequence | CONFIRMED | test | `TestEnv_SurfacesErrorInfo` | PR4 | todo |
| ELV-12 | cmd/env elevate | `cmd/root.go:520-522` | Delete `if len(elevateResp.Response.Results) == 0 { return nil, errors.New("elevation failed: no results returned") }` (env path). Mutant panics on `Results[0]` only if a test supplies an empty slice — none does | CONFIRMED | test | `TestEnv_EmptyResultsGuard` | PR4 | todo |
| ELV-13 | cmd/root cloud elevate | `cmd/root.go:802-805` | Delete the identical empty-`Results` guard in `elevateCloud` | CONFIRMED | test | `TestElevateCloud_EmptyResultsGuard` | PR4 | todo |
| ELV-14 | cmd/root group elevate | `cmd/root.go:832-835` | Delete the identical empty-`Results` guard in `elevateGroup` | CONFIRMED | test | `TestElevateGroup_EmptyResultsGuard` | PR4 | todo |
| ELV-15 | cmd/root JSON | `cmd/root.go:936-937` | In `writeElevationJSON`, swap `Target: cloudRes.target.WorkspaceName` and `Role: cloudRes.target.RoleInfo.Name` | CONFIRMED | test | `TestElevationJSON_Contract` (`assertJSONEqual`) | PR5 | todo |
| ELV-16 | cmd/root JSON | `cmd/root.go:923-924` | In `writeElevationJSON`, swap `GroupID: groupRes.group.GroupID` and `DirectoryID: groupRes.group.DirectoryID` | CONFIRMED | test | `TestGroupElevationJSON_Contract` | PR5 | todo |
| ELV-17 | cmd/env JSON | `cmd/env.go:145-147` | Swap `SecretAccessKey: awsCreds.SecretAccessKey` and `SessionToken: awsCreds.SessionToken`. Asymmetry is the point: the identical swap in the **text** export path is killed (`env_test.go:77`) | CONFIRMED | test | `TestEnvJSON_Contract` (`assertJSONEqual`) | PR5 | todo |
| ELV-18 | cmd/root JSON | `cmd/root.go:934` | `Provider: strings.ToLower(string(cloudRes.target.CSP))` → drop the `strings.ToLower` | CONFIRMED | test | `TestElevationJSON_Contract` | PR5 | todo |
| ELV-19 | cmd/root | `cmd/root.go:341-344` | Delete `if len(all) == 0 { return nil, errors.New("no eligible targets found, check your SCA policies") }` in `fetchEligibility`'s multi-CSP branch. Callers replace the intended aggregate error with their own message | CONFIRMED | test | `TestFetchEligibility_AllCSPsFail` | PR4 | todo |
| ELV-20 | cmd/env elevate | `cmd/root.go:510-514` | Remove the fresh-context setup and elevate with the original `ctx`: delete `elevCtx, elevCancel := context.WithTimeout(...)` / `defer elevCancel()` and call `elevateService.Elevate(ctx, req)`. **Note:** a raw `elevCtx → ctx` token substitution does *not* compile (`declared and not used: elevCtx`) — use the semantic form above. Root's three interactive dispatch paths *are* covered by `TestRootElevate_SlowPromptTimeout`; env is not | CONFIRMED | test | `TestEnv_SlowPromptTimeout` | PR4 | todo |
| ELV-21 | cmd/env auth | `cmd/root.go:419` | `authLoader.LoadAuthentication(profile, true)` → `(profile, false)` in `resolveAndElevate` (env path) | CONFIRMED | test | `TestEnv_AuthCacheFlag` | PR4 | todo |
| ELV-22 | cmd/root auth | `cmd/root.go:620` | `authLoader.LoadAuthentication(profile, true)` → `(profile, false)` in the root elevate path | CONFIRMED | test | `TestRootElevate_AuthCacheFlag` | PR4 | todo |
| ELV-23 | cmd/env selector | `cmd/root.go:480` | `selector.SelectTarget(allTargets)` → `selector.SelectTarget(nil)`. `mockTargetSelector` returns its canned target without inspecting the slice | CONFIRMED | test | `TestEnv_SelectorReceivesAllTargets` | PR4 | todo |
| ELV-24 | cmd/root Execute | `cmd/root.go:291` | `if !verbose && passedArgValidation {` → `if verbose && passedArgValidation {`. `TestVerboseHintSuppressedForArgErrors` calls Cobra's `root.Execute()` and then *reconstructs* the hint logic; it never invokes the package-level `Execute()` | CONFIRMED | test | `TestExecute_VerboseHintCondition` | PR4 | todo |
| ELV-25 | cmd/root dispatch | `cmd/root.go:631-636` | Swap the dispatch order: test `if flags.groups` before `if flags.group != ""`. `--group` and `--groups` are **not** mutually exclusive (`root.go:136-142` pairs neither), so their precedence is unspecified and unpinned | CONFIRMED | test | `TestRootElevate_GroupAndGroupsPrecedence` | PR4 | todo |
| ELV-26 | cmd test quality | `cmd/root_elevate_test.go:248` | No production site. The `multi-CSP concurrent fetch - parallel execution` case duplicates the line-174 success setup, adds sleeps, and asserts **no** elapsed time. Real concurrency is covered by `TestFetchEligibility_ConcurrentExecution` | CONFIRMED | test | Delete the duplicate case or give it a real elapsed-time assertion | PR4 | todo |
| ELV-27 | cmd test quality | `cmd/root_test.go` (`TestFetchEligibility_ConcurrentExecution`) | Claim: the `<350ms` bound for two concurrent 200ms sleeps is flaky. **Not demonstrated** — 50/50 runs passed. The wall-clock sensitivity remains a plausible overloaded-CI risk, so widen the bound; do not claim an observed flake | OVERSTATED | test | Widen the bound in `TestFetchEligibility_ConcurrentExecution` | PR4 | todo |
| SFU-01 | internal/selfupdate | `internal/selfupdate/selfupdate.go:345` | `case path.IsAbs(cleaned):` → `case false:` | CONFIRMED | test | `TestCheckArchivePath` — one guard-specific `wantErrContains` per arm, with a valid `grant` entry beside each malicious one so the "no binary" fallback cannot be the reason for the error | PR2 | done |
| SFU-02 | internal/selfupdate | `internal/selfupdate/selfupdate.go:347` | `case strings.HasPrefix(normalized, "//"):` → `case false:`. **Production change (PR2):** move this arm *before* `path.IsAbs` — `path.Clean` collapses `//host/share/x` → `/host/share/x`, so `IsAbs` always wins and the UNC arm is unreachable. Rejection is unchanged; only the message differs | CONFIRMED | test + prod-fix | `TestCheckArchivePath/unc_path` | PR2 | done |
| SFU-03 | internal/selfupdate | `internal/selfupdate/selfupdate.go:349` | `case hasDriveLetter(normalized):` → `case false:` | CONFIRMED | test | `TestCheckArchivePath/drive_absolute` | PR2 | done |
| SFU-04 | internal/selfupdate | `internal/selfupdate/selfupdate.go:343` | `case name == "":` → `case false:` | CONFIRMED | test | `TestCheckArchivePath/empty_name` | PR2 | done |
| SFU-05 | internal/selfupdate | `internal/selfupdate/selfupdate.go:339` | `normalized := strings.ReplaceAll(name, "\\", "/")` → `normalized := name` (backslash traversal and backslash UNC then slip through) | CONFIRMED | test | `TestCheckArchivePath/backslash_traversal`, `.../backslash_unc` | PR2 | done |
| SFU-06 | internal/selfupdate | `internal/selfupdate/selfupdate.go:359` (`hasDriveLetter`) | Narrow the check to uppercase drive letters only, so lowercase `c:\...` passes | CONFIRMED | test | `TestCheckArchivePath/lowercase_drive`, `.../forward_slash_drive` | PR2 | done |
| SFU-07 | internal/selfupdate | `internal/selfupdate/selfupdate.go:392` | `if hdr.Typeflag != tar.TypeReg \|\| !isBinaryEntry(hdr.Name) {` → drop the `hdr.Typeflag != tar.TypeReg` operand. Probe (`Typeflag: tar.TypeSymlink, Name: "grant", Size: 0, Linkname: "/etc/passwd"`): baseline `bytes=0 err=archive does not contain a grant binary`; mutated `bytes=0 err=<nil>` — i.e. a **zero-byte self-destruct**. No symlink case exists anywhere in the package | CONFIRMED | test + prod-fix | `TestExtractBinaryRejectsNonRegularEntries` (symlink / hardlink / directory named `grant`, plus a zip directory entry). Reverified: with the mutation the type-specific cases fail on the *message* (`grant in archive is empty` instead of `does not contain a grant binary`), because the new empty-binary backstop catches the bytes while the type tests catch the classification — exactly why both are kept. **Production:** reject a zero-length extracted binary *and* add a second non-empty check at the apply boundary (`internal/selfupdate/apply.go:50`). CHANGELOG `### Security` | PR2 | done |
| SFU-08 | internal/selfupdate | `internal/selfupdate/selfupdate.go:389-391` | Delete the tar declared-size guard (`if hdr.Size > maxDownloadBytes`) | CONFIRMED | test | `TestExtractFromTarGzRejectsOversizeDecoy` — oversized **decoy** beside a valid binary | PR2 | done |
| SFU-09 | internal/selfupdate | `internal/selfupdate/selfupdate.go:430-432` | Delete the zip declared-size guard (`if maxDownloadBytes >= 0 && f.UncompressedSize64 > uint64(maxDownloadBytes)`) | CONFIRMED | test | `TestExtractBinaryRejectsOversizedEntry/zip`, asserting the pre-filter's exact wording ("declares 300 bytes, over the 64 byte limit") rather than readCapped's "exceeds". **Correction:** a zip oversize *decoy* cannot kill this mutation and must not — `zip.NewReader` never opens a skipped entry, so the asymmetry is intentional (SFU-22). `TestExtractFromZipIgnoresOversizeDecoy` pins that instead | PR2 | done |
| SFU-10 | internal/selfupdate | `internal/selfupdate/apply.go:74` | Delete the `if err := syncStagedFile(target); err != nil { ... }` call. Per the consistency review this is **not** a production gap — `applyWithOptions` already returns a wrapped sync error before commit and `syncStagedFile` (`:110`) already returns `f.Sync()` errors. Scope is a seam plus tests; **no CHANGELOG entry** | CONFIRMED | test | `TestApplyWithOptionsSyncsBeforeCommit` + `TestApplyWithOptionsAbortsOnSyncError`, via a `syncStagedFileFn` seam (call-order + abort-before-commit) | PR3 | done |
| SFU-11 | internal/selfupdate | `internal/selfupdate/apply.go:110-115` | In `syncStagedFile`, ignore the `f.Sync()` error: `_ = f.Sync(); return nil` | CONFIRMED | test | `TestSyncStagedFileReportsSyncError` (`apply_unix_test.go`). **Correction:** the seam cannot kill this mutation — it lives *inside* `syncStagedFile`, so a stubbed seam never runs it. The kill needs a real failing `fsync`: a FIFO at the staged path (`fsync(2)` on a FIFO returns `EINVAL`). Unix only; skipped on Windows, where no portable equivalent exists | PR3 | done |
| SFU-12 | internal/selfupdate | `internal/selfupdate/apply.go:154-156` | In `InterruptedUpdate`, delete the target-exists guard (`if _, err := os.Stat(targetPath); err == nil \|\| !errors.Is(err, os.ErrNotExist) { return "", false }`). The untested case is target **present** and `.old` present — the documented Windows steady state | CONFIRMED | test | `TestInterruptedUpdate/target_present_with_backup_present` | PR3 | done |
| SFU-13 | internal/selfupdate | `internal/selfupdate/selfupdate.go:197-199` | Delete the non-200 check `if resp.StatusCode != http.StatusOK { ... }` in `fetchLatestRelease` | CONFIRMED | test | `TestFetchLatestRelease/not_found` and `/rate_limited` already kill this once the message is asserted; `newFixtureServerWith(t, opts)` was added for the other rows | PR3 | done |
| SFU-14 | internal/selfupdate | `internal/selfupdate/selfupdate.go:202-204` | In `fetchLatestRelease`, swallow the `json.Unmarshal` error on an empty body: `_ = json.Unmarshal(body, &rel)` | CONFIRMED | test | `TestFetchLatestReleaseRejectsBadPayloads/empty_body` — asserting the *decode* message, since an empty body also yields an empty `tag_name` | PR3 | done |
| SFU-15 | internal/selfupdate | `internal/selfupdate/selfupdate.go:205-207` | Delete `if rel.TagName == "" { return nil, errors.New("GitHub release response has no tag_name") }` | CONFIRMED | test | `TestFetchLatestReleaseRejectsBadPayloads/empty_tag_name`; non-200 on the **asset** and **checksums** downloads plus the empty-download guard are `TestUpdateSelfFailsOnAssetDownloadStatus`, which must assert the inner `download returned status N` message — the `failed to download X` wrapper alone is satisfied by the empty-download error | PR3 | done |
| SFU-16 | internal/selfupdate | `internal/selfupdate/version.go` (`comparePreRelease`, numeric-vs-numeric branch) | Invert the numeric-vs-numeric comparison so `rc.10` sorts before `rc.2` | CONFIRMED | test | `TestCompareVersions/numeric_prerelease_compares_numerically_mirrored` (`rc.10` vs `rc.2` → +1). **Note:** a full inversion of the branch is caught by the pre-existing case too; the mutation that genuinely needs the mirror is dropping the `case aNum > bNum: return 1` arm, which was the one reverified | PR3 | done |
| SFU-17 | internal/selfupdate | `internal/selfupdate/version.go:194` | `if !isAllDigits(part) {` → `if false {` in the core `MAJOR.MINOR.PATCH` loop, so `"1.+5.3"` is accepted | CONFIRMED | test | `TestParseVersion/non_numeric` (`"1.x.3"`) and `/empty_core_segment` (`"1.2."`), asserting `is not a non-negative integer`. **Correction:** `"1.+5.3"` does NOT reach the guard — `ParseVersion` splits build metadata at the first `+` before parsing the core, so it fails with `expected MAJOR.MINOR.PATCH` mutated or not. It is kept as a case, documented as such. Only the message distinguishes the guard from `strconv.Atoi` | PR3 | done |
| SFU-18 | internal/selfupdate | `internal/selfupdate/selfupdate.go:284-287` | `if len(fields) != 2 { return fmt.Errorf("malformed line in %s: %q", ...) }` → `continue` | CONFIRMED | test | `TestVerifyChecksum/malformed_line_with_one_field` and `/malformed_line_with_three_fields` | PR3 | done |
| SFU-19 | internal/selfupdate | `internal/selfupdate/selfupdate.go:316-317` | In `extractBinary`, replace the `default:` unsupported-format error with `return extractFromTarGz(archive)` | CONFIRMED | test | `TestExtractBinary/unknown_archive_format` with `wantErrContains: "unsupported archive format"` | PR3 | done |
| SFU-20 | internal/selfupdate | `internal/selfupdate/selfupdate.go:402` | Delete `if int64(len(data)) != hdr.Size { ... }` (tar truncation cross-check). **Unreachable by construction**: a successful capped read returns exactly `hdr.Size`, and earlier exhaustion returns `io.ErrUnexpectedEOF`. Hand-patched proof: header declares 40 with body `"bin"` → `bytes=40 err=<nil>`; header declares 2000 → `bytes=0 err=... unexpected EOF` | CONFIRMED | wont-fix | none — keep as defense-in-depth, comment it as unreachable, and claim no coverage. Rename `TestExtractBinaryRejectsTruncatedEntry` → `...TruncatedArchive` | PR2 | done |
| SFU-21 | internal/selfupdate | `internal/selfupdate/selfupdate.go:437` | Delete `if uint64(len(data)) != f.UncompressedSize64 { ... }` (zip truncation cross-check). Same unreachability argument as SFU-20 | CONFIRMED | wont-fix | none — defense-in-depth, no coverage claimed | PR2 | done |
| SFU-22 | internal/selfupdate | `internal/selfupdate/selfupdate.go:389` vs `:430` | tar/zip size-check asymmetry. The original "zip decompression bomb" framing is **overstated**: the structural asymmetry is real (`maxDownloadBytes=10`, 5000-byte decoy → `TAR bytes=0 err=<limit>` vs `ZIP bytes=3 err=<nil>`), but `zip.NewReader` parses only the central directory and never opens skipped entries. The tar guard is load-bearing; the zip placement is a consistency point, not a vulnerability | OVERSTATED | wont-fix | Pin the asymmetry as **intentional** with a comment and a test asserting a skipped zip entry is never inflated | PR2 | done |
| CACHE-01 | internal/cache | `internal/cache/cached_eligibility.go:84` | When `c.refresh` is true, skip the write: guard `Set(c.store, key, *resp)` with `if !c.refresh`. `--refresh` must bypass the **read** but still **write** | CONFIRMED | test | `TestCachedEligibility_RefreshStillWrites` | PR6 | todo |
| CACHE-02 | internal/cache | `internal/cache/cached_eligibility.go:117` | Same mutation on the groups-eligibility write | CONFIRMED | test | `TestCachedGroupsEligibility_RefreshStillWrites` | PR6 | todo |
| CACHE-03 | internal/cache | `internal/cache/cached_roles.go:53` | Same mutation on the on-demand-roles write | CONFIRMED | test | `TestCachedRoles_RefreshStillWrites` | PR6 | todo |
| CACHE-04 | internal/cache | `internal/cache/cache.go:39-41` | `if err := json.Unmarshal(data, &e); err != nil { return false }` → ignore the error and fall through. `TestGet_CorruptJSON` passes today via the zero-`CachedAt` TTL branch, not the unmarshal guard | CONFIRMED | test | Fix `TestGet_CorruptJSON` to use a **fresh** `cached_at` with a type-mismatched payload, so only the unmarshal guard can produce the miss | PR6 | todo |
| CACHE-05 | internal/cache | `internal/cache/cached_eligibility.go:131` | `"groups_eligibility_" + ...` → `"eligibility_" + ...` (key collision with the cloud-eligibility prefix) | CONFIRMED | test | `TestCacheKeys_DistinctPrefixes` | PR6 | todo |
| CACHE-06 | internal/cache | `internal/cache/cached_eligibility.go:127` and `:131` | Drop `strings.ToLower(string(csp))` from both key builders | CONFIRMED | test | `TestCacheKeys_LowercaseCSP` | PR6 | todo |
| CACHE-07 | internal/cache | `internal/cache/session_tracker.go:14` | `const maxSessionAge = 24 * time.Hour` → `25 * time.Hour`. No test pins either value; code says 24h and CLAUDE.md says 25h | CONFIRMED | test + prod-fix | `TestSessionTimestamps_RetentionBoundary`. **Production:** rename to `sessionTimestampRetention` (keep 24h) with a comment stating it is local retention for remaining-time display — not a session limit or access-control boundary. Also fix the factually wrong "removed on cleanup" comment: `CleanupSessions` filters on active IDs and never reads it. Drop the 25h claim from CLAUDE.md | PR6 | todo |
| CFG-01 | internal/config | `internal/config/config.go:54-58` | In `Load`, return the default config for **any** read error: `if err != nil { return DefaultConfig(), nil }`. Killed on Linux by `config_test.go:197`, but `config_test.go:184-186` **skips on Windows**, so there is zero coverage on the windows-latest leg | CONFIRMED | test | Portable replacement: `Load(<dir>)` — errors as EISDIR on POSIX / ERROR_ACCESS_DENIED on Windows, and `errors.Is(err, os.ErrNotExist)` is false on both. (Windows half reasoned, not measured — verify on the CI leg) | PR6 | todo |
| CFG-02 | internal/config | `internal/config/config.go:110-113` | Add a `d <= 0` rejection to `ParseCacheTTL` — **it also survives**, i.e. the tests are blind in both directions. There is no negative/zero-TTL table row at all | CONFIRMED | test + prod-fix | `TestParseCacheTTL` rows for `0s`, `-5m`, `garbage`. **Production:** `ParseCacheTTL` returns `(time.Duration, error)`; empty → default, any explicitly-supplied invalid value (unparseable **or** non-positive) → error. Validate at config load. Ripple: `buildCachedLister` (`cmd/root.go:242`, seven call sites) + `cmd/request_submit.go:541`. CHANGELOG `### Changed` | PR6 | todo |
| CFG-03 | internal/config | `internal/config/config.go:20` | `const DefaultCacheTTL = 4 * time.Hour` → `400 * time.Hour`. The existing assertion is the tautology `want: DefaultCacheTTL` | CONFIRMED | test | `TestParseCacheTTL_DefaultIsFourHours` (assert the literal `4 * time.Hour`) | PR6 | todo |
| CFG-04 | internal/config | `internal/config/config.go:60` | `cfg := DefaultConfig()` → `cfg := &Config{}` (defaults no longer survive a partial YAML file) | CONFIRMED | test | `TestLoad_PartialYAMLKeepsDefaults` | PR6 | todo |
| CFG-05 | internal/config | `internal/config/config.go:65-67` | Delete `if cfg.Favorites == nil { cfg.Favorites = make(map[string]Favorite) }` | CONFIRMED | test | `TestLoad_FavoritesNeverNil` | PR6 | todo |
| CFG-06 | internal/config | `internal/config/config.go:61-63` | Swallow the YAML error: `_ = yaml.Unmarshal(data, cfg)` | CONFIRMED | test | `TestLoad_InvalidYAMLErrors` | PR6 | todo |
| CFG-07 | internal/config | `internal/config/config.go:103` | `filepath.Join(home, ".grant")` → `".grantx"` | CONFIRMED | test | `TestConfigDir_EndsInDotGrant` | PR6 | todo |
| CFG-08 | internal/config | `internal/config/config.go:84` | `os.WriteFile(path, data, 0o600)` → `0o644` | CONFIRMED | test | `TestSave_FileMode` with the `runtime.GOOS == "windows"` skip | PR6 | todo |
| CFG-09 | internal/config | `internal/config/config.go:75` | `if err := os.MkdirAll(dir, 0o700); err != nil { ... }` → ignore the error | CONFIRMED | test | `TestSave_MkdirAllFailure` — force it portably by pointing at a path whose parent component is an existing **regular file** (ENOTDIR / ERROR_DIRECTORY), never a hardcoded `/dev/null/...` | PR6 | todo |
| UI-01 | internal/ui | `internal/ui/tty.go:18` | `return IsTerminalFunc(os.Stdin.Fd())` → `IsTerminalFunc(os.Stdout.Fd())`. This swap is what makes `grant revoke < /dev/null` hang in a terminal. All twelve prompt-level guards are well covered (8 spot-checked, all killed with `errors.Is` + flag hints); `IsInteractive()` itself is not, because every stub ignores `fd` | CONFIRMED | test | `TestIsInteractive_ChecksStdinFd` — a stub that records the fd and asserts `os.Stdin.Fd()` | PR7 | todo |
| UI-02 | internal/ui | `internal/ui/group_selector.go:60` | Delete the `sort.Slice(sorted, ...)` call in the group selector | CONFIRMED | test + prod-fix | Extract `sortGroupsForDisplay` so ordering is testable without a TTY; `TestSortGroupsForDisplay_CollisionOrdering` | PR7 | todo |
| UI-03 | internal/ui | `internal/ui/session_selector.go:57` | `if remaining <= 0 {` → `if remaining < 0 {`. The fixture only supplies `-5m` (`session_selector_test.go:154`), so exactly-zero is unpinned | CONFIRMED | test | `TestFormatSessionOption_ExactlyZeroRemaining` | PR7 | todo |
| UI-04 | internal/ui | `internal/ui/request_selector.go:18` | Delete the `time.Parse(time.RFC3339Nano, ts)` branch in the timestamp formatter | CONFIRMED | test | `TestFormatRequestOption_RFC3339Nano` | PR7 | todo |
| UI-05 | internal/ui | `internal/ui/role_selector.go:36` | Make the role sort case-**sensitive** (drop the `strings.ToLower` normalization in the `sort.SliceStable` less-func). Note: the raw mutation orphans the `strings` import — remove it too | CONFIRMED | test | `TestSortRolesForDisplay_MixedCase` | PR7 | todo |
| UI-06 | internal/ui | `internal/ui/selector.go:49` | Delete the `if len(targets) == 0` guard in `SelectTarget`. (`SelectRole`/`SelectRequest` equivalents are **killed**; these three are not) | CONFIRMED | test | `TestSelectTarget_EmptyList` | PR7 | todo |
| UI-07 | internal/ui | `internal/ui/session_selector.go:112` | Delete the `if len(sessions) == 0` guard in `SelectSessions` | CONFIRMED | test | `TestSelectSessions_EmptyList` | PR7 | todo |
| UI-08 | internal/ui | `internal/ui/group_selector.go:54` | Delete the `if len(groups) == 0` guard in `SelectGroup`. Note: the raw mutation orphans the `errors` import — remove it too | CONFIRMED | test | `TestSelectGroup_EmptyList` | PR7 | todo |
| UI-09 | internal/ui | `internal/ui/role_selector.go` (post-`survey` index bounds check) | Disable the returned-index bounds check in `SelectRole` | CONFIRMED | wont-fix | none — defensive-only and unreachable through `survey`, which can only return a string it was given | PR7 | todo |
| UI-10 | internal/ui | `internal/ui/request_selector.go` (post-`survey` index bounds check) | Disable the returned-index bounds check in `SelectRequest` | CONFIRMED | wont-fix | none — same rationale as UI-09 | PR7 | todo |

---

## Summary

### By PR

| PR | Rows | Of which CONFIRMED |
|---|---|---|
| PR1 — Test isolation + integration harness | 2 | 0 (both OVERSTATED) |
| PR2 — Archive extraction and path security | 12 | 11 |
| PR3 — Remaining self-update correctness | 10 | 10 |
| PR4 — Argument capture | 42 | 41 |
| PR5 — Output contracts | 32 | 30 |
| PR6 — Cache and config semantics | 16 | 16 |
| PR7 — UI behavior | 10 | 10 |
| PR8 — SCA / workflows / models wire contracts | 36 | 34 |
| *(no PR — settled, recorded only)* | 5 | 0 |
| **Total** | **165** | **152** |

### By verdict

| Verdict | Rows |
|---|---|
| CONFIRMED | 152 |
| OVERSTATED | 9 |
| REFUTED | 4 |

### By disposition

| Disposition | Rows |
|---|---|
| `test` | 149 |
| `test + prod-fix` | 5 |
| `prod-fix` | 1 |
| `wont-fix` | 5 |
| `refuted` | 5 |
| **Total** | **165** |

The seven production changes, matching the plan's table:

| Row | Change | PR | CHANGELOG |
|---|---|---|---|
| SFU-07 | Reject zero-length extracted binary + apply-boundary check | PR2 | `### Security` |
| SFU-02 | UNC check before `path.IsAbs` (message only) | PR2 | no |
| OUT-26 | `favorites add` early non-interactive guard, favorites-specific message | PR1 | `### Fixed` |
| CFG-02 | `ParseCacheTTL` errors on any explicitly-invalid value | PR6 | `### Changed` |
| CACHE-07 | `maxSessionAge` → `sessionTimestampRetention` | PR6 | no (internal) |
| UI-02 | `sortGroupsForDisplay` extraction | PR7 | no (refactor) |
| SFU-10 | `syncStagedFileFn` seam | PR3 | no (test seam; **not** a production gap) |

### Total CONFIRMED

**152 CONFIRMED**, plus **9 OVERSTATED** (real survivors whose stated consequence
was weaker than originally claimed) and **4 REFUTED**. **165 rows total.**
5 rows are `wont-fix` (SFU-20, SFU-21, SFU-22, UI-09, UI-10), so **160 rows require
work**, of which 6 carry a production change.

### Reconciliation against "145"

The ledger does **not** reconcile cleanly to 145, and the rows were not padded or
truncated to make it. The gap is almost entirely *granularity* — every row traces
to a named, independently reproduced finding in a verification report.

| Batch | Verifier's stated count | Rows here | Reconciles? |
|---|---|---|---|
| 1 — cmd request/auth | 22 confirmed | 23 (22 CONFIRMED + 1 OVERSTATED) | **Yes.** The 22 CONFIRMED rows are mutation-level and match exactly. REQ-23 (integration suite absent from CI) is reported *outside* the 22. |
| 2 — cmd status/favorites/list | 25 real of 29 claimed | 29 (23 CONFIRMED, 3 OVERSTATED, 3 REFUTED) | **Approximately.** All 29 claimed items are listed so the three refutations stay recorded. 23 + 3 OVERSTATED = 26 actionable, one above the verifier's "25" — its own prose is imprecise about whether OUT-21/OUT-25/OUT-26 count as "real". |
| 3 — internal/sca + workflows | 31 + 4 extra = 35 | 38 (34 CONFIRMED, 3 OVERSTATED, 1 REFUTED) | **Yes.** 34 CONFIRMED + SCA-10 (a real survivor, only its truncation consequence overstated) = exactly 35 survivors. The other 3 rows are SCA-15 (X-API-Version coverage topology, which PR8 acts on) and SCA-17/SCA-18, recorded so they are not re-filed. |
| 4 — cmd root/elevate/env | 22 confirmed | 27 (26 CONFIRMED, 1 OVERSTATED) | **No — +5.** The report's headline groups its own sub-lettered mutations inconsistently: H2.1–2.3, H3.1–3.4, M4.1–2, M5.1–3, M6.1–6.4 and M9.1–3 are enumerated individually in the body, each with its own `go test ./cmd/ -count=1 → ok` transcript, but collapsed in the total. Listing them individually gives 25 production mutations plus 2 test-quality rows (ELV-26, ELV-27). |
| 5 — cache/config/ui/selfupdate | 44 reproduced, 41 actionable | 48 (all CONFIRMED, 4 of them `wont-fix`) | **Partly — +4.** Same granularity problem: M7 and M9 are two mutations each; L1, L3, L4 and L5 are three each; L9 is three survivors. Enumerating every reproduced mutation gives 48; removing the 4 unreachable/defensive `wont-fix` rows (SFU-20, SFU-21, UI-09, UI-10) gives **44 actionable**, matching "44 reproduced" but not "41 actionable" — the report never itemises which 3 it dropped. |

**Net: 165 rows against a headline of 145.** Roughly 9 of the excess is finer
enumeration in batches 4 and 5 (mutations the reports reproduced individually but
totalled in groups); the rest is the 13 OVERSTATED/REFUTED rows the headline count
deliberately excluded but which belong here as settled questions. Nothing was
invented and nothing was dropped to hit a number.

There are no `NEEDS-REVIEW` rows: every row's source report is unambiguous about
the mutation applied and the observed result.

---

## PR1 closure evidence

Both PR1 rows are `done`. Neither has a production mutation of its own (both are
harness rows), so each is closed against the mutation that its new assertion is
supposed to kill.

**REQ-23** — mutation: `cmd/version.go:31`, `v = "dev"` → `v = "bogus"`.

| assertion | result |
|---|---|
| old, `contains("dev") \|\| contains("unknown")` | `ok` — **survived**; `commit: unknown` satisfies the second arm regardless of the version string |
| new, `contains("grant version dev")` | `FAIL: expected a dev build banner, got: grant version bogus` |

Reverted; `go test -tags=integration ./cmd -count=1 -run TestIntegration_Version` → `ok`.
The other half of the row (integration tests absent from CI) is closed by the
`Integration tests` step running `go test -tags=integration ./cmd` on both CI legs.

**OUT-26** — mutation: `cmd/main_test.go` `TestMain`, unwrap `testenv.Run` so it
calls `installBootstrapStub(); os.Exit(m.Run())` directly.

```
--- FAIL: TestSandboxIsolation (0.00s)
    main_test.go:40: testenv.AssertSandboxed called outside testenv.Run; no sandbox is active
--- FAIL: TestCacheDirResolvesInsideSandbox (0.00s)
    main_test.go:56: no testenv sandbox is active; TestMain is not wrapping m.Run
```

Reverted; both tests `ok`. The row's second half (the `favorites add`
non-interactive guard) was mutation-verified when it landed.

**Redirect-list drop-one.** Every entry of `testenv.redirectedVars` was deleted
in turn and `go test ./cmd ./internal/config ./internal/cache ./internal/testenv
-count=1` run. Before the explicit-literal and hostile-value tests, four of five
survived (`USERPROFILE`, `XDG_CONFIG_HOME`, `IDSEC_PROFILES_FOLDER`,
`GRANT_CONFIG` — with `HOME` redirected their fallbacks already land in-sandbox).
After, all eight fail.
