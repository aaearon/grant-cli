package cmd

// Output contract tests.
//
// Each machine-facing document (status, list, elevation, env credentials,
// favorites list, access requests) gets ONE whole-object test that compares the
// emitted JSON against an inline literal via assertJSONEqual. Everything else
// about those outputs stays covered by focused tests.
//
// FIXTURE VALUES ARE DELIBERATELY ALL DIFFERENT AND SELF-DESCRIBING
// ("ws-name", "ws-id", "role-name", "role-id", "grp-id", "dir-id",
// "AKIA-fixture", "secret-fixture", "token-fixture"). A field swap — target
// with role, secret key with session token, groupId with directoryId — is
// invisible when both sides hold "test" or "", so these tests only detect one
// if every value is unique. Do not "tidy" them into shared constants or
// realistic-looking duplicates.

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/cache"
	"github.com/aaearon/grant-cli/internal/config"
	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
	wfmodels "github.com/aaearon/grant-cli/internal/workflows/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// --- status -----------------------------------------------------------------

// pinnedRemainingSeconds is the value substituted for the wall-clock-derived
// remainingSeconds field before a whole-object comparison.
const pinnedRemainingSeconds = 2700

// pinRemainingSeconds range-checks every sessions[].remainingSeconds and
// rewrites it to pinnedRemainingSeconds. The field is computed from time.Now()
// and therefore cannot appear verbatim in a literal; pinning it keeps the rest
// of the document — including whether the field is present at all — under the
// whole-object comparison.
func pinRemainingSeconds(t *testing.T, raw []byte, minSecs, maxSecs int) []byte {
	t.Helper()

	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("status output is not valid JSON: %v\nraw:\n%s", err, raw)
	}
	sessions, ok := doc["sessions"].([]interface{})
	if !ok {
		t.Fatalf("status output has no sessions array:\n%s", raw)
	}
	for _, s := range sessions {
		session, ok := s.(map[string]interface{})
		if !ok {
			t.Fatalf("session entry is not an object:\n%s", raw)
		}
		v, ok := session["remainingSeconds"]
		if !ok {
			continue
		}
		secs, ok := v.(float64)
		if !ok {
			t.Fatalf("remainingSeconds is not a number: %#v", v)
		}
		if int(secs) < minSecs || int(secs) > maxSecs {
			t.Errorf("remainingSeconds = %d, want between %d and %d", int(secs), minSecs, maxSecs)
		}
		session["remainingSeconds"] = pinnedRemainingSeconds
	}

	pinned, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-marshal failed: %v", err)
	}
	return pinned
}

// TestStatusJSON_Contract pins the whole `grant status --output json` document
// for a cloud session and a group session at once. Six independent mutations in
// writeStatusJSON survived before it existed: provider case, workspaceId,
// duration, roleId, the workspace-name lookup and the group/cloud type tag.
func TestStatusJSON_Contract(t *testing.T) {
	auth := &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt", Username: "user-fixture@example.test"}}

	sessions := &mockSessionLister{sessions: &scamodels.SessionsResponse{
		Response: []scamodels.SessionInfo{
			{
				// CSP is mixed case on purpose: strings.ToLower, strings.ToUpper
				// and the raw value are three different strings only if it is.
				SessionID: "sess-cloud", CSP: "Azure",
				WorkspaceID: "ws-id", RoleID: "role-id", SessionDuration: 3600,
			},
			{
				SessionID: "sess-group", CSP: "Azure",
				WorkspaceID: "dir-ws-id", SessionDuration: 1800,
				Target: &scamodels.SessionTarget{ID: "grp-id", Type: scamodels.TargetTypeGroups},
			},
		},
		Total: 2,
	}}

	// Names differ from the IDs that key them, so dropping the lookup is visible.
	elig := &mockEligibilityLister{response: &scamodels.EligibilityResponse{
		Response: []scamodels.EligibleTarget{
			{WorkspaceID: "ws-id", WorkspaceName: "ws-name"},
			{WorkspaceID: "dir-ws-id", WorkspaceName: "dir-ws-name"},
		},
		Total: 2,
	}}
	groupsElig := &mockGroupsEligibilityLister{response: &scamodels.GroupsEligibilityResponse{
		Response: []scamodels.GroupsEligibleTarget{
			{GroupID: "grp-id", GroupName: "grp-name", DirectoryID: "dir-id"},
		},
		Total: 1,
	}}

	tracker := cache.NewStore(t.TempDir(), 25*time.Hour)
	if err := cache.RecordSession(tracker, "sess-cloud", time.Now().Add(-15*time.Minute)); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	cmd := NewStatusCommandWithDeps(auth, sessions, elig, groupsElig, tracker)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	stdout, stderr, err := executeCommandStreams(root, "status", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// The fixture makes this deterministically 2699; the window is narrow on
	// purpose so a whole-minute arithmetic error dies at the pin itself rather
	// than relying on the sibling text assertion.
	got := pinRemainingSeconds(t, []byte(stdout), 2695, pinnedRemainingSeconds)

	assertJSONEqual(t, got, `{
  "authenticated": true,
  "username": "user-fixture@example.test",
  "sessions": [
    {
      "sessionId": "sess-cloud",
      "provider": "azure",
      "workspaceId": "ws-id",
      "workspaceName": "ws-name",
      "roleId": "role-id",
      "duration": 3600,
      "remainingSeconds": 2700,
      "type": "cloud"
    },
    {
      "sessionId": "sess-group",
      "provider": "azure",
      "workspaceId": "dir-ws-id",
      "workspaceName": "dir-ws-name",
      "duration": 1800,
      "type": "group",
      "groupId": "grp-id",
      "groupName": "grp-name"
    }
  ]
}`)
}

// TestStatus_DirectoryNameMergePrecedence pins the precedence rule in runStatus:
// a workspace name that came from eligibility wins over the directory-name
// fallback for the same key. Making the merge unconditional reverses it.
func TestStatus_DirectoryNameMergePrecedence(t *testing.T) {
	auth := &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt", Username: "user-fixture@example.test"}}

	sessions := &mockSessionLister{sessions: &scamodels.SessionsResponse{
		Response: []scamodels.SessionInfo{
			{SessionID: "sess-collide", CSP: scamodels.CSPAzure, WorkspaceID: "ws-collide", RoleID: "role-id", SessionDuration: 3600},
		},
		Total: 1,
	}}

	// The first entry teaches fetchStatusData ws-collide -> elig-name.
	// The second makes buildDirectoryNameMap produce ws-collide -> dir-fallback-name
	// for the very same key, via the organizationId fallback pass.
	elig := &mockEligibilityLister{response: &scamodels.EligibilityResponse{
		Response: []scamodels.EligibleTarget{
			{WorkspaceID: "ws-collide", WorkspaceName: "elig-name"},
			{WorkspaceID: "ws-other", WorkspaceName: "dir-fallback-name", OrganizationID: "ws-collide"},
		},
		Total: 2,
	}}

	cmd := NewStatusCommandWithDeps(auth, sessions, elig, nil, nil)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	stdout, stderr, err := executeCommandStreams(root, "status", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	var out statusOutput
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if len(out.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(out.Sessions))
	}
	if out.Sessions[0].WorkspaceName != "elig-name" {
		t.Errorf("workspaceName = %q, want elig-name (eligibility must win over the directory fallback)", out.Sessions[0].WorkspaceName)
	}
}

// TestStatus_CleansUpStaleSessionTimestamps pins the lazy cleanup call in
// runStatus: timestamps for sessions the API no longer reports are dropped.
func TestStatus_CleansUpStaleSessionTimestamps(t *testing.T) {
	auth := &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt", Username: "user-fixture@example.test"}}

	sessions := &mockSessionLister{sessions: &scamodels.SessionsResponse{
		Response: []scamodels.SessionInfo{
			{SessionID: "sess-active", CSP: scamodels.CSPAzure, WorkspaceID: "ws-id", RoleID: "role-id", SessionDuration: 3600},
		},
		Total: 1,
	}}
	elig := &mockEligibilityLister{response: &scamodels.EligibilityResponse{}}

	tracker := cache.NewStore(t.TempDir(), 25*time.Hour)
	now := time.Now()
	if err := cache.RecordSession(tracker, "sess-active", now.Add(-10*time.Minute)); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}
	if err := cache.RecordSession(tracker, "sess-gone", now.Add(-10*time.Minute)); err != nil {
		t.Fatalf("RecordSession() error = %v", err)
	}

	cmd := NewStatusCommandWithDeps(auth, sessions, elig, nil, tracker)
	if _, err := executeCommand(cmd); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	remaining := cache.SessionTimestamps(tracker)
	if _, ok := remaining["sess-gone"]; ok {
		t.Error("timestamp for an inactive session survived; status must call cache.CleanupSessions")
	}
	if _, ok := remaining["sess-active"]; !ok {
		t.Error("timestamp for the active session was removed")
	}
}

// --- list -------------------------------------------------------------------

// listContractFixture is the eligibility used by the list contract and
// round-trip tests. workspaceId, organizationId, name, role name and role id
// are five distinct strings so sourcing a field from the wrong one is visible.
func listContractFixture() []scamodels.EligibleTarget {
	return []scamodels.EligibleTarget{{
		CSP:            scamodels.CSPAzure,
		OrganizationID: "org-id",
		WorkspaceID:    "ws-id",
		WorkspaceName:  "ws-name",
		WorkspaceType:  scamodels.WorkspaceTypeSubscription,
		RoleInfo:       scamodels.RoleInfo{ID: "role-id", Name: "role-name"},
	}}
}

func listContractGroups() []scamodels.GroupsEligibleTarget {
	return []scamodels.GroupsEligibleTarget{{
		GroupName:     "grp-name",
		GroupID:       "grp-id",
		DirectoryID:   "dir-id",
		DirectoryName: "dir-name",
	}}
}

// TestListJSON_Contract pins the whole `grant list --output json` document.
// Sourcing workspaceId from organizationId, or blanking workspaceType, roleId,
// groupId or directoryId, all survived before it existed.
func TestListJSON_Contract(t *testing.T) {
	auth := &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}}
	targets := listContractFixture()
	elig := &mockEligibilityLister{
		listFunc: func(_ context.Context, csp scamodels.CSP) (*scamodels.EligibilityResponse, error) {
			if csp == scamodels.CSPAzure {
				return &scamodels.EligibilityResponse{Response: targets, Total: len(targets)}, nil
			}
			return &scamodels.EligibilityResponse{}, nil
		},
	}
	groupsElig := &mockGroupsEligibilityLister{response: &scamodels.GroupsEligibilityResponse{
		Response: listContractGroups(), Total: 1,
	}}

	cmd := NewListCommandWithDeps(auth, elig, groupsElig)
	root := newTestRootCommand()
	root.AddCommand(cmd)

	stdout, stderr, err := executeCommandStreams(root, "list", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	assertJSONEqual(t, []byte(stdout), `{
  "cloud": [
    {
      "provider": "azure",
      "target": "ws-name",
      "workspaceId": "ws-id",
      "workspaceType": "subscription",
      "role": "role-name",
      "roleId": "role-id"
    }
  ],
  "groups": [
    {
      "groupName": "grp-name",
      "groupId": "grp-id",
      "directoryId": "dir-id",
      "directory": "dir-name"
    }
  ]
}`)
}

// TestListJSON_RoundTripsToRequestSubmit is the reusability guarantee an LLM or
// script depends on: values emitted by `grant list -o json` must feed straight
// back into the flags that consume them.
//
// Note which field goes where — a verifier corrected this. `--target` resolves
// on the emitted NAME (`target`), not on `workspaceId`; `roleId` is the value
// `--role-id` takes verbatim.
func TestListJSON_RoundTripsToRequestSubmit(t *testing.T) {
	auth := &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}}
	targets := listContractFixture()
	elig := &mockEligibilityLister{
		listFunc: func(_ context.Context, csp scamodels.CSP) (*scamodels.EligibilityResponse, error) {
			if csp == scamodels.CSPAzure {
				return &scamodels.EligibilityResponse{Response: targets, Total: len(targets)}, nil
			}
			return &scamodels.EligibilityResponse{}, nil
		},
	}

	listCmd := NewListCommandWithDeps(auth, elig, &mockGroupsEligibilityLister{listErr: errNotAuthenticated})
	listRoot := newTestRootCommand()
	listRoot.AddCommand(listCmd)

	stdout, stderr, err := executeCommandStreams(listRoot, "list", "--output", "json")
	if err != nil {
		t.Fatalf("list failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	var listed listOutput
	if err := json.Unmarshal([]byte(stdout), &listed); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, stdout)
	}
	if len(listed.Cloud) != 1 {
		t.Fatalf("expected 1 cloud target, got %d", len(listed.Cloud))
	}
	emitted := listed.Cloud[0]

	// 1. The root command's --target/--role path, through the production matcher.
	resolved := findMatchingTarget(targets, emitted.Target, emitted.Role)
	if resolved == nil {
		t.Fatalf("findMatchingTarget(%q, %q) = nil; the emitted target/role do not resolve back", emitted.Target, emitted.Role)
	}
	if resolved.WorkspaceID != emitted.WorkspaceID {
		t.Errorf("resolved workspaceId = %q, emitted %q", resolved.WorkspaceID, emitted.WorkspaceID)
	}
	if resolved.RoleInfo.ID != emitted.RoleID {
		t.Errorf("resolved roleId = %q, emitted %q", resolved.RoleInfo.ID, emitted.RoleID)
	}

	// 2. `grant request submit --target <emitted target> --role-id <emitted roleId>`.
	//    Only the auth/eligibility fetch is stubbed out; the resolution itself
	//    runs the production deduplicateWorkspaces + matchWorkspaceByName pair
	//    that resolveSubmitTarget calls, so changing what --target matches on
	//    breaks this test.
	origResolve := resolveSubmitTargetFn
	t.Cleanup(func() { resolveSubmitTargetFn = origResolve })
	resolveSubmitTargetFn = func(_ context.Context, _, targetName string, _ bool) (*submitWorkspace, error) {
		if ws := matchWorkspaceByName(deduplicateWorkspaces(targets), targetName); ws != nil {
			return ws, nil
		}
		t.Errorf("emitted target %q matched no eligible workspace", targetName)
		return nil, errNotAuthenticated
	}

	svc := &mockAccessRequestService{submitResult: &wfmodels.AccessRequest{
		RequestID: "req-id", RequestState: wfmodels.RequestStatePending,
	}}
	submitRoot := newTestRootCommand()
	submitRoot.AddCommand(NewRequestCommandWithDeps(svc))

	out, err := executeCommand(submitRoot, "request", "submit",
		"--target", emitted.Target, "--role-id", emitted.RoleID, "--role", emitted.Role,
		"--reason", "reason-fixture", "--date", "2026-04-21",
		"--timezone", "UTC", "--from", "09:00", "--to", "17:00", "--yes")
	if err != nil {
		t.Fatalf("submit failed: %v\noutput: %s", err, out)
	}

	submitted := svc.lastSubmit()
	if submitted == nil {
		t.Fatal("SubmitRequest was never called")
	}
	for _, tc := range []struct{ key, want string }{
		{"workspaceId", emitted.WorkspaceID},
		{"workspaceName", emitted.Target},
		{"roleId", emitted.RoleID},
		{"roleName", emitted.Role},
	} {
		if got, _ := submitted.RequestDetails[tc.key].(string); got != tc.want {
			t.Errorf("submitted %s = %q, want %q", tc.key, got, tc.want)
		}
	}
}

// --- elevation --------------------------------------------------------------

// awsCredsFixture is the accessCredentials payload used by the elevation and
// env contract tests. The three values are distinct so swapping the secret key
// with the session token is detectable.
const awsCredsFixture = `{"aws_access_key":"AKIA-fixture","aws_secret_access_key":"secret-fixture","aws_session_token":"token-fixture"}`

func awsElevationTarget() *scamodels.EligibleTarget {
	return &scamodels.EligibleTarget{
		CSP:            scamodels.CSPAWS,
		OrganizationID: "org-id",
		WorkspaceID:    "ws-id",
		WorkspaceName:  "ws-name",
		WorkspaceType:  scamodels.WorkspaceTypeAccount,
		RoleInfo:       scamodels.RoleInfo{ID: "role-id", Name: "role-name"},
	}
}

// TestElevationJSON_Contract pins the whole cloud-elevation document, including
// the AWS credential block. Swapping target with role, dropping the provider
// lowercasing, and swapping secretAccessKey with sessionToken all survived.
func TestElevationJSON_Contract(t *testing.T) {
	creds := awsCredsFixture
	target := awsElevationTarget()

	auth := &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt", Username: "user-fixture@example.test"}}
	elig := &mockEligibilityLister{response: &scamodels.EligibilityResponse{
		Response: []scamodels.EligibleTarget{*target}, Total: 1,
	}}
	elev := &mockElevateService{response: &scamodels.ElevateResponse{Response: scamodels.ElevateAccessResult{
		CSP: scamodels.CSPAWS, OrganizationID: "org-id",
		Results: []scamodels.ElevateTargetResult{{
			WorkspaceID: "ws-id", RoleID: "role-id", SessionID: "sess-id",
			AccessCredentials: &creds,
		}},
	}}}
	sel := &mockUnifiedSelector{item: &selectionItem{kind: selectionCloud, cloud: target}}

	cmd := NewRootCommandWithDeps(nil, auth, elig, elev, sel,
		&mockGroupsEligibilityLister{listErr: errNotAuthenticated}, nil, config.DefaultConfig())

	stdout, stderr, err := executeCommandStreams(cmd, "--output", "json", "--provider", "aws")
	if err != nil {
		t.Fatalf("unexpected error: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	assertJSONEqual(t, []byte(stdout), `{
  "type": "cloud",
  "provider": "aws",
  "sessionId": "sess-id",
  "target": "ws-name",
  "role": "role-name",
  "credentials": {
    "accessKeyId": "AKIA-fixture",
    "secretAccessKey": "secret-fixture",
    "sessionToken": "token-fixture"
  }
}`)
}

// TestGroupElevationJSON_Contract pins the whole group-elevation document.
// Swapping groupId with directoryId survived before it existed.
func TestGroupElevationJSON_Contract(t *testing.T) {
	auth := &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt", Username: "user-fixture@example.test"}}
	elig := &mockEligibilityLister{response: &scamodels.EligibilityResponse{}}
	groupsElig := &mockGroupsEligibilityLister{response: &scamodels.GroupsEligibilityResponse{
		Response: []scamodels.GroupsEligibleTarget{{
			GroupName: "grp-name", GroupID: "grp-id", DirectoryID: "dir-id", DirectoryName: "dir-name",
		}},
		Total: 1,
	}}
	groupsElev := &mockGroupsElevator{response: &scamodels.GroupsElevateResponse{
		DirectoryID: "dir-id", CSP: scamodels.CSPAzure,
		Results: []scamodels.GroupsElevateTargetResult{{GroupID: "grp-id", SessionID: "sess-id"}},
	}}

	cmd := NewRootCommandWithDeps(nil, auth, elig, nil, nil, groupsElig, groupsElev, config.DefaultConfig())

	stdout, stderr, err := executeCommandStreams(cmd, "--output", "json", "--group", "grp-name")
	if err != nil {
		t.Fatalf("unexpected error: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	assertJSONEqual(t, []byte(stdout), `{
  "type": "group",
  "sessionId": "sess-id",
  "groupName": "grp-name",
  "groupId": "grp-id",
  "directoryId": "dir-id",
  "directory": "dir-name"
}`)
}

// TestEnvJSON_Contract pins `grant env --output json`. The identical swap in the
// text export path is already caught by TestEnvCommand_AWSSuccess; the JSON
// document carrying the same three secrets was unpinned.
func TestEnvJSON_Contract(t *testing.T) {
	creds := awsCredsFixture
	target := awsElevationTarget()

	auth := &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt"}}
	elig := &mockEligibilityLister{response: &scamodels.EligibilityResponse{
		Response: []scamodels.EligibleTarget{*target}, Total: 1,
	}}
	elev := &mockElevateService{response: &scamodels.ElevateResponse{Response: scamodels.ElevateAccessResult{
		CSP: scamodels.CSPAWS, OrganizationID: "org-id",
		Results: []scamodels.ElevateTargetResult{{
			WorkspaceID: "ws-id", RoleID: "role-id", SessionID: "sess-id",
			AccessCredentials: &creds,
		}},
	}}}
	sel := &mockTargetSelector{target: target}

	cmd := NewEnvCommandWithDeps(nil, auth, elig, elev, sel, config.DefaultConfig())
	root := newTestRootCommand()
	root.AddCommand(cmd)

	stdout, stderr, err := executeCommandStreams(root, "env",
		"--provider", "aws", "--target", "ws-name", "--role", "role-name", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	assertJSONEqual(t, []byte(stdout), `{
  "accessKeyId": "AKIA-fixture",
  "secretAccessKey": "secret-fixture",
  "sessionToken": "token-fixture"
}`)
}

// --- favorites --------------------------------------------------------------

// TestFavoritesListJSON_Contract pins the whole `grant favorites list -o json`
// array. Blanking provider, role or directoryId all survived: the previous test
// switched on Name and asserted only type, target and group.
func TestFavoritesListJSON_Contract(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GRANT_CONFIG", configPath)

	cfg := config.DefaultConfig()
	if err := config.AddFavorite(cfg, "fav-cloud", config.Favorite{
		Provider: "aws", Target: "ws-name", Role: "role-name",
	}); err != nil {
		t.Fatalf("AddFavorite() error = %v", err)
	}
	if err := config.AddFavorite(cfg, "fav-group", config.Favorite{
		Type: config.FavoriteTypeGroups, Provider: "azure", Group: "grp-name", DirectoryID: "dir-id",
	}); err != nil {
		t.Fatalf("AddFavorite() error = %v", err)
	}
	if err := config.Save(cfg, configPath); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	root := newTestRootCommand()
	root.AddCommand(NewFavoritesCommand())

	stdout, stderr, err := executeCommandStreams(root, "favorites", "list", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// ListFavorites sorts by name, so the order is deterministic.
	assertJSONEqual(t, []byte(stdout), `[
  {
    "name": "fav-cloud",
    "type": "cloud",
    "provider": "aws",
    "target": "ws-name",
    "role": "role-name"
  },
  {
    "name": "fav-group",
    "type": "groups",
    "provider": "azure",
    "group": "grp-name",
    "directoryId": "dir-id"
  }
]`)
}
