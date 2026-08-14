// NOTE: Do not use t.Parallel() in cmd/ tests due to package-level state
// (verbose, passedArgValidation) that is mutated during test execution.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/cache"
	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

func testAuthLoader() *mockAuthLoader {
	expiresIn := commonmodels.IdsecRFC3339Time(time.Now().Add(1 * time.Hour))
	return &mockAuthLoader{token: &authmodels.IdsecToken{Token: "jwt", Username: "user@example.com", ExpiresIn: expiresIn}}
}

func revokeResponse(pairs ...string) *scamodels.RevokeResponse {
	results := make([]scamodels.RevocationResult, 0, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		results = append(results, scamodels.RevocationResult{SessionID: pairs[i], RevocationStatus: pairs[i+1]})
	}
	return &scamodels.RevokeResponse{Response: results}
}

// TestRevokeCommand_OutcomeClassification covers the exit-code contract:
// exit 0 only when every *requested* session was accepted by the service.
func TestRevokeCommand_OutcomeClassification(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		response       *scamodels.RevokeResponse
		wantErr        bool
		wantContain    []string
		wantNotContain []string
	}{
		{
			name:        "all revoked exits zero",
			args:        []string{"s1", "s2"},
			response:    revokeResponse("s1", scamodels.RevocationSuccessful, "s2", scamodels.RevocationSuccessful),
			wantErr:     false,
			wantContain: []string{"s1", "s2", "revoked", "SUCCESSFULLY_REVOKED", "2 of 2 requested sessions revoked"},
		},
		{
			name:        "all in progress exits zero but is not called revoked",
			args:        []string{"s1", "s2"},
			response:    revokeResponse("s1", scamodels.RevocationInProgress, "s2", scamodels.RevocationInProgress),
			wantErr:     false,
			wantContain: []string{"revocation in progress", "REVOCATION_IN_PROGRESS", "0 of 2 requested sessions revoked", "2 revocations in progress"},
		},
		{
			name:     "not applicable exits non-zero, provider-neutral wording",
			args:     []string{"s1"},
			response: revokeResponse("s1", scamodels.RevocationNotApplicable),
			wantErr:  true,
			wantContain: []string{
				"NOT revoked",
				"the service reported revocation is not applicable",
				"REVOCATION_NOT_APPLICABLE",
				"0 of 1 requested sessions revoked",
			},
			// The status proves only that the service declined to act. Naming a
			// mechanism grant never observed would be an invented explanation.
			wantNotContain: []string{"STS", "temporary credentials", "AWS"},
		},
		{
			name:        "unknown status exits non-zero and keeps the raw token",
			args:        []string{"s1"},
			response:    revokeResponse("s1", "TOTALLY_NEW_STATUS"),
			wantErr:     true,
			wantContain: []string{"NOT revoked", "unexpected status", "TOTALLY_NEW_STATUS"},
		},
		{
			name:        "empty status exits non-zero",
			args:        []string{"s1"},
			response:    revokeResponse("s1", ""),
			wantErr:     true,
			wantContain: []string{"NOT revoked", "unexpected status"},
		},
		{
			name:        "requested two, one row returned",
			args:        []string{"s1", "s2"},
			response:    revokeResponse("s1", scamodels.RevocationSuccessful),
			wantErr:     true,
			wantContain: []string{"s2", "no result returned", "1 of 2 requested sessions revoked"},
		},
		{
			name:        "empty response array reports every requested session",
			args:        []string{"s1", "s2"},
			response:    &scamodels.RevokeResponse{Response: []scamodels.RevocationResult{}},
			wantErr:     true,
			wantContain: []string{"s1", "s2", "no result returned", "0 of 2 requested sessions revoked"},
		},
		{
			name:        "partial exits non-zero",
			args:        []string{"s1", "s2"},
			response:    revokeResponse("s1", scamodels.RevocationSuccessful, "s2", scamodels.RevocationNotApplicable),
			wantErr:     true,
			wantContain: []string{"revoked (SUCCESSFULLY_REVOKED)", "NOT revoked", "1 of 2 requested sessions revoked", "1 not revoked"},
		},
		{
			name:        "partial with in-progress distinguishes the two",
			args:        []string{"s1", "s2"},
			response:    revokeResponse("s1", scamodels.RevocationInProgress, "s2", scamodels.RevocationNotApplicable),
			wantErr:     true,
			wantContain: []string{"0 of 2 requested sessions revoked", "1 revocation in progress", "1 not revoked"},
		},
		{
			name:        "unexpected ID is surfaced but satisfies nothing",
			args:        []string{"s1"},
			response:    revokeResponse("s1", scamodels.RevocationSuccessful, "zz", scamodels.RevocationSuccessful),
			wantErr:     false,
			wantContain: []string{"unexpected result", "zz"},
		},
		{
			name:        "duplicate request IDs are deduplicated",
			args:        []string{"s1", "s1"},
			response:    revokeResponse("s1", scamodels.RevocationSuccessful),
			wantErr:     false,
			wantContain: []string{"1 of 1 requested sessions revoked"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			revoker := &mockSessionRevoker{response: tt.response}
			cmd := NewRevokeCommandWithDeps(testAuthLoader(), &mockSessionLister{}, &mockEligibilityLister{},
				revoker, &mockSessionSelector{}, &mockConfirmPrompter{})

			output, err := executeCommand(cmd, tt.args...)

			if tt.wantErr && err == nil {
				t.Errorf("expected an error (exit 1) but got none\noutput:\n%s", output)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v\noutput:\n%s", err, output)
			}
			for _, want := range tt.wantContain {
				if !strings.Contains(output, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, output)
				}
			}
			for _, notWant := range tt.wantNotContain {
				if strings.Contains(output, notWant) {
					t.Errorf("output must not contain %q\ngot:\n%s", notWant, output)
				}
			}
		})
	}
}

// TestRevokeCommand_ProviderNeutralWording asserts the not-applicable wording
// does not vary by CSP.
func TestRevokeCommand_ProviderNeutralWording(t *testing.T) {
	render := func(csp scamodels.CSP) string {
		lister := &mockSessionLister{sessions: &scamodels.SessionsResponse{
			Response: []scamodels.SessionInfo{
				{SessionID: "s1", CSP: csp, WorkspaceID: "ws", RoleID: "Admin", SessionDuration: 3600},
			},
			Total: 1,
		}}
		revoker := &mockSessionRevoker{response: revokeResponse("s1", scamodels.RevocationNotApplicable)}
		cmd := NewRevokeCommandWithDeps(testAuthLoader(), lister, &mockEligibilityLister{},
			revoker, &mockSessionSelector{}, &mockConfirmPrompter{})
		out, err := executeCommand(cmd, "--all", "--yes")
		if err == nil {
			t.Fatalf("expected an error for a not-applicable revocation (%s)", csp)
		}
		return out
	}

	aws := render(scamodels.CSPAWS)
	azure := render(scamodels.CSPAzure)

	const phrase = "the service reported revocation is not applicable"
	if !strings.Contains(aws, phrase) || !strings.Contains(azure, phrase) {
		t.Fatalf("expected identical provider-neutral wording\naws:\n%s\nazure:\n%s", aws, azure)
	}
	for _, banned := range []string{"STS", "temporary credentials"} {
		if strings.Contains(aws, banned) {
			t.Errorf("AWS output must not claim a mechanism grant did not observe (%q)\n%s", banned, aws)
		}
	}
}

// TestRevokeCommand_BatchesOverAPILimit verifies --all across more than 100
// sessions is chunked to the API's 100-ID cap and fully accounted for.
func TestRevokeCommand_BatchesOverAPILimit(t *testing.T) {
	const total = 150

	sessions := make([]scamodels.SessionInfo, total)
	for i := range sessions {
		sessions[i] = scamodels.SessionInfo{
			SessionID:       fmt.Sprintf("s%03d", i),
			CSP:             scamodels.CSPAzure,
			WorkspaceID:     "ws",
			RoleID:          "Reader",
			SessionDuration: 3600,
		}
	}

	revoker := &mockSessionRevoker{
		revokeFunc: func(ctx context.Context, req *scamodels.RevokeRequest) (*scamodels.RevokeResponse, error) {
			if len(req.SessionIDs) > scamodels.MaxRevokeBatchSize {
				t.Errorf("sent %d session IDs, exceeding the API cap of %d", len(req.SessionIDs), scamodels.MaxRevokeBatchSize)
			}
			results := make([]scamodels.RevocationResult, len(req.SessionIDs))
			for i, id := range req.SessionIDs {
				results[i] = scamodels.RevocationResult{SessionID: id, RevocationStatus: scamodels.RevocationSuccessful}
			}
			return &scamodels.RevokeResponse{Response: results}, nil
		},
	}

	lister := &mockSessionLister{sessions: &scamodels.SessionsResponse{Response: sessions, Total: total}}
	cmd := NewRevokeCommandWithDeps(testAuthLoader(), lister, &mockEligibilityLister{},
		revoker, &mockSessionSelector{}, &mockConfirmPrompter{})

	output, err := executeCommand(cmd, "--all", "--yes")
	if err != nil {
		t.Fatalf("unexpected error: %v\n%s", err, output)
	}
	if len(revoker.calls) != 2 {
		t.Errorf("made %d revoke calls, want 2", len(revoker.calls))
	}
	for _, s := range sessions {
		if !strings.Contains(output, s.SessionID) {
			t.Fatalf("output missing session %s", s.SessionID)
		}
	}
	if !strings.Contains(output, "150 of 150 requested sessions revoked") {
		t.Errorf("expected all 150 accounted for, got:\n%s", output)
	}
}

// TestRevokeCommand_BatchErrorKeepsEarlierOutcomes asserts a mid-sequence batch
// failure still reports what is known.
func TestRevokeCommand_BatchErrorKeepsEarlierOutcomes(t *testing.T) {
	const total = 150

	sessions := make([]scamodels.SessionInfo, total)
	for i := range sessions {
		sessions[i] = scamodels.SessionInfo{SessionID: fmt.Sprintf("s%03d", i), CSP: scamodels.CSPAzure, SessionDuration: 3600}
	}

	call := 0
	revoker := &mockSessionRevoker{
		revokeFunc: func(ctx context.Context, req *scamodels.RevokeRequest) (*scamodels.RevokeResponse, error) {
			call++
			if call == 2 {
				return nil, errors.New("service unavailable")
			}
			results := make([]scamodels.RevocationResult, len(req.SessionIDs))
			for i, id := range req.SessionIDs {
				results[i] = scamodels.RevocationResult{SessionID: id, RevocationStatus: scamodels.RevocationSuccessful}
			}
			return &scamodels.RevokeResponse{Response: results}, nil
		},
	}

	lister := &mockSessionLister{sessions: &scamodels.SessionsResponse{Response: sessions, Total: total}}
	cmd := NewRevokeCommandWithDeps(testAuthLoader(), lister, &mockEligibilityLister{},
		revoker, &mockSessionSelector{}, &mockConfirmPrompter{})

	output, err := executeCommand(cmd, "--all", "--yes")
	if err == nil {
		t.Fatal("expected an error from the failing batch")
	}
	if !strings.Contains(output, "service unavailable") {
		t.Errorf("expected the transport error to be reported, got:\n%s", output)
	}
	if !strings.Contains(output, "100 of 150 requested sessions revoked") {
		t.Errorf("expected the first batch's outcomes to survive, got:\n%s", output)
	}
	if !strings.Contains(output, "s149") {
		t.Errorf("expected the unattempted sessions to be reported, got:\n%s", output)
	}
}

// TestRevokeCommand_ExpiryNote covers the best-effort expiry hint. The clock is
// pinned; deriving the expectation from time.Now() would straddle a minute
// boundary and flake.
func TestRevokeCommand_ExpiryNote(t *testing.T) {
	elevatedAt := time.Now().Add(-20 * time.Minute)
	pinned := elevatedAt.Add(20 * time.Minute)

	tracker := cache.NewStore(t.TempDir(), 25*time.Hour)
	if err := cache.RecordSession(tracker, "s1", elevatedAt); err != nil {
		t.Fatalf("failed to seed tracker: %v", err)
	}

	lister := &mockSessionLister{sessions: &scamodels.SessionsResponse{
		Response: []scamodels.SessionInfo{
			{SessionID: "s1", CSP: scamodels.CSPAzure, WorkspaceID: "ws", RoleID: "Admin", SessionDuration: 3600},
		},
		Total: 1,
	}}
	revoker := &mockSessionRevoker{response: revokeResponse("s1", scamodels.RevocationNotApplicable)}

	cmd := newRevokeCommandWithClock(testAuthLoader(), lister, &mockEligibilityLister{}, revoker,
		&mockSessionSelector{}, &mockConfirmPrompter{}, tracker, func() time.Time { return pinned })

	output, err := executeCommand(cmd, "--all", "--yes")
	if err == nil {
		t.Fatal("expected an error for a not-applicable revocation")
	}
	if !strings.Contains(output, "expires in ~40m") {
		t.Errorf("expected the expiry note, got:\n%s", output)
	}
}

// TestRevokeCommand_ExpiryNoteAbsentInDirectMode: direct mode has bare IDs and
// no session metadata, so no expiry can be claimed.
func TestRevokeCommand_ExpiryNoteAbsentInDirectMode(t *testing.T) {
	elevatedAt := time.Now().Add(-20 * time.Minute)
	tracker := cache.NewStore(t.TempDir(), 25*time.Hour)
	if err := cache.RecordSession(tracker, "s1", elevatedAt); err != nil {
		t.Fatalf("failed to seed tracker: %v", err)
	}

	revoker := &mockSessionRevoker{response: revokeResponse("s1", scamodels.RevocationNotApplicable)}
	cmd := newRevokeCommandWithClock(testAuthLoader(), &mockSessionLister{}, &mockEligibilityLister{}, revoker,
		&mockSessionSelector{}, &mockConfirmPrompter{}, tracker, func() time.Time { return elevatedAt.Add(20 * time.Minute) })

	output, err := executeCommand(cmd, "s1")
	if err == nil {
		t.Fatal("expected an error for a not-applicable revocation")
	}
	if strings.Contains(output, "expires in") {
		t.Errorf("direct mode has no session metadata, so no expiry may be claimed:\n%s", output)
	}
}

// TestRevokeCommand_EmptySelection: selecting nothing is a no-op, not a
// revocation of nothing. It must never reach the API.
func TestRevokeCommand_EmptySelection(t *testing.T) {
	lister := &mockSessionLister{sessions: &scamodels.SessionsResponse{
		Response: []scamodels.SessionInfo{
			{SessionID: "s1", CSP: scamodels.CSPAzure, WorkspaceID: "ws", RoleID: "Admin", SessionDuration: 3600},
		},
		Total: 1,
	}}
	revoker := &mockSessionRevoker{}
	confirmer := &mockConfirmPrompter{
		confirmFunc: func(count int) (bool, error) {
			t.Error("confirmation must not be requested when nothing was selected")
			return false, nil
		},
	}

	cmd := NewRevokeCommandWithDeps(testAuthLoader(), lister, &mockEligibilityLister{},
		revoker, &mockSessionSelector{sessions: nil}, confirmer)

	output, err := executeCommand(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v\n%s", err, output)
	}
	if !strings.Contains(output, "No sessions selected") {
		t.Errorf("expected the no-op to be reported, got:\n%s", output)
	}
	if len(revoker.calls) != 0 {
		t.Errorf("made %d revoke calls, want 0", len(revoker.calls))
	}
}

func TestRevokeCommand_JSONOutcomes(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		response *scamodels.RevokeResponse
		wantErr  bool
		check    func(t *testing.T, parsed []revocationOutput)
	}{
		{
			name:     "all revoked",
			args:     []string{"s1", "s2"},
			response: revokeResponse("s1", scamodels.RevocationSuccessful, "s2", scamodels.RevocationSuccessful),
			check: func(t *testing.T, parsed []revocationOutput) {
				if len(parsed) != 2 {
					t.Fatalf("got %d entries, want 2", len(parsed))
				}
				for _, p := range parsed {
					if p.Outcome != string(scamodels.OutcomeRevoked) || !p.Accepted || !p.Complete {
						t.Errorf("entry = %+v, want outcome=revoked accepted=true complete=true", p)
					}
					if p.Status != scamodels.RevocationSuccessful {
						t.Errorf("status = %q, want the raw API value", p.Status)
					}
				}
			},
		},
		{
			name:     "in progress is accepted but not complete",
			args:     []string{"s1"},
			response: revokeResponse("s1", scamodels.RevocationInProgress),
			check: func(t *testing.T, parsed []revocationOutput) {
				if parsed[0].Outcome != string(scamodels.OutcomeInProgress) {
					t.Errorf("outcome = %q, want in_progress", parsed[0].Outcome)
				}
				if !parsed[0].Accepted || parsed[0].Complete {
					t.Errorf("entry = %+v, want accepted=true complete=false", parsed[0])
				}
			},
		},
		{
			name:     "partial keeps a reason on the refused entry",
			args:     []string{"s1", "s2"},
			response: revokeResponse("s1", scamodels.RevocationSuccessful, "s2", scamodels.RevocationNotApplicable),
			wantErr:  true,
			check: func(t *testing.T, parsed []revocationOutput) {
				if len(parsed) != 2 {
					t.Fatalf("got %d entries, want 2", len(parsed))
				}
				if parsed[1].Accepted || parsed[1].Reason == "" {
					t.Errorf("entry = %+v, want accepted=false with a reason", parsed[1])
				}
			},
		},
		{
			name:     "missing session appears with an empty status",
			args:     []string{"s1", "s2"},
			response: revokeResponse("s1", scamodels.RevocationSuccessful),
			wantErr:  true,
			check: func(t *testing.T, parsed []revocationOutput) {
				if len(parsed) != 2 {
					t.Fatalf("got %d entries, want one per requested session", len(parsed))
				}
				if parsed[1].SessionID != "s2" || parsed[1].Status != "" || parsed[1].Outcome != string(scamodels.OutcomeUnknown) {
					t.Errorf("entry = %+v, want s2 with empty status and outcome unknown", parsed[1])
				}
			},
		},
		{
			name:     "unattributed row is never a success, whatever its status",
			args:     []string{"s1"},
			response: revokeResponse("s1", scamodels.RevocationSuccessful, "zz", scamodels.RevocationSuccessful),
			check: func(t *testing.T, parsed []revocationOutput) {
				if len(parsed) != 2 {
					t.Fatalf("got %d entries, want the requested session plus the unattributed row", len(parsed))
				}
				u := parsed[1]
				if !u.Unexpected || u.SessionID != "zz" {
					t.Fatalf("entry = %+v, want the unattributed zz row", u)
				}
				// outcome and the accepted/complete axes must agree: a row grant
				// never requested is not a success by any reading.
				if u.Outcome != string(scamodels.OutcomeUnknown) {
					t.Errorf("outcome = %q, want unknown", u.Outcome)
				}
				if u.Accepted || u.Complete {
					t.Errorf("entry = %+v, want accepted=false complete=false", u)
				}
				if u.Status != scamodels.RevocationSuccessful {
					t.Errorf("status = %q, want the raw API value preserved", u.Status)
				}
			},
		},
		{
			name:     "unattributed row with an empty session ID is never a success",
			args:     []string{"s1"},
			response: revokeResponse("s1", scamodels.RevocationSuccessful, "", scamodels.RevocationInProgress),
			check: func(t *testing.T, parsed []revocationOutput) {
				u := parsed[len(parsed)-1]
				if !u.Unexpected || u.SessionID != "" {
					t.Fatalf("entry = %+v, want the unattributable empty-ID row", u)
				}
				if u.Outcome != string(scamodels.OutcomeUnknown) || u.Accepted || u.Complete {
					t.Errorf("entry = %+v, want outcome=unknown accepted=false complete=false", u)
				}
			},
		},
		{
			name:     "unknown status preserves the raw value",
			args:     []string{"s1"},
			response: revokeResponse("s1", "TOTALLY_NEW_STATUS"),
			wantErr:  true,
			check: func(t *testing.T, parsed []revocationOutput) {
				if parsed[0].Status != "TOTALLY_NEW_STATUS" {
					t.Errorf("status = %q, want the raw API value", parsed[0].Status)
				}
				if parsed[0].Outcome != string(scamodels.OutcomeUnknown) {
					t.Errorf("outcome = %q, want unknown", parsed[0].Outcome)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			revoker := &mockSessionRevoker{response: tt.response}
			cmd := NewRevokeCommandWithDeps(testAuthLoader(), &mockSessionLister{}, &mockEligibilityLister{},
				revoker, &mockSessionSelector{}, &mockConfirmPrompter{})
			root := newTestRootCommand()
			root.AddCommand(cmd)

			args := append([]string{"revoke"}, tt.args...)
			args = append(args, "--yes", "--output", "json")
			stdout, _, err := executeCommandStreams(root, args...)

			if tt.wantErr && err == nil {
				t.Errorf("expected an error (exit 1) but got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			// JSON must be complete and valid even when the command exits 1.
			var parsed []revocationOutput
			if uerr := json.Unmarshal([]byte(stdout), &parsed); uerr != nil {
				t.Fatalf("invalid JSON on stdout: %v\n%s", uerr, stdout)
			}
			if strings.Contains(stdout, `"revoked":true`) || strings.Contains(stdout, `"revoked": true`) {
				t.Errorf("JSON must never carry a revoked boolean:\n%s", stdout)
			}
			tt.check(t, parsed)
		})
	}
}
