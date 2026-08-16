package ui

import (
	"testing"

	"github.com/aaearon/grant-cli/internal/sca/models"
)

// duplicateTargets returns three targets, the first two of which render identically:
// FormatTargetOption carries no workspace ID, so the same workspace name and role in
// two different subscriptions is indistinguishable on screen.
func duplicateTargets() []models.EligibleTarget {
	return []models.EligibleTarget{
		{
			CSP:           models.CSPAzure,
			WorkspaceID:   "sub-first",
			WorkspaceName: "Production",
			WorkspaceType: "SUBSCRIPTION",
			RoleInfo:      models.RoleInfo{Name: "Owner"},
		},
		{
			CSP:           models.CSPAzure,
			WorkspaceID:   "sub-second",
			WorkspaceName: "Production",
			WorkspaceType: "SUBSCRIPTION",
			RoleInfo:      models.RoleInfo{Name: "Owner"},
		},
		{
			CSP:           models.CSPAzure,
			WorkspaceID:   "sub-zebra",
			WorkspaceName: "Zebra",
			WorkspaceType: "SUBSCRIPTION",
			RoleInfo:      models.RoleInfo{Name: "Reader"},
		},
	}
}

// TestSelectTarget_PTY_DuplicateDisplay pins the real SelectTarget wiring, not just
// resolveTargetSelection: it drives the live survey prompt over a pty and asserts that
// highlighting the second of two identically rendered targets returns that second
// target. Reverting SelectTarget to display-string resolution must fail this test.
//
// Not parallel: newPTYSession swaps os.Stdin/os.Stderr and forceInteractive swaps
// the package-global IsTerminalFunc.
func TestSelectTarget_PTY_DuplicateDisplay(t *testing.T) {
	tests := []struct {
		name  string
		keys  string
		wants string
	}{
		{
			name:  "arrow to second duplicate",
			keys:  keyDown + keyEnter,
			wants: "sub-second",
		},
		{
			name: "filter first, then arrow to second duplicate",
			// Typing a filter is the dangerous path: the visible rows are a subset,
			// yet survey still reports an index into the original option slice.
			keys:  "Production" + keyDown + keyEnter,
			wants: "sub-second",
		},
		{
			name:  "accept the highlighted first duplicate",
			keys:  keyEnter,
			wants: "sub-first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forceInteractive(t)
			p := newPTYSession(t)

			type result struct {
				target *models.EligibleTarget
				err    error
			}
			done := make(chan result, 1)
			go func() {
				target, err := SelectTarget(duplicateTargets())
				done <- result{target, err}
			}()

			p.waitFor(t, "Select a target:")
			p.send(t, tt.keys)

			got := <-done
			if got.err != nil {
				t.Fatalf("SelectTarget() error = %v; screen:\n%s", got.err, p.screen())
			}
			if got.target.WorkspaceID != tt.wants {
				t.Errorf("SelectTarget() WorkspaceID = %q, want %q (wrong row selected)",
					got.target.WorkspaceID, tt.wants)
			}
		})
	}
}
