package cmd

import (
	"testing"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

// duplicateGroupItems returns three selection items, the first two of which are
// distinct Entra ID groups that render identically: FormatGroupOption falls back to
// "Group: <name>" when no directory name has been cross-referenced, so the same group
// name in two different directories is indistinguishable on screen.
func duplicateGroupItems() []selectionItem {
	first := &scamodels.GroupsEligibleTarget{
		DirectoryID: "dir-first",
		GroupID:     "group-first",
		GroupName:   "Cloud Admins",
	}
	second := &scamodels.GroupsEligibleTarget{
		DirectoryID: "dir-second",
		GroupID:     "group-second",
		GroupName:   "Cloud Admins",
	}
	zebra := &scamodels.GroupsEligibleTarget{
		DirectoryID: "dir-zebra",
		GroupID:     "group-zebra",
		GroupName:   "Zebra Admins",
	}
	return []selectionItem{
		{kind: selectionGroup, group: first},
		{kind: selectionGroup, group: second},
		{kind: selectionGroup, group: zebra},
	}
}

// TestUIUnifiedSelector_PTY_DuplicateGroupDisplay pins the wiring of the selector that
// plain `grant`, `grant --groups` and `grant favorites add` actually reach. It drives
// the live survey prompt over a pty and asserts that highlighting the second of two
// identically rendered groups elevates into that group. Resolving by display string
// instead of by index must fail this test.
//
// Not parallel: newPTYSession swaps os.Stdin/os.Stderr and forceInteractive swaps
// the package-global ui.IsTerminalFunc.
func TestUIUnifiedSelector_PTY_DuplicateGroupDisplay(t *testing.T) {
	tests := []struct {
		name        string
		keys        string
		wantGroupID string
		wantDirID   string
	}{
		{
			name:        "arrow to second duplicate",
			keys:        keyDown + keyEnter,
			wantGroupID: "group-second",
			wantDirID:   "dir-second",
		},
		{
			name: "filter first, then arrow to second duplicate",
			// Typing a filter is the dangerous path: the visible rows are a subset,
			// yet survey still reports an index into the original option slice.
			keys:        "Cloud" + keyDown + keyEnter,
			wantGroupID: "group-second",
			wantDirID:   "dir-second",
		},
		{
			name:        "accept the highlighted first duplicate",
			keys:        keyEnter,
			wantGroupID: "group-first",
			wantDirID:   "dir-first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forceInteractive(t)
			p := newPTYSession(t)

			type result struct {
				item *selectionItem
				err  error
			}
			done := make(chan result, 1)
			go func() {
				s := &uiUnifiedSelector{}
				item, err := s.SelectItem(duplicateGroupItems())
				done <- result{item, err}
			}()

			p.waitFor(t, "Select a target:")
			p.send(t, tt.keys)

			got := <-done
			if got.err != nil {
				t.Fatalf("SelectItem() error = %v; screen:\n%s", got.err, p.screen())
			}
			if got.item.kind != selectionGroup {
				t.Fatalf("SelectItem() kind = %v, want selectionGroup", got.item.kind)
			}
			if got.item.group.GroupID != tt.wantGroupID {
				t.Errorf("SelectItem() GroupID = %q, want %q (wrong group selected)",
					got.item.group.GroupID, tt.wantGroupID)
			}
			if got.item.group.DirectoryID != tt.wantDirID {
				t.Errorf("SelectItem() DirectoryID = %q, want %q (wrong directory)",
					got.item.group.DirectoryID, tt.wantDirID)
			}
		})
	}
}
