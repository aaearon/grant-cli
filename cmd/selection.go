package cmd

import (
	"fmt"
	"sort"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
)

type selectionKind int

const (
	selectionCloud selectionKind = iota
	selectionGroup
)

// selectionItem is a tagged union representing either a cloud target or a group target.
type selectionItem struct {
	kind  selectionKind
	cloud *scamodels.EligibleTarget
	group *scamodels.GroupsEligibleTarget
}

// groupElevationResult holds the outcome of a successful group elevation request.
type groupElevationResult struct {
	group  *scamodels.GroupsEligibleTarget
	result *scamodels.GroupsElevateTargetResult
}

// formatSelectionItem formats a selectionItem into a display string.
// Group items always show an (azure) suffix since Entra ID groups are Azure-only.
func formatSelectionItem(item selectionItem) string {
	switch item.kind {
	case selectionCloud:
		return ui.FormatTargetOption(*item.cloud)
	case selectionGroup:
		return ui.FormatGroupOption(*item.group) + " (azure)"
	default:
		return ""
	}
}

// buildUnifiedOptions builds sorted display strings and a matching sorted items slice.
func buildUnifiedOptions(items []selectionItem) ([]string, []selectionItem) {
	if len(items) == 0 {
		return []string{}, nil
	}

	// Build display strings for sorting
	type indexed struct {
		display string
		item    selectionItem
	}
	pairs := make([]indexed, len(items))
	for i, item := range items {
		pairs[i] = indexed{display: formatSelectionItem(item), item: item}
	}

	// Stable so that items which render identically keep their input order, and the
	// options slice and the sorted items slice stay index-for-index aligned.
	sort.SliceStable(pairs, func(i, j int) bool {
		return pairs[i].display < pairs[j].display
	})

	options := make([]string, len(pairs))
	sorted := make([]selectionItem, len(pairs))
	for i, p := range pairs {
		options[i] = p.display
		sorted[i] = p.item
	}

	return options, sorted
}

// resolveSelectionItem recovers the item at the index survey returned. Resolving by
// index rather than by display text is what makes duplicate display strings safe:
// formatSelectionItem carries no ID, so the same group name in two directories — or
// the same workspace name and role in two subscriptions — renders identically, and a
// text lookup would return the first match no matter which row the user highlighted.
// Out-of-range indexes are an error, never clamped: guessing a row is the bug.
func resolveSelectionItem(sorted []selectionItem, idx int) (*selectionItem, error) {
	if idx < 0 || idx >= len(sorted) {
		return nil, fmt.Errorf("invalid selection index %d", idx)
	}
	return &sorted[idx], nil
}
