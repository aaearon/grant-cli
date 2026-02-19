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
		return fmt.Sprintf("%s (azure)", ui.FormatGroupOption(*item.group))
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

	sort.Slice(pairs, func(i, j int) bool {
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

// findItemByDisplay finds a selectionItem by its formatted display string.
func findItemByDisplay(items []selectionItem, display string) (*selectionItem, error) {
	for i := range items {
		if formatSelectionItem(items[i]) == display {
			return &items[i], nil
		}
	}
	return nil, fmt.Errorf("item not found: %s", display)
}
