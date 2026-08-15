package ui

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/Iilun/survey/v2"
	"github.com/aaearon/grant-cli/internal/sca/models"
)

// FormatGroupOption formats a groups eligible target into a display string.
func FormatGroupOption(group models.GroupsEligibleTarget) string {
	if group.DirectoryName != "" {
		return fmt.Sprintf("Directory: %s / Group: %s", group.DirectoryName, group.GroupName)
	}
	return "Group: " + group.GroupName
}

// BuildGroupOptions builds a sorted list of display options from groups eligible targets.
func BuildGroupOptions(groups []models.GroupsEligibleTarget) []string {
	if len(groups) == 0 {
		return []string{}
	}

	options := make([]string, len(groups))
	for i, group := range groups {
		options[i] = FormatGroupOption(group)
	}

	sort.Strings(options)
	return options
}

// FindGroupByDisplay finds a group by its formatted display string. SelectGroup no
// longer uses it — it resolves by index — so this has no production caller today.
// On a display collision it returns the first match in the slice it is given.
func FindGroupByDisplay(groups []models.GroupsEligibleTarget, display string) (*models.GroupsEligibleTarget, error) {
	for i := range groups {
		if FormatGroupOption(groups[i]) == display {
			return &groups[i], nil
		}
	}
	return nil, fmt.Errorf("group not found: %s", display)
}

// sortGroupsForDisplay returns a copy of groups ordered by display string, leaving
// the caller's slice untouched. It only fixes the order the options are rendered in;
// which group a selection denotes is decided by index in resolveGroupSelection.
// The sort is stable, so groups that render identically keep their input order.
func sortGroupsForDisplay(groups []models.GroupsEligibleTarget) []models.GroupsEligibleTarget {
	sorted := make([]models.GroupsEligibleTarget, len(groups))
	copy(sorted, groups)
	sort.SliceStable(sorted, func(i, j int) bool {
		return FormatGroupOption(sorted[i]) < FormatGroupOption(sorted[j])
	})
	return sorted
}

// resolveGroupSelection recovers the group at the index survey returned. Resolving by
// index rather than by display text is what makes duplicate display strings safe: the
// same group name in two directories renders identically, and a text lookup would
// return the first match no matter which row the user highlighted.
func resolveGroupSelection(sorted []models.GroupsEligibleTarget, idx int) (*models.GroupsEligibleTarget, error) {
	if idx < 0 || idx >= len(sorted) {
		return nil, fmt.Errorf("invalid group selection index %d", idx)
	}
	return &sorted[idx], nil
}

// SelectGroup presents an interactive selector for choosing a group. Uses the selected
// index (not display text) to recover the group, so duplicate display strings are safe.
func SelectGroup(groups []models.GroupsEligibleTarget) (*models.GroupsEligibleTarget, error) {
	if !IsInteractive() {
		return nil, fmt.Errorf("%w; use --group flag for non-interactive mode", ErrNotInteractive)
	}

	if len(groups) == 0 {
		return nil, errors.New("no eligible groups available")
	}

	sorted := sortGroupsForDisplay(groups)

	options := make([]string, len(sorted))
	for i := range sorted {
		options[i] = FormatGroupOption(sorted[i])
	}

	var selectedIdx int
	prompt := &survey.Select{
		Message: "Select a group:",
		Options: options,
		Filter:  nil,
	}

	if err := survey.AskOne(prompt, &selectedIdx, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)); err != nil {
		return nil, fmt.Errorf("group selection failed: %w", err)
	}

	return resolveGroupSelection(sorted, selectedIdx)
}
