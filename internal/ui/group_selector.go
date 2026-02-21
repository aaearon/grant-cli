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

// FindGroupByDisplay finds a group by its formatted display string.
func FindGroupByDisplay(groups []models.GroupsEligibleTarget, display string) (*models.GroupsEligibleTarget, error) {
	for i := range groups {
		if FormatGroupOption(groups[i]) == display {
			return &groups[i], nil
		}
	}
	return nil, fmt.Errorf("group not found: %s", display)
}

// SelectGroup presents an interactive selector for choosing a group.
// It sorts a copy of the groups so that FindGroupByDisplay searches the same
// ordered slice the user saw, avoiding wrong-group selection on display collisions.
func SelectGroup(groups []models.GroupsEligibleTarget) (*models.GroupsEligibleTarget, error) {
	if len(groups) == 0 {
		return nil, errors.New("no eligible groups available")
	}

	sorted := make([]models.GroupsEligibleTarget, len(groups))
	copy(sorted, groups)
	sort.Slice(sorted, func(i, j int) bool {
		return FormatGroupOption(sorted[i]) < FormatGroupOption(sorted[j])
	})

	options := make([]string, len(sorted))
	for i := range sorted {
		options[i] = FormatGroupOption(sorted[i])
	}

	var selected string
	prompt := &survey.Select{
		Message: "Select a group:",
		Options: options,
		Filter:  nil,
	}

	if err := survey.AskOne(prompt, &selected, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)); err != nil {
		return nil, fmt.Errorf("group selection failed: %w", err)
	}

	return FindGroupByDisplay(sorted, selected)
}
