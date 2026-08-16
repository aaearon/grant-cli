package ui

import (
	"fmt"
	"sort"

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
