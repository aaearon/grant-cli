package ui

import (
	"fmt"
	"sort"

	"github.com/Iilun/survey/v2"
	"github.com/aaearon/sca-cli/internal/sca/models"
)

// FormatTargetOption formats an eligible target into a display string.
func FormatTargetOption(target models.AzureEligibleTarget) string {
	var prefix string
	switch target.WorkspaceType {
	case models.WorkspaceTypeSubscription:
		prefix = "Subscription"
	case models.WorkspaceTypeResourceGroup:
		prefix = "Resource Group"
	case models.WorkspaceTypeManagementGroup:
		prefix = "Management Group"
	case models.WorkspaceTypeDirectory:
		prefix = "Directory"
	case models.WorkspaceTypeResource:
		prefix = "Resource"
	default:
		prefix = string(target.WorkspaceType)
	}
	return fmt.Sprintf("%s: %s / Role: %s", prefix, target.WorkspaceName, target.RoleInfo.Name)
}

// BuildOptions builds a sorted list of display options from eligible targets.
func BuildOptions(targets []models.AzureEligibleTarget) []string {
	if len(targets) == 0 {
		return []string{}
	}

	options := make([]string, len(targets))
	for i, target := range targets {
		options[i] = FormatTargetOption(target)
	}

	sort.Strings(options)
	return options
}

// FindTargetByDisplay finds a target by its formatted display string.
func FindTargetByDisplay(targets []models.AzureEligibleTarget, display string) (*models.AzureEligibleTarget, error) {
	for i := range targets {
		if FormatTargetOption(targets[i]) == display {
			return &targets[i], nil
		}
	}
	return nil, fmt.Errorf("target not found: %s", display)
}

// SelectTarget presents an interactive selector for choosing a target.
func SelectTarget(targets []models.AzureEligibleTarget) (*models.AzureEligibleTarget, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no eligible targets available")
	}

	options := BuildOptions(targets)

	var selected string
	prompt := &survey.Select{
		Message: "Select a target:",
		Options: options,
		Filter:  nil, // Enable default fuzzy filter
	}

	if err := survey.AskOne(prompt, &selected); err != nil {
		return nil, fmt.Errorf("target selection failed: %w", err)
	}

	return FindTargetByDisplay(targets, selected)
}
