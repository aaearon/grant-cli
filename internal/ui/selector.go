// Package ui provides interactive selection prompts for the CLI.
package ui

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/Iilun/survey/v2"
	"github.com/aaearon/grant-cli/internal/sca/models"
)

// FormatTargetOption formats an eligible target into a display string.
func FormatTargetOption(target models.EligibleTarget) string {
	var prefix string
	switch strings.ToLower(string(target.WorkspaceType)) {
	case "subscription":
		prefix = "Subscription"
	case "resource_group":
		prefix = "Resource Group"
	case "management_group":
		prefix = "Management Group"
	case "directory":
		prefix = "Directory"
	case "resource":
		prefix = "Resource"
	case "account":
		prefix = "Account"
	default:
		prefix = string(target.WorkspaceType)
	}
	base := fmt.Sprintf("%s: %s / Role: %s", prefix, target.WorkspaceName, target.RoleInfo.Name)
	if target.CSP != "" {
		return fmt.Sprintf("%s (%s)", base, strings.ToLower(string(target.CSP)))
	}
	return base
}

// BuildOptions builds a sorted list of display options from eligible targets.
func BuildOptions(targets []models.EligibleTarget) []string {
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
func FindTargetByDisplay(targets []models.EligibleTarget, display string) (*models.EligibleTarget, error) {
	for i := range targets {
		if FormatTargetOption(targets[i]) == display {
			return &targets[i], nil
		}
	}
	return nil, fmt.Errorf("target not found: %s", display)
}

// SelectTarget presents an interactive selector for choosing a target.
func SelectTarget(targets []models.EligibleTarget) (*models.EligibleTarget, error) {
	if len(targets) == 0 {
		return nil, errors.New("no eligible targets available")
	}

	options := BuildOptions(targets)

	var selected string
	prompt := &survey.Select{
		Message: "Select a target:",
		Options: options,
		Filter:  nil, // Enable default fuzzy filter
	}

	if err := survey.AskOne(prompt, &selected, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)); err != nil {
		return nil, fmt.Errorf("target selection failed: %w", err)
	}

	return FindTargetByDisplay(targets, selected)
}
