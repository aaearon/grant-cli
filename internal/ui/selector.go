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
	case "project":
		prefix = "Project"
	case "folder":
		prefix = "Folder"
	case "gcp_organization":
		prefix = "GCP Organization"
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

// sortTargetsForDisplay returns a copy of targets ordered by display string, leaving
// the caller's slice untouched. It only fixes the order the options are rendered in;
// which target a selection denotes is decided by index in resolveTargetSelection.
// The sort is stable, so targets that render identically keep their input order.
func sortTargetsForDisplay(targets []models.EligibleTarget) []models.EligibleTarget {
	sorted := make([]models.EligibleTarget, len(targets))
	copy(sorted, targets)
	sort.SliceStable(sorted, func(i, j int) bool {
		return FormatTargetOption(sorted[i]) < FormatTargetOption(sorted[j])
	})
	return sorted
}

// resolveTargetSelection recovers the target at the index survey returned. Resolving
// by index rather than by display text is what makes duplicate display strings safe:
// FormatTargetOption carries no ID, so the same workspace name and role in two
// subscriptions or accounts renders identically, and a text lookup would return the
// first match no matter which row the user highlighted.
func resolveTargetSelection(sorted []models.EligibleTarget, idx int) (*models.EligibleTarget, error) {
	if idx < 0 || idx >= len(sorted) {
		return nil, fmt.Errorf("invalid target selection index %d", idx)
	}
	return &sorted[idx], nil
}

// SelectTarget presents an interactive selector for choosing a target. Uses the
// selected index (not display text) to recover the target, so duplicate display
// strings are safe, and renders from the same sorted copy it resolves against.
func SelectTarget(targets []models.EligibleTarget) (*models.EligibleTarget, error) {
	if !IsInteractive() {
		return nil, fmt.Errorf("%w; use --target and --role flags for non-interactive mode", ErrNotInteractive)
	}

	if len(targets) == 0 {
		return nil, errors.New("no eligible targets available")
	}

	sorted := sortTargetsForDisplay(targets)
	options := make([]string, len(sorted))
	for i := range sorted {
		options[i] = FormatTargetOption(sorted[i])
	}

	var selectedIdx int
	prompt := &survey.Select{
		Message: "Select a target:",
		Options: options,
		Filter:  nil, // Enable default fuzzy filter
	}

	if err := survey.AskOne(prompt, &selectedIdx, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)); err != nil {
		return nil, fmt.Errorf("target selection failed: %w", err)
	}

	return resolveTargetSelection(sorted, selectedIdx)
}
