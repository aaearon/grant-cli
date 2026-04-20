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

// FormatRoleOption formats an on-demand role into a display string.
// Custom roles are marked with a [custom] tag. Descriptions are truncated to 70 chars.
func FormatRoleOption(r models.OnDemandResource) string {
	name := r.ResourceName
	if r.Custom {
		name += "  [custom]"
	}
	if r.Description != "" {
		desc := r.Description
		if len(desc) > 70 {
			desc = desc[:70]
		}
		return fmt.Sprintf("%s — %s", name, desc)
	}
	return name
}

// BuildRoleOptions builds display strings in custom-first-then-alphabetic order.
// Returns a parallel slice of roles that matches the display strings by index.
func BuildRoleOptions(roles []models.OnDemandResource) ([]string, []models.OnDemandResource) {
	sorted := make([]models.OnDemandResource, len(roles))
	copy(sorted, roles)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Custom != sorted[j].Custom {
			return sorted[i].Custom
		}
		return strings.ToLower(sorted[i].ResourceName) < strings.ToLower(sorted[j].ResourceName)
	})
	opts := make([]string, len(sorted))
	for i, r := range sorted {
		opts[i] = FormatRoleOption(r)
	}
	return opts, sorted
}

// SelectRole prompts the user to pick a role from the list. Uses the selected
// index (not display text) to recover the role, so duplicate display strings are safe.
func SelectRole(roles []models.OnDemandResource) (*models.OnDemandResource, error) {
	if !IsInteractive() {
		return nil, fmt.Errorf("%w; use --role-id for non-interactive mode", ErrNotInteractive)
	}
	if len(roles) == 0 {
		return nil, errors.New("no on-demand roles available for this workspace; use --role-id if this is unexpected")
	}

	options, sorted := BuildRoleOptions(roles)

	var selectedIdx int
	prompt := &survey.Select{
		Message:  "Select a role:",
		Options:  options,
		PageSize: 15,
		Filter:   nil,
	}
	if err := survey.AskOne(prompt, &selectedIdx, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)); err != nil {
		return nil, fmt.Errorf("role selection failed: %w", err)
	}
	if selectedIdx < 0 || selectedIdx >= len(sorted) {
		return nil, fmt.Errorf("invalid role selection index %d", selectedIdx)
	}
	return &sorted[selectedIdx], nil
}
