package ui

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Iilun/survey/v2"
	wfmodels "github.com/aaearon/grant-cli/internal/workflows/models"
)

// formatSelectorTimestamp strips fractional seconds from a timestamp while preserving
// timezone offset information. Duplicated locally to avoid import cycle with cmd package.
func formatSelectorTimestamp(ts string) string {
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t.Format("2006-01-02T15:04:05Z07:00")
	}
	if i := strings.IndexByte(ts, '.'); i >= 0 {
		return ts[:i]
	}
	return ts
}

// FormatRequestOption formats an access request into a display string for the picker.
// Format: <state>  <workspaceName> / <roleName>  (by <createdBy>, <timestamp>)  [<short-id>]
func FormatRequestOption(r wfmodels.AccessRequest) string {
	workspace := r.DetailString("workspaceName")
	if workspace == "" {
		workspace = "-"
	}
	role := r.DetailString("roleName")
	if role == "" {
		role = "-"
	}
	shortID := r.RequestID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	return fmt.Sprintf("%s  %s / %s  (by %s, %s)  [%s]",
		r.RequestState,
		workspace,
		role,
		r.CreatedBy,
		formatSelectorTimestamp(r.CreatedAt),
		shortID,
	)
}

// BuildRequestOptions returns display strings and a parallel slice of requests,
// sorted by CreatedAt descending (most recent first).
func BuildRequestOptions(requests []wfmodels.AccessRequest) ([]string, []wfmodels.AccessRequest) {
	sorted := make([]wfmodels.AccessRequest, len(requests))
	copy(sorted, requests)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].CreatedAt > sorted[j].CreatedAt
	})
	opts := make([]string, len(sorted))
	for i, r := range sorted {
		opts[i] = FormatRequestOption(r)
	}
	return opts, sorted
}

// SelectRequest prompts the user to pick a request from the list. Uses the selected
// index (not display text) to recover the request, so duplicate display strings are safe.
func SelectRequest(requests []wfmodels.AccessRequest) (*wfmodels.AccessRequest, error) {
	if !IsInteractive() {
		return nil, fmt.Errorf("%w; pass the request ID as a positional argument for non-interactive mode", ErrNotInteractive)
	}
	if len(requests) == 0 {
		return nil, errors.New("no access requests available to select")
	}

	options, sorted := BuildRequestOptions(requests)

	var selectedIdx int
	prompt := &survey.Select{
		Message:  "Select a request:",
		Options:  options,
		PageSize: 15,
		Filter:   nil,
	}
	if err := survey.AskOne(prompt, &selectedIdx, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)); err != nil {
		return nil, fmt.Errorf("request selection failed: %w", err)
	}
	if selectedIdx < 0 || selectedIdx >= len(sorted) {
		return nil, fmt.Errorf("invalid request selection index %d", selectedIdx)
	}
	return &sorted[selectedIdx], nil
}
