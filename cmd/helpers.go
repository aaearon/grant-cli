package cmd

import (
	"context"
	"fmt"
	"io"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

// buildWorkspaceNameMap fetches eligibility for each unique CSP in sessions
// and builds a workspaceID -> workspaceName map. Errors are silently ignored
// (graceful degradation — the raw workspace ID is shown as fallback).
func buildWorkspaceNameMap(ctx context.Context, eligLister eligibilityLister, sessions []scamodels.SessionInfo, errWriter io.Writer) map[string]string {
	nameMap := make(map[string]string)

	// Collect unique CSPs
	csps := make(map[scamodels.CSP]bool)
	for _, s := range sessions {
		csps[s.CSP] = true
	}

	// Fetch eligibility for each CSP
	for csp := range csps {
		if ctx.Err() != nil {
			break
		}
		resp, err := eligLister.ListEligibility(ctx, csp)
		if err != nil || resp == nil {
			if verbose && err != nil {
				fmt.Fprintf(errWriter, "Warning: failed to fetch names for %s: %v\n", csp, err)
			}
			continue
		}
		for _, target := range resp.Response {
			if target.WorkspaceName != "" {
				nameMap[target.WorkspaceID] = target.WorkspaceName
			}
		}
	}

	return nameMap
}
