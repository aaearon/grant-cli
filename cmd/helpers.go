package cmd

import (
	"context"
	"fmt"
	"io"
	"sync"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

// statusData holds the results of concurrent sessions + eligibility fetches.
type statusData struct {
	sessions *scamodels.SessionsResponse
	nameMap  map[string]string
}

// fetchStatusData fires sessions and all-CSP eligibility calls concurrently,
// then joins results. A sessions error is fatal; eligibility errors are
// gracefully degraded (empty nameMap entry, verbose warning).
func fetchStatusData(
	ctx context.Context,
	sessionLister sessionLister,
	eligLister eligibilityLister,
	cspFilter *scamodels.CSP,
	errWriter io.Writer,
) (*statusData, error) {
	type eligResult struct {
		csp     scamodels.CSP
		targets []scamodels.EligibleTarget
		err     error
	}

	var (
		sessions    *scamodels.SessionsResponse
		sessionsErr error
		wg          sync.WaitGroup
	)

	// Goroutine 1: fetch sessions
	wg.Add(1)
	go func() {
		defer wg.Done()
		sessions, sessionsErr = sessionLister.ListSessions(ctx, cspFilter)
	}()

	// Determine which CSPs to query for eligibility
	cspsToQuery := supportedCSPs
	if cspFilter != nil {
		cspsToQuery = []scamodels.CSP{*cspFilter}
	}

	// Goroutines 2..N: fetch eligibility for each CSP
	eligResults := make(chan eligResult, len(cspsToQuery))
	for _, csp := range cspsToQuery {
		wg.Add(1)
		go func(csp scamodels.CSP) {
			defer wg.Done()
			resp, err := eligLister.ListEligibility(ctx, csp)
			if err != nil || resp == nil {
				eligResults <- eligResult{csp: csp, err: err}
				return
			}
			eligResults <- eligResult{csp: csp, targets: resp.Response}
		}(csp)
	}

	// Close channel after all goroutines finish
	go func() {
		wg.Wait()
		close(eligResults)
	}()

	// Build nameMap from eligibility results
	nameMap := make(map[string]string)
	for r := range eligResults {
		if r.err != nil {
			if verbose {
				fmt.Fprintf(errWriter, "Warning: failed to fetch names for %s: %v\n", r.csp, r.err)
			}
			continue
		}
		for _, t := range r.targets {
			if t.WorkspaceName != "" {
				nameMap[t.WorkspaceID] = t.WorkspaceName
			}
		}
	}

	// Check sessions result (goroutine has finished since channel is drained after wg.Wait)
	if sessionsErr != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", sessionsErr)
	}

	return &statusData{sessions: sessions, nameMap: nameMap}, nil
}

// buildDirectoryNameMap fetches Azure cloud eligibility to resolve directoryId -> name.
// It looks for DIRECTORY-type workspace entries whose workspaceId matches a directory ID.
// Falls back to organizationId -> first workspace name if no DIRECTORY entries exist.
// Errors are silently ignored (graceful degradation — groups display without directory context).
func buildDirectoryNameMap(ctx context.Context, eligLister eligibilityLister, errWriter io.Writer) map[string]string {
	nameMap := make(map[string]string)

	resp, err := eligLister.ListEligibility(ctx, scamodels.CSPAzure)
	if err != nil {
		if verbose {
			fmt.Fprintf(errWriter, "Warning: failed to resolve directory names: %v\n", err)
		}
		return nameMap
	}

	// First pass: look for DIRECTORY-type workspaces (most specific)
	for _, t := range resp.Response {
		if t.WorkspaceType == scamodels.WorkspaceTypeDirectory && t.WorkspaceName != "" {
			nameMap[t.WorkspaceID] = t.WorkspaceName
		}
	}

	// Second pass: fall back to organizationId -> first workspace name
	// for orgs that didn't have a DIRECTORY entry
	for _, t := range resp.Response {
		if t.OrganizationID != "" && t.WorkspaceName != "" {
			if _, exists := nameMap[t.OrganizationID]; !exists {
				nameMap[t.OrganizationID] = t.WorkspaceName
			}
		}
	}

	return nameMap
}

// buildWorkspaceNameMap fetches eligibility for each unique CSP in sessions
// concurrently and builds a workspaceID -> workspaceName map. Errors are
// silently ignored (graceful degradation — the raw workspace ID is shown
// as fallback).
func buildWorkspaceNameMap(ctx context.Context, eligLister eligibilityLister, sessions []scamodels.SessionInfo, errWriter io.Writer) map[string]string {
	nameMap := make(map[string]string)

	// Collect unique CSPs
	csps := make(map[scamodels.CSP]bool)
	for _, s := range sessions {
		csps[s.CSP] = true
	}
	if len(csps) == 0 {
		return nameMap
	}

	type eligResult struct {
		csp     scamodels.CSP
		targets []scamodels.EligibleTarget
		err     error
	}

	// Fetch eligibility for each CSP concurrently
	results := make(chan eligResult, len(csps))
	var wg sync.WaitGroup
	for csp := range csps {
		wg.Add(1)
		go func(csp scamodels.CSP) {
			defer wg.Done()
			resp, err := eligLister.ListEligibility(ctx, csp)
			if err != nil || resp == nil {
				results <- eligResult{csp: csp, err: err}
				return
			}
			results <- eligResult{csp: csp, targets: resp.Response}
		}(csp)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	for r := range results {
		if r.err != nil {
			if verbose {
				fmt.Fprintf(errWriter, "Warning: failed to fetch names for %s: %v\n", r.csp, r.err)
			}
			continue
		}
		for _, t := range r.targets {
			if t.WorkspaceName != "" {
				nameMap[t.WorkspaceID] = t.WorkspaceName
			}
		}
	}

	return nameMap
}
