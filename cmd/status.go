package cmd

import (
	"context"
	"fmt"
	"sort"
	"strings"

	sca_models "github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/spf13/cobra"
)

// NewStatusCommand creates the status command
func NewStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show authentication state and active SCA sessions",
		Long:  "Display the current authentication state and list all active elevated sessions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			ispAuth, svc, profile, err := bootstrapSCAService()
			if err != nil {
				return err
			}

			return runStatus(cmd, ispAuth, svc, svc, profile)
		},
	}

	cmd.Flags().StringP("provider", "p", "", "filter sessions by provider (azure, aws, gcp)")

	return cmd
}

// NewStatusCommandWithDeps creates a status command with injected dependencies for testing
func NewStatusCommandWithDeps(authLoader authLoader, sessionLister sessionLister, eligLister eligibilityLister) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show authentication state and active SCA sessions",
		Long:  "Display the current authentication state and list all active elevated sessions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd, authLoader, sessionLister, eligLister, nil)
		},
	}

	cmd.Flags().StringP("provider", "p", "", "filter sessions by provider (azure, aws, gcp)")

	return cmd
}

func runStatus(cmd *cobra.Command, authLoader authLoader, sessionLister sessionLister, eligLister eligibilityLister, profile *models.IdsecProfile) error {
	// Load authentication state
	token, err := authLoader.LoadAuthentication(profile, true)
	if err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Not authenticated. Run 'grant login' first.\n")
		return nil
	}

	// Display authenticated user
	fmt.Fprintf(cmd.OutOrStdout(), "Authenticated as: %s\n", token.Username)

	// Parse provider filter if specified
	provider, _ := cmd.Flags().GetString("provider")
	var cspFilter *sca_models.CSP
	if provider != "" {
		csp, err := parseProvider(provider)
		if err != nil {
			return err
		}
		cspFilter = &csp
	}

	// List sessions
	ctx := context.Background()
	sessions, err := sessionLister.ListSessions(ctx, cspFilter)
	if err != nil {
		return fmt.Errorf("failed to list sessions: %w", err)
	}

	// Display sessions
	if len(sessions.Response) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "\nNo active sessions.\n")
		return nil
	}

	// Build workspace name map from eligibility data
	nameMap := buildWorkspaceNameMap(ctx, eligLister, sessions.Response)

	// Group sessions by provider
	sessionsByProvider := groupSessionsByProvider(sessions.Response)

	// Display grouped sessions
	fmt.Fprintf(cmd.OutOrStdout(), "\n")
	for _, p := range sortedProviders(sessionsByProvider) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s sessions:\n", formatProviderName(p))
		for _, session := range sessionsByProvider[p] {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", formatSession(session, nameMap))
		}
	}

	return nil
}

// parseProvider converts a provider string to a CSP enum
func parseProvider(provider string) (sca_models.CSP, error) {
	switch strings.ToUpper(provider) {
	case "AZURE":
		return sca_models.CSPAzure, nil
	case "AWS":
		return sca_models.CSPAWS, nil
	case "GCP":
		return sca_models.CSPGCP, nil
	default:
		return "", fmt.Errorf("invalid provider %q: must be one of: azure, aws, gcp", provider)
	}
}

// groupSessionsByProvider groups sessions by their CSP
func groupSessionsByProvider(sessions []sca_models.SessionInfo) map[string][]sca_models.SessionInfo {
	grouped := make(map[string][]sca_models.SessionInfo)
	for _, session := range sessions {
		providerName := string(session.CSP)
		grouped[providerName] = append(grouped[providerName], session)
	}
	return grouped
}

// sortedProviders returns provider names in sorted order
func sortedProviders(sessionsByProvider map[string][]sca_models.SessionInfo) []string {
	providers := make([]string, 0, len(sessionsByProvider))
	for provider := range sessionsByProvider {
		providers = append(providers, provider)
	}
	sort.Strings(providers)
	return providers
}

// formatProviderName formats a provider name for display
func formatProviderName(provider string) string {
	switch provider {
	case "AZURE":
		return "Azure"
	case "AWS":
		return "AWS"
	case "GCP":
		return "GCP"
	default:
		return provider
	}
}

// buildWorkspaceNameMap fetches eligibility for each unique CSP in sessions
// and builds a workspaceID -> workspaceName map. Errors are silently ignored
// (graceful degradation — the raw workspace ID is shown as fallback).
func buildWorkspaceNameMap(ctx context.Context, eligLister eligibilityLister, sessions []sca_models.SessionInfo) map[string]string {
	nameMap := make(map[string]string)

	// Collect unique CSPs
	csps := make(map[sca_models.CSP]bool)
	for _, s := range sessions {
		csps[s.CSP] = true
	}

	// Fetch eligibility for each CSP
	for csp := range csps {
		resp, err := eligLister.ListEligibility(ctx, csp)
		if err != nil || resp == nil {
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

// formatSession formats a session for display.
// The live API's role_id field contains the role display name (e.g., "User Access Administrator").
// workspace_id contains the ARM resource path. If a friendly name is available from
// the eligibility API, it is shown as "name (path)"; otherwise the raw path is shown.
func formatSession(session sca_models.SessionInfo, nameMap map[string]string) string {
	durationMin := session.SessionDuration / 60
	var durationStr string
	if durationMin >= 60 {
		durationStr = fmt.Sprintf("%dh %dm", durationMin/60, durationMin%60)
	} else {
		durationStr = fmt.Sprintf("%dm", durationMin)
	}

	workspace := session.WorkspaceID
	if name, ok := nameMap[session.WorkspaceID]; ok {
		workspace = fmt.Sprintf("%s (%s)", name, session.WorkspaceID)
	}

	return fmt.Sprintf("%s on %s - duration: %s", session.RoleID, workspace, durationStr)
}

func init() {
	rootCmd.AddCommand(NewStatusCommand())
}
