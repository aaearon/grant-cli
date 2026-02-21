package cmd

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aaearon/grant-cli/internal/config"
	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/spf13/cobra"
)

// newStatusCommand creates the status cobra command with the given RunE function.
func newStatusCommand(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show authentication state and active SCA sessions",
		Long:  "Display the current authentication state and list all active elevated sessions.",
		RunE:  runFn,
	}

	cmd.Flags().StringP("provider", "p", "", "filter sessions by provider (azure, aws)")

	return cmd
}

// NewStatusCommand creates the production status command.
func NewStatusCommand() *cobra.Command {
	return newStatusCommand(func(cmd *cobra.Command, args []string) error {
		ispAuth, svc, profile, err := bootstrapSCAService()
		if err != nil {
			return err
		}

		cfg, _, err := config.LoadDefaultWithPath()
		if err != nil {
			return err
		}

		cachedLister := buildCachedLister(cfg, false, svc, nil)

		return runStatus(cmd, ispAuth, svc, cachedLister, profile)
	})
}

// NewStatusCommandWithDeps creates a status command with injected dependencies for testing.
func NewStatusCommandWithDeps(authLoader authLoader, sessionLister sessionLister, eligLister eligibilityLister) *cobra.Command {
	return newStatusCommand(func(cmd *cobra.Command, args []string) error {
		return runStatus(cmd, authLoader, sessionLister, eligLister, nil)
	})
}

func runStatus(cmd *cobra.Command, authLoader authLoader, sessionLister sessionLister, eligLister eligibilityLister, profile *models.IdsecProfile) error {
	// Load authentication state
	token, err := authLoader.LoadAuthentication(profile, true)
	if err != nil {
		if isJSONOutput() {
			return writeJSON(cmd.OutOrStdout(), statusOutput{Authenticated: false, Sessions: []sessionOutput{}})
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Not authenticated. Run 'grant login' first.\n")
		return nil
	}

	// Parse provider filter if specified
	provider, _ := cmd.Flags().GetString("provider")
	var cspFilter *scamodels.CSP
	if provider != "" {
		csp, err := parseProvider(provider)
		if err != nil {
			return err
		}
		cspFilter = &csp
	}

	// Fetch sessions and eligibility concurrently
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	data, err := fetchStatusData(ctx, sessionLister, eligLister, cspFilter)
	if err != nil {
		return err
	}

	// Resolve directory names for group sessions (best-effort)
	dirNameMap := buildDirectoryNameMap(ctx, eligLister)
	for k, v := range dirNameMap {
		if _, exists := data.nameMap[k]; !exists {
			data.nameMap[k] = v
		}
	}

	if isJSONOutput() {
		return writeStatusJSON(cmd, token.Username, data)
	}

	// Display authenticated user
	fmt.Fprintf(cmd.OutOrStdout(), "Authenticated as: %s\n", token.Username)

	// Display sessions
	if len(data.sessions.Response) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "\nNo active sessions.\n")
		return nil
	}

	// Separate cloud sessions from group sessions
	var cloudSessions, groupSessions []scamodels.SessionInfo
	for _, s := range data.sessions.Response {
		if s.IsGroupSession() {
			groupSessions = append(groupSessions, s)
		} else {
			cloudSessions = append(cloudSessions, s)
		}
	}

	fmt.Fprintf(cmd.OutOrStdout(), "\n")

	// Display cloud sessions grouped by provider
	if len(cloudSessions) > 0 {
		sessionsByProvider := groupSessionsByProvider(cloudSessions)
		for _, p := range sortedProviders(sessionsByProvider) {
			fmt.Fprintf(cmd.OutOrStdout(), "%s sessions:\n", formatProviderName(p))
			for _, session := range sessionsByProvider[p] {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", ui.FormatSessionOption(session, data.nameMap))
			}
		}
	}

	// Display group sessions
	if len(groupSessions) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "Groups sessions:\n")
		for _, session := range groupSessions {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", ui.FormatSessionOption(session, data.nameMap))
		}
	}

	return nil
}

// writeStatusJSON outputs the status as JSON.
func writeStatusJSON(cmd *cobra.Command, username string, data *statusData) error {
	out := statusOutput{
		Authenticated: true,
		Username:      username,
		Sessions:      make([]sessionOutput, 0, len(data.sessions.Response)),
	}

	for _, s := range data.sessions.Response {
		so := sessionOutput{
			SessionID:   s.SessionID,
			Provider:    strings.ToLower(string(s.CSP)),
			WorkspaceID: s.WorkspaceID,
			Duration:    s.SessionDuration,
			RoleID:      s.RoleID,
		}
		if name, ok := data.nameMap[s.WorkspaceID]; ok {
			so.WorkspaceName = name
		}
		if s.IsGroupSession() {
			so.Type = "group"
			so.GroupID = s.Target.ID
		} else {
			so.Type = "cloud"
		}
		out.Sessions = append(out.Sessions, so)
	}

	return writeJSON(cmd.OutOrStdout(), out)
}

// parseProvider converts a provider string to a CSP enum
func parseProvider(provider string) (scamodels.CSP, error) {
	switch strings.ToUpper(provider) {
	case "AZURE":
		return scamodels.CSPAzure, nil
	case "AWS":
		return scamodels.CSPAWS, nil
	default:
		return "", fmt.Errorf("invalid provider %q: must be one of: azure, aws", provider)
	}
}

// groupSessionsByProvider groups sessions by their CSP
func groupSessionsByProvider(sessions []scamodels.SessionInfo) map[string][]scamodels.SessionInfo {
	grouped := make(map[string][]scamodels.SessionInfo)
	for _, session := range sessions {
		providerName := string(session.CSP)
		grouped[providerName] = append(grouped[providerName], session)
	}
	return grouped
}

// sortedProviders returns provider names in sorted order
func sortedProviders(sessionsByProvider map[string][]scamodels.SessionInfo) []string {
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
	default:
		return provider
	}
}

