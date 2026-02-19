package cmd

import (
	"context"
	"fmt"
	"sort"
	"strings"

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

		return runStatus(cmd, ispAuth, svc, svc, profile)
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
		fmt.Fprintf(cmd.OutOrStdout(), "Not authenticated. Run 'grant login' first.\n")
		return nil
	}

	// Display authenticated user
	fmt.Fprintf(cmd.OutOrStdout(), "Authenticated as: %s\n", token.Username)

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

	// List sessions
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
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
	nameMap := buildWorkspaceNameMap(ctx, eligLister, sessions.Response, cmd.ErrOrStderr())

	// Group sessions by provider
	sessionsByProvider := groupSessionsByProvider(sessions.Response)

	// Display grouped sessions
	fmt.Fprintf(cmd.OutOrStdout(), "\n")
	for _, p := range sortedProviders(sessionsByProvider) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s sessions:\n", formatProviderName(p))
		for _, session := range sessionsByProvider[p] {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", ui.FormatSessionOption(session, nameMap))
		}
	}

	return nil
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

