package cmd

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aaearon/sca-cli/internal/sca"
	sca_models "github.com/aaearon/sca-cli/internal/sca/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	auth_models "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
)

var (
	statusProvider string
)

// NewStatusCommand creates the status command
func NewStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show authentication state and active SCA sessions",
		Long:  "Display the current authentication state and list all active elevated sessions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load profile
			loader := profiles.DefaultProfilesLoader()
			profile, err := (*loader).LoadProfile("sca-cli")
			if err != nil {
				return fmt.Errorf("failed to load profile: %w", err)
			}

			// Create ISP auth
			ispAuth := auth.NewIdsecISPAuth(true)

			// Authenticate to get token (required before creating SCA service)
			_, err = ispAuth.Authenticate(profile, nil, &auth_models.IdsecSecret{Secret: ""}, false, true)
			if err != nil {
				return fmt.Errorf("authentication failed: %w", err)
			}

			// Create SCA service
			svc, err := sca.NewSCAAccessService(ispAuth)
			if err != nil {
				return fmt.Errorf("failed to create SCA service: %w", err)
			}

			return runStatus(cmd, ispAuth, svc, profile)
		},
	}

	cmd.Flags().StringVarP(&statusProvider, "provider", "p", "", "filter sessions by provider (azure, aws, gcp)")

	return cmd
}

// NewStatusCommandWithDeps creates a status command with injected dependencies for testing
func NewStatusCommandWithDeps(authLoader authLoader, sessionLister sessionLister) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show authentication state and active SCA sessions",
		Long:  "Display the current authentication state and list all active elevated sessions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatusWithDeps(cmd, authLoader, sessionLister)
		},
	}

	cmd.Flags().StringVarP(&statusProvider, "provider", "p", "", "filter sessions by provider (azure, aws, gcp)")

	return cmd
}

func runStatus(cmd *cobra.Command, authLoader authLoader, sessionLister sessionLister, profile *models.IdsecProfile) error {
	// Load authentication state
	token, err := authLoader.LoadAuthentication(profile, true)
	if err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Not authenticated. Run 'sca-cli login' first.\n")
		return nil
	}

	// Display authenticated user
	fmt.Fprintf(cmd.OutOrStdout(), "Authenticated as: %s\n", token.Username)

	// Parse provider filter if specified
	var cspFilter *sca_models.CSP
	if statusProvider != "" {
		csp, err := parseProvider(statusProvider)
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

	// Group sessions by provider
	sessionsByProvider := groupSessionsByProvider(sessions.Response)

	// Display grouped sessions
	fmt.Fprintf(cmd.OutOrStdout(), "\n")
	for _, provider := range sortedProviders(sessionsByProvider) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s sessions:\n", formatProviderName(provider))
		for _, session := range sessionsByProvider[provider] {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", formatSession(session))
		}
	}

	return nil
}

func runStatusWithDeps(cmd *cobra.Command, authLoader authLoader, sessionLister sessionLister) error {
	// Load authentication state
	token, err := authLoader.LoadAuthentication(nil, true)
	if err != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Not authenticated. Run 'sca-cli login' first.\n")
		return nil
	}

	// Display authenticated user
	fmt.Fprintf(cmd.OutOrStdout(), "Authenticated as: %s\n", token.Username)

	// Parse provider filter if specified
	var cspFilter *sca_models.CSP
	if statusProvider != "" {
		csp, err := parseProvider(statusProvider)
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

	// Group sessions by provider
	sessionsByProvider := groupSessionsByProvider(sessions.Response)

	// Display grouped sessions
	fmt.Fprintf(cmd.OutOrStdout(), "\n")
	for _, provider := range sortedProviders(sessionsByProvider) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s sessions:\n", formatProviderName(provider))
		for _, session := range sessionsByProvider[provider] {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", formatSession(session))
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

// formatSession formats a session for display.
// The live API's role_id field contains the role display name (e.g., "User Access Administrator").
// workspace_id contains the ARM resource path.
func formatSession(session sca_models.SessionInfo) string {
	durationMin := session.SessionDuration / 60
	var durationStr string
	if durationMin >= 60 {
		durationStr = fmt.Sprintf("%dh %dm", durationMin/60, durationMin%60)
	} else {
		durationStr = fmt.Sprintf("%dm", durationMin)
	}

	return fmt.Sprintf("%s on %s - duration: %s", session.RoleID, session.WorkspaceID, durationStr)
}

func init() {
	rootCmd.AddCommand(NewStatusCommand())
}
