package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca"
	"github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	sdk_config "github.com/cyberark/idsec-sdk-golang/pkg/config"
	sdk_models "github.com/cyberark/idsec-sdk-golang/pkg/models"
	auth_models "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
)

var verbose bool

// elevateFlags holds the command-line flags for elevation
type elevateFlags struct {
	provider string
	target   string
	role     string
	favorite string
}

// newRootCommand creates the root cobra command with the given RunE function.
// All flag registration and PersistentPreRunE setup is centralized here.
func newRootCommand(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Request temporary elevated cloud permissions",
		Long: `Grant temporary elevated cloud permissions via CyberArk Secure Cloud Access (SCA).

Running grant with no subcommand requests access elevation.

Three execution modes:
1. Interactive mode (no flags): Select target interactively
2. Direct mode (--target and --role): Directly specify target and role
3. Favorite mode (--favorite): Use a saved favorite

Examples:
  # Interactive selection
  grant

  # Direct selection
  grant --target "Prod-EastUS" --role "Contributor"

  # Use a favorite
  grant --favorite prod-contrib

  # Specify provider explicitly
  grant --provider azure`,
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				sdk_config.EnableVerboseLogging("INFO")
			} else {
				sdk_config.DisableVerboseLogging()
			}
			return nil
		},
		RunE: runFn,
	}

	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	cmd.Flags().StringP("provider", "p", "", "Cloud provider (default from config, v1: azure only)")
	cmd.Flags().StringP("target", "t", "", "Target name (subscription, resource group, etc.)")
	cmd.Flags().StringP("role", "r", "", "Role name")
	cmd.Flags().StringP("favorite", "f", "", "Use a saved favorite alias")

	return cmd
}

var rootCmd = newRootCommand(runElevateProduction)

// runElevateProduction is the production RunE for the root command
func runElevateProduction(cmd *cobra.Command, args []string) error {
	flags := &elevateFlags{}
	flags.provider, _ = cmd.Flags().GetString("provider")
	flags.target, _ = cmd.Flags().GetString("target")
	flags.role, _ = cmd.Flags().GetString("role")
	flags.favorite, _ = cmd.Flags().GetString("favorite")

	// Load config
	cfgPath, err := config.ConfigPath()
	if err != nil {
		return fmt.Errorf("failed to determine config path: %w", err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Load profile
	loader := profiles.DefaultProfilesLoader()
	profile, err := (*loader).LoadProfile("grant")
	if err != nil {
		return fmt.Errorf("failed to load profile: %w", err)
	}

	// Create ISP authenticator
	ispAuth := auth.NewIdsecISPAuth(true)

	// Authenticate to get token (required before creating SCA service)
	_, err = ispAuth.Authenticate(profile, nil, &auth_models.IdsecSecret{Secret: ""}, false, true)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Create SCA service
	scaService, err := sca.NewSCAAccessService(ispAuth)
	if err != nil {
		return fmt.Errorf("failed to create SCA service: %w", err)
	}

	return runElevateWithDeps(cmd, flags, profile, ispAuth, scaService, scaService, &uiSelector{}, cfg)
}

// NewRootCommandWithDeps creates a root command with injected dependencies for testing
func NewRootCommandWithDeps(
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector targetSelector,
	cfg *config.Config,
) *cobra.Command {
	return newRootCommand(func(cmd *cobra.Command, args []string) error {
		flags := &elevateFlags{}
		flags.provider, _ = cmd.Flags().GetString("provider")
		flags.target, _ = cmd.Flags().GetString("target")
		flags.role, _ = cmd.Flags().GetString("role")
		flags.favorite, _ = cmd.Flags().GetString("favorite")

		// Load SDK profile
		loader := profiles.DefaultProfilesLoader()
		profile, err := (*loader).LoadProfile(cfg.Profile)
		if err != nil {
			return fmt.Errorf("failed to load profile: %w", err)
		}

		return runElevateWithDeps(cmd, flags, profile, authLoader, eligibilityLister, elevateService, selector, cfg)
	})
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if !verbose {
			fmt.Fprintln(os.Stderr, "Hint: re-run with --verbose for more details")
		}
		os.Exit(1)
	}
}


func runElevateWithDeps(
	cmd *cobra.Command,
	flags *elevateFlags,
	profile *sdk_models.IdsecProfile,
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector targetSelector,
	cfg *config.Config,
) error {
	ctx := context.Background()

	// Check authentication state
	_, err := authLoader.LoadAuthentication(profile, true)
	if err != nil {
		return fmt.Errorf("not authenticated, run 'grant login' first")
	}

	// Determine execution mode
	var targetName, roleName string
	var isFavoriteMode bool
	var provider string

	if flags.favorite != "" {
		// Favorite mode
		isFavoriteMode = true
		fav, err := cfg.GetFavorite(flags.favorite)
		if err != nil {
			return fmt.Errorf("favorite %q not found, run 'grant favorites list'", flags.favorite)
		}

		// Check provider mismatch
		if flags.provider != "" && !strings.EqualFold(flags.provider, fav.Provider) {
			return fmt.Errorf("provider %q does not match favorite provider %q", flags.provider, fav.Provider)
		}

		provider = fav.Provider
		targetName = fav.Target
		roleName = fav.Role
	} else {
		// Direct or interactive mode
		targetName = flags.target
		roleName = flags.role

		// Validate direct mode flags
		if (targetName != "" && roleName == "") || (targetName == "" && roleName != "") {
			return fmt.Errorf("both --target and --role must be provided")
		}

		// Determine provider from flag or config
		provider = flags.provider
		if provider == "" {
			provider = cfg.DefaultProvider
		}
	}

	// Validate provider (v1 only accepts azure)
	if strings.ToLower(provider) != "azure" {
		return fmt.Errorf("provider %q is not supported in this version, supported providers: azure", provider)
	}

	// Convert provider to CSP
	csp := models.CSP(strings.ToUpper(provider))

	// Check if eligibilityLister is available
	if eligibilityLister == nil {
		return fmt.Errorf("eligibility service not available")
	}

	// Fetch eligibility list
	eligibilityResp, err := eligibilityLister.ListEligibility(ctx, csp)
	if err != nil {
		return fmt.Errorf("failed to fetch eligible targets: %w", err)
	}

	if len(eligibilityResp.Response) == 0 {
		return fmt.Errorf("no eligible %s targets found, check your SCA policies", strings.ToLower(provider))
	}

	// Resolve target based on mode
	var selectedTarget *models.AzureEligibleTarget

	if isFavoriteMode || (targetName != "" && roleName != "") {
		// Direct or favorite mode - find matching target
		selectedTarget = findMatchingTarget(eligibilityResp.Response, targetName, roleName)
		if selectedTarget == nil {
			return fmt.Errorf("target %q or role %q not found, run 'grant' to see available options", targetName, roleName)
		}
	} else {
		// Interactive mode
		selectedTarget, err = selector.SelectTarget(eligibilityResp.Response)
		if err != nil {
			return fmt.Errorf("target selection failed: %w", err)
		}
	}

	// Build elevation request
	req := &models.ElevateRequest{
		CSP:            csp,
		OrganizationID: selectedTarget.OrganizationID,
		Targets: []models.ElevateTarget{
			{
				WorkspaceID: selectedTarget.WorkspaceID,
				RoleID:      selectedTarget.RoleInfo.ID,
			},
		},
	}

	// Execute elevation
	elevateResp, err := elevateService.Elevate(ctx, req)
	if err != nil {
		return fmt.Errorf("elevation request failed: %w", err)
	}

	// Check for errors in response
	if len(elevateResp.Response.Results) == 0 {
		return fmt.Errorf("elevation failed: no results returned")
	}

	result := elevateResp.Response.Results[0]
	if result.ErrorInfo != nil {
		return fmt.Errorf("elevation failed: %s - %s\n%s",
			result.ErrorInfo.Code,
			result.ErrorInfo.Message,
			result.ErrorInfo.Description)
	}

	// Display success message
	fmt.Fprintf(cmd.OutOrStdout(), "Elevated to %s on %s\n",
		selectedTarget.RoleInfo.Name,
		selectedTarget.WorkspaceName)
	fmt.Fprintf(cmd.OutOrStdout(), "  Session ID: %s\n", result.SessionID)

	// TODO: Display session expiry when available from API
	fmt.Fprintf(cmd.OutOrStdout(), "\n  Your az CLI session now has the elevated permissions.\n")

	return nil
}

// findMatchingTarget finds a target by workspace name and role name
func findMatchingTarget(targets []models.AzureEligibleTarget, targetName, roleName string) *models.AzureEligibleTarget {
	for i := range targets {
		if targets[i].WorkspaceName == targetName && targets[i].RoleInfo.Name == roleName {
			return &targets[i]
		}
	}
	return nil
}

// uiSelector wraps the ui.SelectTarget function to implement the targetSelector interface
type uiSelector struct{}

func (s *uiSelector) SelectTarget(targets []models.AzureEligibleTarget) (*models.AzureEligibleTarget, error) {
	return ui.SelectTarget(targets)
}
