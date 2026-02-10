package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/aaearon/sca-cli/internal/config"
	"github.com/aaearon/sca-cli/internal/sca"
	"github.com/aaearon/sca-cli/internal/sca/models"
	"github.com/aaearon/sca-cli/internal/ui"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	sdk_models "github.com/cyberark/idsec-sdk-golang/pkg/models"
	auth_models "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
)

// elevateFlags holds the command-line flags for elevate
type elevateFlags struct {
	provider string
	target   string
	role     string
	favorite string
	duration int
}

// NewElevateCommand creates the elevate command
func NewElevateCommand() *cobra.Command {
	flags := &elevateFlags{}

	cmd := &cobra.Command{
		Use:   "elevate",
		Short: "Elevate cloud permissions",
		Long: `Elevate your cloud permissions via CyberArk Secure Cloud Access (SCA).

Three execution modes:
1. Interactive mode (no flags): Select target interactively
2. Direct mode (--target and --role): Directly specify target and role
3. Favorite mode (--favorite): Use a saved favorite

Examples:
  # Interactive selection
  sca-cli elevate

  # Direct selection
  sca-cli elevate --target "Prod-EastUS" --role "Contributor"

  # Use a favorite
  sca-cli elevate --favorite prod-contrib

  # Specify provider explicitly
  sca-cli elevate --provider azure`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load config
			cfg, err := config.Load(config.ConfigPath())
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			// Load profile
			loader := profiles.DefaultProfilesLoader()
			profile, err := (*loader).LoadProfile("sca-cli")
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

			return runElevate(cmd, flags, ispAuth, scaService, scaService, &uiSelector{}, cfg)
		},
	}

	cmd.Flags().StringVarP(&flags.provider, "provider", "p", "", "Cloud provider (default from config, v1: azure only)")
	cmd.Flags().StringVarP(&flags.target, "target", "t", "", "Target name (subscription, resource group, etc.)")
	cmd.Flags().StringVarP(&flags.role, "role", "r", "", "Role name")
	cmd.Flags().StringVarP(&flags.favorite, "favorite", "f", "", "Use a saved favorite alias")
	cmd.Flags().IntVarP(&flags.duration, "duration", "d", 0, "Requested session duration in minutes (if policy allows)")

	return cmd
}

// NewElevateCommandWithDeps creates an elevate command with injected dependencies for testing
func NewElevateCommandWithDeps(
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector targetSelector,
	cfg *config.Config,
) *cobra.Command {
	flags := &elevateFlags{}

	cmd := &cobra.Command{
		Use:   "elevate",
		Short: "Elevate cloud permissions",
		Long:  "Elevate your cloud permissions via CyberArk Secure Cloud Access (SCA).",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load SDK profile
			loader := profiles.DefaultProfilesLoader()
			profile, err := (*loader).LoadProfile(cfg.Profile)
			if err != nil {
				return fmt.Errorf("failed to load profile: %w", err)
			}

			return runElevateWithDeps(cmd, flags, profile, authLoader, eligibilityLister, elevateService, selector, cfg)
		},
	}

	cmd.Flags().StringVarP(&flags.provider, "provider", "p", "", "Cloud provider (default from config, v1: azure only)")
	cmd.Flags().StringVarP(&flags.target, "target", "t", "", "Target name (subscription, resource group, etc.)")
	cmd.Flags().StringVarP(&flags.role, "role", "r", "", "Role name")
	cmd.Flags().StringVarP(&flags.favorite, "favorite", "f", "", "Use a saved favorite alias")
	cmd.Flags().IntVarP(&flags.duration, "duration", "d", 0, "Requested session duration in minutes (if policy allows)")

	return cmd
}

func runElevate(
	cmd *cobra.Command,
	flags *elevateFlags,
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector targetSelector,
	cfg *config.Config,
) error {
	// Load SDK profile
	loader := profiles.DefaultProfilesLoader()
	profile, err := (*loader).LoadProfile(cfg.Profile)
	if err != nil {
		return fmt.Errorf("failed to load profile: %w", err)
	}

	return runElevateWithDeps(cmd, flags, profile, authLoader, eligibilityLister, elevateService, selector, cfg)
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
		return fmt.Errorf("Not authenticated. Run 'sca-cli login' first")
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
			return fmt.Errorf("Favorite '%s' not found. Run 'sca-cli favorites list'", flags.favorite)
		}

		// Check provider mismatch
		if flags.provider != "" && strings.ToLower(flags.provider) != strings.ToLower(fav.Provider) {
			return fmt.Errorf("Provider '%s' does not match favorite provider '%s'", flags.provider, fav.Provider)
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
			return fmt.Errorf("Both --target and --role must be provided")
		}

		// Determine provider from flag or config
		provider = flags.provider
		if provider == "" {
			provider = cfg.DefaultProvider
		}
	}

	// Validate provider (v1 only accepts azure)
	if strings.ToLower(provider) != "azure" {
		return fmt.Errorf("Provider '%s' is not supported in this version. Supported providers: azure", provider)
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
		return fmt.Errorf("No eligible %s targets found. Check your SCA policies", strings.ToLower(provider))
	}

	// Resolve target based on mode
	var selectedTarget *models.AzureEligibleTarget

	if isFavoriteMode || (targetName != "" && roleName != "") {
		// Direct or favorite mode - find matching target
		selectedTarget = findMatchingTarget(eligibilityResp.Response, targetName, roleName)
		if selectedTarget == nil {
			return fmt.Errorf("Target '%s' or role '%s' not found. Run 'sca-cli elevate' to see available options", targetName, roleName)
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
		return fmt.Errorf("Elevation failed: no results returned")
	}

	result := elevateResp.Response.Results[0]
	if result.ErrorInfo != nil {
		return fmt.Errorf("Elevation failed: %s - %s\n%s",
			result.ErrorInfo.Code,
			result.ErrorInfo.Message,
			result.ErrorInfo.Description)
	}

	// Display success message
	fmt.Fprintf(cmd.OutOrStdout(), "✓ Elevated to %s on %s\n",
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

func init() {
	rootCmd.AddCommand(NewElevateCommand())
}
