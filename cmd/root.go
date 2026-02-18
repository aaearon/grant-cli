package cmd

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca"
	"github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	sdkconfig "github.com/cyberark/idsec-sdk-golang/pkg/config"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
)

// apiTimeout is the default timeout for SCA API requests.
const apiTimeout = 30 * time.Second

// verbose and passedArgValidation are package-level by design: the CLI binary
// runs a single command per process, so there is no concurrent access.
// They are NOT safe for concurrent use and must not be shared across goroutines.
var verbose bool

// passedArgValidation is set to true in PersistentPreRunE.
// If an arg/flag validation error occurs, PersistentPreRunE never runs,
// so this stays false — allowing Execute() to suppress the verbose hint.
var passedArgValidation bool

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
  grant --provider azure
  grant --provider aws`,
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			passedArgValidation = true
			if verbose {
				sdkconfig.EnableVerboseLogging("INFO")
			} else {
				sdkconfig.DisableVerboseLogging()
			}
			return nil
		},
		RunE: runFn,
	}

	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	cmd.Flags().StringP("provider", "p", "", "Cloud provider: azure, aws (omit to show all)")
	cmd.Flags().StringP("target", "t", "", "Target name (subscription, resource group, etc.)")
	cmd.Flags().StringP("role", "r", "", "Role name")
	cmd.Flags().StringP("favorite", "f", "", "Use a saved favorite (see 'grant favorites list')")

	cmd.MarkFlagsMutuallyExclusive("favorite", "target")
	cmd.MarkFlagsMutuallyExclusive("favorite", "role")

	return cmd
}

var rootCmd = newRootCommand(runElevateProduction)

// bootstrapSCAService loads the profile, authenticates, and creates the SCA service.
func bootstrapSCAService() (auth.IdsecAuth, *sca.SCAAccessService, *sdkmodels.IdsecProfile, error) {
	loader := profiles.DefaultProfilesLoader()
	profile, err := (*loader).LoadProfile("grant")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load profile: %w", err)
	}

	ispAuth := auth.NewIdsecISPAuth(true)

	_, err = ispAuth.Authenticate(profile, nil, &authmodels.IdsecSecret{Secret: ""}, false, true)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("authentication failed: %w", err)
	}

	svc, err := sca.NewSCAAccessService(ispAuth)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create SCA service: %w", err)
	}

	return ispAuth, svc, profile, nil
}

// parseElevateFlags reads the elevation flags from the command.
func parseElevateFlags(cmd *cobra.Command) *elevateFlags {
	flags := &elevateFlags{}
	flags.provider, _ = cmd.Flags().GetString("provider")
	flags.target, _ = cmd.Flags().GetString("target")
	flags.role, _ = cmd.Flags().GetString("role")
	flags.favorite, _ = cmd.Flags().GetString("favorite")
	return flags
}

// runElevateProduction is the production RunE for the root command
func runElevateProduction(cmd *cobra.Command, args []string) error {
	flags := parseElevateFlags(cmd)

	cfg, _, err := config.LoadDefaultWithPath()
	if err != nil {
		return err
	}

	ispAuth, scaService, profile, err := bootstrapSCAService()
	if err != nil {
		return err
	}

	return runElevateWithDeps(cmd, flags, profile, ispAuth, scaService, scaService, &uiSelector{}, cfg)
}

// NewRootCommandWithDeps creates a root command with injected dependencies for testing.
// It accepts a pre-loaded profile to avoid filesystem access during tests.
func NewRootCommandWithDeps(
	profile *sdkmodels.IdsecProfile,
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector targetSelector,
	cfg *config.Config,
) *cobra.Command {
	return newRootCommand(func(cmd *cobra.Command, args []string) error {
		flags := parseElevateFlags(cmd)
		return runElevateWithDeps(cmd, flags, profile, authLoader, eligibilityLister, elevateService, selector, cfg)
	})
}

func Execute() {
	passedArgValidation = false
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(rootCmd.ErrOrStderr(), err)
		if !verbose && passedArgValidation {
			fmt.Fprintln(rootCmd.ErrOrStderr(), "Hint: re-run with --verbose for more details")
		}
		os.Exit(1)
	}
}

// supportedCSPs lists the cloud providers supported for elevation.
var supportedCSPs = []models.CSP{models.CSPAzure, models.CSPAWS}

// fetchEligibility retrieves eligible targets. When provider is empty, all
// supported CSPs are queried and results merged. When set, only that CSP is queried.
// Each returned target has its CSP field set.
func fetchEligibility(ctx context.Context, eligLister eligibilityLister, provider string) ([]models.EligibleTarget, error) {
	if provider == "" {
		type cspResult struct {
			targets []models.EligibleTarget
			csp     models.CSP
			err     error
		}

		results := make(chan cspResult, len(supportedCSPs))
		var wg sync.WaitGroup
		for _, csp := range supportedCSPs {
			wg.Add(1)
			go func(csp models.CSP) {
				defer wg.Done()
				resp, err := eligLister.ListEligibility(ctx, csp)
				if err != nil {
					results <- cspResult{csp: csp, err: err}
					return
				}
				results <- cspResult{targets: resp.Response, csp: csp}
			}(csp)
		}
		go func() {
			wg.Wait()
			close(results)
		}()

		var all []models.EligibleTarget
		for r := range results {
			if r.err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "[verbose] %s eligibility query failed: %v\n", r.csp, r.err)
				}
				continue
			}
			for _, t := range r.targets {
				t.CSP = r.csp
				all = append(all, t)
			}
		}
		if len(all) == 0 {
			return nil, fmt.Errorf("no eligible targets found, check your SCA policies")
		}
		return all, nil
	}

	csp := models.CSP(strings.ToUpper(provider))
	if !slices.Contains(supportedCSPs, csp) {
		var names []string
		for _, s := range supportedCSPs {
			names = append(names, strings.ToLower(string(s)))
		}
		return nil, fmt.Errorf("provider %q is not supported, supported providers: %s", provider, strings.Join(names, ", "))
	}
	resp, err := eligLister.ListEligibility(ctx, csp)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch eligible targets: %w", err)
	}
	if len(resp.Response) == 0 {
		return nil, fmt.Errorf("no eligible %s targets found, check your SCA policies", strings.ToLower(provider))
	}
	targets := make([]models.EligibleTarget, len(resp.Response))
	copy(targets, resp.Response)
	return targets, nil
}

// resolveTargetCSP ensures the CSP field is set on a selected target.
// When provider is specified, it is used directly. Otherwise CSP is resolved
// from allTargets (set during multi-CSP fetch).
func resolveTargetCSP(target *models.EligibleTarget, allTargets []models.EligibleTarget, provider string) {
	if target.CSP != "" {
		return
	}
	if provider != "" {
		target.CSP = models.CSP(strings.ToUpper(provider))
		return
	}
	for _, t := range allTargets {
		if t.WorkspaceID == target.WorkspaceID && t.RoleInfo.ID == target.RoleInfo.ID {
			target.CSP = t.CSP
			return
		}
	}
}

// elevationResult holds the outcome of a successful elevation request.
type elevationResult struct {
	target *models.EligibleTarget
	result *models.ElevateTargetResult
}

// resolveAndElevate performs the full elevation flow: auth check, flag resolution,
// eligibility fetch, target selection, and elevation request. It is shared by
// the root command and the env command.
func resolveAndElevate(
	flags *elevateFlags,
	profile *sdkmodels.IdsecProfile,
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector targetSelector,
	cfg *config.Config,
) (*elevationResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	// Check authentication state
	_, err := authLoader.LoadAuthentication(profile, true)
	if err != nil {
		return nil, fmt.Errorf("not authenticated, run 'grant login' first: %w", err)
	}

	// Determine execution mode
	var targetName, roleName string
	var isFavoriteMode bool
	var provider string

	if flags.favorite != "" {
		// Favorite mode
		isFavoriteMode = true
		fav, err := config.GetFavorite(cfg, flags.favorite)
		if err != nil {
			return nil, fmt.Errorf("favorite %q not found, run 'grant favorites list'", flags.favorite)
		}

		// Check provider mismatch
		if flags.provider != "" && !strings.EqualFold(flags.provider, fav.Provider) {
			return nil, fmt.Errorf("provider %q does not match favorite provider %q", flags.provider, fav.Provider)
		}

		provider = fav.Provider
		targetName = fav.Target
		roleName = fav.Role
	} else {
		// Direct or interactive mode — provider from flag only (empty = all CSPs)
		targetName = flags.target
		roleName = flags.role

		// Validate direct mode flags
		if (targetName != "" && roleName == "") || (targetName == "" && roleName != "") {
			return nil, fmt.Errorf("both --target and --role must be provided")
		}

		provider = flags.provider
	}

	// Fetch eligibility (all CSPs when provider is empty)
	allTargets, err := fetchEligibility(ctx, eligibilityLister, provider)
	if err != nil {
		return nil, err
	}

	// Resolve target based on mode
	var selectedTarget *models.EligibleTarget

	if isFavoriteMode || (targetName != "" && roleName != "") {
		// Direct or favorite mode - find matching target
		selectedTarget = findMatchingTarget(allTargets, targetName, roleName)
		if selectedTarget == nil {
			return nil, fmt.Errorf("target %q or role %q not found, run 'grant' to see available options", targetName, roleName)
		}
	} else {
		// Interactive mode
		selectedTarget, err = selector.SelectTarget(allTargets)
		if err != nil {
			return nil, fmt.Errorf("target selection failed: %w", err)
		}
	}

	// Ensure CSP is set on selected target
	resolveTargetCSP(selectedTarget, allTargets, provider)

	// Build elevation request
	req := &models.ElevateRequest{
		CSP:            selectedTarget.CSP,
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
		return nil, fmt.Errorf("elevation request failed: %w", err)
	}

	// Check for errors in response
	if len(elevateResp.Response.Results) == 0 {
		return nil, fmt.Errorf("elevation failed: no results returned")
	}

	result := elevateResp.Response.Results[0]
	if result.ErrorInfo != nil {
		return nil, fmt.Errorf("elevation failed: %s - %s\n%s",
			result.ErrorInfo.Code,
			result.ErrorInfo.Message,
			result.ErrorInfo.Description)
	}

	return &elevationResult{target: selectedTarget, result: &result}, nil
}

func runElevateWithDeps(
	cmd *cobra.Command,
	flags *elevateFlags,
	profile *sdkmodels.IdsecProfile,
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector targetSelector,
	cfg *config.Config,
) error {
	res, err := resolveAndElevate(flags, profile, authLoader, eligibilityLister, elevateService, selector, cfg)
	if err != nil {
		return err
	}

	// Display success message
	fmt.Fprintf(cmd.OutOrStdout(), "Elevated to %s on %s\n",
		res.target.RoleInfo.Name,
		res.target.WorkspaceName)
	fmt.Fprintf(cmd.OutOrStdout(), "  Session ID: %s\n", res.result.SessionID)

	// CSP-aware post-elevation guidance
	if res.result.AccessCredentials != nil {
		awsCreds, err := models.ParseAWSCredentials(*res.result.AccessCredentials)
		if err != nil {
			return fmt.Errorf("failed to parse access credentials: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "\n  export AWS_ACCESS_KEY_ID='%s'\n", awsCreds.AccessKeyID)
		fmt.Fprintf(cmd.OutOrStdout(), "  export AWS_SECRET_ACCESS_KEY='%s'\n", awsCreds.SecretAccessKey)
		fmt.Fprintf(cmd.OutOrStdout(), "  export AWS_SESSION_TOKEN='%s'\n", awsCreds.SessionToken)
		fmt.Fprintf(cmd.OutOrStdout(), "\n  Or run: eval $(grant env --provider aws)\n")
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "\n  Your az CLI session now has the elevated permissions.\n")
	}

	return nil
}

// findMatchingTarget finds a target by workspace name and role name (case-insensitive)
func findMatchingTarget(targets []models.EligibleTarget, targetName, roleName string) *models.EligibleTarget {
	for i := range targets {
		if strings.EqualFold(targets[i].WorkspaceName, targetName) && strings.EqualFold(targets[i].RoleInfo.Name, roleName) {
			return &targets[i]
		}
	}
	return nil
}

// uiSelector wraps the ui.SelectTarget function to implement the targetSelector interface
type uiSelector struct{}

func (s *uiSelector) SelectTarget(targets []models.EligibleTarget) (*models.EligibleTarget, error) {
	return ui.SelectTarget(targets)
}
