// Package cmd implements the grant CLI commands.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	survey "github.com/Iilun/survey/v2"
	"github.com/aaearon/grant-cli/internal/cache"
	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca"
	"github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	sdkconfig "github.com/cyberark/idsec-sdk-golang/pkg/config"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"
	"github.com/spf13/cobra"
)

// apiTimeout is the default timeout for SCA API requests.
var apiTimeout = 30 * time.Second

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
	refresh  bool
	groups   bool
	group    string
}

// newRootCommand creates the root cobra command with the given RunE function.
// All flag registration and PersistentPreRunE setup is centralized here.
func newRootCommand(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Request temporary elevated cloud permissions",
		Long: `Grant temporary elevated cloud permissions via CyberArk Secure Cloud Access (SCA).

Running grant with no subcommand requests access elevation. The interactive
selector shows both cloud roles and Entra ID groups in a unified list.

Execution modes:
1. Interactive mode (no flags): Select target or group interactively
2. Direct cloud mode (--target and --role): Directly specify target and role
3. Direct group mode (--group): Directly specify group name
4. Favorite mode (--favorite): Use a saved favorite (cloud or group)

Examples:
  # Interactive selection (cloud roles + groups)
  grant

  # Direct cloud selection
  grant --target "Prod-EastUS" --role "Contributor"

  # Direct group membership elevation
  grant --group "Cloud Admins"

  # Show only groups in interactive selector
  grant --groups

  # Use a favorite
  grant --favorite prod-contrib

  # Specify provider explicitly (cloud targets only)
  grant --provider azure
  grant --provider aws

  # Bypass eligibility cache and fetch fresh data
  grant --refresh`,
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			passedArgValidation = true
			if verbose {
				sdkconfig.EnableVerboseLogging("INFO")
			} else {
				sdkconfig.DisableVerboseLogging()
			}
			if outputFormat != "text" && outputFormat != "json" {
				return fmt.Errorf("invalid output format %q: must be one of: text, json", outputFormat)
			}
			if isJSONOutput() {
				ui.IsTerminalFunc = func(fd uintptr) bool { return false }
			}
			return nil
		},
		RunE: runFn,
	}

	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	cmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "text", "Output format: text, json")
	cmd.Flags().StringP("provider", "p", "", "Cloud provider: azure, aws (omit to show all)")
	cmd.Flags().StringP("target", "t", "", "Target name (subscription, resource group, etc.)")
	cmd.Flags().StringP("role", "r", "", "Role name")
	cmd.Flags().StringP("favorite", "f", "", "Use a saved favorite (see 'grant favorites list')")
	cmd.Flags().Bool("refresh", false, "Bypass eligibility cache and fetch fresh data")
	cmd.Flags().Bool("groups", false, "Show only Entra ID groups in interactive selector")
	cmd.Flags().StringP("group", "g", "", "Group name for direct group membership elevation")

	cmd.MarkFlagsMutuallyExclusive("favorite", "target")
	cmd.MarkFlagsMutuallyExclusive("favorite", "role")
	cmd.MarkFlagsMutuallyExclusive("groups", "provider")
	cmd.MarkFlagsMutuallyExclusive("groups", "target")
	cmd.MarkFlagsMutuallyExclusive("groups", "role")
	cmd.MarkFlagsMutuallyExclusive("group", "target")
	cmd.MarkFlagsMutuallyExclusive("group", "role")

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
	flags.refresh, _ = cmd.Flags().GetBool("refresh")
	flags.groups, _ = cmd.Flags().GetBool("groups")
	flags.group, _ = cmd.Flags().GetString("group")
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

	cachedLister := buildCachedLister(cfg, flags.refresh, scaService, scaService)

	return runElevateWithDeps(cmd, flags, profile, ispAuth, cachedLister, scaService, &uiUnifiedSelector{}, cachedLister, scaService, cfg)
}

// buildCachedLister creates a CachedEligibilityLister wrapping the given services.
// If the cache directory cannot be resolved, it falls back to the unwrapped services.
func buildCachedLister(cfg *config.Config, refresh bool, cloudInner cache.EligibilityLister, groupsInner cache.GroupsEligibilityLister) *cache.CachedEligibilityLister {
	cacheLog := common.GetLogger("grant", -1)
	cacheDir, err := cache.CacheDir()
	if err != nil {
		return cache.NewCachedEligibilityLister(cloudInner, groupsInner, cache.NewStore("", 0), true, nil)
	}
	ttl := config.ParseCacheTTL(cfg)
	store := cache.NewStore(cacheDir, ttl)
	return cache.NewCachedEligibilityLister(cloudInner, groupsInner, store, refresh, cacheLog)
}

// NewRootCommandWithDeps creates a root command with injected dependencies for testing.
// It accepts a pre-loaded profile to avoid filesystem access during tests.
func NewRootCommandWithDeps(
	profile *sdkmodels.IdsecProfile,
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector unifiedSelector,
	groupsEligLister groupsEligibilityLister,
	groupsElevator groupsElevator,
	cfg *config.Config,
) *cobra.Command {
	return newRootCommand(func(cmd *cobra.Command, args []string) error {
		flags := parseElevateFlags(cmd)
		return runElevateWithDeps(cmd, flags, profile, authLoader, eligibilityLister, elevateService, selector, groupsEligLister, groupsElevator, cfg)
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
				log.Info("%s eligibility query failed: %v", r.csp, r.err)
				continue
			}
			for _, t := range r.targets {
				t.CSP = r.csp
				all = append(all, t)
			}
		}
		if len(all) == 0 {
			return nil, errors.New("no eligible targets found, check your SCA policies")
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

		// Group favorites must be used via the groups command
		if fav.ResolvedType() == config.FavoriteTypeGroups {
			return nil, fmt.Errorf("favorite %q is a group favorite; use 'grant groups --favorite %s' instead", flags.favorite, flags.favorite)
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
			return nil, errors.New("both --target and --role must be provided")
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

	// Fresh context for elevation — the original ctx may have expired during
	// an interactive prompt (the user can take arbitrarily long to select).
	elevCtx, elevCancel := context.WithTimeout(context.Background(), apiTimeout)
	defer elevCancel()

	// Execute elevation
	elevateResp, err := elevateService.Elevate(elevCtx, req)
	if err != nil {
		return nil, fmt.Errorf("elevation request failed: %w", err)
	}

	// Check for errors in response
	if len(elevateResp.Response.Results) == 0 {
		return nil, errors.New("elevation failed: no results returned")
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

// fetchGroupsEligibility fetches groups eligibility and enriches with directory names.
func fetchGroupsEligibility(ctx context.Context, groupsEligLister groupsEligibilityLister, cloudEligLister eligibilityLister) ([]models.GroupsEligibleTarget, error) {
	eligResp, err := groupsEligLister.ListGroupsEligibility(ctx, models.CSPAzure)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch eligible groups: %w", err)
	}
	if len(eligResp.Response) == 0 {
		return nil, errors.New("no eligible groups found, check your SCA policies")
	}

	// Resolve directory names from cloud eligibility (best-effort)
	dirNameMap := buildDirectoryNameMap(ctx, cloudEligLister)
	for i := range eligResp.Response {
		if name, ok := dirNameMap[eligResp.Response[i].DirectoryID]; ok {
			eligResp.Response[i].DirectoryName = name
		}
	}

	return eligResp.Response, nil
}

// resolvedFlags holds the resolved state after processing favorites and flag defaults.
type resolvedFlags struct {
	targetName      string
	roleName        string
	provider        string
	favDirectoryID  string
	isFavoriteMode  bool
	isGroupFavorite bool
}

// resolveFavoriteFlags resolves favorite and direct flags into concrete values.
func resolveFavoriteFlags(flags *elevateFlags, cfg *config.Config) (*resolvedFlags, error) {
	rf := &resolvedFlags{}

	if flags.favorite != "" {
		rf.isFavoriteMode = true
		fav, err := config.GetFavorite(cfg, flags.favorite)
		if err != nil {
			return nil, fmt.Errorf("favorite %q not found, run 'grant favorites list'", flags.favorite)
		}

		if fav.ResolvedType() == config.FavoriteTypeGroups {
			rf.isGroupFavorite = true
			flags.group = fav.Group
			rf.favDirectoryID = fav.DirectoryID
		} else {
			if flags.provider != "" && !strings.EqualFold(flags.provider, fav.Provider) {
				return nil, fmt.Errorf("provider %q does not match favorite provider %q", flags.provider, fav.Provider)
			}
			rf.provider = fav.Provider
			rf.targetName = fav.Target
			rf.roleName = fav.Role
		}
	} else {
		rf.targetName = flags.target
		rf.roleName = flags.role
		rf.provider = flags.provider

		if (rf.targetName != "" && rf.roleName == "") || (rf.targetName == "" && rf.roleName != "") {
			return nil, errors.New("both --target and --role must be provided")
		}
	}

	return rf, nil
}

// resolveAndElevateUnified handles all elevation modes: cloud, group, and unified.
// Returns (*elevationResult, nil, nil) for cloud or (nil, *groupElevationResult, nil) for group.
func resolveAndElevateUnified(
	cmd *cobra.Command,
	flags *elevateFlags,
	profile *sdkmodels.IdsecProfile,
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector unifiedSelector,
	groupsEligLister groupsEligibilityLister,
	groupsElevator groupsElevator,
	cfg *config.Config,
) (*elevationResult, *groupElevationResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	// Check authentication state
	_, err := authLoader.LoadAuthentication(profile, true)
	if err != nil {
		return nil, nil, fmt.Errorf("not authenticated, run 'grant login' first: %w", err)
	}

	rf, err := resolveFavoriteFlags(flags, cfg)
	if err != nil {
		return nil, nil, err
	}

	// Dispatch to the appropriate elevation path
	if flags.group != "" {
		return resolveAndElevateDirectGroup(ctx, flags.group, rf.favDirectoryID, groupsEligLister, eligibilityLister, groupsElevator)
	}
	if flags.groups {
		return resolveAndElevateGroupsFilter(ctx, groupsEligLister, eligibilityLister, selector, groupsElevator)
	}
	if rf.provider != "" || rf.isFavoriteMode || (rf.targetName != "" && rf.roleName != "") {
		return resolveAndElevateCloudOnly(ctx, rf, eligibilityLister, elevateService, selector)
	}
	return resolveAndElevateUnifiedPath(ctx, eligibilityLister, groupsEligLister, selector, elevateService, groupsElevator)
}

// resolveAndElevateDirectGroup handles the --group flag or group favorite path.
func resolveAndElevateDirectGroup(ctx context.Context, groupName, favDirectoryID string, groupsEligLister groupsEligibilityLister, cloudEligLister eligibilityLister, groupsElevator groupsElevator) (*elevationResult, *groupElevationResult, error) {
	groups, err := fetchGroupsEligibility(ctx, groupsEligLister, cloudEligLister)
	if err != nil {
		return nil, nil, err
	}

	selectedGroup := findMatchingGroup(groups, groupName, favDirectoryID)
	if selectedGroup == nil {
		if favDirectoryID != "" {
			return nil, nil, fmt.Errorf("group %q not found in directory %q, run 'grant' to see available options", groupName, favDirectoryID)
		}
		return nil, nil, fmt.Errorf("group %q not found, run 'grant' to see available options", groupName)
	}

	return elevateGroup(ctx, selectedGroup, groupsElevator)
}

// resolveAndElevateGroupsFilter handles the --groups interactive filter path.
func resolveAndElevateGroupsFilter(ctx context.Context, groupsEligLister groupsEligibilityLister, cloudEligLister eligibilityLister, selector unifiedSelector, groupsElevator groupsElevator) (*elevationResult, *groupElevationResult, error) {
	groups, err := fetchGroupsEligibility(ctx, groupsEligLister, cloudEligLister)
	if err != nil {
		return nil, nil, err
	}

	var items []selectionItem
	for i := range groups {
		items = append(items, selectionItem{kind: selectionGroup, group: &groups[i]})
	}

	selected, err := selector.SelectItem(items)
	if err != nil {
		return nil, nil, fmt.Errorf("selection failed: %w", err)
	}

	// Fresh context for elevation — the original ctx may have expired during
	// the interactive prompt.
	elevCtx, elevCancel := context.WithTimeout(context.Background(), apiTimeout)
	defer elevCancel()
	return elevateGroup(elevCtx, selected.group, groupsElevator)
}

// resolveAndElevateCloudOnly handles the cloud-only path (--provider, direct, or favorite).
func resolveAndElevateCloudOnly(ctx context.Context, rf *resolvedFlags, eligLister eligibilityLister, elevateService elevateService, selector unifiedSelector) (*elevationResult, *groupElevationResult, error) {
	allTargets, err := fetchEligibility(ctx, eligLister, rf.provider)
	if err != nil {
		return nil, nil, err
	}

	var selectedTarget *models.EligibleTarget
	if rf.isFavoriteMode && !rf.isGroupFavorite || (rf.targetName != "" && rf.roleName != "") {
		selectedTarget = findMatchingTarget(allTargets, rf.targetName, rf.roleName)
		if selectedTarget == nil {
			return nil, nil, fmt.Errorf("target %q or role %q not found, run 'grant' to see available options", rf.targetName, rf.roleName)
		}
	} else {
		var items []selectionItem
		for i := range allTargets {
			items = append(items, selectionItem{kind: selectionCloud, cloud: &allTargets[i]})
		}

		selected, err := selector.SelectItem(items)
		if err != nil {
			return nil, nil, fmt.Errorf("selection failed: %w", err)
		}
		selectedTarget = selected.cloud
	}

	resolveTargetCSP(selectedTarget, allTargets, rf.provider)

	// Fresh context for elevation — the original ctx may have expired during
	// the interactive prompt.
	elevCtx, elevCancel := context.WithTimeout(context.Background(), apiTimeout)
	defer elevCancel()
	return elevateCloud(elevCtx, selectedTarget, elevateService)
}

// resolveAndElevateUnifiedPath handles the unified path (no filter flags) with parallel fetch.
func resolveAndElevateUnifiedPath(ctx context.Context, eligLister eligibilityLister, groupsEligLister groupsEligibilityLister, selector unifiedSelector, elevateService elevateService, groupsElevator groupsElevator) (*elevationResult, *groupElevationResult, error) {
	type cloudResult struct {
		targets []models.EligibleTarget
		err     error
	}
	type groupsResult struct {
		groups []models.GroupsEligibleTarget
		err    error
	}

	cloudCh := make(chan cloudResult, 1)
	groupsCh := make(chan groupsResult, 1)

	go func() {
		targets, err := fetchEligibility(ctx, eligLister, "")
		cloudCh <- cloudResult{targets: targets, err: err}
	}()

	go func() {
		groups, err := fetchGroupsEligibility(ctx, groupsEligLister, eligLister)
		groupsCh <- groupsResult{groups: groups, err: err}
	}()

	cr := <-cloudCh
	gr := <-groupsCh

	var items []selectionItem
	if cr.err == nil {
		for i := range cr.targets {
			items = append(items, selectionItem{kind: selectionCloud, cloud: &cr.targets[i]})
		}
	}
	if gr.err == nil {
		for i := range gr.groups {
			items = append(items, selectionItem{kind: selectionGroup, group: &gr.groups[i]})
		}
	}

	if len(items) == 0 {
		return nil, nil, errors.New("no eligible targets or groups found, check your SCA policies")
	}

	selected, err := selector.SelectItem(items)
	if err != nil {
		return nil, nil, fmt.Errorf("selection failed: %w", err)
	}

	// Fresh context for elevation — the original ctx may have expired during
	// the interactive prompt.
	elevCtx, elevCancel := context.WithTimeout(context.Background(), apiTimeout)
	defer elevCancel()

	switch selected.kind {
	case selectionCloud:
		resolveTargetCSP(selected.cloud, cr.targets, "")
		return elevateCloud(elevCtx, selected.cloud, elevateService)
	case selectionGroup:
		return elevateGroup(elevCtx, selected.group, groupsElevator)
	default:
		return nil, nil, errors.New("unexpected selection kind")
	}
}

// elevateCloud performs cloud role elevation for a selected target.
func elevateCloud(ctx context.Context, target *models.EligibleTarget, elevateService elevateService) (*elevationResult, *groupElevationResult, error) {
	req := &models.ElevateRequest{
		CSP:            target.CSP,
		OrganizationID: target.OrganizationID,
		Targets: []models.ElevateTarget{
			{
				WorkspaceID: target.WorkspaceID,
				RoleID:      target.RoleInfo.ID,
			},
		},
	}

	elevateResp, err := elevateService.Elevate(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("elevation request failed: %w", err)
	}

	if len(elevateResp.Response.Results) == 0 {
		return nil, nil, errors.New("elevation failed: no results returned")
	}

	result := elevateResp.Response.Results[0]
	if result.ErrorInfo != nil {
		return nil, nil, fmt.Errorf("elevation failed: %s - %s\n%s",
			result.ErrorInfo.Code,
			result.ErrorInfo.Message,
			result.ErrorInfo.Description)
	}

	return &elevationResult{target: target, result: &result}, nil, nil
}

// elevateGroup performs Entra ID group membership elevation.
func elevateGroup(ctx context.Context, group *models.GroupsEligibleTarget, elevator groupsElevator) (*elevationResult, *groupElevationResult, error) {
	req := &models.GroupsElevateRequest{
		DirectoryID: group.DirectoryID,
		CSP:         models.CSPAzure,
		Targets: []models.GroupsElevateTarget{
			{GroupID: group.GroupID},
		},
	}

	elevateResp, err := elevator.ElevateGroups(ctx, req)
	if err != nil {
		return nil, nil, fmt.Errorf("elevation request failed: %w", err)
	}

	if len(elevateResp.Results) == 0 {
		return nil, nil, errors.New("elevation failed: no results returned")
	}

	result := elevateResp.Results[0]
	if result.ErrorInfo != nil {
		return nil, nil, fmt.Errorf("elevation failed: %s - %s\n%s",
			result.ErrorInfo.Code,
			result.ErrorInfo.Message,
			result.ErrorInfo.Description)
	}

	return nil, &groupElevationResult{group: group, result: &result}, nil
}

func runElevateWithDeps(
	cmd *cobra.Command,
	flags *elevateFlags,
	profile *sdkmodels.IdsecProfile,
	authLoader authLoader,
	eligibilityLister eligibilityLister,
	elevateService elevateService,
	selector unifiedSelector,
	groupsEligLister groupsEligibilityLister,
	groupsElevator groupsElevator,
	cfg *config.Config,
) error {
	cloudRes, groupRes, err := resolveAndElevateUnified(
		cmd, flags, profile, authLoader, eligibilityLister, elevateService,
		selector, groupsEligLister, groupsElevator, cfg,
	)
	if err != nil {
		return err
	}

	// Record session timestamp for remaining-time tracking (best-effort)
	if groupRes != nil {
		recordSessionTimestamp(groupRes.result.SessionID)
	} else if cloudRes != nil {
		recordSessionTimestamp(cloudRes.result.SessionID)
	}

	if isJSONOutput() {
		return writeElevationJSON(cmd, cloudRes, groupRes)
	}

	if groupRes != nil {
		// Display group elevation result
		dirContext := ""
		if groupRes.group.DirectoryName != "" {
			dirContext = " in " + groupRes.group.DirectoryName
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Elevated to group %s%s\n", groupRes.group.GroupName, dirContext)
		fmt.Fprintf(cmd.OutOrStdout(), "  Session ID: %s\n", groupRes.result.SessionID)
		return nil
	}

	// Display cloud elevation result
	res := cloudRes
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

// writeElevationJSON writes the elevation result as JSON.
func writeElevationJSON(cmd *cobra.Command, cloudRes *elevationResult, groupRes *groupElevationResult) error {
	if groupRes != nil {
		out := groupElevationJSON{
			Type:        "group",
			SessionID:   groupRes.result.SessionID,
			GroupName:   groupRes.group.GroupName,
			GroupID:     groupRes.group.GroupID,
			DirectoryID: groupRes.group.DirectoryID,
			Directory:   groupRes.group.DirectoryName,
		}
		return writeJSON(cmd.OutOrStdout(), out)
	}

	out := cloudElevationOutput{
		Type:      "cloud",
		Provider:  strings.ToLower(string(cloudRes.target.CSP)),
		SessionID: cloudRes.result.SessionID,
		Target:    cloudRes.target.WorkspaceName,
		Role:      cloudRes.target.RoleInfo.Name,
	}

	if cloudRes.result.AccessCredentials != nil {
		awsCreds, err := models.ParseAWSCredentials(*cloudRes.result.AccessCredentials)
		if err != nil {
			return fmt.Errorf("failed to parse access credentials: %w", err)
		}
		out.Credentials = &awsCredentialOutput{
			AccessKeyID:    awsCreds.AccessKeyID,
			SecretAccessKey: awsCreds.SecretAccessKey,
			SessionToken:   awsCreds.SessionToken,
		}
	}

	return writeJSON(cmd.OutOrStdout(), out)
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

// uiUnifiedSelector implements unifiedSelector using survey.Select
type uiUnifiedSelector struct{}

func (s *uiUnifiedSelector) SelectItem(items []selectionItem) (*selectionItem, error) {
	if !ui.IsInteractive() {
		return nil, fmt.Errorf("%w; use --target/--role, --group, or --favorite flags for non-interactive mode", ui.ErrNotInteractive)
	}

	if len(items) == 0 {
		return nil, errors.New("no eligible targets or groups available")
	}

	options, sorted := buildUnifiedOptions(items)

	var selected string
	prompt := &survey.Select{
		Message: "Select a target:",
		Options: options,
		Filter:  nil,
	}

	if err := survey.AskOne(prompt, &selected, survey.WithStdio(os.Stdin, os.Stderr, os.Stderr)); err != nil {
		return nil, fmt.Errorf("selection failed: %w", err)
	}

	return findItemByDisplay(sorted, selected)
}
