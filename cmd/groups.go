package cmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/aaearon/grant-cli/internal/config"
	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	sdkmodels "github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/spf13/cobra"
)

// uiGroupSelector wraps ui.SelectGroup to implement groupSelector
type uiGroupSelector struct{}

func (s *uiGroupSelector) SelectGroup(groups []scamodels.GroupsEligibleTarget) (*scamodels.GroupsEligibleTarget, error) {
	return ui.SelectGroup(groups)
}

// newGroupsCommand creates the groups cobra command with the given RunE function.
func newGroupsCommand(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "groups",
		Short: "Request temporary Entra ID group membership",
		Long: `Request temporary Entra ID group membership via CyberArk Secure Cloud Access (SCA).

Three execution modes:
1. Interactive mode (no flags): Select group interactively
2. Direct mode (--group): Directly specify group name
3. Favorite mode (--favorite): Use a saved favorite

Examples:
  # Interactive selection
  grant groups

  # Direct selection
  grant groups --group "Cloud Admins"

  # Favorite mode
  grant groups --favorite my-group`,
		RunE: runFn,
	}

	cmd.Flags().StringP("group", "g", "", "Group name for direct mode")
	cmd.Flags().StringP("favorite", "f", "", "Use a saved favorite (see 'grant favorites list')")

	return cmd
}

// NewGroupsCommand creates the production groups command.
func NewGroupsCommand() *cobra.Command {
	return newGroupsCommand(func(cmd *cobra.Command, args []string) error {
		ispAuth, svc, profile, err := bootstrapSCAService()
		if err != nil {
			return err
		}

		cfg, _, err := config.LoadDefaultWithPath()
		if err != nil {
			return err
		}

		cachedLister := buildCachedLister(cfg, false, svc, svc)

		return runGroups(cmd, ispAuth, cachedLister, cachedLister, svc, &uiGroupSelector{}, profile, cfg)
	})
}

// NewGroupsCommandWithDeps creates a groups command with injected dependencies for testing.
func NewGroupsCommandWithDeps(
	profile *sdkmodels.IdsecProfile,
	auth authLoader,
	cloudElig eligibilityLister,
	groupsElig groupsEligibilityLister,
	elevator groupsElevator,
	selector groupSelector,
	cfg *config.Config,
) *cobra.Command {
	return newGroupsCommand(func(cmd *cobra.Command, args []string) error {
		return runGroups(cmd, auth, cloudElig, groupsElig, elevator, selector, profile, cfg)
	})
}

func runGroups(
	cmd *cobra.Command,
	auth authLoader,
	cloudElig eligibilityLister,
	groupsElig groupsEligibilityLister,
	elevator groupsElevator,
	selector groupSelector,
	profile *sdkmodels.IdsecProfile,
	cfg *config.Config,
) error {
	groupFlag, _ := cmd.Flags().GetString("group")
	favoriteFlag, _ := cmd.Flags().GetString("favorite")

	var favDirectoryID string

	if favoriteFlag != "" {
		if cfg == nil {
			var err error
			cfg, _, err = config.LoadDefaultWithPath()
			if err != nil {
				return err
			}
		}

		fav, err := config.GetFavorite(cfg, favoriteFlag)
		if err != nil {
			return fmt.Errorf("favorite %q not found, run 'grant favorites list'", favoriteFlag)
		}

		if fav.ResolvedType() != config.FavoriteTypeGroups {
			return fmt.Errorf("favorite %q is a cloud favorite; use 'grant --favorite %s' instead", favoriteFlag, favoriteFlag)
		}

		groupFlag = fav.Group
		favDirectoryID = fav.DirectoryID
	}

	// Check authentication
	_, err := auth.LoadAuthentication(profile, true)
	if err != nil {
		return fmt.Errorf("not authenticated, run 'grant login' first: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	// Fetch groups eligibility (always Azure for Entra ID)
	eligResp, err := groupsElig.ListGroupsEligibility(ctx, scamodels.CSPAzure)
	if err != nil {
		return fmt.Errorf("failed to fetch eligible groups: %w", err)
	}

	if len(eligResp.Response) == 0 {
		return fmt.Errorf("no eligible groups found, check your SCA policies")
	}

	// Resolve directory names from cloud eligibility (best-effort)
	dirNameMap := buildDirectoryNameMap(ctx, cloudElig, cmd.ErrOrStderr())
	for i := range eligResp.Response {
		if name, ok := dirNameMap[eligResp.Response[i].DirectoryID]; ok {
			eligResp.Response[i].DirectoryName = name
		}
	}

	// Resolve group
	var selectedGroup *scamodels.GroupsEligibleTarget

	if groupFlag != "" {
		// Direct mode (or favorite-resolved)
		selectedGroup = findMatchingGroup(eligResp.Response, groupFlag, favDirectoryID)
		if selectedGroup == nil {
			if favDirectoryID != "" {
				return fmt.Errorf("group %q not found in directory %q, run 'grant groups' to see available options", groupFlag, favDirectoryID)
			}
			return fmt.Errorf("group %q not found, run 'grant groups' to see available options", groupFlag)
		}
	} else {
		// Interactive mode
		selectedGroup, err = selector.SelectGroup(eligResp.Response)
		if err != nil {
			return fmt.Errorf("group selection failed: %w", err)
		}
	}

	// Build elevation request
	req := &scamodels.GroupsElevateRequest{
		DirectoryID: selectedGroup.DirectoryID,
		CSP:         scamodels.CSPAzure,
		Targets: []scamodels.GroupsElevateTarget{
			{GroupID: selectedGroup.GroupID},
		},
	}

	// Execute elevation
	elevateResp, err := elevator.ElevateGroups(ctx, req)
	if err != nil {
		return fmt.Errorf("elevation request failed: %w", err)
	}

	// Check results
	if len(elevateResp.Results) == 0 {
		return fmt.Errorf("elevation failed: no results returned")
	}

	result := elevateResp.Results[0]
	if result.ErrorInfo != nil {
		return fmt.Errorf("elevation failed: %s - %s\n%s",
			result.ErrorInfo.Code,
			result.ErrorInfo.Message,
			result.ErrorInfo.Description)
	}

	// Display success
	dirContext := ""
	if selectedGroup.DirectoryName != "" {
		dirContext = fmt.Sprintf(" in %s", selectedGroup.DirectoryName)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Elevated to group %s%s\n", selectedGroup.GroupName, dirContext)
	fmt.Fprintf(cmd.OutOrStdout(), "  Session ID: %s\n", result.SessionID)

	return nil
}

// findMatchingGroup finds a group by name (case-insensitive).
// If directoryID is non-empty, only matches groups in that directory.
func findMatchingGroup(groups []scamodels.GroupsEligibleTarget, name string, directoryID string) *scamodels.GroupsEligibleTarget {
	for i := range groups {
		if strings.EqualFold(groups[i].GroupName, name) {
			if directoryID != "" && groups[i].DirectoryID != directoryID {
				continue
			}
			return &groups[i]
		}
	}
	return nil
}
