package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/sca/models"
	"github.com/aaearon/grant-cli/internal/ui"
	"github.com/spf13/cobra"
)

// listOutput is the JSON representation of the list command output.
type listOutput struct {
	Cloud  []listCloudTarget `json:"cloud"`
	Groups []listGroupTarget `json:"groups"`
}

// listCloudTarget is a single cloud eligible target in JSON output.
type listCloudTarget struct {
	Provider      string `json:"provider"`
	Target        string `json:"target"`
	WorkspaceID   string `json:"workspaceId"`
	WorkspaceType string `json:"workspaceType"`
	Role          string `json:"role"`
	RoleID        string `json:"roleId"`
}

// listGroupTarget is a single group eligible target in JSON output.
type listGroupTarget struct {
	GroupName   string `json:"groupName"`
	GroupID     string `json:"groupId"`
	DirectoryID string `json:"directoryId"`
	Directory   string `json:"directory,omitempty"`
}

// newListCommand creates the list cobra command with the given RunE function.
func newListCommand(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List eligible targets and groups",
		Long: `List all eligible cloud targets and Entra ID groups without triggering elevation.

Use this command to discover what you can elevate to. Supports both text
and JSON output for programmatic consumption.

Examples:
  # List all eligible targets (cloud + groups)
  grant list

  # List only cloud targets for a specific provider
  grant list --provider azure

  # List only Entra ID groups
  grant list --groups

  # JSON output for programmatic use
  grant list --output json

  # Bypass eligibility cache
  grant list --refresh`,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE:          runFn,
	}

	cmd.Flags().StringP("provider", "p", "", "Cloud provider: azure, aws (omit to show all)")
	cmd.Flags().Bool("groups", false, "Show only Entra ID groups")
	cmd.Flags().Bool("refresh", false, "Bypass eligibility cache and fetch fresh data")

	cmd.MarkFlagsMutuallyExclusive("groups", "provider")

	return cmd
}

// NewListCommand creates the production list command.
func NewListCommand() *cobra.Command {
	return newListCommand(func(cmd *cobra.Command, args []string) error {
		ispAuth, svc, _, err := bootstrapSCAService()
		if err != nil {
			return err
		}

		cfg, _, err := config.LoadDefaultWithPath()
		if err != nil {
			return err
		}

		refresh, _ := cmd.Flags().GetBool("refresh")
		cachedLister := buildCachedLister(cfg, refresh, svc, svc)

		return runList(cmd, ispAuth, cachedLister, cachedLister)
	})
}

// NewListCommandWithDeps creates a list command with injected dependencies for testing.
func NewListCommandWithDeps(auth authLoader, eligLister eligibilityLister, groupsElig groupsEligibilityLister) *cobra.Command {
	return newListCommand(func(cmd *cobra.Command, args []string) error {
		return runList(cmd, auth, eligLister, groupsElig)
	})
}

func runList(
	cmd *cobra.Command,
	auth authLoader,
	eligLister eligibilityLister,
	groupsElig groupsEligibilityLister,
) error {
	// Check authentication
	_, err := auth.LoadAuthentication(nil, true)
	if err != nil {
		return fmt.Errorf("not authenticated, run 'grant login' first: %w", err)
	}

	provider, _ := cmd.Flags().GetString("provider")
	groupsOnly, _ := cmd.Flags().GetBool("groups")

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	var cloudTargets []models.EligibleTarget
	var groups []models.GroupsEligibleTarget

	// Fetch cloud targets (unless --groups)
	if !groupsOnly {
		cloudTargets, err = fetchEligibility(ctx, eligLister, provider)
		if err != nil {
			log.Info("cloud eligibility fetch failed: %v", err)
		}
	}

	// Fetch groups (unless --provider is set)
	if provider == "" {
		groups, err = fetchGroupsEligibility(ctx, groupsElig, eligLister)
		if err != nil {
			log.Info("groups eligibility fetch failed: %v", err)
		}
	}

	if len(cloudTargets) == 0 && len(groups) == 0 {
		return errors.New("no eligible targets or groups found, check your SCA policies")
	}

	if isJSONOutput() {
		return writeListJSON(cmd, cloudTargets, groups)
	}

	writeListText(cmd, cloudTargets, groups)
	return nil
}

// writeListJSON outputs the list as JSON.
func writeListJSON(cmd *cobra.Command, cloudTargets []models.EligibleTarget, groups []models.GroupsEligibleTarget) error {
	out := listOutput{
		Cloud:  make([]listCloudTarget, 0, len(cloudTargets)),
		Groups: make([]listGroupTarget, 0, len(groups)),
	}

	for _, t := range cloudTargets {
		out.Cloud = append(out.Cloud, listCloudTarget{
			Provider:      strings.ToLower(string(t.CSP)),
			Target:        t.WorkspaceName,
			WorkspaceID:   t.WorkspaceID,
			WorkspaceType: strings.ToLower(string(t.WorkspaceType)),
			Role:          t.RoleInfo.Name,
			RoleID:        t.RoleInfo.ID,
		})
	}

	for _, g := range groups {
		out.Groups = append(out.Groups, listGroupTarget{
			GroupName:   g.GroupName,
			GroupID:     g.GroupID,
			DirectoryID: g.DirectoryID,
			Directory:   g.DirectoryName,
		})
	}

	return writeJSON(cmd.OutOrStdout(), out)
}

// writeListText outputs the list as formatted text.
func writeListText(cmd *cobra.Command, cloudTargets []models.EligibleTarget, groups []models.GroupsEligibleTarget) {
	if len(cloudTargets) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "Cloud targets:")
		options := ui.BuildOptions(cloudTargets)
		for _, opt := range options {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", opt)
		}
	}

	if len(groups) > 0 {
		if len(cloudTargets) > 0 {
			fmt.Fprintln(cmd.OutOrStdout())
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Groups:")
		options := ui.BuildGroupOptions(groups)
		for _, opt := range options {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", opt)
		}
	}
}
