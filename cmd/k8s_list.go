package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/k8s"
	"github.com/aaearon/grant-cli/internal/ui"
	"github.com/spf13/cobra"
)

// newK8sListCommand creates the "grant k8s list" command with the given RunE.
func newK8sListCommand(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List eligible Kubernetes clusters",
		Long: `List the Kubernetes clusters you are eligible to access via Secure Cloud Access.

Examples:
  # List clusters across all supported providers
  grant k8s list

  # Only AWS (EKS) clusters
  grant k8s list --provider aws

  # JSON output for programmatic use
  grant k8s list --output json

  # Bypass the cluster cache
  grant k8s list --refresh`,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE:          runFn,
	}

	cmd.Flags().StringP("provider", "p", "", "Cloud provider: aws, azure (omit to show all)")
	cmd.Flags().Bool("refresh", false, "Bypass the cluster cache and fetch fresh data")

	return cmd
}

// NewK8sListCommand creates the production "grant k8s list" command.
func NewK8sListCommand() *cobra.Command {
	return newK8sListCommand(func(cmd *cobra.Command, args []string) error {
		ispAuth, _, err := bootstrapISPAuth()
		if err != nil {
			return err
		}

		svc, err := bootstrapK8sService()
		if err != nil {
			return err
		}

		cfg, _, err := config.LoadDefaultWithPath()
		if err != nil {
			return err
		}

		refresh, _ := cmd.Flags().GetBool("refresh")
		return runK8sList(cmd, ispAuth, buildCachedClusterLister(cfg, refresh, svc))
	})
}

// runK8sList lists eligible clusters in text or JSON form.
func runK8sList(cmd *cobra.Command, auth authLoader, lister clusterLister) error {
	if _, err := auth.LoadAuthentication(nil, true); err != nil {
		return fmt.Errorf("not authenticated, run 'grant login' first: %w", err)
	}

	provider, _ := cmd.Flags().GetString("provider")
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider != "" {
		if _, err := k8s.NormalizeCSP(provider); err != nil {
			return err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()

	clusters, err := lister.ListClusters(ctx, provider)
	if err != nil {
		return fmt.Errorf("failed to list clusters: %w", err)
	}

	if len(clusters) == 0 {
		return errors.New("no eligible Kubernetes clusters found, check your SCA policies")
	}

	if isJSONOutput() {
		return writeJSON(cmd.OutOrStdout(), buildK8sListOutput(clusters))
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Clusters:")
	for _, opt := range ui.BuildClusterOptions(clusters) {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", opt)
	}
	return nil
}

func buildK8sListOutput(clusters []k8s.Cluster) k8sListOutput {
	out := k8sListOutput{Clusters: make([]clusterOutput, 0, len(clusters))}
	for _, c := range clusters {
		out.Clusters = append(out.Clusters, clusterOutput{
			Provider:       c.Provider,
			Name:           c.Name,
			ClusterID:      c.ClusterID,
			FQDN:           c.FQDN,
			Region:         c.Region,
			Scope:          c.Scope,
			Namespace:      c.Namespace,
			WorkspaceID:    c.WorkspaceID,
			WorkspaceName:  c.WorkspaceName,
			WorkspaceType:  strings.ToLower(c.WorkspaceType),
			Role:           c.RoleName,
			RoleID:         c.RoleID,
			OrganizationID: c.OrganizationID,
		})
	}
	return out
}
