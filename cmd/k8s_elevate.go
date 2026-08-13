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

// newK8sElevateCommand creates the "grant k8s elevate" command with the given RunE.
func newK8sElevateCommand(runFn func(*cobra.Command, []string) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "elevate [cluster]",
		Short: "Elevate access for a Kubernetes cluster",
		Long: `Request JIT elevation for a Kubernetes cluster you are eligible for.

The cluster may be given by name or by API endpoint FQDN. Omit it in a terminal
to pick from an interactive list.

Examples:
  grant k8s elevate                       # interactive picker
  grant k8s elevate prod-cluster
  grant k8s elevate --provider azure aks1
  grant k8s elevate prod-cluster --output json`,
		Args:          cobra.MaximumNArgs(1),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE:          runFn,
	}

	cmd.Flags().StringP("provider", "p", "", "Cloud provider: aws, azure")
	cmd.Flags().String("role-id", "", "Cloud role ID to elevate (defaults to the eligible role)")
	cmd.Flags().Bool("refresh", false, "Bypass the cluster cache and fetch fresh data")

	return cmd
}

// NewK8sElevateCommand creates the production "grant k8s elevate" command.
func NewK8sElevateCommand() *cobra.Command {
	return newK8sElevateCommand(func(cmd *cobra.Command, args []string) error {
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
		return runK8sElevate(cmd, args, ispAuth, buildCachedClusterLister(cfg, refresh, svc), svc)
	})
}

// runK8sElevate resolves a cluster then elevates access for it.
func runK8sElevate(
	cmd *cobra.Command,
	args []string,
	auth authLoader,
	lister clusterLister,
	elevator clusterElevator,
) error {
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

	cluster, err := resolveCluster(clusters, args)
	if err != nil {
		return err
	}
	if cluster.FQDN == "" {
		return fmt.Errorf("cluster %q has no API endpoint FQDN and cannot be elevated", cluster.Name)
	}

	roleID, _ := cmd.Flags().GetString("role-id")
	if strings.TrimSpace(roleID) == "" {
		roleID = cluster.RoleID
	}

	result, err := elevator.Elevate(ctx, k8s.ElevateParams{
		CSP:            cluster.Provider,
		FQDN:           cluster.FQDN,
		RoleID:         roleID,
		OrganizationID: cluster.OrganizationID,
		Namespace:      cluster.Namespace,
	})
	if err != nil {
		return err
	}

	return writeK8sElevateResult(cmd, cluster, result)
}

// resolveCluster picks a cluster from args, or opens the interactive selector.
func resolveCluster(clusters []k8s.Cluster, args []string) (*k8s.Cluster, error) {
	if len(args) == 0 {
		return ui.SelectCluster(clusters)
	}

	needle := strings.ToLower(strings.TrimSpace(args[0]))
	var matches []k8s.Cluster
	for i := range clusters {
		c := clusters[i]
		if strings.EqualFold(c.Name, needle) || strings.EqualFold(c.FQDN, needle) ||
			strings.EqualFold(c.ClusterID, needle) {
			return &clusters[i], nil
		}
		if strings.Contains(strings.ToLower(c.Name), needle) {
			matches = append(matches, c)
		}
	}

	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no eligible cluster matches %q, run 'grant k8s list' to see your clusters", args[0])
	case 1:
		return &matches[0], nil
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.Name)
		}
		return nil, fmt.Errorf("%q matches multiple clusters (%s); use the full name or FQDN",
			args[0], strings.Join(names, ", "))
	}
}

func writeK8sElevateResult(cmd *cobra.Command, cluster *k8s.Cluster, result *k8s.ElevateResult) error {
	if isJSONOutput() {
		return writeJSON(cmd.OutOrStdout(), k8sElevateOutput{
			Provider:   cluster.Provider,
			Cluster:    cluster.Name,
			FQDN:       cluster.FQDN,
			Role:       result.RoleName,
			RoleID:     result.RoleID,
			SessionID:  result.SessionID,
			ExpiresAt:  result.SessionExpTime,
			TargetID:   result.TargetID,
			Namespace:  cluster.Namespace,
			Kubeconfig: "run 'grant k8s kubeconfig' to update your kubeconfig",
		})
	}

	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Elevated access to %s (%s)\n", cluster.Name, cluster.Provider)
	if result.RoleName != "" {
		fmt.Fprintf(out, "  Role:    %s\n", result.RoleName)
	}
	if result.SessionID != "" {
		fmt.Fprintf(out, "  Session: %s\n", result.SessionID)
	}
	if result.SessionExpTime != "" {
		fmt.Fprintf(out, "  Expires: %s\n", result.SessionExpTime)
	}
	fmt.Fprintln(out, "\nRun 'grant k8s kubeconfig' to add this cluster to your kubeconfig.")
	return nil
}
