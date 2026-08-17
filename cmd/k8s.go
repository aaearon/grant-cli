package cmd

import (
	"fmt"

	"github.com/aaearon/grant-cli/internal/cache"
	"github.com/aaearon/grant-cli/internal/config"
	"github.com/aaearon/grant-cli/internal/k8s"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/spf13/cobra"
)

// NewK8sCommand creates the "grant k8s" parent command.
func NewK8sCommand() *cobra.Command {
	cmd := newK8sParent()
	cmd.AddCommand(
		NewK8sListCommand(),
		NewK8sElevateCommand(),
		NewK8sKubeconfigCommand(),
		NewK8sExecCredentialCommand(),
	)
	return cmd
}

// NewK8sCommandWithDeps creates the k8s parent with injected dependencies for testing.
func NewK8sCommandWithDeps(auth authLoader, clusters clusterLister) *cobra.Command {
	cmd := newK8sParent()
	cmd.AddCommand(
		newK8sListCommand(func(c *cobra.Command, _ []string) error {
			return runK8sList(c, auth, clusters)
		}),
	)
	return cmd
}

// NewK8sElevateCommandWithDeps creates the elevate command with injected deps.
func NewK8sElevateCommandWithDeps(auth authLoader, clusters clusterLister, elevator clusterElevator) *cobra.Command {
	return newK8sElevateCommand(func(c *cobra.Command, args []string) error {
		return runK8sElevate(c, args, auth, clusters, elevator)
	})
}

// NewK8sKubeconfigCommandWithDeps creates the kubeconfig command with injected deps.
func NewK8sKubeconfigCommandWithDeps(auth authLoader, generator kubeconfigGenerator) *cobra.Command {
	return newK8sKubeconfigCommand(func(c *cobra.Command, _ []string) error {
		return runK8sKubeconfig(c, auth, generator)
	})
}

// NewK8sExecCredentialCommandWithDeps creates the exec-credential command with
// injected deps. execInfo stands in for the KUBERNETES_EXEC_INFO env var.
// resolveDeps is called only on a cache miss, so tests can assert that a cache
// hit never authenticates.
func NewK8sExecCredentialCommandWithDeps(
	resolveDeps func(interactive bool) (*execCredentialDeps, error),
	credCache *k8s.CredentialCache,
	execInfo string,
) *cobra.Command {
	return newK8sExecCredentialCommand(func(c *cobra.Command, _ []string) error {
		return runK8sExecCredential(c, resolveDeps, credCache, execInfo)
	})
}

func newK8sParent() *cobra.Command {
	return &cobra.Command{
		Use:   "k8s",
		Short: "Work with SCA-eligible Kubernetes clusters",
		Long: `Discover and access Kubernetes clusters you are eligible for via
Secure Cloud Access.

Supported providers: aws (EKS) and azure (AKS). The Azure path requires the
Azure CLI to be installed and logged in (` + "`az login`" + `).`,
	}
}

// bootstrapK8sService loads the profile, authenticates, and creates the SCA K8s
// service. The underlying auth is memoized across calls within one invocation.
func bootstrapK8sService() (*k8s.Service, error) {
	ispAuth, _, err := bootstrapISPAuth()
	if err != nil {
		return nil, err
	}

	svc, err := k8s.NewService(ispAuth)
	if err != nil {
		return nil, fmt.Errorf("failed to create SCA k8s service: %w", err)
	}
	return svc, nil
}

// buildCachedClusterLister wraps a cluster lister with the on-disk cache.
// If the cache directory cannot be resolved it degrades to an always-miss store.
func buildCachedClusterLister(cfg *config.Config, refresh bool, inner cache.ClusterLister) (*cache.CachedClusterLister, error) {
	cacheLog := common.GetLogger("grant", -1)
	cacheDir, err := cache.CacheDir()
	if err != nil {
		return cache.NewCachedClusterLister(inner, cache.NewStore("", 0), true, nil), nil
	}
	ttl, err := config.ParseCacheTTL(cfg)
	if err != nil {
		return nil, err
	}
	store := cache.NewStore(cacheDir, ttl)
	return cache.NewCachedClusterLister(inner, store, refresh, cacheLog), nil
}
