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
func buildCachedClusterLister(cfg *config.Config, refresh bool, inner cache.ClusterLister) *cache.CachedClusterLister {
	cacheLog := common.GetLogger("grant", -1)
	cacheDir, err := cache.CacheDir()
	if err != nil {
		return cache.NewCachedClusterLister(inner, cache.NewStore("", 0), true, nil)
	}
	store := cache.NewStore(cacheDir, config.ParseCacheTTL(cfg))
	return cache.NewCachedClusterLister(inner, store, refresh, cacheLog)
}
