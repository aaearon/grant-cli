package cache

import (
	"context"
	"strings"

	"github.com/aaearon/grant-cli/internal/k8s"
)

// ClusterLister mirrors cmd.clusterLister to avoid import cycles.
type ClusterLister interface {
	ListClusters(ctx context.Context, csp string) ([]k8s.Cluster, error)
}

// CachedClusterLister decorates a ClusterLister with file-based caching,
// mirroring CachedEligibilityLister.
type CachedClusterLister struct {
	inner   ClusterLister
	store   *Store
	refresh bool
	log     Logger
}

// NewCachedClusterLister creates a caching decorator around a ClusterLister.
// When refresh is true the cache read is bypassed but the response is still cached.
// Logger is optional — pass nil for silent operation.
func NewCachedClusterLister(inner ClusterLister, store *Store, refresh bool, log Logger) *CachedClusterLister {
	if log == nil {
		log = nopLogger{}
	}
	return &CachedClusterLister{inner: inner, store: store, refresh: refresh, log: log}
}

// ListClusters checks the cache first, then falls through to the inner lister.
func (c *CachedClusterLister) ListClusters(ctx context.Context, csp string) ([]k8s.Cluster, error) {
	key := clustersCacheKey(csp)

	if c.refresh {
		c.log.Info("Cache refresh requested for %s clusters, bypassing cache", key)
	} else {
		var cached []k8s.Cluster
		if Get(c.store, key, &cached) {
			c.log.Info("Cache hit for %s (%d clusters)", key, len(cached))
			return cached, nil
		}
		c.log.Info("Cache miss for %s, fetching from API", key)
	}

	clusters, err := c.inner.ListClusters(ctx, csp)
	if err != nil {
		return nil, err
	}

	if err := Set(c.store, key, clusters); err != nil {
		c.log.Info("Cache write failed for %s: %v", key, err)
	} else {
		c.log.Info("Cached %s (%d clusters)", key, len(clusters))
	}

	return clusters, nil
}

func clustersCacheKey(csp string) string {
	normalized := strings.ToLower(strings.TrimSpace(csp))
	if normalized == "" {
		normalized = "all"
	}
	return "clusters_" + normalized
}
