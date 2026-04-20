package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

// OnDemandRolesLister mirrors the service method for on-demand role discovery.
type OnDemandRolesLister interface {
	ListOnDemandResources(ctx context.Context, req scamodels.OnDemandRequest) ([]scamodels.OnDemandResource, error)
}

// CachedRolesLister decorates an OnDemandRolesLister with file-based caching.
type CachedRolesLister struct {
	inner   OnDemandRolesLister
	store   *Store
	refresh bool
	log     Logger
}

// NewCachedRolesLister creates a caching decorator for on-demand role discovery.
// When refresh is true, the cache read is bypassed but the API response is still cached.
func NewCachedRolesLister(inner OnDemandRolesLister, store *Store, refresh bool, log Logger) *CachedRolesLister {
	if log == nil {
		log = nopLogger{}
	}
	return &CachedRolesLister{inner: inner, store: store, refresh: refresh, log: log}
}

// ListOnDemandResources checks the cache first, then falls through to the inner lister.
func (c *CachedRolesLister) ListOnDemandResources(ctx context.Context, req scamodels.OnDemandRequest) ([]scamodels.OnDemandResource, error) {
	key := onDemandRolesCacheKey(req.PlatformName, req.WorkspaceID)

	if c.refresh {
		c.log.Info("Cache refresh requested for on-demand roles (%s), bypassing cache", req.PlatformName)
	} else {
		var cached []scamodels.OnDemandResource
		if Get(c.store, key, &cached) {
			c.log.Info("Cache hit for on-demand roles (%s, %d roles)", req.PlatformName, len(cached))
			return cached, nil
		}
		c.log.Info("Cache miss for on-demand roles (%s), fetching from API", req.PlatformName)
	}

	roles, err := c.inner.ListOnDemandResources(ctx, req)
	if err != nil {
		return nil, err
	}

	if err := Set(c.store, key, roles); err != nil {
		c.log.Info("Cache write failed for on-demand roles (%s): %v", req.PlatformName, err)
	} else {
		c.log.Info("Cached on-demand roles (%s, %d roles)", req.PlatformName, len(roles))
	}
	return roles, nil
}

// onDemandRolesCacheKey builds a cache key from platformName and a sha256 hash of workspaceID.
// Hashing eliminates unsafe filesystem characters from workspace identifiers like
// "/providers/Microsoft.Management/managementGroups/...".
func onDemandRolesCacheKey(platformName, workspaceID string) string {
	sum := sha256.Sum256([]byte(workspaceID))
	return "ondemand_roles_" + platformName + "_" + hex.EncodeToString(sum[:])
}
