package cache

import (
	"context"
	"fmt"
	"strings"

	"github.com/aaearon/grant-cli/internal/sca/models"
)

// EligibilityLister mirrors cmd.eligibilityLister to avoid import cycles.
type EligibilityLister interface {
	ListEligibility(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error)
}

// GroupsEligibilityLister mirrors cmd.groupsEligibilityLister to avoid import cycles.
type GroupsEligibilityLister interface {
	ListGroupsEligibility(ctx context.Context, csp models.CSP) (*models.GroupsEligibilityResponse, error)
}

// Logger interface for verbose output — satisfied by *common.IdsecLogger.
type Logger interface {
	Info(msg string, v ...interface{})
}

// nopLogger discards all log output.
type nopLogger struct{}

func (nopLogger) Info(string, ...interface{}) {}

// CachedEligibilityLister decorates eligibility listers with file-based caching.
// It implements both EligibilityLister and GroupsEligibilityLister.
type CachedEligibilityLister struct {
	cloudInner  EligibilityLister
	groupsInner GroupsEligibilityLister
	store       *Store
	refresh     bool
	log         Logger
}

// NewCachedEligibilityLister creates a new caching decorator.
// Either inner may be nil if that type of listing is not needed.
// When refresh is true, the cache read is bypassed but the API response is still cached.
// Logger is optional — pass nil for silent operation.
func NewCachedEligibilityLister(
	cloudInner EligibilityLister,
	groupsInner GroupsEligibilityLister,
	store *Store,
	refresh bool,
	log Logger,
) *CachedEligibilityLister {
	if log == nil {
		log = nopLogger{}
	}
	return &CachedEligibilityLister{
		cloudInner:  cloudInner,
		groupsInner: groupsInner,
		store:       store,
		refresh:     refresh,
		log:         log,
	}
}

// ListEligibility checks the cache first, then falls through to the inner lister.
func (c *CachedEligibilityLister) ListEligibility(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
	key := eligibilityCacheKey(csp)

	if c.refresh {
		c.log.Info("Cache refresh requested for %s eligibility, bypassing cache", csp)
	} else {
		var cached models.EligibilityResponse
		if Get(c.store, key, &cached) {
			c.log.Info("Cache hit for %s eligibility (%d targets)", csp, len(cached.Response))
			return &cached, nil
		}
		c.log.Info("Cache miss for %s eligibility, fetching from API", csp)
	}

	resp, err := c.cloudInner.ListEligibility(ctx, csp)
	if err != nil {
		return nil, err
	}

	if err := Set(c.store, key, *resp); err != nil {
		c.log.Info("Cache write failed for %s eligibility: %v", csp, err)
	} else {
		c.log.Info("Cached %s eligibility (%d targets)", csp, len(resp.Response))
	}

	return resp, nil
}

// ListGroupsEligibility checks the cache first, then falls through to the inner lister.
func (c *CachedEligibilityLister) ListGroupsEligibility(ctx context.Context, csp models.CSP) (*models.GroupsEligibilityResponse, error) {
	if c.groupsInner == nil {
		return nil, fmt.Errorf("groups eligibility listing not available")
	}

	key := groupsEligibilityCacheKey(csp)

	if c.refresh {
		c.log.Info("Cache refresh requested for %s groups eligibility, bypassing cache", csp)
	} else {
		var cached models.GroupsEligibilityResponse
		if Get(c.store, key, &cached) {
			c.log.Info("Cache hit for %s groups eligibility (%d groups)", csp, len(cached.Response))
			return &cached, nil
		}
		c.log.Info("Cache miss for %s groups eligibility, fetching from API", csp)
	}

	resp, err := c.groupsInner.ListGroupsEligibility(ctx, csp)
	if err != nil {
		return nil, err
	}

	if err := Set(c.store, key, *resp); err != nil {
		c.log.Info("Cache write failed for %s groups eligibility: %v", csp, err)
	} else {
		c.log.Info("Cached %s groups eligibility (%d groups)", csp, len(resp.Response))
	}

	return resp, nil
}

func eligibilityCacheKey(csp models.CSP) string {
	return "eligibility_" + strings.ToLower(string(csp))
}

func groupsEligibilityCacheKey(csp models.CSP) string {
	return "groups_eligibility_" + strings.ToLower(string(csp))
}
