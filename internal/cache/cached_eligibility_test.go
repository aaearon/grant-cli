package cache

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/sca/models"
)

// mockEligibilityLister implements eligibilityLister for testing.
type mockEligibilityLister struct {
	calls    int
	response *models.EligibilityResponse
	err      error
}

func (m *mockEligibilityLister) ListEligibility(ctx context.Context, csp models.CSP) (*models.EligibilityResponse, error) {
	m.calls++
	return m.response, m.err
}

// mockGroupsEligibilityLister implements groupsEligibilityLister for testing.
type mockGroupsEligibilityLister struct {
	calls    int
	response *models.GroupsEligibilityResponse
	err      error
}

func (m *mockGroupsEligibilityLister) ListGroupsEligibility(ctx context.Context, csp models.CSP) (*models.GroupsEligibilityResponse, error) {
	m.calls++
	return m.response, m.err
}

func TestCachedEligibilityLister_CacheHit(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir(), 4*time.Hour)

	inner := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{
				{WorkspaceID: "ws-1", WorkspaceName: "Sub1", RoleInfo: models.RoleInfo{ID: "r1", Name: "Reader"}},
			},
			Total: 1,
		},
	}

	cached := NewCachedEligibilityLister(inner, nil, store, false, nil)
	ctx := t.Context()

	// First call — miss, calls inner
	resp1, err := cached.ListEligibility(ctx, models.CSPAzure)
	if err != nil {
		t.Fatalf("first call error = %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("expected 1 inner call, got %d", inner.calls)
	}
	if len(resp1.Response) != 1 {
		t.Fatalf("expected 1 target, got %d", len(resp1.Response))
	}

	// Second call — hit, no additional inner call
	resp2, err := cached.ListEligibility(ctx, models.CSPAzure)
	if err != nil {
		t.Fatalf("second call error = %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("expected still 1 inner call, got %d", inner.calls)
	}
	if len(resp2.Response) != 1 || resp2.Response[0].WorkspaceID != "ws-1" {
		t.Errorf("unexpected cached response: %+v", resp2)
	}
}

func TestCachedEligibilityLister_CacheMiss_Expired(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ttl := 1 * time.Hour

	inner := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{
				{WorkspaceID: "ws-1", WorkspaceName: "Sub1"},
			},
			Total: 1,
		},
	}

	// Write cache entry in the past
	pastStore := &Store{dir: dir, ttl: ttl, now: func() time.Time { return time.Now().Add(-2 * time.Hour) }}
	cached := NewCachedEligibilityLister(inner, nil, pastStore, false, nil)
	ctx := t.Context()

	_, _ = cached.ListEligibility(ctx, models.CSPAzure)
	if inner.calls != 1 {
		t.Fatalf("expected 1 inner call for initial set, got %d", inner.calls)
	}

	// Now read with current time — should be expired
	currentStore := NewStore(dir, ttl)
	cached2 := NewCachedEligibilityLister(inner, nil, currentStore, false, nil)
	_, err := cached2.ListEligibility(ctx, models.CSPAzure)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if inner.calls != 2 {
		t.Fatalf("expected 2 inner calls (expired cache), got %d", inner.calls)
	}
}

func TestCachedEligibilityLister_RefreshBypass(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir(), 4*time.Hour)

	inner := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{
				{WorkspaceID: "ws-1"},
			},
			Total: 1,
		},
	}

	// Pre-populate cache
	cached := NewCachedEligibilityLister(inner, nil, store, false, nil)
	ctx := t.Context()
	_, _ = cached.ListEligibility(ctx, models.CSPAzure)
	if inner.calls != 1 {
		t.Fatalf("expected 1 call, got %d", inner.calls)
	}

	// With refresh=true, should bypass cache
	refreshed := NewCachedEligibilityLister(inner, nil, store, true, nil)
	_, err := refreshed.ListEligibility(ctx, models.CSPAzure)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if inner.calls != 2 {
		t.Fatalf("expected 2 calls with refresh, got %d", inner.calls)
	}
}

func TestCachedEligibilityLister_APIError_NoCache(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir(), 4*time.Hour)

	apiErr := errors.New("api failure")
	inner := &mockEligibilityLister{err: apiErr}

	cached := NewCachedEligibilityLister(inner, nil, store, false, nil)
	ctx := t.Context()

	_, err := cached.ListEligibility(ctx, models.CSPAzure)
	if !errors.Is(err, apiErr) {
		t.Fatalf("expected api error, got %v", err)
	}
}

func TestCachedEligibilityLister_CorruptCache_Fallthrough(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewStore(dir, 4*time.Hour)

	inner := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{{WorkspaceID: "ws-fresh"}},
			Total:    1,
		},
	}

	// Write corrupt cache file
	key := eligibilityCacheKey(models.CSPAzure)
	if err := writeCorruptCacheFile(dir, key); err != nil {
		t.Fatalf("failed to write corrupt cache: %v", err)
	}

	cached := NewCachedEligibilityLister(inner, nil, store, false, nil)
	ctx := t.Context()

	resp, err := cached.ListEligibility(ctx, models.CSPAzure)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("expected inner call on corrupt cache, got %d calls", inner.calls)
	}
	if resp.Response[0].WorkspaceID != "ws-fresh" {
		t.Errorf("expected fresh data, got %+v", resp)
	}
}

func TestCachedGroupsEligibilityLister_CacheHit(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir(), 4*time.Hour)

	inner := &mockGroupsEligibilityLister{
		response: &models.GroupsEligibilityResponse{
			Response: []models.GroupsEligibleTarget{
				{GroupID: "g-1", GroupName: "Admins"},
			},
			Total: 1,
		},
	}

	cached := NewCachedEligibilityLister(nil, inner, store, false, nil)
	ctx := t.Context()

	// First call — miss
	resp1, err := cached.ListGroupsEligibility(ctx, models.CSPAzure)
	if err != nil {
		t.Fatalf("first call error = %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("expected 1 inner call, got %d", inner.calls)
	}
	if len(resp1.Response) != 1 {
		t.Fatalf("expected 1 group, got %d", len(resp1.Response))
	}

	// Second call — hit
	resp2, err := cached.ListGroupsEligibility(ctx, models.CSPAzure)
	if err != nil {
		t.Fatalf("second call error = %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("expected still 1 inner call, got %d", inner.calls)
	}
	if resp2.Response[0].GroupID != "g-1" {
		t.Errorf("unexpected cached response: %+v", resp2)
	}
}

func TestCachedGroupsEligibilityLister_RefreshBypass(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir(), 4*time.Hour)

	inner := &mockGroupsEligibilityLister{
		response: &models.GroupsEligibilityResponse{
			Response: []models.GroupsEligibleTarget{
				{GroupID: "g-1", GroupName: "Admins"},
			},
			Total: 1,
		},
	}

	// Pre-populate cache
	cached := NewCachedEligibilityLister(nil, inner, store, false, nil)
	ctx := t.Context()
	_, _ = cached.ListGroupsEligibility(ctx, models.CSPAzure)

	// With refresh=true, should bypass cache
	refreshed := NewCachedEligibilityLister(nil, inner, store, true, nil)
	_, err := refreshed.ListGroupsEligibility(ctx, models.CSPAzure)
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if inner.calls != 2 {
		t.Fatalf("expected 2 calls with refresh, got %d", inner.calls)
	}
}

func TestCachedGroupsEligibilityLister_NilInner(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir(), 4*time.Hour)

	cached := NewCachedEligibilityLister(nil, nil, store, false, nil)
	ctx := t.Context()

	_, err := cached.ListGroupsEligibility(ctx, models.CSPAzure)
	if err == nil {
		t.Fatal("expected error when groupsInner is nil")
	}
}

func TestCachedEligibilityLister_DifferentCSPs_SeparateKeys(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir(), 4*time.Hour)

	inner := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{{WorkspaceID: "ws-1"}},
			Total:    1,
		},
	}

	cached := NewCachedEligibilityLister(inner, nil, store, false, nil)
	ctx := t.Context()

	_, _ = cached.ListEligibility(ctx, models.CSPAzure)
	_, _ = cached.ListEligibility(ctx, models.CSPAWS)

	// Both CSPs should have called inner (separate cache keys)
	if inner.calls != 2 {
		t.Fatalf("expected 2 inner calls for different CSPs, got %d", inner.calls)
	}

	// Now both should be cached
	_, _ = cached.ListEligibility(ctx, models.CSPAzure)
	_, _ = cached.ListEligibility(ctx, models.CSPAWS)
	if inner.calls != 2 {
		t.Fatalf("expected still 2 inner calls after cache hits, got %d", inner.calls)
	}
}

// recordingLogger captures Info calls for assertions.
type recordingLogger struct {
	messages []string
}

func (l *recordingLogger) Info(msg string, v ...interface{}) {
	l.messages = append(l.messages, fmt.Sprintf(msg, v...))
}

func TestCachedEligibilityLister_LogsHitAndMiss(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir(), 4*time.Hour)
	log := &recordingLogger{}

	inner := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{{WorkspaceID: "ws-1"}},
			Total:    1,
		},
	}

	cached := NewCachedEligibilityLister(inner, nil, store, false, log)
	ctx := t.Context()

	// First call — miss
	_, _ = cached.ListEligibility(ctx, models.CSPAzure)
	if len(log.messages) < 1 {
		t.Fatal("expected at least 1 log message on miss")
	}
	found := false
	for _, m := range log.messages {
		if strings.Contains(m, "Cache miss") && strings.Contains(m, "AZURE") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Cache miss' log, got: %v", log.messages)
	}

	// Second call — hit
	log.messages = nil
	_, _ = cached.ListEligibility(ctx, models.CSPAzure)
	found = false
	for _, m := range log.messages {
		if strings.Contains(m, "Cache hit") && strings.Contains(m, "AZURE") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Cache hit' log, got: %v", log.messages)
	}
}

func TestCachedEligibilityLister_LogsRefreshBypass(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir(), 4*time.Hour)
	log := &recordingLogger{}

	inner := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{{WorkspaceID: "ws-1"}},
			Total:    1,
		},
	}

	cached := NewCachedEligibilityLister(inner, nil, store, true, log)
	ctx := t.Context()

	_, _ = cached.ListEligibility(ctx, models.CSPAzure)
	found := false
	for _, m := range log.messages {
		if strings.Contains(m, "refresh requested") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'refresh requested' log, got: %v", log.messages)
	}
}

// writeCorruptCacheFile writes invalid JSON to a cache file.
func writeCorruptCacheFile(dir, key string) error {
	return os.WriteFile(dir+"/"+key+".json", []byte("{invalid json"), 0o600)
}
