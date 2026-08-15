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

// writeCorruptCacheFile writes a well-formed cache envelope with a FRESH
// cached_at and a type-mismatched "response" payload. Freshness matters: a
// zero-valued cached_at (as unparseable garbage produces) is also a miss via
// the TTL branch, so it would not exercise the unmarshal guard at all.
func writeCorruptCacheFile(dir, key string) error {
	envelope := []byte(`{"cached_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","response":"not-an-object"}`)
	return os.WriteFile(dir+"/"+key+".json", envelope, 0o600)
}

// TestCachedEligibility_RefreshStillWrites pins that --refresh bypasses the
// cache READ but still WRITES the fresh response. Counting inner calls is not
// enough: with the write skipped, the pre-warmed entry survives and a later
// read still hits. Only re-reading and comparing the PAYLOAD detects it, which
// is why the two responses below must stay distinguishable.
func TestCachedEligibility_RefreshStillWrites(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir(), 4*time.Hour)
	ctx := t.Context()

	inner := &mockEligibilityLister{
		response: &models.EligibilityResponse{
			Response: []models.EligibleTarget{{WorkspaceID: "ws-stale"}},
			Total:    1,
		},
	}

	// Pre-warm the cache with the stale payload.
	if _, err := NewCachedEligibilityLister(inner, nil, store, false, nil).ListEligibility(ctx, models.CSPAzure); err != nil {
		t.Fatalf("prewarm: %v", err)
	}

	// Distinguishable from "ws-stale" on purpose — do not collapse these.
	inner.response = &models.EligibilityResponse{
		Response: []models.EligibleTarget{{WorkspaceID: "ws-fresh"}},
		Total:    1,
	}

	if _, err := NewCachedEligibilityLister(inner, nil, store, true, nil).ListEligibility(ctx, models.CSPAzure); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if inner.calls != 2 {
		t.Fatalf("refresh should bypass the read: want 2 inner calls, got %d", inner.calls)
	}

	// A non-refresh read must now hit the cache AND see the refreshed payload.
	resp, err := NewCachedEligibilityLister(inner, nil, store, false, nil).ListEligibility(ctx, models.CSPAzure)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if inner.calls != 2 {
		t.Errorf("read back should have hit the cache: want 2 inner calls, got %d", inner.calls)
	}
	if len(resp.Response) != 1 || resp.Response[0].WorkspaceID != "ws-fresh" {
		t.Errorf("cache still holds the pre-refresh payload: %+v", resp.Response)
	}
}

// TestCachedGroupsEligibility_RefreshStillWrites is the groups mirror of
// TestCachedEligibility_RefreshStillWrites.
func TestCachedGroupsEligibility_RefreshStillWrites(t *testing.T) {
	t.Parallel()
	store := NewStore(t.TempDir(), 4*time.Hour)
	ctx := t.Context()

	inner := &mockGroupsEligibilityLister{
		response: &models.GroupsEligibilityResponse{
			Response: []models.GroupsEligibleTarget{{GroupID: "g-stale"}},
			Total:    1,
		},
	}

	if _, err := NewCachedEligibilityLister(nil, inner, store, false, nil).ListGroupsEligibility(ctx, models.CSPAzure); err != nil {
		t.Fatalf("prewarm: %v", err)
	}

	// Distinguishable from "g-stale" on purpose — do not collapse these.
	inner.response = &models.GroupsEligibilityResponse{
		Response: []models.GroupsEligibleTarget{{GroupID: "g-fresh"}},
		Total:    1,
	}

	if _, err := NewCachedEligibilityLister(nil, inner, store, true, nil).ListGroupsEligibility(ctx, models.CSPAzure); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if inner.calls != 2 {
		t.Fatalf("refresh should bypass the read: want 2 inner calls, got %d", inner.calls)
	}

	resp, err := NewCachedEligibilityLister(nil, inner, store, false, nil).ListGroupsEligibility(ctx, models.CSPAzure)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if inner.calls != 2 {
		t.Errorf("read back should have hit the cache: want 2 inner calls, got %d", inner.calls)
	}
	if len(resp.Response) != 1 || resp.Response[0].GroupID != "g-fresh" {
		t.Errorf("cache still holds the pre-refresh payload: %+v", resp.Response)
	}
}

// TestCacheKeys_DistinctPrefixes pins that cloud and group eligibility never
// share a cache file. Collapsing the prefixes makes the two responses
// cross-deserialize into each other's entries.
func TestCacheKeys_DistinctPrefixes(t *testing.T) {
	t.Parallel()
	for _, csp := range []models.CSP{models.CSPAzure, models.CSPAWS, models.CSPGCP} {
		cloud := eligibilityCacheKey(csp)
		groups := groupsEligibilityCacheKey(csp)
		if cloud == groups {
			t.Errorf("csp %s: cloud and groups eligibility share cache key %q", csp, cloud)
		}
	}
}

// TestCacheKeys_LowercaseCSP pins the documented on-disk file names. The CSP
// constants are upper-case ("AZURE"), so without strings.ToLower the
// documented eligibility_azure.json becomes eligibility_AZURE.json.
func TestCacheKeys_LowercaseCSP(t *testing.T) {
	t.Parallel()
	if got, want := eligibilityCacheKey(models.CSPAzure), "eligibility_azure"; got != want {
		t.Errorf("eligibilityCacheKey = %q, want %q", got, want)
	}
	if got, want := groupsEligibilityCacheKey(models.CSPAzure), "groups_eligibility_azure"; got != want {
		t.Errorf("groupsEligibilityCacheKey = %q, want %q", got, want)
	}
}
