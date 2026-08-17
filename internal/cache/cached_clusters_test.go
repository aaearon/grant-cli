package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aaearon/grant-cli/internal/k8s"
)

type fakeClusterLister struct {
	calls    int
	clusters []k8s.Cluster
	err      error
}

func (f *fakeClusterLister) ListClusters(_ context.Context, _ string) ([]k8s.Cluster, error) {
	f.calls++
	return f.clusters, f.err
}

func newClusterStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(t.TempDir(), time.Hour)
}

func TestCachedClusterListerCachesResults(t *testing.T) {
	inner := &fakeClusterLister{clusters: []k8s.Cluster{{Provider: "aws", Name: "prod"}}}
	store := newClusterStore(t)

	lister := NewCachedClusterLister(inner, store, false, nil)

	first, err := lister.ListClusters(t.Context(), "aws")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	second, err := lister.ListClusters(t.Context(), "aws")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if inner.calls != 1 {
		t.Errorf("inner called %d times, want 1 (second call should hit the cache)", inner.calls)
	}
	if len(first) != 1 || len(second) != 1 || second[0].Name != "prod" {
		t.Errorf("first=%v second=%v", first, second)
	}
}

func TestCachedClusterListerRefreshBypassesCache(t *testing.T) {
	inner := &fakeClusterLister{clusters: []k8s.Cluster{{Provider: "aws", Name: "prod"}}}
	store := newClusterStore(t)

	if _, err := NewCachedClusterLister(inner, store, false, nil).ListClusters(t.Context(), "aws"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := NewCachedClusterLister(inner, store, true, nil).ListClusters(t.Context(), "aws"); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if inner.calls != 2 {
		t.Errorf("inner called %d times, want 2 (refresh must bypass the cache)", inner.calls)
	}
}

func TestCachedClusterListerKeysPerCSP(t *testing.T) {
	inner := &fakeClusterLister{clusters: []k8s.Cluster{{Provider: "aws"}}}
	store := newClusterStore(t)
	lister := NewCachedClusterLister(inner, store, false, nil)

	for _, csp := range []string{"aws", "azure", ""} {
		if _, err := lister.ListClusters(t.Context(), csp); err != nil {
			t.Fatalf("csp %q: %v", csp, err)
		}
	}

	if inner.calls != 3 {
		t.Errorf("inner called %d times, want 3 (one per distinct cache key)", inner.calls)
	}
}

func TestCachedClusterListerPropagatesError(t *testing.T) {
	sentinel := errors.New("api down")
	inner := &fakeClusterLister{err: sentinel}
	lister := NewCachedClusterLister(inner, newClusterStore(t), false, nil)

	if _, err := lister.ListClusters(t.Context(), "aws"); !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
}

func TestClustersCacheKey(t *testing.T) {
	tests := []struct{ csp, want string }{
		{csp: "aws", want: "clusters_aws"},
		{csp: "AZURE", want: "clusters_azure"},
		{csp: "", want: "clusters_all"},
	}
	for _, tt := range tests {
		if got := clustersCacheKey(tt.csp); got != tt.want {
			t.Errorf("clustersCacheKey(%q) = %q, want %q", tt.csp, got, tt.want)
		}
	}
}
