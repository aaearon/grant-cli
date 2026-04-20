package cache

import (
	"context"
	"errors"
	"testing"
	"time"

	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

type fakeRolesLister struct {
	callCount int
	roles     []scamodels.OnDemandResource
	err       error
}

func (f *fakeRolesLister) ListOnDemandResources(_ context.Context, _ scamodels.OnDemandRequest) ([]scamodels.OnDemandResource, error) {
	f.callCount++
	if f.err != nil {
		return nil, f.err
	}
	return f.roles, nil
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	return NewStore(t.TempDir(), time.Hour)
}

func TestCachedRolesLister_MissThenHit(t *testing.T) {
	fake := &fakeRolesLister{roles: []scamodels.OnDemandResource{{ResourceID: "r1", ResourceName: "Role 1"}}}
	cached := NewCachedRolesLister(fake, newTestStore(t), nil)

	req := scamodels.OnDemandRequest{WorkspaceID: "ws-1", PlatformName: "azure_ad", OrgID: "ws-1"}

	roles1, err := cached.ListOnDemandResources(t.Context(), req)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if len(roles1) != 1 {
		t.Errorf("first call: expected 1 role, got %d", len(roles1))
	}

	roles2, err := cached.ListOnDemandResources(t.Context(), req)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if len(roles2) != 1 {
		t.Errorf("second call: expected 1 role, got %d", len(roles2))
	}
	if fake.callCount != 1 {
		t.Errorf("expected inner to be called once, got %d", fake.callCount)
	}
}

func TestCachedRolesLister_DifferentWorkspacesDistinct(t *testing.T) {
	fake := &fakeRolesLister{roles: []scamodels.OnDemandResource{{ResourceID: "r1"}}}
	cached := NewCachedRolesLister(fake, newTestStore(t), nil)

	reqA := scamodels.OnDemandRequest{WorkspaceID: "ws-A", PlatformName: "azure_ad", OrgID: "ws-A"}
	reqB := scamodels.OnDemandRequest{WorkspaceID: "ws-B", PlatformName: "azure_ad", OrgID: "ws-B"}

	if _, err := cached.ListOnDemandResources(t.Context(), reqA); err != nil {
		t.Fatal(err)
	}
	if _, err := cached.ListOnDemandResources(t.Context(), reqB); err != nil {
		t.Fatal(err)
	}
	if fake.callCount != 2 {
		t.Errorf("expected 2 inner calls for distinct workspaces, got %d", fake.callCount)
	}
}

func TestCachedRolesLister_DifferentPlatformsDistinct(t *testing.T) {
	fake := &fakeRolesLister{roles: []scamodels.OnDemandResource{{ResourceID: "r1"}}}
	cached := NewCachedRolesLister(fake, newTestStore(t), nil)

	reqAD := scamodels.OnDemandRequest{WorkspaceID: "same-id", PlatformName: "azure_ad", OrgID: "same-id"}
	reqAWS := scamodels.OnDemandRequest{WorkspaceID: "same-id", PlatformName: "aws", OrgID: "same-id"}

	if _, err := cached.ListOnDemandResources(t.Context(), reqAD); err != nil {
		t.Fatal(err)
	}
	if _, err := cached.ListOnDemandResources(t.Context(), reqAWS); err != nil {
		t.Fatal(err)
	}
	if fake.callCount != 2 {
		t.Errorf("expected 2 inner calls for distinct platforms with same workspaceID, got %d", fake.callCount)
	}
}

func TestCachedRolesLister_InnerError(t *testing.T) {
	fake := &fakeRolesLister{err: errors.New("api failure")}
	cached := NewCachedRolesLister(fake, newTestStore(t), nil)

	req := scamodels.OnDemandRequest{WorkspaceID: "ws-1", PlatformName: "aws", OrgID: "ws-1"}
	_, err := cached.ListOnDemandResources(t.Context(), req)
	if err == nil {
		t.Fatal("expected error from inner")
	}
}

func TestOnDemandRolesCacheKey_HandlesSlashes(t *testing.T) {
	key := onDemandRolesCacheKey("azure_resource", "/providers/Microsoft.Management/managementGroups/abc")
	for _, c := range key {
		if c == '/' {
			t.Errorf("cache key should not contain slashes: %s", key)
		}
	}
}
