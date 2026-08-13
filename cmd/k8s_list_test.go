package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/k8s"
	"github.com/spf13/cobra"
)

func sampleClusters() []k8s.Cluster {
	return []k8s.Cluster{
		{
			Provider: "aws", Name: "prod", ClusterID: "arn:aws:eks:us-east-1:1:cluster/prod",
			FQDN: "abc.eks.amazonaws.com", Region: "us-east-1", Scope: "cluster",
			WorkspaceID: "111", WorkspaceName: "prod-account", WorkspaceType: "ACCOUNT",
			RoleName: "admin", RoleID: "arn:aws:iam::1:role/admin", OrganizationID: "o-1",
		},
		{
			Provider: "azure", Name: "aks1", ClusterID: "/subscriptions/s/.../aks1",
			FQDN: "aks1.hcp.westeurope.azmk8s.io", RoleName: "reader", RoleID: "/rd/reader",
		},
	}
}

func TestK8sListJSONOutput(t *testing.T) {
	old := outputFormat
	defer func() { outputFormat = old }()
	outputFormat = "json"

	cmd := NewK8sCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{clusters: sampleClusters()})
	out, err := executeCommand(cmd, "list")
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	}

	var got k8sListOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if len(got.Clusters) != 2 {
		t.Fatalf("got %d clusters, want 2", len(got.Clusters))
	}
	first := got.Clusters[0]
	if first.Provider != "aws" || first.Name != "prod" || first.Region != "us-east-1" {
		t.Errorf("unexpected first cluster: %+v", first)
	}
	if first.FQDN != "abc.eks.amazonaws.com" || first.RoleID != "arn:aws:iam::1:role/admin" {
		t.Errorf("unexpected first cluster: %+v", first)
	}
}

func TestK8sListTextOutput(t *testing.T) {
	cmd := NewK8sCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{clusters: sampleClusters()})
	out, err := executeCommand(cmd, "list")
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	}
	if !strings.Contains(out, "prod") || !strings.Contains(out, "aks1") {
		t.Errorf("expected both clusters in output, got:\n%s", out)
	}
}

func TestK8sListProviderValidation(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		wantErr  bool
	}{
		{name: "aws", provider: "aws"},
		{name: "azure", provider: "azure"},
		{name: "uppercase", provider: "AWS"},
		{name: "gcp rejected", provider: "gcp", wantErr: true},
		{name: "garbage rejected", provider: "nope", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lister := &mockClusterLister{clusters: sampleClusters()}
			cmd := NewK8sCommandWithDeps(&mockAuthLoader{}, lister)
			_, err := executeCommand(cmd, "list", "--provider", tt.provider)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error for provider %q", tt.provider)
			}
			if !tt.wantErr {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !strings.EqualFold(lister.gotCSP, tt.provider) {
					t.Errorf("lister got csp %q, want %q", lister.gotCSP, strings.ToLower(tt.provider))
				}
			}
		})
	}
}

func TestK8sListPassesEmptyProviderForAll(t *testing.T) {
	lister := &mockClusterLister{clusters: sampleClusters()}
	cmd := NewK8sCommandWithDeps(&mockAuthLoader{}, lister)
	if _, err := executeCommand(cmd, "list"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if lister.gotCSP != "" {
		t.Errorf("csp = %q, want empty (all providers)", lister.gotCSP)
	}
}

func TestK8sListRefreshFlagReachesLister(t *testing.T) {
	var gotRefresh bool
	lister := &mockClusterLister{clusters: sampleClusters()}
	cmd := newK8sListCommand(func(c *cobra.Command, _ []string) error {
		gotRefresh, _ = c.Flags().GetBool("refresh")
		return runK8sList(c, &mockAuthLoader{}, lister)
	})

	if _, err := executeCommand(cmd, "--refresh"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !gotRefresh {
		t.Error("--refresh flag was not visible to the command")
	}
}

func TestK8sListNoClusters(t *testing.T) {
	cmd := NewK8sCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{})
	_, err := executeCommand(cmd, "list")
	if err == nil {
		t.Fatal("expected an error when no clusters are eligible")
	}
	if !strings.Contains(err.Error(), "no eligible") {
		t.Errorf("err = %v, want a no-eligible-clusters message", err)
	}
}

func TestK8sListRequiresAuth(t *testing.T) {
	auth := &mockAuthLoader{loadErr: errNotAuthenticated}
	cmd := NewK8sCommandWithDeps(auth, &mockClusterLister{clusters: sampleClusters()})
	_, err := executeCommand(cmd, "list")
	if err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("err = %v, want a not-authenticated error", err)
	}
}

func TestK8sListPropagatesListerError(t *testing.T) {
	sentinel := errors.New("api exploded")
	cmd := NewK8sCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{err: sentinel})
	_, err := executeCommand(cmd, "list")
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want wrapped %v", err, sentinel)
	}
}

// mockClusterLister implements clusterLister for testing.
type mockClusterLister struct {
	clusters []k8s.Cluster
	err      error
	gotCSP   string
	calls    int
}

func (m *mockClusterLister) ListClusters(_ context.Context, csp string) ([]k8s.Cluster, error) {
	m.gotCSP = csp
	m.calls++
	return m.clusters, m.err
}
