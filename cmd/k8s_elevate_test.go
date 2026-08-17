package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/k8s"
	"github.com/aaearon/grant-cli/internal/ui"
)

// mockClusterElevator implements clusterElevator.
type mockClusterElevator struct {
	result *k8s.ElevateResult
	err    error
	got    k8s.ElevateParams
	calls  int
}

func (m *mockClusterElevator) Elevate(_ context.Context, p k8s.ElevateParams) (*k8s.ElevateResult, error) {
	m.calls++
	m.got = p
	if m.result == nil && m.err == nil {
		return &k8s.ElevateResult{SessionID: "s1", RoleName: "admin"}, nil
	}
	return m.result, m.err
}

func TestK8sElevateByName(t *testing.T) {
	setOutputFormat(t, "text")

	elevator := &mockClusterElevator{}
	cmd := NewK8sElevateCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{clusters: sampleClusters()}, elevator)

	out, err := executeCommand(cmd, "prod")
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	}
	if elevator.got.FQDN != "abc.eks.amazonaws.com" {
		t.Errorf("FQDN = %q", elevator.got.FQDN)
	}
	if elevator.got.CSP != "aws" {
		t.Errorf("CSP = %q", elevator.got.CSP)
	}
	if elevator.got.RoleID != "arn:aws:iam::1:role/admin" {
		t.Errorf("RoleID = %q, want the eligible role", elevator.got.RoleID)
	}
	if !strings.Contains(out, "Elevated access to prod") {
		t.Errorf("output = %q", out)
	}
}

func TestK8sElevateByFQDN(t *testing.T) {
	elevator := &mockClusterElevator{}
	cmd := NewK8sElevateCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{clusters: sampleClusters()}, elevator)

	if _, err := executeCommand(cmd, "aks1.hcp.westeurope.azmk8s.io"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if elevator.got.CSP != "azure" {
		t.Errorf("CSP = %q, want azure", elevator.got.CSP)
	}
}

func TestK8sElevateRoleIDOverride(t *testing.T) {
	elevator := &mockClusterElevator{}
	cmd := NewK8sElevateCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{clusters: sampleClusters()}, elevator)

	if _, err := executeCommand(cmd, "prod", "--role-id", "custom-role"); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if elevator.got.RoleID != "custom-role" {
		t.Errorf("RoleID = %q, want the --role-id override", elevator.got.RoleID)
	}
}

func TestK8sElevateJSONOutput(t *testing.T) {
	setOutputFormat(t, "json")

	elevator := &mockClusterElevator{result: &k8s.ElevateResult{
		SessionID: "sess-1", RoleName: "admin", SessionExpTime: "2026-08-13T18:00:00Z",
	}}
	cmd := NewK8sElevateCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{clusters: sampleClusters()}, elevator)

	out, err := executeCommand(cmd, "prod")
	if err != nil {
		t.Fatalf("execute: %v\n%s", err, out)
	}

	var got k8sElevateOutput
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if got.Cluster != "prod" || got.SessionID != "sess-1" || got.Provider != "aws" {
		t.Errorf("output = %+v", got)
	}
}

func TestK8sElevateNoArgsNonInteractive(t *testing.T) {
	original := ui.IsTerminalFunc
	t.Cleanup(func() { ui.IsTerminalFunc = original })
	ui.IsTerminalFunc = func(uintptr) bool { return false }

	elevator := &mockClusterElevator{}
	cmd := NewK8sElevateCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{clusters: sampleClusters()}, elevator)

	_, err := executeCommand(cmd)
	if !errors.Is(err, ui.ErrNotInteractive) {
		t.Fatalf("err = %v, want ErrNotInteractive", err)
	}
	if !strings.Contains(err.Error(), "grant k8s list") {
		t.Errorf("error should hint at 'grant k8s list': %v", err)
	}
	if elevator.calls != 0 {
		t.Error("no elevation should be attempted without a cluster")
	}
}

func TestK8sElevateUnknownCluster(t *testing.T) {
	cmd := NewK8sElevateCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{clusters: sampleClusters()}, &mockClusterElevator{})
	_, err := executeCommand(cmd, "nope")
	if err == nil || !strings.Contains(err.Error(), "no eligible cluster matches") {
		t.Fatalf("err = %v", err)
	}
}

func TestK8sElevateAmbiguousCluster(t *testing.T) {
	clusters := []k8s.Cluster{
		{Provider: "aws", Name: "prod-east", FQDN: "a", RoleID: "r"},
		{Provider: "aws", Name: "prod-west", FQDN: "b", RoleID: "r"},
	}
	cmd := NewK8sElevateCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{clusters: clusters}, &mockClusterElevator{})
	_, err := executeCommand(cmd, "prod")
	if err == nil || !strings.Contains(err.Error(), "matches multiple clusters") {
		t.Fatalf("err = %v, want an ambiguity error", err)
	}
}

func TestK8sElevateProviderValidation(t *testing.T) {
	cmd := NewK8sElevateCommandWithDeps(&mockAuthLoader{}, &mockClusterLister{clusters: sampleClusters()}, &mockClusterElevator{})
	if _, err := executeCommand(cmd, "prod", "--provider", "gcp"); err == nil {
		t.Fatal("expected an unsupported-provider error")
	}
}

func TestK8sElevateRequiresAuth(t *testing.T) {
	cmd := NewK8sElevateCommandWithDeps(
		&mockAuthLoader{loadErr: errNotAuthenticated},
		&mockClusterLister{clusters: sampleClusters()},
		&mockClusterElevator{},
	)
	if _, err := executeCommand(cmd, "prod"); err == nil || !strings.Contains(err.Error(), "not authenticated") {
		t.Fatalf("err = %v", err)
	}
}
