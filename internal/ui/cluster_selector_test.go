package ui

import (
	"errors"
	"strings"
	"testing"

	"github.com/aaearon/grant-cli/internal/k8s"
)

func TestFormatClusterOption(t *testing.T) {
	tests := []struct {
		name string
		in   k8s.Cluster
		want string
	}{
		{
			name: "aws cluster with role",
			in:   k8s.Cluster{Provider: "aws", Name: "prod", Region: "us-east-1", RoleName: "admin"},
			want: "prod (us-east-1) / Role: admin (aws)",
		},
		{
			name: "azure cluster without region",
			in:   k8s.Cluster{Provider: "azure", Name: "aks1", RoleName: "reader"},
			want: "aks1 / Role: reader (azure)",
		},
		{
			name: "namespace scoped",
			in:   k8s.Cluster{Provider: "azure", Name: "aks1", Namespace: "team-a", RoleName: "reader"},
			want: "aks1 [ns: team-a] / Role: reader (azure)",
		},
		{
			name: "no provider",
			in:   k8s.Cluster{Name: "solo", RoleName: "admin"},
			want: "solo / Role: admin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatClusterOption(tt.in); got != tt.want {
				t.Errorf("FormatClusterOption() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildClusterOptionsSorted(t *testing.T) {
	clusters := []k8s.Cluster{
		{Provider: "aws", Name: "zeta", RoleName: "r"},
		{Provider: "aws", Name: "alpha", RoleName: "r"},
	}
	options := BuildClusterOptions(clusters)
	if len(options) != 2 {
		t.Fatalf("got %d options, want 2", len(options))
	}
	if options[0] != "alpha / Role: r (aws)" {
		t.Errorf("options not sorted: %v", options)
	}

	if got := BuildClusterOptions(nil); len(got) != 0 {
		t.Errorf("BuildClusterOptions(nil) = %v, want empty", got)
	}
}

func TestFindClusterByDisplay(t *testing.T) {
	clusters := []k8s.Cluster{
		{Provider: "aws", Name: "alpha", RoleName: "r"},
		{Provider: "azure", Name: "beta", RoleName: "r"},
	}

	got, err := FindClusterByDisplay(clusters, "beta / Role: r (azure)")
	if err != nil {
		t.Fatalf("FindClusterByDisplay: %v", err)
	}
	if got.Name != "beta" {
		t.Errorf("got %q, want beta", got.Name)
	}

	if _, err := FindClusterByDisplay(clusters, "nope"); err == nil {
		t.Error("expected error for unknown display string")
	}
}

func TestSelectClusterNonInteractive(t *testing.T) {
	original := IsTerminalFunc
	t.Cleanup(func() { IsTerminalFunc = original })
	IsTerminalFunc = func(uintptr) bool { return false }

	_, err := SelectCluster([]k8s.Cluster{{Name: "a"}})
	if !errors.Is(err, ErrNotInteractive) {
		t.Fatalf("err = %v, want ErrNotInteractive", err)
	}
	if got := err.Error(); !strings.Contains(got, "grant k8s list") {
		t.Errorf("error should hint at 'grant k8s list', got %q", got)
	}
}

func TestSelectClusterEmpty(t *testing.T) {
	original := IsTerminalFunc
	t.Cleanup(func() { IsTerminalFunc = original })
	IsTerminalFunc = func(uintptr) bool { return true }

	if _, err := SelectCluster(nil); err == nil {
		t.Fatal("expected error when there are no clusters")
	}
}
