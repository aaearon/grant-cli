package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	grantconfig "github.com/aaearon/grant-cli/internal/config"
	scamodels "github.com/aaearon/grant-cli/internal/sca/models"
)

// writeBadCacheTTLConfig points GRANT_CONFIG at a config whose cache_ttl is
// unusable and returns the path.
func writeBadCacheTTLConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("profile: grant\ncache_ttl: garbage\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("GRANT_CONFIG", path)
	return path
}

// TestResolveSubmit_ConfigLoadErrorPropagates pins that `grant request submit`
// reports an unloadable config instead of substituting DefaultConfig(). Both
// resolution steps used to discard the load error, which made request submit
// the one command where an invalid cache_ttl was neither honored nor
// reported.
//
// The assertion that the error is NOT errTestBootstrapDisabled is what proves
// the config is read first: if the load moved back after bootstrapSCAService,
// the stubbed bootstrap would fail first and the config error would never be
// produced at all.
//
// Not parallel: sets GRANT_CONFIG for the process.
func TestResolveSubmit_ConfigLoadErrorPropagates(t *testing.T) {
	ws := &submitWorkspace{
		WorkspaceID:    "dir-1",
		WorkspaceName:  "Contoso Directory",
		WorkspaceType:  scamodels.WorkspaceType("DIRECTORY"),
		OrganizationID: "org-1",
	}

	tests := []struct {
		name string
		call func(t *testing.T) error
	}{
		{
			name: "resolveSubmitTarget",
			call: func(t *testing.T) error {
				_, err := resolveSubmitTarget(t.Context(), "azure", "anything", false)
				return err
			},
		},
		{
			name: "resolveSubmitRole",
			call: func(t *testing.T) error {
				_, _, err := resolveSubmitRole(t.Context(), ws, false)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeBadCacheTTLConfig(t)

			err := tt.call(t)
			if err == nil {
				t.Fatal("got nil error, want the config load failure to propagate")
			}
			if errors.Is(err, errTestBootstrapDisabled) {
				t.Fatalf("got the bootstrap sentinel (%v); the config must be validated before authenticating", err)
			}
			if !strings.Contains(err.Error(), `invalid cache_ttl "garbage"`) {
				t.Errorf("error = %q, want it to name the invalid cache_ttl", err)
			}
		})
	}
}

// TestBuildCachedRolesLister_TTL covers both arms of the cache_ttl handling in
// the on-demand roles factory, mirroring TestBuildCachedLister_TTL. config.Load
// already rejects a bad value, so the error arm is reachable only for a Config
// assembled in memory — which is exactly what this test builds.
func TestBuildCachedRolesLister_TTL(t *testing.T) {
	tests := []struct {
		name     string
		cacheTTL string
		// wantErrContains empty means the call must succeed.
		wantErrContains string
	}{
		{name: "absent ttl uses the default", cacheTTL: ""},
		{name: "valid ttl", cacheTTL: "30m"},
		{name: "unparseable ttl", cacheTTL: "garbage", wantErrContains: `invalid cache_ttl "garbage"`},
		{name: "zero ttl", cacheTTL: "0s", wantErrContains: "must be greater than zero"},
		{name: "negative ttl", cacheTTL: "-1h", wantErrContains: "must be greater than zero"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := grantconfig.DefaultConfig()
			cfg.CacheTTL = tt.cacheTTL

			lister, err := buildCachedRolesLister(cfg, false, nil)

			if tt.wantErrContains != "" {
				if err == nil {
					t.Fatalf("buildCachedRolesLister() = nil error, want one containing %q", tt.wantErrContains)
				}
				if !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("error = %q, want it to contain %q", err, tt.wantErrContains)
				}
				if lister != nil {
					t.Error("expected a nil lister alongside the error")
				}
				return
			}

			if err != nil {
				t.Fatalf("buildCachedRolesLister() error = %v, want nil", err)
			}
			if lister == nil {
				t.Fatal("buildCachedRolesLister() = nil lister without an error")
			}
		})
	}
}
